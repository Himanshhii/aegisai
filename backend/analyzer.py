"""Static APK analysis. The APK is treated as data and is never installed/executed."""

import base64
import hashlib
import os
import re
import subprocess
import tempfile
import zipfile
from pathlib import Path
from typing import Dict, List, Tuple

from androguard.core.apk import APK

from .models import AppInfo, Finding, IOC

SEVERITY_ORDER = {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

DANGEROUS_PERMISSIONS = {
    "android.permission.SEND_SMS": ("HIGH", "Can send SMS messages and may be abused for OTP fraud or premium-SMS abuse."),
    "android.permission.RECEIVE_SMS": ("HIGH", "Can receive SMS messages and may be abused to intercept OTPs."),
    "android.permission.READ_SMS": ("HIGH", "Can read SMS messages, including potentially sensitive OTPs."),
    "android.permission.BIND_ACCESSIBILITY_SERVICE": ("CRITICAL", "Accessibility can read screen content and automate user interaction."),
    "android.permission.SYSTEM_ALERT_WINDOW": ("HIGH", "Overlay capability can be abused for phishing or credential theft."),
    "android.permission.REQUEST_INSTALL_PACKAGES": ("HIGH", "Can request installation of other APKs and may support payload delivery."),
    "android.permission.READ_CONTACTS": ("MEDIUM", "Can access contacts."),
    "android.permission.CAMERA": ("MEDIUM", "Can access the camera."),
    "android.permission.RECORD_AUDIO": ("MEDIUM", "Can record microphone audio."),
    "android.permission.ACCESS_FINE_LOCATION": ("MEDIUM", "Can access precise location."),
    "android.permission.ACCESS_COARSE_LOCATION": ("MEDIUM", "Can access approximate location."),
    "android.permission.READ_CALL_LOG": ("MEDIUM", "Can read call history."),
    "android.permission.PROCESS_OUTGOING_CALLS": ("MEDIUM", "Can monitor outgoing calls."),
    "android.permission.WRITE_EXTERNAL_STORAGE": ("LOW", "Can write shared storage."),
    "android.permission.READ_EXTERNAL_STORAGE": ("LOW", "Can read shared storage."),
}

API_RULES = [
    (r"SmsManager|sendTextMessage|SmsMessage|TelephonyManager", "APK-API-SMS", "HIGH", "SMS-related API usage detected", "SMS APIs can be legitimate, but combined with SMS permissions they may support OTP interception or messaging abuse.", "Review SMS API call sites and verify the app's business purpose.", "T1636", "Protected User Data"),
    (r"AccessibilityService|performGlobalAction|TYPE_ACCESSIBILITY_OVERLAY", "APK-API-ACCESSIBILITY", "CRITICAL", "Accessibility-related API usage detected", "Accessibility APIs can observe UI content and automate actions.", "Review all AccessibilityService code and user-facing justification.", "T1417", "Input Capture"),
    (r"DexClassLoader|PathClassLoader|InMemoryDexClassLoader|loadClass", "APK-API-DYNAMIC-CODE", "HIGH", "Dynamic code-loading API detected", "Dynamic loading can hide functionality until runtime and is worth deeper review.", "Inspect loaded DEX/JAR paths and verify they are expected.", "T1407", "Download New Code at Runtime"),
    (r"Runtime\.getRuntime\(\)|ProcessBuilder|/system/bin/sh|/system/xbin/su", "APK-API-SHELL", "HIGH", "Shell/process execution indicator detected", "Process execution can be legitimate but may also support command execution or device manipulation.", "Review process-launching call sites and command strings.", "T1627", "Execution through Module Load"),
    (r"WebView|addJavascriptInterface|evaluateJavascript|setJavaScriptEnabled", "APK-API-WEBVIEW", "MEDIUM", "WebView/JavaScript API usage detected", "WebViews are common in apps but unsafe JavaScript bridges or remote content can increase attack surface.", "Review remote URLs, JavaScript bridges and WebView configuration.", None, None),
    (r"Cipher\.getInstance|SecretKeySpec|AES|DES|RSA", "APK-API-CRYPTO", "LOW", "Cryptography API usage detected", "Cryptography is common in legitimate apps; hardcoded keys or weak algorithms would be more concerning.", "Inspect key management and algorithms.", None, None),
    (r"HttpURLConnection|OkHttpClient|Retrofit|URLConnection|Socket|DatagramSocket", "APK-API-NETWORK", "LOW", "Network API usage detected", "The application contains code that can perform network communication.", "Review extracted URLs/domains and network destinations.", None, None),
]

SECRET_PATTERNS = [
    ("AWS Access Key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("Generic API key", re.compile(r"(?i)\b(api[_-]?key|apikey)\s*[:=]\s*[\"']?[A-Za-z0-9_\-]{16,}[\"']?")),
    ("Bearer token", re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{20,}")),
    ("Private key material", re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----")),
    ("Password assignment", re.compile(r"(?i)\b(password|passwd|secret)\s*[:=]\s*[\"'][^\"']{6,}[\"']")),
]

URL_RE = re.compile(r"https?://[^\s\"'<>]{5,}", re.I)
DOMAIN_RE = re.compile(r"(?<![\w.-])(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,}(?![\w.-])")
IP_RE = re.compile(r"(?<!\d)(?:\d{1,3}\.){3}\d{1,3}(?!\d)")


def _strings_from_apk(file_path: str, max_chars: int = 2_000_000) -> str:
    chunks: List[str] = []
    with zipfile.ZipFile(file_path) as z:
        for name in z.namelist():
            if name.endswith(('.dex', '.xml', '.json', '.txt', '.properties', '.smali', '.so')):
                try:
                    data = z.read(name)
                except Exception:
                    continue
                text = data.decode("utf-8", errors="ignore")
                # Keep readable runs from binary files as well.
                readable = "\n".join(re.findall(r"[ -~]{4,}", text))
                chunks.append(f"\n--- {name} ---\n{text}\n{readable}")
                if sum(map(len, chunks)) > max_chars:
                    break
    return "".join(chunks)[:max_chars]


def _find_jadx() -> Path | None:
    """Locate the JADX executable, checking an env override first, then
    common install layouts on both Windows and Unix."""
    env = os.getenv("JADX_PATH")
    if env:
        p = Path(env)
        return p if p.exists() else None

    tools_dir = Path(__file__).resolve().parent.parent / "tools"
    candidates = [
        tools_dir / "jadx" / "bin" / "jadx.bat",  # Windows, standard release zip
        tools_dir / "jadx" / "bin" / "jadx",       # Linux/Mac, standard release zip
        tools_dir / "jadx" / "jadx.bat",
        tools_dir / "jadx" / "jadx",
    ]
    for c in candidates:
        if c.exists():
            return c
    return None


def _find_apktool() -> Path | None:
    """Locate the apktool .jar file, checking an env override first."""
    env = os.getenv("APKTOOL_JAR")
    if env:
        p = Path(env)
        return p if p.exists() else None

    tools_dir = Path(__file__).resolve().parent.parent / "tools"
    for c in sorted(tools_dir.glob("apktool*.jar")):
        return c
    return None


def _run_optional_tool(command: List[str], timeout: int = 90) -> str:
    try:
        result = subprocess.run(command, capture_output=True, text=True, timeout=timeout, check=False)
        return (result.stdout or "") + "\n" + (result.stderr or "")
    except (FileNotFoundError, subprocess.TimeoutExpired, OSError):
        return ""


def _decompile_with_optional_tools(file_path: str) -> Tuple[str, Dict[str, str]]:
    """Run JADX/APKTool only when configured. These tools parse/decompile; the APK is not executed."""
    evidence = ""
    capabilities = {"jadx": "not configured", "apktool": "not configured"}
    jadx = _find_jadx()
    apktool = _find_apktool()

    with tempfile.TemporaryDirectory(prefix="aegis_decompile_") as td:
        if jadx:
            out = Path(td) / "jadx_out"
            _run_optional_tool([str(jadx), "-d", str(out), file_path])
            if out.exists():
                parts = []
                for p in out.rglob("*.java"):
                    try:
                        parts.append(p.read_text(errors="ignore"))
                    except Exception:
                        pass
                evidence += "\n".join(parts)[:2_000_000]
                capabilities["jadx"] = "available"
        if apktool:
            out = Path(td) / "apktool_out"
            _run_optional_tool(["java", "-jar", str(apktool), "d", "-f", "-o", str(out), file_path])
            if out.exists():
                parts = []
                for p in out.rglob("*.smali"):
                    try:
                        parts.append(p.read_text(errors="ignore"))
                    except Exception:
                        pass
                evidence += "\n".join(parts)[:2_000_000]
                capabilities["apktool"] = "available"
    return evidence, capabilities


def _finding(rule_id, title, severity, category, description, recommendation, evidence=None, mitre_id=None, mitre_technique=None, confidence=0.8, source="static"):
    return Finding(rule_id=rule_id, title=title, severity=severity, category=category, description=description,
                   recommendation=recommendation, evidence=evidence, mitre_id=mitre_id,
                   mitre_technique=mitre_technique, confidence=confidence, source=source)


def _permission_findings(apk: APK) -> List[Finding]:
    findings = []
    for p in apk.get_permissions() or []:
        if p in DANGEROUS_PERMISSIONS:
            sev, reason = DANGEROUS_PERMISSIONS[p]
            mitre_id = "T1636" if "SMS" in p else None
            mitre_name = "Protected User Data" if mitre_id else None
            findings.append(_finding("APK-PERM", f"Sensitive permission: {p.split('.')[-1]}", sev, "Permission", reason,
                                     "Verify that the permission is required and matches the app's declared purpose.", p,
                                     mitre_id, mitre_name, 0.95))
    return findings


def _manifest_findings(apk: APK) -> List[Finding]:
    findings = []
    target = apk.get_effective_target_sdk_version()
    if target and str(target).isdigit() and int(target) < 23:
        findings.append(_finding("APK-SDK", "Low target SDK version", "LOW", "Manifest",
            "The app targets an old Android SDK and may miss newer platform protections.",
            "Review and update the target SDK for production releases.", str(target), confidence=0.95))

    try:
        debuggable = str(apk.get_attribute_value("application", "debuggable")).lower() == "true"
    except Exception:
        debuggable = False
    if debuggable:
        findings.append(_finding("APK-DEBUG", "Application is debuggable", "MEDIUM", "Manifest",
            "android:debuggable=true is enabled.", "Disable debugging in release builds.", "android:debuggable=true", confidence=0.98))

    try:
        allow_backup_raw = apk.get_attribute_value("application", "allowBackup")
        allow_backup = str(allow_backup_raw).lower() in ("true", "none")
    except Exception:
        allow_backup_raw, allow_backup = None, False
    if allow_backup:
        findings.append(_finding("APK-BACKUP", "Backup is enabled or unspecified", "LOW", "Manifest",
            "Application backup is not explicitly disabled.", "Review backup policy for sensitive applications.", f"android:allowBackup={allow_backup_raw}", confidence=0.85))

    exported = []
    try:
        for a in apk.get_activities() or []:
            try:
                value = apk.get_attribute_value("activity", "exported", name=a)
            except Exception:
                value = None
            if str(value).lower() == "true":
                exported.append(a)
    except Exception:
        pass
    if exported:
        findings.append(_finding("APK-EXPORTED", f"{len(exported)} exported activities", "LOW", "Manifest",
            "Exported activities can be invoked by other apps.", "Review exported components and protect sensitive entry points.", ", ".join(exported[:10]), confidence=0.9))
    return findings


def _certificate_info(apk: APK) -> Tuple[str, str, str]:
    issuer = subject = fingerprint = "Unknown / Unsigned"
    try:
        certs = apk.get_certificates()
        if certs:
            cert = certs[0]
            issuer = str(cert.issuer.human_friendly)
            subject = str(cert.subject.human_friendly)
            raw = getattr(cert, "encoded", None) or getattr(cert, "dump", lambda: b"")()
            if raw:
                fingerprint = hashlib.sha256(raw).hexdigest()
    except Exception:
        pass
    return issuer, subject, fingerprint


def _extract_iocs(text: str, package_name: str | None) -> List[IOC]:
    iocs: List[IOC] = []
    seen = set()
    def add(kind, value, conf=0.8):
        value = value.strip().rstrip(".,);]")
        key = (kind, value.lower())
        if key not in seen and value and len(value) < 500:
            seen.add(key); iocs.append(IOC(type=kind, value=value, source="static strings/decompiled code", confidence=conf))
    for u in URL_RE.findall(text): add("URL", u, 0.9)
    for ip in IP_RE.findall(text):
        parts = ip.split(".")
        if all(0 <= int(x) <= 255 for x in parts): add("IP", ip, 0.9)
    for d in DOMAIN_RE.findall(text):
        if not d.lower().endswith(("android.com", "google.com", "example.com")):
            add("Domain", d, 0.75)
    if package_name: add("Package", package_name, 1.0)
    return iocs[:100]


def _code_findings(text: str) -> List[Finding]:
    findings = []
    for pattern, rule, sev, title, desc, rec, mitre_id, mitre_name in API_RULES:
        if re.search(pattern, text, re.I):
            findings.append(_finding(rule, title, sev, "Code/API", desc, rec,
                                     re.search(pattern, text, re.I).group(0), mitre_id, mitre_name, 0.82))
    for name, pattern in SECRET_PATTERNS:
        m = pattern.search(text)
        if m:
            # Do not expose the secret itself in the UI/report.
            findings.append(_finding("APK-SECRET", f"Possible hardcoded {name}", "HIGH", "Secrets",
                "A string pattern resembling credential/secret material was found in APK contents.",
                "Remove hardcoded secrets and rotate the exposed credential if it is genuine.",
                f"pattern={name}", confidence=0.72))
    return findings


def _obfuscation_finding(text: str) -> List[Finding]:
    if not text:
        return []
    # Heuristic: many very short class/method identifiers can indicate name obfuscation.
    short_names = re.findall(r"(?:class|interface)\s+([a-zA-Z_$][\w$]*)", text)
    if short_names and len(short_names) >= 8:
        ratio = sum(len(n) <= 2 for n in short_names) / len(short_names)
        if ratio >= 0.45:
            return [_finding("APK-OBFUSCATION", "Possible identifier obfuscation", "MEDIUM", "Obfuscation",
                "A high proportion of very short class/interface names was observed. This is a heuristic and is not proof of malicious obfuscation.",
                "Inspect decompiled code and mapping files before concluding that obfuscation is malicious.",
                f"short_identifier_ratio={ratio:.2f}", confidence=0.65)]
    return []


def analyze_apk(file_path: str, original_name: str):
    apk = APK(file_path)
    app_info = AppInfo(
        file_name=original_name,
        package_name=apk.get_package(),
        app_name=apk.get_app_name(),
        version_name=apk.get_androidversion_name(),
        version_code=apk.get_androidversion_code(),
        min_sdk=apk.get_min_sdk_version(),
        target_sdk=apk.get_target_sdk_version(),
        permission_count=len(apk.get_permissions() or []),
    )

    issuer, subject, cert_fp = _certificate_info(apk)
    app_info.certificate_issuer = issuer
    app_info.certificate_subject = subject

    findings = _permission_findings(apk) + _manifest_findings(apk)
    iocs = _extract_iocs(_strings_from_apk(file_path), app_info.package_name)

    raw_text = _strings_from_apk(file_path)
    decompiled_text, tool_caps = _decompile_with_optional_tools(file_path)
    combined = (raw_text + "\n" + decompiled_text)[:4_000_000]

    findings += _code_findings(combined)
    findings += _obfuscation_finding(decompiled_text)
    if cert_fp != "Unknown / Unsigned":
        iocs.append(IOC(type="Certificate SHA-256", value=cert_fp, source="signing certificate", confidence=0.98))

    # Combination rule: SMS + accessibility/overlay is more concerning than isolated permissions.
    perms = set(apk.get_permissions() or [])
    if ("android.permission.READ_SMS" in perms or "android.permission.RECEIVE_SMS" in perms) and \
       ("android.permission.BIND_ACCESSIBILITY_SERVICE" in perms or "android.permission.SYSTEM_ALERT_WINDOW" in perms):
        findings.append(_finding("APK-COMB-SMS-UI", "SMS + UI-control capability combination", "CRITICAL", "Correlation",
            "The APK requests SMS access together with Accessibility or overlay capability, a combination that can support OTP interception and credential phishing.",
            "Perform deeper code and dynamic analysis; verify the app's legitimate need for both capabilities.",
            "SMS permission + Accessibility/Overlay permission", "T1636", "Protected User Data", 0.9))

    findings.sort(key=lambda f: -SEVERITY_ORDER.get(f.severity, 1))
    capabilities = {
        "manifest": "implemented",
        "permissions": "implemented",
        "certificate": "implemented",
        "sha256": "implemented by orchestrator",
        "strings_ioc_extraction": "implemented",
        "api_pattern_analysis": "implemented",
        "secret_detection": "implemented",
        "obfuscation_heuristic": "implemented when decompiled source is available",
        "jadx": tool_caps["jadx"],
        "apktool": tool_caps["apktool"],
        "sandbox": "not implemented",
        "network_runtime": "not implemented",
        "codegraph": "not implemented",
    }
    return app_info, findings, iocs, capabilities
