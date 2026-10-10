"""
Threat Intelligence Agent

Computes the APK's SHA-256 hash and looks it up against VirusTotal's
database of known files. This mirrors the "Threat Intelligence Agent" in
the AegisAI architecture: it cross-references file hashes against an
external threat feed, without executing or re-uploading the file unless
explicitly asked to.
"""

import hashlib
import os
from typing import Optional

import httpx

from .models import Finding

VT_API_KEY = os.getenv("VT_API_KEY", "")
VT_BASE_URL = "https://www.virustotal.com/api/v3/files"


def compute_sha256(file_path: str) -> str:
    sha256 = hashlib.sha256()
    with open(file_path, "rb") as f:
        for chunk in iter(lambda: f.read(8192), b""):
            sha256.update(chunk)
    return sha256.hexdigest()


async def check_virustotal(file_hash: str) -> dict:
    """Look up a file hash on VirusTotal. Returns a dict describing the result."""
    if not VT_API_KEY:
        return {
            "queried": False,
            "reason": "No VT_API_KEY configured. Set the VT_API_KEY environment variable to enable this check.",
        }

    headers = {"x-apikey": VT_API_KEY}
    url = f"{VT_BASE_URL}/{file_hash}"

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            resp = await client.get(url, headers=headers)
    except Exception as e:
        return {"queried": False, "reason": f"VirusTotal request failed: {e}"}

    if resp.status_code == 404:
        return {
            "queried": True,
            "found": False,
            "reason": "This exact file hash was not found in VirusTotal's database (common for new/uncommon or open-source apps).",
        }

    if resp.status_code != 200:
        return {
            "queried": True,
            "found": False,
            "reason": f"VirusTotal returned status {resp.status_code}.",
        }

    data = resp.json()
    stats = data.get("data", {}).get("attributes", {}).get("last_analysis_stats", {})
    malicious = stats.get("malicious", 0)
    suspicious = stats.get("suspicious", 0)
    harmless = stats.get("harmless", 0)
    undetected = stats.get("undetected", 0)
    total = malicious + suspicious + harmless + undetected

    return {
        "queried": True,
        "found": True,
        "malicious": malicious,
        "suspicious": suspicious,
        "harmless": harmless,
        "undetected": undetected,
        "total_engines": total,
        "permalink": f"https://www.virustotal.com/gui/file/{file_hash}",
    }


def build_threat_intel_findings(file_hash: str, result: dict) -> list:
    """Convert a VirusTotal lookup result into standard Finding objects."""
    findings = []

    if not result.get("queried"):
        findings.append(
            Finding(
                rule_id="TI-UNAVAILABLE",
                title="Threat intelligence check unavailable",
                severity="LOW",
                category="Threat Intelligence",
                description=result.get("reason", "VirusTotal check was not performed."),
                recommendation="Configure a VirusTotal API key to enable hash-based reputation checks.",
                evidence=file_hash,
            )
        )
        return findings

    if not result.get("found"):
        findings.append(
            Finding(
                rule_id="TI-UNKNOWN",
                title="File hash not found in VirusTotal",
                severity="LOW",
                category="Threat Intelligence",
                description="No prior scan record exists for this exact file. This is common for legitimate but less widely distributed apps, and does not by itself indicate malware.",
                recommendation="Rely on static findings (permissions, certificate) alongside this result; consider submitting the file for a first-time scan if further assurance is needed.",
                evidence=file_hash,
            )
        )
        return findings

    malicious = result["malicious"]
    suspicious = result["suspicious"]
    total = result["total_engines"]

    if malicious > 0:
        severity = "CRITICAL" if malicious >= 5 else "HIGH"
        findings.append(
            Finding(
                rule_id="TI-MALICIOUS",
                title=f"Flagged malicious by {malicious}/{total} security engines",
                severity=severity,
                category="Threat Intelligence",
                description=f"VirusTotal reports {malicious} security vendors detected this exact file as malicious, and {suspicious} flagged it as suspicious.",
                recommendation="Treat this file as untrusted. Do not install; investigate the source it was obtained from.",
                evidence=result.get("permalink"),
            )
        )
    elif suspicious > 0:
        findings.append(
            Finding(
                rule_id="TI-SUSPICIOUS",
                title=f"Flagged suspicious by {suspicious}/{total} security engines",
                severity="MEDIUM",
                category="Threat Intelligence",
                description=f"No engine flagged this file as outright malicious, but {suspicious} flagged it as suspicious.",
                recommendation="Combine with static findings before making a final judgement; consider deeper (dynamic) analysis.",
                evidence=result.get("permalink"),
            )
        )
    else:
        findings.append(
            Finding(
                rule_id="TI-CLEAN",
                title=f"No detections across {total} security engines",
                severity="LOW",
                category="Threat Intelligence",
                description="This exact file hash has a clean scan history on VirusTotal.",
                recommendation="No action needed from threat intelligence alone; still review static findings.",
                evidence=result.get("permalink"),
            )
        )

    return findings
