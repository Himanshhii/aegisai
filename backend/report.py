from typing import Dict, List, Optional
from .models import AppInfo, Finding, IOC

SEVERITY_WEIGHT = {"LOW": 5, "MEDIUM": 15, "HIGH": 25, "CRITICAL": 40}


def compute_risk_score(findings: List[Finding]) -> int:
    score = sum(SEVERITY_WEIGHT.get(f.severity, 0) for f in findings)
    # Correlation rules deserve a small additional boost, but never exceed 100.
    if any(f.category == "Correlation" for f in findings):
        score += 10
    if any(f.rule_id == "TI-MALICIOUS" for f in findings):
        score = max(score, 85)
    return min(score, 100)


def compute_confidence(findings: List[Finding], vt_available: bool) -> int:
    if not findings:
        return 90
    base = sum(f.confidence for f in findings) / len(findings)
    corroboration = 0.05 if vt_available and any(f.category == "Threat Intelligence" for f in findings) else 0
    return max(0, min(100, round((base + corroboration) * 100)))


def risk_label(score: int, findings: List[Finding]) -> str:
    if any(f.rule_id == "TI-MALICIOUS" for f in findings) or score >= 80:
        return "HIGH"
    if score >= 35:
        return "MEDIUM"
    if score > 0:
        return "LOW"
    return "MINIMAL"


def build_mitre(findings: List[Finding]) -> List[Dict]:
    result, seen = [], set()
    for f in findings:
        if f.mitre_id and f.mitre_id not in seen:
            seen.add(f.mitre_id)
            result.append({"id": f.mitre_id, "technique": f.mitre_technique, "evidence": f.title})
    return result


def build_attack_chain(findings: List[Finding], iocs: List[IOC]) -> List[str]:
    chain = []
    titles = " ".join(f.title.lower() for f in findings)
    if "permission" in titles or any(f.category == "Permission" for f in findings):
        chain.append("Capability acquisition: sensitive Android permissions are requested.")
    if "accessibility" in titles or "overlay" in titles:
        chain.append("UI control / credential phishing: Accessibility or overlay capability may enable screen interaction or deceptive UI.")
    if "sms" in titles:
        chain.append("Potential OTP/SMS access: SMS-related capability may expose protected messages.")
    if "dynamic code" in titles:
        chain.append("Runtime payload capability: dynamic code loading can introduce functionality after installation.")
    if any(i.type in ("URL", "Domain", "IP") for i in iocs):
        chain.append("Potential communication stage: static indicators include network destinations requiring validation.")
    if not chain:
        chain.append("No multi-stage attack chain could be inferred from the currently available static evidence.")
    return chain


def build_report(app_info: AppInfo, findings: List[Finding], iocs: List[IOC], explanation: Optional[str], capabilities: Dict[str, str], retried_agents: List[str], vt_available: bool):
    score = compute_risk_score(findings)
    confidence = compute_confidence(findings, vt_available)
    return {
        "app_info": app_info.model_dump(),
        "findings": [f.model_dump() for f in findings],
        "iocs": [i.model_dump() for i in iocs],
        "mitre_mappings": build_mitre(findings),
        "attack_chain": build_attack_chain(findings, iocs),
        "finding_count": len(findings),
        "risk_score": score,
        "risk_label": risk_label(score, findings),
        "confidence_score": confidence,
        "retried_agents": retried_agents,
        "llm_explanation": explanation,
        "analysis_capabilities": capabilities,
    }
