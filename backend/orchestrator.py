"""AegisAI investigation orchestrator.

This version implements the feasible static/intelligence/reasoning pipeline.
Sandbox and runtime network analysis remain explicitly marked as future modules;
the orchestrator never installs or executes an uploaded APK.
"""

from .analyzer import analyze_apk
from .threat_intel import compute_sha256, check_virustotal, build_threat_intel_findings
from .llm import explain_with_ollama
from .report import build_report, compute_confidence
from .models import IOC


async def run_investigation(file_path: str, original_name: str):
    # Static Analysis Agent
    app_info, static_findings, iocs, capabilities = analyze_apk(file_path, original_name)

    # Threat Intelligence Agent
    file_hash = compute_sha256(file_path)
    vt_result = await check_virustotal(file_hash)
    ti_findings = build_threat_intel_findings(file_hash, vt_result)
    app_info.sha256 = file_hash
    iocs.append(IOC(type="SHA-256", value=file_hash, source="file hash", confidence=1.0))

    all_findings = static_findings + ti_findings

    # Adaptive re-task hook: re-run static analysis when evidence confidence is low.
    # This is a deterministic local retry, not dynamic execution.
    confidence = compute_confidence(all_findings, bool(vt_result.get("queried")))
    retried_agents = []
    if confidence < 65:
        app_info2, static2, iocs2, _ = analyze_apk(file_path, original_name)
        all_findings = static2 + ti_findings
        iocs.extend(iocs2)
        retried_agents.append("Static Analysis Agent")

    # GenAI reasoning agent
    explanation = await explain_with_ollama(app_info, all_findings, iocs)

    return build_report(
        app_info,
        all_findings,
        iocs,
        explanation,
        capabilities,
        retried_agents,
        bool(vt_result.get("queried")),
    )
