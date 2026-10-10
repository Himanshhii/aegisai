from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class Finding(BaseModel):
    rule_id: str
    title: str
    severity: str
    category: str
    description: str
    recommendation: str
    evidence: Optional[str] = None
    mitre_id: Optional[str] = None
    mitre_technique: Optional[str] = None
    confidence: float = 0.75
    source: str = "static"


class IOC(BaseModel):
    type: str
    value: str
    source: str
    confidence: float = 0.75


class AppInfo(BaseModel):
    file_name: str
    package_name: Optional[str] = None
    app_name: Optional[str] = None
    version_name: Optional[str] = None
    version_code: Optional[str] = None
    min_sdk: Optional[str] = None
    target_sdk: Optional[str] = None
    is_debuggable: Optional[bool] = None
    allows_backup: Optional[bool] = None
    permission_count: int = 0
    certificate_issuer: Optional[str] = None
    certificate_subject: Optional[str] = None
    sha256: Optional[str] = None


class InvestigationReport(BaseModel):
    app_info: AppInfo
    findings: List[Finding] = Field(default_factory=list)
    iocs: List[IOC] = Field(default_factory=list)
    mitre_mappings: List[Dict[str, Any]] = Field(default_factory=list)
    attack_chain: List[str] = Field(default_factory=list)
    finding_count: int = 0
    risk_score: int = 0
    risk_label: str = "MINIMAL"
    confidence_score: int = 0
    retried_agents: List[str] = Field(default_factory=list)
    llm_explanation: Optional[str] = None
    analysis_capabilities: Dict[str, str] = Field(default_factory=dict)


class ReasoningRequest(BaseModel):
    app_info: AppInfo
    findings: List[Finding] = Field(default_factory=list)
    iocs: List[IOC] = Field(default_factory=list)
