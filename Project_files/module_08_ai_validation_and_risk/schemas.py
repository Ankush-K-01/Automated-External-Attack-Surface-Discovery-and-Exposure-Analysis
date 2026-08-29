"""Pydantic schemas for Module 8 AI Validation & Risk Prioritization."""
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

class UnifiedFindingSchema(BaseModel):
    id: str
    scope_id: str
    source_module: str
    finding_type: str
    title: str
    description: Optional[str] = None
    severity: str = "MEDIUM"
    cvss_score: Optional[float] = None
    epss_score: Optional[float] = None
    is_cisa_kev: bool = False
    waf_detected: bool = False
    risk_score: float = 0.0
    risk_level: str = "INFO"
    ai_triage_summary: Optional[str] = None
    remediation_guidance: Optional[str] = None
    details: Dict[str, Any] = Field(default_factory=dict)

class RiskPrioritizationExport(BaseModel):
    scope_id: str
    overall_risk_score: float = 0.0
    findings_count: int = 0
    unified_findings: List[UnifiedFindingSchema] = Field(default_factory=list)
    risk_summary: Dict[str, int] = Field(default_factory=dict)
