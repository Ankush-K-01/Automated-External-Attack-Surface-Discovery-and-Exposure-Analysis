"""Pydantic schemas for Module 7 Threat Intelligence."""
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

class CVEMatchSchema(BaseModel):
    id: str
    scope_id: str
    asset_id: Optional[str] = None
    technology: str
    version: Optional[str] = None
    cve_id: str
    cvss_score: Optional[float] = None
    severity: str = "UNKNOWN"
    summary: Optional[str] = None
    published_date: Optional[str] = None
    is_cisa_kev: bool = False

class KEVFlagSchema(BaseModel):
    id: str
    scope_id: str
    cve_id: str
    vendor_project: Optional[str] = None
    product: Optional[str] = None
    vulnerability_name: Optional[str] = None
    date_added: Optional[str] = None
    short_description: Optional[str] = None
    required_action: Optional[str] = None
    due_date: Optional[str] = None

class EPSSScoreSchema(BaseModel):
    id: str
    scope_id: str
    cve_id: str
    epss: float
    percentile: Optional[float] = None
    date: Optional[str] = None

class OSINTMentionSchema(BaseModel):
    id: str
    scope_id: str
    domain_or_brand: str
    title: str
    source: str
    snippet: Optional[str] = None
    url: Optional[str] = None
    confidence: float = 0.5

class ThreatIntelExport(BaseModel):
    scope_id: str
    cve_matches: List[CVEMatchSchema] = Field(default_factory=list)
    kev_flags: List[KEVFlagSchema] = Field(default_factory=list)
    epss_scores: List[EPSSScoreSchema] = Field(default_factory=list)
    osint_mentions: List[OSINTMentionSchema] = Field(default_factory=list)
    data_sources: Dict[str, str] = Field(default_factory=dict)
