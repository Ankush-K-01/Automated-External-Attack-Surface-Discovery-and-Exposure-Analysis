"""Pydantic schemas for Module 6 Brand & Email Intelligence."""
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

class EmailAuthSchema(BaseModel):
    id: str
    scope_id: str
    domain: str
    record_type: str
    raw_record: Optional[str] = None
    status: str = "PASS"
    policy: Optional[str] = None
    issues: List[str] = Field(default_factory=list)
    details: Dict[str, Any] = Field(default_factory=dict)

class LookalikeDomainSchema(BaseModel):
    id: str
    scope_id: str
    target_domain: str
    permutation_domain: str
    fuzzer_type: str
    resolved_ip: Optional[str] = None
    mx_records: List[str] = Field(default_factory=list)
    ns_records: List[str] = Field(default_factory=list)
    is_registered: bool = False
    phishing_risk: str = "INFO"
    details: Dict[str, Any] = Field(default_factory=dict)

class LookalikeCertSchema(BaseModel):
    id: str
    scope_id: str
    permutation_domain: str
    cert_issuer: Optional[str] = None
    cert_subject: Optional[str] = None
    valid_from: Optional[str] = None
    valid_to: Optional[str] = None
    fingerprint: Optional[str] = None

class BrandImpersonationSchema(BaseModel):
    id: str
    scope_id: str
    brand_name: str
    platform: str
    title: str
    url: str
    confidence: float = 0.5
    details: Dict[str, Any] = Field(default_factory=dict)

class BrandIntelExport(BaseModel):
    scope_id: str
    email_auth: List[EmailAuthSchema] = Field(default_factory=list)
    lookalike_domains: List[LookalikeDomainSchema] = Field(default_factory=list)
    lookalike_certs: List[LookalikeCertSchema] = Field(default_factory=list)
    impersonations: List[BrandImpersonationSchema] = Field(default_factory=list)
    gap_notes: List[str] = Field(default_factory=list)
