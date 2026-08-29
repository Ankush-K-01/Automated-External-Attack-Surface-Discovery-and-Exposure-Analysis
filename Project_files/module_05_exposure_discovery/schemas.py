"""Pydantic schemas for Module 05 Exposure Discovery."""
from pydantic import BaseModel, Field
from typing import List, Dict, Optional, Any

class ExposureFindingSchema(BaseModel):
    id: str
    scope_id: str
    asset_id: Optional[str] = None
    finding_type: str
    category: str
    description: str
    severity: str = "INFO"
    confidence: float = 1.0
    waf_detected: bool = False
    in_scope_confirmed: bool = True
    details: Dict[str, Any] = Field(default_factory=dict)
    first_seen: str = ""

class ExposureExport(BaseModel):
    scope_id: str
    counts: Dict[str, int] = Field(default_factory=dict)
    exposures: List[ExposureFindingSchema] = Field(default_factory=list)
