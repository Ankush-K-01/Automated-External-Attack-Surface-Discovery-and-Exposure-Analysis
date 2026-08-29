"""SQLAlchemy Models for Module 8 AI Validation & Risk Prioritization."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, Float, DateTime, JSON, Text
from module_01_scope_management.db import Base

class UnifiedFinding(Base):
    __tablename__ = "unified_findings"
    __table_args__ = {'extend_existing': True}

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    source_module = Column(String, nullable=False)
    finding_type = Column(String, nullable=False, index=True)
    title = Column(String, nullable=False)
    description = Column(Text, nullable=True)
    severity = Column(String, nullable=False, default="MEDIUM")
    cvss_score = Column(Float, nullable=True)
    epss_score = Column(Float, nullable=True)
    is_cisa_kev = Column(Boolean, default=False)
    waf_detected = Column(Boolean, default=False)
    risk_score = Column(Float, nullable=False, default=0.0)
    risk_level = Column(String, nullable=False, default="INFO")
    ai_triage_summary = Column(Text, nullable=True)
    remediation_guidance = Column(Text, nullable=True)
    details = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

class Module8SubtaskStatus(Base):
    __tablename__ = "module8_subtask_status"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    subtask_name = Column(String, nullable=False)
    completed = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=datetime.utcnow)
