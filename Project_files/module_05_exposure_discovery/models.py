"""SQLAlchemy Models for Module 5 Exposure Discovery."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, Float, DateTime, JSON, Text
from module_01_scope_management.db import Base

class ExposureFinding(Base):
    __tablename__ = "exposure_findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    asset_id = Column(String, nullable=True, index=True)
    finding_type = Column(String, nullable=False, index=True)
    category = Column(String, nullable=False)
    description = Column(Text, nullable=False)
    severity = Column(String, nullable=False, default="INFO")
    confidence = Column(Float, nullable=False, default=1.0)
    waf_detected = Column(Boolean, default=False)
    in_scope_confirmed = Column(Boolean, default=True)
    details = Column(JSON, default=dict)
    first_seen = Column(DateTime, default=datetime.utcnow)

class SecurityHeaderFinding(Base):
    __tablename__ = "security_header_findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    url = Column(String, nullable=False)
    header_name = Column(String, nullable=False)
    status = Column(String, nullable=False)  # PRESENT, MISSING

class DiscoveredForm(Base):
    __tablename__ = "discovered_forms"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    url = Column(String, nullable=False)
    method = Column(String, nullable=False, default="GET")
    inputs = Column(JSON, default=list)

class TechFingerprint(Base):
    __tablename__ = "tech_fingerprints"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    asset_id = Column(String, nullable=True)
    target = Column(String, nullable=False)
    technology = Column(String, nullable=False)
    version = Column(String, nullable=True)
    category = Column(String, nullable=True)

class TLSFinding(Base):
    __tablename__ = "tls_findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    asset_id = Column(String, nullable=True)
    target = Column(String, nullable=False)
    issue = Column(String, nullable=False)
    severity = Column(String, nullable=False, default="MEDIUM")

class ExposedSecret(Base):
    __tablename__ = "exposed_secrets"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    asset_id = Column(String, nullable=True)
    url = Column(String, nullable=False)
    secret_type = Column(String, nullable=False)
    match_snippet = Column(Text, nullable=False)

class TakeoverCandidate(Base):
    __tablename__ = "takeover_candidates"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    cname = Column(String, nullable=False)
    service = Column(String, nullable=False)
    status = Column(String, nullable=False, default="POTENTIAL_TAKEOVER")

class Module5SubtaskStatus(Base):
    __tablename__ = "module5_subtask_status"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    subtask_name = Column(String, nullable=False)
    completed = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=datetime.utcnow)
