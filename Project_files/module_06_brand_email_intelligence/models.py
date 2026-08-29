"""SQLAlchemy Models for Module 6 Brand & Email Intelligence."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, Float, DateTime, JSON, Text
from module_01_scope_management.db import Base

class EmailAuthFinding(Base):
    __tablename__ = "email_auth_findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    domain = Column(String, nullable=False, index=True)
    record_type = Column(String, nullable=False)  # SPF, DMARC, DKIM, BIMI
    raw_record = Column(Text, nullable=True)
    status = Column(String, nullable=False, default="PASS")  # PASS, WEAK, MISSING, INVALID
    policy = Column(String, nullable=True)
    issues = Column(JSON, default=list)
    details = Column(JSON, default=dict)
    checked_at = Column(DateTime, default=datetime.utcnow)

class LookalikeDomain(Base):
    __tablename__ = "lookalike_domains"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    target_domain = Column(String, nullable=False, index=True)
    permutation_domain = Column(String, nullable=False, index=True)
    fuzzer_type = Column(String, nullable=False)
    resolved_ip = Column(String, nullable=True)
    mx_records = Column(JSON, default=list)
    ns_records = Column(JSON, default=list)
    is_registered = Column(Boolean, default=False)
    phishing_risk = Column(String, default="INFO")  # HIGH, MEDIUM, LOW, INFO
    details = Column(JSON, default=dict)
    first_seen = Column(DateTime, default=datetime.utcnow)

class LookalikeCertMatch(Base):
    __tablename__ = "lookalike_cert_matches"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    permutation_domain = Column(String, nullable=False, index=True)
    cert_issuer = Column(String, nullable=True)
    cert_subject = Column(String, nullable=True)
    valid_from = Column(String, nullable=True)
    valid_to = Column(String, nullable=True)
    fingerprint = Column(String, nullable=True)
    details = Column(JSON, default=dict)

class BrandImpersonationFinding(Base):
    __tablename__ = "brand_impersonation_findings"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    brand_name = Column(String, nullable=False)
    platform = Column(String, nullable=False)  # PlayStore, AppStore, SocialMedia
    title = Column(String, nullable=False)
    url = Column(String, nullable=False)
    confidence = Column(Float, default=0.5)
    details = Column(JSON, default=dict)

class Module6SubtaskStatus(Base):
    __tablename__ = "module6_subtask_status"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    subtask_name = Column(String, nullable=False)
    completed = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=datetime.utcnow)
