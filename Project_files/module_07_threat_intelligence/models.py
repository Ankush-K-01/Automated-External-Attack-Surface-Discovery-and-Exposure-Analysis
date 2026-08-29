"""SQLAlchemy Models for Module 7 Threat Intelligence."""
import uuid
from datetime import datetime
from sqlalchemy import Column, String, Boolean, Float, DateTime, JSON, Text
from module_01_scope_management.db import Base

class CVEMatch(Base):
    __tablename__ = "cve_matches"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    asset_id = Column(String, nullable=True, index=True)
    technology = Column(String, nullable=False)
    version = Column(String, nullable=True)
    cve_id = Column(String, nullable=False, index=True)
    cvss_score = Column(Float, nullable=True)
    severity = Column(String, nullable=False, default="UNKNOWN")
    summary = Column(Text, nullable=True)
    published_date = Column(String, nullable=True)
    is_cisa_kev = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)

class KEVFlag(Base):
    __tablename__ = "kev_flags"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    cve_id = Column(String, nullable=False, index=True)
    vendor_project = Column(String, nullable=True)
    product = Column(String, nullable=True)
    vulnerability_name = Column(String, nullable=True)
    date_added = Column(String, nullable=True)
    short_description = Column(Text, nullable=True)
    required_action = Column(Text, nullable=True)
    due_date = Column(String, nullable=True)

class EPSSScore(Base):
    __tablename__ = "epss_scores"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    cve_id = Column(String, nullable=False, index=True)
    epss = Column(Float, nullable=False)
    percentile = Column(Float, nullable=True)
    date = Column(String, nullable=True)

class OSINTMention(Base):
    __tablename__ = "osint_mentions"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    domain_or_brand = Column(String, nullable=False)
    title = Column(String, nullable=False)
    source = Column(String, nullable=False)
    snippet = Column(Text, nullable=True)
    url = Column(String, nullable=True)
    confidence = Column(Float, default=0.5)

class Module7SubtaskStatus(Base):
    __tablename__ = "module7_subtask_status"

    id = Column(String, primary_key=True, default=lambda: str(uuid.uuid4()))
    scope_id = Column(String, nullable=False, index=True)
    subtask_name = Column(String, nullable=False)
    completed = Column(Boolean, default=False)
    updated_at = Column(DateTime, default=datetime.utcnow)
