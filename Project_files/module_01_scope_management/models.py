"""SQLAlchemy models for normalized, relational scope storage."""
from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from uuid import UUID, uuid4
from sqlalchemy import DateTime, Enum, ForeignKey, Integer, String, UniqueConstraint, func
from sqlalchemy import JSON as JSON, UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from .db import Base


class ScopeStatus(StrEnum):
    DRAFT = "DRAFT"
    VALIDATED = "VALIDATED"
    DISPATCHED = "DISPATCHED"
    ERROR = "ERROR"


class TldSource(StrEnum):
    USER_SUPPLIED = "user_supplied"
    AUTO_DETECTED = "auto_detected"


class PipelineStatus(StrEnum):
    STARTED = "STARTED"
    COMPLETED = "COMPLETED"
    ERROR = "ERROR"


class Scope(Base):
    __tablename__ = "scopes"
    scope_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), primary_key=True, default=uuid4)
    status: Mapped[ScopeStatus] = mapped_column(Enum(ScopeStatus, name="scope_status"), default=ScopeStatus.DRAFT)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
    updated_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now(), onupdate=func.now())
    domains: Mapped[list[ScopeDomain]] = relationship(cascade="all, delete-orphan")
    asns: Mapped[list[ScopeAsn]] = relationship(cascade="all, delete-orphan")
    cidrs: Mapped[list[ScopeCidr]] = relationship(cascade="all, delete-orphan")
    orgs: Mapped[list[ScopeOrg]] = relationship(cascade="all, delete-orphan")
    tlds: Mapped[list[ScopeTld]] = relationship(cascade="all, delete-orphan")
    policy: Mapped[ScanPolicy | None] = relationship(cascade="all, delete-orphan", uselist=False)


class TargetBase:
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(ForeignKey("scopes.scope_id", ondelete="CASCADE"), index=True)


class ScopeDomain(TargetBase, Base):
    __tablename__ = "scope_domains"; __table_args__ = (UniqueConstraint("scope_id", "domain"),)
    domain: Mapped[str] = mapped_column(String(253)); is_seed: Mapped[bool] = mapped_column(default=True)


class ScopeAsn(TargetBase, Base):
    __tablename__ = "scope_asns"; __table_args__ = (UniqueConstraint("scope_id", "asn"),)
    asn: Mapped[int] = mapped_column()


class ScopeCidr(TargetBase, Base):
    __tablename__ = "scope_cidrs"; __table_args__ = (UniqueConstraint("scope_id", "cidr"),)
    cidr: Mapped[str] = mapped_column(String(43))


class ScopeOrg(TargetBase, Base):
    __tablename__ = "scope_orgs"; __table_args__ = (UniqueConstraint("scope_id", "org_name"),)
    org_name: Mapped[str] = mapped_column(String(512))


class ScopeTld(TargetBase, Base):
    __tablename__ = "scope_tlds"; __table_args__ = (UniqueConstraint("scope_id", "tld"),)
    tld: Mapped[str] = mapped_column(String(63)); source: Mapped[TldSource] = mapped_column(Enum(TldSource, name="tld_source"))


class ScanPolicy(TargetBase, Base):
    __tablename__ = "scan_policies"
    policy_json: Mapped[dict] = mapped_column(JSON, default=dict)


class ModuleStatus(Base):
    __tablename__ = "module_status"; __table_args__ = (UniqueConstraint("scope_id", "module_name"),)
    id: Mapped[int] = mapped_column(primary_key=True); scope_id: Mapped[UUID] = mapped_column(ForeignKey("scopes.scope_id"), index=True)
    module_name: Mapped[str] = mapped_column(String(100)); status: Mapped[PipelineStatus] = mapped_column(Enum(PipelineStatus, name="pipeline_status"))
    completed_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True)); output_ref: Mapped[str | None] = mapped_column(String(1024)); error: Mapped[str | None] = mapped_column(String(2048))
