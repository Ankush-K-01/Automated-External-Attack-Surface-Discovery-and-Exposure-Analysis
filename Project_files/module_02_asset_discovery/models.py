"""SQLAlchemy models for Module 2 Asset Discovery Engine."""
from __future__ import annotations
from datetime import datetime
from uuid import UUID
from sqlalchemy import DateTime, ForeignKey, Integer, String, Text, UniqueConstraint, func
from sqlalchemy import UUID as PG_UUID
from sqlalchemy.orm import Mapped, mapped_column, relationship
from module_01_scope_management.db import Base

class DiscoveredSubdomain(Base):
    __tablename__ = "discovered_subdomains"
    __table_args__ = (UniqueConstraint("scope_id", "subdomain"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("scopes.scope_id", ondelete="CASCADE"), index=True)
    subdomain: Mapped[str] = mapped_column(String(253))
    discovered_by: Mapped[str | None] = mapped_column(String(100))

class ResolvedIP(Base):
    __tablename__ = "resolved_ips"
    __table_args__ = (UniqueConstraint("scope_id", "ip", "domain"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("scopes.scope_id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(45))
    domain: Mapped[str | None] = mapped_column(String(253))
    is_ipv6: Mapped[bool] = mapped_column(default=False)

class DNSRecord(Base):
    __tablename__ = "dns_records"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("scopes.scope_id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(253))
    record_type: Mapped[str] = mapped_column(String(10))
    value: Mapped[str] = mapped_column(Text)

class WhoisRecord(Base):
    __tablename__ = "whois_records"
    __table_args__ = (UniqueConstraint("scope_id", "domain"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("scopes.scope_id", ondelete="CASCADE"), index=True)
    domain: Mapped[str] = mapped_column(String(253))
    registrar: Mapped[str | None] = mapped_column(String(255))
    organization: Mapped[str | None] = mapped_column(String(255))
    creation_date: Mapped[str | None] = mapped_column(String(100))
    expiry_date: Mapped[str | None] = mapped_column(String(100))
    nameservers: Mapped[str | None] = mapped_column(Text)
    raw_whois: Mapped[str | None] = mapped_column(Text)

class OpenPort(Base):
    __tablename__ = "open_ports"
    __table_args__ = (UniqueConstraint("scope_id", "ip", "port", "protocol"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("scopes.scope_id", ondelete="CASCADE"), index=True)
    ip: Mapped[str] = mapped_column(String(45))
    port: Mapped[int] = mapped_column(Integer)
    protocol: Mapped[str] = mapped_column(String(10), default="tcp")
    service_name: Mapped[str | None] = mapped_column(String(100))
    service_version: Mapped[str | None] = mapped_column(String(255))
    banner: Mapped[str | None] = mapped_column(Text)

class HistoricEndpoint(Base):
    __tablename__ = "historic_endpoints"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("scopes.scope_id", ondelete="CASCADE"), index=True)
    domain: Mapped[str | None] = mapped_column(String(253))
    url: Mapped[str] = mapped_column(Text)

class MobileAppCandidate(Base):
    __tablename__ = "mobile_app_candidates"
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("scopes.scope_id", ondelete="CASCADE"), index=True)
    app_name: Mapped[str] = mapped_column(String(255))
    package_id: Mapped[str] = mapped_column(String(255))
    match_confidence: Mapped[float] = mapped_column(default=0.0)

class Module2SubtaskStatus(Base):
    __tablename__ = "module2_subtask_status"
    __table_args__ = (UniqueConstraint("scope_id", "phase_name"),)
    id: Mapped[int] = mapped_column(Integer, primary_key=True)
    scope_id: Mapped[UUID] = mapped_column(PG_UUID(as_uuid=True), ForeignKey("scopes.scope_id", ondelete="CASCADE"), index=True)
    phase_name: Mapped[str] = mapped_column(String(100))
    status: Mapped[str] = mapped_column(String(50), default="COMPLETED")
    completed_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), server_default=func.now())
