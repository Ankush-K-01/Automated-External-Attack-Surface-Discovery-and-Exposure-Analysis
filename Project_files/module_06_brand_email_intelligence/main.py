"""FastAPI Application for Module 6 Brand & Email Intelligence."""
import os
import json
import logging
from uuid import UUID
from pathlib import Path
from fastapi import FastAPI, HTTPException, status
from sqlalchemy import select
from module_01_scope_management.db import SessionLocal, engine, Base
from module_01_scope_management.models import ModuleStatus, PipelineStatus
from .engine import BrandEmailEngine
from .models import (
    EmailAuthFinding, LookalikeDomain, LookalikeCertMatch, BrandImpersonationFinding
)
from .schemas import (
    BrandIntelExport, EmailAuthSchema, LookalikeDomainSchema,
    LookalikeCertSchema, BrandImpersonationSchema
)

logger = logging.getLogger(__name__)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Module 06: Brand & Email Intelligence",
    version="1.0.0",
    description="Corporate Email Risk, Typosquatting, and Brand Protection Audit Engine"
)

def gate(scope_id: str | UUID):
    s_uuid = UUID(str(scope_id)) if isinstance(scope_id, str) else scope_id
    with SessionLocal() as session:
        all_completed = session.scalars(
            select(ModuleStatus.module_name).where(
                ModuleStatus.scope_id == s_uuid,
                ModuleStatus.status == PipelineStatus.COMPLETED
            )
        ).all()

        if "module_04_attack_surface_inventory" not in all_completed:
            logger.warning(f"scope_id={s_uuid} waiting on module_04_attack_surface_inventory")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Module 06 execution refused for scope {s_uuid}. Prerequisites incomplete (module_04_attack_surface_inventory required)."
            )

@app.post("/brand-intel/{scope_id}/run", response_model=BrandIntelExport)
async def run_brand_intel(scope_id: str):
    gate(scope_id)
    engine_inst = BrandEmailEngine(scope_id)
    await engine_inst.run_all()
    return get_brand_intel(scope_id)

@app.get("/brand-intel/{scope_id}", response_model=BrandIntelExport)
def get_brand_intel(scope_id: str):
    s_str = str(scope_id)
    with SessionLocal() as session:
        email_findings = session.scalars(
            select(EmailAuthFinding).where(EmailAuthFinding.scope_id == s_str)
        ).all()

        lookalikes = session.scalars(
            select(LookalikeDomain).where(LookalikeDomain.scope_id == s_str)
        ).all()

        certs = session.scalars(
            select(LookalikeCertMatch).where(LookalikeCertMatch.scope_id == s_str)
        ).all()

        impersonations = session.scalars(
            select(BrandImpersonationFinding).where(BrandImpersonationFinding.scope_id == s_str)
        ).all()

        export = BrandIntelExport(
            scope_id=s_str,
            email_auth=[
                EmailAuthSchema(
                    id=str(f.id),
                    scope_id=str(f.scope_id),
                    domain=f.domain,
                    record_type=f.record_type,
                    raw_record=f.raw_record,
                    status=f.status,
                    policy=f.policy,
                    issues=f.issues or [],
                    details=f.details or {}
                )
                for f in email_findings
            ],
            lookalike_domains=[
                LookalikeDomainSchema(
                    id=str(l.id),
                    scope_id=str(l.scope_id),
                    target_domain=l.target_domain,
                    permutation_domain=l.permutation_domain,
                    fuzzer_type=l.fuzzer_type,
                    resolved_ip=l.resolved_ip,
                    mx_records=l.mx_records or [],
                    ns_records=l.ns_records or [],
                    is_registered=l.is_registered or False,
                    phishing_risk=l.phishing_risk or "INFO",
                    details=l.details or {}
                )
                for l in lookalikes
            ],
            lookalike_certs=[
                LookalikeCertSchema(
                    id=str(c.id),
                    scope_id=str(c.scope_id),
                    permutation_domain=c.permutation_domain,
                    cert_issuer=c.cert_issuer,
                    cert_subject=c.cert_subject,
                    valid_from=c.valid_from,
                    valid_to=c.valid_to,
                    fingerprint=c.fingerprint
                )
                for c in certs
            ],
            impersonations=[
                BrandImpersonationSchema(
                    id=str(i.id),
                    scope_id=str(i.scope_id),
                    brand_name=i.brand_name,
                    platform=i.platform,
                    title=i.title,
                    url=i.url,
                    confidence=i.confidence or 0.5,
                    details=i.details or {}
                )
                for i in impersonations
            ],
            gap_notes=[
                "Backlink audit: no free data source integrated (out-of-scope for free tier)",
                "Social/App store impersonation is evaluated as best-effort store search heuristics."
            ]
        )

        out_dir = Path("output")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{s_str}.json"
        out_file.write_text(export.model_dump_json(indent=2), encoding="utf-8")

        return export

@app.get("/brand-intel/{scope_id}/export")
def export_brand_intel_json(scope_id: str):
    return get_brand_intel(scope_id)
