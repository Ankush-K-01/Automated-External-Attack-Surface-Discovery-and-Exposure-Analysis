"""FastAPI Application for Module 7 Threat Intelligence."""
import os
import json
import logging
from uuid import UUID
from pathlib import Path
from fastapi import FastAPI, HTTPException, status
from sqlalchemy import select
from module_01_scope_management.db import SessionLocal, engine, Base
from module_01_scope_management.models import ModuleStatus, PipelineStatus
from .engine import ThreatIntelEngine
from .models import CVEMatch, KEVFlag, EPSSScore, OSINTMention
from .schemas import (
    ThreatIntelExport, CVEMatchSchema, KEVFlagSchema,
    EPSSScoreSchema, OSINTMentionSchema
)

logger = logging.getLogger(__name__)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Module 07: Threat Intelligence Engine",
    version="1.0.0",
    description="CVE Matching, CISA KEV, FIRST.org EPSS, and OSINT Threat Intelligence"
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
                detail=f"Module 07 execution refused for scope {s_uuid}. Prerequisites incomplete (module_04_attack_surface_inventory required)."
            )

@app.post("/threat-intel/{scope_id}/run", response_model=ThreatIntelExport)
async def run_threat_intel(scope_id: str):
    gate(scope_id)
    engine_inst = ThreatIntelEngine(scope_id)
    await engine_inst.run_all()
    return get_threat_intel(scope_id)

@app.get("/threat-intel/{scope_id}", response_model=ThreatIntelExport)
def get_threat_intel(scope_id: str):
    s_str = str(scope_id)
    with SessionLocal() as session:
        cves = session.scalars(
            select(CVEMatch).where(CVEMatch.scope_id == s_str)
        ).all()

        kevs = session.scalars(
            select(KEVFlag).where(KEVFlag.scope_id == s_str)
        ).all()

        epss = session.scalars(
            select(EPSSScore).where(EPSSScore.scope_id == s_str)
        ).all()

        osints = session.scalars(
            select(OSINTMention).where(OSINTMention.scope_id == s_str)
        ).all()

        export = ThreatIntelExport(
            scope_id=s_str,
            cve_matches=[
                CVEMatchSchema(
                    id=str(c.id),
                    scope_id=str(c.scope_id),
                    asset_id=str(c.asset_id) if c.asset_id else None,
                    technology=c.technology,
                    version=c.version,
                    cve_id=c.cve_id,
                    cvss_score=c.cvss_score,
                    severity=c.severity or "UNKNOWN",
                    summary=c.summary,
                    published_date=c.published_date,
                    is_cisa_kev=c.is_cisa_kev or False
                )
                for c in cves
            ],
            kev_flags=[
                KEVFlagSchema(
                    id=str(k.id),
                    scope_id=str(k.scope_id),
                    cve_id=k.cve_id,
                    vendor_project=k.vendor_project,
                    product=k.product,
                    vulnerability_name=k.vulnerability_name,
                    date_added=k.date_added,
                    short_description=k.short_description,
                    required_action=k.required_action,
                    due_date=k.due_date
                )
                for k in kevs
            ],
            epss_scores=[
                EPSSScoreSchema(
                    id=str(e.id),
                    scope_id=str(e.scope_id),
                    cve_id=e.cve_id,
                    epss=e.epss,
                    percentile=e.percentile,
                    date=e.date
                )
                for e in epss
            ],
            osint_mentions=[
                OSINTMentionSchema(
                    id=str(o.id),
                    scope_id=str(o.scope_id),
                    domain_or_brand=o.domain_or_brand,
                    title=o.title,
                    source=o.source,
                    snippet=o.snippet,
                    url=o.url,
                    confidence=o.confidence or 0.5
                )
                for o in osints
            ],
            data_sources={
                "NVD_API": "https://services.nvd.nist.gov/rest/json/cves/2.0 (Public rate-limited)",
                "CISA_KEV": "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json (Free public feed)",
                "FIRST_EPSS": "https://api.first.org/data/v1/epss (Free public API)"
            }
        )

        out_dir = Path("output")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{s_str}.json"
        out_file.write_text(export.model_dump_json(indent=2), encoding="utf-8")

        return export

@app.get("/threat-intel/{scope_id}/export")
def export_threat_intel_json(scope_id: str):
    return get_threat_intel(scope_id)
