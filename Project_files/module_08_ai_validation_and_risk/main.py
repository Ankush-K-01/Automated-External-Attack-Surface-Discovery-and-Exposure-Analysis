"""FastAPI Application for Module 8 AI Validation & Risk Prioritization."""
import os
import json
import logging
from uuid import UUID
from pathlib import Path
from fastapi import FastAPI, HTTPException, status
from sqlalchemy import select
from module_01_scope_management.db import SessionLocal, engine, Base
from module_01_scope_management.models import ModuleStatus, PipelineStatus
from .engine import AIRiskEngine
from .models import UnifiedFinding
from .schemas import RiskPrioritizationExport, UnifiedFindingSchema

logger = logging.getLogger(__name__)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Module 08: AI Validation & Risk Prioritization",
    version="1.0.0",
    description="Unified Finding Normalization, Weighted Risk Scoring, and AI Triage"
)

REQUIRED_UPSTREAM_MODULES = [
    "module_05_exposure_discovery",
    "module_06_brand_email_intelligence",
    "module_07_threat_intelligence"
]

def gate(scope_id: str | UUID):
    s_uuid = UUID(str(scope_id)) if isinstance(scope_id, str) else scope_id
    with SessionLocal() as session:
        completed = session.scalars(
            select(ModuleStatus.module_name).where(
                ModuleStatus.scope_id == s_uuid,
                ModuleStatus.status == PipelineStatus.COMPLETED
            )
        ).all()

        missing = [mod for mod in REQUIRED_UPSTREAM_MODULES if mod not in completed]
        if missing:
            logger.warning(f"scope_id={s_uuid} waiting on upstream modules: {missing}")
            raise HTTPException(
                status_code=status.HTTP_409_CONFLICT,
                detail=f"Module 08 execution refused for scope {s_uuid}. Prerequisites incomplete. Missing: {', '.join(missing)}"
            )

@app.post("/validation/{scope_id}/run", response_model=RiskPrioritizationExport)
async def run_validation(scope_id: str):
    gate(scope_id)
    engine_inst = AIRiskEngine(scope_id)
    await engine_inst.run_all()
    return get_validation(scope_id)

@app.get("/validation/{scope_id}", response_model=RiskPrioritizationExport)
def get_validation(scope_id: str):
    s_str = str(scope_id)
    with SessionLocal() as session:
        findings = session.scalars(
            select(UnifiedFinding).where(UnifiedFinding.scope_id == s_str)
        ).all()

        schemas = [
            UnifiedFindingSchema(
                id=str(f.id),
                scope_id=str(f.scope_id),
                source_module=f.source_module,
                finding_type=f.finding_type,
                title=f.title,
                description=f.description,
                severity=f.severity or "MEDIUM",
                cvss_score=f.cvss_score,
                epss_score=f.epss_score,
                is_cisa_kev=f.is_cisa_kev or False,
                waf_detected=f.waf_detected or False,
                risk_score=f.risk_score or 0.0,
                risk_level=f.risk_level or "INFO",
                ai_triage_summary=f.ai_triage_summary,
                remediation_guidance=f.remediation_guidance,
                details=f.details or {}
            )
            for f in findings
        ]

        summary = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}
        total_score = 0.0
        for s in schemas:
            summary[s.risk_level] = summary.get(s.risk_level, 0) + 1
            total_score += s.risk_score

        overall = round(total_score / len(schemas), 1) if schemas else 0.0

        export = RiskPrioritizationExport(
            scope_id=s_str,
            overall_risk_score=overall,
            findings_count=len(schemas),
            unified_findings=schemas,
            risk_summary=summary
        )

        out_dir = Path("output")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{s_str}.json"
        out_file.write_text(export.model_dump_json(indent=2), encoding="utf-8")

        return export

@app.get("/validation/{scope_id}/export")
def export_validation_json(scope_id: str):
    return get_validation(scope_id)
