"""FastAPI application for Module 5 Exposure Discovery."""
import os
import json
import logging
from uuid import UUID
from pathlib import Path
from fastapi import FastAPI, HTTPException, status
from sqlalchemy import select
from module_01_scope_management.db import SessionLocal, engine, Base
from module_01_scope_management.models import ModuleStatus, PipelineStatus
from .engine import ExposureEngine
from .models import ExposureFinding
from .schemas import ExposureExport, ExposureFindingSchema

logger = logging.getLogger(__name__)
Base.metadata.create_all(bind=engine)

app = FastAPI(
    title="Module 05: Exposure Discovery Engine",
    version="1.0.0",
    description="Authorized Attack Surface Exposure Assessment Engine"
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
                detail=f"Module 05 execution refused for scope {s_uuid}. Prerequisites incomplete (module_04_attack_surface_inventory required)."
            )

@app.post("/exposure/{scope_id}/run", response_model=ExposureExport)
async def run_exposure_discovery(scope_id: str):
    gate(scope_id)
    engine_inst = ExposureEngine(scope_id)
    await engine_inst.run_all()
    return get_exposure_findings(scope_id)

@app.get("/exposure/{scope_id}", response_model=ExposureExport)
def get_exposure_findings(scope_id: str):
    s_str = str(scope_id)
    with SessionLocal() as session:
        findings = session.scalars(
            select(ExposureFinding).where(ExposureFinding.scope_id == s_str)
        ).all()

        schemas = []
        counts = {"CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0, "INFO": 0}

        for f in findings:
            sev = (f.severity or "INFO").upper()
            if sev in counts:
                counts[sev] += 1
            schemas.append(ExposureFindingSchema(
                id=str(f.id),
                scope_id=str(f.scope_id),
                asset_id=str(f.asset_id) if f.asset_id else None,
                finding_type=f.finding_type,
                category=f.category,
                description=f.description,
                severity=f.severity,
                confidence=f.confidence,
                waf_detected=f.waf_detected or False,
                in_scope_confirmed=f.in_scope_confirmed or True,
                details=f.details or {},
                first_seen=f.first_seen.isoformat() if f.first_seen else ""
            ))

        export = ExposureExport(
            scope_id=s_str,
            counts=counts,
            exposures=schemas
        )

        out_dir = Path("output")
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / f"{s_str}.json"
        out_file.write_text(export.model_dump_json(indent=2), encoding="utf-8")

        return export

@app.get("/exposure/{scope_id}/export")
def export_exposure_json(scope_id: str):
    return get_exposure_findings(scope_id)
