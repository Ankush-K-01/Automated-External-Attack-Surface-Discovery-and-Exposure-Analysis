from __future__ import annotations
from contextlib import nullcontext as _nullctx
import sys, logging, json
from pathlib import Path
from uuid import UUID
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from module_01_scope_management.db import get_session
from module_01_scope_management.models import ModuleStatus, PipelineStatus
from module_01_scope_management.pipeline_status import bind_session, reset_session, mark_module_completed, mark_module_failed
from .models import CorrelationFinding
from .schemas import CorrelationExport
from .engine import IdentityCorrelationEngine

if sys.version_info[:2] != (3, 13):
    raise RuntimeError("Module 3 requires Python 3.13.x")

app = FastAPI(title="ASM Module 3: Identity & Asset Correlation")
NAME = "module_03_identity_correlation"
log = logging.getLogger(__name__)

def gated(s: Session, scope: UUID):
    row = s.query(ModuleStatus).filter_by(scope_id=scope, module_name="module_02_asset_discovery").one_or_none()
    if not row or row.status is not PipelineStatus.COMPLETED:
        log.warning("scope_id=%s waiting on module_02_asset_discovery", scope)
        raise HTTPException(409, "waiting on module_02_asset_discovery")

def result(s: Session, scope: UUID):
    rows = s.query(CorrelationFinding).filter_by(scope_id=scope).all()
    return CorrelationExport(
        scope_id=str(scope),
        correlation_findings=[{"type": x.finding_type, "description": x.description, "confidence": x.confidence, "assets": x.related_asset_ids} for x in rows]
    )

@app.post("/correlation/{scope_id}/run", response_model=CorrelationExport)
def run(scope_id: UUID, s: Session = Depends(get_session)):
    gated(s, scope_id)
    try:
        engine = IdentityCorrelationEngine(scope_id)
        run_data = engine.run_pipeline()
        
        Path("output").mkdir(exist_ok=True)
        path = Path("output") / f"{scope_id}.json"
        path.write_text(json.dumps(run_data, indent=2), encoding="utf-8")
        
        token = bind_session(s)
        try:
            mark_module_completed(scope_id, NAME, str(path))
        finally:
            reset_session(token)
            
        return result(s, scope_id)
    except Exception as exc:
        log.error(f"Correlation failed for {scope_id}: {exc}", exc_info=True)
        token = bind_session(s)
        try:
            mark_module_failed(scope_id, NAME, str(exc))
            s.commit()
        finally:
            reset_session(token)
        raise HTTPException(500, f"correlation failed: {exc}") from exc

@app.get("/correlation/{scope_id}", response_model=CorrelationExport)
def get(scope_id: UUID, s: Session = Depends(get_session)):
    return result(s, scope_id)

@app.get("/correlation/{scope_id}/export", response_model=CorrelationExport)
def export(scope_id: UUID, s: Session = Depends(get_session)):
    return result(s, scope_id)
