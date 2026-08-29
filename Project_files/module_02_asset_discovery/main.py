"""Module 2 Asset Discovery API Service."""
from __future__ import annotations
import asyncio
from contextlib import nullcontext as _nullctx
import json, logging, sys
from pathlib import Path
from uuid import UUID
from fastapi import Depends, FastAPI, HTTPException
from sqlalchemy.orm import Session
from module_01_scope_management.db import get_session
from module_01_scope_management.models import ModuleStatus, PipelineStatus, Scope, ScopeStatus
from module_01_scope_management.pipeline_status import bind_session, reset_session, mark_module_completed, mark_module_failed
from .models import DiscoveredSubdomain, ResolvedIP, DNSRecord, HistoricEndpoint, MobileAppCandidate, WhoisRecord, OpenPort
from .schemas import DiscoveryExport
from .engine import DiscoveryEngine

if sys.version_info[:2] != (3, 13): raise RuntimeError("Module 2 requires Python 3.13.x")
app = FastAPI(title="ASM Module 2: Asset Discovery"); log = logging.getLogger(__name__); NAME = "module_02_asset_discovery"; OUT = Path("output")

def allowed(session: Session, scope_id: UUID) -> Scope:
    prior = session.query(ModuleStatus).filter_by(scope_id=scope_id, module_name="module_01_scope_management").one_or_none()
    if not prior or prior.status is not PipelineStatus.COMPLETED:
        log.warning("scope_id=%s waiting on module_01_scope_management", scope_id)
        raise HTTPException(409, "waiting on module_01_scope_management")
    scope = session.get(Scope, scope_id)
    if not scope or scope.status is not ScopeStatus.DISPATCHED:
        raise HTTPException(409, "finalized Module 1 scope required")
    return scope

def payload(session: Session, scope_id: UUID) -> DiscoveryExport:
    subdomains = sorted({x.subdomain for x in session.query(DiscoveredSubdomain).filter_by(scope_id=scope_id)})
    ips = sorted({x.ip for x in session.query(ResolvedIP).filter_by(scope_id=scope_id)})
    dns_recs = [{"domain": x.domain, "type": x.record_type, "value": x.value} for x in session.query(DNSRecord).filter_by(scope_id=scope_id)]
    historic = [x.url for x in session.query(HistoricEndpoint).filter_by(scope_id=scope_id)]
    mobile = [{"name": x.app_name, "package_id": x.package_id, "confidence": x.match_confidence} for x in session.query(MobileAppCandidate).filter_by(scope_id=scope_id)]
    return DiscoveryExport(
        scope_id=str(scope_id),
        subdomains=subdomains,
        ips=ips,
        dns_records=dns_recs,
        historic_endpoints=historic,
        mobile_app_candidates=mobile
    )

@app.post("/discovery/{scope_id}/run", response_model=DiscoveryExport)
def run(scope_id: UUID, session: Session = Depends(get_session)):
    allowed(session, scope_id)
    try:
        engine = DiscoveryEngine(scope_id, session)
        asyncio.run(engine.run_pipeline())

        result = payload(session, scope_id)
        OUT.mkdir(exist_ok=True)
        path = OUT / f"{scope_id}.json"
        path.write_text(result.model_dump_json(indent=2), encoding="utf-8")
        
        token = bind_session(session)
        try:
            mark_module_completed(scope_id, NAME, str(path))
            session.commit()
        finally:
            reset_session(token)
        return result
    except Exception as exc:
        import traceback; traceback.print_exc()
        token = bind_session(session)
        try:
            with _nullctx():
                mark_module_failed(scope_id, NAME, str(exc))
                session.commit()
        finally:
            reset_session(token)
        raise HTTPException(500, f"discovery failed: {exc}") from exc

@app.get("/discovery/{scope_id}", response_model=DiscoveryExport)
def get(scope_id: UUID, session: Session = Depends(get_session)):
    return payload(session, scope_id)

@app.get("/discovery/{scope_id}/export", response_model=DiscoveryExport)
def export(scope_id: UUID, session: Session = Depends(get_session)):
    return payload(session, scope_id)
