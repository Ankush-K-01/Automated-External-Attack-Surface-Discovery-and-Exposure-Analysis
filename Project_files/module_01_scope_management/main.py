"""FastAPI service for Module 1; it validates scope only and never scans."""
from __future__ import annotations
import logging, sys
from pathlib import Path
from uuid import UUID
from fastapi import Depends, FastAPI, HTTPException, status
from sqlalchemy.orm import Session, selectinload
from .db import get_session, settings
from .models import Scope, ScopeAsn, ScopeCidr, ScopeDomain, ScopeOrg, ScopeStatus, ScopeTld, ScanPolicy, TldSource, ModuleStatus
from .pipeline_status import bind_session, mark_module_completed, mark_module_failed, mark_module_started, reset_session
from .schemas import ScopeCreated, ScopeExport, ScopeInput
if sys.version_info[:2] != (3, 13): raise RuntimeError(f"Module 1 requires Python 3.13.x; found {sys.version}")
logging.basicConfig(format="%(asctime)s %(levelname)s scope_id=%(scope_id)s %(message)s")
logger = logging.getLogger(__name__); app = FastAPI(title="ASM Module 1: Scope & Target Management"); MODULE_NAME = "module_01_scope_management"
def log(scope_id: UUID, message: str) -> None: logger.info(message, extra={"scope_id": scope_id})
def get_scope(session: Session, scope_id: UUID) -> Scope:
    scope = session.query(Scope).options(selectinload(Scope.domains),selectinload(Scope.asns),selectinload(Scope.cidrs),selectinload(Scope.orgs),selectinload(Scope.tlds),selectinload(Scope.policy)).filter_by(scope_id=scope_id).one_or_none()
    if scope is None: raise HTTPException(404, "scope not found")
    return scope
def export(scope: Scope) -> ScopeExport:
    return ScopeExport(scope_id=str(scope.scope_id),status=scope.status.value,domains=sorted(x.domain for x in scope.domains),asns=sorted(x.asn for x in scope.asns),cidrs=sorted(x.cidr for x in scope.cidrs),organizations=sorted(x.org_name for x in scope.orgs),custom_tlds=sorted(x.tld for x in scope.tlds if x.source is TldSource.USER_SUPPLIED),scan_policy=scope.policy.policy_json if scope.policy else {})
def attach(scope: Scope, payload: ScopeInput) -> None:
    scope.domains.extend(ScopeDomain(domain=x) for x in payload.domains if x not in {d.domain for d in scope.domains}); scope.asns.extend(ScopeAsn(asn=int(x)) for x in payload.asns if int(x) not in {a.asn for a in scope.asns}); scope.cidrs.extend(ScopeCidr(cidr=x) for x in payload.cidrs if x not in {c.cidr for c in scope.cidrs}); scope.orgs.extend(ScopeOrg(org_name=x) for x in payload.organizations if x.lower() not in {o.org_name.lower() for o in scope.orgs}); scope.tlds.extend(ScopeTld(tld=x,source=TldSource.USER_SUPPLIED) for x in payload.custom_tlds if x not in {t.tld for t in scope.tlds})
    if payload.scan_policy: scope.policy = ScanPolicy(policy_json=payload.scan_policy)

@app.post("/scope",response_model=ScopeCreated,status_code=status.HTTP_201_CREATED)
def create_scope(payload: ScopeInput, session: Session=Depends(get_session)) -> ScopeCreated:
    try:
        scope=Scope(status=ScopeStatus.VALIDATED); session.add(scope); attach(scope,payload); session.commit(); token=bind_session(session)
        try:
            mark_module_started(scope.scope_id,MODULE_NAME)
            session.commit()
            log(scope.scope_id,"scope validated")
        finally: reset_session(token)
        return ScopeCreated(scope_id=str(scope.scope_id),status=scope.status.value)
    except Exception as exc: session.rollback(); raise HTTPException(500,"scope creation failed") from exc

@app.get("/scope/{scope_id}",response_model=ScopeExport)
def fetch_scope(scope_id: UUID,session: Session=Depends(get_session))->ScopeExport: return export(get_scope(session,scope_id))

@app.patch("/scope/{scope_id}",response_model=ScopeExport)
def patch_scope(scope_id: UUID,payload: ScopeInput,session: Session=Depends(get_session))->ScopeExport:
    scope=get_scope(session,scope_id)
    if scope.status is not ScopeStatus.DRAFT: raise HTTPException(409,"only DRAFT scopes are mutable")
    attach(scope,payload); session.commit()
    return export(scope)

@app.get("/scope/{scope_id}/export",response_model=ScopeExport)
def export_scope(scope_id: UUID,session: Session=Depends(get_session))->ScopeExport: return export(get_scope(session,scope_id))

@app.post("/scope/{scope_id}/dispatch",response_model=ScopeExport)
def dispatch_scope(scope_id: UUID,session: Session=Depends(get_session))->ScopeExport:
    scope=get_scope(session,scope_id)
    if scope.status is ScopeStatus.DISPATCHED: raise HTTPException(409,"scope is already dispatched")
    try:
        payload=export(scope); directory=Path(settings.scope_export_dir); directory.mkdir(parents=True,exist_ok=True); output=directory/f"{scope_id}.json"; output.write_text(payload.model_dump_json(indent=2),encoding="utf-8"); scope.status=ScopeStatus.DISPATCHED; session.commit(); token=bind_session(session)
        try:
            mark_module_completed(scope_id,MODULE_NAME,str(output))
            session.commit()
            log(scope_id,"scope dispatched; completion published")
        finally: reset_session(token)
        return payload.model_copy(update={"status":ScopeStatus.DISPATCHED.value})
    except Exception as exc:
        session.rollback(); token=bind_session(session)
        try:
            mark_module_failed(scope_id,MODULE_NAME,str(exc))
            session.commit()
        finally: reset_session(token)
        raise HTTPException(500,"scope dispatch failed") from exc

@app.get("/scope/{scope_id}/status")
def get_pipeline_status(scope_id: UUID, session: Session=Depends(get_session)):
    get_scope(session, scope_id)
    rows = session.query(ModuleStatus).filter_by(scope_id=scope_id).all()
    statuses = {r.module_name: {"status": r.status.value, "output_ref": r.output_ref, "error": r.error} for r in rows}
    return {"scope_id": str(scope_id), "modules": statuses}

