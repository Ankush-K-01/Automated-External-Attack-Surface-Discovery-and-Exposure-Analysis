from contextlib import nullcontext as _nullctx
import sys, logging, json
from pathlib import Path
from uuid import UUID
from fastapi import FastAPI, Depends, HTTPException
from sqlalchemy.orm import Session
from module_01_scope_management.db import get_session
from module_01_scope_management.models import ModuleStatus, PipelineStatus
from module_01_scope_management.pipeline_status import bind_session, reset_session, mark_module_completed, mark_module_failed
from .models import UnifiedAsset, InventorySnapshotMeta
from .schemas import InventoryExport
from .builder import InventoryBuilder

if sys.version_info[:2] != (3, 13):
    raise RuntimeError("Module 4 requires Python 3.13.x")

app = FastAPI(title="ASM Module 4: Unified Inventory")
NAME = "module_04_attack_surface_inventory"
log = logging.getLogger(__name__)

def gate(s, scope):
    r = s.query(ModuleStatus).filter_by(scope_id=scope, module_name="module_03_identity_correlation").one_or_none()
    if not r or r.status is not PipelineStatus.COMPLETED:
        log.warning("scope_id=%s waiting on module_03_identity_correlation", scope)
        raise HTTPException(409, "waiting on module_03_identity_correlation")

def data(s, scope):
    assets = [
        {
            "asset_id": str(x.asset_id),
            "subdomain": x.subdomain,
            "ip": x.ip,
            "port": x.port,
            "protocol": x.protocol,
            "asset_type": x.asset_type,
            "asn": x.asn,
            "asn_org": x.asn_org,
            "cloud_provider": x.cloud_provider,
            "cert_fingerprint": x.cert_fingerprint,
            "in_scope_confirmed": x.in_scope_confirmed,
            "discovery_sources": x.discovery_sources
        }
        for x in s.query(UnifiedAsset).filter_by(scope_id=scope)
    ]
    return InventoryExport(scope_id=str(scope), assets=assets, counts={"total": len(assets)})

@app.post("/inventory/{scope_id}/build", response_model=InventoryExport)
def build(scope_id: UUID, s: Session = Depends(get_session)):
    gate(s, scope_id)
    try:
        builder = InventoryBuilder(scope_id)
        inv_data = builder.build_inventory()
        
        Path("output").mkdir(exist_ok=True)
        p = Path("output") / f"{scope_id}.json"
        p.write_text(json.dumps(inv_data, indent=2), encoding="utf-8")
        
        t = bind_session(s)
        try:
            mark_module_completed(scope_id, NAME, str(p))
        finally:
            reset_session(t)
            
        return data(s, scope_id)
    except Exception as e:
        log.error(f"Inventory build failed for {scope_id}: {e}", exc_info=True)
        t = bind_session(s)
        try:
            mark_module_failed(scope_id, NAME, str(e))
            s.commit()
        finally:
            reset_session(t)
        raise HTTPException(500, f"inventory build failed: {e}") from e

@app.get("/inventory/{scope_id}", response_model=InventoryExport)
def get(scope_id: UUID, s: Session = Depends(get_session)):
    return data(s, scope_id)

@app.get("/inventory/{scope_id}/export", response_model=InventoryExport)
def export(scope_id: UUID, s: Session = Depends(get_session)):
    return data(s, scope_id)

@app.get("/inventory/{scope_id}/asset/{asset_id}")
def asset(scope_id: UUID, asset_id: UUID, s: Session = Depends(get_session)):
    r = s.get(UnifiedAsset, asset_id)
    if not r or str(r.scope_id) != str(scope_id):
        raise HTTPException(404, "asset not found")
    return {
        "asset_id": str(r.asset_id),
        "subdomain": r.subdomain,
        "ip": r.ip,
        "port": r.port,
        "asset_type": r.asset_type
    }
