"""Shared sequential-pipeline status contract for Modules 1 through 12."""
from __future__ import annotations
from contextvars import ContextVar
from datetime import datetime, timezone
from uuid import UUID
from sqlalchemy.orm import Session
from .models import ModuleStatus, PipelineStatus

_session: ContextVar[Session] = ContextVar("pipeline_session")
def bind_session(session: Session): return _session.set(session)
def reset_session(token: object) -> None: _session.reset(token)
def _row(scope_id: UUID, module_name: str) -> ModuleStatus:
    session = _session.get(); row = session.query(ModuleStatus).filter_by(scope_id=scope_id, module_name=module_name).one_or_none()
    if row is None: row = ModuleStatus(scope_id=scope_id, module_name=module_name, status=PipelineStatus.STARTED); session.add(row)
    return row
def mark_module_started(scope_id: UUID, module_name: str) -> None:
    session = _session.get()
    _row(scope_id, module_name).status = PipelineStatus.STARTED
    session.commit()
def mark_module_completed(scope_id: UUID, module_name: str, output_ref: str) -> None:
    session = _session.get()
    row = _row(scope_id, module_name); row.status = PipelineStatus.COMPLETED; row.completed_at = datetime.now(timezone.utc); row.output_ref = output_ref; row.error = None
    session.commit()
def mark_module_failed(scope_id: UUID, module_name: str, error: str) -> None:
    session = _session.get()
    row = _row(scope_id, module_name); row.status = PipelineStatus.ERROR; row.error = error
    session.commit()
