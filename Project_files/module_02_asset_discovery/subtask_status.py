"""Subtask status tracking for Module 2 resumability."""
from uuid import UUID
from sqlalchemy.orm import Session
from .models import Module2SubtaskStatus

def is_phase_completed(session: Session, scope_id: UUID, phase_name: str) -> bool:
    rec = session.query(Module2SubtaskStatus).filter_by(scope_id=scope_id, phase_name=phase_name, status="COMPLETED").one_or_none()
    return rec is not None

def mark_phase_completed(session: Session, scope_id: UUID, phase_name: str) -> None:
    rec = session.query(Module2SubtaskStatus).filter_by(scope_id=scope_id, phase_name=phase_name).one_or_none()
    if not rec:
        rec = Module2SubtaskStatus(scope_id=scope_id, phase_name=phase_name, status="COMPLETED")
        session.add(rec)
    else:
        rec.status = "COMPLETED"
    session.commit()
