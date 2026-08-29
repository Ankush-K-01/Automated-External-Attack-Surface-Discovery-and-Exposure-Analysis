"""Subtask status tracking helper for Module 7 Threat Intelligence."""
from sqlalchemy import select
from module_01_scope_management.db import SessionLocal
from .models import Module7SubtaskStatus

def is_phase_completed(scope_id: str, phase_name: str) -> bool:
    s_str = str(scope_id)
    with SessionLocal() as session:
        sub = session.scalars(
            select(Module7SubtaskStatus).where(
                Module7SubtaskStatus.scope_id == s_str,
                Module7SubtaskStatus.subtask_name == phase_name,
                Module7SubtaskStatus.completed == True
            )
        ).first()
        return sub is not None

def mark_phase_completed(scope_id: str, phase_name: str):
    s_str = str(scope_id)
    with SessionLocal() as session:
        sub = session.scalars(
            select(Module7SubtaskStatus).where(
                Module7SubtaskStatus.scope_id == s_str,
                Module7SubtaskStatus.subtask_name == phase_name
            )
        ).first()
        
        if not sub:
            sub = Module7SubtaskStatus(
                scope_id=s_str,
                subtask_name=phase_name,
                completed=True
            )
            session.add(sub)
        else:
            sub.completed = True
        session.commit()
