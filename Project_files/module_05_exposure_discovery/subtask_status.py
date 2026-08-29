"""Subtask status tracking helper for Module 5 Exposure Discovery."""
from sqlalchemy import select
from module_01_scope_management.db import SessionLocal
from .models import Module5SubtaskStatus

def is_phase_completed(scope_id: str, phase_name: str) -> bool:
    s_str = str(scope_id)
    with SessionLocal() as session:
        sub = session.scalars(
            select(Module5SubtaskStatus).where(
                Module5SubtaskStatus.scope_id == s_str,
                Module5SubtaskStatus.subtask_name == phase_name,
                Module5SubtaskStatus.completed == True
            )
        ).first()
        return sub is not None

def mark_phase_completed(scope_id: str, phase_name: str):
    s_str = str(scope_id)
    with SessionLocal() as session:
        sub = session.scalars(
            select(Module5SubtaskStatus).where(
                Module5SubtaskStatus.scope_id == s_str,
                Module5SubtaskStatus.subtask_name == phase_name
            )
        ).first()
        
        if not sub:
            sub = Module5SubtaskStatus(
                scope_id=s_str,
                subtask_name=phase_name,
                completed=True
            )
            session.add(sub)
        else:
            sub.completed = True
        session.commit()
