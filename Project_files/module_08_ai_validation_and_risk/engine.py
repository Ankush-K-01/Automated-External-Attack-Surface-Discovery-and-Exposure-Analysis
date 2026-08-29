"""Module 8 Engine orchestrating Normalization, Risk Scoring, and Groq AI Triage."""
import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Any
from uuid import UUID

from sqlalchemy import select
from module_01_scope_management.db import SessionLocal, engine, Base
from .models import UnifiedFinding, Module8SubtaskStatus
from .subtask_status import is_phase_completed, mark_phase_completed
from .normalization.finding_normalizer import FindingNormalizer
from .scoring.risk_scorer import RiskScorer
from .ai_triage.llm_triager import GroqLLMTriager

logger = logging.getLogger(__name__)

class AIRiskEngine:
    def __init__(self, scope_id: str | UUID, mock_429: bool = False):
        self.scope_id = str(scope_id)
        self.log_dir = Path("tool_output") / self.scope_id
        self.log_dir.mkdir(parents=True, exist_ok=True)
        self.mock_429 = mock_429
        Base.metadata.create_all(bind=engine)

    async def run_all(self):
        logger.info(f"Starting Module 8 AI Validation & Risk Engine for Scope {self.scope_id}")

        # Phase A: Finding Normalization
        normalized = []
        if not is_phase_completed(self.scope_id, "Phase_A_Normalization"):
            normalizer = FindingNormalizer(self.scope_id)
            normalized = normalizer.normalize_all()
            mark_phase_completed(self.scope_id, "Phase_A_Normalization")
        else:
            with SessionLocal() as session:
                records = session.scalars(select(UnifiedFinding).where(UnifiedFinding.scope_id == self.scope_id)).all()
                normalized = [
                    {
                        "source_module": r.source_module,
                        "finding_type": r.finding_type,
                        "title": r.title,
                        "description": r.description,
                        "severity": r.severity,
                        "cvss_score": r.cvss_score,
                        "epss_score": r.epss_score,
                        "is_cisa_kev": r.is_cisa_kev,
                        "waf_detected": r.waf_detected,
                        "details": r.details or {}
                    }
                    for r in records
                ]

        # Phase B: Deterministic Risk Scoring & Groq AI Batch Triage
        if not is_phase_completed(self.scope_id, "Phase_B_Scoring_And_Triage"):
            # 1. Deterministic Risk Scoring (CVSS, EPSS, KEV, WAF)
            scored_findings = [RiskScorer.calculate_risk(item) for item in normalized]

            # 2. Groq AI Batch Triage (preserves deterministic risk scores & levels)
            triager = GroqLLMTriager(mock_429=self.mock_429)
            triaged_findings = triager.triage_batch(scored_findings)

            with SessionLocal() as session:
                for f in triaged_findings:
                    session.add(UnifiedFinding(
                        scope_id=self.scope_id,
                        source_module=f["source_module"],
                        finding_type=f["finding_type"],
                        title=f["title"],
                        description=f["description"],
                        severity=f["severity"],
                        cvss_score=f["cvss_score"],
                        epss_score=f["epss_score"],
                        is_cisa_kev=f["is_cisa_kev"],
                        waf_detected=f["waf_detected"],
                        risk_score=f["risk_score"],
                        risk_level=f["risk_level"],
                        ai_triage_summary=f.get("ai_triage_summary"),
                        remediation_guidance=f.get("remediation_guidance"),
                        details=f["details"]
                    ))
                session.commit()

            mark_phase_completed(self.scope_id, "Phase_B_Scoring_And_Triage")
