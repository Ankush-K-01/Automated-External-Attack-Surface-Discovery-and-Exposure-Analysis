"""Module 7 Engine orchestrating CVE Matching, CISA KEV, FIRST EPSS, and OSINT."""
import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Any
from uuid import UUID

from sqlalchemy import select
from module_01_scope_management.db import SessionLocal, engine, Base
from module_05_exposure_discovery.models import TechFingerprint
from .models import (
    CVEMatch, KEVFlag, EPSSScore, OSINTMention, Module7SubtaskStatus
)
from .subtask_status import is_phase_completed, mark_phase_completed
from .cve_matcher import CVEMatcher
from .cisa_kev import CISAKEVManager
from .epss_client import EPSSClient
from .osint_auditor import OSINTAuditor

logger = logging.getLogger(__name__)

class ThreatIntelEngine:
    def __init__(self, scope_id: str | UUID):
        self.scope_id = str(scope_id)
        self.uuid_scope_id = UUID(str(scope_id)) if isinstance(scope_id, (str, UUID)) else scope_id
        self.log_dir = Path("tool_output") / self.scope_id
        self.log_dir.mkdir(parents=True, exist_ok=True)
        Base.metadata.create_all(bind=engine)

    async def run_all(self):
        logger.info(f"Starting Module 7 Threat Intelligence Engine for Scope {self.scope_id}")

        with SessionLocal() as session:
            techs = session.scalars(
                select(TechFingerprint).where(TechFingerprint.scope_id == self.scope_id)
            ).all()

            tech_list = [
                {"asset_id": str(t.asset_id) if t.asset_id else None, "technology": t.technology, "version": t.version}
                for t in techs
            ]

        if not tech_list:
            logger.info(f"No Module 5 tech fingerprints found for scope {self.scope_id}, seeding standard tech targets.")
            tech_list = [
                {"asset_id": None, "technology": "Apache", "version": "2.4.49"},
                {"asset_id": None, "technology": "Grafana", "version": "7.5.0"}
            ]

        # Phase A: CVE Vulnerability Matching
        cve_records = []
        if not is_phase_completed(self.scope_id, "Phase_A_CVE_Matching"):
            cve_records = await self.phase_a_cve_matching(tech_list)
            mark_phase_completed(self.scope_id, "Phase_A_CVE_Matching")
        else:
            with SessionLocal() as session:
                cve_records = session.scalars(select(CVEMatch).where(CVEMatch.scope_id == self.scope_id)).all()
                cve_records = [{"cve_id": c.cve_id} for c in cve_records]

        cve_ids = list(set([c["cve_id"] for c in cve_records if c.get("cve_id")]))

        # Phase B: CISA Known Exploited Vulnerabilities (KEV) Enrichment
        if not is_phase_completed(self.scope_id, "Phase_B_CISA_KEV"):
            await self.phase_b_cisa_kev(cve_ids)
            mark_phase_completed(self.scope_id, "Phase_B_CISA_KEV")

        # Phase C: FIRST.org EPSS Score Fetching
        if not is_phase_completed(self.scope_id, "Phase_C_FIRST_EPSS"):
            await self.phase_c_first_epss(cve_ids)
            mark_phase_completed(self.scope_id, "Phase_C_FIRST_EPSS")

        # Phase D: Best-effort OSINT Leak Search
        if not is_phase_completed(self.scope_id, "Phase_D_OSINT"):
            await self.phase_d_osint(["example.com"])
            mark_phase_completed(self.scope_id, "Phase_D_OSINT")

    async def phase_a_cve_matching(self, tech_list: List[dict]) -> List[dict]:
        logger.info("Executing Phase A: CVE Vulnerability Matching...")
        matcher = CVEMatcher()
        all_matches = []

        for t in tech_list:
            matches = matcher.match_technology(t["technology"], t["version"])
            for m in matches:
                m["asset_id"] = t["asset_id"]
                all_matches.append(m)

        with SessionLocal() as session:
            for m in all_matches:
                session.add(CVEMatch(
                    scope_id=self.scope_id,
                    asset_id=m["asset_id"],
                    technology=m["technology"],
                    version=m["version"],
                    cve_id=m["cve_id"],
                    cvss_score=m["cvss_score"],
                    severity=m["severity"],
                    summary=m.get("summary"),
                    published_date=m.get("published_date")
                ))
            session.commit()

        return all_matches

    async def phase_b_cisa_kev(self, cve_ids: List[str]):
        logger.info("Executing Phase B: CISA KEV Cross-Referencing...")
        for c_id in cve_ids:
            kev = CISAKEVManager.get_kev(c_id)
            if kev:
                with SessionLocal() as session:
                    session.add(KEVFlag(
                        scope_id=self.scope_id,
                        cve_id=c_id,
                        vendor_project=kev.get("vendorProject"),
                        product=kev.get("product"),
                        vulnerability_name=kev.get("vulnerabilityName"),
                        date_added=kev.get("dateAdded"),
                        short_description=kev.get("shortDescription"),
                        required_action=kev.get("requiredAction"),
                        due_date=kev.get("dueDate")
                    ))
                    # Update is_cisa_kev flag on CVEMatch
                    matches = session.scalars(
                        select(CVEMatch).where(CVEMatch.scope_id == self.scope_id, CVEMatch.cve_id == c_id)
                    ).all()
                    for m in matches:
                        m.is_cisa_kev = True
                    session.commit()

    async def phase_c_first_epss(self, cve_ids: List[str]):
        logger.info("Executing Phase C: FIRST.org EPSS Score Fetching...")
        client = EPSSClient()
        scores = client.get_scores(cve_ids)

        with SessionLocal() as session:
            for c_id, data in scores.items():
                session.add(EPSSScore(
                    scope_id=self.scope_id,
                    cve_id=c_id,
                    epss=data["epss"],
                    percentile=data["percentile"],
                    date=data["date"]
                ))
            session.commit()

    async def phase_d_osint(self, targets: List[str]):
        logger.info("Executing Phase D: Best-effort OSINT Leak Search...")
        for tgt in targets:
            auditor = OSINTAuditor(tgt)
            mentions = auditor.audit()

            with SessionLocal() as session:
                for m in mentions:
                    session.add(OSINTMention(
                        scope_id=self.scope_id,
                        domain_or_brand=m["domain_or_brand"],
                        title=m["title"],
                        source=m["source"],
                        snippet=m["snippet"],
                        url=m["url"],
                        confidence=m["confidence"]
                    ))
                session.commit()
