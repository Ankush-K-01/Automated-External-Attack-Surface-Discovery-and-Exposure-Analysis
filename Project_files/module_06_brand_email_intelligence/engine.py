"""Module 6 Engine orchestrating Email Auth, Typosquatting, and Brand Impersonation."""
import asyncio
import logging
from pathlib import Path
from typing import List, Dict, Any
from uuid import UUID

from sqlalchemy import select
from module_01_scope_management.db import SessionLocal, engine, Base
from module_01_scope_management.models import ScopeDomain, Scope
from .models import (
    EmailAuthFinding, LookalikeDomain, LookalikeCertMatch,
    BrandImpersonationFinding, Module6SubtaskStatus
)
from .subtask_status import is_phase_completed, mark_phase_completed
from .email_auth import EmailAuthAuditor
from .typosquat import TyposquatAnalyzer
from .brand_impersonation import BrandImpersonator

logger = logging.getLogger(__name__)

class BrandEmailEngine:
    def __init__(self, scope_id: str | UUID):
        self.scope_id = str(scope_id)
        self.uuid_scope_id = UUID(str(scope_id)) if isinstance(scope_id, (str, UUID)) else scope_id
        self.log_dir = Path("tool_output") / self.scope_id
        self.log_dir.mkdir(parents=True, exist_ok=True)
        Base.metadata.create_all(bind=engine)

    async def run_all(self):
        logger.info(f"Starting Module 6 Brand & Email Intelligence Engine for Scope {self.scope_id}")

        with SessionLocal() as session:
            domains = session.scalars(
                select(ScopeDomain.domain).where(ScopeDomain.scope_id == self.uuid_scope_id)
            ).all()

        domain_list = list(set(domains))
        if not domain_list:
            logger.warning(f"No in-scope domains found for scope {self.scope_id}")
            domain_list = ["example.com"]

        # Phase A: Corporate Email Security Audit (SPF, DMARC, DKIM, BIMI)
        if not is_phase_completed(self.scope_id, "Phase_A_Email_Auth"):
            await self.phase_a_email_auth(domain_list)
            mark_phase_completed(self.scope_id, "Phase_A_Email_Auth")

        # Phase B: Typosquat & Lookalike Domain Detection (dnstwist)
        if not is_phase_completed(self.scope_id, "Phase_B_Typosquat"):
            await self.phase_b_typosquat(domain_list)
            mark_phase_completed(self.scope_id, "Phase_B_Typosquat")

        # Phase C: Brand & App Store Impersonation Audit
        if not is_phase_completed(self.scope_id, "Phase_C_Impersonation"):
            await self.phase_c_impersonation(domain_list)
            mark_phase_completed(self.scope_id, "Phase_C_Impersonation")

        # Phase D: Backlink Audit (Explicit Free-Tier Gap Logging)
        logger.info("Backlink audit: no free data source integrated (out-of-scope for free tier)")

    async def phase_a_email_auth(self, domains: List[str]):
        logger.info("Executing Phase A: Corporate Email Security Audit (SPF, DMARC, DKIM, BIMI)...")
        for dom in domains:
            auditor = EmailAuthAuditor(dom)
            findings = auditor.audit_all()

            with SessionLocal() as session:
                for f in findings:
                    session.add(EmailAuthFinding(
                        scope_id=self.scope_id,
                        domain=f["domain"],
                        record_type=f["record_type"],
                        raw_record=f["raw_record"],
                        status=f["status"],
                        policy=f["policy"],
                        issues=f["issues"],
                        details=f["details"]
                    ))
                session.commit()

    async def phase_b_typosquat(self, domains: List[str]):
        logger.info("Executing Phase B: Typosquat & Lookalike Domain Detection (dnstwist)...")
        for dom in domains:
            analyzer = TyposquatAnalyzer(dom)
            lookalikes = await analyzer.analyze_async()

            with SessionLocal() as session:
                for lk in lookalikes:
                    session.add(LookalikeDomain(
                        scope_id=self.scope_id,
                        target_domain=lk["target_domain"],
                        permutation_domain=lk["permutation_domain"],
                        fuzzer_type=lk["fuzzer_type"],
                        resolved_ip=lk["resolved_ip"],
                        mx_records=lk["mx_records"],
                        ns_records=lk["ns_records"],
                        is_registered=lk["is_registered"],
                        phishing_risk=lk["phishing_risk"],
                        details=lk["details"]
                    ))

                    # Fetch SSL cert details if registered
                    if lk["resolved_ip"]:
                        cert_info = analyzer.fetch_cert_details(lk["permutation_domain"])
                        if cert_info:
                            session.add(LookalikeCertMatch(
                                scope_id=self.scope_id,
                                permutation_domain=cert_info["permutation_domain"],
                                cert_issuer=cert_info["cert_issuer"],
                                cert_subject=cert_info["cert_subject"],
                                valid_from=cert_info["valid_from"],
                                valid_to=cert_info["valid_to"],
                                fingerprint=cert_info["fingerprint"]
                            ))
                session.commit()

    async def phase_c_impersonation(self, domains: List[str]):
        logger.info("Executing Phase C: Brand & App Store Impersonation Heuristic Audit...")
        for dom in domains:
            brand_name = dom.split(".")[0]
            impersonator = BrandImpersonator(brand_name)
            findings = impersonator.audit()

            with SessionLocal() as session:
                for imp in findings:
                    session.add(BrandImpersonationFinding(
                        scope_id=self.scope_id,
                        brand_name=imp["brand_name"],
                        platform=imp["platform"],
                        title=imp["title"],
                        url=imp["url"],
                        confidence=imp["confidence"],
                        details=imp["details"]
                    ))
                session.commit()
