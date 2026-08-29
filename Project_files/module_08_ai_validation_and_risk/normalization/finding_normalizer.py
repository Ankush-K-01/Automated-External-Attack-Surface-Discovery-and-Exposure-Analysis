"""Finding Normalizer merging Module 5, 6, and 7 outputs into unified structure."""
import logging
from typing import List, Dict, Any
from sqlalchemy import select
from module_01_scope_management.db import SessionLocal

from module_05_exposure_discovery.models import (
    ExposureFinding, TLSFinding, ExposedSecret, TakeoverCandidate
)
from module_06_brand_email_intelligence.models import (
    EmailAuthFinding, LookalikeDomain, BrandImpersonationFinding
)
from module_07_threat_intelligence.models import (
    CVEMatch, KEVFlag, EPSSScore
)

logger = logging.getLogger(__name__)

class FindingNormalizer:
    def __init__(self, scope_id: str):
        self.scope_id = str(scope_id)

    def normalize_all(self) -> List[Dict[str, Any]]:
        normalized = []
        normalized.extend(self._normalize_module_5())
        normalized.extend(self._normalize_module_6())
        normalized.extend(self._normalize_module_7())
        return normalized

    def _normalize_module_5(self) -> List[Dict[str, Any]]:
        findings = []
        with SessionLocal() as session:
            # 1. Exposure Findings
            exposures = session.scalars(
                select(ExposureFinding).where(ExposureFinding.scope_id == self.scope_id)
            ).all()
            for ef in exposures:
                findings.append({
                    "source_module": "module_05_exposure_discovery",
                    "finding_type": ef.finding_type or "EXPOSURE",
                    "title": f"Exposure: {ef.finding_type}",
                    "description": ef.description,
                    "severity": ef.severity or "MEDIUM",
                    "cvss_score": None,
                    "epss_score": None,
                    "is_cisa_kev": False,
                    "waf_detected": ef.waf_detected or False,
                    "details": ef.details or {}
                })

            # 2. TLS Findings
            tls_list = session.scalars(
                select(TLSFinding).where(TLSFinding.scope_id == self.scope_id)
            ).all()
            for tls in tls_list:
                findings.append({
                    "source_module": "module_05_exposure_discovery",
                    "finding_type": "TLS_MISCONFIGURATION",
                    "title": f"TLS Configuration Issue: {tls.issue}",
                    "description": f"TLS configuration security weakness detected on target {tls.target}",
                    "severity": tls.severity or "MEDIUM",
                    "cvss_score": None,
                    "epss_score": None,
                    "is_cisa_kev": False,
                    "waf_detected": False,
                    "details": {"target": tls.target, "issue": tls.issue}
                })

            # 3. Exposed Secrets
            secrets = session.scalars(
                select(ExposedSecret).where(ExposedSecret.scope_id == self.scope_id)
            ).all()
            for sec in secrets:
                findings.append({
                    "source_module": "module_05_exposure_discovery",
                    "finding_type": "EXPOSED_SECRET",
                    "title": f"Exposed Secret ({sec.secret_type})",
                    "description": f"Potential leak of {sec.secret_type} found at {sec.url}",
                    "severity": "HIGH",
                    "cvss_score": None,
                    "epss_score": None,
                    "is_cisa_kev": False,
                    "waf_detected": False,
                    "details": {"url": sec.url, "secret_type": sec.secret_type}
                })

            # 4. Takeover Candidates
            takeovers = session.scalars(
                select(TakeoverCandidate).where(TakeoverCandidate.scope_id == self.scope_id)
            ).all()
            for tk in takeovers:
                findings.append({
                    "source_module": "module_05_exposure_discovery",
                    "finding_type": "SUBDOMAIN_TAKEOVER",
                    "title": f"Subdomain Takeover Risk ({tk.service})",
                    "description": f"Dangling CNAME record pointing to {tk.cname} ({tk.service})",
                    "severity": "HIGH",
                    "cvss_score": None,
                    "epss_score": None,
                    "is_cisa_kev": False,
                    "waf_detected": False,
                    "details": {"cname": tk.cname, "service": tk.service}
                })

        return findings

    def _normalize_module_6(self) -> List[Dict[str, Any]]:
        findings = []
        with SessionLocal() as session:
            # 1. Email Auth Findings (WEAK or MISSING)
            email_auths = session.scalars(
                select(EmailAuthFinding).where(
                    EmailAuthFinding.scope_id == self.scope_id,
                    EmailAuthFinding.status.in_(["WEAK", "MISSING"])
                )
            ).all()
            for ea in email_auths:
                sev = "HIGH" if ea.record_type == "DMARC" and ea.status == "MISSING" else "MEDIUM"
                findings.append({
                    "source_module": "module_06_brand_email_intelligence",
                    "finding_type": f"EMAIL_AUTH_{ea.record_type}",
                    "title": f"Weak {ea.record_type} Policy for {ea.domain}",
                    "description": f"{ea.record_type} authentication issue on {ea.domain}. Issues: {', '.join(ea.issues or [])}",
                    "severity": sev,
                    "cvss_score": None,
                    "epss_score": None,
                    "is_cisa_kev": False,
                    "waf_detected": False,
                    "details": {"domain": ea.domain, "record_type": ea.record_type, "status": ea.status}
                })

            # 2. Typosquat / Lookalike Domains
            lookalikes = session.scalars(
                select(LookalikeDomain).where(
                    LookalikeDomain.scope_id == self.scope_id,
                    LookalikeDomain.is_registered == True
                )
            ).all()
            for lk in lookalikes:
                findings.append({
                    "source_module": "module_06_brand_email_intelligence",
                    "finding_type": "TYPOSQUAT_DOMAIN",
                    "title": f"Lookalike Domain Registered: {lk.permutation_domain}",
                    "description": f"Active lookalike permutation for {lk.target_domain} (Fuzzer: {lk.fuzzer_type}, IP: {lk.resolved_ip})",
                    "severity": lk.phishing_risk or "MEDIUM",
                    "cvss_score": None,
                    "epss_score": None,
                    "is_cisa_kev": False,
                    "waf_detected": False,
                    "details": {"permutation_domain": lk.permutation_domain, "fuzzer": lk.fuzzer_type, "ip": lk.resolved_ip}
                })

            # 3. Brand Impersonations
            impersonations = session.scalars(
                select(BrandImpersonationFinding).where(BrandImpersonationFinding.scope_id == self.scope_id)
            ).all()
            for imp in impersonations:
                findings.append({
                    "source_module": "module_06_brand_email_intelligence",
                    "finding_type": "BRAND_IMPERSONATION",
                    "title": f"Brand Impersonation Signal [{imp.platform}]",
                    "description": f"Potential mobile app / store listing for {imp.brand_name}: {imp.title}",
                    "severity": "INFO",
                    "cvss_score": None,
                    "epss_score": None,
                    "is_cisa_kev": False,
                    "waf_detected": False,
                    "details": {"platform": imp.platform, "url": imp.url}
                })

        return findings

    def _normalize_module_7(self) -> List[Dict[str, Any]]:
        findings = []
        with SessionLocal() as session:
            cves = session.scalars(
                select(CVEMatch).where(CVEMatch.scope_id == self.scope_id)
            ).all()

            # Map EPSS scores by cve_id
            epss_records = session.scalars(
                select(EPSSScore).where(EPSSScore.scope_id == self.scope_id)
            ).all()
            epss_map = {e.cve_id: e.epss for e in epss_records}

            for cve in cves:
                epss_val = epss_map.get(cve.cve_id)
                findings.append({
                    "source_module": "module_07_threat_intelligence",
                    "finding_type": "CVE_VULNERABILITY",
                    "title": f"{cve.cve_id} on {cve.technology} {cve.version or ''}".strip(),
                    "description": cve.summary or f"Known vulnerability {cve.cve_id} affecting {cve.technology}",
                    "severity": cve.severity or "HIGH",
                    "cvss_score": cve.cvss_score,
                    "epss_score": epss_val,
                    "is_cisa_kev": cve.is_cisa_kev or False,
                    "waf_detected": False,
                    "details": {"cve_id": cve.cve_id, "technology": cve.technology, "version": cve.version}
                })

        return findings
