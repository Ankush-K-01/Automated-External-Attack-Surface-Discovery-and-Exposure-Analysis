"""Fast Email Security Authentication Auditor (SPF, DMARC, DKIM, BIMI)."""
import logging
import asyncio
from concurrent.futures import ThreadPoolExecutor
from typing import List, Dict, Any
import dns.resolver

logger = logging.getLogger(__name__)

COMMON_DKIM_SELECTORS = ["default", "google", "k1", "mail", "s1", "selector1"]

class EmailAuthAuditor:
    def __init__(self, domain: str):
        self.domain = domain

    def _get_resolver(self):
        r = dns.resolver.Resolver()
        r.timeout = 1.0
        r.lifetime = 1.0
        return r

    def audit_all(self) -> List[Dict[str, Any]]:
        findings = []
        findings.append(self.audit_spf())
        findings.append(self.audit_dmarc())
        findings.extend(self.audit_dkim())
        findings.append(self.audit_bimi())
        return findings

    def audit_spf(self) -> Dict[str, Any]:
        result = {
            "domain": self.domain,
            "record_type": "SPF",
            "raw_record": None,
            "status": "MISSING",
            "policy": None,
            "issues": [],
            "details": {}
        }
        try:
            resolver = self._get_resolver()
            answers = resolver.resolve(self.domain, "TXT")
            for rdata in answers:
                txt_str = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings])
                if txt_str.startswith("v=spf1"):
                    result["raw_record"] = txt_str
                    result["policy"] = txt_str
                    result["status"] = "PASS"

                    if "+all" in txt_str:
                        result["status"] = "WEAK"
                        result["issues"].append("SPF ends with +all allowing any host to send email as domain")
                    elif "?all" in txt_str:
                        result["status"] = "WEAK"
                        result["issues"].append("SPF ends with ?all (neutral) providing no spoofing protection")
                    elif "~all" in txt_str:
                        result["issues"].append("SPF ends with ~all (softfail) instead of strict -all")
                    elif "-all" not in txt_str:
                        result["status"] = "WEAK"
                        result["issues"].append("SPF record lacks explicit -all or ~all mechanism")

                    includes = [part for part in txt_str.split() if part.startswith("include:")]
                    result["details"]["include_count"] = len(includes)
                    result["details"]["includes"] = includes
                    break
        except Exception as e:
            logger.debug(f"SPF lookup error for {self.domain}: {e}")

        if result["status"] == "MISSING":
            result["issues"].append(f"No SPF TXT record found for domain {self.domain}")

        return result

    def audit_dmarc(self) -> Dict[str, Any]:
        result = {
            "domain": self.domain,
            "record_type": "DMARC",
            "raw_record": None,
            "status": "MISSING",
            "policy": None,
            "issues": [],
            "details": {}
        }
        dmarc_domain = f"_dmarc.{self.domain}"
        try:
            resolver = self._get_resolver()
            answers = resolver.resolve(dmarc_domain, "TXT")
            for rdata in answers:
                txt_str = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings])
                if "v=DMARC1" in txt_str:
                    result["raw_record"] = txt_str
                    result["policy"] = txt_str
                    result["status"] = "PASS"

                    parts = [p.strip() for p in txt_str.split(";")]
                    p_val = None
                    for part in parts:
                        if part.startswith("p="):
                            p_val = part.split("=")[1].strip()
                        elif part.startswith("rua="):
                            result["details"]["rua"] = part.split("=")[1].strip()
                        elif part.startswith("ruf="):
                            result["details"]["ruf"] = part.split("=")[1].strip()

                    result["details"]["p"] = p_val
                    if p_val == "none":
                        result["status"] = "WEAK"
                        result["issues"].append("DMARC policy is set to p=none (monitoring only, no enforcement)")
                    elif p_val not in ("quarantine", "reject"):
                        result["status"] = "WEAK"
                        result["issues"].append(f"Unrecognized DMARC policy: {p_val}")

                    if "rua" not in result["details"]:
                        result["issues"].append("DMARC record lacks aggregate reporting address (rua)")
                    break
        except Exception as e:
            logger.debug(f"DMARC lookup error for {dmarc_domain}: {e}")

        if result["status"] == "MISSING":
            result["issues"].append(f"No DMARC TXT record found for _dmarc.{self.domain}")

        return result

    def audit_dkim(self) -> List[Dict[str, Any]]:
        results = []
        found_any = False
        resolver = self._get_resolver()

        for selector in COMMON_DKIM_SELECTORS:
            dkim_domain = f"{selector}._domainkey.{self.domain}"
            try:
                answers = resolver.resolve(dkim_domain, "TXT")
                for rdata in answers:
                    txt_str = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings])
                    if "v=DKIM1" in txt_str or "p=" in txt_str:
                        found_any = True
                        results.append({
                            "domain": self.domain,
                            "record_type": "DKIM",
                            "raw_record": txt_str,
                            "status": "PASS",
                            "policy": f"selector={selector}",
                            "issues": [],
                            "details": {"selector": selector}
                        })
                        break
            except Exception:
                pass

        if not found_any:
            results.append({
                "domain": self.domain,
                "record_type": "DKIM",
                "raw_record": None,
                "status": "MISSING",
                "policy": None,
                "issues": [f"No DKIM record found for common selectors on {self.domain}"],
                "details": {"tested_selectors": COMMON_DKIM_SELECTORS}
            })

        return results

    def audit_bimi(self) -> Dict[str, Any]:
        result = {
            "domain": self.domain,
            "record_type": "BIMI",
            "raw_record": None,
            "status": "MISSING",
            "policy": None,
            "issues": [],
            "details": {}
        }
        bimi_domain = f"default._bimi.{self.domain}"
        try:
            resolver = self._get_resolver()
            answers = resolver.resolve(bimi_domain, "TXT")
            for rdata in answers:
                txt_str = "".join([b.decode("utf-8", errors="ignore") for b in rdata.strings])
                if "v=BIMI1" in txt_str:
                    result["raw_record"] = txt_str
                    result["status"] = "PASS"
                    result["policy"] = txt_str
                    parts = [p.strip() for p in txt_str.split(";")]
                    for part in parts:
                        if part.startswith("l="):
                            result["details"]["logo_url"] = part.split("=")[1].strip()
                        elif part.startswith("a="):
                            result["details"]["vmc_url"] = part.split("=")[1].strip()
                    break
        except Exception:
            pass

        if result["status"] == "MISSING":
            result["issues"].append(f"No BIMI logo record found at default._bimi.{self.domain}")

        return result
