"""Ultra-Fast Typosquatting and Lookalike Domain Analyzer using dnstwist & async DNS."""
import asyncio
import logging
import socket
import ssl
from typing import List, Dict, Any
import dnstwist

logger = logging.getLogger(__name__)

class TyposquatAnalyzer:
    def __init__(self, domain: str):
        self.domain = domain

    async def analyze_async(self) -> List[Dict[str, Any]]:
        logger.info(f"Generating lookalike permutations for {self.domain} via dnstwist...")
        try:
            fuzzer = dnstwist.Fuzzer(self.domain)
            fuzzer.generate()
            perms = fuzzer.permutations()
        except Exception as e:
            logger.error(f"dnstwist permutation generation error for {self.domain}: {e}")
            return []

        targets = []
        for p in perms[:15]:
            p_domain = p.get("domain")
            f_type = p.get("fuzzer", "unknown")
            if p_domain and p_domain != self.domain and f_type != "*original":
                targets.append((p_domain, f_type))

        async def resolve_one(p_domain: str, f_type: str):
            loop = asyncio.get_running_loop()
            def sync_lookup():
                old_timeout = socket.getdefaulttimeout()
                try:
                    socket.setdefaulttimeout(0.3)
                    ip = socket.gethostbyname(p_domain)
                    return ip
                except Exception:
                    return None
                finally:
                    socket.setdefaulttimeout(old_timeout)

            ip = await loop.run_in_executor(None, sync_lookup)
            if ip:
                phishing_risk = "HIGH" if f_type in ("bitsquatting", "homoglyph", "hyphenation", "omission", "replacement") else "MEDIUM"
                return {
                    "target_domain": self.domain,
                    "permutation_domain": p_domain,
                    "fuzzer_type": f_type,
                    "resolved_ip": ip,
                    "mx_records": [],
                    "ns_records": [],
                    "is_registered": True,
                    "phishing_risk": phishing_risk,
                    "details": {"dns_resolved": True}
                }
            return None

        tasks = [resolve_one(p_dom, f_tp) for p_dom, f_tp in targets]
        results = await asyncio.gather(*tasks)
        return [r for r in results if r is not None]

    def fetch_cert_details(self, domain: str) -> Dict[str, Any]:
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
            with socket.create_connection((domain, 443), timeout=1.0) as sock:
                with ctx.wrap_socket(sock, server_hostname=domain) as ssock:
                    cert = ssock.getpeercert(binary_form=False)
                    return {
                        "permutation_domain": domain,
                        "cert_issuer": str(cert.get("issuer", ""))[:200],
                        "cert_subject": str(cert.get("subject", ""))[:200],
                        "valid_from": cert.get("notBefore", ""),
                        "valid_to": cert.get("notAfter", ""),
                        "fingerprint": None
                    }
        except Exception:
            return None
