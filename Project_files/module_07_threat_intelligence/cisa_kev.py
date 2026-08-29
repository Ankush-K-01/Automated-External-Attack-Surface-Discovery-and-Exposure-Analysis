"""CISA Known Exploited Vulnerabilities (KEV) Catalog Fetcher & Lookup."""
import logging
import urllib.request
import json
from typing import Dict, Any, Optional

logger = logging.getLogger(__name__)

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

class CISAKEVManager:
    _cached_catalog: Optional[Dict[str, Dict[str, Any]]] = None

    @classmethod
    def load_catalog(cls) -> Dict[str, Dict[str, Any]]:
        if cls._cached_catalog is not None:
            return cls._cached_catalog

        catalog = {}
        logger.info(f"Fetching CISA KEV feed from {CISA_KEV_URL}...")
        try:
            req = urllib.request.Request(CISA_KEV_URL, headers={"User-Agent": "Thunder-ASM/1.0"})
            with urllib.request.urlopen(req, timeout=10) as resp:
                data = json.loads(resp.read().decode("utf-8"))
                vulnerabilities = data.get("vulnerabilities", [])
                for vuln in vulnerabilities:
                    cve = vuln.get("cveID")
                    if cve:
                        catalog[cve] = vuln
                logger.info(f"Loaded {len(catalog)} vulnerabilities from CISA KEV catalog.")
        except Exception as e:
            logger.error(f"Failed to fetch CISA KEV feed: {e}")

        cls._cached_catalog = catalog
        return catalog

    @classmethod
    def get_kev(cls, cve_id: str) -> Optional[Dict[str, Any]]:
        cat = cls.load_catalog()
        return cat.get(cve_id)
