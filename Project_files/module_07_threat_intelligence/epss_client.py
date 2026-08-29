"""FIRST.org Exploit Prediction Scoring System (EPSS) API Client."""
import logging
import urllib.request
import urllib.parse
import json
import time
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

EPSS_API_URL = "https://api.first.org/data/v1/epss"

class EPSSClient:
    def __init__(self):
        self.url = EPSS_API_URL

    def get_scores(self, cve_ids: List[str]) -> Dict[str, Dict[str, Any]]:
        if not cve_ids:
            return {}

        results = {}
        # Batch query up to 30 CVEs per request
        batch_size = 30
        for i in range(0, len(cve_ids), batch_size):
            chunk = cve_ids[i:i + batch_size]
            cve_param = ",".join(chunk)
            query_url = f"{self.url}?cve={urllib.parse.quote(cve_param)}"

            try:
                req = urllib.request.Request(query_url, headers={"User-Agent": "Thunder-ASM/1.0"})
                with urllib.request.urlopen(req, timeout=8) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    items = data.get("data", [])
                    for item in items:
                        cve = item.get("cve")
                        epss_val = float(item.get("epss", 0.0))
                        percentile_val = float(item.get("percentile", 0.0))
                        dt = item.get("date")
                        results[cve] = {
                            "epss": epss_val,
                            "percentile": percentile_val,
                            "date": dt
                        }
            except Exception as e:
                logger.error(f"EPSS API error for batch {chunk}: {e}")

            time.sleep(0.2)  # Respect public API rate limits with polite delay

        return results
