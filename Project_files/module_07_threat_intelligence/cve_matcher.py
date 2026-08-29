"""CVE Vulnerability Matcher querying NVD public API & local dictionary fallback."""
import logging
import urllib.request
import urllib.parse
import json
import time
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

# Known vulnerability signature database for common web tech fingerprints
FALLBACK_CVE_DB = {
    "WordPress": [
        {"cve_id": "CVE-2021-29447", "cvss_score": 7.5, "severity": "HIGH", "summary": "WordPress XXE vulnerability in Media Library audio metadata parsing"},
        {"cve_id": "CVE-2022-21661", "cvss_score": 7.5, "severity": "HIGH", "summary": "WordPress SQL injection via WP_Query"}
    ],
    "Apache": [
        {"cve_id": "CVE-2021-41773", "cvss_score": 7.5, "severity": "HIGH", "summary": "Apache HTTP Server 2.4.49 path traversal and remote code execution"},
        {"cve_id": "CVE-2021-42013", "cvss_score": 9.8, "severity": "CRITICAL", "summary": "Apache HTTP Server 2.4.50 incomplete fix for CVE-2021-41773 path traversal"}
    ],
    "Grafana": [
        {"cve_id": "CVE-2021-43798", "cvss_score": 7.5, "severity": "HIGH", "summary": "Grafana directory traversal vulnerability in plugin asset endpoints"}
    ],
    "OpenSSH": [
        {"cve_id": "CVE-2023-38408", "cvss_score": 9.8, "severity": "CRITICAL", "summary": "OpenSSH PKCS#11 provider remote code execution in ssh-agent"}
    ],
    "nginx": [
        {"cve_id": "CVE-2021-23017", "cvss_score": 7.7, "severity": "HIGH", "summary": "nginx resolver off-by-one heap-based buffer overflow"}
    ]
}

class CVEMatcher:
    def __init__(self):
        self.nvd_url = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    def match_technology(self, tech_name: str, version: str = None) -> List[Dict[str, Any]]:
        matches = []
        
        # 1. Query fallback CVE dictionary first for instantaneous response
        for key, cve_list in FALLBACK_CVE_DB.items():
            if key.lower() in tech_name.lower():
                for item in cve_list:
                    item_copy = dict(item)
                    item_copy["technology"] = tech_name
                    item_copy["version"] = version
                    matches.append(item_copy)

        # 2. Query NVD Public API with rate-limit backoff if tech_name is provided
        if not matches and tech_name:
            try:
                query = f"{tech_name} {version}" if version else tech_name
                url = f"{self.nvd_url}?keywordSearch={urllib.parse.quote(query)}&resultsPerPage=5"
                req = urllib.request.Request(url, headers={"User-Agent": "Thunder-ASM/1.0"})
                with urllib.request.urlopen(req, timeout=5) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    vulnerabilities = data.get("vulnerabilities", [])
                    for v in vulnerabilities:
                        cve_obj = v.get("cve", {})
                        c_id = cve_obj.get("id")
                        metrics = cve_obj.get("metrics", {}).get("cvssMetricV31", [{}])[0]
                        cvss_data = metrics.get("cvssData", {})
                        score = cvss_data.get("baseScore")
                        sev = cvss_data.get("baseSeverity", "UNKNOWN")
                        desc = cve_obj.get("descriptions", [{}])[0].get("value")
                        pub_date = cve_obj.get("published", "")

                        if c_id:
                            matches.append({
                                "technology": tech_name,
                                "version": version,
                                "cve_id": c_id,
                                "cvss_score": score,
                                "severity": sev,
                                "summary": desc[:300] if desc else "",
                                "published_date": pub_date
                            })
                time.sleep(0.6)  # NVD free API rate limit delay (6 seconds per 10 requests without key)
            except Exception as e:
                logger.debug(f"NVD API lookup error for {tech_name}: {e}")

        return matches
