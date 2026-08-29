"""Deterministic Risk Scorer (CVSS, EPSS, CISA KEV, WAF weighted)."""
import logging
from typing import Dict, Any

logger = logging.getLogger(__name__)

SEVERITY_WEIGHTS = {
    "CRITICAL": 9.5,
    "HIGH": 7.5,
    "MEDIUM": 5.0,
    "LOW": 2.5,
    "INFO": 0.5
}

class RiskScorer:
    @staticmethod
    def calculate_risk(finding: Dict[str, Any]) -> Dict[str, Any]:
        cvss = finding.get("cvss_score")
        epss = finding.get("epss_score")
        severity = finding.get("severity", "MEDIUM").upper()
        is_kev = finding.get("is_cisa_kev", False)
        waf_detected = finding.get("waf_detected", False)

        # 1. Base Severity Score
        sev_weight = SEVERITY_WEIGHTS.get(severity, 5.0)

        # 2. CVSS Score Component
        cvss_val = cvss if cvss is not None else sev_weight

        # 3. EPSS Score Component (scaled 0 to 10)
        epss_val = (epss * 10.0) if epss is not None else (sev_weight * 0.5)

        # 4. Weighted Formula
        base_score = (cvss_val * 0.5) + (epss_val * 0.25) + (sev_weight * 0.25)

        # 5. KEV Multiplier (1.4x for active in-the-wild exploitation)
        multiplier = 1.4 if is_kev else 1.0

        # 6. WAF Mitigation Factor (0.8x if WAF fronted)
        waf_factor = 0.8 if waf_detected else 1.0

        final_score = round(min(10.0, base_score * multiplier * waf_factor), 1)

        # Assign Risk Level
        if final_score >= 9.0:
            level = "CRITICAL"
        elif final_score >= 7.0:
            level = "HIGH"
        elif final_score >= 4.0:
            level = "MEDIUM"
        elif final_score > 0.0:
            level = "LOW"
        else:
            level = "INFO"

        result = dict(finding)
        result["risk_score"] = final_score
        result["risk_level"] = level
        return result
