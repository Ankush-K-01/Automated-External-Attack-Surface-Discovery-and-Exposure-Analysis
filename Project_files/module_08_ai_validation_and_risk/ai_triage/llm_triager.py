"""Groq OpenAI-Compatible LLM Triage Assistant with Rate Limiting & Graceful Fallback."""
import os
import time
import json
import logging
import urllib.request
import urllib.error
from typing import List, Dict, Any

logger = logging.getLogger(__name__)

class GroqLLMTriager:
    def __init__(self, mock_429: bool = False):
        self.api_key = os.getenv("GROQ_API_KEY")
        self.api_base = os.getenv("GROQ_API_BASE", "https://api.groq.com/openai/v1").rstrip("/")
        self.model = os.getenv("GROQ_MODEL", "openai/gpt-oss-120b")
        self.mock_429 = mock_429
        self.provider_enabled = bool(self.api_key)

    def triage_batch(self, findings: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
        """Batch triage findings using Groq OpenAI-compatible API with 429 retry & fallback."""
        if not self.provider_enabled:
            logger.info("AI enrichment skipped: GROQ_API_KEY is not configured. Using deterministic triage.")
            return [self._fallback_triage(f) for f in findings]

        if not findings:
            return []

        # Formulate single batch prompt to respect RPM / TPM rate limits
        try:
            ai_results = self._call_groq_with_retry(findings)
            if ai_results:
                enriched = []
                for i, f in enumerate(findings):
                    item = dict(f)
                    ai_info = ai_results.get(str(i), ai_results.get(f.get("title"), {}))
                    item["ai_triage_summary"] = ai_info.get("summary") or self._fallback_triage(f)["summary"]
                    item["remediation_guidance"] = ai_info.get("remediation") or self._fallback_triage(f)["remediation"]
                    enriched.append(item)
                return enriched
        except Exception as exc:
            logger.warning(f"Groq AI enrichment failed or retries exhausted: {exc}. Falling back to deterministic triage.")

        # Fallback if AI call fails or is exhausted
        return [self._fallback_triage(f) for f in findings]

    def _call_groq_with_retry(self, findings: List[Dict[str, Any]], max_retries: int = 3) -> Dict[str, Any]:
        if self.mock_429:
            raise urllib.error.HTTPError(
                url=f"{self.api_base}/chat/completions",
                code=429,
                msg="Too Many Requests (Simulated)",
                hdrs={},
                fp=None
            )

        url = f"{self.api_base}/chat/completions"
        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
            "User-Agent": "ProjectThunder-EASM/1.0"
        }

        # Compact findings summary for batch prompt
        prompt_items = []
        for idx, f in enumerate(findings):
            prompt_items.append({
                "index": str(idx),
                "title": f.get("title"),
                "finding_type": f.get("finding_type"),
                "risk_level": f.get("risk_level"),
                "risk_score": f.get("risk_score"),
                "is_cisa_kev": f.get("is_cisa_kev"),
                "source_module": f.get("source_module")
            })

        system_msg = (
            "You are a Senior Cybersecurity AI Analyst. Enrich the provided list of vulnerabilities. "
            "For each index, return a JSON object with 'summary' (executive summary & prioritization rationale) "
            "and 'remediation' (concise business impact & remediation recommendations). "
            "Return raw JSON mapping index string -> {'summary': ..., 'remediation': ...}."
        )

        body = {
            "model": self.model,
            "messages": [
                {"role": "system", "content": system_msg},
                {"role": "user", "content": json.dumps(prompt_items, indent=2)}
            ],
            "temperature": 0.2,
            "max_tokens": 1000
        }

        retry_count = 0
        backoff = 1.0

        while retry_count <= max_retries:
            try:
                req = urllib.request.Request(url, data=json.dumps(body).encode("utf-8"), headers=headers, method="POST")
                with urllib.request.urlopen(req, timeout=30) as resp:
                    data = json.loads(resp.read().decode("utf-8"))
                    content = data["choices"][0]["message"]["content"]
                    
                    # Extract JSON payload from model response
                    clean_content = content.strip()
                    if "```json" in clean_content:
                        clean_content = clean_content.split("```json")[1].split("```")[0].strip()
                    elif "```" in clean_content:
                        clean_content = clean_content.split("```")[1].split("```")[0].strip()
                        
                    return json.loads(clean_content)

            except urllib.error.HTTPError as e:
                if e.code in (429, 500, 502, 503, 504):
                    retry_count += 1
                    logger.warning(f"Groq API HTTP {e.code} Rate-Limited/Transient Error. Retry {retry_count}/{max_retries} with backoff {backoff}s...")
                    if retry_count > max_retries:
                        raise e
                    time.sleep(backoff)
                    backoff *= 2.0
                else:
                    raise e
            except Exception as e:
                logger.error(f"Unexpected error during Groq API call: {e}")
                raise e

        return {}

    def _fallback_triage(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        f_type = finding.get("finding_type", "GENERIC")
        risk_lvl = finding.get("risk_level", "MEDIUM")
        title = finding.get("title", "")

        summary = f"[Deterministic Triage] Verified {risk_lvl} finding: {title} (Source: {finding.get('source_module')})."

        remediation_map = {
            "CVE_VULNERABILITY": "Upgrade affected software component to the latest patched version and verify CISA KEV guidelines.",
            "EMAIL_AUTH_DMARC": "Update DNS _dmarc record to enforce strict p=quarantine or p=reject policy and specify rua reporting.",
            "EMAIL_AUTH_SPF": "Update SPF TXT record to specify explicit -all or ~all mechanisms and remove permissive +all directives.",
            "TYPOSQUAT_DOMAIN": "Monitor active lookalike domain for phishing activity or file UDRP domain dispute.",
            "EXPOSED_SECRET": "Immediately revoke and rotate leaked secrets/credentials and audit access logs.",
            "SUBDOMAIN_TAKEOVER": "Remove dangling DNS CNAME records or claim backend cloud resources."
        }

        remediation = remediation_map.get(f_type, "Review security configuration and apply vendor hardening guidelines.")

        result = dict(finding)
        result["ai_triage_summary"] = summary
        result["remediation_guidance"] = remediation
        return result
