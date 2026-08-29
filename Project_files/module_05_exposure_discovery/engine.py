"""Module 5 Exposure Discovery Fast Engine implementing Phases A through G."""
import asyncio
import logging
import os
import re
import json
import shutil
import ssl
import socket
from pathlib import Path
from urllib.parse import urlparse, urljoin
from typing import List, Dict, Set
from uuid import UUID

import aiohttp
from sqlalchemy import select
from module_01_scope_management.db import SessionLocal, engine, Base
from module_04_attack_surface_inventory.models import UnifiedAsset
from module_02_asset_discovery.models import ResolvedIP
from .models import (
    ExposureFinding, DiscoveredForm, SecurityHeaderFinding,
    TechFingerprint, TLSFinding, ExposedSecret, TakeoverCandidate,
    Module5SubtaskStatus
)
from .subtask_status import is_phase_completed, mark_phase_completed

logger = logging.getLogger(__name__)

SECRET_PATTERNS = [
    ("AWS Access Key", "AKIA[0-9A-Z]{16}"),
    ("Generic API Key", "api_key"),
    ("Generic Secret", "secret_token"),
    ("Private Key Header", "-----BEGIN PRIVATE KEY-----"),
    ("Slack Webhook", "https://hooks.slack.com/services/")
]

SENSITIVE_FILES = [".env", ".git/config", "config.json", "backup.zip", "database.yml"]

KNOWN_TAKEOVER_SIGNALS = {
    "github.io": "There isn't a GitHub Pages site here.",
    "herokuapp.com": "No such app",
    "s3.amazonaws.com": "The specified bucket does not exist",
    "azurewebsites.net": "404 Web Site not found"
}

class ExposureEngine:
    def __init__(self, scope_id: str | UUID):
        self.raw_scope_id = scope_id
        self.scope_id = str(scope_id)
        self.uuid_scope_id = UUID(str(scope_id)) if isinstance(scope_id, (str, UUID)) else scope_id
        self.log_dir = Path("tool_output") / self.scope_id
        self.log_dir.mkdir(parents=True, exist_ok=True)
        Base.metadata.create_all(bind=engine)

    async def _async_run(self, cmd: List[str], log_file: Path, timeout: int = 5) -> str:
        logger.info(f"Running command: {' '.join(cmd)}")
        try:
            proc = await asyncio.create_subprocess_exec(
                *cmd,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE
            )
            try:
                stdout, stderr = await asyncio.wait_for(proc.communicate(), timeout=timeout)
                output = stdout.decode('utf-8', errors='ignore') + "\n" + stderr.decode('utf-8', errors='ignore')
                log_file.write_text(output, encoding='utf-8')
                return output
            except asyncio.TimeoutError:
                logger.warning(f"Command timed out after {timeout}s: {' '.join(cmd)}")
                try:
                    proc.kill()
                    await proc.wait()
                except Exception:
                    pass
                return ""
        except Exception as e:
            logger.error(f"Execution error for {' '.join(cmd)}: {e}")
            return ""

    async def run_all(self):
        logger.info(f"Starting Module 5 Exposure Discovery Engine for Scope {self.scope_id}")
        
        with SessionLocal() as session:
            assets = session.scalars(select(UnifiedAsset).where(UnifiedAsset.scope_id == self.uuid_scope_id)).all()
            asset_dicts = [
                {
                    "asset_id": str(a.asset_id),
                    "subdomain": a.subdomain,
                    "ip": a.ip,
                    "port": a.port,
                    "protocol": a.protocol,
                    "asset_type": a.asset_type,
                    "in_scope_confirmed": a.in_scope_confirmed
                }
                for a in assets
            ]

        if not is_phase_completed(self.scope_id, "Phase_A_WAF"):
            await self.phase_a_waf(asset_dicts)
            mark_phase_completed(self.scope_id, "Phase_A_WAF")

        if not is_phase_completed(self.scope_id, "Phase_B_Crawl"):
            await self.phase_b_crawl(asset_dicts)
            mark_phase_completed(self.scope_id, "Phase_B_Crawl")

        if not is_phase_completed(self.scope_id, "Phase_C_Fuzz"):
            await self.phase_c_fuzz(asset_dicts)
            mark_phase_completed(self.scope_id, "Phase_C_Fuzz")

        if not is_phase_completed(self.scope_id, "Phase_D_Param"):
            await self.phase_d_param(asset_dicts)
            mark_phase_completed(self.scope_id, "Phase_D_Param")

        if not is_phase_completed(self.scope_id, "Phase_E_TLS"):
            await self.phase_e_tls(asset_dicts)
            mark_phase_completed(self.scope_id, "Phase_E_TLS")

        if not is_phase_completed(self.scope_id, "Phase_F_Tech"):
            await self.phase_f_tech(asset_dicts)
            mark_phase_completed(self.scope_id, "Phase_F_Tech")

        if not is_phase_completed(self.scope_id, "Phase_G_Takeover"):
            await self.phase_g_takeover(asset_dicts)
            mark_phase_completed(self.scope_id, "Phase_G_Takeover")

    async def phase_a_waf(self, assets: List[dict]):
        logger.info("Executing Phase A: WAF/CDN Fingerprinting...")
        wafw00f_bin = shutil.which("wafw00f") or "/usr/bin/wafw00f"
        
        for asset in assets:
            sub = asset["subdomain"] or asset["ip"]
            port = asset["port"] or 80
            scheme = "https" if port in (443, 8443) else "http"
            target_url = f"{scheme}://{sub}:{port}"
            log_path = self.log_dir / f"Phase_A_waf_{asset['asset_id']}.log"

            out = await self._async_run([wafw00f_bin, target_url, "-o", "-", "-f", "json"], log_path, timeout=4)
            waf_detected = False
            waf_name = None

            if "is behind" in out or "detected" in out.lower():
                waf_detected = True
                m = re.search("is behind ([^\n]+)", out)
                waf_name = m.group(1).strip() if m else "Generic WAF"

            if waf_detected:
                with SessionLocal() as session:
                    session.add(ExposureFinding(
                        scope_id=self.scope_id,
                        asset_id=asset["asset_id"],
                        finding_type="WAF_DETECTED",
                        category="INFRASTRUCTURE",
                        description=f"Asset is fronted by WAF/CDN: {waf_name}",
                        severity="INFO",
                        confidence=0.9,
                        waf_detected=True,
                        in_scope_confirmed=asset["in_scope_confirmed"],
                        details={"waf_name": waf_name, "target_url": target_url}
                    ))
                    session.commit()

    async def phase_b_crawl(self, assets: List[dict]):
        logger.info("Executing Phase B: Read-only Site Structure Inventory & Secret Crawl...")
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=2)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as client:
            for asset in assets:
                sub = asset["subdomain"] or asset["ip"]
                port = asset["port"] or 80
                scheme = "https" if port in (443, 8443) else "http"
                base_url = f"{scheme}://{sub}:{port}"

                try:
                    async with client.get(base_url) as resp:
                        headers = resp.headers
                        text = await resp.text()

                        sec_headers = ["content-security-policy", "strict-transport-security", "x-frame-options", "x-content-type-options"]
                        with SessionLocal() as session:
                            for sh in sec_headers:
                                status = "PRESENT" if sh in headers else "MISSING"
                                session.add(SecurityHeaderFinding(
                                    scope_id=self.scope_id,
                                    url=base_url,
                                    header_name=sh,
                                    status=status
                                ))
                                if status == "MISSING":
                                    session.add(ExposureFinding(
                                        scope_id=self.scope_id,
                                        asset_id=asset["asset_id"],
                                        finding_type="MISSING_SECURITY_HEADER",
                                        category="CONFIG_HYGIENE",
                                        description=f"Missing recommended security header: {sh.upper()}",
                                        severity="LOW",
                                        confidence=1.0,
                                        in_scope_confirmed=asset["in_scope_confirmed"],
                                        details={"header_name": sh, "url": base_url}
                                    ))
                            session.commit()

                        if "<form" in text.lower():
                            with SessionLocal() as session:
                                session.add(DiscoveredForm(
                                    scope_id=self.scope_id,
                                    url=base_url,
                                    method="POST",
                                    inputs=[]
                                ))
                                session.commit()

                        for sec_name, pat in SECRET_PATTERNS:
                            if pat in text:
                                idx = text.find(pat)
                                snippet = text[max(0, idx-10):min(len(text), idx+50)]
                                with SessionLocal() as session:
                                    session.add(ExposedSecret(
                                        scope_id=self.scope_id,
                                        asset_id=asset["asset_id"],
                                        url=base_url,
                                        secret_type=sec_name,
                                        match_snippet=snippet
                                    ))
                                    session.add(ExposureFinding(
                                        scope_id=self.scope_id,
                                        asset_id=asset["asset_id"],
                                        finding_type="HARDCODED_SECRET",
                                        category="SECRET_HYGIENE",
                                        description=f"Potential exposed {sec_name} in response body",
                                        severity="HIGH",
                                        confidence=0.85,
                                        in_scope_confirmed=asset["in_scope_confirmed"],
                                        details={"secret_type": sec_name, "snippet": snippet, "url": base_url}
                                    ))
                                    session.commit()

                        for s_file in SENSITIVE_FILES:
                            s_url = urljoin(base_url, s_file)
                            try:
                                async with client.get(s_url) as s_resp:
                                    if s_resp.status == 200 and len(await s_resp.read()) > 0:
                                        with SessionLocal() as session:
                                            session.add(ExposureFinding(
                                                scope_id=self.scope_id,
                                                asset_id=asset["asset_id"],
                                                finding_type="SENSITIVE_FILE_EXPOSED",
                                                category="CONFIG_HYGIENE",
                                                description=f"Sensitive file publicly accessible: {s_file}",
                                                severity="MEDIUM",
                                                confidence=0.95,
                                                in_scope_confirmed=asset["in_scope_confirmed"],
                                                details={"file_path": s_file, "url": s_url}
                                            ))
                                            session.commit()
                            except Exception:
                                pass

                except Exception as e:
                    logger.debug(f"Phase B crawl skipped/failed for {base_url}: {e}")

    async def phase_c_fuzz(self, assets: List[dict]):
        logger.info("Executing Phase C: Directory & Content Discovery (ffuf)...")
        ffuf_bin = shutil.which("ffuf") or "/usr/bin/ffuf"
        wordlist = "/usr/share/wordlists/dirb/common.txt"
        if not os.path.exists(wordlist):
            wordlist = "/usr/share/wordlists/metasploit/common_roots.txt"

        for asset in assets:
            if not asset["in_scope_confirmed"]:
                logger.info(f"Skipping active Phase C fuzzing for non-confirmed asset {asset['asset_id']}")
                continue

            sub = asset["subdomain"] or asset["ip"]
            port = asset["port"] or 80
            scheme = "https" if port in (443, 8443) else "http"
            target_url = f"{scheme}://{sub}:{port}/FUZZ"
            log_path = self.log_dir / f"Phase_C_ffuf_{asset['asset_id']}.log"

            out = await self._async_run([
                ffuf_bin, "-u", target_url, "-w", wordlist,
                "-mc", "200,301,302", "-s", "-o", "-", "-of", "json", "-rate", "20"
            ], log_path, timeout=5)

            try:
                data = json.loads(out)
                results = data.get("results", [])
                with SessionLocal() as session:
                    for r in results[:10]:
                        path_found = r.get("input", {}).get("FUZZ")
                        session.add(ExposureFinding(
                            scope_id=self.scope_id,
                            asset_id=asset["asset_id"],
                            finding_type="DISCOVERED_DIRECTORY",
                            category="CONTENT_DISCOVERY",
                            description=f"Discovered unlinked web path: /{path_found} (Status: {r.get('status')})",
                            severity="INFO",
                            confidence=0.9,
                            in_scope_confirmed=True,
                            details={"path": path_found, "status": r.get("status"), "length": r.get("length")}
                        ))
                    session.commit()
            except Exception:
                pass

    async def phase_d_param(self, assets: List[dict]):
        logger.info("Executing Phase D: Safe Parameter Reflection Behavior Analysis...")
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=2)
        marker_str = "thundertest9982"

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as client:
            for asset in assets:
                if not asset["in_scope_confirmed"]:
                    continue

                sub = asset["subdomain"] or asset["ip"]
                port = asset["port"] or 80
                scheme = "https" if port in (443, 8443) else "http"
                test_url = f"{scheme}://{sub}:{port}/?q={marker_str}"

                try:
                    async with client.get(test_url) as resp:
                        body = await resp.text()
                        if marker_str in body:
                            with SessionLocal() as session:
                                session.add(ExposureFinding(
                                    scope_id=self.scope_id,
                                    asset_id=asset["asset_id"],
                                    finding_type="PARAMETER_REFLECTION",
                                    category="INPUT_HANDLING",
                                    description="Query parameter reflected unescaped in response body (Needs review)",
                                    severity="LOW",
                                    confidence=0.8,
                                    in_scope_confirmed=True,
                                    details={"parameter": "q", "url": test_url}
                                ))
                                session.commit()
                except Exception:
                    pass

    async def phase_e_tls(self, assets: List[dict]):
        logger.info("Executing Phase E: TLS/SSL Configuration Audit (sslscan)...")
        sslscan_bin = shutil.which("sslscan") or "/usr/bin/sslscan"

        for asset in assets:
            port = asset["port"] or 443
            if port not in (443, 8443):
                continue

            sub = asset["subdomain"] or asset["ip"]
            target = f"{sub}:{port}"
            log_path = self.log_dir / f"Phase_E_sslscan_{asset['asset_id']}.log"

            out = await self._async_run([sslscan_bin, "--no-failed", target], log_path, timeout=5)
            
            issues = []
            if "SSLv2" in out or "SSLv3" in out:
                issues.append("Deprecated SSLv2/SSLv3 Protocol Enabled")
            if "TLSv1.0" in out or "TLSv1.1" in out:
                issues.append("Deprecated TLS 1.0/1.1 Protocol Enabled")
            if "RC4" in out or "NULL" in out:
                issues.append("Weak Cipher Suites Supported")

            with SessionLocal() as session:
                for issue in issues:
                    session.add(TLSFinding(
                        scope_id=self.scope_id,
                        asset_id=asset["asset_id"],
                        target=target,
                        issue=issue,
                        severity="MEDIUM"
                    ))
                    session.add(ExposureFinding(
                        scope_id=self.scope_id,
                        asset_id=asset["asset_id"],
                        finding_type="TLS_MISCONFIG",
                        category="CRYPTO_HYGIENE",
                        description=issue,
                        severity="MEDIUM",
                        confidence=0.95,
                        in_scope_confirmed=asset["in_scope_confirmed"],
                        details={"target": target, "issue": issue}
                    ))
                session.commit()

    async def phase_f_tech(self, assets: List[dict]):
        logger.info("Executing Phase F: Technology Fingerprinting (whatweb)...")
        whatweb_bin = shutil.which("whatweb") or "/usr/bin/whatweb"

        for asset in assets:
            sub = asset["subdomain"] or asset["ip"]
            port = asset["port"] or 80
            scheme = "https" if port in (443, 8443) else "http"
            target_url = f"{scheme}://{sub}:{port}"
            log_path = self.log_dir / f"Phase_F_whatweb_{asset['asset_id']}.log"

            out = await self._async_run([whatweb_bin, "--log-json=-", target_url], log_path, timeout=5)
            
            try:
                for line in out.splitlines():
                    if line.startswith("[") and line.endswith("]"):
                        items = json.loads(line)
                        for item in items:
                            plugins = item.get("plugins", {})
                            with SessionLocal() as session:
                                for tech_name, tech_data in plugins.items():
                                    ver_list = tech_data.get("version", [])
                                    version = ver_list[0] if ver_list else None
                                    session.add(TechFingerprint(
                                        scope_id=self.scope_id,
                                        asset_id=asset["asset_id"],
                                        target=target_url,
                                        technology=tech_name,
                                        version=version,
                                        category="WEB_TECH"
                                    ))
                                session.commit()
            except Exception as e:
                logger.debug(f"WhatWeb JSON parse error for {target_url}: {e}")

    async def phase_g_takeover(self, assets: List[dict]):
        logger.info("Executing Phase G: Subdomain Takeover Hygiene Check...")
        connector = aiohttp.TCPConnector(ssl=False)
        timeout = aiohttp.ClientTimeout(total=2)

        async with aiohttp.ClientSession(connector=connector, timeout=timeout) as client:
            for asset in assets:
                sub = asset["subdomain"]
                if not sub:
                    continue

                for cname_suffix, sig_text in KNOWN_TAKEOVER_SIGNALS.items():
                    if cname_suffix in sub:
                        target_url = f"http://{sub}"
                        try:
                            async with client.get(target_url) as resp:
                                body = await resp.text()
                                if sig_text in body:
                                    with SessionLocal() as session:
                                        session.add(TakeoverCandidate(
                                            scope_id=self.scope_id,
                                            cname=sub,
                                            service=cname_suffix,
                                            status="POTENTIAL_TAKEOVER"
                                        ))
                                        session.add(ExposureFinding(
                                            scope_id=self.scope_id,
                                            asset_id=asset["asset_id"],
                                            finding_type="SUBDOMAIN_TAKEOVER",
                                            category="DNS_HYGIENE",
                                            description=f"Dangling CNAME signature detected ({cname_suffix})",
                                            severity="HIGH",
                                            confidence=0.9,
                                            in_scope_confirmed=asset["in_scope_confirmed"],
                                            details={"subdomain": sub, "service": cname_suffix}
                                        ))
                                        session.commit()
                        except Exception:
                            pass
