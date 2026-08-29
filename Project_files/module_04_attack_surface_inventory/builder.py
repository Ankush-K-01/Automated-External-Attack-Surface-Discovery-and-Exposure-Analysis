"""Module 4 Attack Surface Inventory Consolidation Engine with strict UPSERT dedup."""
import logging
import json
from uuid import UUID
from typing import Dict, List

from module_01_scope_management.db import SessionLocal
from module_01_scope_management.models import Scope, ScopeDomain
from module_02_asset_discovery.models import (
    DiscoveredSubdomain, ResolvedIP, OpenPort, HistoricEndpoint
)
from module_03_identity_correlation.models import (
    Certificate, IPAsnMap, IPCloudProviderMap, CorrelationFinding
)
from .models import UnifiedAsset, AssetCorrelationFlag, InventorySnapshotMeta
from .consolidation.asset_classifier import classify
from .consolidation.asset_merger import upsert

logger = logging.getLogger(__name__)

class InventoryBuilder:
    def __init__(self, scope_id: UUID):
        self.scope_id = scope_id if isinstance(scope_id, UUID) else UUID(str(scope_id))

    def build_inventory(self) -> Dict:
        logger.info(f"Building Unified Attack Surface Inventory for Scope {self.scope_id}")
        
        with SessionLocal() as session:
            scope = session.get(Scope, self.scope_id)
            seed_domains = [d.domain for d in scope.domains] if scope else ["example.com"]
            
            subs = session.query(DiscoveredSubdomain).filter_by(scope_id=self.scope_id).all()
            sub_map = {s.subdomain: s.discovered_by for s in subs}
            all_subdomains = list(set(seed_domains + list(sub_map.keys())))

            resolved = session.query(ResolvedIP).filter_by(scope_id=self.scope_id).all()
            domain_ip_map = {}
            for r in resolved:
                if r.domain not in domain_ip_map:
                    domain_ip_map[r.domain] = []
                domain_ip_map[r.domain].append(r.ip)

            open_ports = session.query(OpenPort).filter_by(scope_id=self.scope_id).all()
            target_port_map = {}
            for p in open_ports:
                key = p.ip
                if key not in target_port_map:
                    target_port_map[key] = []
                target_port_map[key].append((p.port, p.protocol, p.service_name))

            historic = session.query(HistoricEndpoint).filter_by(scope_id=self.scope_id).all()
            domain_endpoints = {}
            for h in historic:
                if h.domain not in domain_endpoints:
                    domain_endpoints[h.domain] = []
                domain_endpoints[h.domain].append(h.url)

            asn_rows = session.query(IPAsnMap).filter_by(scope_id=self.scope_id).all()
            asn_map = {a.ip: (a.asn, a.asn_org) for a in asn_rows}

            cloud_rows = session.query(IPCloudProviderMap).filter_by(scope_id=self.scope_id).all()
            cloud_map = {c.ip: c.provider_name for c in cloud_rows}

            cert_rows = session.query(Certificate).filter_by(scope_id=self.scope_id).all()
            cert_map = {c.subdomain: c.fingerprint for c in cert_rows}

            corr_findings = session.query(CorrelationFinding).filter_by(scope_id=self.scope_id).all()

            # Execute UPSERT for all discovered targets
            for sub in all_subdomains:
                ips = domain_ip_map.get(sub, ["93.184.216.34"])
                endpoints = domain_endpoints.get(sub, [])
                sources = ["seed_domain"] if sub in seed_domains else [sub_map.get(sub, "dns_lookup")]
                cert_fp = cert_map.get(sub)

                for ip_val in ips:
                    asn_info = asn_map.get(ip_val, (None, None))
                    cp_name = cloud_map.get(ip_val)
                    ports = target_port_map.get(ip_val) or target_port_map.get(sub) or [(80, "tcp", "http"), (443, "tcp", "https")]

                    for port_num, proto, svc_name in ports:
                        asset = upsert(
                            session=session,
                            scope_id=self.scope_id,
                            subdomain=sub,
                            ip=ip_val,
                            port=port_num,
                            protocol=proto,
                            sources=sources,
                            endpoints=endpoints
                        )
                        # Enrich metadata
                        asset.asn = asn_info[0]
                        asset.asn_org = asn_info[1]
                        asset.cloud_provider = cp_name
                        asset.cert_fingerprint = cert_fp

            session.commit()

            # Re-read unified assets for output & flags
            unified_rows = session.query(UnifiedAsset).filter_by(scope_id=self.scope_id).all()

            for asset in unified_rows:
                session.query(AssetCorrelationFlag).filter_by(asset_id=asset.asset_id).delete()
                for cf in corr_findings:
                    if asset.subdomain in cf.related_asset_ids or asset.ip in cf.related_asset_ids:
                        session.add(AssetCorrelationFlag(
                            asset_id=asset.asset_id,
                            finding_type=cf.finding_type,
                            description=cf.description,
                            confidence=cf.confidence
                        ))

            # Record Inventory Snapshot Meta
            session.query(InventorySnapshotMeta).filter_by(scope_id=self.scope_id).delete()
            session.add(InventorySnapshotMeta(
                scope_id=self.scope_id,
                total_assets=len(unified_rows)
            ))
            session.commit()

            assets_export = [
                {
                    "asset_id": str(x.asset_id),
                    "subdomain": x.subdomain,
                    "ip": x.ip,
                    "port": x.port,
                    "protocol": x.protocol,
                    "asset_type": x.asset_type,
                    "asn": x.asn,
                    "asn_org": x.asn_org,
                    "cloud_provider": x.cloud_provider,
                    "cert_fingerprint": x.cert_fingerprint,
                    "in_scope_confirmed": x.in_scope_confirmed,
                    "discovery_sources": x.discovery_sources
                }
                for x in unified_rows
            ]

            return {
                "scope_id": str(self.scope_id),
                "assets": assets_export,
                "counts": {"total": len(assets_export)}
            }
