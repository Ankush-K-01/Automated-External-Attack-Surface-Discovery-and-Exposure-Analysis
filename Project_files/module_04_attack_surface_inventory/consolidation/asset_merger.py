"""Asset Merger with robust UPSERT logic for deduplication."""
from datetime import datetime, timezone
from .asset_classifier import classify
from ..models import UnifiedAsset

def upsert(session, scope_id, subdomain, ip, port, protocol, sources, endpoints=[]):
    row = session.query(UnifiedAsset).filter_by(
        scope_id=scope_id,
        subdomain=subdomain,
        ip=ip,
        port=port,
        protocol=protocol
    ).one_or_none()

    if row is None:
        atype = classify(subdomain, port, endpoints)
        row = UnifiedAsset(
            scope_id=scope_id,
            subdomain=subdomain,
            ip=ip,
            port=port,
            protocol=protocol,
            asset_type=atype,
            discovery_sources=sorted(list(set(sources)))
        )
        session.add(row)
    else:
        row.last_seen = datetime.now(timezone.utc)
        existing_sources = row.discovery_sources or []
        row.discovery_sources = sorted(list(set(existing_sources + sources)))
    
    return row
