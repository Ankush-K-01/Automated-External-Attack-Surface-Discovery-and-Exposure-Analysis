from datetime import datetime
from uuid import UUID,uuid4
from sqlalchemy import Boolean,DateTime,ForeignKey,Integer,String,UniqueConstraint,func
from sqlalchemy import JSON as JSON,UUID as PG_UUID
from sqlalchemy.orm import Mapped,mapped_column
from module_01_scope_management.db import Base
class UnifiedAsset(Base):
 __tablename__="unified_assets"; __table_args__=(UniqueConstraint("scope_id","subdomain","ip","port","protocol"),)
 asset_id:Mapped[UUID]=mapped_column(PG_UUID(as_uuid=True),primary_key=True,default=uuid4); scope_id:Mapped[str]=mapped_column(ForeignKey("scopes.scope_id"),index=True); subdomain:Mapped[str|None]=mapped_column(String); ip:Mapped[str|None]=mapped_column(String); port:Mapped[int|None]=mapped_column(); protocol:Mapped[str]=mapped_column(String,default="tcp"); asn:Mapped[str|None]=mapped_column(String); asn_org:Mapped[str|None]=mapped_column(String); cloud_provider:Mapped[str|None]=mapped_column(String); geo_country:Mapped[str|None]=mapped_column(String); geo_city:Mapped[str|None]=mapped_column(String); cert_fingerprint:Mapped[str|None]=mapped_column(String); asset_type:Mapped[str]=mapped_column(String,default="UNKNOWN_SERVICE"); in_scope_confirmed:Mapped[bool]=mapped_column(Boolean,default=True); first_seen:Mapped[datetime]=mapped_column(DateTime(timezone=True),server_default=func.now()); last_seen:Mapped[datetime]=mapped_column(DateTime(timezone=True),server_default=func.now()); discovery_sources:Mapped[list]=mapped_column(JSON,default=list)
class AssetCorrelationFlag(Base):
 __tablename__="asset_correlation_flags"; id:Mapped[int]=mapped_column(Integer,primary_key=True); asset_id:Mapped[UUID]=mapped_column(ForeignKey("unified_assets.asset_id")); finding_type:Mapped[str]=mapped_column(String); description:Mapped[str]=mapped_column(String); confidence:Mapped[float]=mapped_column()
class InventorySnapshotMeta(Base):
 __tablename__="inventory_snapshot_meta"; id:Mapped[int]=mapped_column(Integer,primary_key=True); scope_id:Mapped[str]=mapped_column(ForeignKey("scopes.scope_id"),index=True); total_assets:Mapped[int]=mapped_column(); generated_at:Mapped[datetime]=mapped_column(DateTime(timezone=True),server_default=func.now())
