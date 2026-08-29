from enum import StrEnum
from sqlalchemy import ForeignKey,Integer,String,UniqueConstraint
from sqlalchemy import JSON as JSON
from sqlalchemy.orm import Mapped,mapped_column
from module_01_scope_management.db import Base
class Row:
 id:Mapped[int]=mapped_column(Integer,primary_key=True); scope_id:Mapped[str]=mapped_column(ForeignKey("scopes.scope_id"),index=True)
class Certificate(Row,Base):
 __tablename__="certificates"; subdomain:Mapped[str]=mapped_column(String); issuer:Mapped[str|None]=mapped_column(String); subject:Mapped[str|None]=mapped_column(String); sans:Mapped[list]=mapped_column(JSON,default=list); fingerprint:Mapped[str]=mapped_column(String); valid_from:Mapped[str|None]=mapped_column(String); valid_to:Mapped[str|None]=mapped_column(String)
class IPAsnMap(Row,Base):
 __tablename__="ip_asn_map"; ip:Mapped[str]=mapped_column(String); asn:Mapped[str|None]=mapped_column(String); asn_org:Mapped[str|None]=mapped_column(String)
class IPCloudProviderMap(Row,Base):
 __tablename__="ip_cloud_provider_map"; ip:Mapped[str]=mapped_column(String); provider_name:Mapped[str|None]=mapped_column(String)
class CorrelationFinding(Row,Base):
 __tablename__="correlation_findings"; finding_type:Mapped[str]=mapped_column(String); description:Mapped[str]=mapped_column(String); related_asset_ids:Mapped[list]=mapped_column(JSON,default=list); confidence:Mapped[float]=mapped_column()
class Module3SubtaskStatus(Row,Base):
 __tablename__="module3_subtask_status"; __table_args__=(UniqueConstraint("scope_id","subtask"),); subtask:Mapped[str]=mapped_column(String); status:Mapped[str]=mapped_column(String); error:Mapped[str|None]=mapped_column(String)
