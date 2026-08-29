"""Pydantic v2 request validation and canonical export schemas."""
from __future__ import annotations

import ipaddress, re
from typing import Annotated
from pydantic import BaseModel, BeforeValidator, Field, field_validator, model_validator
import tldextract

type TargetValues = list[str]
extractor = tldextract.TLDExtract(suffix_list_urls=())

def split_values(value: object) -> TargetValues:
    if value is None: return []
    values = value.split(",") if isinstance(value, str) else value
    if not isinstance(values, list): raise ValueError("must be a string or list of strings")
    return [part.strip() for item in values for part in item.split(",") if part.strip()]

Targets = Annotated[TargetValues, BeforeValidator(split_values)]

def domain(value: str) -> str:
    raw = value.strip().lower()
    if "://" in raw: raw = raw.split("://", 1)[1]
    raw = raw.removeprefix("www.").rstrip("/")
    if "/" in raw or "@" in raw or re.fullmatch(r"\d{1,3}(\.\d{1,3}){3}", raw): raise ValueError("must be a domain, not a URL path or IP address")
    result = extractor(raw)
    if not result.domain or not result.suffix: raise ValueError("must be a syntactically valid registrable domain")
    return f"{result.subdomain + '.' if result.subdomain else ''}{result.domain}.{result.suffix}"

class ScopeInput(BaseModel):
    domains: Targets = Field(default_factory=list); asns: Targets = Field(default_factory=list); cidrs: Targets = Field(default_factory=list)
    organizations: Targets = Field(default_factory=list); custom_tlds: Targets = Field(default_factory=list); scan_policy: dict = Field(default_factory=dict)
    @field_validator("domains")
    @classmethod
    def domains_valid(cls, values: TargetValues) -> TargetValues: return sorted(set(map(domain, values)))
    @field_validator("asns")
    @classmethod
    def asns_valid(cls, values: TargetValues) -> TargetValues:
        normalized = []
        for value in values:
            token = value.upper().removeprefix("AS")
            if not token.isdigit() or int(token) < 1: raise ValueError(f"invalid ASN: {value}")
            normalized.append(str(int(token)))
        return sorted(set(normalized), key=int)
    @field_validator("cidrs")
    @classmethod
    def cidrs_valid(cls, values: TargetValues) -> TargetValues:
        try: return sorted({str(ipaddress.ip_network(item, strict=False)) for item in values})
        except ValueError as exc: raise ValueError(f"invalid CIDR: {exc}") from exc
    @field_validator("organizations")
    @classmethod
    def orgs_valid(cls, values: TargetValues) -> TargetValues: return sorted({v.strip() for v in values if v.strip()}, key=str.lower)
    @field_validator("custom_tlds")
    @classmethod
    def tlds_valid(cls, values: TargetValues) -> TargetValues:
        out = [v.lower().lstrip(".") for v in values]
        if any(not re.fullmatch(r"[a-z0-9-]{2,63}", v) for v in out): raise ValueError("invalid custom TLD")
        return sorted(set(out))
    @model_validator(mode="after")
    def has_seed(self) -> "ScopeInput":
        if not any((self.domains, self.asns, self.cidrs, self.organizations, self.custom_tlds)): raise ValueError("at least one seed target is required")
        return self

class ScopeCreated(BaseModel): scope_id: str; status: str
class ScopeExport(BaseModel): scope_id: str; status: str; domains: list[str]; asns: list[int]; cidrs: list[str]; organizations: list[str]; custom_tlds: list[str]; scan_policy: dict
