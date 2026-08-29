from pydantic import BaseModel
class DiscoveryExport(BaseModel): scope_id:str; subdomains:list[str]=[]; ips:list[str]=[]; dns_records:list[dict]=[]; historic_endpoints:list[str]=[]; mobile_app_candidates:list[dict]=[]
