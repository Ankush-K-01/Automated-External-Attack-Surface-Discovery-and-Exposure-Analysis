from pydantic import BaseModel
class CorrelationExport(BaseModel): scope_id:str; enriched_assets:list[dict]=[]; correlation_findings:list[dict]=[]; graph:dict={}
