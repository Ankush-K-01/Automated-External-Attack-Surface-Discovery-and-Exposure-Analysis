from pydantic import BaseModel
class InventoryExport(BaseModel): scope_id:str; assets:list[dict]=[]; counts:dict={}
