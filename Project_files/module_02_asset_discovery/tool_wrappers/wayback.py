import httpx
def run(domain:str)->list[list[str]]: return httpx.get("https://web.archive.org/cdx/search/cdx",params={"url":f"*.{domain}/*","output":"json","filter":"statuscode:200"},timeout=30).json()
