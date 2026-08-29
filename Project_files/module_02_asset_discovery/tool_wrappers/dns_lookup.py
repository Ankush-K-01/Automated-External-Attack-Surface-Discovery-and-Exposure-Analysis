import dns.resolver
def run(domain:str)->dict[str,list[str]]: return {kind:[str(x) for x in dns.resolver.resolve(domain,kind,lifetime=10)] for kind in ("A","AAAA","MX","TXT","NS","CNAME") if _exists(domain,kind)}
def _exists(domain:str,kind:str)->bool:
    try: dns.resolver.resolve(domain,kind,lifetime=10); return True
    except Exception: return False
