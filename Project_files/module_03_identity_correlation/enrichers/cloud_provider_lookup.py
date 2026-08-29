import ipaddress
def provider(ip:str,ranges:dict[str,list[str]])->str|None:
 return next((name for name,nets in ranges.items() if any(ipaddress.ip_address(ip) in ipaddress.ip_network(n) for n in nets)),None)
