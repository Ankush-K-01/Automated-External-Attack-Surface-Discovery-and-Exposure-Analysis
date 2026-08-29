import subprocess
def lookup(ip:str)->str: return subprocess.run(["whois","-h","whois.cymru.com",ip],capture_output=True,text=True,timeout=20,check=False).stdout
