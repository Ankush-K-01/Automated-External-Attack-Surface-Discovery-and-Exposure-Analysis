import socket,ssl,hashlib
def fetch(host:str,port:int=443)->dict:
 ctx=ssl.create_default_context()
 with socket.create_connection((host,port),timeout=10) as raw:
  with ctx.wrap_socket(raw,server_hostname=host) as s:
   der=s.getpeercert(binary_form=True); return {"fingerprint":hashlib.sha256(der).hexdigest(),"subject":s.getpeercert().get("subject",[]),"sans":s.getpeercert().get("subjectAltName",[])}
