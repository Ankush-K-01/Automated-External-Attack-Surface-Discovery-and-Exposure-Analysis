import subprocess
def run(domain:str)->set[str]: return set(subprocess.run(["amass","enum","-passive","-d",domain],capture_output=True,text=True,timeout=180,check=False).stdout.splitlines())
