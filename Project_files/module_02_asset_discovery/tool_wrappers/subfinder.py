import subprocess
def run(domain:str)->set[str]: return set(subprocess.run(["subfinder","-silent","-d",domain],capture_output=True,text=True,timeout=120,check=False).stdout.splitlines())
