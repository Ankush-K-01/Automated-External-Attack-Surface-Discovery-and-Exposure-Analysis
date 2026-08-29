import subprocess
def run(target:str)->set[str]: return set(subprocess.run(["naabu","-host",target,"-silent"],capture_output=True,text=True,timeout=180,check=False).stdout.splitlines())
