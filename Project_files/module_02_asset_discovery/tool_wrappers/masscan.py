import subprocess
def run(target:str)->set[str]: return set(subprocess.run(["masscan",target,"--rate","1000"],capture_output=True,text=True,timeout=300,check=False).stdout.splitlines())
