"""Run the original native five-worker Skill on an independent fixture repository."""
import argparse
import shutil
import subprocess
from pathlib import Path
import anyio
from security_agent.infra.claude import provider_env
from security_agent.validation.baseline_host import run_baseline

p=argparse.ArgumentParser()
p.add_argument('--run',required=True)
p.add_argument('--package',default='../review-skills/skills/review')
p.add_argument('--source',default='benchmarks/cases/C001')
p.add_argument('--file',default='main.cpp')
p.add_argument('--function',default='inspect')
p.add_argument('--timeout',type=float,default=300)
p.add_argument('--usd',type=float,default=2)
a=p.parse_args()
root=Path(a.run).resolve();root.mkdir(parents=True,exist_ok=False)
repo=root/'repository';shutil.copytree(a.source,repo)
for cmd in [('init','-q'),('add','.'),('-c','user.name=Benchmark','-c','user.email=benchmark@example.invalid','commit','-qm','fixture')]:
    subprocess.run(['git','-C',str(repo),*cmd],check=True,capture_output=True)
async def main():
    result=await run_baseline(repo,a.package,root/'host',file=a.file,function=a.function,
        model=provider_env().get('ANTHROPIC_MODEL','sonnet'),timeout=a.timeout,usd=a.usd)
    print({k:v for k,v in result.items() if k!='denials'})
anyio.run(main)
