"""Repeat-4 top-up: rerun topology-failed baseline trials under full host enforcement
(v3: worker stage-scope + Main orchestration-scope), plus matching security-agent repeats,
so every case gets a best-protocol-condition accuracy data point. Failed trials stay recorded.
"""
import shutil
import subprocess
from pathlib import Path
import anyio
from security_agent.core.storage import atomic_json, read_json
from security_agent.infra.claude import provider_env
from security_agent.validation.baseline_host import run_baseline
from security_agent.validation.benchmark import baseline_observation, load_corpus, score

PANEL = Path('.runs/paired-panel-v1')
AGENT_R4 = Path('.runs/benchmark-development-r113-x3-r4')
USD, TIMEOUT = 8.0, 900.0


def fixture(repo, source):
    shutil.copytree(source, repo)
    for cmd in [('init', '-q'), ('add', '.'), ('-c', 'user.name=Benchmark', '-c', 'user.email=benchmark@example.invalid', 'commit', '-qm', 'fixture')]:
        subprocess.run(['git', '-C', str(repo), *cmd], check=True, capture_output=True)


async def main():
    corpus = load_corpus('benchmarks/corpus.json')
    cases = {c['id']: c for c in corpus['cases']}
    model = provider_env().get('ANTHROPIC_MODEL', 'sonnet')
    observations = list(read_json(PANEL / 'observations.json'))
    baseline_rows = [o for o in observations if o['system'] == 'review-skills']
    completed_cases = {o['case_id'] for o in baseline_rows if o['execution'] == 'COMPLETED'}
    topup = sorted(set(cases) - completed_cases)
    print(f'cases without an authentic baseline completion, repeat-4 under v3 enforcement: {topup}', flush=True)
    for case_id in topup:
        case = cases[case_id]
        run = PANEL / f'{case_id}-r4'
        if not (run / 'host' / 'receipt.json').exists():
            if run.exists():
                raise RuntimeError(f'partial repeat-4 run: {run}')
            run.mkdir(parents=True)
            fixture(run / 'repository', Path('benchmarks') / case['source_dir'])
            receipt = await run_baseline(run / 'repository', '../review-skills/skills/review', run / 'host',
                                         file=case['file'], function=case['function'], model=model,
                                         timeout=TIMEOUT, usd=USD)
            print(f"{case_id} r4 execution={receipt['execution']} topology={receipt['topology_verified']} "
                  f"main_denials={receipt.get('main_scope_denials')} cost={receipt['cost_usd']}", flush=True)
        row = baseline_observation(case, run, 4)
        atomic_json(run / 'observation.json', row)
        observations.append(row)
        atomic_json(PANEL / 'observations.json', observations)
    agent_r4 = AGENT_R4 / 'observations.json'
    if not agent_r4.exists():
        raise RuntimeError(f'run security-agent repeat-4 first: benchmark.py --cases {",".join(topup)} --repeat 1 --run {AGENT_R4}')
    for row in read_json(agent_r4):
        row['system'] = 'security-agent'
        row['repeat'] = 4
        observations.append(row)
    atomic_json(PANEL / 'observations.json', observations)
    atomic_json(PANEL / 'scores.json', score(corpus, observations))
    result = read_json(PANEL / 'scores.json')
    print({k: v['counts'] for k, v in result['systems'].items()}, flush=True)


if __name__ == '__main__':
    anyio.run(main)
