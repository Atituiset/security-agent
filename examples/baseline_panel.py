"""Assemble the paired 10-case x 3-repeat baseline panel; failed trials stay in denominators.

Reuses already-recorded native baseline runs, executes missing trials sequentially,
and merges the security-agent panel observations into one scored panel."""
import json
import shutil
import subprocess
from pathlib import Path
import anyio
from security_agent.core.storage import atomic_json, digest, read_json
from security_agent.infra.claude import provider_env
from security_agent.validation.baseline_host import run_baseline
from security_agent.validation.benchmark import baseline_observation, load_corpus, score

PANEL = Path('.runs/paired-panel-v1')
AGENT_PANEL = Path('.runs/benchmark-development-r113-x3')
# Trials already recorded with the same case/repeat assignment.
EXISTING = {('C001', 1): '.runs/baseline-native-probe-v1',
            ('C001', 2): '.runs/baseline-native-probe-v2',
            ('C001', 3): '.runs/baseline-native-probe-v3',
            ('C002', 1): '.runs/baseline-native-c002-v1',
            ('C002', 2): '.runs/baseline-native-c002-v2'}
USD, TIMEOUT = 8.0, 900.0


def fixture(repo, source):
    shutil.copytree(source, repo)
    for cmd in [('init', '-q'), ('add', '.'), ('-c', 'user.name=Benchmark', '-c', 'user.email=benchmark@example.invalid', 'commit', '-qm', 'fixture')]:
        subprocess.run(['git', '-C', str(repo), *cmd], check=True, capture_output=True)


async def main():
    corpus = load_corpus('benchmarks/corpus.json')
    cases = {c['id']: c for c in corpus['cases']}
    model = provider_env().get('ANTHROPIC_MODEL', 'sonnet')
    fresh = not PANEL.exists()
    PANEL.mkdir(parents=True, exist_ok=True)
    planned = [(c['id'], r) for c in corpus['cases'] for r in (1, 2, 3)]
    missing = [k for k in planned if k not in EXISTING]
    if fresh:
        atomic_json(PANEL / 'experiment.json', {
            'corpus_sha256': digest(Path('benchmarks/corpus.json').read_bytes()),
            'agent_panel': str(AGENT_PANEL.resolve()), 'existing_baseline_runs': {f'{c}:{r}': p for (c, r), p in EXISTING.items()},
            'planned_trials': len(planned), 'missing_trials': len(missing),
            'config': {'model': model, 'usd': USD, 'timeout': TIMEOUT},
            'planned_usd_reservation': len(missing) * USD, 'status': 'RUNNING'})
    observations = list(read_json(AGENT_PANEL / 'observations.json'))
    for row in observations:
        row['system'] = 'security-agent'
    for (case_id, repeat), run_dir in EXISTING.items():
        observations.append(baseline_observation(cases[case_id], run_dir, repeat))
    prior = []
    if (PANEL / 'observations.json').exists():
        prior = [o for o in read_json(PANEL / 'observations.json') if o['system'] == 'review-skills'
                 and (o['case_id'], o['repeat']) not in EXISTING]
    done = {(o['case_id'], o['repeat']) for o in prior}
    observations.extend(prior)
    atomic_json(PANEL / 'observations.json', observations)
    for case_id, repeat in missing:
        if (case_id, repeat) in done:
            continue
        case = cases[case_id]
        run = PANEL / f'{case_id}-r{repeat}'
        if not (run / 'host' / 'receipt.json').exists():
            if (run / 'host').exists():
                raise RuntimeError(f'partial baseline run without receipt: {run}; inspect or remove before rerunning')
            run.mkdir(parents=True, exist_ok=True)
            fixture(run / 'repository', Path('benchmarks') / case['source_dir'])
            receipt = await run_baseline(run / 'repository', '../review-skills/skills/review', run / 'host',
                                         file=case['file'], function=case['function'], model=model,
                                         timeout=TIMEOUT, usd=USD)
            print(f"{case_id} r{repeat} execution={receipt['execution']} topology={receipt['topology_verified']} cost={receipt['cost_usd']}", flush=True)
        row = baseline_observation(case, run, repeat)
        atomic_json(run / 'observation.json', row)
        observations.append(row)
        atomic_json(PANEL / 'observations.json', observations)
        atomic_json(PANEL / 'scores.json', score(corpus, observations))
    experiment = read_json(PANEL / 'experiment.json')
    experiment['status'] = 'COMPLETED'
    atomic_json(PANEL / 'experiment.json', experiment)
    result = score(corpus, observations)
    atomic_json(PANEL / 'scores.json', result)
    print(json.dumps({'paired_panel': result['paired_panel'],
                      'systems': {k: v['counts'] for k, v in result['systems'].items()}}, ensure_ascii=False))


if __name__ == '__main__':
    anyio.run(main)
