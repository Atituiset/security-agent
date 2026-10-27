"""Run a frozen development corpus without passing oracle labels to the Agent."""
import argparse
from pathlib import Path
import shutil
import subprocess
import time
from security_agent.core.storage import atomic_json, read_json, digest
from security_agent.infra.claude import provider_env
from security_agent.infra.routing import RoleExecutor
from security_agent.pipeline.controller import create, run
from security_agent.tools.semantic import SemanticQueries
from security_agent.validation.benchmark import baseline_observation, load_corpus, runtime_observation, score


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--corpus', default='benchmarks/corpus.json')
    parser.add_argument('--run', required=True)
    parser.add_argument('--cases', help='comma-separated IDs; defaults to all cases')
    parser.add_argument('--repeat', type=int, default=1)
    parser.add_argument('--model')
    parser.add_argument('--max-calls', type=int, default=4)
    parser.add_argument('--call-usd', type=float, default=0.25)
    parser.add_argument('--timeout', type=float, default=120)
    parser.add_argument('--baseline', action='append', default=[],
                        help='CASE:REPEAT:RUN_DIR of a finished native baseline probe; scored into the same panel')
    args = parser.parse_args()
    corpus = load_corpus(args.corpus)
    selected = set(args.cases.split(',')) if args.cases else {c['id'] for c in corpus['cases']}
    if args.repeat < 1 or not selected <= {c['id'] for c in corpus['cases']}:
        parser.error('invalid repeat or case selection')
    root = Path(args.run).resolve(); root.mkdir(parents=True, exist_ok=False)
    config = {'model': args.model or provider_env().get('ANTHROPIC_MODEL', 'sonnet'), 'backend': 'claude',
              'max_calls': args.max_calls, 'call_usd': args.call_usd, 'timeout': args.timeout,
              'max_context_bytes': 120000, 'max_tool_calls': 12, 'max_rounds': 2, 'total_timeout': 600}
    atomic_json(root / 'experiment.json', {'corpus_sha256': digest(Path(args.corpus).read_bytes()),
                'selected_cases': sorted(selected), 'repeats': args.repeat, 'config': config,
                'planned_call_ceiling': len(selected)*args.repeat*args.max_calls,
                'planned_usd_reservation': len(selected)*args.repeat*args.max_calls*args.call_usd,
                'baseline_runs': sorted(args.baseline), 'status': 'RUNNING'})
    observations = []
    for case in corpus['cases']:
        if case['id'] not in selected: continue
        repo = root / 'repositories' / case['id']
        shutil.copytree(Path(args.corpus).resolve().parent / case['source_dir'], repo)
        def git(*cmd):
            subprocess.run(['git','-C',str(repo),*cmd],check=True,capture_output=True)
        git('init','-q'); git('add','.')
        git('-c','user.name=Benchmark','-c','user.email=benchmark@example.invalid','commit','-qm','fixture')
        for repeat in range(1,args.repeat+1):
            output = root / f"{case['id']}-{repeat}"
            start = time.monotonic()
            create(repo,'HEAD','HEAD',output,config,target_paths=[case['file']],function=case['function'])
            factory = lambda sources,access,directory: SemanticQueries(sources,access,directory)
            run(output,RoleExecutor(config),factory)
            row = runtime_observation(case,output,repeat)
            row['elapsed_seconds'] = time.monotonic()-start
            observations.append(row)
            atomic_json(root / 'observations.json', observations)
            atomic_json(root / 'scores.json', score(corpus,observations))
            print(f"{case['id']} repeat={repeat} execution={row['execution']} verdict={row['verdict']}",flush=True)
    cases = {c['id']: c for c in corpus['cases']}
    for spec in args.baseline:
        case_id, repeat, run_dir = spec.split(':', 2)
        if case_id not in cases:
            parser.error(f'unknown baseline case {case_id}')
        row = baseline_observation(cases[case_id], run_dir, int(repeat))
        row['elapsed_seconds'] = None
        observations.append(row)
        print(f"{case_id} baseline repeat={repeat} execution={row['execution']} verdict={row['verdict']}", flush=True)
    if args.baseline:
        atomic_json(root / 'observations.json', observations)
        atomic_json(root / 'scores.json', score(corpus, observations))
    experiment = read_json(root/'experiment.json'); experiment['status']='COMPLETED'
    atomic_json(root/'experiment.json',experiment)


if __name__ == '__main__':
    main()
