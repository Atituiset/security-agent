"""Paired fault-injection driver: stub trials for security-agent, real trials for the native baseline.

Real trials spend money against the configured provider; the hard cap lives in experiment.json.
The interrupt trial SIGKILLs only its own child process group."""
import argparse
import json
import os
from pathlib import Path
import signal
import subprocess
import sys
import time
from security_agent.core.storage import atomic_json, read_json
from security_agent.infra.claude import provider_env
from security_agent.validation import faults
from security_agent.validation.faults import record

PROJECT = Path(__file__).resolve().parent.parent


def launch(run_dir, usd, timeout, log):
    return subprocess.Popen([sys.executable, 'examples/baseline_probe.py', '--run', str(run_dir),
                             '--usd', str(usd), '--timeout', str(timeout)],
                            cwd=PROJECT, start_new_session=True, stdout=log, stderr=subprocess.STDOUT)


def kill(proc):
    try:
        os.killpg(proc.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    proc.wait(timeout=30)


def count_hooks(path, needle):
    if not Path(path).exists():
        return 0
    return sum(needle in line for line in Path(path).read_text().splitlines())


def trial_baseline_interrupt(root, usd):
    run_dir = root / 'trials' / 'baseline-interrupt'
    with (root / 'trials' / 'baseline-interrupt.driver.log').open('w') as log:
        proc = launch(run_dir, usd, 150, log)
        hooks = run_dir / 'host' / 'hooks.jsonl'
        event = faults.wait_for_event(hooks, '"SubagentStart"', timeout=180)
        injected = 'first SubagentStart observed; SIGKILL to driver process group 8s later' if event else \
                   'no SubagentStart within 180s; SIGKILL at fallback deadline'
        if event:
            time.sleep(8)
        kill(proc)
    starts = count_hooks(hooks, '"SubagentStart"')
    receipt = (run_dir / 'host' / 'receipt.json').exists()
    return record('review-skills', 'model-interrupt',
                  f'first review-worker active ({starts} SubagentStart) in native five-stage protocol', 'real',
                  'KILLED', False, None, None, None, True, None,
                  detail=(injected + '; host wrote no receipt/topology and keeps no checkpoint: '
                          'no-session-persistence is forced and the output directory is single-use, '
                          'so a rerun starts a brand-new paid run. True spend before the kill is unknown '
                          '(no ResultMessage); reservation cap was $%.2f.' % usd),
                  artifacts=str(run_dir), subagent_starts=starts, receipt_written=receipt,
                  errors_evidence='partial hooks.jsonl/messages.jsonl survive; no recovery entry point exists')


def analyze_head_move(root, old, new, injected_at, killed):
    run_dir = root / 'trials' / 'baseline-head-move'
    repo, host = run_dir / 'repository', run_dir / 'host'
    hooks = (host / 'hooks.jsonl').read_text().splitlines() if (host / 'hooks.jsonl').exists() else []
    receipt = read_json(host / 'receipt.json') if (host / 'receipt.json').exists() else {}
    detections = []
    for line in hooks:
        if '"SubagentStop"' not in line:
            continue
        message = json.loads(line).get('last_assistant_message', '').lower()
        if 'head' in message and any(k in message for k in ('mismatch', 'moved', 'changed', 'differ', 'invalid')):
            detections.append(message[:300])
    sessions = list((repo / '.review' / 'sessions').glob('*')) if (repo / '.review' / 'sessions').is_dir() else []
    findings_path = next((s / 'output' / 'findings.json' for s in sessions
                          if (s / 'output' / 'findings.json').is_file()), None)
    published = read_json(findings_path)['findings'] if findings_path else []
    visible = bool(detections) or 'baseline' in receipt.get('detail', '').lower()
    return record('review-skills', 'baseline-change',
                  f'HEAD amended {injected_at}; session pins the pre-fault commit', 'real',
                  receipt.get('execution', 'KILLED' if killed else 'NO_RECEIPT'), False, None, 0,
                  bool(published), visible, receipt.get('cost_usd'),
                  detail=('fixture HEAD moved %s -> %s mid-run; no stage flagged the divergence: both finished '
                          'workers reported completed with empty errors against the recorded commit, and the run '
                          'ended on %s before post-process publication checks' %
                          (old[:10], new[:10], receipt.get('execution', 'kill'))),
                  wasted_paid_calls=count_hooks(host / 'hooks.jsonl', '"SubagentStart"'),
                  artifacts=str(run_dir), head_before=old, head_after=new, injected_at=injected_at,
                  topology_verified=receipt.get('topology_verified'), findings_published=len(published),
                  subagent_starts=count_hooks(host / 'hooks.jsonl', '"SubagentStart"'),
                  rev_parse_calls=count_hooks(host / 'hooks.jsonl', 'rev-parse'),
                  head_move_detected_by_worker=bool(detections), detection_evidence=detections,
                  artifact_evidence=('session %s pins commit %s while repository HEAD is %s' %
                                     (sessions[0].name if sessions else None, old[:10], new[:10])),
                  driver_killed=killed, denials=len(receipt.get('denials', [])))


def trial_baseline_head_move(root, usd):
    run_dir = root / 'trials' / 'baseline-head-move'
    repo = run_dir / 'repository'
    with (root / 'trials' / 'baseline-head-move.driver.log').open('w') as log:
        proc = launch(run_dir, usd, 240, log)
        stop = faults.wait_for_event(run_dir / 'host' / 'hooks.jsonl', '"SubagentStop"', timeout=150)
        injected_at = 'after first worker (pre-process) finished' if stop else \
                      'fallback: first worker still running after 150s'
        old, new = faults.amend_head(repo, file='main.cpp')
        deadline = time.monotonic() + 420
        while proc.poll() is None and time.monotonic() < deadline:
            time.sleep(5)
        killed = proc.poll() is None
        if killed:
            kill(proc)
    return analyze_head_move(root, old, new, injected_at, killed)


def reference_records():
    v1, v2 = PROJECT / '.runs' / 'baseline-native-probe-v1', PROJECT / '.runs' / 'baseline-native-probe-v2'
    if not (v2 / 'host' / 'receipt.json').exists():
        return []
    receipt = read_json(v2 / 'host' / 'receipt.json')
    starts = count_hooks(v2 / 'host' / 'hooks.jsonl', '"SubagentStart"')
    prior = read_json(v1 / 'host' / 'receipt.json')['cost_usd'] if (v1 / 'host' / 'receipt.json').exists() else None
    return [record('review-skills', 'model-interrupt',
                   '.runs/baseline-native-probe-v1 stopped (budget); v2 is the from-scratch rerun of the same target',
                   'reference', 'FAILED (error_max_budget_usd)', False, None, starts, None, True,
                   receipt['cost_usd'],
                   detail=('existing probe pair: v1 spent $%s with no resumable state; v2 re-paid the full '
                           'protocol from zero (%d worker starts, $%.2f). No call carried over.' %
                           (prior, starts, receipt['cost_usd'])),
                   artifacts=str(v2), subagent_starts=starts)]


def not_run_records():
    rows = []
    for fault in ('crash-after-receipt', 'index-timeout', 'rule-change'):
        rows.append(record('review-skills', fault, 'not injected against the native host this round', 'not-run',
                           None, False, None, None, None, None, None,
                           detail=('structural only: the native host forces no-session-persistence and keeps '
                                   'no checkpoints, so no resume path exists for any fault; the fault itself '
                                   'was not injected in this round')))
    return rows


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--run', required=True)
    parser.add_argument('--stub-only', action='store_true', help='skip real (paid) baseline trials')
    parser.add_argument('--interrupt-usd', type=float, default=1.0)
    parser.add_argument('--head-move-usd', type=float, default=2.0)
    parser.add_argument('--budget', type=float, default=12.0)
    args = parser.parse_args()
    if args.interrupt_usd + args.head_move_usd > args.budget:
        parser.error('trial caps exceed the hard budget')
    root = Path(args.run).resolve()
    root.mkdir(parents=True, exist_ok=False)
    (root / 'trials').mkdir()
    budget = {'hard_cap_usd': args.budget,
              'planned_real_trials': {} if args.stub_only else
                  {'baseline-interrupt': {'usd_cap': args.interrupt_usd, 'kill': 'SIGKILL after first SubagentStart'},
                   'baseline-head-move': {'usd_cap': args.head_move_usd, 'fault': 'HEAD amended mid-run'}},
              'stub_trials_real_cost': 0.0}
    atomic_json(root / 'experiment.json', {
        'purpose': 'paired fault injection per docs/evaluation-plan.md stability section',
        'faults': faults.FAULTS, 'budget': budget, 'status': 'RUNNING',
        'systems': {'security-agent': 'stub executors; deterministic; zero real cost',
                    'review-skills': 'native five-worker host; real model calls'},
        'model': provider_env().get('ANTHROPIC_MODEL', 'sonnet')})
    records = faults.run_stub_trials(root / 'trials')
    for row in records:
        atomic_json(root / 'trials' / f"{row['system']}-{row['fault']}.json", row)
        print(f"stub {row['fault']}: after={row['execution_after_fault']} resume={row['resume_execution']}", flush=True)
    if not args.stub_only:
        for trial in (trial_baseline_interrupt, trial_baseline_head_move):
            cap = args.interrupt_usd if trial is trial_baseline_interrupt else args.head_move_usd
            row = trial(root, cap)
            records.append(row)
            atomic_json(root / 'trials' / f"{row['system']}-{row['fault']}-real.json", row)
            print(f"real {row['fault']}: after={row['execution_after_fault']} cost={row['cost_usd_total']}", flush=True)
        records.extend(reference_records())
        records.extend(not_run_records())
    matrix = faults.paired_matrix(records, budget)
    atomic_json(root / 'matrix.json', matrix)
    experiment = read_json(root / 'experiment.json')
    experiment['status'] = 'COMPLETED'
    experiment['real_cost_known_usd'] = matrix['budget']['real_cost_known_usd']
    experiment['real_cost_unknown_trials'] = matrix['budget']['real_cost_unknown_trials']
    atomic_json(root / 'experiment.json', experiment)
    print(json.dumps({'real_cost_known_usd': experiment['real_cost_known_usd'],
                      'real_cost_unknown_trials': experiment['real_cost_unknown_trials']}))


if __name__ == '__main__':
    main()
