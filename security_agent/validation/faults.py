"""Paired fault-injection matrix: fault definitions, stub trials, and trial records.

Security-agent trials use stub executors (deterministic, zero real cost) against fresh
fixture repositories; review-skills trials are real model runs driven by examples/fault_matrix.py.
Every trial yields one structured record so both systems land in the same matrix."""
import copy
import json
import subprocess
import time
from pathlib import Path
from unittest.mock import patch
from security_agent.core.contracts import Execution
from security_agent.core.executor import AgentResult
from security_agent.core.skills import load_rule
from security_agent.core.storage import atomic_json, read_json
from security_agent.pipeline import controller
from security_agent.pipeline.controller import create, run

SOURCE = 'int *get();\nint f() {\n int *p = get();\n return *p;\n}\n'
PROVIDER = 'int *get() { return nullptr; }\n'

FAULTS = [
    {'fault': 'model-interrupt', 'fault_point': 'review-execute attempt mid-call',
     'injection': 'executor/process killed before a durable outcome exists'},
    {'fault': 'crash-after-receipt', 'fault_point': 'outcome.json durable, before checkpoint projection',
     'injection': 'process kill after the attempt receipt is written'},
    {'fault': 'index-timeout', 'fault_point': 'prepare/index action',
     'injection': 'index backend raises TimeoutError'},
    {'fault': 'baseline-change', 'fault_point': 'completed run; repository HEAD amended',
     'injection': 'git commit --amend moves the recorded baseline ref'},
    {'fault': 'rule-change', 'fault_point': 'completed run; rule package hash changed',
     'injection': 'load_rule reports a different rule sha256'},
]

REQUIRED_FIELDS = ('system', 'fault', 'fault_point', 'mode', 'execution_after_fault',
                   'resume_supported', 'resume_execution', 'duplicate_paid_calls',
                   'wasted_paid_calls', 'findings_carried', 'errors_visible',
                   'cost_usd_total', 'detail', 'artifacts')


def record(system, fault, fault_point, mode, execution_after_fault, resume_supported,
           resume_execution, duplicate_paid_calls, findings_carried, errors_visible,
           cost_usd_total, detail='', wasted_paid_calls=None, artifacts=None, **extra):
    row = {'system': system, 'fault': fault, 'fault_point': fault_point, 'mode': mode,
           'execution_after_fault': execution_after_fault, 'resume_supported': resume_supported,
           'resume_execution': resume_execution, 'duplicate_paid_calls': duplicate_paid_calls,
           'wasted_paid_calls': wasted_paid_calls, 'findings_carried': findings_carried,
           'errors_visible': errors_visible, 'cost_usd_total': cost_usd_total,
           'detail': detail, 'artifacts': artifacts}
    row.update(extra)
    return row


def assessment(expanded=False):
    refs = [('origin', 'provider.cpp', 1, 1)] if expanded else [('origin', 'a.cpp', 3, 3)]
    refs += [('sink', 'a.cpp', 4, 4), ('path', 'a.cpp', 2, 5)]
    return {'scenarios': [{'id': 'H1', 'hypothesis': 'callee may return null', 'sink_line': 4,
                          'references': [{'kind': k, 'file': f, 'start': a, 'end': b} for k, f, a, b in refs],
                          'unresolved': [] if expanded else ['callee return contract']}], 'unresolved': []}


def judge(task, verdict='UNKNOWN', follow=True):
    return {'decisions': [{'scenario_id': s['id'], 'verdict': verdict,
                          'evidence_ids': s['evidence_ids'], 'reason': 'source supports bounded assessment',
                          'unresolved': ['callee return contract'] if verdict == 'UNKNOWN' else [],
                          'follow_up': []}
                         for s in task.payload['scenarios']]}


class Executor:
    def __init__(self, *responses):
        self.responses = list(responses)
        self.tasks = []

    def execute(self, task, directory):
        self.tasks.append(task)
        item = self.responses.pop(0)
        if isinstance(item, AgentResult):
            return item
        return AgentResult(Execution.COMPLETED, item(task) if callable(item) else item, '', 0.01)


def git(repo, *args):
    return subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True, text=True)


def fixture_repo(path):
    repo = Path(path)
    repo.mkdir(parents=True)
    (repo / 'a.cpp').write_text(SOURCE)
    (repo / 'provider.cpp').write_text(PROVIDER)
    git(repo, 'init', '-q')
    git(repo, 'add', '.')
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=t@example.invalid', 'commit', '-qm', 'fixture')
    return repo


def amend_head(repo, file='provider.cpp'):
    old = git(repo, 'rev-parse', 'HEAD').stdout.strip()
    path = Path(repo) / file
    path.write_text(path.read_text() + '\nint fixture_baseline_moved;\n')
    git(repo, 'add', file)
    git(repo, '-c', 'user.name=Test', '-c', 'user.email=t@example.invalid', 'commit', '-q', '--amend', '--no-edit')
    return old, git(repo, 'rev-parse', 'HEAD').stdout.strip()


def prepare(repo, out, **kwargs):
    create(repo, 'HEAD', 'HEAD', out,
           {'model': 'test', 'max_calls': 8, 'timeout': 10, 'call_usd': 0.25,
            'max_context_bytes': 50000, **kwargs.pop('config', {})},
           target_paths=['a.cpp'], function='f', **kwargs)


def costs(state):
    values = [a.get('cost_usd') for a in state['attempts']]
    return sum(values) if all(v is not None for v in values) else None


def wasted(state):
    return sum(1 for a in state['attempts']
               if a['execution'] in ('INTERRUPTED', 'FAILED', 'TIMED_OUT') and a.get('cost_usd'))


def trial_model_interrupt(root):
    repo = fixture_repo(root / 'repo')
    out = root / 'run'
    prepare(repo, out)
    state = read_json(out / 'state.json')
    other = copy.deepcopy(state['investigations'][0])
    other['id'] = 'I0002'
    state['investigations'].append(other)
    atomic_json(out / 'state.json', state)
    first = run(out, Executor(assessment(True), lambda t: judge(t, 'CONFIRMED'),
                              AgentResult(Execution.INTERRUPTED, None, 'executor killed mid-call', 0.01)))
    before = read_json(out / 'state.json')
    carried = [f['fingerprint'] for f in before['findings']]
    completed_actions = {a['action_id'] for a in before['attempts'] if a['execution'] == 'COMPLETED'}
    resumer = Executor(assessment(True), lambda t: judge(t, 'REJECTED'))
    second = run(out, resumer)
    new_attempts = [a for a in second['attempts'] if a['id'] not in {p['id'] for p in before['attempts']}]
    duplicates = sum(1 for a in new_attempts if a['action_id'] in completed_actions)
    visible = any(a['execution'] == 'INTERRUPTED' and a['detail'] for a in second['attempts'])
    return record('security-agent', 'model-interrupt',
                  'review-execute; second investigation unit mid-investigator call', 'stub',
                  first['execution'], True, second['execution'], duplicates,
                  [f['fingerprint'] for f in second['findings']] == carried,
                  visible, costs(second), wasted_paid_calls=wasted(second),
                  detail='interrupted attempt keeps INTERRUPTED detail; resume retries only the unfinished action',
                  resume_calls=len(resumer.tasks), attempts_total=len(second['attempts']))


def trial_crash_after_receipt(root):
    repo = fixture_repo(root / 'repo')
    out = root / 'run'
    prepare(repo, out)
    original = controller.finish_attempt

    def kill(root_, state, unit, attempt, receipt):
        if attempt['role'] == 'judge':
            raise SystemExit('simulated kill after durable receipt')
        return original(root_, state, unit, attempt, receipt)

    with patch.object(controller, 'finish_attempt', side_effect=kill):
        try:
            run(out, Executor(assessment(True), lambda t: judge(t, 'CONFIRMED')))
        except SystemExit:
            pass
    crashed = read_json(out / 'state.json')
    visible = (crashed['execution'] == 'RUNNING' and crashed['attempts'][-1]['execution'] == 'RUNNING'
               and (out / 'attempts' / crashed['attempts'][-1]['id'] / 'outcome.json').exists())
    resumer = Executor()
    resumed = run(out, resumer)
    return record('security-agent', 'crash-after-receipt',
                  'judge outcome.json durable, process killed before checkpoint projection', 'stub',
                  crashed['execution'], True, resumed['execution'], len(resumer.tasks),
                  len(resumed['findings']) == 1, visible, costs(resumed),
                  wasted_paid_calls=wasted(resumed),
                  detail='durable receipt replayed on resume; no repeated paid call',
                  resume_calls=len(resumer.tasks), attempts_total=len(resumed['attempts']))


def trial_index_timeout(root):
    repo = fixture_repo(root / 'repo')
    out = root / 'run'

    def backend(baseline, root_):
        raise TimeoutError('index build exceeded its deadline')

    prepare(repo, out, prepare_backend=backend)
    prepared = read_json(out / 'state.json')
    index = next(a for a in prepared['prepare']['actions'] if a['kind'] == 'index')
    resumer = Executor(assessment(), lambda t: judge(t, 'REJECTED'))
    state = run(out, resumer)
    report = (out / 'report.md').read_text()
    visible = index['execution'] == 'FAILED' and 'TimeoutError' in index['detail'] and 'prepare/index' in report
    return record('security-agent', 'index-timeout', 'prepare/index action', 'stub',
                  f"PREPARING degraded: index {index['execution']}", True, state['execution'], 0,
                  None, visible, costs(state), wasted_paid_calls=wasted(state),
                  detail='index failure degrades to source fallback; gap visible in state and report',
                  resume_calls=len(resumer.tasks), attempts_total=len(state['attempts']))


def _completed_run(root):
    repo = fixture_repo(root / 'repo')
    out = root / 'run'
    prepare(repo, out)
    first = run(out, Executor(assessment(True), lambda t: judge(t, 'CONFIRMED')))
    assert first['execution'] == 'COMPLETED' and len(first['findings']) == 1
    return repo, out


def _stale_record(fault, fault_point, out, second, resumer):
    sarif = read_json(out / 'review.sarif')
    dropped = sarif['runs'][0]['results'] == []
    return record('security-agent', fault, fault_point, 'stub',
                  second['execution'], False, None, len(resumer.tasks),
                  not dropped if second['execution'] == 'STALE' else None,
                  second['execution'] == 'STALE' and bool(second['detail']),
                  costs(second), wasted_paid_calls=wasted(second),
                  detail=second['detail'], resume_calls=len(resumer.tasks),
                  attempts_total=len(second['attempts']))


def trial_baseline_change(root):
    repo, out = _completed_run(root)
    old, new = amend_head(repo)
    resumer = Executor()
    second = run(out, resumer)
    row = _stale_record('baseline-change',
                        'completed run with one CONFIRMED finding; fixture HEAD amended', out, second, resumer)
    row['head_before'], row['head_after'] = old, new
    return row


def trial_rule_change(root):
    repo, out = _completed_run(root)
    changed = {**load_rule(), 'sha256': '0' * 64}
    resumer = Executor()
    with patch('security_agent.pipeline.controller.load_rule', return_value=changed):
        second = run(out, resumer)
    return _stale_record('rule-change',
                         'completed run with one CONFIRMED finding; rule package hash changed', out, second, resumer)


TRIALS = {'model-interrupt': trial_model_interrupt, 'crash-after-receipt': trial_crash_after_receipt,
          'index-timeout': trial_index_timeout, 'baseline-change': trial_baseline_change,
          'rule-change': trial_rule_change}


def run_stub_trials(root):
    root = Path(root)
    root.mkdir(parents=True, exist_ok=True)
    records = []
    for spec in FAULTS:
        trial_dir = root / f"security-agent-{spec['fault']}"
        trial_dir.mkdir(exist_ok=False)
        row = TRIALS[spec['fault']](trial_dir)
        row['artifacts'] = str(trial_dir)
        atomic_json(trial_dir / 'trial.json', row)
        records.append(row)
    return records


def wait_for_event(path, needle, timeout=300, poll=2.0):
    """Poll a jsonl log for a line containing needle; return the parsed line or None."""
    deadline = time.monotonic() + timeout
    path = Path(path)
    while time.monotonic() < deadline:
        if path.exists():
            for line in path.read_text().splitlines():
                if needle in line:
                    return json.loads(line)
        time.sleep(poll)
    return None


def paired_matrix(records, budget):
    grouped = {}
    for row in records:
        grouped.setdefault(row['fault'], {}).setdefault(row['system'], []).append(row)
    rows = [{'fault': spec['fault'], 'fault_point': spec['fault_point'], 'injection': spec['injection'],
             'security-agent': grouped.get(spec['fault'], {}).get('security-agent', []),
             'review-skills': grouped.get(spec['fault'], {}).get('review-skills', [])}
            for spec in FAULTS]
    real = [r for r in records if r['mode'] == 'real']
    known = sum(r['cost_usd_total'] for r in real if r['cost_usd_total'] is not None)
    return {'faults': rows,
            'budget': {**budget, 'real_cost_known_usd': known,
                       'real_cost_unknown_trials': sum(1 for r in real if r['cost_usd_total'] is None)},
            'superiority_established': False,
            'limitations': [
                'Security-agent trials use stub executors: they prove checkpoint/resume semantics, not real model behaviour under faults.',
                'Only two fault types were injected against the native baseline host with real model calls, both on a single C001 fixture.',
                'The killed baseline run has unknown true cost; unknown is kept, not replaced by zero.',
                'For baseline-change, carrying findings across a moved baseline is the failure mode; the two systems are therefore compared on opposite directions of findings_carried.',
                'Point observations from one fixture and one model do not establish stability superiority.']}
