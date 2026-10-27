"""Normalized execution traces: one timeline view over runtime runs and baseline host runs.

A trace is derived from durable artifacts only (state.json, attempt receipts, host hooks);
it never trusts report prose. Integrity bindings let an evaluator detect post-hoc edits.
"""
import json
from pathlib import Path
from security_agent.core.storage import digest, read_json


def _cost(events):
    values = [e['cost_usd'] for e in events if e.get('cost_usd') is not None]
    unknown = sum(1 for e in events if e.get('kind') == 'model_call' and e.get('cost_usd') is None)
    return {'known_usd': sum(values), 'unknown_calls': unknown}


def runtime_trace(run):
    """Trace a security-agent runtime run directory (state.json + attempts/)."""
    root = Path(run).resolve()
    state = read_json(root / 'state.json')
    events = []
    for action in state.get('prepare', {}).get('actions', []):
        events.append({'kind': 'prepare', 'actor': action['kind'], 'execution': action['execution'],
                       'detail': action.get('detail', ''), 'at': action.get('finished_at')})
    for attempt in state.get('attempts', []):
        events.append({'kind': 'model_call', 'actor': attempt.get('role'),
                       'id': attempt['id'], 'action_id': attempt.get('action_id'),
                       'investigation': attempt.get('investigation_id'), 'round': attempt.get('round'),
                       'execution': attempt.get('execution'), 'detail': attempt.get('detail', ''),
                       'reserved_usd': attempt.get('reserved_usd'), 'cost_usd': attempt.get('cost_usd'),
                       'at': attempt.get('started_at'), 'finished_at': attempt.get('finished_at')})
    for unit in state.get('investigations', []):
        for turn in unit.get('rounds', []):
            events.append({'kind': 'round', 'actor': unit['id'], 'number': turn['number'],
                           'accepted': turn.get('accepted'), 'artifact': turn.get('assessment_artifact', {}).get('sha256')})
        for decision in unit.get('decisions', []):
            events.append({'kind': 'decision', 'actor': unit['id'], 'scenario': decision['scenario_id'],
                           'verdict': decision['verdict'], 'detail': decision.get('reason', '')})
    for finding in state.get('findings', []):
        events.append({'kind': 'finding', 'actor': finding['investigation_id'], 'id': finding['id'],
                       'file': finding['file'], 'line': finding['line'],
                       'evidence_version': finding.get('evidence_version'),
                       'fingerprint': finding.get('fingerprint')})
    stages = state.get('stage_records', {})
    for name, record in stages.items():
        events.append({'kind': 'stage', 'actor': name, 'execution': record.get('status'),
                       'attempt': record.get('attempt'), 'at': record.get('updated_at') or record.get('finished_at')})
    return {'system': 'security-agent', 'run': str(root), 'execution': state['execution'],
            'policy_version': state['policy_version'], 'rule_sha256': state['rule']['sha256'],
            'baseline_head': state['baseline']['head'],
            'profile': {k: state['config'].get(k) for k in
                        ('backend', 'model', 'judge_backend', 'judge_model', 'max_calls', 'investigation_max_calls',
                         'investigation_max_usd', 'max_action_attempts', 'timeout', 'max_rounds')},
            'events': events, 'cost': _cost(events),
            'calls': sum(1 for e in events if e['kind'] == 'model_call'),
            'state_sha256': digest((root / 'state.json').read_bytes())}


def baseline_trace(run):
    """Trace a native review-skills host run directory (repository/ + host/)."""
    root = Path(run).resolve()
    host = root / 'host'
    request = read_json(host / 'request.json')
    receipt = read_json(host / 'receipt.json')
    topology = read_json(host / 'topology.json')
    hooks = [json.loads(line) for line in (host / 'hooks.jsonl').read_text().splitlines()]
    events = []
    for worker in topology.get('workers', []):
        events.append({'kind': 'worker', 'actor': worker['agent_id'], 'call_id': worker.get('call_id'),
                       'stages_read': worker.get('stages_read', []),
                       'span': [worker.get('start_event'), worker.get('return_event')]})
    for denial in receipt.get('denials', []):
        events.append({'kind': 'denial', 'actor': denial['tool'],
                       'detail': str(denial.get('input', ''))[:200]})
    tool_calls = sum(1 for e in hooks if e.get('hook_event_name') == 'PreToolUse')
    events.append({'kind': 'model_call', 'actor': 'main+workers', 'execution': receipt['execution'],
                   'cost_usd': receipt.get('cost_usd'), 'detail': f"{tool_calls} tool calls recorded"})
    return {'system': 'review-skills', 'run': str(root), 'execution': receipt['execution'],
            'topology_verified': topology.get('topology_verified'),
            'topology_errors': topology.get('errors', []),
            'model': request.get('model'), 'target': {'file': request.get('file'), 'function': request.get('function')},
            'events': events, 'cost': _cost(events),
            'calls': len(topology.get('workers', [])),
            'hooks_sha256': receipt.get('hooks_sha256'), 'messages_sha256': receipt.get('messages_sha256')}


def trace(run):
    root = Path(run).resolve()
    if (root / 'state.json').exists():
        return runtime_trace(root)
    if (root / 'host' / 'receipt.json').exists():
        return baseline_trace(root)
    raise ValueError(f'unrecognized run directory: {root}')
