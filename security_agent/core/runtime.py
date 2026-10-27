"""Persistent investigation projections and bounded follow-up policy, without SDK types."""
import json
from datetime import datetime, timezone
from .contracts import ContractError
from .storage import digest, read_json, verify
from .judge import decide
from .queries import OPERATIONS


def fingerprint(value):
    return digest(json.dumps(value, sort_keys=True, ensure_ascii=True).encode())


def remaining(state):
    created = datetime.fromisoformat(state['created_at'])
    return state['config'].get('total_timeout', 1800) - (datetime.now(timezone.utc) - created).total_seconds()


def evidence_signature(assessment):
    return fingerprint(sorted({(e['kind'], e['file'], e['start'], e['end'], e['quote'])
                               for e in assessment['evidence']}))


def project(root, unit):
    """Derive current hypotheses/evidence/decisions from immutable round artifacts."""
    scenarios, evidence, decisions, versions = {}, {}, {}, {}
    gaps = []
    for turn in unit.get('rounds', []):
        artifact = turn.get('assessment_artifact')
        if not artifact:
            continue
        verify(root, artifact)
        if not turn.get('accepted', True):
            continue
        assessment = read_json(root / artifact['path'])
        for scenario in assessment['scenarios']:
            sid = scenario['id']
            scenarios[sid] = scenario
            versions[sid] = turn['number']
            decisions.pop(sid, None)
        evidence.update({e['id']: e for e in assessment['evidence']})
        gaps.extend(assessment['unresolved'])
        if turn.get('decision_artifact'):
            verify(root, turn['decision_artifact'])
            output = read_json(root / turn['decision_artifact']['path'])
            items, _ = decide(unit, assessment, output)
            decisions.update({d['scenario_id']: d for d in items})
    ids = {eid for s in scenarios.values() for eid in s['evidence_ids']}
    assessment = {'scenarios': list(scenarios.values()),
                  'evidence': [e for eid, e in evidence.items() if eid in ids],
                  'unresolved': list(dict.fromkeys(gaps))}
    hypotheses = [{'id': sid, 'statement': s['hypothesis'], 'sink_line': s['sink_line'],
                   'evidence_version': versions[sid], 'evidence_ids': s['evidence_ids'],
                   'verdict': decisions.get(sid, {}).get('verdict', 'UNKNOWN'),
                   'missing_facts': list(dict.fromkeys(s['unresolved'] + decisions.get(sid, {}).get('unresolved', [])))}
                  for sid, s in scenarios.items()]
    findings = []
    for sid, decision in decisions.items():
        s = scenarios[sid]
        subset = {'scenarios': [s], 'evidence': [evidence[eid] for eid in s['evidence_ids']], 'unresolved': []}
        _, fs = decide(unit, subset, {'decisions': [decision]})
        for f in fs:
            f['evidence_version'] = versions[sid]
        findings.extend(fs)
    return assessment, list(decisions.values()), hypotheses, findings


def refresh(root, state, unit):
    assessment, decisions, hypotheses, _ = project(root, unit)
    unit.update(assessment=assessment, decisions=decisions, hypotheses=hypotheses)
    verdicts = {d['verdict'] for d in decisions}
    unit['verdict'] = ('CONFIRMED' if 'CONFIRMED' in verdicts else 'UNKNOWN'
                       if 'UNKNOWN' in verdicts or not verdicts or len(decisions) < len(hypotheses)
                       or assessment['unresolved'] else 'REJECTED')
    findings = {}
    for other in state['investigations']:
        for f in project(root, other)[3]:
            findings.setdefault(f['fingerprint'], f)
    state['findings'] = list(findings.values())


def _checked_followups(decisions, sources):
    requests = []
    for decision in decisions:
        items = decision.get('follow_up', [])
        if items and decision['verdict'] != 'UNKNOWN':
            raise ContractError('only UNKNOWN decisions may request follow-up')
        for item in items:
            if item['operation'] not in OPERATIONS:
                raise ContractError('unsupported follow-up operation')
            args = item['arguments']
            op = item['operation']
            if op != 'find_pattern' and not args.get('symbol'):
                raise ContractError('follow-up requires symbol identity')
            if op == 'find_pattern' and (not args.get('kind') or args['kind'] == 'literal' and not args.get('text')):
                raise ContractError('follow-up pattern requires kind and literal text where applicable')
            if op == 'find_assignments' or op == 'find_pattern' and args.get('kind') != 'literal':
                if not all(k in args for k in ('file', 'start', 'end')):
                    raise ContractError('follow-up structural query requires bounded scope')
            if args.get('file') is not None and args['file'] not in sources:
                raise ContractError('follow-up file outside frozen source view')
            if 'start' in args or 'end' in args:
                if not args.get('file') or not 1 <= args.get('start', 1) <= args.get('end', len(sources[args['file']].splitlines())) <= len(sources[args['file']].splitlines()):
                    raise ContractError('invalid follow-up source range')
            requests.append({'scenario_id': decision['scenario_id'], **item})
    unique = {fingerprint(r): r for r in requests}
    return list(unique.values())


def followups(decisions, sources):
    """An invalid suggested action cannot erase an otherwise valid UNKNOWN verdict."""
    requests, rejected = [], []
    for decision in decisions:
        for item in decision.get('follow_up', []):
            try:
                requests.extend(_checked_followups([{**decision, 'follow_up': [item]}], sources))
            except ContractError as exc:
                rejected.append({'scenario_id': decision['scenario_id'], 'question': item['question'], 'reason': str(exc)})
    return list({fingerprint(r): r for r in requests}.values()), rejected


def stop(unit, reason, execution='COMPLETED'):
    unit.update(phase='done', stop_reason=reason, execution=execution)
