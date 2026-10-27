"""Ground-truth-aware scoring; UNKNOWN and failures remain visible in denominators."""
from collections import Counter, defaultdict
from pathlib import Path
from security_agent.core.storage import digest, read_json, seal
from security_agent.pipeline.controller import SCORING_POLICIES, guard


def load_corpus(path):
    path = Path(path).resolve()
    data = read_json(path)
    seen = set()
    for case in data['cases']:
        if case['id'] in seen or case['expected'] not in ('CONFIRMED', 'REJECTED', 'UNKNOWN'):
            raise ValueError('duplicate case or invalid oracle label')
        seen.add(case['id'])
        directory = (path.parent / case['source_dir']).resolve()
        if not directory.is_relative_to(path.parent):
            raise ValueError('case source escapes corpus')
        files = {str(p.relative_to(directory)): digest(p.read_bytes()) for p in sorted(directory.rglob('*')) if p.is_file()}
        if case['file'] not in files:
            raise ValueError('missing target source')
        if not 1 <= case['sink_line'] <= len((directory / case['file']).read_text().splitlines()):
            raise ValueError('invalid oracle location')
        case['sources'] = files
    return data


def runtime_observation(case, run, repeat=1):
    root = Path(run).resolve()
    state = read_json(root / 'state.json')
    # Recheck raw artifacts and derived judgments; a report alone is not evidence.
    guard(root, state, policies=SCORING_POLICIES)
    actual = {p: record['sha256'] for p, record in state['baseline']['sources'].items()}
    if actual != case['sources']:
        raise ValueError('evaluated sources differ from the case corpus')
    units = state['investigations']
    if len(units) != 1 or units[0]['file'] != case['file'] or units[0].get('function', {}).get('name') != case['function']:
        raise ValueError('evaluated target differs from requested function')
    unit = units[0]
    matching = [d for d in unit['decisions'] if any(s['id'] == d['scenario_id'] and s['sink_line'] == case['sink_line']
                for s in unit.get('assessment', {}).get('scenarios', []))]
    confirmations = [{'file': f['file'], 'line': f['line']} for f in state['findings']]
    verdicts = {d['verdict'] for d in matching}
    verdict = 'CONFIRMED' if any(f == {'file': case['file'], 'line': case['sink_line']} for f in confirmations) else (
        'REJECTED' if verdicts == {'REJECTED'} else 'UNKNOWN')
    costs = [a.get('cost_usd') for a in state['attempts']]
    return {'case_id': case['id'], 'repeat': repeat, 'system': 'security-agent',
            'execution': state['execution'], 'verdict': verdict, 'confirmations': confirmations,
            'sources': actual, 'profile': {k: state['config'].get(k) for k in
                       ('backend','model','judge_backend','judge_model','max_calls','timeout','max_rounds')},
            'rule_hash': state['rule']['sha256'], 'run': str(root), 'state_artifact': seal(root, 'state.json'),
            'calls': len(state['attempts']), 'cost_usd': sum(costs) if all(c is not None for c in costs) else None}


def baseline_observation(case, run, repeat=1):
    """Extract a review-skills native-host observation from a run root with repository/ and host/.

    A host receipt claiming COMPLETED is not accepted unless the topology auditor verified
    five fresh sequential workers on the raw hook events; otherwise the trial stays in the
    denominators as a failed execution with empty confirmations."""
    root = Path(run).resolve()
    repo, host = root / 'repository', root / 'host'
    receipt = read_json(host / 'receipt.json')
    request = read_json(host / 'request.json')
    topology = read_json(host / 'topology.json')
    actual = {str(p.relative_to(repo)): digest(p.read_bytes()) for p in sorted(repo.rglob('*'))
              if p.is_file() and not ({'.git', '.review'} & set(p.relative_to(repo).parts))}
    if actual != case['sources']:
        raise ValueError('evaluated sources differ from the case corpus')
    if request['file'] != case['file'] or request['function'] != case['function']:
        raise ValueError('evaluated target differs from requested function')
    authentic = receipt['execution'] == 'COMPLETED' and topology.get('topology_verified') is True
    execution = receipt['execution'] if authentic else 'FAILED'
    sessions = [p for p in (repo / '.review' / 'sessions').glob('*') if p.is_dir()] if (repo / '.review' / 'sessions').is_dir() else []
    confirmations, verdict = [], 'UNKNOWN'
    if authentic:
        if len(sessions) != 1:
            raise ValueError('authentic baseline run must contain exactly one review session')
        report_path = sessions[0] / 'output' / 'findings.json'
        if report_path.is_file():
            report = read_json(report_path)
            confirmations = [{'file': f['location']['path'], 'line': f['location']['start_line']}
                             for f in report['findings']]
            counts = report['coverage']['scenario_counts']
            if any(f == {'file': case['file'], 'line': case['sink_line']} for f in confirmations):
                verdict = 'CONFIRMED'
            elif (report['status'] == 'completed' and counts['unresolved'] == 0
                  and counts['confirmed'] == 0 and counts['excluded'] > 0):
                verdict = 'REJECTED'
    calls = sum(1 for line in (host / 'hooks.jsonl').read_text().splitlines()
                if '"SubagentStart"' in line)
    return {'case_id': case['id'], 'repeat': repeat, 'system': 'review-skills',
            'execution': execution, 'verdict': verdict, 'confirmations': confirmations,
            'sources': actual, 'profile': {'backend': 'native-skill-host', 'model': request.get('model'),
                                           'timeout': request.get('timeout'), 'usd': request.get('usd')},
            'rule_hash': request['package_hashes'].get('skills/review-rules/cwe-476-null-pointer/SKILL.md'),
            'run': str(root), 'state_artifact': seal(host, 'receipt.json'),
            'calls': calls, 'cost_usd': receipt.get('cost_usd')}


def score(corpus, observations):
    cases = {c['id']: c for c in corpus['cases']}
    seen, groups = set(), defaultdict(list)
    for row in observations:
        key = (row['system'], row['case_id'], row['repeat'])
        if key in seen:
            raise ValueError('duplicate trial would bias the comparison')
        seen.add(key)
        case = cases[row['case_id']]
        if row['sources'] != case['sources']:
            raise ValueError('source mismatch in scored observation')
        if row['verdict'] not in ('CONFIRMED','REJECTED','UNKNOWN') or type(row['repeat']) is not int or row['repeat'] < 1:
            raise ValueError('invalid observation')
        groups[row['system']].append(row)
    summary = {}
    for system, rows in groups.items():
        counts = Counter()
        repeats = defaultdict(list)
        for row in rows:
            case = cases[row['case_id']]
            expected = case['expected']
            counts['trials'] += 1
            counts['expected_' + expected] += 1
            completed = row['execution'] == 'COMPLETED'
            counts['execution_completed'] += completed
            counts['execution_failed_or_incomplete'] += not completed
            counts['unknown'] += row['verdict'] == 'UNKNOWN'
            hits = [f for f in row['confirmations'] if f == {'file':case['file'], 'line':case['sink_line']}]
            false_findings = sum(not (expected == 'CONFIRMED' and f in hits)
                                 for f in row['confirmations'])
            # Execution failure affects completion/recall, not the truth of a finding.
            # A correct target verdict with extra wrong findings is not an exact trial.
            counts['exact_verdict_correct'] += (completed and row['verdict'] == expected
                                               and not false_findings
                                               and (expected != 'CONFIRMED' or bool(hits)))
            tp = completed and expected == 'CONFIRMED' and bool(hits)
            counts['true_positive_trials'] += tp
            counts['missed_positive_trials'] += expected == 'CONFIRMED' and not tp
            counts['false_positive_findings'] += false_findings
            counts['correct_findings_in_incomplete_trials'] += (not completed and expected == 'CONFIRMED') * len(hits)
            counts['negative_trials_with_false_positive'] += expected == 'REJECTED' and bool(row['confirmations'])
            counts['resolved_negative_trials'] += completed and expected == 'REJECTED' and row['verdict'] == 'REJECTED'
            counts['unsupported_confirmation_trials'] += expected == 'UNKNOWN' and bool(row['confirmations'])
            repeats[row['case_id']].append((row['execution'], row['verdict'], tuple(sorted((f['file'], f['line']) for f in row['confirmations']))))
        rate = lambda n,d: counts[n] / counts[d] if counts[d] else None
        summary[system] = {'counts': dict(counts), 'positive_recall_including_failures': rate('true_positive_trials','expected_CONFIRMED'),
                           'negative_false_positive_rate': rate('negative_trials_with_false_positive','expected_REJECTED'),
                           'resolved_negative_rate': rate('resolved_negative_trials','expected_REJECTED'),
                           'exact_three_way_accuracy': rate('exact_verdict_correct','trials'),
                           'execution_completion_rate': rate('execution_completed','trials'),
                           'repeated_cases': sum(len(v)>1 for v in repeats.values()),
                           'inconsistent_repeated_cases': sum(len(v)>1 and len(set(v))>1 for v in repeats.values()),
                           'case_ids': sorted(repeats)}
    panels = {name: {(r['case_id'],r['repeat']) for r in rows} for name,rows in groups.items()}
    paired = len(panels) == 2 and set(panels) == {'security-agent','review-skills'} and len({frozenset(p) for p in panels.values()}) == 1
    return {'split': corpus['split'], 'systems': summary, 'paired_panel': paired,
            'superiority_established': False,
            'limitations': ['Development corpus is not held-out accuracy evidence.',
                           'Comparable model, tools, budgets and authentic stage delegation must be verified separately.',
                           'A paired panel and point estimates alone do not establish superiority.',
                           'Incomplete executions stay in accuracy/recall denominators; zero findings alone is not REJECTED.']}
