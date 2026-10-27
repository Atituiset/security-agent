"""Eval ledger: append-only record of scored panels, with regression comparison.

The ledger is derived data (default .runs/eval/); the authoritative evidence stays in the
run directories each record points at. A record binds corpus/rule/panel hashes so a score
cannot be silently re-attributed to a different corpus or rule version.
"""
import json
from pathlib import Path
from security_agent.core.storage import atomic_json, digest, now, read_json

LEDGER = 'index.jsonl'


def panel_record(name, corpus_path, panel_dir):
    corpus_path, panel_dir = Path(corpus_path).resolve(), Path(panel_dir).resolve()
    scores = read_json(panel_dir / 'scores.json')
    observations = read_json(panel_dir / 'observations.json')
    systems = {}
    for system, summary in scores['systems'].items():
        rows = [o for o in observations if o['system'] == system]
        costs = [o.get('cost_usd') for o in rows]
        systems[system] = {
            'counts': summary['counts'],
            'exact_three_way_accuracy': summary['exact_three_way_accuracy'],
            'positive_recall_including_failures': summary['positive_recall_including_failures'],
            'negative_false_positive_rate': summary['negative_false_positive_rate'],
            'resolved_negative_rate': summary['resolved_negative_rate'],
            'execution_completion_rate': summary['execution_completion_rate'],
            'inconsistent_repeated_cases': summary['inconsistent_repeated_cases'],
            'cost_known_usd': sum(c for c in costs if c is not None),
            'cost_unknown_trials': sum(c is None for c in costs),
            'rule_hashes': sorted({o.get('rule_hash') for o in rows if o.get('rule_hash')}),
        }
    return {'name': name, 'recorded_at': now(), 'split': scores.get('split'),
            'corpus': {'path': str(corpus_path), 'sha256': digest(corpus_path.read_bytes())},
            'panel': {'path': str(panel_dir),
                      'observations_sha256': digest((panel_dir / 'observations.json').read_bytes())},
            'paired_panel': scores['paired_panel'],
            'superiority_established': scores['superiority_established'],
            'systems': systems}


def append_ledger(directory, record):
    directory = Path(directory)
    directory.mkdir(parents=True, exist_ok=True)
    ledger = directory / LEDGER
    if ledger.exists():
        for line in ledger.read_text().splitlines():
            existing = json.loads(line)
            if existing['name'] == record['name']:
                if existing == record:
                    return False
                raise ValueError(f"ledger name {record['name']!r} already bound to a different panel")
    with ledger.open('a') as handle:
        handle.write(json.dumps(record, ensure_ascii=False) + '\n')
    (directory / 'panels').mkdir(exist_ok=True)
    atomic_json(directory / 'panels' / f"{record['name']}.json", record)
    return True


def history(directory):
    ledger = Path(directory) / LEDGER
    if not ledger.exists():
        return []
    return [json.loads(line) for line in ledger.read_text().splitlines()]


def compare(older, newer):
    """Metric deltas newer - older per system; None where a side lacks the system."""
    metrics = ('exact_three_way_accuracy', 'positive_recall_including_failures',
               'negative_false_positive_rate', 'resolved_negative_rate', 'execution_completion_rate',
               'inconsistent_repeated_cases', 'cost_known_usd')
    systems = sorted(set(older['systems']) | set(newer['systems']))
    deltas = {}
    for system in systems:
        a, b = older['systems'].get(system), newer['systems'].get(system)
        if not a or not b:
            deltas[system] = {'missing_in': 'older' if not a else 'newer'}
            continue
        deltas[system] = {m: (None if a.get(m) is None or b.get(m) is None else b[m] - a[m])
                          for m in metrics if m in a or m in b}
        deltas[system]['trials'] = (a['counts'].get('trials'), b['counts'].get('trials'))
    return {'older': older['name'], 'newer': newer['name'],
            'same_corpus': older['corpus']['sha256'] == newer['corpus']['sha256'],
            'systems': deltas}
