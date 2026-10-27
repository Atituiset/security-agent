"""Five stage contracts and persisted handoffs, independent of Agent execution."""
from security_agent.core.storage import atomic_json, now, seal

CONTRACTS = {
    'pre-process': {'inputs': ['repository', 'revision', 'target'], 'outputs': ['baseline', 'units'],
                    'completion': 'fixed commits and unambiguous investigation scope'},
    'preload': {'inputs': ['baseline', 'units'], 'outputs': ['context'],
                'completion': 'bounded source context with explicit gaps'},
    'dispatch': {'inputs': ['units', 'context', 'rule_contract'], 'outputs': ['plan'],
                 'completion': 'every investigation assigned a compatible versioned rule'},
    'review-execute': {'inputs': ['plan', 'context'], 'outputs': ['assessments', 'decisions'],
                       'completion': 'each unit has a result or explicit execution failure'},
    'post-process': {'inputs': ['assessments', 'decisions'], 'outputs': ['report.md', 'review.sarif'],
                     'completion': 'validated results and coverage limitations published'},
}


def prepare(root, state, sources, rule):
    directory = root / 'stages'; directory.mkdir()
    records = {name: {'status': 'PENDING', 'attempt': 0, 'contract': contract}
               for name, contract in CONTRACTS.items()}
    baseline = state['baseline']
    documents = {
        'pre-process': {'commit': baseline['head'], 'units': [
            {'id': u['id'], 'file': u['file'], 'function': u.get('function')}
            for u in state['investigations']], 'limitations': baseline['limitations']},
        'preload': {'contexts': [{'unit': u['id'], 'file': u['file'], 'function': u.get('function'),
                                 'source_ref': baseline['sources'].get(u['file']),
                                 'limitations': ['types/macros and cross-file relationships require lazy queries']}
                                for u in state['investigations']],
                    'query_backend': ({'producer': 'codegraph', 'version': state['query_backend']['version'],
                                       'binding': 'graph/binding.json'} if state.get('query_backend') else None),
                    'symbol_query': 'graph/preload/symbols.json' if (root / 'graph/preload/symbols.json').exists() else None},
        'dispatch': {'rule': {k: v for k, v in rule.items() if k != 'prompts'},
                     'assignments': [{'unit': u['id'], 'rule': rule['id'], 'version': rule['version']}
                                     for u in state['investigations']]}}
    for name, document in documents.items():
        rel = f'stages/{name}.json'
        atomic_json(root / rel, document)
        artifact = seal(root, rel)
        state['baseline']['artifacts'].append(artifact)
        records[name].update(status='PARTIAL' if baseline['limitations'] or name == 'preload' else 'COMPLETED',
                             attempt=1, artifact=artifact, finished_at=now())
    state['stage_records'] = records
    atomic_json(directory / 'pipeline.json', records)


def checkpoint(root, state, name, status):
    record = state['stage_records'][name]
    if status == 'RUNNING':
        record['attempt'] += 1
    record.update(status=status, updated_at=now())
    if status != 'RUNNING':
        rel = f'stages/{name}.json'
        atomic_json(root / rel, {'stage': name, 'status': status,
                                'units': [{'id': u['id'], 'execution': u['execution'], 'verdict': u['verdict']}
                                          for u in state['investigations']]})
        record['artifact'] = seal(root, rel)
    atomic_json(root / 'stages/pipeline.json', state['stage_records'])
