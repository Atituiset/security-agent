import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from security_agent.validation.reference_session import inspect_session, compare
from security_agent.pipeline.controller import create
from security_agent.core.storage import digest, read_json
from test_review import CONFIG, SOURCE


class ReferenceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / 'repo'
        self.repo.mkdir()
        def git(*args):
            return subprocess.check_output(['git', '-C', str(self.repo), *args], stderr=subprocess.PIPE).decode().strip()
        git('init', '-q')
        git('config', 'user.name', 'Test')
        git('config', 'user.email', 'test@example.invalid')
        (self.repo / 'a.cpp').write_text(SOURCE)
        git('add', '.')
        git('commit', '-qm', 'source')
        self.commit = git('rev-parse', 'HEAD')
        self.session = self.root / 'session'
        (self.session / 'context/queries').mkdir(parents=True)
        (self.session / 'reviews').mkdir()
        self.write('session.json', {'baseline': {'commit': self.commit}})
        self.write('target.json', {'type': 'file', 'repository': str(self.repo), 'paths': ['a.cpp']})
        self.write('reviews/cwe-476.json', {'scenarios': [{
            'id': 'old-1', 'sink': {'path': 'a.cpp', 'start_line': 3, 'end_line': 3},
            'state': 'excluded', 'evidence': [{'query_id': 'q1', 'fact_id': 'f1'}]}]})
        self.write('context/queries/q1.json', {'id': 'q1', 'facts': [{'id': 'f1', 'raw_ref': 'raw.txt'}],
                                            'dependencies': [{'path': 'a.cpp', 'sha256': digest(SOURCE.encode())}]})
        (self.session / 'raw.txt').write_text(SOURCE)

    def write(self, name, value):
        (self.session / name).write_text(json.dumps(value))

    def test_reference_is_verified_without_accepting_old_conclusions(self):
        ref = inspect_session(self.session)
        self.assertEqual(ref['checked_evidence_refs'], 1)
        self.assertEqual(ref['counts'], {'excluded': 1})
        output = self.root / 'run'
        create(self.repo, self.commit, self.commit, output, CONFIG,
               target_paths=ref['paths'], input_provenance=ref)
        state = read_json(output / 'state.json')
        self.assertEqual(len(state['investigations']), 1)
        self.assertEqual(state['findings'], [])
        self.assertEqual(state['investigations'][0]['verdict'], 'UNKNOWN')
        self.assertIn('not Git diff', state['baseline']['scope'])
        self.assertEqual(compare(ref, state)['cases'][0]['comparison'], 'unmatched')

    def test_changed_dependency_is_rejected(self):
        path = self.session / 'context/queries/q1.json'
        data = read_json(path)
        data['dependencies'][0]['sha256'] = '0' * 64
        self.write('context/queries/q1.json', data)
        with self.assertRaisesRegex(ValueError, 'differs from commit'):
            inspect_session(self.session)

    def test_missing_reference_is_rejected(self):
        data = read_json(self.session / 'reviews/cwe-476.json')
        data['scenarios'][0]['evidence'][0]['fact_id'] = 'missing'
        self.write('reviews/cwe-476.json', data)
        with self.assertRaisesRegex(ValueError, 'unresolvable'):
            inspect_session(self.session)

    def test_reference_path_escape_is_rejected(self):
        data = read_json(self.session / 'context/queries/q1.json')
        data['facts'][0]['raw_ref'] = '../secret.txt'
        self.write('context/queries/q1.json', data)
        with self.assertRaisesRegex(ValueError, 'escapes session'):
            inspect_session(self.session)
