import json
import subprocess
import tempfile
import unittest
from pathlib import Path
from security_agent.core.storage import read_json
from security_agent.validation import faults


class StubFaultTrialTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.temp = tempfile.TemporaryDirectory()
        cls.addClassCleanup(cls.temp.cleanup)
        cls.root = Path(cls.temp.name) / 'trials'
        cls.records = {r['fault']: r for r in faults.run_stub_trials(cls.root)}

    def test_all_faults_have_structured_records(self):
        self.assertEqual(set(self.records), {f['fault'] for f in faults.FAULTS})
        for row in self.records.values():
            for field in faults.REQUIRED_FIELDS:
                self.assertIn(field, row)
            self.assertEqual(row['system'], 'security-agent')
            self.assertEqual(row['mode'], 'stub')
            self.assertTrue((Path(row['artifacts']) / 'trial.json').exists())

    def test_model_interrupt_resumes_without_duplicate_paid_calls(self):
        row = self.records['model-interrupt']
        self.assertEqual(row['execution_after_fault'], 'INTERRUPTED')
        self.assertTrue(row['resume_supported'])
        self.assertEqual(row['resume_execution'], 'COMPLETED')
        self.assertEqual(row['duplicate_paid_calls'], 0)
        self.assertEqual(row['wasted_paid_calls'], 1)
        self.assertEqual(row['resume_calls'], 2)
        self.assertEqual(row['attempts_total'], 5)
        self.assertTrue(row['findings_carried'])
        self.assertTrue(row['errors_visible'])
        self.assertEqual(row['cost_usd_total'], 0.05)

    def test_crash_after_durable_receipt_replays_without_model(self):
        row = self.records['crash-after-receipt']
        self.assertEqual(row['execution_after_fault'], 'RUNNING')
        self.assertEqual(row['resume_execution'], 'COMPLETED')
        self.assertEqual(row['duplicate_paid_calls'], 0)
        self.assertEqual(row['resume_calls'], 0)
        self.assertEqual(row['attempts_total'], 2)
        self.assertTrue(row['findings_carried'])
        self.assertTrue(row['errors_visible'])

    def test_index_timeout_degrades_with_visible_gap(self):
        row = self.records['index-timeout']
        self.assertIn('index FAILED', row['execution_after_fault'])
        self.assertEqual(row['resume_execution'], 'COMPLETED')
        self.assertIsNone(row['findings_carried'])
        self.assertTrue(row['errors_visible'])
        state = read_json(Path(row['artifacts']) / 'run/state.json')
        index = next(a for a in state['prepare']['actions'] if a['kind'] == 'index')
        self.assertEqual(index['execution'], 'FAILED')
        self.assertIn('prepare/index', (Path(row['artifacts']) / 'run/report.md').read_text())

    def test_baseline_and_rule_change_are_stale_and_drop_findings(self):
        for fault, phrase in (('baseline-change', 'reference moved'), ('rule-change', 'security skill changed')):
            row = self.records[fault]
            self.assertEqual(row['execution_after_fault'], 'STALE')
            self.assertFalse(row['resume_supported'])
            self.assertIsNone(row['resume_execution'])
            self.assertEqual(row['duplicate_paid_calls'], 0)
            self.assertEqual(row['resume_calls'], 0)
            self.assertFalse(row['findings_carried'])
            self.assertTrue(row['errors_visible'])
            self.assertIn(phrase, row['detail'])
            sarif = read_json(Path(row['artifacts']) / 'run/review.sarif')
            self.assertEqual(sarif['runs'][0]['results'], [])

    def test_baseline_change_records_head_movement(self):
        row = self.records['baseline-change']
        self.assertNotEqual(row['head_before'], row['head_after'])

    def test_paired_matrix_keeps_all_records_and_never_claims_superiority(self):
        matrix = faults.paired_matrix(list(self.records.values()), {'hard_cap_usd': 12})
        self.assertEqual([r['fault'] for r in matrix['faults']], [f['fault'] for f in faults.FAULTS])
        for row in matrix['faults']:
            self.assertEqual(len(row['security-agent']), 1)
            self.assertEqual(row['review-skills'], [])
        self.assertFalse(matrix['superiority_established'])
        self.assertTrue(matrix['limitations'])


class FaultHelperTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)

    def test_wait_for_event_matches_and_times_out(self):
        log = self.root / 'hooks.jsonl'
        log.write_text(json.dumps({'hook_event_name': 'SubagentStart'}) + '\n')
        self.assertEqual(faults.wait_for_event(log, '"SubagentStart"', timeout=1, poll=0.05),
                         {'hook_event_name': 'SubagentStart'})
        self.assertIsNone(faults.wait_for_event(log, '"SubagentStop"', timeout=0.2, poll=0.05))
        self.assertIsNone(faults.wait_for_event(self.root / 'missing.jsonl', 'x', timeout=0.2, poll=0.05))

    def test_amend_head_moves_head_and_keeps_fixture_commitable(self):
        repo = faults.fixture_repo(self.root / 'repo')
        old, new = faults.amend_head(repo)
        self.assertNotEqual(old, new)
        head = subprocess.run(['git', '-C', str(repo), 'rev-parse', 'HEAD'],
                              check=True, capture_output=True, text=True).stdout.strip()
        self.assertEqual(head, new)
        self.assertIn('fixture_baseline_moved', (repo / 'provider.cpp').read_text())


if __name__ == '__main__':
    unittest.main()
