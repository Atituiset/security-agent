import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from security_agent.core.contracts import Execution
from security_agent.core.executor import AgentResult
from security_agent.pipeline.controller import create, run
from security_agent.validation.evaluate import append_ledger, compare, history, panel_record
from security_agent.validation.trace import baseline_trace, trace, runtime_trace

SOURCE = 'int *get();\nint f() {\n int *p = get();\n return *p;\n}\n'


class TraceEvalTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.repo = self.root / 'repo'; self.repo.mkdir()
        (self.repo / 'a.cpp').write_text(SOURCE)
        def git(*args):
            subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True)
        git('init', '-q'); git('add', '.')
        git('-c', 'user.name=Test', '-c', 'user.email=t@example.invalid', 'commit', '-qm', 'fixture')
        self.out = self.root / 'run'
        create(self.repo, 'HEAD', 'HEAD', self.out,
               {'model': 'test', 'max_calls': 4, 'timeout': 10, 'call_usd': 0.25, 'max_context_bytes': 50000},
               target_paths=['a.cpp'], function='f')

    def finish(self):
        output = {'scenarios': [{'id': 'H1', 'sink_line': 4, 'hypothesis': 'null', 'unresolved': [],
                                 'references': [{'kind': k, 'file': 'a.cpp', 'start': a, 'end': b}
                                                for k, a, b in [('origin', 3, 3), ('sink', 4, 4), ('path', 2, 4)]]}],
                  'unresolved': []}
        class Executor:
            def execute(self, task, directory):
                if task.role == 'investigator':
                    return AgentResult(Execution.COMPLETED, output, '', 0.01)
                return AgentResult(Execution.COMPLETED,
                                   {'decisions': [{'scenario_id': 'H1', 'verdict': 'CONFIRMED', 'reason': 'ok',
                                                   'evidence_ids': task.payload['scenarios'][0]['evidence_ids'],
                                                   'unresolved': []}]}, '', 0.01)
        return run(self.out, Executor())

    def test_runtime_trace_timeline_and_cost(self):
        self.finish()
        result = runtime_trace(self.out)
        kinds = [e['kind'] for e in result['events']]
        self.assertEqual(result['system'], 'security-agent')
        self.assertEqual(result['calls'], 2)
        self.assertAlmostEqual(result['cost']['known_usd'], 0.02)
        self.assertEqual(result['cost']['unknown_calls'], 0)
        self.assertIn('prepare', kinds)
        self.assertEqual(kinds.count('model_call'), 2)
        self.assertIn('decision', kinds)
        self.assertIn('finding', kinds)
        self.assertEqual(trace(self.out)['run'], result['run'])

    def test_baseline_trace_requires_host_receipt(self):
        host = self.root / 'baseline' / 'host'
        host.mkdir(parents=True)
        (host / 'request.json').write_text(json.dumps({'file': 'main.cpp', 'function': 'inspect', 'model': 'm'}))
        (host / 'topology.json').write_text(json.dumps({'topology_verified': True, 'workers': [
            {'agent_id': 'w1', 'call_id': 'c1', 'stages_read': ['pre-process'], 'start_event': 1, 'return_event': 2}], 'errors': []}))
        (host / 'hooks.jsonl').write_text('{"hook_event_name":"PreToolUse","tool_name":"Agent"}\n')
        (host / 'receipt.json').write_text(json.dumps({'execution': 'COMPLETED', 'denials': [], 'cost_usd': 1.5,
                                                       'hooks_sha256': 'x', 'messages_sha256': 'y'}))
        result = baseline_trace(self.root / 'baseline')
        self.assertEqual(result['system'], 'review-skills')
        self.assertTrue(result['topology_verified'])
        self.assertEqual(result['calls'], 1)
        self.assertAlmostEqual(result['cost']['known_usd'], 1.5)
        self.assertEqual(trace(self.root / 'baseline')['model'], 'm')

    def panel(self, name, accuracy, trials=30):
        directory = self.root / name
        directory.mkdir()
        (directory / 'observations.json').write_text(json.dumps(
            [{'system': 'security-agent', 'cost_usd': 0.1, 'rule_hash': 'r1'}] * trials))
        (directory / 'scores.json').write_text(json.dumps({
            'split': 'development', 'paired_panel': True, 'superiority_established': False,
            'systems': {'security-agent': {
                'counts': {'trials': trials},
                'exact_three_way_accuracy': accuracy,
                'positive_recall_including_failures': 1.0,
                'negative_false_positive_rate': 0.0,
                'resolved_negative_rate': 1.0,
                'execution_completion_rate': 1.0,
                'inconsistent_repeated_cases': 0}}}))
        return directory

    def test_ledger_record_dedup_and_compare(self):
        corpus = self.root / 'corpus.json'
        corpus.write_text('{"version": 1, "split": "development", "cases": []}')
        ledger = self.root / 'eval'
        first = panel_record('v1', corpus, self.panel('p1', 0.8))
        self.assertTrue(append_ledger(ledger, first))
        self.assertFalse(append_ledger(ledger, first))
        changed = panel_record('v1', corpus, self.panel('p1b', 0.8))
        changed['paired_panel'] = False
        with self.assertRaises(ValueError):
            append_ledger(ledger, changed)
        second = panel_record('v2', corpus, self.panel('p2', 1.0))
        append_ledger(ledger, second)
        self.assertEqual([r['name'] for r in history(ledger)], ['v1', 'v2'])
        deltas = compare(first, second)
        self.assertTrue(deltas['same_corpus'])
        self.assertAlmostEqual(deltas['systems']['security-agent']['exact_three_way_accuracy'], 0.2)
        self.assertEqual(deltas['systems']['security-agent']['trials'], (30, 30))


if __name__ == '__main__':
    unittest.main()
