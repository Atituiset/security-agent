import copy
from datetime import datetime, timedelta, timezone
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch
from security_agent.pipeline.controller import create, run
from security_agent.core.executor import AgentResult
from security_agent.core.contracts import Execution
from security_agent.core.storage import read_json, atomic_json

SOURCE = 'int *get();\nint f() {\n int *p = get();\n return *p;\n}\n'
PROVIDER = 'int *get() { return nullptr; }\n'


def assessment(expanded=False, sid='H1'):
    refs = [('origin', 'provider.cpp', 1, 1)] if expanded else [('origin', 'a.cpp', 3, 3)]
    refs += [('sink', 'a.cpp', 4, 4), ('path', 'a.cpp', 2, 5)]
    return {'scenarios': [{'id': sid, 'hypothesis': 'callee may return null', 'sink_line': 4,
                          'references': [{'kind': k, 'file': f, 'start': a, 'end': b} for k,f,a,b in refs],
                          'unresolved': [] if expanded else ['callee return contract']}], 'unresolved': []}


def judge(task, verdict='UNKNOWN', follow=True):
    return {'decisions': [{'scenario_id': s['id'], 'verdict': verdict,
                          'evidence_ids': s['evidence_ids'], 'reason': 'source supports bounded assessment',
                          'unresolved': ['callee return contract'] if verdict == 'UNKNOWN' else [],
                          'follow_up': [{'question': 'When does get return null?', 'operation': 'find_definition',
                                         'arguments': {'symbol': 'get', 'purpose': 'resolve return contract'}}]
                                        if verdict == 'UNKNOWN' and follow else []}
                         for s in task.payload['scenarios']]}


class Executor:
    def __init__(self, *responses):
        self.responses = list(responses); self.tasks = []
    def execute(self, task, directory):
        self.tasks.append(task)
        item = self.responses.pop(0)
        if isinstance(item, AgentResult):
            return item
        return AgentResult(Execution.COMPLETED, item(task) if callable(item) else item, '', 0.01)


class RuntimeTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.repo = self.root / 'repo'; self.repo.mkdir()
        for file, source in {'a.cpp': SOURCE, 'provider.cpp': PROVIDER}.items():
            (self.repo / file).write_text(source)
        def git(*args):
            subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True)
        git('init', '-q'); git('add', '.')
        git('-c', 'user.name=Test', '-c', 'user.email=t@example.invalid', 'commit', '-qm', 'fixture')
        self.out = self.root / 'run'
    def prepare(self, **config):
        create(self.repo, 'HEAD', 'HEAD', self.out,
               {'model': 'test', 'max_calls': 8, 'timeout': 10, 'call_usd': 0.25,
                'max_context_bytes': 50000, **config}, target_paths=['a.cpp'], function='f')

    def test_judge_gap_drives_second_round_and_versioned_finding(self):
        self.prepare()
        executor = Executor(assessment(), judge, assessment(True), lambda t: judge(t, 'CONFIRMED'))
        state = run(self.out, executor)
        unit = state['investigations'][0]
        self.assertEqual([t.role for t in executor.tasks], ['investigator','judge','investigator','judge'])
        self.assertEqual(len(unit['rounds']), 2)
        self.assertEqual(unit['hypotheses'][0]['evidence_version'], 2)
        self.assertEqual(state['findings'][0]['evidence_version'], 2)
        self.assertTrue(executor.tasks[2].payload['follow_up'])
        self.assertEqual(executor.tasks[3].payload['evidence_version'], 2)
        self.assertNotIn('callee may return null', str(executor.tasks[3].payload))
        self.assertEqual(len(state['actions']), 4)
        self.assertTrue((self.out / 'attempts/A00004/outcome.json').exists())
        self.assertEqual(len(run(self.out, executor)['attempts']), 4)

    def test_no_new_evidence_stops_without_repeated_judge(self):
        self.prepare()
        executor = Executor(assessment(), judge, assessment())
        state = run(self.out, executor)
        unit = state['investigations'][0]
        self.assertEqual(state['execution'], 'COMPLETED')
        self.assertEqual(unit['verdict'], 'UNKNOWN')
        self.assertIn('no new evidence', unit['stop_reason'])
        self.assertEqual(len(executor.tasks), 3)
        self.assertFalse(unit['rounds'][-1]['accepted'])
        self.assertEqual(unit['hypotheses'][0]['evidence_version'], 1)

    def test_followup_can_refute_instead_of_confirm(self):
        self.prepare()
        state = run(self.out, Executor(assessment(), judge, assessment(True), lambda t: judge(t, 'REJECTED')))
        self.assertEqual(state['investigations'][0]['verdict'], 'REJECTED')
        self.assertEqual(state['findings'], [])

    def test_followup_round_limit_and_call_budget(self):
        for limits in ({'max_rounds': 1}, {'max_calls': 2}):
            self.out = self.root / ('limit-' + next(iter(limits)))
            self.prepare(**limits)
            state = run(self.out, Executor(assessment(), judge))
            self.assertEqual(state['execution'], 'BUDGET_EXHAUSTED')
            self.assertEqual(state['investigations'][0]['verdict'], 'UNKNOWN')
            self.assertEqual(len(state['attempts']), 2)

    def test_interrupt_followup_resumes_same_action_with_new_attempt(self):
        self.prepare()
        executor = Executor(assessment(), judge, AgentResult(Execution.INTERRUPTED, None, 'cancelled'))
        first = run(self.out, executor)
        self.assertEqual(first['execution'], 'INTERRUPTED')
        self.assertEqual(first['investigations'][0]['round'], 2)
        second = run(self.out, Executor(assessment(True), lambda t: judge(t, 'CONFIRMED')))
        self.assertEqual(second['execution'], 'COMPLETED')
        action = second['actions']['I0001-R2-investigator']
        self.assertEqual(action['attempts'], ['A00003','A00004'])
        self.assertEqual(len(second['attempts']), 5)

    def test_crash_after_durable_receipt_replays_without_model(self):
        self.prepare()
        from security_agent.pipeline import controller
        original = controller.finish_attempt
        def crash(root, state, unit, attempt, receipt):
            if attempt['role'] == 'judge':
                raise SystemExit('simulated kill after receipt')
            return original(root, state, unit, attempt, receipt)
        executor = Executor(assessment(True), lambda t: judge(t, 'CONFIRMED'))
        with patch.object(controller, 'finish_attempt', side_effect=crash):
            with self.assertRaises(SystemExit):
                run(self.out, executor)
        saved = read_json(self.out / 'state.json')
        self.assertEqual(saved['attempts'][-1]['execution'], 'RUNNING')
        resumed = run(self.out, Executor())
        self.assertEqual(len(resumed['attempts']), 2)
        self.assertEqual(len(resumed['findings']), 1)

    def test_deadline_is_persistent_and_blocks_model(self):
        self.prepare(total_timeout=0.000001)
        executor = Executor()
        state = run(self.out, executor)
        self.assertEqual(state['execution'], 'TIMED_OUT')
        self.assertFalse(executor.tasks)

    def test_foreign_evidence_version_is_rejected(self):
        self.prepare()
        old_ids = []
        def first(t):
            old_ids.extend(t.payload['scenarios'][0]['evidence_ids'])
            return judge(t)
        def stale(t):
            value = judge(t, 'CONFIRMED')
            value['decisions'][0]['evidence_ids'] = old_ids
            return value
        state = run(self.out, Executor(assessment(), first, assessment(True), stale))
        self.assertEqual(state['execution'], 'FAILED')
        self.assertFalse(state['findings'])

    def test_out_of_scope_followup_cannot_be_scheduled(self):
        self.prepare()
        def invalid(t):
            result = judge(t)
            result['decisions'][0]['follow_up'][0]['arguments']['file'] = '/etc/passwd'
            return result
        state = run(self.out, Executor(assessment(), invalid))
        self.assertEqual(state['execution'], 'COMPLETED')
        self.assertEqual(state['investigations'][0]['verdict'], 'UNKNOWN')
        self.assertTrue(state['investigations'][0]['rejected_follow_up'])
        self.assertEqual(len(state['attempts']), 2)

    def test_followup_cannot_drop_or_move_hypothesis(self):
        self.prepare()
        changed = assessment(True); changed['scenarios'][0]['sink_line'] = 3
        state = run(self.out, Executor(assessment(), judge, changed))
        self.assertEqual(state['execution'], 'FAILED')
        self.assertIn('sink identity', state['investigations'][0]['detail'])

    def test_hypothesis_cap_fails_explicitly(self):
        self.prepare(max_hypotheses=1)
        value = assessment(); value['scenarios'].extend(assessment(sid='H2')['scenarios'])
        state = run(self.out, Executor(value))
        self.assertEqual(state['execution'], 'FAILED')
        self.assertIn('hypothesis count', state['investigations'][0]['detail'])

    def test_settled_hypothesis_survives_other_hypothesis_followup(self):
        self.prepare()
        initial = assessment(True)
        initial['scenarios'].extend(assessment(sid='H2')['scenarios'])
        def mixed(t):
            confirmed = judge(t, 'CONFIRMED')['decisions'][0]
            unknown = judge(t)['decisions'][1]
            return {'decisions': [confirmed, unknown]}
        executor = Executor(initial, mixed, AgentResult(Execution.INTERRUPTED, None, 'cancelled'))
        state = run(self.out, executor)
        self.assertEqual(len(state['findings']), 1)
        self.assertEqual(state['findings'][0]['scenario_id'], 'H1')
        state = run(self.out, Executor(assessment(True, 'H2'), lambda t: judge(t, 'REJECTED')))
        self.assertEqual(len(state['findings']), 1)
        self.assertEqual(len(state['investigations'][0]['hypotheses']), 2)

    def test_repeated_query_reuses_facts_without_backend_execution(self):
        from security_agent.core.context import prepare_task
        from security_agent.tools.semantic import SemanticQueries
        directory = self.root / 'standalone'; directory.mkdir()
        calls = []
        def factory(sources, access, path):
            backend = SemanticQueries(sources, access, path)
            class Queries:
                def execute(self, operation, request):
                    calls.append(operation)
                    return backend.execute(operation, request)
            return Queries()
        task, access = prepare_task('investigator', {'sources': {'a.cpp': SOURCE}, 'target': 'a.cpp'},
                                    {'max_context_bytes': 50000, 'timeout': 1, 'call_usd': 1, 'model': 'test'},
                                    directory, factory)
        tool = next(t for t in task.tools if t.name == 'find_definition')
        first = tool.execute({'symbol': 'f', 'purpose': 'locate body'})
        second = tool.execute({'symbol': 'f', 'purpose': 'same body, different wording'})
        self.assertEqual(calls, ['find_definition'])
        self.assertEqual(first['facts'], second['facts'])
        self.assertIn('reused_from', second)
        self.assertEqual(access.calls, 2)

    def test_round_robin_does_not_starve_other_investigations(self):
        self.prepare()
        state = read_json(self.out / 'state.json')
        # Create a second explicit unit from the same immutable file, with separate identity.
        # The normal controller also uses this scheduling for distinct diff files.
        other = copy.deepcopy(state['investigations'][0]); other['id'] = 'I0002'
        state['investigations'].append(other)
        atomic_json(self.out / 'state.json', state)
        executor = Executor(assessment(), judge, assessment(True), lambda t: judge(t, 'REJECTED'),
                            assessment(True), lambda t: judge(t, 'CONFIRMED'))
        state = run(self.out, executor)
        self.assertEqual([a['investigation_id'] for a in state['attempts']],
                         ['I0001','I0001','I0002','I0002','I0001','I0001'])

    def test_no_progress_limit_allows_bounded_extra_attempt_not_extra_judge(self):
        self.prepare(max_no_progress=2)
        executor = Executor(assessment(), judge, assessment(), assessment())
        state = run(self.out, executor)
        self.assertEqual([t.role for t in executor.tasks], ['investigator','judge','investigator','investigator'])
        self.assertEqual(state['investigations'][0]['no_progress'], 2)
        self.assertEqual(state['investigations'][0]['phase'], 'done')

    def test_rejected_round_artifact_corruption_is_not_ignored(self):
        self.prepare()
        state = run(self.out, Executor(assessment(), judge, assessment()))
        artifact = state['investigations'][0]['rounds'][-1]['assessment_artifact']
        (self.out / artifact['path']).write_text('{}')
        self.assertEqual(run(self.out, Executor())['execution'], 'STALE')


class PrepareRecoveryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.repo = self.root / 'repo'; self.repo.mkdir()
        for file, source in {'a.cpp': SOURCE, 'provider.cpp': PROVIDER}.items():
            (self.repo / file).write_text(source)
        def git(*args):
            subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True)
        git('init', '-q'); git('add', '.')
        git('-c', 'user.name=Test', '-c', 'user.email=t@example.invalid', 'commit', '-qm', 'fixture')
        self.out = self.root / 'run'
    def create(self, backend=None, **config):
        return create(self.repo, 'HEAD', 'HEAD', self.out,
               {'model': 'test', 'max_calls': 8, 'timeout': 10, 'call_usd': 0.25,
                'max_context_bytes': 50000, **config}, target_paths=['a.cpp'], function='f',
               prepare_backend=backend)
    def actions(self):
        state = read_json(self.out / 'state.json')
        return state, {a['kind']: a for a in state['prepare']['actions']}
    def test_prepare_actions_checkpointed_without_backend(self):
        self.create()
        state, actions = self.actions()
        self.assertEqual(state['execution'], 'PENDING')
        self.assertEqual({k: a['execution'] for k, a in actions.items()},
                         {'snapshot': 'COMPLETED', 'scope': 'COMPLETED', 'index': 'SKIPPED', 'handoff': 'COMPLETED'})
    def test_index_failure_degrades_with_visible_gap(self):
        def broken(baseline, root):
            raise RuntimeError('index timed out')
        self.create(broken)
        state, actions = self.actions()
        self.assertEqual(state['execution'], 'PENDING')
        self.assertEqual(actions['index']['execution'], 'FAILED')
        self.assertIn('timed out', actions['index']['detail'])
        self.assertNotIn('query_backend', state)
        state = run(self.out, Executor(assessment(), lambda t: judge(t, 'REJECTED', follow=False)))
        self.assertEqual(state['execution'], 'COMPLETED')
        report = (self.out / 'report.md').read_text()
        self.assertIn('prepare/index', report)
    def test_index_interruption_leaves_no_completion_and_resumes(self):
        calls = []
        def hanging(baseline, root):
            calls.append(1)
            if len(calls) == 1:
                raise KeyboardInterrupt
            return {'producer': 'fake', 'version': '0'}
        with self.assertRaises(KeyboardInterrupt):
            self.create(hanging)
        state, actions = self.actions()
        self.assertEqual(state['execution'], 'PREPARING')
        self.assertEqual(actions['index']['execution'], 'RUNNING')
        self.assertNotIn('query_backend', state)
        self.assertEqual(run(self.out, Executor())['execution'], 'PREPARING')
        self.create(hanging)
        state, actions = self.actions()
        self.assertEqual(state['execution'], 'PENDING')
        self.assertEqual(actions['index']['execution'], 'COMPLETED')
        self.assertEqual(state['query_backend'], {'producer': 'fake', 'version': '0'})
    def test_prepare_resume_rejects_changed_arguments(self):
        with self.assertRaises(KeyboardInterrupt):
            self.create(lambda baseline, root: (_ for _ in ()).throw(KeyboardInterrupt()))
        with self.assertRaises(ValueError):
            self.create(max_calls=9)
        with self.assertRaises(ValueError):
            create(self.repo, 'different-ref', 'HEAD', self.out,
                   {'model': 'test', 'max_calls': 8, 'timeout': 10, 'call_usd': 0.25,
                    'max_context_bytes': 50000}, target_paths=['a.cpp'], function='f')
        from security_agent.core.skills import load_rule
        changed = {**load_rule(), 'sha256': '0' * 64}
        with patch('security_agent.pipeline.controller.load_rule', return_value=changed):
            with self.assertRaises(ValueError):
                self.create()
    def test_prepared_directory_cannot_be_created_twice(self):
        self.create()
        with self.assertRaises(ValueError):
            self.create()


class LayeredBudgetTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name); self.repo = self.root / 'repo'; self.repo.mkdir()
        for file, source in {'a.cpp': SOURCE, 'provider.cpp': PROVIDER}.items():
            (self.repo / file).write_text(source)
        def git(*args):
            subprocess.run(['git', '-C', str(self.repo), *args], check=True, capture_output=True)
        git('init', '-q'); git('add', '.')
        git('-c', 'user.name=Test', '-c', 'user.email=t@example.invalid', 'commit', '-qm', 'fixture')
        self.out = self.root / 'run'
    def prepare(self, **config):
        create(self.repo, 'HEAD', 'HEAD', self.out,
               {'model': 'test', 'max_calls': 8, 'timeout': 10, 'call_usd': 0.25,
                'max_context_bytes': 50000, **config}, target_paths=['a.cpp'], function='f')
    def test_investigation_call_budget(self):
        self.prepare(investigation_max_calls=2)
        state = run(self.out, Executor(assessment(), judge))
        self.assertEqual(state['execution'], 'BUDGET_EXHAUSTED')
        self.assertIn('investigation call budget', state['investigations'][0]['detail'])
        self.assertEqual(len(state['attempts']), 2)
    def test_investigation_usd_reservation_budget(self):
        self.prepare(investigation_max_usd=0.5)
        state = run(self.out, Executor(assessment(), judge))
        self.assertEqual(state['execution'], 'BUDGET_EXHAUSTED')
        self.assertIn('cost reservation', state['investigations'][0]['detail'])
        self.assertEqual(len(state['attempts']), 2)
    def test_action_retry_budget(self):
        self.prepare()
        class AlwaysFail:
            calls = 0
            def execute(self, task, directory):
                self.calls += 1
                return AgentResult(Execution.FAILED, None, 'boom')
        executor = AlwaysFail()
        for _ in range(3):
            run(self.out, executor)
        state = run(self.out, executor)
        self.assertEqual(executor.calls, 3)
        self.assertEqual(len(state['attempts']), 3)
        self.assertIn('retry budget', state['investigations'][0]['detail'])
        self.assertEqual(state['execution'], 'BUDGET_EXHAUSTED')
