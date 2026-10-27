"""Architecture tests exercise Core through its execution port, never SDK mocks."""
import ast
from pathlib import Path
import subprocess
import tempfile
import unittest
from security_agent.core.executor import AgentResult
from security_agent.core.contracts import Execution, ContractError
from security_agent.core.judge import admit
from security_agent.pipeline.controller import create, run
from security_agent.core.storage import read_json
from security_agent.inputs.function_scope import locate


class ArchitectureTests(unittest.TestCase):
    def test_core_has_no_infra_input_or_sdk_imports(self):
        root = Path(__file__).resolve().parents[1] / 'security_agent'
        for path in (root / 'core').glob('*.py'):
            for node in ast.walk(ast.parse(path.read_text())):
                names = [a.name for a in node.names] if isinstance(node, ast.Import) else [node.module or ''] if isinstance(node, ast.ImportFrom) else []
                for name in names:
                    self.assertFalse(any(x in name for x in ('claude', 'infra', 'inputs', 'pipeline', 'validation', 'tree_sitter', 'security_agent.tools')), (path, name))
        adapter = (root / 'infra/claude.py').read_text()
        for forbidden in ('CWE-476', 'SourceAccess', 'scoped_source', 'INVESTIGATOR', 'JUDGE_SCHEMA', 'task.role =='):
            self.assertNotIn(forbidden, adapter)
        self.assertNotIn('reference_session', (root / 'pipeline/controller.py').read_text())

    def test_fresh_repo_function_runs_through_plain_executor_port(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            repo = root / 'repo'; repo.mkdir()
            def git(*args):
                subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True)
            git('init', '-q'); git('config', 'user.name', 'Test'); git('config', 'user.email', 'test@example.invalid')
            source = 'int other() { return 0; }\nint target() {\n  int *p = 0;\n  return *p;\n}\n'
            (repo / 'a.cpp').write_text(source)
            git('add', '.'); git('commit', '-qm', 'new repository')
            config = {'model': 'test', 'max_calls': 2, 'call_usd': 1, 'timeout': 1, 'max_context_bytes': 10000}
            out = root / 'run'
            create(repo, 'HEAD', 'HEAD', out, config, target_paths=['a.cpp'], function='target')
            testcase = self
            class Executor:
                calls = 0
                def execute(self, task, artifact_dir):
                    self.calls += 1
                    if task.role == 'investigator':
                        testcase.assertNotIn('other()', task.payload['target_source'])
                        testcase.assertEqual(task.payload['candidates'], [])
                        testcase.assertIn('2: int target()', task.payload['target_source'])
                        testcase.assertEqual(len(task.tools), 2)
                        output = {'scenarios': [{'id': 'new-scene', 'hypothesis': 'null is dereferenced', 'sink_line': 4,
                                  'references': [{'kind': kind, 'file': 'a.cpp', 'start': start, 'end': end}
                                                 for kind, start, end in [('origin', 3, 3), ('sink', 4, 4), ('path', 2, 5)]],
                                  'unresolved': []}], 'unresolved': []}
                    else:
                        testcase.assertEqual(task.tools, ())
                        output = {'decisions': [{'scenario_id': 'new-scene', 'verdict': 'CONFIRMED',
                                   'evidence_ids': task.payload['scenarios'][0]['evidence_ids'], 'reason': 'Direct null dereference.', 'unresolved': []}]}
                    return AgentResult(Execution.COMPLETED, output, '')
            executor = Executor()
            state = run(out, executor)
            self.assertEqual(executor.calls, 2)
            self.assertEqual(len(state['findings']), 1)
            self.assertEqual(state['baseline']['function']['start'], 2)
            self.assertFalse((out / 'reference.json').exists())
            invalid = {'scenarios': [{'id': 'out-of-scope', 'hypothesis': 'another function', 'sink_line': 1,
                                     'references': [], 'unresolved': ['unknown']}], 'unresolved': []}
            with self.assertRaisesRegex(ContractError, 'outside requested function'):
                admit(state['investigations'][0], invalid, {'a.cpp': source}, state['baseline'], 'test')

    def test_function_locator_handles_scope_overloads_and_strings(self):
        source = 'namespace n {\nint f(int x) { const char* s = "}"; return x; }\nint f(double x) { return 0; }\n}\n'
        with self.assertRaisesRegex(ValueError, 'ambiguous'):
            locate(source, 'a.cpp', 'f')
        self.assertEqual(locate(source, 'a.cpp', 'n::f', 3)['start'], 3)
        with self.assertRaisesRegex(ValueError, 'not found'):
            locate(source, 'a.cpp', 'missing')
        self.assertEqual(locate('int *f(void) { return 0; }', 'a.c', 'f')['name'], 'f')
        self.assertEqual(locate('struct X { X() {} };', 'a.cpp', 'X::X')['name'], 'X::X')
