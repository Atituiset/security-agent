import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from security_agent.core.source_tools import SourceAccess
from security_agent.core.context import prepare_task
from security_agent.core.skills import load_rule
from security_agent.tools.semantic import SemanticQueries
from security_agent.tools.codegraph import CodeGraph
from security_agent.pipeline.controller import create, run
from security_agent.core.executor import AgentResult
from security_agent.core.contracts import Execution


class QueryTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.sources = {'a.cpp': 'int f(int *p) {\n return *p;\n}\nint g() { return f(nullptr); }\n'}
        self.access = SourceAccess(self.sources, 'a.cpp', 12, 40000, self.root / 'tools.jsonl')
        self.queries = SemanticQueries(self.sources, self.access, self.root / 'queries')

    def test_definition_and_structural_observations_have_exact_provenance(self):
        result = self.queries.execute('find_definition', {'symbol': 'f', 'purpose': 'locate definition'})
        fact = next(f for f in result['facts'] if f['precision'] == 'syntax-observation')
        self.assertEqual(fact['location']['end_line'], 3)
        self.assertEqual((self.root / fact['raw_ref']).read_text(), fact['content'])
        self.assertFalse(result['coverage']['exhaustive'])
        derefs = self.queries.execute('find_pattern', {'kind': 'dereference', 'file': 'a.cpp', 'start': 1, 'end': 3, 'purpose': 'find sinks'})
        self.assertTrue(any('*p' in f['content'] for f in derefs['facts']))

    def test_no_graph_does_not_turn_text_into_call_edges(self):
        result = self.queries.execute('find_callers', {'symbol': 'f', 'purpose': 'find arguments'})
        self.assertEqual(result['status'], 'partial')
        self.assertTrue(all(f['precision'] == 'text-candidate' for f in result['facts']))
        empty = self.queries.execute('find_callers', {'symbol': 'missing', 'purpose': 'find arguments'})
        self.assertFalse(empty['coverage']['exhaustive'])
        self.assertEqual(empty['status'], 'partial')

    def test_truncation_and_unavailable_scope(self):
        result = self.queries.execute('find_references', {'symbol': 'f', 'purpose': 'references', 'limit': 1})
        self.assertTrue(result['coverage']['truncated'])
        unsupported = self.queries.execute('find_assignments', {'symbol': 'p', 'purpose': 'writes'})
        self.assertEqual(unsupported['status'], 'unsupported')
        self.assertEqual(unsupported['facts'], [])
        bad = self.queries.execute('find_pattern', {'file': '../elsewhere', 'kind': 'literal', 'text': 'p', 'purpose': 'test containment'})
        self.assertEqual(bad['status'], 'error')
        self.assertFalse(bad['facts'])

    def test_budget_blocks_queries_and_preserves_undelivered_raw_result(self):
        self.access.max_calls = 0
        result = self.queries.execute('find_definition', {'symbol': 'f', 'purpose': 'definition'})
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['facts'], [])
        self.assertTrue(self.access.exhausted)
        self.assertTrue((self.root / 'queries/Q00001/request.json').exists())

    def test_rule_drives_semantic_tools_and_judge_has_no_tools(self):
        config = {'max_context_bytes': 40000, 'timeout': 1, 'call_usd': 1, 'model': 'test'}
        factory = lambda sources, access, directory: SemanticQueries(sources, access, directory)
        task, _ = prepare_task('investigator', {'sources': self.sources, 'target': 'a.cpp'}, config, self.root, factory)
        self.assertEqual(set(load_rule()['operations']), {t.name for t in task.tools} - {'read_source', 'search_source'})
        judge, _ = prepare_task('judge', {}, config, self.root, factory)
        self.assertEqual(judge.tools, ())

    @unittest.skipUnless(os.environ.get('CODEGRAPH_CLI'), 'set CODEGRAPH_CLI for real tool integration')
    def test_real_graph_new_repo_five_stage_resume_and_stale_index(self):
        repo = self.root / 'repo'; repo.mkdir()
        (repo / 'a.cpp').write_text(self.sources['a.cpp'])
        def git(*args):
            subprocess.run(['git', '-C', str(repo), *args], check=True, capture_output=True)
        git('init', '-q'); git('add', '.'); git('-c', 'user.name=Test', '-c', 'user.email=t@example.invalid', 'commit', '-qm', 'fixture')
        out = self.root / 'run'
        config = {'model': 'test', 'timeout': 10, 'call_usd': 1, 'max_calls': 2, 'max_context_bytes': 40000}
        box = {}
        def prepare(baseline, root):
            box['graph'] = CodeGraph.prepare(repo, baseline['head'], os.environ['CODEGRAPH_CLI'], root / 'graph')
            return box['graph'].record
        create(repo, 'HEAD', 'HEAD', out, config, target_paths=['a.cpp'], function='f', prepare_backend=prepare)
        graph = box['graph']; test = self
        class Executor:
            calls = 0
            def execute(self, task, directory):
                self.calls += 1
                if task.role == 'investigator':
                    tools = {t.name: t for t in task.tools}
                    result = tools['find_callers'].execute({'symbol': 'f', 'purpose': 'establish null argument'})
                    test.assertTrue(any(f['candidate'].get('name') == 'g' for f in result['facts']))
                    tools['find_definition'].execute({'symbol': 'f', 'purpose': 'source flow'})
                    output = {'scenarios': [{'id': 's', 'sink_line': 2, 'hypothesis': 'null argument', 'unresolved': [],
                              'references': [{'kind': k, 'file': 'a.cpp', 'start': a, 'end': b}
                                             for k,a,b in [('origin',4,4),('sink',2,2),('path',1,3)]]}], 'unresolved': []}
                else:
                    output = {'decisions': [{'scenario_id': 's', 'verdict': 'CONFIRMED', 'reason': 'literal null caller',
                               'evidence_ids': task.payload['scenarios'][0]['evidence_ids'], 'unresolved': []}]}
                return AgentResult(Execution.COMPLETED, output, '')
        executor = Executor()
        factory = lambda sources, access, directory: SemanticQueries(sources, access, directory, graph)
        state = run(out, executor, factory, graph.check)
        self.assertEqual(len(state['findings']), 1)
        self.assertEqual(state['stage_records']['post-process']['status'], 'COMPLETED')
        self.assertTrue(state['investigations'][0]['assessment']['evidence'][0]['query_refs'])
        run(out, executor, factory, graph.check)
        self.assertEqual(executor.calls, 2)
        (graph.project / 'a.cpp').write_text('changed')
        self.assertEqual(run(out, executor, factory, graph.check)['execution'], 'STALE')
        self.assertFalse((repo / '.codegraph').exists())

    def test_query_request_rejects_oversized_limit_and_unknown_fields(self):
        from security_agent.core.contracts import ContractError
        for request in ({'purpose': 'test', 'symbol': 'f', 'limit': 101},
                        {'purpose': 'test', 'symbol': 'f', 'command': 'shell'},
                        {'purpose': 'test', 'symbol': 'x' * 201}):
            with self.assertRaises(ContractError):
                self.queries.execute('find_definition', request)

    def test_raw_non_json_zero_exit_is_an_error_and_timeout_is_saved(self):
        project = self.root / 'project'; project.mkdir()
        cli = self.root / 'fake-cli.js'; cli.write_text('console.log("missing symbol")')
        record = {'project': str(project), 'cli': str(cli), 'files': {}, 'tool_files': {}, 'version': 'fixture'}
        graph = CodeGraph(record)
        directory = self.root / 'raw'; directory.mkdir()
        result = graph.query('find_callers', 'f', 10, directory, 1)
        self.assertEqual(result['status'], 'error')
        self.assertEqual(result['candidates'], [])
        self.assertIn('missing symbol', (directory / 'graph.stdout').read_text())
        cli.write_text('setTimeout(() => {}, 10000)')
        result = graph.query('find_callers', 'f', 10, directory, 0.05)
        self.assertEqual(result['status'], 'error')
        self.assertIn('tool timeout', result['errors'])
