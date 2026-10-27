import asyncio
import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from urllib.request import Request, urlopen
from urllib.error import HTTPError
from unittest.mock import patch
from security_agent.core.executor import Task, SecurityTool, AgentResult
from security_agent.core.contracts import obj, STRING, Execution
from security_agent.infra.tool_bridge import tool_bridge
from security_agent.infra.routing import RoleExecutor
from security_agent.infra.local_process import run_process, normalized
from security_agent.infra.opencode import OpenCodeExecutor


class InfraTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(); self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.task = Task('investigator', {}, obj({'value': STRING}), 2, 0.1, 'provider/model', 'Return JSON')

    def test_bridge_auth_allowlist_and_schema(self):
        calls = []
        tool = SecurityTool('fact', 'read', obj({}), lambda args: calls.append(args) or {'value': 'ok'})
        with tool_bridge([tool]) as env:
            def call(token, name, arguments):
                request = Request(env['SECURITY_TOOL_URL'] + '/call',
                                  data=json.dumps({'name': name, 'arguments': arguments}).encode(),
                                  headers={'Authorization': 'Bearer ' + token})
                return json.load(urlopen(request, timeout=2))
            with self.assertRaises(HTTPError) as error:
                call('wrong', 'fact', {})
            self.assertEqual(error.exception.code, 403)
            with self.assertRaises(HTTPError):
                call(env['SECURITY_TOOL_TOKEN'], 'shell', {})
            with self.assertRaises(HTTPError):
                call(env['SECURITY_TOOL_TOKEN'], 'fact', {'unexpected': 1})
            self.assertEqual(call(env['SECURITY_TOOL_TOKEN'], 'fact', {}), {'value': 'ok'})
            self.assertEqual(calls, [{}])

    def test_actual_mcp_stdio_transport(self):
        from mcp import ClientSession, StdioServerParameters
        from mcp.client.stdio import stdio_client
        tool = SecurityTool('fact', 'read', obj({}), lambda args: {'value': 'bridge'})
        async def probe(env):
            parameters = StdioServerParameters(command=sys.executable,
                        args=[str(Path('security_agent/infra/mcp_stdio.py').resolve())], env={**os.environ, **env})
            async with stdio_client(parameters) as (r, w):
                async with ClientSession(r, w) as session:
                    await session.initialize()
                    self.assertEqual([t.name for t in (await session.list_tools()).tools], ['fact'])
                    result = await session.call_tool('fact', {})
                    self.assertFalse(result.is_error)
                    self.assertIn('bridge', result.content[0].text)
        with tool_bridge([tool]) as env:
            asyncio.run(probe(env))

    def test_process_timeout_preserves_raw_output(self):
        status = run_process([sys.executable, '-u', '-c', 'import time; print("started"); time.sleep(20)'],
                             '', os.environ.copy(), self.root, self.root, 0.1)
        self.assertEqual(status, 'TIMED_OUT')
        self.assertIn('started', (self.root / 'stdout.raw').read_text())

    def test_role_routes_without_silent_fallback(self):
        seen = []
        class Fake:
            def __init__(self, name): self.name = name
            def execute(self, task, directory):
                seen.append((self.name, task.model, task.tools))
                return AgentResult(Execution.FAILED, None, 'unavailable')
        with patch('security_agent.infra.routing.adapter', side_effect=lambda name, config: Fake(name)):
            router = RoleExecutor({'backend': 'opencode', 'judge_backend': 'hermes', 'judge_model': 'judge-model'})
            router.execute(self.task, self.root)
            from dataclasses import replace
            router.execute(replace(self.task, role='judge'), self.root)
        self.assertEqual(seen, [('opencode','provider/model',()), ('hermes','judge-model',())])

    def test_opencode_isolated_configuration_and_no_secrets_in_request(self):
        def process(command, stdin, env, cwd, directory, timeout):
            config = json.loads(env['OPENCODE_CONFIG_CONTENT'])
            self.assertEqual(config['permission']['*'], 'deny')
            self.assertEqual(config['plugin'], [])
            self.assertIn('--pure', command)
            self.assertNotEqual(str(cwd), os.getcwd())
            self.assertEqual(env['OPENCODE_DISABLE_PROJECT_CONFIG'], 'true')
            (directory / 'stdout.raw').write_text(json.dumps({'type': 'text', 'part': {'text': '{"value":"ok"}'}}))
            (directory / 'stderr.raw').write_text('')
            return 0
        with patch('security_agent.infra.opencode.run_process', side_effect=process):
            result = OpenCodeExecutor().execute(self.task, self.root)
        self.assertEqual(result.execution, 'COMPLETED')
        self.assertNotIn('SECURITY_TOOL_TOKEN', (self.root / 'request.json').read_text())

    def test_structured_result_is_validated_outside_vendor(self):
        from security_agent.core.contracts import ContractError
        with self.assertRaises(ContractError):
            normalized(self.task, {'invented': 'field'})
