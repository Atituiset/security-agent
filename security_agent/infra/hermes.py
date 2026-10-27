"""Hermes adapter uses its installed Agent loop, with an explicit tool registry."""
import json
import os
from pathlib import Path
import tempfile
from security_agent.core.executor import AgentResult
from security_agent.core.contracts import Execution
from security_agent.core.storage import atomic_json
from .tool_bridge import tool_bridge
from .local_process import run_process, parse_json, normalized


class HermesExecutor:
    def __init__(self, python=None, source=None, provider='deepseek', credential_home=None):
        self.source = Path(source or Path.home() / '.hermes/hermes-agent')
        self.python = str(python or self.source / 'venv/bin/python')
        self.provider = provider
        self.credential_home = str(credential_home or Path.home() / '.hermes')

    def execute(self, task, artifact_dir):
        atomic_json(artifact_dir / 'request.json', {'backend': 'hermes', 'model': task.model,
                    'provider': self.provider, 'payload': task.payload, 'schema': task.schema,
                    'system_prompt': task.system_prompt, 'allowed_tools': [t.name for t in task.tools],
                    'max_turns': task.max_turns, 'budget_support': 'call reservation only; no native USD ceiling'})
        try:
            with tempfile.TemporaryDirectory(prefix='security-hermes-') as temp, tool_bridge(task.tools) as bridge:
                root = Path(temp); profile = root / 'profile'; profile.mkdir()
                cwd = root / 'workspace'; cwd.mkdir()
                # No user hooks, MCP servers, skills, memory or project rules in this profile.
                (profile / 'config.yaml').write_text('plugins:\n  enabled: []\nmcp_servers: {}\ntools:\n  tool_search:\n    enabled: off\n')
                env = {k: v for k, v in os.environ.items() if not k.startswith(('HERMES_', 'PYTHONPATH', 'PYTHONHOME'))}
                env.update(bridge, HERMES_HOME=str(profile), SECURITY_HERMES_SOURCE=str(self.source),
                           HERMES_SKIP_RIPGREP_CHECK='1', HERMES_DISABLE_TELEMETRY='1')
                result_path = artifact_dir.resolve() / 'hermes-result.json'
                packet = {'payload': task.payload, 'schema': task.schema, 'system_prompt': task.system_prompt,
                          'model': task.model, 'max_turns': task.max_turns, 'timeout': task.timeout,
                          'provider': self.provider, 'credential_home': self.credential_home,
                          'result_path': str(result_path)}
                status = run_process([self.python, str(Path(__file__).with_name('hermes_worker.py'))],
                                     json.dumps(packet), env, cwd, artifact_dir, task.timeout)
                if isinstance(status, str):
                    return AgentResult(Execution(status), None, 'Hermes ' + status)
                if status or not result_path.exists():
                    return AgentResult(Execution.FAILED, None, 'Hermes process failed; see stderr.raw')
                result = json.loads(result_path.read_text())
                if result.get('error') or result.get('interrupted'):
                    return AgentResult(Execution.FAILED, None, 'Hermes returned incomplete/error result')
                return normalized(task, parse_json(result.get('final_response') or ''))
        except (OSError, ValueError, KeyError) as exc:
            return AgentResult(Execution.FAILED, None, f'Hermes: {exc}')
