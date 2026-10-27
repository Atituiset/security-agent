"""OpenCode local CLI adapter with isolated config and only Core-owned MCP tools."""
import json
import os
from pathlib import Path
import sys
import tempfile
from security_agent.core.executor import AgentResult
from security_agent.core.contracts import Execution
from security_agent.core.storage import atomic_json
from .tool_bridge import tool_bridge
from .local_process import run_process, parse_json, normalized


class OpenCodeExecutor:
    def __init__(self, binary='opencode'):
        self.binary = binary

    def execute(self, task, artifact_dir):
        atomic_json(artifact_dir / 'request.json', {'backend': 'opencode', 'model': task.model,
                    'payload': task.payload, 'schema': task.schema, 'system_prompt': task.system_prompt,
                    'allowed_tools': [t.name for t in task.tools], 'max_turns': task.max_turns,
                    'budget_support': 'call reservation only; no native USD ceiling'})
        try:
            with tempfile.TemporaryDirectory(prefix='security-opencode-') as temp, tool_bridge(task.tools) as bridge:
                home = Path(temp); cwd = home / 'workspace'; cwd.mkdir()
                config = {'$schema': 'https://opencode.ai/config.json', 'autoupdate': False,
                          'share': 'disabled', 'plugin': [], 'instructions': [], 'model': task.model,
                          'permission': {'*': 'deny', 'security': 'allow', 'security_*': 'allow'},
                          'agent': {'security': {'mode': 'primary', 'prompt': task.system_prompt,
                                                'steps': task.max_turns}},
                          'mcp': {'security': {'type': 'local', 'command': [sys.executable,
                                  str(Path(__file__).with_name('mcp_stdio.py'))], 'environment': bridge,
                                  'enabled': True}} if task.tools else {}}
                env = {k: v for k, v in os.environ.items() if not k.startswith('OPENCODE_')}
                env.update(XDG_CONFIG_HOME=str(home / 'config'), XDG_DATA_HOME=str(home / 'data'),
                           XDG_CACHE_HOME=str(home / 'cache'), XDG_STATE_HOME=str(home / 'state'),
                           OPENCODE_CONFIG_CONTENT=json.dumps(config), OPENCODE_DISABLE_PROJECT_CONFIG='true',
                           OPENCODE_DISABLE_EXTERNAL_SKILLS='true', OPENCODE_DISABLE_CLAUDE_CODE_SKILLS='true')
                # Copy only the selected provider's auth into the disposable Agent home.
                auth_path = Path(os.environ.get('XDG_DATA_HOME', str(Path.home() / '.local/share'))) / 'opencode/auth.json'
                if auth_path.exists():
                    auth = json.loads(auth_path.read_text()); provider = task.model.split('/')[0]
                    if provider in auth:
                        dest = home / 'data/opencode/auth.json'; dest.parent.mkdir(parents=True)
                        dest.write_text(json.dumps({provider: auth[provider]})); dest.chmod(0o600)
                prompt = json.dumps({'task': task.payload, 'output_schema': task.schema,
                                     'instruction': 'Return ONLY the final JSON object matching output_schema. Use only the supplied security tools.'})
                status = run_process([self.binary, 'run', '--pure', '--print-logs', '--log-level', 'WARN', '--format', 'json', '--agent', 'security',
                                      '--model', task.model], prompt, env, cwd, artifact_dir, task.timeout)
                if isinstance(status, str):
                    return AgentResult(Execution(status), None, 'OpenCode ' + status)
                events = []
                for line in (artifact_dir / 'stdout.raw').read_text().splitlines():
                    try:
                        events.append(json.loads(line))
                    except ValueError:
                        continue
                atomic_json(artifact_dir / 'events.json', events)
                errors = [e for e in events if e.get('type') == 'error']
                if status or errors:
                    return AgentResult(Execution.FAILED, None, 'OpenCode process/error event; see raw output')
                texts = [e['part']['text'] for e in events if e.get('type') == 'text' and e.get('part', {}).get('text')]
                if not texts:
                    raise ValueError('OpenCode returned no final text')
                return normalized(task, parse_json(texts[-1]))
        except (OSError, ValueError, KeyError) as exc:
            return AgentResult(Execution.FAILED, None, f'OpenCode: {exc}')
