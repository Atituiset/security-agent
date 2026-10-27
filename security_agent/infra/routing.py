"""Explicit per-role execution profiles; never silently fail over to another model."""
from dataclasses import replace
from .claude import ClaudeExecutor
from .opencode import OpenCodeExecutor
from .hermes import HermesExecutor

BACKENDS = ('claude', 'opencode', 'hermes')


def adapter(name, config):
    if name == 'claude':
        return ClaudeExecutor(config.get('claude_settings'))
    if name == 'opencode':
        return OpenCodeExecutor(config.get('opencode_binary', 'opencode'))
    if name == 'hermes':
        return HermesExecutor(config.get('hermes_python'), config.get('hermes_source'), config.get('hermes_provider', 'deepseek'))
    raise ValueError('unsupported Agent backend: ' + name)


class RoleExecutor:
    def __init__(self, config):
        self.config = config
        primary = config.get('backend', 'claude')
        judge = config.get('judge_backend') or primary
        self.profiles = {'investigator': adapter(primary, config), 'judge': adapter(judge, config)}

    def execute(self, task, artifact_dir):
        model = self.config.get('judge_model') if task.role == 'judge' else None
        return self.profiles[task.role].execute(replace(task, model=model or task.model), artifact_dir)


def backend_info():
    import shutil
    from pathlib import Path
    return {
        'claude': {'transport': 'Claude Agent SDK', 'native_json_schema': True,
                   'native_usd_budget': True, 'tools': 'SDK MCP', 'available': True},
        'opencode': {'transport': 'local CLI JSON events', 'native_json_schema': False,
                     'native_usd_budget': False, 'tools': 'local MCP bridge',
                     'available': shutil.which('opencode') is not None},
        'hermes': {'transport': 'installed AIAgent in isolated worker', 'native_json_schema': False,
                   'native_usd_budget': False, 'tools': 'explicit registry bridge',
                   'available': (Path.home() / '.hermes/hermes-agent/venv/bin/python').exists()},
    }
