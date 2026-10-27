"""Runs inside the installed Hermes interpreter, in an isolated temporary profile."""
import json
import os
from pathlib import Path
import sys
from urllib.request import Request, urlopen


def rpc(path, data):
    request = Request(os.environ['SECURITY_TOOL_URL'] + path, data=json.dumps(data).encode(),
                      headers={'Authorization': 'Bearer ' + os.environ['SECURITY_TOOL_TOKEN'], 'Content-Type': 'application/json'})
    with urlopen(request, timeout=60) as response:
        return json.load(response)


def main():
    task = json.load(sys.stdin)
    install = Path(os.environ['SECURITY_HERMES_SOURCE'])
    sys.path.insert(0, str(install))
    from dotenv import dotenv_values
    provider = task['provider']
    key_names = {'deepseek': 'DEEPSEEK_API_KEY', 'openrouter': 'OPENROUTER_API_KEY',
                 'openai': 'OPENAI_API_KEY', 'nous': 'NOUS_API_KEY', 'nvidia': 'NVIDIA_API_KEY'}
    key_name = key_names.get(provider)
    if key_name:
        value = dotenv_values(Path(task['credential_home']) / '.env').get(key_name)
        if value and key_name not in os.environ:
            os.environ[key_name] = value
    from tools.registry import registry
    from toolsets import TOOLSETS
    descriptors = rpc('/list', {})
    TOOLSETS['security_runtime'] = {'description': 'Explicit read-only security fact tools',
                                   'tools': [t['name'] for t in descriptors], 'includes': []}
    for descriptor in descriptors:
        name = descriptor['name']
        def handler(args, _name=name, **kwargs):
            return json.dumps(rpc('/call', {'name': _name, 'arguments': args}))
        registry.register(name=name, toolset='security_runtime',
                          schema={'name': name, 'description': descriptor['description'], 'parameters': descriptor['schema']},
                          handler=handler)
    from hermes_cli.runtime_provider import resolve_runtime_provider
    from run_agent import AIAgent
    runtime = resolve_runtime_provider(requested=provider, target_model=task['model'])
    agent = AIAgent(api_key=runtime.get('api_key'), base_url=runtime.get('base_url'),
                    provider=runtime.get('provider'), api_mode=runtime.get('api_mode'), model=task['model'],
                    enabled_toolsets=['security_runtime'], max_iterations=task['max_turns'],
                    quiet_mode=True, skip_context_files=True, skip_memory=True, skip_background_review=True,
                    save_trajectories=False, checkpoints_enabled=False, run_budget_seconds=task['timeout'],
                    fallback_model=None, session_db=None, max_tokens=8192)
    try:
        allowed = {t['name'] for t in descriptors}
        if agent.valid_tool_names != allowed:
            raise ValueError(f'Hermes tool isolation failed: {sorted(agent.valid_tool_names - allowed)}')
        result = agent.run_conversation(json.dumps({'task': task['payload'], 'output_schema': task['schema'],
                            'instruction': 'Return ONLY a JSON object matching output_schema.'}),
                            system_message=task['system_prompt'])
        Path(task['result_path']).write_text(json.dumps(result, default=str))
    finally:
        agent.close()


if __name__ == '__main__':
    main()
