"""Real local Agent tool-loop probe. It measures compatibility, not security accuracy."""
import argparse
from pathlib import Path
from uuid import uuid4
from security_agent.core.executor import Task, SecurityTool
from security_agent.core.contracts import obj, STRING
from security_agent.core.storage import atomic_json
from security_agent.infra.routing import adapter


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument('--backend', required=True, choices=['claude', 'opencode', 'hermes'])
    parser.add_argument('--model', required=True)
    parser.add_argument('--run', required=True)
    args = parser.parse_args()
    directory = Path(args.run).resolve(); directory.mkdir(parents=True, exist_ok=False)
    nonce = uuid4().hex
    calls = []
    def lookup(arguments):
        calls.append(arguments)
        return {'value': nonce}
    task = Task('investigator', {'instruction': 'Call lookup_fact and return its value as observed. Do not guess.'},
                obj({'observed': STRING}), 120, 0.1, args.model,
                'Use the supplied tool then output the requested JSON only.',
                (SecurityTool('lookup_fact', 'Read the fact required to answer', obj({}), lookup),), 4)
    result = adapter(args.backend, {}).execute(task, directory)
    passed = result.execution == 'COMPLETED' and result.output == {'observed': nonce} and bool(calls)
    atomic_json(directory / 'smoke.json', {'execution': result.execution, 'detail': result.detail,
                                         'passed': passed, 'tool_calls': len(calls), 'cost_usd': result.cost_usd})
    print((directory / 'smoke.json').read_text())
    return 0 if passed else 2


if __name__ == '__main__':
    raise SystemExit(main())
