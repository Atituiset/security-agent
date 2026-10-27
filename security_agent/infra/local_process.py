"""Bounded process transport shared by local Agent adapters; no security policy."""
import json
import os
from pathlib import Path
import signal
import subprocess
from security_agent.core.contracts import Execution, validate
from security_agent.core.executor import AgentResult


def run_process(command, stdin, environment, cwd, directory, timeout):
    with (directory / 'stdout.raw').open('wb') as stdout, (directory / 'stderr.raw').open('wb') as stderr:
        process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=stdout, stderr=stderr,
                                   cwd=cwd, env=environment, start_new_session=True)
        try:
            process.communicate(stdin.encode(), timeout=timeout)
            return process.returncode
        except (subprocess.TimeoutExpired, KeyboardInterrupt) as exc:
            os.killpg(process.pid, signal.SIGKILL); process.wait()
            return 'TIMED_OUT' if isinstance(exc, subprocess.TimeoutExpired) else 'INTERRUPTED'


def parse_json(text):
    value = text.strip()
    if value.startswith('```') and value.endswith('```'):
        value = '\n'.join(value.splitlines()[1:-1])
    return json.loads(value)


def normalized(task, output, cost=None):
    validate(output, task.schema)
    return AgentResult(Execution.COMPLETED, output, '', cost)
