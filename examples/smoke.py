"""Create a tiny committed C fixture and review it through the real Claude SDK.

Usage: .venv/bin/python examples/smoke.py /tmp/security-agent-smoke
Requires configured Claude authentication. At most two $0.25 SDK calls.
"""
from pathlib import Path
import subprocess
import sys

# Allow running the example directly from a source checkout.
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_agent.infra.claude import ClaudeExecutor
from security_agent.pipeline.controller import create, run


def main():
    root = Path(sys.argv[1]).resolve()
    root.mkdir(parents=True, exist_ok=False)
    repo = root / "repo"
    repo.mkdir()
    def git(*args):
        return subprocess.check_output(["git", "-C", str(repo), *args], stderr=subprocess.PIPE).decode().strip()
    git("init", "-q")
    git("config", "user.name", "Security Agent Example")
    git("config", "user.email", "example@example.invalid")
    git("commit", "--allow-empty", "-qm", "base")
    base = git("rev-parse", "HEAD")
    (repo / "null.c").write_text("int example(void) {\n    int *ptr = 0;\n    return *ptr;\n}\n")
    git("add", "null.c")
    git("commit", "-qm", "null dereference")
    out = root / "review"
    create(repo, base, "HEAD", out, {"model": "sonnet", "max_calls": 2,
                                   "call_usd": 0.25, "timeout": 45, "max_context_bytes": 10000})
    state = run(out, ClaudeExecutor())
    print(f"Execution: {state['execution']}; findings: {len(state['findings'])}; report: {out / 'report.md'}")
    for unit in state["investigations"]:
        print(f"{unit['id']}: {unit['execution']}: {unit['detail']}")
    return 0 if state["execution"] == "COMPLETED" and state["findings"] else 2


if __name__ == "__main__":
    raise SystemExit(main())
