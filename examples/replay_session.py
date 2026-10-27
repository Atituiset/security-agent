"""Re-run the file scope of a review-skills session through this project's SDK pipeline."""
import argparse
from pathlib import Path
import sys
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
from security_agent.infra.claude import ClaudeExecutor, provider_env
from security_agent.pipeline.controller import create, run
from security_agent.validation.reference_session import inspect_session, compare
from security_agent.core.storage import atomic_json


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--session", required=True)
    parser.add_argument("--run", required=True)
    parser.add_argument("--prepare-only", action="store_true")
    parser.add_argument("--call-usd", type=float, default=0.5)
    parser.add_argument("--max-calls", type=int, default=4)
    args = parser.parse_args()
    reference = inspect_session(args.session)
    root = Path(args.run).resolve()
    create(reference["repo"], reference["commit"], reference["commit"], root,
           {"model": provider_env().get("ANTHROPIC_MODEL", "sonnet"), "max_calls": args.max_calls,
            "call_usd": args.call_usd, "timeout": 300, "max_context_bytes": 180000,
            "max_tool_calls": 40, "max_snapshot_bytes": 10000000},
           target_paths=reference["paths"], input_provenance=reference,
           candidates={p: [{"id": c["id"], "start": c["sink"]["start_line"], "end": c["sink"]["end_line"]}
                           for c in reference["scenarios"] if c["sink"]["path"] == p] for p in reference["paths"]})
    atomic_json(root / "reference.json", reference)
    print(f"Reference: {len(reference['scenarios'])} CWE-476 scenarios; "
          f"{reference['checked_evidence_refs']} evidence refs; "
          f"{len(reference['dependencies'])} dependency hashes verified", flush=True)
    if args.prepare_only:
        return 0
    state = run(root, ClaudeExecutor())
    atomic_json(root / "comparison.json", compare(reference, state))
    print(f"Execution: {state['execution']}; findings: {len(state['findings'])}; report: {root / 'report.md'}")
    for unit in state["investigations"]:
        print(f"{unit['id']}: {unit['execution']}: {unit['detail']}")
    return 0 if state["execution"] == "COMPLETED" else 2


if __name__ == "__main__":
    raise SystemExit(main())
