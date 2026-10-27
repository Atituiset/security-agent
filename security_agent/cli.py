"""Local CLI. Signals stop the active SDK request and leave resumable checkpoints."""
import argparse
import json
from pathlib import Path
import signal
import sys
from datetime import datetime
from uuid import uuid4
from security_agent.infra.claude import provider_env
from security_agent.infra.routing import RoleExecutor, BACKENDS, backend_info
from security_agent.pipeline.controller import create, run
from security_agent.core.storage import read_json, atomic_json
from security_agent.tools.codegraph import CodeGraph
from security_agent.tools.semantic import SemanticQueries


def main(argv=None):
    parser = argparse.ArgumentParser(description="Evidence-based C/C++ file, function, and Git diff review (CWE-476)")
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("backends", help="show installed adapters and capability differences")
    trace_cmd = sub.add_parser("trace", help="print the normalized execution trace of a run directory")
    trace_cmd.add_argument("--run", required=True)
    report_cmd = sub.add_parser("report", help="render the self-contained HTML delivery report for a run")
    report_cmd.add_argument("--run", required=True)
    report_cmd.add_argument("--out", help="output path; defaults to <run>/review.html")
    eval_cmd = sub.add_parser("eval", help="record scored panels into the eval ledger and compare them")
    eval_cmd.add_argument("--dir", default=".runs/eval", help="ledger directory")
    eval_cmd.add_argument("--record", metavar="NAME", help="record a panel under NAME")
    eval_cmd.add_argument("--corpus", help="corpus json for --record")
    eval_cmd.add_argument("--panel", help="directory with observations.json and scores.json for --record")
    eval_cmd.add_argument("--history", action="store_true", help="list recorded panels")
    eval_cmd.add_argument("--compare", nargs=2, metavar=("OLDER", "NEWER"), help="metric deltas between two recorded panels")
    review = sub.add_parser("review", help="review a committed file/function or Git diff")
    review.add_argument("--repo", required=True)
    review.add_argument("--base", help="base revision for Git diff mode")
    review.add_argument("--head", default="HEAD")
    review.add_argument("--file", help="repository-relative C/C++ file; no previous review required")
    review.add_argument("--function", help="function name, optionally qualified with namespace/class")
    review.add_argument("--line", type=int, help="line inside the desired overload")
    review.add_argument("--prepare-only", action="store_true", help="freeze and locate target without model calls")
    review.add_argument("--run", help="new output directory; defaults to .runs/<timestamp-id>")
    review.add_argument("--codegraph-cli", help="path to built CodeGraph JS CLI; prepares an isolated baseline index")
    review.add_argument("--backend", choices=BACKENDS, default="claude")
    review.add_argument("--judge-backend", choices=BACKENDS)
    review.add_argument("--judge-model", help="model for independent Judge; required if changing its backend")
    review.add_argument("--opencode-binary", default="opencode")
    review.add_argument("--hermes-python", help="installed Hermes Python interpreter")
    review.add_argument("--hermes-source", help="installed Hermes source directory")
    review.add_argument("--hermes-provider", default="deepseek")
    review.add_argument("--model", help="defaults to configured ANTHROPIC_MODEL, then sonnet")
    review.add_argument("--claude-settings", help="provider env only; defaults to ~/.claude/settings.json")
    review.add_argument("--max-rounds", type=int, default=3)
    review.add_argument("--max-hypotheses", type=int, default=20)
    review.add_argument("--max-no-progress", type=int, default=1)
    review.add_argument("--total-timeout", type=float, default=1800, help="run deadline seconds from creation, including downtime")
    review.add_argument("--max-calls", type=int, default=20)
    review.add_argument("--call-usd", type=float, default=0.5)
    review.add_argument("--investigation-max-calls", type=int, help="per-investigation model call cap; defaults to the run budget")
    review.add_argument("--investigation-max-usd", type=float, help="per-investigation cost reservation cap")
    review.add_argument("--max-action-attempts", type=int, default=3, help="retry cap for one action; old reservations are not refunded")
    review.add_argument("--index-timeout", type=float, default=120, help="seconds per CodeGraph index command during prepare")
    review.add_argument("--timeout", type=float, default=120)
    review.add_argument("--max-context-bytes", type=int, default=120000)
    review.add_argument("--max-tool-calls", type=int, default=12)
    review.add_argument("--max-snapshot-bytes", type=int, default=10000000)
    resume = sub.add_parser("resume", help="resume with the original baseline, model and budget")
    resume.add_argument("--run", required=True)
    resume.add_argument("--codegraph-cli", help="retry a failed/skipped CodeGraph index during prepare resume")
    resume.add_argument("--index-timeout", type=float, default=120)
    sign_cmd = sub.add_parser("sign", help="pack a run directory into a reproducible tarball and GPG-sign it")
    sign_cmd.add_argument("--run", required=True)
    sign_cmd.add_argument("--key", help="GPG key id/fingerprint; defaults to the gpg default key")
    sign_cmd.add_argument("--out", help="output bundle path; defaults to <run>-delivery.tar.gz next to the run")
    verify_cmd = sub.add_parser("verify", help="check an extracted delivery bundle against its SHA256SUMS manifest")
    verify_cmd.add_argument("--dir", required=True, help="extracted bundle directory")
    verify_cmd.add_argument("--sums", required=True, help="SHA256SUMS manifest from the bundle")
    args = parser.parse_args(argv)
    if args.command == "backends":
        print(json.dumps(backend_info(), indent=2))
        return 0
    if args.command == "trace":
        from security_agent.validation.trace import trace
        print(json.dumps(trace(args.run), indent=2, ensure_ascii=False))
        return 0
    if args.command == "report":
        from security_agent.core.output import export_html
        root = Path(args.run).resolve()
        if not (root / 'state.json').exists():
            parser.error("not a run directory: " + str(root))
        path = export_html(root, read_json(root / 'state.json'))
        if args.out:
            Path(args.out).write_text(path.read_text(encoding='utf-8'), encoding='utf-8')
            path = Path(args.out)
        print(json.dumps({"html": str(path)}, indent=2))
        return 0
    if args.command == "eval":
        from security_agent.validation import evaluate
        if args.record:
            if not args.corpus or not args.panel:
                parser.error("--record requires --corpus and --panel")
            record = evaluate.panel_record(args.record, args.corpus, args.panel)
            appended = evaluate.append_ledger(args.dir, record)
            print(json.dumps({"recorded": args.record, "appended": appended}, indent=2))
            return 0
        if args.history:
            rows = [{"name": r["name"], "recorded_at": r["recorded_at"], "paired_panel": r["paired_panel"],
                     "systems": {s: v["counts"].get("trials") for s, v in r["systems"].items()}}
                    for r in evaluate.history(args.dir)]
            print(json.dumps(rows, indent=2, ensure_ascii=False))
            return 0
        if args.compare:
            panels = {r["name"]: r for r in evaluate.history(args.dir)}
            older, newer = (panels.get(n) for n in args.compare)
            if not older or not newer:
                parser.error("unknown panel name in --compare")
            print(json.dumps(evaluate.compare(older, newer), indent=2, ensure_ascii=False))
            return 0
        parser.error("eval requires --record, --history or --compare")
    if args.command == "sign":
        from security_agent.core import delivery
        root = Path(args.run).resolve()
        if not (root / 'state.json').exists():
            parser.error("not a run directory: " + str(root))
        out = Path(args.out).resolve() if args.out else root.with_name(root.name + '-delivery.tar.gz')
        try:
            bundle, sums = delivery.pack(root, out)
            signature = delivery.sign(bundle, args.key)
        except RuntimeError as exc:
            print(f"security-agent: {exc}\n"
                  "hint: create a signing key first, e.g. gpg --quick-generate-key 'Name <email>' default sign never",
                  file=sys.stderr)
            return 2
        print(json.dumps({"bundle": str(bundle), "sums": str(sums), "signature": str(signature),
                          "recipient_steps": [
                              f"gpg --verify {signature.name} {bundle.name}",
                              f"tar -xzf {bundle.name} && sha256sum -c {sums.name} --ignore-missing | grep -v ': OK$' || echo 'all files OK'"]},
                         indent=2, ensure_ascii=False))
        return 0
    if args.command == "verify":
        from security_agent.core import delivery
        ok, problems = delivery.verify(args.dir, args.sums)
        print(json.dumps({"integrity_ok": ok, "problems": problems}, indent=2, ensure_ascii=False))
        return 0 if ok else 2
    previous = signal.signal(signal.SIGTERM, _interrupt)
    try:
        if args.command == "review":
            if args.file and args.base:
                parser.error("choose --file [--function] or --base/--head diff mode")
            if not args.file and not args.base:
                parser.error("provide --file [--function] or --base")
            if args.function and not args.file:
                parser.error("--function requires --file")
            if args.line is not None and (not args.function or args.line < 1):
                parser.error("--line requires --function and a positive line number")
            args.run = args.run or str(Path('.runs') / (datetime.now().strftime('%Y%m%d-%H%M%S') + '-' + uuid4().hex[:8]))
        root = Path(args.run).resolve()
        if args.command == "review":
            if args.judge_backend and args.judge_backend != args.backend and not args.judge_model:
                parser.error("--judge-model is required when changing Judge backend")
            if args.backend != "claude" and not args.model:
                parser.error("--model must be explicit for non-Claude backends")
            args.model = args.model or provider_env(args.claude_settings).get("ANTHROPIC_MODEL", "sonnet")
            def prepare_backend(baseline, root):
                graph = CodeGraph.prepare(baseline['repo'], baseline['head'], args.codegraph_cli,
                                          root / 'graph', args.index_timeout)
                if baseline.get('function'):
                    directory = root / 'graph/preload'; directory.mkdir()
                    result = graph.query('find_definition', baseline['function']['name'], 30, directory, min(30, args.index_timeout))
                    atomic_json(directory / 'symbols.json', result)
                return graph.record
            try:
                create(args.repo, args.base or args.head, args.head, root,
                       {key: getattr(args, key) for key in
                        ("model", "max_calls", "call_usd", "timeout", "max_context_bytes", "claude_settings", "max_tool_calls", "max_snapshot_bytes", "max_rounds", "max_hypotheses", "max_no_progress", "total_timeout", "backend", "judge_backend", "judge_model", "opencode_binary", "hermes_python", "hermes_source", "hermes_provider", "investigation_max_calls", "investigation_max_usd", "max_action_attempts")},
                       target_paths=[args.file] if args.file else None, function=args.function, line=args.line,
                       prepare_backend=prepare_backend if args.codegraph_cli else None)
            except ValueError as exc:
                if (root / 'state.json').exists() and read_json(root / 'state.json').get('execution') == 'PREPARING':
                    raise ValueError(f"{exc} (run directory {root} is left in PREPARING state; "
                                     "re-run with corrected arguments to resume, or remove it)") from exc
                raise
            if args.prepare_only:
                print(json.dumps({"execution": "PENDING", "run": str(root),
                                  "scope": read_json(root / "state.json")["baseline"]["scope"]}))
                return 0
        config = read_json(root / "state.json")["config"]
        saved = read_json(root / 'state.json')
        if saved["execution"] == "PREPARING":
            if not saved["investigations"]:
                raise ValueError("prepare stopped before scope completed; re-run review with the original --file/--function arguments")
            refs = saved["prepare"]["input_refs"]
            def resume_backend(baseline, root):
                graph = CodeGraph.prepare(baseline['repo'], baseline['head'], args.codegraph_cli,
                                          root / 'graph', args.index_timeout)
                return graph.record
            create(refs["repo"], refs["base"], refs["head"], root, config,
                   prepare_backend=resume_backend if args.codegraph_cli else None)
            saved = read_json(root / 'state.json')
        graph = CodeGraph(read_json(root / 'graph/binding.json')) if saved.get('query_backend') else None
        factory = lambda sources, access, directory: SemanticQueries(sources, access, directory, graph, min(30, config['timeout']))
        state = run(root, RoleExecutor(config), factory, graph.check if graph else None)
        print(json.dumps({"execution": state["execution"],
                          "findings": 0 if state["execution"] == "STALE" else len(state["findings"]),
                          "report": str(root / "report.md"), "sarif": str(root / "review.sarif")}))
        if state["execution"] == "INTERRUPTED":
            return 130
        if state["execution"] != "COMPLETED":
            return 2
        sarif = json.loads((root / "review.sarif").read_text())
        if not sarif["runs"][0]["properties"]["coverageComplete"]:
            return 2
        return 1 if state["findings"] else 0
    except KeyboardInterrupt:
        print("Interrupted; resume the same run to recover the checkpoint.", file=sys.stderr)
        return 130
    except (ValueError, OSError) as exc:
        print(f"security-agent: {exc}", file=sys.stderr)
        return 2
    finally:
        signal.signal(signal.SIGTERM, previous)


def _interrupt(signum, frame):
    raise KeyboardInterrupt
