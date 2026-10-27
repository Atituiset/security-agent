"""Real Git input + real adapter/SDK types; only ClaudeSDKClient is replaced offline."""
import json
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import patch

import anyio
from claude_agent_sdk import ResultMessage, SystemMessage
from security_agent.infra.claude import ClaudeExecutor
from security_agent.pipeline.controller import create, run
from security_agent.core.storage import atomic_json, read_json, lock
from security_agent.cli import main
from security_agent.core.source_tools import numbered

SOURCE = "int example(void) {\n    int *ptr = 0;\n    return *ptr;\n}\n"
GUARDED = "int example(int *ptr) {\n    if (!ptr) return 0;\n    return *ptr;\n}\n"
CONFIG = {"model": "sonnet", "max_calls": 8, "call_usd": 0.25, "timeout": 1,
          "max_context_bytes": 120000}


def investigation(source=SOURCE, filename="null.c", unresolved=None):
    lines = source.splitlines()
    return {"scenarios": [{"id": "S1", "hypothesis": "investigator-private-hypothesis",
                           "sink_line": 3, "unresolved": unresolved or [],
                           "references": [
                               {"kind": kind, "file": filename, "start": start, "end": end}
                               for kind, start, end in (("origin", 2, 2), ("sink", 3, 3), ("path", 1, 4))]}],
            "unresolved": []}


def judgment(payload, verdict="CONFIRMED"):
    return {"decisions": [{"scenario_id": s["id"], "verdict": verdict,
                           "evidence_ids": s["evidence_ids"], "reason": "Evidence supports the decision.",
                           "unresolved": ["callee definition is unavailable"] if verdict == "UNKNOWN" else []}
                          for s in payload["scenarios"]]}


class FakeClient:
    queue = []
    options_seen = []
    payloads = []
    closed = 0

    def __init__(self, options):
        self.options = options
        type(self).options_seen.append(options)

    async def __aenter__(self):
        return self

    async def __aexit__(self, *args):
        type(self).closed += 1

    async def query(self, prompt):
        self.payload = json.loads(prompt)
        type(self).payloads.append(self.payload)

    async def receive_response(self):
        yield SystemMessage(subtype="init", data={"test": True})
        item = type(self).queue.pop(0)
        if item == "timeout":
            await anyio.sleep(10)
        if item == "crash":
            raise RuntimeError("SDK unavailable")
        if item == "interrupt":
            raise KeyboardInterrupt
        if callable(item):
            item = item(self.payload)
        if isinstance(item, ResultMessage):
            yield item
        else:
            yield ResultMessage(subtype="success", duration_ms=1, duration_api_ms=1,
                                is_error=False, num_turns=1, session_id="test-session",
                                structured_output=item, total_cost_usd=0.01)


class ReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.repo = self.root / "repo"
        self.repo.mkdir()
        self.git("init", "-q")
        self.git("config", "user.email", "test@example.invalid")
        self.git("config", "user.name", "Test")
        self.git("commit", "--allow-empty", "-qm", "base")
        self.base = self.git("rev-parse", "HEAD")
        self.output = self.root / "run"
        FakeClient.queue, FakeClient.options_seen, FakeClient.payloads, FakeClient.closed = [], [], [], 0
        self.mock = patch("claude_agent_sdk.ClaudeSDKClient", FakeClient)
        self.mock.start()
        self.addCleanup(self.mock.stop)

    def git(self, *args):
        return subprocess.check_output(["git", "-C", str(self.repo), *args], stderr=subprocess.PIPE).decode().strip()

    def setup_run(self, source=SOURCE, config=None, head="HEAD", extra=None, filename="null.c"):
        (self.repo / filename).write_text(source)
        for path, text in (extra or {}).items():
            (self.repo / path).write_text(text)
        self.git("add", ".")
        self.git("commit", "-qm", "head")
        create(self.repo, self.base, head, self.output, {**CONFIG, **(config or {})})

    def run_review(self, *responses):
        FakeClient.queue.extend(responses)
        return run(self.output, ClaudeExecutor())

    def sarif(self):
        return read_json(self.output / "review.sarif")["runs"][0]

    def test_complete_flow_and_resume_is_idempotent(self):
        self.setup_run()
        state = self.run_review(investigation(), judgment)
        self.assertEqual(state["execution"], "COMPLETED")
        self.assertEqual(len(state["findings"]), 1)
        self.assertEqual(state["findings"][0]["remediation"], "NOT_STARTED")
        self.assertEqual(self.sarif()["results"][0]["ruleId"], "CWE-476")
        self.assertEqual(self.sarif()["results"][0]["locations"][0]["physicalLocation"]["region"]["startLine"], 3)
        self.assertIn("CWE-476", (self.output / "report.md").read_text())
        self.assertEqual(len(self.run_review()["attempts"]), 2)
        self.assertEqual(FakeClient.closed, 2)
        for options in FakeClient.options_seen:
            self.assertEqual(options.tools, [])
            self.assertEqual(options.setting_sources, [])
            self.assertIsNone(options.resume)
            self.assertEqual(options.max_budget_usd, 0.25)
        self.assertNotEqual(FakeClient.options_seen[0].cwd, FakeClient.options_seen[1].cwd)
        self.assertNotIn("sources", FakeClient.payloads[0])
        self.assertEqual(FakeClient.payloads[0]["target_source"], numbered(SOURCE))
        self.assertEqual(FakeClient.options_seen[1].mcp_servers, {})
        self.assertEqual(FakeClient.options_seen[1].allowed_tools, [])
        self.assertIn("security", FakeClient.options_seen[0].mcp_servers)
        self.assertNotIn("investigator-private-hypothesis", json.dumps(FakeClient.payloads[1]))
        self.assertTrue((self.output / "attempts/A00001/messages.jsonl").exists())

    def test_guarded_scenario_is_rejected_not_finding(self):
        self.setup_run(GUARDED)
        state = self.run_review(investigation(GUARDED), lambda p: judgment(p, "REJECTED"))
        self.assertEqual(state["investigations"][0]["verdict"], "REJECTED")
        self.assertEqual(state["findings"], [])

    def test_missing_definition_stays_unknown(self):
        self.setup_run()
        state = self.run_review(investigation(unresolved=["missing definition"]),
                                lambda p: judgment(p, "UNKNOWN"))
        self.assertEqual(state["execution"], "COMPLETED")
        self.assertEqual(state["investigations"][0]["verdict"], "UNKNOWN")
        self.assertFalse(self.sarif()["properties"]["coverageComplete"])
        self.assertEqual(state["findings"], [])

    def test_empty_scope_is_not_coverage_complete(self):
        (self.repo / "readme.txt").write_text("hello\n")
        self.git("add", ".")
        self.git("commit", "-qm", "head")
        create(self.repo, self.base, "HEAD", self.output, CONFIG)
        state = self.run_review()
        self.assertEqual(state["execution"], "COMPLETED")
        self.assertEqual(state["investigations"], [])
        self.assertFalse(self.sarif()["properties"]["coverageComplete"])
        report = (self.output / "report.md").read_text()
        self.assertIn("nothing was reviewed", report)

    def test_sarif_related_locations_embed_evidence(self):
        self.setup_run()
        self.run_review(investigation(), lambda p: judgment(p))
        result = self.sarif()["results"][0]
        related = result["relatedLocations"]
        self.assertEqual(len(related), 3)
        kinds = [rl["message"]["text"].split(" evidence")[0] for rl in related]
        self.assertEqual(kinds, ["origin", "sink", "path"])
        self.assertIn("int *ptr = 0;", related[0]["physicalLocation"]["region"]["snippet"]["text"])

    def test_html_report_is_self_contained_and_escapes_source(self):
        source = "int example(void) {\n    int *ptr = 0;\n    if (*ptr < 1) return 1;\n    return 0;\n}\n"
        self.setup_run(source=source)
        self.run_review(investigation(source=source), lambda p: judgment(p))
        page = (self.output / "review.html").read_text()
        self.assertIn("int *ptr = 0;", page)
        self.assertIn("if (*ptr &lt; 1)", page)
        self.assertIn("origin", page)
        self.assertIn("cwe476-v7-runtime", page)
        self.assertIn("coverage", page)
        self.assertIn("A00001", page)

    def test_cross_file_source_is_in_context(self):
        self.setup_run(extra={"provider.h": "int *get(void);\n"})
        # Header also receives its own investigation, preserving dispatch coverage.
        state = self.run_review(investigation(), judgment,
                                {"scenarios": [], "unresolved": ["declaration only"]}, judgment)
        self.assertIn("provider.h", FakeClient.payloads[0]["source_index"])
        self.assertEqual(len(state["investigations"]), 2)

    def test_fabricated_quote_fails_closed(self):
        self.setup_run()
        forged = investigation()
        forged["scenarios"][0]["references"][0]["quote"] = "invented code"
        state = self.run_review(forged)
        self.assertEqual(state["execution"], "FAILED")
        self.assertEqual(state["findings"], [])
        self.assertEqual(len(state["attempts"]), 1)

    def test_judge_fabricated_reference_fails_closed(self):
        self.setup_run()
        def forged(p):
            result = judgment(p)
            result["decisions"][0]["evidence_ids"] = ["imaginary"]
            return result
        state = self.run_review(investigation(), forged)
        self.assertEqual(state["execution"], "FAILED")
        self.assertEqual(state["findings"], [])

    def test_required_evidence_gate(self):
        self.setup_run()
        output = investigation()
        output["scenarios"][0]["references"] = output["scenarios"][0]["references"][1:]
        state = self.run_review(output, judgment)
        self.assertEqual(state["execution"], "FAILED")
        self.assertEqual(state["findings"], [])

    def test_unresolved_cannot_be_confirmed(self):
        self.setup_run()
        state = self.run_review(investigation(unresolved=["pointer origin unknown"]), judgment)
        self.assertEqual(state["execution"], "FAILED")
        self.assertEqual(state["findings"], [])

    def test_budget_exhausted_between_roles(self):
        self.setup_run(config={"max_calls": 1})
        state = self.run_review(investigation())
        self.assertEqual(state["execution"], "BUDGET_EXHAUSTED")
        self.assertEqual(state["investigations"][0]["phase"], "judge")
        self.assertEqual(len(self.run_review()["attempts"]), 1)
        self.assertEqual(self.sarif()["results"], [])

    def test_context_budget_exhausted_before_calls(self):
        self.setup_run(config={"max_context_bytes": 2})
        state = self.run_review()
        self.assertEqual(state["execution"], "BUDGET_EXHAUSTED")
        self.assertEqual(state["attempts"], [])

    def test_timeout_retains_partial_events_and_resume(self):
        self.setup_run(config={"timeout": 0.05})
        state = self.run_review("timeout")
        self.assertEqual(state["execution"], "TIMED_OUT")
        self.assertIn("SystemMessage", (self.output / "attempts/A00001/messages.jsonl").read_text())
        state = self.run_review(investigation(), judgment)
        self.assertEqual(state["execution"], "COMPLETED")
        self.assertEqual(len(state["attempts"]), 3)
        self.assertEqual(FakeClient.closed, 3)

    def test_interruption_retains_checkpoint_and_resume(self):
        self.setup_run()
        state = self.run_review(investigation(), "interrupt")
        self.assertEqual(state["execution"], "INTERRUPTED")
        self.assertEqual(state["investigations"][0]["phase"], "judge")
        state = self.run_review(judgment)
        self.assertEqual(state["execution"], "COMPLETED")
        self.assertEqual(len(state["attempts"]), 3)

    def test_abrupt_death_reservation_is_not_refunded(self):
        self.setup_run()
        state = read_json(self.output / "state.json")
        state["attempts"] = [{"id": "A00001", "execution": "RUNNING"}]
        state["investigations"][0]["execution"] = "RUNNING"
        (self.output / "attempts/A00001").mkdir()
        atomic_json(self.output / "state.json", state)
        state = self.run_review(investigation(), judgment)
        self.assertEqual(state["attempts"][0]["execution"], "INTERRUPTED")
        self.assertEqual(len(state["attempts"]), 3)

    def test_ref_change_invalidates_even_unchanged_sink(self):
        self.setup_run()
        self.run_review(investigation(), judgment)
        (self.repo / "provider.cpp").write_text("int *get() { return nullptr; }\n")
        self.git("add", ".")
        self.git("commit", "-qm", "new callee")
        state = self.run_review()
        self.assertEqual(state["execution"], "STALE")
        self.assertEqual(self.sarif()["results"], [])

    def test_fixed_commit_ignores_uncommitted_edits(self):
        self.setup_run()
        (self.repo / "null.c").write_text("working copy differs\n")
        state = self.run_review(investigation(), judgment)
        self.assertEqual(state["execution"], "COMPLETED")

    def test_source_corruption_invalidates(self):
        self.setup_run()
        state = read_json(self.output / "state.json")
        artifact = state["baseline"]["sources"]["null.c"]["path"]
        (self.output / artifact).write_text("changed")
        self.assertEqual(self.run_review()["execution"], "STALE")

    def test_raw_response_corruption_invalidates(self):
        self.setup_run()
        self.run_review(investigation(), judgment)
        (self.output / "attempts/A00001/messages.jsonl").write_text("changed")
        self.assertEqual(self.run_review()["execution"], "STALE")
        self.assertEqual(self.sarif()["results"], [])

    def test_changed_budget_is_rejected(self):
        self.setup_run()
        state = read_json(self.output / "state.json")
        state["config"]["max_calls"] += 1
        atomic_json(self.output / "state.json", state)
        self.assertEqual(self.run_review()["execution"], "STALE")

    def test_auth_error_reports_actionable_reason(self):
        self.setup_run()
        result = ResultMessage(subtype="success", duration_ms=1, duration_api_ms=1,
                               is_error=True, num_turns=0, session_id="unauthenticated",
                               result="Not logged in · Please run /login")
        state = self.run_review(result)
        self.assertEqual(state["execution"], "FAILED")
        self.assertIn("Not logged in", state["investigations"][0]["detail"])
        self.assertEqual(self.sarif()["results"], [])

    def test_sdk_error_is_not_rejection(self):
        self.setup_run()
        state = self.run_review("crash")
        self.assertEqual(state["execution"], "FAILED")
        self.assertEqual(state["investigations"][0]["verdict"], "UNKNOWN")

    def test_single_writer(self):
        self.setup_run()
        with lock(self.output):
            with self.assertRaisesRegex(ValueError, "active writer"):
                self.run_review()

    def test_cli_exit_findings(self):
        self.setup_run()
        FakeClient.queue = [investigation(), judgment]
        self.assertEqual(main(["resume", "--run", str(self.output)]), 1)

    def test_deleted_file_and_non_cpp_have_no_targets(self):
        self.setup_run()
        old = self.git("rev-parse", "HEAD")
        (self.repo / "null.c").unlink()
        (self.repo / "readme.txt").write_text("text")
        self.git("add", "-A")
        self.git("commit", "-qm", "delete")
        other = self.root / "other"
        create(self.repo, old, "HEAD", other, CONFIG)
        state = run(other, ClaudeExecutor())
        self.assertEqual(state["execution"], "COMPLETED")
        self.assertEqual(state["investigations"], [])

    def test_unusual_filename_is_preserved(self):
        path = '空 格"name.cpp'
        self.setup_run(filename=path)
        state = self.run_review(investigation(filename=path), judgment)
        self.assertEqual(state["findings"][0]["file"], path)
        self.assertIn("%20", self.sarif()["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"])

    def test_non_utf8_fails_closed(self):
        self.setup_run()
        (self.repo / "null.c").write_bytes(b"\xff")
        self.git("add", ".")
        self.git("commit", "-qm", "encoding")
        other = self.root / "encoding"
        create(self.repo, self.base, "HEAD", other, CONFIG)
        self.assertEqual(run(other, ClaudeExecutor())["execution"], "FAILED")

    def test_symlink_source_fails_closed(self):
        (self.repo / "external.c").symlink_to("/etc/passwd")
        self.setup_run()
        self.assertEqual(self.run_review()["execution"], "FAILED")

    def test_checkpoint_finding_cannot_be_forged(self):
        self.setup_run()
        self.run_review(investigation(), judgment)
        state = read_json(self.output / "state.json")
        state["findings"][0]["reason"] = "tampered"
        atomic_json(self.output / "state.json", state)
        self.assertEqual(self.run_review()["execution"], "STALE")
        self.assertEqual(self.sarif()["results"], [])

    def test_judge_omission_is_failure(self):
        self.setup_run()
        state = self.run_review(investigation(), {"decisions": []})
        self.assertEqual(state["execution"], "FAILED")
        self.assertEqual(state["findings"], [])

    def test_invalid_sdk_schema_is_preserved_as_failure(self):
        self.setup_run()
        state = self.run_review({"unexpected": "response"})
        self.assertEqual(state["execution"], "FAILED")
        self.assertIn("unexpected", (self.output / "attempts/A00001/messages.jsonl").read_text())

    def test_cross_file_evidence_is_validated_and_sent_to_judge(self):
        # Provider exists before the diff; only caller.cpp is an investigation target.
        provider = "int *get(void) { return 0; }\n"
        (self.repo / "provider.cpp").write_text(provider)
        self.git("add", ".")
        self.git("commit", "-qm", "provider")
        self.base = self.git("rev-parse", "HEAD")
        caller = "int *get(void);\nint example(void) { int *ptr = get();\n    return *ptr;\n}\n"
        self.setup_run(source=caller, filename="caller.cpp")
        output = investigation(caller, "caller.cpp")
        output["scenarios"][0]["references"][0] = {
            "kind": "origin", "file": "provider.cpp", "start": 1, "end": 1}
        state = self.run_review(output, judgment)
        self.assertEqual(len(state["findings"]), 1)
        self.assertIn("provider.cpp", FakeClient.payloads[1]["source_context"])
        self.assertEqual(len(state["investigations"]), 1)

    def test_empty_scenarios_still_report_coverage_gap(self):
        self.setup_run()
        state = self.run_review({"scenarios": [], "unresolved": []}, judgment)
        self.assertEqual(state["execution"], "COMPLETED")
        self.assertEqual(state["investigations"][0]["verdict"], "UNKNOWN")
        self.assertFalse(self.sarif()["properties"]["coverageComplete"])

    def test_sdk_budget_result_keeps_unknown(self):
        self.setup_run()
        result = ResultMessage(subtype="error_max_budget_usd", duration_ms=1,
                               duration_api_ms=1, is_error=True, num_turns=1, session_id="budget")
        state = self.run_review(result)
        self.assertEqual(state["execution"], "BUDGET_EXHAUSTED")
        self.assertEqual(state["investigations"][0]["verdict"], "UNKNOWN")

    def test_canonical_evidence_comes_from_git_not_model_text(self):
        self.setup_run()
        state = self.run_review(investigation(), judgment)
        evidence = state["investigations"][0]["assessment"]["evidence"]
        self.assertEqual(evidence[1]["quote"], "    return *ptr;")
        self.assertNotIn("quote", investigation()["scenarios"][0]["references"][0])

    def test_completed_sdk_response_is_replayed_without_another_call(self):
        self.setup_run()
        state = self.run_review(investigation(), judgment)
        unit = state["investigations"][0]
        unit.update(phase="judge", execution="FAILED", decisions=[])
        unit.pop("decision_artifact")
        unit["rounds"][-1].pop("decision_artifact")
        from security_agent.core.runtime import refresh
        refresh(self.output, state, unit)
        state["findings"] = []
        atomic_json(self.output / "state.json", state)
        resumed = self.run_review()
        self.assertEqual(resumed["execution"], "COMPLETED")
        self.assertEqual(len(resumed["attempts"]), 2)
        self.assertEqual(len(resumed["findings"]), 1)

    def test_confirmation_must_cite_primary_sink(self):
        self.setup_run()
        output = investigation()
        output["scenarios"][0]["references"][1]["start"] = 2
        output["scenarios"][0]["references"][1]["end"] = 2
        state = self.run_review(output, judgment)
        self.assertEqual(state["execution"], "FAILED")
        self.assertIn("primary sink", state["investigations"][0]["detail"])

    def test_nonfinite_budget_rejected(self):
        with self.assertRaises(ValueError):
            create(self.repo, self.base, "HEAD", self.output, {**CONFIG, "timeout": float("nan")})


if __name__ == "__main__":
    unittest.main()
