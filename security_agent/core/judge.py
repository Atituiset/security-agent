"""Deterministic evidence admission and independent semantic Judge boundary."""
from .skills import load_rule
from security_agent.core.contracts import ContractError, INVESTIGATION_SCHEMA, JUDGE_SCHEMA, Verdict, validate
from security_agent.core.storage import digest, now
from security_agent.core.source_tools import numbered


def admit(investigation, output, sources, baseline, attempt_id):
    validate(output, INVESTIGATION_SCHEMA)
    scenarios, evidence, seen = [], [], set()
    for scenario in output["scenarios"]:
        sid = scenario["id"]
        if sid in seen:
            raise ContractError("duplicate scenario id")
        seen.add(sid)
        if scenario["sink_line"] > len(sources[investigation["file"]].splitlines()):
            raise ContractError("sink outside target source")
        scope = investigation.get("function")
        if scope and not scope["start"] <= scenario["sink_line"] <= scope["end"]:
            raise ContractError("sink outside requested function")
        ids = []
        for ref in scenario["references"]:
            if ref["file"] not in sources:
                raise ContractError("reference is not a frozen source")
            lines = sources[ref["file"]].splitlines()
            if not 1 <= ref["start"] <= ref["end"] <= len(lines):
                raise ContractError("reference line range invalid")
            quote = "\n".join(lines[ref["start"] - 1:ref["end"]])
            if ref["kind"] == "sink" and ref["file"] != investigation["file"]:
                raise ContractError("sink reference is outside investigation file")
            if ref["kind"] == "sink" and scope and not scope["start"] <= ref["start"] <= ref["end"] <= scope["end"]:
                raise ContractError("sink reference outside requested function")
            eid = f"{investigation['id']}-{attempt_id}-E{len(evidence) + 1}"
            ids.append(eid)
            evidence.append({"id": eid, **ref, "quote": quote, "producer": "git-blob/exact-lines",
                             "selected_by": attempt_id, "timestamp": now(),
                             "commit": baseline["head"],
                             "blob": baseline["sources"][ref["file"]]["blob"],
                             "source_sha256": baseline["sources"][ref["file"]]["sha256"]})
        scenarios.append({**scenario, "evidence_ids": ids})
    candidates = {c["id"]: c for c in investigation.get("candidates", [])}
    for scenario in scenarios:
        candidate = candidates.get(scenario["id"])
        if candidate and not candidate["start"] <= scenario["sink_line"] <= candidate["end"]:
            raise ContractError("scenario sink is outside its requested candidate range")
    if not set(candidates) <= seen:
        raise ContractError("Investigator omitted requested candidate scenarios")
    return {"scenarios": scenarios, "evidence": evidence, "unresolved": output["unresolved"]}


def judge_payload(unit, assessment, sources):
    # Never pass hypothesis, investigator prose, or its raw response to the Judge.
    evidence = assessment["evidence"]
    contexts = {}
    for file in sorted({e["file"] for e in evidence}):
        lines = sources[file].splitlines()
        intervals = ([(unit["function"]["start"], unit["function"]["end"])]
                     if file == unit["file"] and unit.get("function") else
                     [(1, len(lines))] if file == unit["file"] else
                     sorted((max(1, e["start"] - 20), min(len(lines), e["end"] + 20))
                            for e in evidence if e["file"] == file))
        merged = []
        for start, end in intervals:
            if merged and start <= merged[-1][1] + 1:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        contexts[file] = {"total_lines": len(lines),
                          "complete_file": merged == [[1, len(lines)]],
                          "windows": [{"start": start, "end": end,
                                       "source": numbered("\n".join(lines[start-1:end]), start)}
                                      for start, end in merged]}
    return {"cwe": "CWE-476", "scope": {"file": unit["file"], "function": unit.get("function")},
            "scenarios": [{"id": s["id"], "sink_line": s["sink_line"],
                           "evidence_ids": s["evidence_ids"]} for s in assessment["scenarios"]],
            "evidence": evidence,
            "source_context": contexts,
            "policy": {"confirmed_requires": load_rule()["required_evidence"],
                       "missing_facts": "UNKNOWN; dependency windows may omit other code; never infer absence from windows",
                       "scope": "requested file and candidate scenarios only"}}


def decide(unit, assessment, output):
    validate(output, JUDGE_SCHEMA)
    scenarios = {s["id"]: s for s in assessment["scenarios"]}
    evidence = {e["id"]: e for e in assessment["evidence"]}
    decisions, findings, seen = [], [], set()
    for decision in output["decisions"]:
        sid = decision["scenario_id"]
        if sid not in scenarios or sid in seen:
            raise ContractError("Judge scenario IDs must match exactly once")
        seen.add(sid)
        ids = decision["evidence_ids"]
        if len(ids) != len(set(ids)) or not set(ids) <= set(scenarios[sid]["evidence_ids"]):
            raise ContractError("Judge cited unknown, duplicate or foreign evidence")
        verdict = decision["verdict"]
        if verdict != Verdict.UNKNOWN and not ids:
            raise ContractError("decisive verdict requires evidence")
        if verdict == Verdict.UNKNOWN and not decision["unresolved"]:
            raise ContractError("UNKNOWN requires an unresolved question")
        if verdict == Verdict.CONFIRMED:
            if decision["unresolved"] or scenarios[sid]["unresolved"]:
                raise ContractError("confirmation has unresolved material facts")
            if not set(load_rule()["required_evidence"]) <= {evidence[i]["kind"] for i in ids}:
                raise ContractError("confirmation lacks required evidence")
            sinks = [evidence[i] for i in ids if evidence[i]["kind"] == "sink"
                     and evidence[i]["start"] <= scenarios[sid]["sink_line"] <= evidence[i]["end"]]
            if not sinks:
                raise ContractError("confirmation does not cite its primary sink location")
            sink = sinks[0]
            fingerprint = digest(("CWE-476\0" + unit["file"] + "\0" +
                                  str(scenarios[sid]["sink_line"]) + "\0" + sink["quote"]).encode())
            findings.append({"id": "F-" + fingerprint[:16], "fingerprint": fingerprint,
                             "investigation_id": unit["id"], "scenario_id": sid,
                             "cwe": "CWE-476", "file": unit["file"],
                             "line": scenarios[sid]["sink_line"], "reason": decision["reason"],
                             "evidence_ids": ids, "verdict": "CONFIRMED",
                             "remediation": "NOT_STARTED"})
        decisions.append(decision)
    if seen != set(scenarios):
        raise ContractError("Judge omitted scenarios")
    return decisions, findings
