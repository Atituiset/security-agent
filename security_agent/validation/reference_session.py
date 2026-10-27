"""Read-only import of a review-skills reference session for regression comparison.

Old decisions are comparison data, never investigator/Judge input or new evidence.
"""
from collections import Counter
from pathlib import Path
from security_agent.inputs.git_input import git, resolve
from security_agent.core.storage import digest, read_json


def inspect_session(directory):
    root = Path(directory).resolve()
    session = read_json(root / "session.json")
    target = read_json(root / "target.json")
    review = read_json(root / "reviews/cwe-476.json")
    if target.get("type") != "file":
        raise ValueError("reference replay currently supports file-target sessions")
    repo = target["repository"]
    commit = resolve(repo, session["baseline"]["commit"])
    sources = {}
    def source(path):
        if path.startswith("/") or ".." in Path(path).parts:
            raise ValueError("reference source path escapes repository")
        if path not in sources:
            sources[path] = git(repo, "show", f"{commit}:{path}")
        return sources[path]

    queries = {}
    dependencies = {}
    artifacts = {}
    def remember(path):
        resolved = path.resolve()
        if not resolved.is_relative_to(root):
            raise ValueError("reference artifact escapes session")
        artifacts[str(path.relative_to(root))] = digest(path.read_bytes())

    for name in ("session.json", "target.json", "reviews/cwe-476.json"):
        remember(root / name)
    for path in sorted((root / "context/queries").glob("*.json")):
        data = read_json(path)
        if "facts" not in data:
            continue
        remember(path)
        if data["id"] in queries:
            raise ValueError("duplicate reference query id")
        facts = {fact["id"]: fact for fact in data["facts"]}
        if len(facts) != len(data["facts"]):
            raise ValueError("duplicate reference fact id")
        queries[data["id"]] = facts
        for dependency in data.get("dependencies", []):
            name = dependency["path"]
            actual = digest(source(name))
            if actual != dependency["sha256"]:
                raise ValueError(f"reference dependency differs from commit: {name}")
            dependencies[name] = actual
        for fact in data["facts"]:
            raw = root / fact["raw_ref"]
            remember(raw)
    for path in target["paths"]:
        source(path)
    scenarios, seen, refs = [], set(), 0
    for scenario in review["scenarios"]:
        if scenario["id"] in seen:
            raise ValueError("duplicate reference scenario id")
        seen.add(scenario["id"])
        sink = scenario["sink"]
        if sink["path"] not in target["paths"]:
            raise ValueError("reference scenario outside target")
        if not 1 <= sink["start_line"] <= sink["end_line"] <= len(source(sink["path"]).splitlines()):
            raise ValueError("reference sink range invalid")
        for evidence in scenario["evidence"]:
            if evidence["fact_id"] not in queries.get(evidence["query_id"], {}):
                raise ValueError("unresolvable reference evidence")
            refs += 1
        scenarios.append({"id": scenario["id"], "sink": sink, "expected": scenario["state"]})
    return {"session": str(root), "repo": repo, "commit": commit, "paths": target["paths"],
            "rule": "CWE-476", "scenarios": scenarios,
            "counts": dict(Counter(s["expected"] for s in scenarios)),
            "checked_evidence_refs": refs, "dependencies": dependencies, "artifacts": artifacts,
            "limitations": ["Old exclusions are reference opinions, not ground truth.",
                            "CWE-401/CWE-416 conclusions are outside this MVP.",
                            "Artifact hashes record this import; they do not authenticate the original run."]}


def compare(reference, state):
    rows = []
    for scenario in reference["scenarios"]:
        sink = scenario["sink"]
        matches = []
        for unit in state["investigations"]:
            if unit["file"] != sink["path"]:
                continue
            decisions = {d["scenario_id"]: d for d in unit.get("decisions", [])}
            for new in unit.get("assessment", {}).get("scenarios", []):
                if sink["start_line"] <= new["sink_line"] <= sink["end_line"]:
                    decision = decisions.get(new["id"])
                    if decision:
                        matches.append({"scenario_id": new["id"], "verdict": decision["verdict"]})
        exact = [m for m in matches if m["scenario_id"] == scenario["id"]]
        if exact:
            matches = exact
        rows.append({"reference_id": scenario["id"], "expected": scenario["expected"],
                     "sink": sink, "matches": matches,
                     "comparison": "same-candidate-id" if exact else "unmatched" if not matches else "location-overlap; inspect semantic equivalence",
                     "verdict_agrees": (matches[0]["verdict"] == {"excluded": "REJECTED", "confirmed": "CONFIRMED",
                                            "unresolved": "UNKNOWN"}.get(scenario["expected"])) if exact else None})
    return {"execution": state["execution"], "cases": rows,
            "note": "Location overlap is a comparison aid, not proof of scenario equivalence or accuracy."}
