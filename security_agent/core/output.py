"""Rebuildable reports: findings and coverage gaps remain distinct."""
import html
from pathlib import Path
from urllib.parse import quote
from security_agent.core.storage import atomic_json


def export(root, state):
    stale = state["execution"] == "STALE"
    findings = [] if stale else state["findings"]
    gaps = list(state["baseline"]["limitations"])
    if not state["investigations"]:
        gaps.append("no C/C++ sources in the frozen scope; nothing was reviewed")
    for action in state.get("prepare", {}).get("actions", []):
        if action["execution"] == "FAILED":
            gaps.append(f"prepare/{action['kind']}: {action['detail']}")
    if state.get("detail"):
        gaps.append(state["detail"])
    for unit in state["investigations"]:
        if unit["execution"] != "COMPLETED":
            gaps.append(f"{unit['id']}: {unit['execution']}: {unit.get('detail', '')}")
        for question in unit.get("assessment", {}).get("unresolved", []):
            gaps.append(f"{unit['id']}: {question}")
        if unit["execution"] == "COMPLETED" and not unit.get("decisions"):
            gaps.append(f"{unit['id']}: no scenarios identified; no file-wide safety verdict")
        for decision in unit.get("decisions", []):
            if decision["verdict"] == "UNKNOWN":
                gaps.append(f"{unit['id']}/{decision['scenario_id']}: UNKNOWN: " +
                            "; ".join(decision["unresolved"]))
    gaps = list(dict.fromkeys(gaps))
    complete = state["execution"] == "COMPLETED" and not gaps
    units = {u["id"]: u for u in state["investigations"]}
    results = []
    for finding in findings:
        unit = units[finding["investigation_id"]]
        evidence = {e["id"]: e for e in unit.get("assessment", {}).get("evidence", [])}
        related = []
        for n, eid in enumerate(finding["evidence_ids"], 1):
            e = evidence.get(eid)
            if not e:
                continue
            related.append({"id": n, "physicalLocation": {
                "artifactLocation": {"uri": quote(e["file"], safe="/")},
                "region": {"startLine": e["start"], "endLine": e["end"],
                           "snippet": {"text": e["quote"]}}},
                "message": {"text": f"{e['kind']} evidence ({eid}); commit {e['commit']}, "
                                    f"blob {e['blob']}, source sha256 {e['source_sha256']}"}})
        results.append({"ruleId": "CWE-476", "level": "warning",
                        "message": {"text": finding["reason"]},
                        "locations": [{"physicalLocation": {
                            "artifactLocation": {"uri": quote(finding["file"], safe="/")},
                            "region": {"startLine": finding["line"]}}}],
                        "relatedLocations": related,
                        "partialFingerprints": {"securityAgent/v1": finding["fingerprint"]},
                        "properties": {"findingId": finding["id"],
                                       "investigationId": finding["investigation_id"],
                                       "evidenceIds": finding["evidence_ids"],
                                       "remediation": finding["remediation"],
                                       "evidenceVersion": finding.get("evidence_version")}})
    sarif = {"$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
             "runs": [{"tool": {"driver": {"name": "security-agent", "version": "0.1.0",
                        "rules": [{"id": "CWE-476", "name": "NullPointerDereference",
                                   "shortDescription": {"text": "Null pointer dereference"},
                                   "helpUri": "https://cwe.mitre.org/data/definitions/476.html"}]}},
                       "results": results,
                       "invocations": [{"executionSuccessful": state["execution"] == "COMPLETED",
                           "toolExecutionNotifications": [{"level": "warning", "message": {"text": g}}
                                                          for g in gaps]}],
                       "versionControlProvenance": [{"revisionId": state["baseline"]["head"],
                           "repositoryUri": Path(state["baseline"]["repo"]).as_uri()}],
                       "properties": {"execution": state["execution"], "coverageComplete": complete,
                                      "scope": state["baseline"]["scope"],
                                      "policyVersion": state["policy_version"],
                                      "rule": {"id": state["rule"]["id"], "version": state["rule"]["version"],
                                               "sha256": state["rule"]["sha256"]},
                                      "investigations": [{"id": u["id"], "round": u.get("round", 1),
                                                          "stopReason": u.get("stop_reason"),
                                                          "hypotheses": u.get("hypotheses", [])}
                                                         for u in state["investigations"]],
                                      "baseCommit": state["baseline"]["base"],
                                      "reservedCalls": len(state["attempts"]),
                                      "reservedUsd": len(state["attempts"]) * state["config"]["call_usd"]}}]}
    atomic_json(root / "review.sarif", sarif)
    esc = lambda x: html.escape(str(x)).replace("\n", " ")
    lines = ["# Security review", "", f"Execution: **{state['execution']}**", "",
             f"Baseline: `{state['baseline']['base']}` → `{state['baseline']['head']}`", "",
             f"Scope: {esc(state["baseline"]["scope"])}. "
             "Uncommitted edits are excluded. Findings are not necessarily newly introduced.", "",
             f"Confirmed findings: {len(findings)}. Coverage complete: {str(complete).lower()}.", "",
             "Absence of findings is not a project safety claim. Remediation is NOT_STARTED.", "",
             f"Reserved calls: {len(state['attempts'])}/{state['config']['max_calls']}; "
             f"reserved USD ceiling: {len(state['attempts']) * state['config']['call_usd']:.2f}.", "",
             "## Findings", ""]
    for finding in findings:
        lines.extend([f"### {finding['id']} — CWE-476", "",
                      f"{esc(finding['file'])}:{finding['line']} — {esc(finding['reason'])}", "",
                      "Evidence: " + ", ".join(finding["evidence_ids"]), ""])
    lines += ["## Investigations and verdicts", ""]
    for unit in state["investigations"]:
        lines += [f"- {unit['id']} {esc(unit['file'])}: {unit['execution']}; "
                  f"assessment: {'UNKNOWN' if stale else unit['verdict']}"]
        lines += [f"  - Round: {unit.get('round', 1)}; stop: {esc(unit.get('stop_reason', unit.get('detail', 'pending')))}"]
        for hypothesis in unit.get("hypotheses", []):
            lines += [f"  - Hypothesis {esc(hypothesis['id'])}: evidence version {hypothesis['evidence_version']}; "
                      f"missing facts: {esc('; '.join(hypothesis['missing_facts']))}"]
        for decision in ([] if stale else unit.get("decisions", [])):
            lines += [f"  - {esc(decision['scenario_id'])}: {decision['verdict']} — {esc(decision['reason'])}"]
        for rejected in unit.get("rejected_follow_up", []):
            lines += [f"  - Rejected follow-up: {esc(rejected['question'])}; {esc(rejected['reason'])}"]
    lines += ["", "## Action history", ""]
    for action in state.get("actions", {}).values():
        lines += [f"- {action['id']}: {action['kind']}; {action['execution']}; "
                  f"evidence version {action['evidence_version']}; "
                  f"backend: {esc(action.get('backend', 'claude'))}; model: {esc(action.get('model', state['config']['model']))}; "
                  f"attempts: {', '.join(action['attempts'])}"]
    lines += ["", "## Coverage gaps", ""] + [f"- {esc(g)}" for g in gaps]
    lines += ["", "## Evidence index", ""]
    for unit in state["investigations"]:
        for ev in unit.get("assessment", {}).get("evidence", []):
            lines += [f"- {ev['id']}: {esc(ev['file'])}:{ev['start']}-{ev['end']}; "
                      f"blob `{ev['blob']}`; SHA-256 `{ev['source_sha256']}`; "
                      f"attempt `{ev['selected_by']}`."]
    lines += ["", "Raw requests/responses: `attempts/`. Frozen source: `snapshots/`. "
              "Auditable decisions and original quotes: `state.json` and sealed `assessments/`.", ""]
    (root / "report.md").write_text("\n".join(lines), encoding="utf-8")
    export_html(root, state)


CSS = """
body{font-family:-apple-system,'Segoe UI',Helvetica,Arial,sans-serif;max-width:960px;margin:24px auto;padding:0 16px;color:#1c1e21;line-height:1.5}
h1{font-size:22px} h2{font-size:17px;margin-top:32px;border-bottom:1px solid #ddd;padding-bottom:4px}
.card{border:1px solid #ddd;border-radius:8px;padding:14px 16px;margin:12px 0}
.meta{color:#666;font-size:13px}.badge{display:inline-block;border-radius:4px;padding:1px 8px;font-size:12px;font-weight:600;color:#fff}
.b-ok{background:#1a7f37}.b-bad{background:#cf222e}.b-warn{background:#9a6700}
.kind{border:1px solid #888;border-radius:4px;padding:0 6px;font-size:12px;color:#444}
pre{background:#f6f8fa;border-radius:6px;padding:10px;overflow-x:auto;font-size:12.5px}
table{border-collapse:collapse;width:100%;font-size:13px}td,th{border:1px solid #ddd;padding:4px 8px;text-align:left}
code{background:#f6f8fa;border-radius:4px;padding:0 4px}.hash{font-family:monospace;font-size:11.5px;color:#666;word-break:break-all}
ul.gaps li{margin:4px 0}
"""


def export_html(root, state):
    """Single-file self-contained delivery report: header, findings with embedded evidence,
    verdicts, gaps, action history. Everything a recipient needs without the run directory."""
    import html as H
    esc = lambda x: H.escape(str(x))
    root = Path(root)
    stale = state["execution"] == "STALE"
    findings = [] if stale else state["findings"]
    gaps = list(state["baseline"]["limitations"])
    for action in state.get("prepare", {}).get("actions", []):
        if action["execution"] == "FAILED":
            gaps.append(f"prepare/{action['kind']}: {action['detail']}")
    for unit in state["investigations"]:
        if unit["execution"] != "COMPLETED":
            gaps.append(f"{unit['id']}: {unit['execution']}: {unit.get('detail', '')}")
        for decision in unit.get("decisions", []):
            if decision["verdict"] == "UNKNOWN":
                gaps.append(f"{unit['id']}/{decision['scenario_id']}: UNKNOWN: " + "; ".join(decision["unresolved"]))
        if unit["execution"] == "COMPLETED" and not unit.get("decisions"):
            gaps.append(f"{unit['id']}: no scenarios identified; no file-wide safety verdict")
    if not state["investigations"]:
        gaps.append("no C/C++ sources in the frozen scope; nothing was reviewed")
    gaps = list(dict.fromkeys(gaps))
    complete = state["execution"] == "COMPLETED" and not gaps
    units = {u["id"]: u for u in state["investigations"]}
    rule = state["rule"]
    out = ["<!DOCTYPE html><html><head><meta charset='utf-8'>",
           f"<title>Security review — {esc(state['baseline']['head'][:12])}</title>",
           f"<style>{CSS}</style></head><body>",
           "<h1>Security review</h1>",
           "<div class='card'>",
           f"<span class='badge {'b-ok' if state['execution']=='COMPLETED' else 'b-bad'}'>{esc(state['execution'])}</span> ",
           f"<span class='badge {'b-ok' if complete else 'b-warn'}'>coverage {'complete' if complete else 'incomplete'}</span>",
           f"<p class='meta'>Baseline <code>{esc(state['baseline']['base'])}</code> → "
           f"<code>{esc(state['baseline']['head'])}</code> &nbsp;|&nbsp; Scope: {esc(state['baseline']['scope'])}<br>",
           f"Rule {esc(rule['id'])} v{esc(rule['version'])} <span class='hash'>{esc(rule['sha256'])}</span><br>",
           f"Policy {esc(state['policy_version'])} &nbsp;|&nbsp; Created {esc(state.get('created_at',''))} "
           f"&nbsp;|&nbsp; Calls {len(state['attempts'])}/{state['config']['max_calls']}, "
           f"reserved USD {len(state['attempts']) * state['config']['call_usd']:.2f}</p>",
           "<p class='meta'>Absence of findings is not a project safety claim. "
           "Uncommitted edits excluded. Remediation NOT_STARTED.</p></div>",
           f"<h2>Confirmed findings ({len(findings)})</h2>"]
    if not findings:
        out.append("<p class='meta'>No confirmed findings. See coverage gaps below before interpreting this.</p>")
    for finding in findings:
        unit = units[finding["investigation_id"]]
        evidence = {e["id"]: e for e in unit.get("assessment", {}).get("evidence", [])}
        out += ["<div class='card'>", f"<b>{esc(finding['id'])}</b> — {esc(finding['cwe'])}; ",
                f"<code>{esc(finding['file'])}:{finding['line']}</code>",
                f"<p>{esc(finding['reason'])}</p>",
                f"<p class='meta'>fingerprint <span class='hash'>{esc(finding['fingerprint'])}</span>; "
                f"evidence version {esc(finding.get('evidence_version'))}; remediation {esc(finding['remediation'])}</p>"]
        for eid in finding["evidence_ids"]:
            e = evidence.get(eid)
            if not e:
                continue
            out += [f"<p><span class='kind'>{esc(e['kind'])}</span> <code>{esc(e['file'])}:{e['start']}-{e['end']}</code> "
                    f"<span class='meta'>{esc(eid)}</span></p>",
                    f"<pre>{esc(e['quote'])}</pre>",
                    f"<p class='hash'>commit {esc(e['commit'])} · blob {esc(e['blob'])} · sha256 {esc(e['source_sha256'])}</p>"]
        out.append("</div>")
    out.append("<h2>Investigations and verdicts</h2><table><tr><th>Unit</th><th>Target</th><th>Execution</th>"
               "<th>Verdict</th><th>Stop reason</th></tr>")
    for unit in state["investigations"]:
        out.append(f"<tr><td>{esc(unit['id'])}</td><td>{esc(unit['file'])}</td><td>{esc(unit['execution'])}</td>"
                   f"<td>{'UNKNOWN' if stale else esc(unit['verdict'])}</td>"
                   f"<td>{esc(unit.get('stop_reason', unit.get('detail', '')))}</td></tr>")
        for decision in ([] if stale else unit.get("decisions", [])):
            out.append(f"<tr><td></td><td colspan='4'>{esc(decision['scenario_id'])}: <b>{esc(decision['verdict'])}</b>"
                       f" — {esc(decision['reason'])}</td></tr>")
    out.append("</table>")
    out.append("<h2>Action history</h2><table><tr><th>Attempt</th><th>Role</th><th>Execution</th>"
               "<th>Cost USD</th><th>Started</th></tr>")
    for a in state.get("attempts", []):
        out.append(f"<tr><td>{esc(a['id'])}</td><td>{esc(a.get('role',''))}</td><td>{esc(a.get('execution',''))}</td>"
                   f"<td>{esc(a.get('cost_usd'))}</td><td>{esc(a.get('started_at',''))}</td></tr>")
    out.append("</table>")
    out.append("<h2>Coverage gaps</h2>")
    out.append("<ul class='gaps'>" + "".join(f"<li>{esc(g)}</li>" for g in gaps) + "</ul>" if gaps
               else "<p class='meta'>None recorded.</p>")
    out += ["<p class='meta'>Raw requests/responses and frozen sources stay in the run directory "
            "(<code>attempts/</code>, <code>snapshots/</code>); this file is a view over <code>state.json</code>. "
            "Verify integrity with the signed delivery bundle (security-agent sign / verify).</p>",
            "</body></html>"]
    path = root / "review.html"
    path.write_text("".join(out), encoding="utf-8")
    return path
