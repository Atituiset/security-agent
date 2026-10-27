"""Deterministic five-stage orchestration, checkpoints, and bounded retries."""
import math
from collections import deque
from dataclasses import replace
from pathlib import Path
from security_agent.core.contracts import Execution, ContractError, validate
from security_agent.core.executor import AgentResult
from security_agent.core.context import prepare_task, ContextBudgetExceeded
from security_agent.inputs.git_input import snapshot, source_view, check_baseline
from security_agent.core.judge import admit, judge_payload, decide
from security_agent.inputs.function_scope import locate
from security_agent.core.source_tools import scoped_source
from security_agent.core.output import export
from security_agent.core.storage import atomic_json, read_json, lock, now, seal, verify
from security_agent.core import runtime

from security_agent.core.skills import load_rule
from . import stages

POLICY_VERSION = "cwe476-v7-runtime"
# Read-only verification (benchmark scoring) may trust earlier versions whose
# semantics the current code still reproduces; resume/run always requires current.
SCORING_POLICIES = ("cwe476-v6-runtime", POLICY_VERSION)
PREPARE_ACTIONS = ("snapshot", "scope", "index", "handoff")


def _validated_config(config):
    for key in ("max_calls", "call_usd", "timeout", "max_context_bytes"):
        if not math.isfinite(config[key]) or config[key] <= 0:
            raise ValueError(f"{key} must be positive and finite")
    config = {"max_rounds": 3, "max_hypotheses": 20, "max_no_progress": 1, "total_timeout": 1800,
              "max_action_attempts": 3, **config}
    if not math.isfinite(config["total_timeout"]) or config["total_timeout"] <= 0:
        raise ValueError("total_timeout must be positive and finite")
    for key in ("max_calls", "max_tool_calls", "max_snapshot_bytes", "max_rounds", "max_hypotheses", "max_no_progress", "max_action_attempts"):
        if key in config and (type(config[key]) is not int or config[key] <= 0):
            raise ValueError(f"{key} must be a positive integer")
    if config.get("investigation_max_calls") is not None and (type(config["investigation_max_calls"]) is not int or config["investigation_max_calls"] <= 0):
        raise ValueError("investigation_max_calls must be a positive integer")
    if config.get("investigation_max_usd") is not None and (not math.isfinite(config["investigation_max_usd"]) or config["investigation_max_usd"] <= 0):
        raise ValueError("investigation_max_usd must be positive and finite")
    return config


def create(repo, base, head, root, config, *, target_paths=None, function=None, line=None, candidates=None, input_provenance=None, prepare_backend=None):
    config = _validated_config(config)
    root = Path(root).resolve()
    if (root / "state.json").exists():
        state = read_json(root / "state.json")
        if state["execution"] != "PREPARING":
            raise ValueError("run directory already prepared; use run() or a new directory")
        if state["policy_version"] != POLICY_VERSION or state["config"] != config:
            raise ValueError("run policy/configuration changed; keep the original arguments")
        refs = state["prepare"]["input_refs"]
        if refs != {"repo": str(Path(repo).resolve()), "base": base, "head": head}:
            raise ValueError("run input revisions changed; create a new run")
        if state["rule"]["sha256"] != load_rule()["sha256"]:
            raise ValueError("security skill changed; create a new run")
        if "baseline" in state:
            check_baseline(root, state)
        return _prepare(root, state, repo, base, head, target_paths=target_paths, function=function,
                        line=line, candidates=candidates, input_provenance=input_provenance,
                        prepare_backend=prepare_backend)
    root.mkdir(parents=True, exist_ok=False)
    for name in ("snapshots", "attempts", "assessments"):
        (root / name).mkdir()
    rule = load_rule()
    state = {"schema_version": 1, "policy_version": POLICY_VERSION, "created_at": now(),
             "config": config, "execution": "PREPARING", "detail": "",
             "stages": ["pre-process", "preload", "dispatch"], "attempts": [], "actions": {},
             "findings": [], "investigations": [],
             "rule": {k: v for k, v in rule.items() if k != "prompts"},
             "prepare": {"input_refs": {"repo": str(Path(repo).resolve()), "base": base, "head": head},
                         "actions": []}}
    save(root, state)
    return _prepare(root, state, repo, base, head, target_paths=target_paths, function=function,
                    line=line, candidates=candidates, input_provenance=input_provenance,
                    prepare_backend=prepare_backend)


def _prepare(root, state, repo, base, head, *, target_paths, function, line, candidates, input_provenance, prepare_backend):
    """Checkpointed preparation: each action is durable before the next starts.

    An interrupted action stays RUNNING (outcome unknown, never a completion mark) and is
    retried on resume; a failed index degrades to source fallback with an explicit gap."""
    actions = {a["kind"]: a for a in state["prepare"]["actions"]}

    def record(kind, execution, detail="", artifacts=()):
        actions[kind] = {"kind": kind, "execution": execution, "detail": detail,
                         "artifacts": list(artifacts), "finished_at": now() if execution != "RUNNING" else None}
        state["prepare"]["actions"] = [actions[k] for k in PREPARE_ACTIONS if k in actions]
        save(root, state)

    if actions.get("snapshot", {}).get("execution") != "COMPLETED":
        record("snapshot", "RUNNING")
        try:
            state["baseline"] = snapshot(repo, base, head, root, state["config"].get("max_snapshot_bytes", 10000000))
        except Exception as exc:
            record("snapshot", "FAILED", f"{type(exc).__name__}: {exc}")
            raise
        record("snapshot", "COMPLETED", artifacts=[seal(root, "diff.patch"), seal(root, "tree.raw")])
    baseline = state["baseline"]
    if actions.get("scope", {}).get("execution") != "COMPLETED":
        record("scope", "RUNNING")
        try:
            if target_paths is None and "targets" not in baseline:
                raise ValueError("prepare resume requires the original --file/--function arguments")
            if target_paths is not None:
                if not target_paths or any(p not in baseline["sources"] for p in target_paths):
                    raise ValueError("explicit target must exist in the frozen C/C++ source view")
                baseline["targets"] = sorted(set(target_paths))
                baseline["scope"] = "commit-only; explicit file scope (not Git diff)"
            if function is not None:
                if target_paths is None or len(target_paths) != 1:
                    raise ValueError("function selection requires exactly one file")
                file = target_paths[0]
                source = (root / baseline["sources"][file]["path"]).read_bytes().decode("utf-8")
                baseline["function"] = locate(source, file, function, line)
                baseline["scope"] = f"commit-only; function {baseline['function']['name']} in {file}"
            if input_provenance is not None:
                atomic_json(root / "input.json", input_provenance)
                baseline["artifacts"].append(seal(root, "input.json"))
            state["investigations"] = [{"id": f"I{i + 1:04}", "file": path, "cwe": "CWE-476",
                                        "execution": "PENDING", "verdict": "UNKNOWN", "decisions": [],
                                        "detail": "", "phase": "investigator", "round": 1, "rounds": [],
                                        "hypotheses": [], "follow_up": [], "no_progress": 0}
                                       for i, path in enumerate(baseline["targets"])]
            if function is not None:
                state["investigations"][0]["function"] = baseline["function"]
            for unit in state["investigations"]:
                if candidates and unit["file"] in candidates:
                    unit["candidates"] = candidates[unit["file"]]
        except Exception as exc:
            record("scope", "FAILED", f"{type(exc).__name__}: {exc}")
            raise
        record("scope", "COMPLETED")
    index_state = actions.get("index", {}).get("execution")
    if index_state not in ("COMPLETED", "SKIPPED") and (index_state != "FAILED" or prepare_backend is not None):
        record("index", "RUNNING")
        if prepare_backend is None:
            record("index", "SKIPPED", "no index backend configured")
        else:
            try:
                state["query_backend"] = prepare_backend(baseline, root)
            except Exception as exc:
                detail = f"{type(exc).__name__}: {exc}"
                record("index", "FAILED", detail)
            else:
                state["baseline"]["artifacts"].extend(seal(root, str(p.relative_to(root)))
                    for p in sorted((root / "graph").rglob("*")) if p.is_file() and "repository" not in p.relative_to(root / "graph").parts)
                record("index", "COMPLETED", artifacts=[seal(root, str(p.relative_to(root)))
                    for p in sorted((root / "graph").rglob("*")) if p.is_file() and "repository" not in p.relative_to(root / "graph").parts])
    if actions.get("handoff", {}).get("execution") != "COMPLETED":
        record("handoff", "RUNNING")
        try:
            stages.prepare(root, state, source_view(root, baseline), load_rule())
        except Exception as exc:
            record("handoff", "FAILED", f"{type(exc).__name__}: {exc}")
            raise
        record("handoff", "COMPLETED")
    state["execution"] = "PENDING"
    save(root, state)
    # Store the immutable configuration separately so resume cannot silently change policy/baseline.
    atomic_json(root / "manifest.json", {k: state[k] for k in
                                         ("schema_version", "policy_version", "config", "baseline", "rule")})
    export(root, state)
    return root


def save(root, state):
    state["updated_at"] = now()
    atomic_json(root / "state.json", state)


def mark_stale(root, state, detail):
    state["execution"], state["detail"] = "STALE", detail
    save(root, state)
    export(root, state)
    return state


def guard(root, state, policies=(POLICY_VERSION,)):
    manifest = read_json(root / "manifest.json")
    if any(state[k] != manifest[k] for k in manifest) or state["policy_version"] not in policies:
        raise ValueError("run policy/configuration/baseline changed")
    if state["rule"]["sha256"] != load_rule()["sha256"]:
        raise ValueError("security skill changed; create a new run")
    check_baseline(root, state)
    derived_findings = {}
    for unit in state['investigations']:
        if unit.get('function') != state['baseline'].get('function'):
            raise ValueError('investigation function scope changed')
        assessment, decisions, hypotheses, findings = runtime.project(root, unit)
        if unit.get('rounds'):
            if assessment != unit.get('assessment') or decisions != unit['decisions'] or hypotheses != unit['hypotheses']:
                raise ValueError('checkpoint projection differs from versioned evidence/decisions')
        for f in findings:
            derived_findings.setdefault(f['fingerprint'], f)
    if list(derived_findings.values()) != state['findings']:
        raise ValueError('checkpoint findings differ from verified Judge decisions')


def invoke(root, state, unit, role, payload, executor, query_factory=None):
    config = state['config']
    guard(root, state)
    action_id = f"{unit['id']}-R{unit['round']}-{role}"
    input_hash = runtime.fingerprint(payload)
    action = state['actions'].get(action_id)
    if action and action['input_hash'] != input_hash:
        raise ValueError('action inputs changed without a new round')
    prior = [a for a in state['attempts'] if a.get('action_id') == action_id]
    if prior and prior[-1]['execution'] == 'COMPLETED':
        unit['execution'], unit['detail'] = 'COMPLETED', ''
        return read_json(root / 'attempts' / prior[-1]['id'] / 'result.json'), prior[-1]['id']
    if len(prior) >= config['max_action_attempts']:
        unit.update(execution='BUDGET_EXHAUSTED', detail=f'action {action_id} retry budget exhausted')
        return None
    unit_priors = [a for a in state['attempts'] if a.get('investigation_id') == unit['id']]
    if config.get('investigation_max_calls') is not None and len(unit_priors) >= config['investigation_max_calls']:
        unit.update(execution='BUDGET_EXHAUSTED', detail='investigation call budget exhausted')
        return None
    if config.get('investigation_max_usd') is not None:
        reserved = sum(a.get('reserved_usd') or 0 for a in unit_priors)
        if reserved + config['call_usd'] > config['investigation_max_usd']:
            unit.update(execution='BUDGET_EXHAUSTED', detail='investigation cost reservation budget exhausted')
            return None
    if len(state['attempts']) >= config['max_calls']:
        unit.update(execution='BUDGET_EXHAUSTED', detail='run call budget exhausted')
        return None
    if runtime.remaining(state) <= 0:
        unit.update(execution='TIMED_OUT', detail='run deadline expired')
        return None
    aid = f"A{len(state['attempts']) + 1:05}"
    directory = root / 'attempts' / aid
    directory.mkdir()
    action = state['actions'].setdefault(action_id, {
        'id': action_id, 'investigation_id': unit['id'], 'round': unit['round'],
        'kind': 'INVESTIGATE' if role == 'investigator' else 'REQUEST_JUDGE',
        'input_hash': input_hash, 'evidence_version': unit['round'], 'attempts': [],
        'backend': (config.get('judge_backend') or config.get('backend', 'claude')) if role == 'judge' else config.get('backend', 'claude'),
        'model': (config.get('judge_model') or config['model']) if role == 'judge' else config['model']})
    action['attempts'].append(aid); action['execution'] = 'RUNNING'
    atomic_json(directory / 'action.json', {k: v for k, v in action.items() if k not in ('attempts', 'execution')})
    attempt = {'id': aid, 'action_id': action_id, 'input_hash': input_hash,
               'investigation_id': unit['id'], 'round': unit['round'], 'role': role,
               'execution': 'RUNNING', 'started_at': now(), 'reserved_usd': config['call_usd']}
    state['attempts'].append(attempt)
    unit['execution'] = state['execution'] = 'RUNNING'
    save(root, state)
    try:
        task, access = prepare_task(role, payload, config, directory, query_factory)
        task = replace(task, timeout=min(task.timeout, max(0.001, runtime.remaining(state))))
        result = executor.execute(task, directory)
        if result.output is not None:
            atomic_json(directory / 'response.json', result.output)
        if runtime.remaining(state) <= 0:
            result = AgentResult(Execution.TIMED_OUT, None, 'run deadline expired', result.cost_usd)
        elif access is not None and access.exhausted:
            result = AgentResult(Execution.BUDGET_EXHAUSTED, None, 'source tool budget exhausted', result.cost_usd)
        elif result.output is not None:
            validate(result.output, task.schema)
    except ContractError as exc:
        result = AgentResult(Execution.FAILED, None, f'contract rejected: {exc}')
    except ContextBudgetExceeded as exc:
        result = AgentResult(Execution.BUDGET_EXHAUSTED, None, str(exc))
    except KeyboardInterrupt:
        result = AgentResult(Execution.INTERRUPTED, None, 'interrupted')
    except RuntimeError as exc:
        result = AgentResult(Execution.FAILED, None, str(exc))
    receipt = {'action_id': action_id, 'input_hash': input_hash, 'execution': result.execution,
               'detail': result.detail, 'cost_usd': result.cost_usd, 'finished_at': now()}
    if result.output is not None and result.execution == Execution.COMPLETED:
        atomic_json(directory / 'result.json', result.output)
        receipt['result_artifact'] = seal(root, str((directory / 'result.json').relative_to(root)))
    elif result.execution == Execution.COMPLETED:
        receipt.update(execution='FAILED', detail='completed execution did not return output')
    # Durable receipt precedes checkpoint projection, enabling recovery without another call.
    atomic_json(directory / 'outcome.json', receipt)
    finish_attempt(root, state, unit, attempt, receipt)
    save(root, state)
    if attempt['execution'] != 'COMPLETED':
        return None
    return read_json(directory / 'result.json'), aid


def finish_attempt(root, state, unit, attempt, receipt):
    if receipt['action_id'] != attempt['action_id'] or receipt['input_hash'] != attempt['input_hash']:
        raise ValueError('outcome receipt belongs to different action inputs')
    if receipt['execution'] == 'COMPLETED':
        verify(root, receipt['result_artifact'])
    attempt.update({k: receipt[k] for k in ('execution', 'detail', 'cost_usd', 'finished_at')})
    directory = root / 'attempts' / attempt['id']
    attempt['artifacts'] = [seal(root, str(p.relative_to(root))) for p in sorted(directory.rglob('*')) if p.is_file()]
    state['actions'][attempt['action_id']]['execution'] = attempt['execution']
    unit.update(execution=attempt['execution'], detail=attempt['detail'])


def recover(root, state):
    for attempt in state['attempts']:
        if attempt['execution'] != 'RUNNING':
            continue
        directory = root / 'attempts' / attempt['id']
        receipt_path = directory / 'outcome.json'
        if receipt_path.exists() and attempt.get('action_id'):
            unit = next(u for u in state['investigations'] if u['id'] == attempt['investigation_id'])
            finish_attempt(root, state, unit, attempt, read_json(receipt_path))
        else:
            attempt.update(execution='INTERRUPTED', detail='previous writer stopped before durable outcome', finished_at=now())
            attempt['artifacts'] = [seal(root, str(p.relative_to(root))) for p in directory.rglob('*') if p.is_file()]
            if attempt.get('action_id'):
                state['actions'][attempt['action_id']]['execution'] = 'INTERRUPTED'
    for unit in state['investigations']:
        if unit['execution'] == 'RUNNING':
            unit['execution'] = 'INTERRUPTED'
    save(root, state)


def query_history(root, state, unit):
    history = []
    for attempt in state['attempts']:
        if attempt.get('investigation_id') != unit['id'] or attempt.get('round', 0) >= unit['round']:
            continue
        for p in sorted((root / 'attempts' / attempt['id'] / 'queries').glob('*/request.json')):
            request = read_json(p)
            history.append({'request': request, 'result_ref': str(p.with_name('delivered.json').relative_to(root))})
    return history[-40:]


def take_assessment(root, state, unit, output, aid):
    if len(output.get('scenarios', [])) > state['config']['max_hypotheses']:
        raise ContractError('hypothesis count exceeds configured limit')
    follow_ids = {r['scenario_id'] for r in unit['follow_up']}
    scoped_unit = {**unit, 'candidates': [c for c in unit.get('candidates', []) if not follow_ids or c['id'] in follow_ids]}
    assessment = admit(scoped_unit, output, source_view(root, state['baseline']), state['baseline'], aid)
    if follow_ids:
        if {s['id'] for s in assessment['scenarios']} != follow_ids:
            raise ContractError('follow-up must preserve exactly the requested hypotheses')
        prior = {s['id']: s for s in unit['assessment']['scenarios']}
        if any(s['sink_line'] != prior[s['id']]['sink_line'] for s in assessment['scenarios']):
            raise ContractError('follow-up changed hypothesis sink identity')
    query_records = [p for a in state['attempts'] if a.get('investigation_id') == unit['id']
                     for p in sorted((root / 'attempts' / a['id'] / 'queries').glob('*/delivered.json'))]
    for evidence in assessment['evidence']:
        evidence['query_refs'] = []
        for p in query_records:
            record = read_json(p)
            for fact in record['facts']:
                loc = fact['location']
                if loc['path'] == evidence['file'] and loc['start_line'] <= evidence['start'] <= evidence['end'] <= loc['end_line']:
                    evidence['query_refs'].append({'query': str(p.relative_to(root)), 'fact_id': fact['id'], 'precision': fact['precision']})
    rel = f"assessments/{unit['id']}-R{unit['round']}-{aid}.json"
    atomic_json(root / rel, assessment)
    turn = {'number': unit['round'], 'assessment_artifact': seal(root, rel), 'accepted': True}
    if follow_ids:
        prior = {**unit['assessment'], 'evidence': [e for e in unit['assessment']['evidence']
                 if e['id'] in {eid for s in unit['assessment']['scenarios'] if s['id'] in follow_ids for eid in s['evidence_ids']}]}
        if runtime.evidence_signature(prior) == runtime.evidence_signature(assessment):
            turn['accepted'] = False
            unit['no_progress'] += 1
        else:
            unit['no_progress'] = 0
    unit['rounds'].append(turn)
    runtime.refresh(root, state, unit)
    if not turn['accepted']:
        if unit['no_progress'] >= state['config']['max_no_progress'] or unit['round'] >= state['config']['max_rounds']:
            runtime.stop(unit, 'no new evidence; repeated judgment suppressed')
        else:
            unit['round'] += 1
            unit.update(phase='investigator', execution='PENDING')
    else:
        unit.update(phase='judge', execution='PENDING', assessment_artifact=turn['assessment_artifact'])
    save(root, state)


def advance(root, state, unit, sources, executor, query_factory):
    if unit['phase'] == 'investigator':
        if len(scoped_source(sources[unit['file']], unit.get('function'))[0].encode()) > state['config']['max_context_bytes']:
            unit.update(execution='BUDGET_EXHAUSTED', detail='target exceeds source context budget')
            return
        payload = {'target': unit['file'], 'cwe': unit['cwe'], 'candidates': unit.get('candidates', []),
                   'function_scope': unit.get('function'), 'sources': sources, 'commit': state['baseline']['head']}
        if unit['round'] > 1:
            active = {r['scenario_id'] for r in unit['follow_up']}
            payload.update(follow_up=unit['follow_up'], prior_assessment=unit['assessment'],
                           query_history=query_history(root, state, unit))
            payload['candidates'] = [{'id': s['id'], 'start': s['sink_line'], 'end': s['sink_line']}
                                     for s in unit['assessment']['scenarios'] if s['id'] in active]
        result = invoke(root, state, unit, 'investigator', payload, executor, query_factory)
        if result is None:
            return
        take_assessment(root, state, unit, *result)
        if unit['phase'] != 'judge':
            return
    turn = unit['rounds'][-1]
    assessment = read_json(root / turn['assessment_artifact']['path'])
    packet = judge_payload(unit, assessment, sources)
    packet['evidence_version'] = turn['number']
    result = invoke(root, state, unit, 'judge', packet, executor)
    if result is None:
        return
    decisions, _ = decide(unit, assessment, result[0])
    requests, rejected = runtime.followups(decisions, sources)
    turn["rejected_follow_up"] = rejected
    unit.setdefault("rejected_follow_up", []).extend(rejected)
    turn['decision_artifact'] = seal(root, f'attempts/{result[1]}/result.json')
    unit['decision_artifact'] = turn['decision_artifact']
    runtime.refresh(root, state, unit)
    unit['follow_up'] = requests
    if not requests:
        runtime.stop(unit, 'no actionable follow-up' if any(d['verdict'] == 'UNKNOWN' for d in decisions) else 'judgment completed')
    elif unit['round'] >= state['config']['max_rounds']:
        runtime.stop(unit, 'investigation round limit reached', 'BUDGET_EXHAUSTED')
    elif len(state['attempts']) >= state['config']['max_calls']:
        runtime.stop(unit, 'run call budget exhausted before follow-up', 'BUDGET_EXHAUSTED')
    else:
        unit['round'] += 1
        unit.update(phase='investigator', execution='PENDING')
    save(root, state)


def run(root, executor, query_factory=None, query_guard=None):
    root = Path(root).resolve()
    with lock(root):
        state = read_json(root / 'state.json')
        if state['execution'] == 'STALE':
            export(root, state)
            return state
        if state['execution'] == 'PREPARING':
            state['detail'] = 'prepare incomplete; re-run create (or CLI resume) to finish preparation'
            return state
        try:
            guard(root, state)
            if query_guard:
                query_guard()
            recover(root, state)
        except (ValueError, OSError) as exc:
            return mark_stale(root, state, str(exc))
        sources = source_view(root, state['baseline'])
        stages.checkpoint(root, state, 'review-execute', 'RUNNING')
        state['stages'] = ['pre-process', 'preload', 'dispatch', 'review-execute']
        if state['baseline']['limitations']:
            for unit in state['investigations']:
                unit.update(execution='BUDGET_EXHAUSTED' if state['baseline']['context_bytes'] >
                            state['config'].get('max_snapshot_bytes', 10000000) else 'FAILED',
                            detail='; '.join(state['baseline']['limitations']))
        else:
            queue = deque(u for u in state['investigations'] if u['phase'] != 'done')
            while queue:
                unit = queue.popleft()
                try:
                    if query_guard:
                        query_guard()
                    advance(root, state, unit, sources, executor, query_factory)
                    if unit['execution'] == 'INTERRUPTED':
                        break
                    # One bounded round per unit before returning it to the queue.
                    if unit['phase'] == 'investigator' and unit['execution'] == 'PENDING':
                        queue.append(unit)
                except ContractError as exc:
                    unit.update(execution='FAILED', detail=f'contract rejected: {exc}')
                    save(root, state)
                except (ValueError, OSError) as exc:
                    return mark_stale(root, state, str(exc))
        try:
            guard(root, state)
            if query_guard:
                query_guard()
        except (ValueError, OSError) as exc:
            return mark_stale(root, state, str(exc))
        statuses = {u['execution'] for u in state['investigations']}
        state['execution'] = next((s for s in ('INTERRUPTED', 'TIMED_OUT', 'FAILED', 'BUDGET_EXHAUSTED') if s in statuses), 'COMPLETED')
        if state['baseline']['limitations'] and not statuses:
            state['execution'] = 'FAILED'
        stages.checkpoint(root, state, 'review-execute', state['execution'])
        stages.checkpoint(root, state, 'post-process', 'RUNNING')
        state['stages'].append('post-process')
        save(root, state)
        export(root, state)
        stages.checkpoint(root, state, 'post-process', 'COMPLETED')
        save(root, state)
        return state
