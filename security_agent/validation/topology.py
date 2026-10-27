"""Audit host hook receipts, never stage handoffs, for baseline execution topology.

Input is the ordered, unmodified SDK hook input stream captured by the evaluation
host. This checks topology only: it cannot authenticate a fabricated trace or prove
semantic correctness. A verified trace must still be bound to the host run receipt.
"""
import shlex
from pathlib import Path

STAGES = ('pre-process', 'preload', 'dispatch', 'review-execute', 'post-process')


def main_read_scope(tool, args, cwd, package):
    """True when a Main read-like call only loads orchestration metadata from the
    Skill package. Shell operators, writes and any access outside the package are
    stage work, not scheduling metadata."""
    if tool in ('Grep', 'Glob'):
        target = args.get('path') or args.get('file_path')
        if not target and tool == 'Glob':
            pattern = args.get('pattern', '')
            target = pattern.split('*', 1)[0].split('?', 1)[0].split('[', 1)[0]
        if not target:
            return False
        p = Path(target)
        p = p if p.is_absolute() else Path(cwd) / p
        return p.resolve().is_relative_to(package)
    if tool != 'Bash':
        return False
    command = args.get('command', '')
    if any(c in command for c in '\n;&|><`$()'):
        return False
    try:
        words = shlex.split(command)
    except ValueError:
        return False
    if not words or words[0] not in ('ls', 'find', 'sha256sum'):
        return False
    if words[0] == 'find' and any(w in ('-exec', '-execdir', '-ok', '-okdir', '-delete') for w in words):
        return False
    paths = [w for w in words[1:] if not w.startswith('-')]
    if not paths:
        return True
    resolved = []
    for w in paths:
        p = Path(w)
        resolved.append(p if p.is_absolute() else Path(cwd) / p)
    return all(p.resolve().is_relative_to(package) for p in resolved)


def audit_topology(events, package):
    package = Path(package).resolve()
    expected = {str(package / 'skills' / 'pipeline' / stage / 'SKILL.md'): stage for stage in STAGES}
    errors, workers, completed, seen_ids = [], [], [], set()
    active = None
    pending = None
    awaiting_return = None
    for index, event in enumerate(events):
        kind = event.get('hook_event_name')
        tool = event.get('tool_name')
        args = event.get('tool_input', {})
        if kind == 'PreToolUse' and not event.get('agent_id') and tool in ('Bash','Grep','Glob','Write','Edit'):
            if not main_read_scope(tool, args, event.get('cwd', '.'), package):
                errors.append(f'{index}: Main performed stage work with {tool}')
        if kind == 'PreToolUse' and tool in ('Agent', 'Task'):
            if active is not None or pending is not None or awaiting_return is not None:
                errors.append(f'{index}: overlapping or nested delegation')
            if args.get('subagent_type') != 'review-worker':
                errors.append(f'{index}: unregistered worker type')
            if args.get('resume') or args.get('run_in_background'):
                errors.append(f'{index}: resumed or background worker')
            call_id = event.get('tool_use_id')
            if not call_id or call_id in seen_ids:
                errors.append(f'{index}: missing or reused invocation handle')
            seen_ids.add(call_id)
            pending = call_id
        elif kind == 'SubagentStart':
            agent_id = event.get('agent_id')
            if pending is None or active is not None or not agent_id or any(w['agent_id'] == agent_id for w in workers):
                errors.append(f'{index}: worker start lacks a fresh sequential delegation')
            if event.get('agent_type') != 'review-worker':
                errors.append(f'{index}: wrong native agent type')
            active = {'agent_id': agent_id, 'call_id': pending, 'stages_read': [], 'start_event': index}
            workers.append(active)
            pending = None
        elif kind == 'PostToolUse' and tool == 'Read':
            path = str(Path(args.get('file_path', '')).resolve())
            if path in expected:
                if active is None or event.get('agent_id') != active['agent_id']:
                    errors.append(f'{index}: stage instructions read outside owning worker')
                else:
                    stage = expected[path]
                    if stage not in active['stages_read']:
                        active['stages_read'].append(stage)
        elif kind == 'SubagentStop':
            if active is None or event.get('agent_id') != active['agent_id']:
                errors.append(f'{index}: unmatched worker stop')
            else:
                active['stop_event'] = index
                awaiting_return = active
                active = None
        elif kind in ('PostToolUse', 'PostToolUseFailure') and tool in ('Agent', 'Task'):
            if kind == 'PostToolUseFailure':
                errors.append(f'{index}: delegation failed')
            if awaiting_return is None or event.get('tool_use_id') != awaiting_return['call_id']:
                errors.append(f'{index}: missing or mismatched native worker return')
            else:
                awaiting_return['return_event'] = index
                completed.append(awaiting_return)
                awaiting_return = None
    if active is not None or pending is not None or awaiting_return is not None:
        errors.append('unfinished native delegation')
    if [w['stages_read'] for w in completed] != [[stage] for stage in STAGES] or len(workers) != 5:
        errors.append('requires five fresh sequential workers, each reading exactly its owning stage')
    return {'topology_verified': not errors, 'workers': workers, 'errors': errors,
            'scope': 'Native delegation topology only; requires host receipt binding and separate artifact/content validation.'}
