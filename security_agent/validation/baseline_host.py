"""Validation-only native Skill host; the model, not Python, schedules stages."""
import json
import re
import shlex
from pathlib import Path
from dataclasses import asdict
from security_agent.core.storage import atomic_json, digest
from security_agent.infra.claude import provider_env
from security_agent.validation.topology import STAGES, audit_topology, main_read_scope


def stage_of(text):
    text = text or ''
    for pattern in (r'isolated worker for stage ([a-z-]+)', r'[Ss]tage \d+ ([a-z-]+) worker',
                    r'review/([a-z-]+) stage'):
        match = re.search(pattern, text)
        if match and match.group(1) in STAGES:
            return match.group(1)
    found = [s for s in STAGES if re.search(r'(?<![a-z-])' + re.escape(s) + r'(?![a-z-])', text)]
    return found[0] if len(found) == 1 else None


class StageScope:
    """Track which stage each native worker owns; deny reads of other stages' SKILL.md.

    Mirrors the Runtime's programmatic contract enforcement so the paired comparison
    measures accuracy, not prompt-following luck. Every denial is recorded in the receipt.
    Fail-open: an unparsable delegation prompt enforces nothing."""

    def __init__(self, package):
        self.package = Path(package).resolve()
        self.pending = None
        self.workers = {}

    def observe(self, event):
        kind = event.get('hook_event_name')
        if kind == 'PreToolUse' and event.get('tool_name') in ('Agent', 'Task'):
            args = event.get('tool_input', {})
            self.pending = stage_of(str(args.get('prompt', '')) + ' ' + str(args.get('description', '')))
        elif kind == 'SubagentStart':
            self.workers[event.get('agent_id')] = self.pending
            self.pending = None
        elif kind == 'PreToolUse' and event.get('tool_name') == 'Read':
            agent = event.get('agent_id')
            if agent not in self.workers:
                return None
            path = Path(event.get('tool_input', {}).get('file_path', ''))
            owner = next((s for s in STAGES if path.resolve() == (self.package / 'skills' / 'pipeline' / s / 'SKILL.md')), None)
            if owner is None:
                return None
            stage = self.workers[agent]
            if stage is None:
                # Bootstrap reads the owning stage first (stage-agent/1); self-attribute on first read.
                self.workers[agent] = owner
                return None
            if owner != stage:
                return f'worker owns stage {stage}; {owner} instructions are out of scope'
        return None


class BaselinePolicy:
    """Deliberately bounded probe policy. Denials are harness limitations, not misses."""
    def __init__(self, repo, package):
        self.repo, self.package = Path(repo).resolve(), Path(package).resolve()
        # Read roots include the whole Skill repository (agents/, schemas/, examples);
        # writes stay limited to the probe repository's own session area.
        self.read_roots = (self.repo, self.package.parent.parent)

    def inside(self, value, roots):
        p = Path(value)
        p = (self.repo / p).resolve() if not p.is_absolute() else p.resolve()
        return any(p.is_relative_to(root) for root in roots)

    def allows(self, name, args):
        if name in ('Agent', 'Task'):
            return args.get('subagent_type') == 'review-worker' and not args.get('resume') and not args.get('run_in_background')
        if name in ('Read', 'Glob', 'Grep'):
            if name=='Glob':
                pattern=args.get('pattern','')
                if '..' in Path(pattern).parts:return False
                if Path(pattern).is_absolute():
                    prefix=pattern.split('*',1)[0].split('?',1)[0].split('[',1)[0]
                    if not self.inside(prefix,self.read_roots):return False
            return self.inside(args.get('file_path', args.get('path', str(self.repo))), self.read_roots)
        if name in ('Write','Edit'):
            value=args.get('file_path','')
            p=Path(value);p=(self.repo/p).resolve() if not p.is_absolute() else p.resolve()
            return bool(value) and (p.is_relative_to(self.repo/'.review') or p in (self.repo/'.gitignore',self.repo/'codegraph.json'))
        if name != 'Bash': return False
        command=args.get('command','')
        if any(c in command for c in '\n;&|><`$()'): return False
        try: words=shlex.split(command)
        except ValueError: return False
        if not words:return False
        if words[0]=='date':return all(w in ('-u','+%Y-%m-%dT%H:%M:%SZ','+%s','--iso-8601=seconds') for w in words[1:])
        if words[0]=='ls':
            return all(w.startswith('-') or self.inside(w,self.read_roots) for w in words[1:])
        if words[0]=='find':
            forbidden=('-exec','-execdir','-ok','-okdir','-delete')
            paths=[w for w in words[1:] if not w.startswith('-')]
            return bool(paths) and not any(w in forbidden for w in words) and all(self.inside(p,self.read_roots) for p in paths)
        if words[:2]==['git','--version']:return len(words)==2
        if words[0] in ('mkdir','rmdir'):
            paths=[w for w in words[1:] if w!='-p']
            return bool(paths) and all(not p.startswith('-') and self.inside(p,[self.repo/'.review']) for p in paths)
        if words[0]=='sha256sum':
            return len(words)>1 and all(not p.startswith('-') and self.inside(p,[self.repo,self.package]) for p in words[1:])
        # Never allow git configuration, aliases, external diff, or arbitrary global options.
        if len(words)<4 or words[:2]!=['git','-C'] or not self.inside(words[2],[self.repo]):return False
        command=words[3];rest=words[4:]
        if command=='rev-parse':return bool(rest) and all(v=='HEAD' or v.startswith('--')
                    or (len(v)==40 and all(c in '0123456789abcdef' for c in v)) for v in rest)
        if command=='status':return all(v in ('--short','--porcelain','--porcelain=v1','--untracked-files=all') for v in rest)
        if command=='ls-files':return not rest
        if command=='worktree':
            return (rest in (['list'],['list','--porcelain']) or (len(rest)==4 and rest[:2]==['add','--detach']
                    and self.inside(rest[2],[self.repo/'.review']) and (rest[3]=='HEAD' or (len(rest[3])==40 and all(c in '0123456789abcdef' for c in rest[3])))))
        return False


async def run_baseline(repo, package, output, *, file, function, model, timeout=300, usd=2):
    import anyio
    from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, AgentDefinition, HookMatcher, ResultMessage
    repo,package,output=Path(repo).resolve(),Path(package).resolve(),Path(output).resolve()
    output.mkdir(parents=True,exist_ok=False)
    policy=BaselinePolicy(repo,package)
    scope=StageScope(package)
    worker=(package.parent.parent/'agents/review-worker.md').read_text()
    worker=worker.split('---',2)[2].strip()
    hashes={str(p.relative_to(package)):digest(p.read_bytes()) for p in sorted(package.rglob('*')) if p.is_file()}
    request={'repo':str(repo),'package':str(package),'file':file,'function':function,'model':model,
             'timeout':timeout,'usd':usd,'package_hashes':hashes,'worker_sha256':digest(worker.encode()),
             'purpose':'host connectivity probe; not a paired accuracy observation','codegraph':None}
    atomic_json(output/'request.json',request)
    events=[];denials=[];final=None;status='FAILED';detail=''
    with (output/'hooks.jsonl').open('w') as hook_log, (output/'messages.jsonl').open('w') as messages:
        async def hook(event, tool_use_id, context):
            events.append(event)
            hook_log.write(json.dumps(event,ensure_ascii=True)+'\n');hook_log.flush()
            violation=scope.observe(event)
            if violation:
                denials.append({'tool':'Read','input':event['tool_input'],'enforcement':'stage-scope'})
                return {'hookSpecificOutput':{'hookEventName':'PreToolUse','permissionDecision':'deny',
                        'permissionDecisionReason':f'Stage-scope enforcement: {violation}. Read only your own stage instructions and supporting Query/CWE/Workspace skills.'}}
            if (event['hook_event_name']=='PreToolUse' and not event.get('agent_id')
                    and event['tool_name'] in ('Bash','Grep','Glob','Write','Edit')
                    and not main_read_scope(event['tool_name'],event['tool_input'],event.get('cwd',str(repo)),package)):
                denials.append({'tool':event['tool_name'],'input':event['tool_input'],'enforcement':'main-scope'})
                return {'hookSpecificOutput':{'hookEventName':'PreToolUse','permissionDecision':'deny',
                        'permissionDecisionReason':'Main only orchestrates: delegate all target and session work to workers. Read-only package metadata (ls/find/sha256sum inside the Skill package) is allowed.'}}
            if event['hook_event_name']=='PreToolUse' and not policy.allows(event['tool_name'],event['tool_input']):
                denials.append({'tool':event['tool_name'],'input':event['tool_input']})
                return {'hookSpecificOutput':{'hookEventName':'PreToolUse','permissionDecision':'deny',
                        'permissionDecisionReason':'Probe host permits scoped native file reads and atomic read-only Git/date/mkdir/sha256sum/ls/find commands only. No shell scripts/operators. Record any unavailable capability.'}}
            return {}
        options=ClaudeAgentOptions(model=model,cwd=str(repo),env=provider_env(),setting_sources=[],skills=[],plugins=[],
            system_prompt=(package/'SKILL.md').read_text(),
            agents={'review-worker':AgentDefinition(description='Execute exactly one review stage',prompt=worker)},
            tools=['Agent','Read','Write','Edit','Glob','Grep','Bash'],
            allowed_tools=['Agent','Read','Write','Edit','Glob','Grep','Bash'],permission_mode='default',
            hooks={kind:[HookMatcher(hooks=[hook])] for kind in ('PreToolUse','PostToolUse','PostToolUseFailure','SubagentStart','SubagentStop')},
            max_turns=40,max_budget_usd=usd,
            extra_args={'no-session-persistence':None})
        prompt=(f'Execute the review Skill at {package}. Its review-worker is registered natively. '
                f'TARGET: {repo}. Review committed HEAD, file {file}, function {function}, CWE-476 only. '
                'Use source fallback; Codegraph is unavailable in this probe. Keep generated session/cache in TARGET/.review. '
                'Preserve source and the read-only Skill package. Use native file tools and atomic shell commands; '
                'the probe host does not permit shell scripts, compound commands or arbitrary interpreters. '
                'Follow the five-stage native worker protocol. Report actual capability blocks, never fabricate worker outputs.')
        try:
            with anyio.fail_after(timeout):
                async with ClaudeSDKClient(options=options) as client:
                    await client.query(prompt)
                    async for message in client.receive_response():
                        messages.write(json.dumps({'type':type(message).__name__,'message':asdict(message)},ensure_ascii=True)+'\n');messages.flush()
                        if isinstance(message,ResultMessage):final=message
            status='COMPLETED' if final and not final.is_error and final.subtype=='success' else 'FAILED'
        except TimeoutError:status='TIMED_OUT';detail='host wall-clock limit'
        except Exception as exc:detail=f'{type(exc).__name__}: {exc}'
    topology=audit_topology(events,package)
    atomic_json(output/'topology.json',topology)
    receipt={'execution':status,'detail':detail,'denials':denials,
             'stage_scope_denials':sum(1 for d in denials if d.get('enforcement')=='stage-scope'),
             'main_scope_denials':sum(1 for d in denials if d.get('enforcement')=='main-scope'),
             'topology_verified':topology['topology_verified'],
             'cost_usd':final.total_cost_usd if final else None,
             'hooks_sha256':digest((output/'hooks.jsonl').read_bytes()),
             'messages_sha256':digest((output/'messages.jsonl').read_bytes()),
             'request_sha256':digest((output/'request.json').read_bytes())}
    atomic_json(output/'receipt.json',receipt)
    return receipt
