import unittest
from security_agent.validation.baseline_host import BaselinePolicy

class BaselinePolicyTests(unittest.TestCase):
    def setUp(self):self.policy=BaselinePolicy('/tmp/baseline/repo','/tmp/reference/skills/review')
    def test_package_and_sources_read_only(self):
        self.assertTrue(self.policy.allows('Read',{'file_path':'/tmp/reference/skills/review/SKILL.md'}))
        self.assertFalse(self.policy.allows('Write',{'file_path':'/tmp/reference/skills/review/SKILL.md'}))
        self.assertFalse(self.policy.allows('Write',{'file_path':'main.cpp'}))
        self.assertTrue(self.policy.allows('Write',{'file_path':'.review/sessions/test/session.json'}))
    def test_shell_injection_and_external_git_denied(self):
        for command in ['git -C /tmp/baseline/repo status; touch /tmp/evil','git -C /tmp/baseline/repo -c alias.x=evil x',
                        'git -C /tmp/baseline/repo diff --ext-diff','git -C /tmp/baseline/repo worktree add --detach /tmp/else HEAD',
                        'mkdir -p .review/../../else','python -c evil','date $(touch /tmp/evil)']:
            self.assertFalse(self.policy.allows('Bash',{'command':command}),command)
    def test_atomic_probe_commands(self):
        for command in ['git -C /tmp/baseline/repo status --porcelain','git -C /tmp/baseline/repo worktree add --detach .review/cache/test HEAD',
                        'mkdir -p .review/sessions/test','date -u +%Y-%m-%dT%H:%M:%SZ',
                        'git --version','git -C /tmp/baseline/repo rev-parse --absolute-git-dir',
                        'git -C /tmp/baseline/repo worktree list','ls -la /tmp/reference/skills/review/schemas',
                        'find /tmp/baseline/repo/.review -name plan.json']:
            self.assertTrue(self.policy.allows('Bash',{'command':command}),command)
    def test_widened_reads_stay_read_only_and_scoped(self):
        self.assertTrue(self.policy.allows('Read',{'file_path':'/tmp/reference/agents/review-worker.md'}))
        self.assertTrue(self.policy.allows('Glob',{'pattern':'skills/review/**/*.md','path':'/tmp/reference'}))
        self.assertFalse(self.policy.allows('Read',{'file_path':'/etc/passwd'}))
        self.assertFalse(self.policy.allows('Write',{'file_path':'/tmp/reference/agents/review-worker.md'}))
        self.assertFalse(self.policy.allows('Bash',{'command':'ls -la /etc'}))
        self.assertFalse(self.policy.allows('Bash',{'command':'find /tmp/baseline/repo -name x -delete'}))
        self.assertFalse(self.policy.allows('Bash',{'command':'find /tmp/baseline/repo -exec rm {} ;'}))
    def test_glob_cannot_escape_read_roots(self):
        for pattern in ['/etc/**','../../**']:
            self.assertFalse(self.policy.allows('Glob',{'pattern':pattern}))
        self.assertTrue(self.policy.allows('Glob',{'pattern':'/tmp/baseline/repo/**/*.cpp'}))

from security_agent.validation.baseline_host import StageScope, stage_of

class StageScopeTests(unittest.TestCase):
    def setUp(self):self.scope=StageScope('/tmp/reference/skills/review')
    def delegate(self,stage,agent):
        self.scope.observe({'hook_event_name':'PreToolUse','tool_name':'Agent',
            'tool_input':{'prompt':f'You are the isolated worker for stage {stage}, not the Main orchestrator.'}})
        self.scope.observe({'hook_event_name':'SubagentStart','agent_id':agent})
    def read(self,agent,path):
        return self.scope.observe({'hook_event_name':'PreToolUse','tool_name':'Read',
            'agent_id':agent,'tool_input':{'file_path':path}})
    def test_stage_parsed_only_when_unambiguous(self):
        self.assertEqual(stage_of('worker for stage pre-process'),'pre-process')
        self.assertIsNone(stage_of('run pre-process then preload'))
        self.assertIsNone(stage_of(''))
    def test_cross_stage_read_denied_own_stage_allowed(self):
        self.delegate('preload','w1')
        self.assertIsNone(self.read('w1','/tmp/reference/skills/review/skills/pipeline/preload/SKILL.md'))
        violation=self.read('w1','/tmp/reference/skills/review/skills/pipeline/dispatch/SKILL.md')
        self.assertIn('preload',violation)
        self.assertIn('dispatch',violation)
        self.assertIsNone(self.read('w1','/tmp/reference/skills/review/references/stage-agent.md'))
    def test_unknown_worker_stage_fails_open(self):
        self.scope.observe({'hook_event_name':'PreToolUse','tool_name':'Agent','tool_input':{'prompt':'do the review'}})
        self.scope.observe({'hook_event_name':'SubagentStart','agent_id':'w2'})
        self.assertIsNone(self.read('w2','/tmp/reference/skills/review/skills/pipeline/dispatch/SKILL.md'))

class StageScopeAttributionTests(unittest.TestCase):
    def test_explicit_patterns_beat_ambiguous_text(self):
        prompt=('You are the isolated worker for stage preload. The pre-process handoff says: '
                'recommended_next: preload. Do not read dispatch or review-execute instructions.')
        self.assertEqual(stage_of(prompt),'preload')
        self.assertEqual(stage_of('Stage 3 dispatch worker'),'dispatch')
        self.assertEqual(stage_of('execute review/review-execute stage now'),'review-execute')
    def test_first_stage_read_self_attributes_then_denies_others(self):
        scope=StageScope('/tmp/reference/skills/review')
        scope.observe({'hook_event_name':'PreToolUse','tool_name':'Agent','tool_input':{'prompt':'handoff from pre-process: continue with preload','description':'review worker'}})
        scope.observe({'hook_event_name':'SubagentStart','agent_id':'w1'})
        def read(path):
            return scope.observe({'hook_event_name':'PreToolUse','tool_name':'Read','agent_id':'w1','tool_input':{'file_path':path}})
        base='/tmp/reference/skills/review/skills/pipeline'
        self.assertIsNone(read(f'{base}/preload/SKILL.md'))
        self.assertIsNotNone(read(f'{base}/pre-process/SKILL.md'))
        self.assertIsNotNone(read(f'{base}/dispatch/SKILL.md'))
        self.assertIsNone(read(f'{base}/preload/SKILL.md'))
