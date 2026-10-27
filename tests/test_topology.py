import unittest
from security_agent.validation.topology import STAGES, audit_topology


class TopologyTests(unittest.TestCase):
    def trace(self):
        result=[]
        for n,stage in enumerate(STAGES):
            call={'tool_name':'Agent','tool_input':{'subagent_type':'review-worker'},'tool_use_id':f't{n}'}
            worker={'agent_id':f'a{n}','agent_type':'review-worker'}
            result.extend([
                dict(call,hook_event_name='PreToolUse'),
                dict(worker,hook_event_name='SubagentStart'),
                dict(worker,hook_event_name='PostToolUse',tool_name='Read',tool_input={'file_path':f'/package/skills/pipeline/{stage}/SKILL.md'}),
                dict(worker,hook_event_name='SubagentStop'),
                dict(call,hook_event_name='PostToolUse'),
            ])
        return result
    def test_five_sequential_native_workers(self):
        self.assertTrue(audit_topology(self.trace(),'/package')['topology_verified'])
    def test_handoff_claims_do_not_prove_delegation(self):
        self.assertFalse(audit_topology([{'stage':s,'execution':{'role':'stage-subagent'}} for s in STAGES],'/package')['topology_verified'])
    def test_missing_return_and_wrong_handle_rejected(self):
        for mutation in ('missing','wrong'):
            events=self.trace()
            if mutation=='missing':events.pop(4)
            else:events[4]['tool_use_id']='other'
            self.assertFalse(audit_topology(events,'/package')['topology_verified'])
    def test_reused_context_or_wrong_stage_rejected(self):
        events=self.trace();events[5]['tool_input']['resume']='a0'
        self.assertFalse(audit_topology(events,'/package')['topology_verified'])
        events=self.trace();events[7]['tool_input']['file_path']='/package/skills/pipeline/pre-process/SKILL.md'
        self.assertFalse(audit_topology(events,'/package')['topology_verified'])
    def test_main_read_or_incomplete_trace_rejected(self):
        events=self.trace();events[2].pop('agent_id')
        self.assertFalse(audit_topology(events,'/package')['topology_verified'])
        self.assertFalse(audit_topology(self.trace()[:-1],'/package')['topology_verified'])
    def test_main_may_glob_package_but_not_target(self):
        events=self.trace()
        events.insert(0,{'hook_event_name':'PreToolUse','tool_name':'Glob',
                         'tool_input':{'pattern':'/package/skills/review/**/*.md'}})
        self.assertTrue(audit_topology(events,'/package')['topology_verified'])
        for target in ({'pattern':'src/**/*.cpp'},{'pattern':'/package/**/*.md','path':'/repo'}):
            events=self.trace()
            events.insert(0,{'hook_event_name':'PreToolUse','tool_name':'Glob','tool_input':target,'cwd':'/repo'})
            self.assertFalse(audit_topology(events,'/package')['topology_verified'],target)
        events=self.trace()
        events.insert(0,{'hook_event_name':'PreToolUse','tool_name':'Bash','tool_input':{'command':'sha256sum /package/SKILL.md'}})
        self.assertTrue(audit_topology(events,'/package')['topology_verified'])
        events=self.trace()
        events.insert(0,{'hook_event_name':'PreToolUse','tool_name':'Bash','tool_input':{'command':'ls /package/skills'}})
        self.assertTrue(audit_topology(events,'/package')['topology_verified'])
        for command in ('ls /package && ls /repo','git -C /repo status','find /package -name x -delete','cat /package/SKILL.md'):
            events=self.trace()
            events.insert(0,{'hook_event_name':'PreToolUse','tool_name':'Bash','tool_input':{'command':command}})
            self.assertFalse(audit_topology(events,'/package')['topology_verified'],command)
