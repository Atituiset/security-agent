"""Security-owned context selection, rule application and bounded evidence tools."""
import json
from .contracts import INVESTIGATION_SCHEMA, JUDGE_SCHEMA
from .executor import Task, SecurityTool
from .source_tools import SourceAccess, numbered, scoped_source
from .skills import load_rule
from .queries import QUERY_SCHEMA
from .query_session import QuerySession


class ContextBudgetExceeded(ValueError):
    pass


def prepare_task(role, payload, config, artifact_dir, query_factory=None):
    rule = load_rule()
    access, tools = None, ()
    max_bytes = config['max_context_bytes']
    tool_limit = config.get('max_tool_calls', 12)
    if role == 'investigator':
        sources, target = payload['sources'], payload['target']
        scope = payload.get('function_scope')
        initial, start = scoped_source(sources[target], scope)
        access = SourceAccess(sources, target, tool_limit, max_bytes, artifact_dir / 'tools.jsonl', scope=scope)
        if access.exhausted:
            raise ContextBudgetExceeded('target exceeds source context budget')
        tools = (
            SecurityTool('read_source', 'Read frozen C/C++ source, optionally an inclusive line range',
                         {'type': 'object', 'properties': {'file': {'type': 'string'},
                          'start': {'type': 'integer', 'minimum': 1}, 'end': {'type': 'integer', 'minimum': 1}},
                          'required': ['file'], 'additionalProperties': False},
                         lambda args: access.read(args['file'], args.get('start', 1), args.get('end'))),
            SecurityTool('search_source', 'Search frozen C/C++ sources for a literal string',
                         {'type': 'object', 'properties': {'text': {'type': 'string'}},
                          'required': ['text'], 'additionalProperties': False},
                         lambda args: access.search(args['text'])),
        )
        if query_factory is not None:
            queries = query_factory(sources, access, artifact_dir / 'queries')
            queries = QuerySession(queries, access, artifact_dir, payload.get('query_history', []))
            tools += tuple(SecurityTool(op, 'Query source facts with provenance: ' + op, QUERY_SCHEMA,
                                        lambda args, op=op: queries.execute(op, args))
                           for op in rule['operations'])
        payload = {k: v for k, v in payload.items() if k != 'sources'}
        payload.update(target_source=numbered(initial, start),
                       source_index={p: len(s.encode()) for p, s in sources.items()},
                       budget={'tool_calls': tool_limit, 'source_bytes': max_bytes})
        # Count retained hypothesis/evidence context as well as initial source.
        packet_bytes = len(json.dumps(payload, ensure_ascii=False).encode())
        access.bytes = max(access.bytes, packet_bytes)
        if access.bytes > max_bytes:
            raise ContextBudgetExceeded("investigation packet exceeds context budget")
    elif role == 'judge':
        if len(json.dumps(payload, ensure_ascii=False).encode()) > max_bytes:
            raise ContextBudgetExceeded('Judge evidence packet exceeds context budget')
    else:
        raise ValueError('unknown security role')
    task = Task(role, payload, INVESTIGATION_SCHEMA if role == 'investigator' else JUDGE_SCHEMA,
                config['timeout'], config['call_usd'], config['model'],
                rule['prompts']['system'] + '\n' + rule['prompts'][role], tools,
                tool_limit + 2 if role == 'investigator' else 4)
    return task, access
