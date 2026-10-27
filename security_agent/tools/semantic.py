"""Seven fact queries over a pinned graph and frozen source; no security verdicts."""
import json
from pathlib import Path
from security_agent.core.queries import OPERATIONS, QUERY_SCHEMA
from security_agent.core.contracts import validate
from security_agent.core.storage import atomic_json, digest
from .syntax import observe


class SemanticQueries:
    def __init__(self, sources, access, directory, graph=None, timeout=30):
        self.sources, self.access = sources, access
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True)
        self.graph, self.timeout = graph, timeout
        self.sequence = 0
        self.view_sha256 = digest(json.dumps({p: digest(s.encode()) for p, s in sorted(sources.items())}, sort_keys=True).encode())

    def execute(self, operation, request):
        validate(request, QUERY_SCHEMA)
        if operation not in OPERATIONS:
            raise ValueError('unknown semantic operation')
        self.sequence += 1
        qid = f'Q{self.sequence:05}'
        directory = self.directory / qid
        directory.mkdir()
        atomic_json(directory / 'request.json', {'id': qid, 'operation': operation, **request})
        result = {'id': qid, 'operation': operation, 'status': 'partial', 'facts': [],
                  'coverage': {'exhaustive': False, 'truncated': False}, 'errors': [],
                  'dependencies': [], 'raw_refs': [], 'methods': [],
                  'baseline': {'source_view_sha256': self.view_sha256}}
        if self.access.calls >= self.access.max_calls or self.access.exhausted:
            result['status'] = 'error'; result['errors'] = ['query budget exhausted']
            self.access.exhausted = True
            return self._finish(directory, operation, request, result)
        symbol = request.get('symbol', '')
        limit = request.get('limit', 30)
        ranges = []
        if self.graph and symbol and operation in self.graph.capabilities:
            graph = self.graph.query(operation, symbol, limit, directory, self.timeout)
            atomic_json(directory / 'graph.json', graph)
            result['raw_refs'].extend(str(p.relative_to(self.directory.parent)) for p in sorted(directory.glob('graph.*')))
            result['methods'].append({'producer': 'codegraph', 'version': graph.get('version'), 'precision': 'candidate-relation'})
            result['errors'].extend(graph['errors'])
            result['coverage']['truncated'] = graph.get('truncated', False)
            for node in graph['candidates']:
                # Do not silently discard alternative overloads/identities.
                location = node['location']
                path, start = location['path'], location['start_line']
                if path in self.sources and isinstance(start, int):
                    end = location['end_line']
                    ranges.append((path, start, end, 'candidate-relation', node['identity']))
                else:
                    result['errors'].append('graph candidate outside available frozen sources')
        else:
            result['errors'].append('graph unavailable or operation requires source inspection')
        file = request.get('file')
        if 'start' in request and 'end' in request and request['start'] > request['end']:
            result['status'] = 'error'; result['errors'].append('invalid scope range')
            return self._finish(directory, operation, request, result)
        if file is not None and file not in self.sources:
            result['status'] = 'error'; result['errors'].append('file outside frozen source view')
            return self._finish(directory, operation, request, result)
        # Scoped structural queries return the complete requested window for reasoning.
        # No lexical heuristic is advertised as AST or dataflow resolution.
        structural = operation == 'find_assignments' or (operation == 'find_pattern' and request.get('kind') != 'literal')
        if structural or operation == 'find_definition':
            if structural and (not file or 'start' not in request or 'end' not in request):
                result['status'] = 'unsupported'
                result['errors'].append('structural queries require file/start/end')
            else:
                for path, source in self.sources.items():
                    if file and path != file:
                        continue
                    observations, errors = observe(source, path, operation, request)
                    ranges.extend(observations)
                    if errors:
                        result['errors'].append('syntax errors in ' + path)
                result['methods'].append({'producer': 'tree-sitter', 'precision': 'syntax-observation'})
                result['errors'].append('syntax only: no macro expansion, type resolution or dataflow proof')
        # Literal fallback retains alternate identities and only promises text matches.
        if not structural:
            text = request.get('text') if operation == 'find_pattern' else symbol.split('::')[-1]
            if not text:
                result['status'] = 'error'; result['errors'].append('symbol or literal text required')
            else:
                matches = []
                for path, source in self.sources.items():
                    if file and path != file:
                        continue
                    for number, line in enumerate(source.splitlines(), 1):
                        if request.get('start', 1) <= number <= request.get('end', 10**9) and text in line:
                            matches.append((path, number, number, 'text-candidate', {}))
                if len(matches) > limit:
                    result['coverage']['truncated'] = True
                ranges.extend(matches[:limit])
                result['methods'].append({'producer': 'frozen-source', 'precision': 'text-candidate'})
        seen = set()
        for path, start, end, precision, candidate in ranges:
            lines = self.sources[path].splitlines()
            if type(end) is not int or not 1 <= start <= end <= len(lines):
                result['errors'].append('invalid graph/source range'); continue
            key = (path, start, end, precision, candidate.get('id'), candidate.get('name'))
            if key in seen:
                continue
            seen.add(key)
            if len(result['facts']) >= limit:
                result['coverage']['truncated'] = True; break
            fact = {'id': f'F{len(result["facts"])+1:04}', 'location': {'path': path, 'start_line': start, 'end_line': end},
                    'content': '\n'.join(lines[start-1:end]), 'precision': precision, 'candidate': candidate}
            # Exact source is preserved separately from tool-produced graph relations.
            raw_name = f'source-{fact["id"]}.txt'
            (directory / raw_name).write_text(fact['content'], encoding='utf-8')
            fact['raw_ref'] = str((directory / raw_name).relative_to(self.directory.parent))
            result['facts'].append(fact)
            dep = {'path': path, 'sha256': digest(self.sources[path].encode())}
            if dep not in result['dependencies']:
                result['dependencies'].append(dep)
        if result['coverage']['truncated']:
            result['errors'].append('truncated')
        if result['status'] in ('error', 'unsupported'):
            result['facts'] = []; result['dependencies'] = []
        return self._finish(directory, operation, request, result)

    def _finish(self, directory, operation, request, result):
        atomic_json(directory / 'result.json', result)
        delivered = self.access._record(operation, request, result)
        if 'error' in delivered:
            result = {**result, 'status': 'error', 'facts': [], 'dependencies': [], 'errors': [delivered['error']]}
        atomic_json(directory / 'delivered.json', result)
        return result
