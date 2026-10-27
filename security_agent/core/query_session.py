"""Reuse immutable completed fact queries within/between investigation rounds."""
from copy import deepcopy
from .runtime import fingerprint
from .storage import read_json


def query_key(operation, request):
    # Purpose explains intent but cannot change the underlying bounded fact query.
    return fingerprint({'operation': operation, 'arguments': {k: v for k, v in request.items()
                                                            if k not in ('id', 'operation', 'purpose')}})


class QuerySession:
    def __init__(self, queries, access, artifact_dir, history):
        self.queries, self.access = queries, access
        self.cache = {}
        root = artifact_dir.parent.parent.resolve()
        for entry in history:
            request = entry['request']
            path = (root / entry['result_ref']).resolve()
            if not path.is_relative_to(root) or not path.is_file():
                continue
            result = read_json(path)
            # Errors can be retried. Immutable successful/partial observations can be reused.
            if result['status'] in ('complete', 'partial'):
                self.cache[query_key(request['operation'], request)] = (result, entry['result_ref'])

    def execute(self, operation, request):
        from .contracts import validate
        from .queries import QUERY_SCHEMA
        validate(request, QUERY_SCHEMA)
        key = query_key(operation, request)
        if key in self.cache:
            result, source = self.cache[key]
            result = {**deepcopy(result), 'reused_from': source}
            return self.access._record(operation, request, result)
        result = self.queries.execute(operation, request)
        if result.get('status') in ('complete', 'partial'):
            self.cache[key] = (deepcopy(result), result.get('id', 'current-attempt'))
        return result
