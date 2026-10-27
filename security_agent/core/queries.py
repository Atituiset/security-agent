"""Semantic query contract and execution port owned by Security Core."""
from typing import Protocol

OPERATIONS = ('find_definition', 'find_references', 'find_callers', 'find_callees',
              'find_assignments', 'find_pattern', 'find_related_symbols')

QUERY_SCHEMA = {
    'type': 'object', 'properties': {
        'symbol': {'type': 'string', 'maxLength': 200},
        'file': {'type': 'string'},
        'start': {'type': 'integer', 'minimum': 1},
        'end': {'type': 'integer', 'minimum': 1},
        'kind': {'type': 'string', 'enum': ['literal', 'dereference', 'null_guard', 'return', 'assignment', 'call']},
        'text': {'type': 'string', 'maxLength': 200},
        'purpose': {'type': 'string', 'minLength': 1},
        'limit': {'type': 'integer', 'minimum': 1, 'maximum': 100}},
    'required': ['purpose'], 'additionalProperties': False}


class FactQueries(Protocol):
    """Every result retains provenance, precision, coverage and errors separately."""
    def execute(self, operation: str, request: dict) -> dict: ...
