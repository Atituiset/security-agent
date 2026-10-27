"""Vendor-free contracts and strict validation at the model boundary."""
from enum import StrEnum


class Execution(StrEnum):
    PENDING = "PENDING"
    RUNNING = "RUNNING"
    COMPLETED = "COMPLETED"
    FAILED = "FAILED"
    TIMED_OUT = "TIMED_OUT"
    INTERRUPTED = "INTERRUPTED"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    STALE = "STALE"


class Verdict(StrEnum):
    CONFIRMED = "CONFIRMED"
    REJECTED = "REJECTED"
    UNKNOWN = "UNKNOWN"



def obj(properties):
    return {"type": "object", "properties": properties,
            "required": list(properties), "additionalProperties": False}


def arr(items):
    return {"type": "array", "items": items}


STRING = {"type": "string", "minLength": 1}
STRINGS = arr(STRING)
REF = obj({"kind": {"enum": ["origin", "sink", "path", "guard", "type"]},
           "file": STRING, "start": {"type": "integer", "minimum": 1},
           "end": {"type": "integer", "minimum": 1}})
INVESTIGATION_SCHEMA = obj({"scenarios": arr(obj({
    "id": STRING, "hypothesis": STRING, "sink_line": {"type": "integer", "minimum": 1},
    "references": arr(REF), "unresolved": STRINGS})), "unresolved": STRINGS})
JUDGE_SCHEMA = obj({"decisions": arr(obj({
    "scenario_id": STRING, "verdict": {"enum": list(Verdict)},
    "evidence_ids": STRINGS, "reason": STRING, "unresolved": STRINGS}))})


# Optional on legacy test responses; production instructions request explicit follow-up.
from .queries import QUERY_SCHEMA, OPERATIONS
FOLLOW_UP = obj({'question': STRING, 'operation': {'enum': list(OPERATIONS)}, 'arguments': QUERY_SCHEMA})
JUDGE_SCHEMA['properties']['decisions']['items']['properties']['follow_up'] = arr(FOLLOW_UP)


class ContractError(ValueError):
    pass


def validate(value, schema, path="$"):
    """Validate the small, closed JSON Schema subset used by these contracts."""
    if "enum" in schema and value not in schema["enum"]:
        raise ContractError(f"{path}: invalid enum")
    kind = schema.get("type")
    expected = {"object": dict, "array": list, "string": str, "integer": int}.get(kind)
    if expected and type(value) is not expected:
        raise ContractError(f"{path}: expected {kind}")
    if kind == "object":
        if not set(schema.get("required", schema["properties"])) <= set(value) or set(value) - set(schema["properties"]):
            raise ContractError(f"{path}: missing or unexpected fields")
        for key in value:
            validate(value[key], schema["properties"][key], f"{path}.{key}")
    elif kind == "array":
        for i, child in enumerate(value):
            validate(child, schema["items"], f"{path}[{i}]")
    elif kind == "string" and not value.strip():
        raise ContractError(f"{path}: empty string")
    elif kind == "integer" and not schema.get("minimum", value) <= value <= schema.get("maximum", value):
        raise ContractError(f"{path}: outside numeric bounds")
    if kind == "string" and not schema.get("minLength", 0) <= len(value) <= schema.get("maxLength", len(value)):
        raise ContractError(f"{path}: outside string length bounds")
