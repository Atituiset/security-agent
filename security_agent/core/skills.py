"""Versioned security specifications, loaded independently of any Agent SDK."""
import json
from importlib.resources import files
from .storage import digest


def load_rule():
    package = files('security_agent').joinpath('skills/cwe476')
    raw = package.joinpath('contract.json').read_bytes()
    contract = json.loads(raw)
    if contract['id'] != 'CWE-476' or contract['required_evidence'] != ['origin', 'sink', 'path']:
        raise ValueError('unsupported security rule contract')
    prompts = {role: package.joinpath(name).read_text() for role, name in contract['roles'].items()}
    fingerprint = digest(raw + ''.join(prompts[k] for k in sorted(prompts)).encode())
    return {**contract, 'sha256': fingerprint, 'prompts': prompts}
