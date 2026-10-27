"""Compatibility names; authoritative policy lives in the versioned rule package."""
from .skills import load_rule

_prompts = load_rule()["prompts"]
SYSTEM, INVESTIGATOR, JUDGE = (_prompts[k] for k in ("system", "investigator", "judge"))
