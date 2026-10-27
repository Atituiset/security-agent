"""Adapter seam for future local code tools, separate from the LLM executor."""
from typing import Protocol


class CodeTool(Protocol):
    capabilities: frozenset[str]

    def check(self) -> None:
        """Raise if the bound tool/index/source view is stale."""
        ...

    def query(self, operation: str, symbol: str, limit: int, directory, timeout: float) -> dict:
        """Return status, candidates, errors, producer/version and truncation.

        Each candidate has location {path,start_line,end_line} and identity.
        Adapters translate native output into this shape and persist raw bytes.
        Candidate identity is opaque to the semantic layer and never proves flow.
        """
        ...
