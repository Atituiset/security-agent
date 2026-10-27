"""Execution port: no SDK types, CWE policy, repository access or workflow ownership."""
from dataclasses import dataclass
from typing import Callable, Protocol
from .contracts import Execution


@dataclass(frozen=True)
class SecurityTool:
    name: str
    description: str
    schema: dict
    execute: Callable[[dict], dict]


@dataclass(frozen=True)
class Task:
    role: str
    payload: dict
    schema: dict
    timeout: float
    usd: float
    model: str
    system_prompt: str = ""
    tools: tuple[SecurityTool, ...] = ()
    max_turns: int = 4


@dataclass(frozen=True)
class AgentResult:
    execution: Execution
    output: dict | None
    detail: str
    cost_usd: float | None = None


class AgentExecutor(Protocol):
    def execute(self, task: Task, artifact_dir) -> AgentResult: ...
