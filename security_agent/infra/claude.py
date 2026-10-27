"""Claude Agent SDK adapter. Vendor types stay entirely inside this module."""
import json
import math
import os
from pathlib import Path
from dataclasses import asdict
from importlib.metadata import version
import tempfile
from security_agent.core.contracts import Execution
from security_agent.core.executor import AgentResult
from security_agent.core.storage import atomic_json

# Only provider connection/model settings are imported, never hooks/plugins/permissions.
PROVIDER_ENV_KEYS = frozenset({
    "ANTHROPIC_API_KEY", "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_BASE_URL",
    "ANTHROPIC_MODEL", "ANTHROPIC_SMALL_FAST_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL", "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC",
})


def provider_env(settings_path=None):
    path = Path(settings_path) if settings_path else Path.home() / ".claude/settings.json"
    configured = {}
    if path.exists():
        data = json.loads(path.read_text(encoding="utf-8"))
        if not isinstance(data, dict) or not isinstance(data.get("env", {}), dict):
            raise ValueError("Claude settings env must be an object")
        configured = data.get("env", {})
    elif settings_path:
        raise ValueError("Claude settings file does not exist")
    result = {}
    for key in PROVIDER_ENV_KEYS:
        value = os.environ.get(key, configured.get(key))
        if value is not None:
            if not isinstance(value, str):
                raise ValueError(f"Claude provider setting {key} must be a string")
            result[key] = value
    return result


class ClaudeExecutor:
    def __init__(self, settings_path=None):
        self.settings_path = settings_path

    def execute(self, task, artifact_dir):
        import anyio
        try:
            return anyio.run(self._execute, task, artifact_dir)
        except KeyboardInterrupt:
            return AgentResult(Execution.INTERRUPTED, None, "interrupted by signal")
        except Exception as exc:
            return AgentResult(Execution.FAILED, None, f"{type(exc).__name__}: {exc}")

    async def _execute(self, task, artifact_dir):
        import anyio
        from claude_agent_sdk import ClaudeAgentOptions, ClaudeSDKClient, ResultMessage, tool, create_sdk_mcp_server

        connection_env = provider_env(self.settings_path)
        mcp_servers, allowed_tools = {}, []
        if task.tools:
            sdk_tools = []
            for descriptor in task.tools:
                def bind(tool_descriptor):
                    async def call(args):
                        result = tool_descriptor.execute(args)
                        return {"content": [{"type": "text", "text": json.dumps(result, ensure_ascii=False)}]}
                    return call
                sdk_tools.append(tool(descriptor.name, descriptor.description, descriptor.schema)(bind(descriptor)))
            mcp_servers = {"security": create_sdk_mcp_server(name="security", tools=sdk_tools)}
            allowed_tools = ["mcp__security__" + descriptor.name for descriptor in task.tools]
        payload, system = task.payload, task.system_prompt
        atomic_json(artifact_dir / "request.json", {
            "role": task.role, "payload": payload, "schema": task.schema,
            "system_prompt": system, "model": task.model, "timeout": task.timeout,
            "max_budget_usd": task.usd, "sdk_version": version("claude-agent-sdk"),
            "tools": allowed_tools, "setting_sources": [], "resume": None,
            "provider_env_keys": sorted(connection_env)})
        with tempfile.TemporaryDirectory(prefix="security-agent-") as cwd, \
                (artifact_dir / "messages.jsonl").open("w", encoding="utf-8") as events, \
                (artifact_dir / "stderr.raw").open("w", encoding="utf-8") as stderr:
            def on_stderr(line):
                stderr.write(line + "\n")
                stderr.flush()

            options = ClaudeAgentOptions(
                model=task.model, system_prompt=system, cwd=cwd, env=connection_env,
                tools=[], allowed_tools=allowed_tools, mcp_servers=mcp_servers, strict_mcp_config=True,
                setting_sources=[], skills=[], plugins=[], permission_mode="dontAsk",
                continue_conversation=False, resume=None,
                max_turns=task.max_turns,
                max_budget_usd=task.usd, stderr=on_stderr,
                extra_args={"disable-slash-commands": None, "no-session-persistence": None},
                output_format={"type": "json_schema", "schema": task.schema})
            final = None
            try:
                # A fresh SDK client per role/attempt: SDK owns transport, cancellation and cleanup.
                with anyio.fail_after(task.timeout):
                    async with ClaudeSDKClient(options=options) as client:
                        await client.query(json.dumps(payload, ensure_ascii=False))
                        async for message in client.receive_response():
                            events.write(json.dumps({"type": type(message).__name__,
                                                     "message": asdict(message)}, ensure_ascii=True) + "\n")
                            events.flush()
                            if isinstance(message, ResultMessage):
                                final = message
                if final is None:
                    raise ValueError("SDK stream ended without ResultMessage")
                if final.is_error or final.subtype != "success":
                    status = (Execution.BUDGET_EXHAUSTED if "budget" in final.subtype or
                              "max_turns" in final.subtype else Execution.FAILED)
                    detail = f"SDK result: {final.subtype}; is_error={final.is_error}"
                    if final.result:
                        detail += ": " + final.result[:2000]
                    if final.errors:
                        detail += "; " + "; ".join(final.errors)[:2000]
                    return AgentResult(status, None, detail, final.total_cost_usd)
                cost = final.total_cost_usd
                if cost is not None and (type(cost) not in (int, float) or
                                         not math.isfinite(cost) or cost < 0):
                    raise ValueError("invalid SDK cost")
                return AgentResult(Execution.COMPLETED, final.structured_output, "", cost)
            except TimeoutError:
                return AgentResult(Execution.TIMED_OUT, None, "SDK wall-clock deadline exceeded")
            except Exception as exc:
                # Persist SDK transport/auth/schema failures as UNKNOWN, never a safety verdict.
                return AgentResult(Execution.FAILED, None, f"{type(exc).__name__}: {exc}")
