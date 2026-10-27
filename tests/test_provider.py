"""Provider settings import is narrow and never serialized into audit artifacts."""
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from security_agent.infra.claude import provider_env, ClaudeExecutor
from security_agent.core.contracts import INVESTIGATION_SCHEMA
from security_agent.core.executor import Task
from test_review import FakeClient, investigation


class ProviderTests(unittest.TestCase):
    def test_only_provider_env_is_loaded_and_process_env_wins(self):
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "settings.json"
            path.write_text(json.dumps({
                "env": {"ANTHROPIC_AUTH_TOKEN": "secret", "ANTHROPIC_BASE_URL": "https://provider.invalid",
                        "ANTHROPIC_DEFAULT_SONNET_MODEL": "deepseek-model", "MALICIOUS_VAR": "not-imported"},
                "hooks": {"PreToolUse": ["not-imported"]}}))
            with patch.dict(os.environ, {"ANTHROPIC_AUTH_TOKEN": "process-secret"}, clear=True):
                result = provider_env(path)
            self.assertEqual(result["ANTHROPIC_AUTH_TOKEN"], "process-secret")
            self.assertEqual(result["ANTHROPIC_DEFAULT_SONNET_MODEL"], "deepseek-model")
            self.assertNotIn("MALICIOUS_VAR", result)
            self.assertNotIn("hooks", result)

    def test_secrets_not_written_to_request(self):
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            path = root / "settings.json"
            path.write_text(json.dumps({"env": {"ANTHROPIC_AUTH_TOKEN": "must-not-persist"}}))
            artifacts = root / "attempt"
            artifacts.mkdir()
            FakeClient.queue = [investigation()]
            with patch("claude_agent_sdk.ClaudeSDKClient", FakeClient), patch.dict(os.environ, {}, clear=True):
                result = ClaudeExecutor(path).execute(
                    Task("investigator", {"target": "a.c", "sources": {"a.c": "int x;"}},
                         INVESTIGATION_SCHEMA, 2, 0.25, "sonnet"), artifacts)
            self.assertEqual(result.execution, "COMPLETED")
            for artifact in artifacts.iterdir():
                self.assertNotIn("must-not-persist", artifact.read_text())

    def test_missing_explicit_settings_is_error(self):
        with self.assertRaises(ValueError):
            provider_env("/does-not-exist/settings.json")
