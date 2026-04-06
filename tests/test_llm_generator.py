"""
Unit tests for pipeline.llm_generator
All Claude API calls are mocked – no real API key required.
"""

from __future__ import annotations

import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline.infer_parser import BugReport, TraceStep
from pipeline.llm_generator import LLMGenerator, LLMResult, _USER_PROMPT_TEMPLATE


# ── Helpers ───────────────────────────────────────────────────────────────────

GOOD_LLM_RESPONSE = {
    "reasoning":             "ptr is set to NULL when v < 0, so pass a negative value.",
    "input_type":            "args",
    "args":                  ["-1"],
    "stdin_data":            "",
    "file_inputs":           {},
    "env_vars":              {},
    "expected_crash":        "SIGSEGV",
    "confidence":            "high",
    "needs_instrumentation": False,
    "instrumentation_code":  None,
}


def _make_report(bug_type: str = "NULL_DEREFERENCE") -> BugReport:
    return BugReport(
        bug_type  = bug_type,
        qualifier = "null dereference of `ptr`",
        severity  = "ERROR",
        line      = 42,
        column    = -1,
        procedure = "main",
        file      = "src/foo.c",
        bug_trace = [
            TraceStep("src/foo.c", 38, "ptr set to NULL"),
            TraceStep("src/foo.c", 42, "null dereference"),
        ],
        source_code = "int main() { int *p = NULL; return *p; }",
    )


def _mock_anthropic_response(content: str) -> MagicMock:
    msg_mock = MagicMock()
    msg_mock.content = [MagicMock(text=content)]
    return msg_mock


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestLLMGeneratorInit:

    def test_raises_without_api_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "")
        from config import config
        config.anthropic_api_key = ""
        with pytest.raises(ValueError, match="ANTHROPIC_API_KEY"):
            LLMGenerator()

    def test_creates_with_api_key(self, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-test-fake-key")
        from config import config
        config.anthropic_api_key = "sk-test-fake-key"
        # Should not raise
        with patch("anthropic.Anthropic"):
            gen = LLMGenerator()
        assert gen is not None


class TestLLMResultParsing:

    def test_good_json_parses(self):
        raw = json.dumps(GOOD_LLM_RESPONSE)
        result = LLMResult(GOOD_LLM_RESPONSE, attempt=1)
        assert result.confidence  == "high"
        assert result.input_type  == "args"
        assert result.args        == ["-1"]
        assert result.needs_instrumentation is False

    def test_to_dict_includes_attempt(self):
        result = LLMResult(GOOD_LLM_RESPONSE, attempt=2)
        d = result.to_dict()
        assert d["attempt"] == 2

    def test_defaults_for_missing_fields(self):
        result = LLMResult({}, attempt=1)
        assert result.confidence  == "low"
        assert result.input_type  == "none"
        assert result.args        == []
        assert result.stdin_data  == ""


class TestLLMGeneratorGenerate:

    @patch("anthropic.Anthropic")
    def test_successful_generation(self, mock_anthropic_cls, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        from config import config
        config.anthropic_api_key = "sk-fake"

        # Set up mock
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = _mock_anthropic_response(
            json.dumps(GOOD_LLM_RESPONSE)
        )

        gen    = LLMGenerator()
        report = _make_report()
        result = gen.generate(report)

        assert result is not None
        assert isinstance(result, LLMResult)
        assert result.confidence == "high"
        assert result.args       == ["-1"]

    @patch("anthropic.Anthropic")
    def test_retry_on_bad_json(self, mock_anthropic_cls, monkeypatch):
        """Generator should retry when LLM returns unparseable text, then succeed."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        from config import config
        config.anthropic_api_key = "sk-fake"
        config.max_retries       = 3

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        # First call returns garbage; second call returns valid JSON
        mock_client.messages.create.side_effect = [
            _mock_anthropic_response("This is not JSON at all."),
            _mock_anthropic_response(json.dumps(GOOD_LLM_RESPONSE)),
        ]

        gen    = LLMGenerator()
        result = gen.generate(_make_report())

        assert result is not None
        assert mock_client.messages.create.call_count == 2

    @patch("anthropic.Anthropic")
    def test_returns_none_after_all_retries_fail(self, mock_anthropic_cls, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        from config import config
        config.anthropic_api_key = "sk-fake"
        config.max_retries       = 2

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = _mock_anthropic_response(
            "no json here"
        )

        gen    = LLMGenerator()
        result = gen.generate(_make_report())

        assert result is None
        assert mock_client.messages.create.call_count == 2

    @patch("anthropic.Anthropic")
    def test_json_in_markdown_fence_parsed(self, mock_anthropic_cls, monkeypatch):
        """LLM sometimes wraps JSON in ```json … ``` – must be stripped."""
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        from config import config
        config.anthropic_api_key = "sk-fake"

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        wrapped = f"```json\n{json.dumps(GOOD_LLM_RESPONSE)}\n```"
        mock_client.messages.create.return_value = _mock_anthropic_response(wrapped)

        gen    = LLMGenerator()
        result = gen.generate(_make_report())

        assert result is not None
        assert result.confidence == "high"

    @patch("anthropic.Anthropic")
    def test_instrumentation_response_parsed(self, mock_anthropic_cls, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        from config import config
        config.anthropic_api_key = "sk-fake"

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client

        instr_response = {
            **GOOD_LLM_RESPONSE,
            "needs_instrumentation": True,
            "instrumentation_code":  "assert(divisor != 0);",
        }
        mock_client.messages.create.return_value = _mock_anthropic_response(
            json.dumps(instr_response)
        )

        gen    = LLMGenerator()
        result = gen.generate(_make_report("DIVIDE_BY_ZERO"))

        assert result is not None
        assert result.needs_instrumentation is True
        assert "assert" in result.instrumentation_code


class TestPromptBuilding:
    """Verify prompt content without hitting the API."""

    @patch("anthropic.Anthropic")
    def test_prompt_contains_bug_type(self, mock_anthropic_cls, monkeypatch):
        monkeypatch.setenv("ANTHROPIC_API_KEY", "sk-fake")
        from config import config
        config.anthropic_api_key = "sk-fake"

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = _mock_anthropic_response(
            json.dumps(GOOD_LLM_RESPONSE)
        )

        gen    = LLMGenerator()
        report = _make_report()
        gen.generate(report)

        call_kwargs = mock_client.messages.create.call_args
        user_msg    = call_kwargs.kwargs["messages"][0]["content"]
        assert "NULL_DEREFERENCE" in user_msg
        assert "src/foo.c"        in user_msg
        assert "42"               in user_msg
