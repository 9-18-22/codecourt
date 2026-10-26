"""
Integration test: end-to-end pipeline with mocked Claude API.

Runs the full pipeline (InferParser → LLMGenerator → ASanVerifier → Reporter)
against real sample C files so the compile + run steps are genuine.
"""

from __future__ import annotations

import json
import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

COMPILER_AVAILABLE = bool(shutil.which("clang") or shutil.which("gcc"))

# ── Fixtures ──────────────────────────────────────────────────────────────────

NULL_DEREF_C = """\
#include <stddef.h>
int main() {
    int *p = NULL;
    return *p;  /* NULL dereference */
}
"""

MOCK_LLM_RESPONSE_ARGS = {
    "reasoning":             "Pass no arguments so input stays -1 and ptr is NULL.",
    "input_type":            "args",
    "args":                  [],
    "stdin_data":            "",
    "file_inputs":           {},
    "env_vars":              {},
    "expected_crash":        "SIGSEGV",
    "confidence":            "high",
    "needs_instrumentation": False,
    "instrumentation_code":  None,
}


def _make_infer_report(src_path: Path) -> list:
    return [
        {
            "bug_type":  "NULL_DEREFERENCE",
            "qualifier": "null dereference of `p`",
            "severity":  "ERROR",
            "line":      4,
            "column":    -1,
            "procedure": "main",
            "file":      str(src_path),
            "bug_trace": [
                {
                    "level": 0,
                    "filename": str(src_path),
                    "line_number": 3,
                    "description": "p assigned NULL",
                },
                {
                    "level": 0,
                    "filename": str(src_path),
                    "line_number": 4,
                    "description": "null dereference",
                },
            ],
        }
    ]


# ── Tests ─────────────────────────────────────────────────────────────────────

@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="compiler not available")
class TestEndToEndPipeline:

    @patch("anthropic.Anthropic")
    def test_null_deref_produces_tp(self, mock_anthropic_cls, tmp_path):
        """Full pipeline on a real NULL-deref C file → expects TP verdict."""
        from config import config
        config.anthropic_api_key = "sk-fake"

        # Write C source
        src = tmp_path / "null_deref.c"
        src.write_text(NULL_DEREF_C)

        # Write Infer report
        report_json = tmp_path / "report.json"
        report_json.write_text(json.dumps(_make_infer_report(src)))

        # Mock Claude
        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = MagicMock(
            content=[MagicMock(text=json.dumps(MOCK_LLM_RESPONSE_ARGS))]
        )

        # Run pipeline
        from main import Pipeline
        pipeline = Pipeline(
            report_path = str(report_json),
            source_root = str(tmp_path),
            output_dir  = str(tmp_path / "results"),
        )
        full_report = pipeline.run()

        # Assertions
        assert full_report
        stats = full_report["statistics"]
        assert stats["true_positive_count"] >= 1
        assert stats["llm_success_count"]   >= 1

        result = full_report["results"][0]
        assert result["verdict"]     == "STRICT_TP"
        assert result["llm_success"] is True

    @patch("anthropic.Anthropic")
    def test_report_json_saved(self, mock_anthropic_cls, tmp_path):
        """Verify that the JSON report is written to disk."""
        from config import config
        config.anthropic_api_key = "sk-fake"

        src = tmp_path / "null_deref.c"
        src.write_text(NULL_DEREF_C)
        report_json = tmp_path / "report.json"
        report_json.write_text(json.dumps(_make_infer_report(src)))

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        mock_client.messages.create.return_value = MagicMock(
            content=[MagicMock(text=json.dumps(MOCK_LLM_RESPONSE_ARGS))]
        )

        from main import Pipeline
        output_dir = tmp_path / "results"
        Pipeline(
            report_path = str(report_json),
            source_root = str(tmp_path),
            output_dir  = str(output_dir),
        ).run()

        assert (output_dir / "verification_report.json").exists()

    def test_dry_run_skips_llm_and_asan(self, tmp_path):
        """Dry-run should complete without any API calls."""
        src = tmp_path / "null_deref.c"
        src.write_text(NULL_DEREF_C)
        report_json = tmp_path / "report.json"
        report_json.write_text(json.dumps(_make_infer_report(src)))

        from main import Pipeline
        pipeline = Pipeline(
            report_path = str(report_json),
            source_root = str(tmp_path),
            output_dir  = str(tmp_path / "results"),
            dry_run     = True,
        )
        full_report = pipeline.run()

        # In dry-run, LLM was never called, so llm_success should be False
        assert full_report
        result = full_report["results"][0]
        assert result["llm_success"] is False

    @patch("anthropic.Anthropic")
    def test_llm_failure_still_generates_report(self, mock_anthropic_cls, tmp_path):
        """Even if LLM fails for all bugs, report should still be created."""
        from config import config
        config.anthropic_api_key = "sk-fake"
        config.max_retries       = 1

        src = tmp_path / "null_deref.c"
        src.write_text(NULL_DEREF_C)
        report_json = tmp_path / "report.json"
        report_json.write_text(json.dumps(_make_infer_report(src)))

        mock_client = MagicMock()
        mock_anthropic_cls.return_value = mock_client
        # Always return garbage JSON
        mock_client.messages.create.return_value = MagicMock(
            content=[MagicMock(text="not json")]
        )

        from main import Pipeline
        output_dir = tmp_path / "results"
        full_report = Pipeline(
            report_path = str(report_json),
            source_root = str(tmp_path),
            output_dir  = str(output_dir),
        ).run()

        assert full_report
        result = full_report["results"][0]
        assert result["llm_success"] is False
        assert (output_dir / "verification_report.json").exists()
