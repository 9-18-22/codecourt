"""
Unit tests for pipeline.reporter
"""

from __future__ import annotations

import json
import sys
import tempfile
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline.asan_verifier import ASanResult, Verdict
from pipeline.infer_parser import BugReport
from pipeline.reporter import Reporter, _pct


# ── Helpers ───────────────────────────────────────────────────────────────────

def _make_report(
    bug_type: str = "NULL_DEREFERENCE",
    file: str = "src/foo.c",
    line: int = 42,
    llm_ok: bool = True,
    verdict: Verdict = Verdict.STRICT_TP,
) -> BugReport:
    r = BugReport(
        bug_type  = bug_type,
        qualifier = "test qualifier",
        severity  = "ERROR",
        line      = line,
        column    = -1,
        procedure = "main",
        file      = file,
    )
    r.llm_result = {
        "confidence": "high",
        "input_type": "args",
        "reasoning": "test",
        "attempt": 2,
        "_attempt_history": [
            {"attempt": 1, "status": "retry", "confidence": "low"},
            {"attempt": 2, "status": "accepted", "confidence": "high"},
        ],
        "args": ["42"],
        "stdin_data": "",
        "file_inputs": {},
        "expected_crash": "SEGV",
    } if llm_ok else None
    r._asan_obj  = ASanResult(
        verdict    = verdict,
        crash_type = "heap-use-after-free" if verdict in (Verdict.STRICT_TP, Verdict.FAMILY_TP) else "",
        crash_line = "foo.c:42",
        compile_cmd = "clang ...",
        run_cmd     = "./target",
        match_level = "strict" if verdict == Verdict.STRICT_TP else "",
        type_matched = verdict in (Verdict.STRICT_TP, Verdict.FAMILY_TP),
        matched_frame = "main" if verdict == Verdict.STRICT_TP else "",
        matched_line = 42 if verdict == Verdict.STRICT_TP else 0,
    )
    return r


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestReporter:

    def test_generates_json_file(self, tmp_path):
        reports = [_make_report()]
        reporter = Reporter(output_dir=tmp_path)
        reporter.generate(reports)
        output = tmp_path / "verification_report.json"
        assert output.exists()

    def test_json_structure(self, tmp_path):
        reports = [_make_report(), _make_report(verdict=Verdict.LIKELY_FP)]
        reporter = Reporter(output_dir=tmp_path)
        full_report = reporter.generate(reports)

        assert "generated_at"  in full_report
        assert "statistics"    in full_report
        assert "results"       in full_report
        assert len(full_report["results"]) == 2

    def test_statistics_counts(self, tmp_path):
        reports = [
            _make_report(verdict=Verdict.STRICT_TP),
            _make_report(verdict=Verdict.FAMILY_TP),
            _make_report(verdict=Verdict.LIKELY_FP, llm_ok=False),
        ]
        reporter = Reporter(output_dir=tmp_path)
        full = reporter.generate(reports)
        stats = full["statistics"]

        assert stats["total_bugs"]          == 3
        assert stats["true_positive_count"] == 2
        assert stats["strict_tp_count"]     == 1
        assert stats["family_tp_count"]     == 1
        assert stats["strict_tp_share_of_tp"] == 50.0
        assert stats["family_tp_share_of_tp"] == 50.0
        assert stats["unconfirmed_count"]   == 1
        assert stats["likely_fp_count"]      == 1
        assert stats["llm_success_count"]   == 2

    def test_rates_are_percentages(self, tmp_path):
        reports = [_make_report(verdict=Verdict.STRICT_TP)] * 3
        reporter = Reporter(output_dir=tmp_path)
        full = reporter.generate(reports)
        stats = full["statistics"]

        assert 0.0 <= stats["true_positive_rate"]  <= 100.0
        assert 0.0 <= stats["llm_success_rate"]    <= 100.0

    def test_bug_type_breakdown(self, tmp_path):
        reports = [
            _make_report(bug_type="NULL_DEREFERENCE"),
            _make_report(bug_type="NULL_DEREFERENCE"),
            _make_report(bug_type="USE_AFTER_FREE"),
        ]
        reporter = Reporter(output_dir=tmp_path)
        full = reporter.generate(reports)
        breakdown = full["statistics"]["bug_type_breakdown"]

        assert breakdown["NULL_DEREFERENCE"] == 2
        assert breakdown["USE_AFTER_FREE"]   == 1

    def test_result_record_fields(self, tmp_path):
        reports = [_make_report()]
        reporter = Reporter(output_dir=tmp_path)
        full = reporter.generate(reports)
        rec = full["results"][0]

        for field in (
            "id", "bug_type", "file", "line", "verdict", "llm_success",
            "llm_attempt", "llm_attempt_count", "llm_attempt_history",
            "match_level", "type_matched", "matched_frame", "matched_line",
        ):
            assert field in rec
        assert rec["llm_attempt"] == 2
        assert rec["llm_attempt_count"] == 2

    def test_handles_missing_llm_result(self, tmp_path):
        r = _make_report(llm_ok=False, verdict=Verdict.LIKELY_FP)
        reporter = Reporter(output_dir=tmp_path)
        full = reporter.generate([r])
        rec  = full["results"][0]
        assert rec["llm_success"] is False

    def test_custom_report_filename(self, tmp_path):
        reporter = Reporter(output_dir=tmp_path)
        reporter.generate([_make_report()], report_filename="custom_report.json")
        assert (tmp_path / "custom_report.json").exists()

    def test_output_dir_created(self, tmp_path):
        nested = tmp_path / "a" / "b" / "c"
        reporter = Reporter(output_dir=nested)
        reporter.generate([_make_report()])
        assert nested.exists()


class TestHelpers:

    def test_pct_basic(self):
        assert _pct(1, 4)   == 25.0
        assert _pct(3, 3)   == 100.0
        assert _pct(0, 10)  == 0.0

    def test_pct_zero_denom(self):
        assert _pct(5, 0) == 0.0

    def test_pct_rounds_to_2dp(self):
        assert _pct(1, 3) == round(1/3 * 100, 2)
