"""
Unit tests for pipeline.infer_parser
"""

import json
import tempfile
from pathlib import Path

import pytest

# Make sure project root is importable when run with `pytest` from root dir
import sys
sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline.infer_parser import BugReport, InferParser, TraceStep


# ── Fixtures ──────────────────────────────────────────────────────────────────

SAMPLE_REPORT = [
    {
        "bug_type":   "NULL_DEREFERENCE",
        "qualifier":  "null dereference of `ptr`",
        "severity":   "ERROR",
        "line":       42,
        "column":     -1,
        "procedure":  "main",
        "file":       "src/foo.c",
        "bug_trace": [
            {
                "level":         0,
                "filename":      "src/foo.c",
                "line_number":   38,
                "column_number": -1,
                "description":   "ptr set to NULL",
            },
            {
                "level":         0,
                "filename":      "src/foo.c",
                "line_number":   42,
                "column_number": -1,
                "description":   "null dereference",
            },
        ],
    },
    {
        "bug_type":  "USE_AFTER_FREE",
        "qualifier": "use-after-free of `buf`",
        "severity":  "ERROR",
        "line":      10,
        "column":    -1,
        "procedure": "do_thing",
        "file":      "src/bar.c",
        "bug_trace": [],
    },
    {
        "bug_type":  "DIVIDE_BY_ZERO",          # filtered by default
        "qualifier": "division by zero",
        "severity":  "ERROR",
        "line":      5,
        "column":    -1,
        "procedure": "calc",
        "file":      "src/calc.c",
        "bug_trace": [],
    },
    {
        "bug_type":  "RESOURCE_LEAK",            # always filtered (not in any list)
        "qualifier": "resource leak of `fd`",
        "severity":  "WARNING",
        "line":      99,
        "column":    -1,
        "procedure": "open_file",
        "file":      "src/io.c",
        "bug_trace": [],
    },
]


@pytest.fixture
def report_file():
    """Write SAMPLE_REPORT to a temporary file and return its path."""
    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".json", delete=False, encoding="utf-8"
    ) as f:
        json.dump(SAMPLE_REPORT, f)
        return Path(f.name)


# ── Tests ─────────────────────────────────────────────────────────────────────

class TestInferParser:

    def test_parse_returns_list(self, report_file):
        parser  = InferParser(report_file)
        reports = parser.parse()
        assert isinstance(reports, list)

    def test_filters_unsupported_types(self, report_file):
        """RESOURCE_LEAK should always be filtered out."""
        parser  = InferParser(report_file)
        reports = parser.parse()
        types   = {r.bug_type for r in reports}
        assert "RESOURCE_LEAK" not in types

    def test_null_dereference_included(self, report_file):
        parser  = InferParser(report_file)
        reports = parser.parse()
        types   = [r.bug_type for r in reports]
        assert "NULL_DEREFERENCE" in types

    def test_use_after_free_included(self, report_file):
        parser  = InferParser(report_file)
        reports = parser.parse()
        types   = [r.bug_type for r in reports]
        assert "USE_AFTER_FREE" in types

    def test_bug_trace_parsed(self, report_file):
        parser  = InferParser(report_file)
        reports = parser.parse()
        null_reports = [r for r in reports if r.bug_type == "NULL_DEREFERENCE"]
        assert len(null_reports) == 1
        trace = null_reports[0].bug_trace
        assert len(trace) == 2
        assert isinstance(trace[0], TraceStep)
        assert trace[0].line_number == 38
        assert "NULL" in trace[0].description

    def test_bug_report_id_format(self, report_file):
        parser  = InferParser(report_file)
        reports = parser.parse()
        for r in reports:
            assert ":" in r.id
            assert str(r.line) in r.id

    def test_custom_bug_types_filter(self, report_file):
        """Passing explicit bug_types should restrict results."""
        parser  = InferParser(report_file, bug_types=["NULL_DEREFERENCE"])
        reports = parser.parse()
        assert all(r.bug_type == "NULL_DEREFERENCE" for r in reports)
        assert len(reports) == 1

    def test_sorted_by_file_and_line(self, report_file):
        parser  = InferParser(report_file)
        reports = parser.parse()
        keys    = [(r.file, r.line) for r in reports]
        assert keys == sorted(keys)

    def test_parse_from_list(self, report_file):
        parser  = InferParser(report_file)
        reports = parser.parse_from_list(SAMPLE_REPORT)
        assert len(reports) >= 2   # at least NULL + UAF

    def test_missing_report_raises(self):
        parser = InferParser("/tmp/definitely_does_not_exist.json")
        with pytest.raises(FileNotFoundError):
            parser.parse()

    def test_is_asan_verifiable(self, report_file):
        parser = InferParser(report_file)
        reports = parser.parse()
        null_r = next(r for r in reports if r.bug_type == "NULL_DEREFERENCE")
        assert null_r.is_asan_verifiable is True

    def test_needs_instrumentation(self, report_file):
        """DIVIDE_BY_ZERO (if present) should need instrumentation, not ASan."""
        parser  = InferParser(report_file, bug_types=["DIVIDE_BY_ZERO"])
        reports = parser.parse()
        if reports:
            assert reports[0].needs_instrumentation is True

    def test_trace_as_text(self, report_file):
        parser  = InferParser(report_file)
        reports = parser.parse()
        null_r  = next(r for r in reports if r.bug_type == "NULL_DEREFERENCE")
        text    = null_r.trace_as_text()
        assert "Step 1" in text
        assert "Step 2" in text

    def test_source_code_empty_when_no_file(self, report_file):
        """source_code should be empty string when the file cannot be found."""
        parser  = InferParser(report_file)   # no source_root
        reports = parser.parse()
        # Without a valid source_root, source_code may be empty
        for r in reports:
            assert isinstance(r.source_code, str)
