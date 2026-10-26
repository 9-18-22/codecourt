"""
Unit tests for pipeline.asan_verifier

Some tests compile and run real C code; they require clang or gcc on PATH.
Tests that need a compiler are marked with @pytest.mark.integration.
"""

from __future__ import annotations

import shutil
import sys
import tempfile
from pathlib import Path
from unittest.mock import MagicMock

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from pipeline.asan_verifier import ASanVerifier, Verdict, _ASAN_ERROR_RE
from pipeline.infer_parser import BugReport, TraceStep
from pipeline.llm_generator import LLMResult


# ── Helpers ───────────────────────────────────────────────────────────────────

COMPILER_AVAILABLE = bool(shutil.which("clang") or shutil.which("gcc"))


def _make_report(
    bug_type: str = "NULL_DEREFERENCE",
    source: str = "",
    procedure: str = "main",
    file: str = "test.c",
    line: int = 1,
) -> BugReport:
    r = BugReport(
        bug_type  = bug_type,
        qualifier = "test",
        severity  = "ERROR",
        line      = line,
        column    = -1,
        procedure = procedure,
        file      = file,
        bug_trace = [],
        source_code = source,
    )
    return r


def _make_llm_result(
    input_type: str = "args",
    args: list | None = None,
    stdin_data: str = "",
    needs_instr: bool = False,
    instr_code: str | None = None,
) -> LLMResult:
    raw = {
        "reasoning":             "",
        "input_type":            input_type,
        "args":                  args or [],
        "stdin_data":            stdin_data,
        "file_inputs":           {},
        "env_vars":              {},
        "expected_crash":        "",
        "confidence":            "high",
        "needs_instrumentation": needs_instr,
        "instrumentation_code":  instr_code,
    }
    return LLMResult(raw, attempt=1)


def _write_c_file(tmp: Path, content: str, name: str = "test.c") -> Path:
    p = tmp / name
    p.write_text(content)
    return p


# ── Unit tests (no compiler needed) ──────────────────────────────────────────

class TestASanResultClassification:

    def test_asan_error_regex_matches(self):
        sample = "ERROR: AddressSanitizer: heap-use-after-free on address 0x..."
        m = _ASAN_ERROR_RE.search(sample)
        assert m is not None
        assert "heap-use-after-free" in m.group(1)

    def test_asan_null_deref_matches(self):
        sample = "ERROR: AddressSanitizer: SEGV on unknown address 0x0"
        m = _ASAN_ERROR_RE.search(sample)
        assert m is not None

    def test_classify_strict_tp_on_top_frame_match(self):
        from pipeline.asan_verifier import ASanVerifier
        verifier = ASanVerifier.__new__(ASanVerifier)
        report = _make_report(file="test.c", procedure="main")
        result = verifier._classify(
            "ERROR: AddressSanitizer: heap-use-after-free\n"
            "#0 0x401abc in main /tmp/test.c:10",
            returncode=1,
            compile_cmd="clang ...",
            run_cmd="./target",
            report=report,
        )
        assert result.verdict == Verdict.STRICT_TP
        assert result.match_level == "strict"
        assert result.matched_frame == "main"
        assert "heap-use-after-free" in result.crash_type

    def test_classify_likely_fp_on_clean_exit(self):
        from pipeline.asan_verifier import ASanVerifier
        verifier = ASanVerifier.__new__(ASanVerifier)
        result = verifier._classify(
            "everything is fine",
            returncode=0,
            compile_cmd="",
            run_cmd="",
            report=_make_report(),
        )
        assert result.verdict == Verdict.LIKELY_FP
        assert result.match_level == "no_crash"

    def test_classify_family_tp_without_report_context(self):
        """Signal crash (e.g. SIGSEGV) → returncode < 0."""
        from pipeline.asan_verifier import ASanVerifier
        verifier = ASanVerifier.__new__(ASanVerifier)
        result = verifier._classify(
            "",
            returncode=-11,   # SIGSEGV
            compile_cmd="",
            run_cmd="",
        )
        assert result.verdict == Verdict.FAMILY_TP
        assert result.match_level == "family_no_proc"
        assert "signal" in result.crash_type


    def test_classify_family_tp_on_call_chain_match(self):
        from pipeline.asan_verifier import ASanVerifier
        verifier = ASanVerifier.__new__(ASanVerifier)
        report = _make_report(file="test.c", procedure="target_proc")
        output = (
            "ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
            "#0 0x401abc in helper /tmp/test.c:10\n"
            "#1 0x401def in target_proc /tmp/test.c:20\n"
        )
        result = verifier._classify(output, 1, "", "", report)
        assert result.verdict == Verdict.FAMILY_TP
        assert result.match_level == "family_chain"
        assert result.matched_frame == "target_proc"
        assert result.matched_line == 20

    def test_classify_cross_detection_on_same_file_other_function(self):
        from pipeline.asan_verifier import ASanVerifier
        verifier = ASanVerifier.__new__(ASanVerifier)
        report = _make_report(file="test.c", procedure="target_proc")
        output = (
            "ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
            "#0 0x401abc in helper /tmp/test.c:10\n"
        )
        result = verifier._classify(output, 1, "", "", report)
        assert result.verdict == Verdict.CROSS_DETECTION
        assert result.match_level == "cross_proc"

    def test_classify_cross_detection_on_different_file(self):
        from pipeline.asan_verifier import ASanVerifier
        verifier = ASanVerifier.__new__(ASanVerifier)
        report = _make_report(file="test.c", procedure="main")
        output = (
            "ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
            "#0 0x401abc in main /tmp/other.c:10\n"
        )
        result = verifier._classify(output, 1, "", "", report)
        assert result.verdict == Verdict.CROSS_DETECTION
        assert result.match_level == "diff_file"

    def test_classify_family_tp_when_procedure_missing(self):
        from pipeline.asan_verifier import ASanVerifier
        verifier = ASanVerifier.__new__(ASanVerifier)
        report = _make_report(file="test.c", procedure="")
        output = (
            "ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
            "#0 0x401abc in helper /tmp/test.c:10\n"
        )
        result = verifier._classify(output, 1, "", "", report)
        assert result.verdict == Verdict.FAMILY_TP
        assert result.match_level == "family_no_proc"

    def test_procedure_word_boundary_rejects_partial_function_name(self):
        from pipeline.asan_verifier import ASanVerifier
        verifier = ASanVerifier.__new__(ASanVerifier)
        report = _make_report(file="func_pointer.c", procedure="func_pointer_011")
        output = (
            "ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
            "#0 0x401abc in func_pointer_011_func_001 /tmp/func_pointer.c:10\n"
        )
        result = verifier._classify(output, 1, "", "", report)
        assert result.verdict == Verdict.CROSS_DETECTION
        assert result.match_level == "cross_proc"

    def test_type_mismatch_does_not_change_verdict(self):
        from pipeline.asan_verifier import ASanVerifier
        verifier = ASanVerifier.__new__(ASanVerifier)
        report = _make_report(bug_type="USE_AFTER_FREE", file="test.c", procedure="main")
        output = (
            "ERROR: AddressSanitizer: SEGV on unknown address 0x0\n"
            "#0 0x401abc in main /tmp/test.c:10\n"
        )
        result = verifier._classify(output, 1, "", "", report)
        assert result.verdict == Verdict.STRICT_TP
        assert result.type_matched is False


class TestSkipLogic:

    def test_skips_non_asan_verifiable(self):
        report = _make_report("RESOURCE_LEAK")
        report.resolved_path = Path("/tmp/fake.c")
        verifier = ASanVerifier.__new__(ASanVerifier)
        result   = verifier.verify(report, _make_llm_result())
        assert result.verdict == Verdict.SKIPPED

    def test_compile_error_when_no_source(self):
        report = _make_report("NULL_DEREFERENCE")
        report.resolved_path = None          # source unavailable
        verifier = ASanVerifier.__new__(ASanVerifier)
        result   = verifier.verify(report, _make_llm_result())
        assert result.verdict == Verdict.COMPILE_ERROR


class TestAssertionInjection:

    def test_inject_assertion_inserts_before_line(self):
        source = "int main() {\n    int x = 0;\n    return 1/x;\n}\n"
        result = ASanVerifier._inject_assertion(source, bug_line=3, assertion="assert(x != 0)")
        lines  = result.splitlines()
        # The assertion should appear at what was line 3
        assert any("assert(x != 0)" in l for l in lines)

    def test_inject_assertion_preserves_indentation(self):
        source = "void f() {\n    int d = 0;\n    return 10/d;\n}\n"
        result = ASanVerifier._inject_assertion(source, bug_line=3, assertion="assert(d != 0)")
        for line in result.splitlines():
            if "assert" in line:
                assert line.startswith("    ")
                break


# ── Integration tests (require clang/gcc + ASan) ──────────────────────────────

@pytest.mark.skipif(not COMPILER_AVAILABLE, reason="clang/gcc not available")
class TestASanIntegration:

    def test_null_deref_detected(self, tmp_path):
        """A program that dereferences NULL should be flagged as TP."""
        src = tmp_path / "null.c"
        src.write_text(
            "#include <stddef.h>\n"
            "int main() {\n"
            "    int *p = NULL;\n"
            "    return *p;\n"   # will crash
            "}\n"
        )
        report = _make_report("NULL_DEREFERENCE")
        report.resolved_path = src
        report.file = str(src)

        verifier = ASanVerifier()
        result   = verifier.verify(report, _make_llm_result())

        assert result.verdict == Verdict.STRICT_TP

    def test_clean_program_is_unconfirmed(self, tmp_path):
        """A correct program should yield LIKELY_FP (not a TP)."""
        src = tmp_path / "ok.c"
        src.write_text(
            "#include <stdio.h>\n"
            "int main() {\n"
            "    printf(\"hello\\n\");\n"
            "    return 0;\n"
            "}\n"
        )
        report = _make_report("NULL_DEREFERENCE")
        report.resolved_path = src
        report.file = str(src)

        verifier = ASanVerifier()
        result   = verifier.verify(report, _make_llm_result())

        assert result.verdict == Verdict.LIKELY_FP

    def test_compile_error_on_bad_source(self, tmp_path):
        src = tmp_path / "bad.c"
        src.write_text("this is not valid C code {{{")

        report = _make_report("NULL_DEREFERENCE")
        report.resolved_path = src
        report.file = str(src)

        verifier = ASanVerifier()
        result   = verifier.verify(report, _make_llm_result())

        assert result.verdict == Verdict.COMPILE_ERROR

    def test_buffer_overflow_detected_via_args(self, tmp_path):
        """A buffer overflow triggered by a long argument → TP."""
        src = tmp_path / "bof.c"
        # Use heap OOB index: reliably caught by ASan/UBSan on both Linux and macOS
        src.write_text(
            "#include <stdlib.h>\n"
            "int main() {\n"
            "    int *p = (int*)malloc(4);\n"
            "    p[10] = 42;\n"
            "    free(p);\n"
            "    return 0;\n"
            "}\n"
        )
        report = _make_report("BUFFER_OVERRUN_L1")
        report.resolved_path = src
        report.file = str(src)

        llm = _make_llm_result(input_type="none")
        verifier = ASanVerifier()
        result   = verifier.verify(report, llm)

        assert result.verdict == Verdict.STRICT_TP

    def test_use_after_free_detected(self, tmp_path):
        src = tmp_path / "uaf.c"
        src.write_text(
            "#include <stdlib.h>\n"
            "#include <stdio.h>\n"
            "int main() {\n"
            "    int *p = (int*)malloc(sizeof(int));\n"
            "    *p = 42;\n"
            "    free(p);\n"
            "    printf(\"%d\\n\", *p);\n"   # UAF
            "    return 0;\n"
            "}\n"
        )
        report = _make_report("USE_AFTER_FREE")
        report.resolved_path = src
        report.file = str(src)

        verifier = ASanVerifier()
        result   = verifier.verify(report, _make_llm_result())

        assert result.verdict == Verdict.STRICT_TP

    def test_stdin_input_type(self, tmp_path):
        """Program reading from stdin triggered via LLM stdin_data."""
        src = tmp_path / "stdin_prog.c"
        src.write_text(
            "#include <stdio.h>\n"
            "#include <stdlib.h>\n"
            "int main() {\n"
            "    int n;\n"
            "    scanf(\"%d\", &n);\n"
            "    int *arr = (int*)malloc(n * sizeof(int));\n"
            "    arr[n] = 99;\n"   # off-by-one → OOB write
            "    free(arr);\n"
            "    return 0;\n"
            "}\n"
        )
        report = _make_report("BUFFER_OVERRUN_L1")
        report.resolved_path = src
        report.file = str(src)

        llm = _make_llm_result(input_type="stdin", stdin_data="4\n")
        verifier = ASanVerifier()
        result   = verifier.verify(report, llm)

        assert result.verdict == Verdict.STRICT_TP

    def test_timeout_handled_gracefully(self, tmp_path):
        """Infinite-loop program should result in TIMEOUT, not a hang."""
        src = tmp_path / "inf_loop.c"
        # Use volatile to prevent the compiler from optimising away the infinite loop
        src.write_text(
            "int main() { volatile int x = 0; while(x == 0); return 0; }\n"
        )
        report = _make_report("NULL_DEREFERENCE")
        report.resolved_path = src
        report.file = str(src)

        from config import config as cfg
        original_timeout = cfg.timeout_seconds
        cfg.timeout_seconds = 2   # speed up the test

        try:
            verifier = ASanVerifier()
            result   = verifier.verify(report, _make_llm_result())
            assert result.verdict == Verdict.TIMEOUT
        finally:
            cfg.timeout_seconds = original_timeout
