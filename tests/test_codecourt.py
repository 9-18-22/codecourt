from pathlib import Path
import shutil
import time

import pytest

from pipeline.codecourt.evidence import validate_defense, verify_execution
from pipeline.codecourt.court import CodeCourt
from pipeline.codecourt.models import CourtOptions, ExperimentPlan, InvalidPlan
from pipeline.codecourt.runner import EvidenceRunner
from pipeline.infer_parser import BugReport, TraceStep


def report_for(path, line=4, bug_type="NULL_DEREFERENCE"):
    return BugReport(
        bug_type=bug_type, qualifier="null dereference of p", severity="ERROR",
        line=line, column=-1, procedure="main", file=str(path),
        bug_trace=[TraceStep(str(path), line, "dereference")],
        source_code=path.read_text() if path.exists() else "",
        resolved_path=path,
    )


def test_plan_rejects_generated_code_in_original_mode():
    with pytest.raises(InvalidPlan):
        ExperimentPlan.parse({"hypothesis": "x", "mode": "original",
                              "trigger_code": "int main(void){return 0;}"})


def test_plan_rejects_path_escape_and_sanitizer_override():
    with pytest.raises(InvalidPlan):
        ExperimentPlan.parse({"hypothesis": "x", "file_inputs": {"../x": "data"}})
    with pytest.raises(InvalidPlan):
        ExperimentPlan.parse({"hypothesis": "x", "env_vars": {"ASAN_OPTIONS": "x"}})


def test_defense_citations_must_match_saved_artifact(tmp_path):
    (tmp_path / "original.c").write_text("int main(void) {\n  return 0;\n}\n")
    review = validate_defense({"summary": "s", "objections": [{
        "kind": "OTHER", "claim": "claim", "evidence_id": "round_01",
        "requested_experiment": "run caller", "citations": [
            {"artifact": "original.c", "line": 2, "quote": "return 0"}
        ]
    }]}, tmp_path)
    assert len(review["verified_objections"]) == 1


@pytest.mark.skipif(not (shutil.which("clang") or shutil.which("gcc")),
                    reason="C compiler unavailable")
def test_original_program_produces_persisted_candidate_and_replay(tmp_path):
    source = tmp_path / "bug.c"
    source.write_text(
        "#include <stddef.h>\n"
        "int main(void) {\n"
        "  int *p = NULL;\n"
        "  return *p;\n"
        "}\n"
    )
    report = report_for(source)
    plan = ExperimentPlan.parse({"hypothesis": "main dereferences p", "mode": "original"})
    directory = tmp_path / "evidence"
    directory.mkdir()
    options = CourtOptions(max_rounds=1, max_executions=2, timeout_seconds=5,
                           compile_timeout_seconds=20, max_seconds=40)
    runner = EvidenceRunner(options)
    deadline = time.monotonic() + 40
    manifest = runner.run(report, plan, directory, deadline)
    evidence = verify_execution(report, plan, manifest)
    assert manifest["status"] == "EXECUTED"
    assert evidence["status"] == "CANDIDATE_TRUE"
    first = evidence["signature"]
    runner.replay(plan, directory, manifest, deadline)
    second = verify_execution(report, plan, manifest)
    assert second["signature"] == first
    assert (directory / "manifest.json").exists()
    assert (directory / "run_2.stderr").exists()


def test_mocked_harness_cannot_confirm_from_runtime_evidence(tmp_path):
    source = tmp_path / "lib.c"
    source.write_text("int f(int *p) { return *p; }\n")
    report = BugReport(
        bug_type="NULL_DEREFERENCE", qualifier="p", severity="ERROR", line=1,
        column=-1, procedure="f", file=str(source), source_code=source.read_text(),
        resolved_path=source,
    )
    plan = ExperimentPlan.parse({
        "hypothesis": "call f with null", "mode": "harness",
        "mock_code": "int dependency(void) { return 1; }",
        "trigger_code": "int main(void) { return f((int*)0); }",
    })
    assert plan.mode == "harness"
    # Eligibility is checked independently of whether a sanitizer happens to fire.
    fake = {"status": "EXECUTED", "source_unchanged": True, "runs": [{
        "stderr": str(tmp_path / "none"), "stdout": str(tmp_path / "none"),
        "returncode": 1,
    }]}
    assert verify_execution(report, plan, fake)["checks"]["execution_context_eligible"] is False


@pytest.mark.skipif(not (shutil.which("clang") or shutil.which("gcc")),
                    reason="C compiler unavailable")
def test_court_completes_prosecutor_defense_replay_and_judgement(tmp_path):
    """The orchestration contract is testable without a provider or ground truth."""
    source = tmp_path / "bug.c"
    source.write_text(
        "#include <stddef.h>\n"
        "int main(void) { int *p = NULL; return *p; }\n"
    )
    report = report_for(source, line=2)

    class FakeAdapter:
        def call(self, system, user):
            if "You are CodeCourt's Prosecutor" in system:
                return '{"hypothesis":"main dereferences p","mode":"original","args":[],"stdin_data":"","file_inputs":{},"env_vars":{},"mock_code":"","trigger_code":"","assumptions":[],"expected_observation":"null dereference in main"}'
            return '{"summary":"No supported objection.","objections":[],"next_experiment":""}'

    from pipeline.codecourt.models import CourtOptions
    court = CodeCourt(tmp_path / "results", CourtOptions(max_rounds=2, max_executions=2,
                                                          timeout_seconds=5,
                                                          compile_timeout_seconds=20,
                                                          max_seconds=40),
                      adapter=FakeAdapter())
    result = court.adjudicate(report)
    assert result["verdict"] == "CONFIRMED_TRUE"
    assert result["executions"] == 2
    assert len(result["rounds"]) == 1
    assert list((tmp_path / "results" / "codecourt").glob("bug.c_2_NULL_DEREFERENCE_*/court_report.json"))
