"""Deterministic checks over persisted compiler and sanitizer evidence."""

from pathlib import Path
import re

from pipeline.asan_verifier import (
    _ASAN_ERROR_RE,
    _UBSAN_ERROR_RE,
    _LSAN_ERROR_RE,
    _LSAN_DETECT_RE,
    _LSAN_LEAK_SUMMARY_RE,
    _crash_matches_bug_type,
    _extract_user_code_frames,
    _procedure_in_frame,
)


def _read(path, limit=None):
    value = Path(path).read_text(errors="replace") if path and Path(path).exists() else ""
    return value if limit is None else value[:limit]


def _crash_type(output):
    match = _ASAN_ERROR_RE.search(output)
    if match:
        return match.group(1).strip()
    match = _UBSAN_ERROR_RE.search(output)
    if match:
        return "ubsan:" + match.group(1).strip()
    match = _LSAN_ERROR_RE.search(output)
    if match:
        return "leak:" + match.group(1).strip()
    if _LSAN_DETECT_RE.search(output) or _LSAN_LEAK_SUMMARY_RE.search(output):
        return "leak:detected memory leaks"
    return ""


def verify_execution(report, plan, manifest):
    checks = {}
    checks["experiment_executed"] = manifest.get("status") == "EXECUTED"
    checks["source_unchanged"] = manifest.get("source_unchanged") is True
    if not checks["experiment_executed"]:
        return {
            "status": "INVALID" if manifest.get("status") == "PREPARATION_ERROR" else "INCONCLUSIVE",
            "checks": checks, "crash_type": "", "frames": [],
            "reason": manifest.get("status", "missing execution status"),
        }
    run = manifest["runs"][-1]
    output = _read(run.get("stderr")) + "\n" + _read(run.get("stdout"))
    crash_type = _crash_type(output)
    frames = _extract_user_code_frames(output)
    checks["sanitizer_report_present"] = bool(crash_type)
    checks["bug_type_matches"] = bool(crash_type) and _crash_matches_bug_type(crash_type, report.bug_type)
    source = Path(report.resolved_path).resolve()
    source_frames = [(func, path, line) for func, path, line in frames
                     if Path(path).name == source.name]
    trace_lines = {report.line, *[step.line_number for step in report.bug_trace
                                  if Path(step.filename).name == source.name]}
    checks["original_file_frame"] = bool(source_frames)
    checks["reported_location_matches"] = any(
        abs(line - target) <= 2 for _, _, line in source_frames for target in trace_lines if target > 0
    )
    checks["procedure_matches"] = (
        any(_procedure_in_frame(report.procedure, func) for func, _, _ in source_frames)
        if report.procedure else bool(source_frames)
    )
    checks["generated_frame_is_not_target"] = not any(
        Path(path).name in {"mock.c", "harness.c"} for _, path, _ in source_frames
    )
    # A complete-source harness is acceptable for libraries if it does not replace
    # dependencies. Isolated functions and mocked environments remain supporting evidence.
    checks["execution_context_eligible"] = (
        plan.mode == "original" or (plan.mode == "harness" and not plan.mock_code.strip())
    )
    required = ("source_unchanged", "sanitizer_report_present", "bug_type_matches",
                "original_file_frame", "reported_location_matches", "procedure_matches",
                "execution_context_eligible")
    candidate = all(checks[name] for name in required)
    signature = {
        "crash_type": crash_type,
        "top_original_frame": source_frames[0] if source_frames else None,
    }
    return {
        "status": "CANDIDATE_TRUE" if candidate else "INCONCLUSIVE",
        "checks": checks, "crash_type": crash_type,
        "frames": [{"function": f, "file": p, "line": n} for f, p, n in frames[:20]],
        "signature": signature,
        "reason": "all confirmation checks passed" if candidate else "required evidence is missing",
    }


def validate_defense(defense, directory):
    allowed = {
        "original.c": directory / "original.c",
        "mock.c": directory / "mock.c",
        "harness.c": directory / "harness.c",
        "run.stderr": directory / "run_1.stderr",
        "run.stdout": directory / "run_1.stdout",
        "compile.stderr": directory / "compile.stderr",
    }
    valid, rejected = [], []
    for objection in defense.get("objections", []):
        citations = []
        for citation in objection.get("citations", []):
            path = allowed.get(citation.get("artifact"))
            lines = _read(path).splitlines() if path else []
            line = citation.get("line", 0)
            ok = bool(path and 1 <= line <= len(lines) and citation.get("quote", "") in lines[line - 1])
            citations.append({**citation, "verified": ok})
        item = {**objection, "citations": citations,
                "citation_status": "VERIFIED" if citations and all(c["verified"] for c in citations) else "REJECTED"}
        (valid if item["citation_status"] == "VERIFIED" else rejected).append(item)
    return {"summary": defense.get("summary", ""), "verified_objections": valid,
            "rejected_objections": rejected, "next_experiment": defense.get("next_experiment", "")}


def artifact_excerpt(directory):
    names = {
        "original.c": directory / "original.c",
        "mock.c": directory / "mock.c",
        "harness.c": directory / "harness.c",
        "run.stderr": directory / "run_1.stderr",
        "run.stdout": directory / "run_1.stdout",
        "compile.stderr": directory / "compile.stderr",
    }
    result = {}
    for name, path in names.items():
        text = _read(path)
        lines = text.splitlines()
        if name == "original.c" and len(lines) > 500:
            # Warning-centered source is supplied first by the court context. Keep
            # both ends here for includes, globals and footer code without lying
            # about original line numbers.
            indexes = list(range(0, 250)) + list(range(len(lines) - 250, len(lines)))
        else:
            indexes = list(range(min(len(lines), 800)))
        result[name] = "\n".join(f"{i + 1}: {lines[i]}" for i in indexes)
    return result
