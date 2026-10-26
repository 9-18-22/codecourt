"""
Reporter
=========
Collects per-bug results and produces:
  1. A JSON verification report
  2. A human-readable text summary printed to stdout
"""

from __future__ import annotations

import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import List

from pipeline.asan_verifier import ASanResult, Verdict, is_tp_verdict
from pipeline.infer_parser import BugReport
from utils.file_utils import save_json
from utils.logger import get_logger

log = get_logger(__name__)


# ── Per-bug record ────────────────────────────────────────────────────────────

def _make_record(report: BugReport) -> dict:
    llm  = report.llm_result or {}
    asan: ASanResult | None = getattr(report, "_asan_obj", None)
    attempt_history = llm.get("_attempt_history", []) if isinstance(llm, dict) else []
    file_inputs = llm.get("file_inputs", {}) if isinstance(llm.get("file_inputs", {}), dict) else {}

    court = getattr(report, "court_result", None)
    return {
        "id":          report.id,
        "bug_type":    report.bug_type,
        "file":        report.file,
        "line":        report.line,
        "procedure":   report.procedure,
        "qualifier":   report.qualifier,
        # LLM
        "llm_success":    bool(llm),
        "llm_confidence": llm.get("confidence", "N/A"),
        "llm_input_type": llm.get("input_type", "N/A"),
        "llm_reasoning":  llm.get("reasoning", "")[:300],
        "llm_attempt":    llm.get("attempt", 0),
        "llm_attempt_count": len(attempt_history) if attempt_history else (llm.get("attempt", 0) or 0),
        "llm_attempt_history": attempt_history,
        "llm_retry_required":  llm.get("_retry_required", False),
        "llm_validation_errors": llm.get("_validation_errors", []),
        "llm_args":       llm.get("args", []),
        "llm_stdin_data": (llm.get("stdin_data", "") or "")[:1000],
        "llm_file_inputs": {
            str(name): str(content)[:1000]
            for name, content in file_inputs.items()
        },
        "llm_expected_crash": llm.get("expected_crash", ""),
        "llm_needs_instrumentation": llm.get("needs_instrumentation", False),
        # ASan
        "verdict":     asan.verdict.value if asan else "N/A",
        "crash_type":  asan.crash_type    if asan else "",
        "crash_line":  asan.crash_line    if asan else "",
        "compile_cmd": asan.compile_cmd   if asan else "",
        "run_cmd":     asan.run_cmd       if asan else "",
        "match_level":   asan.match_level   if asan else "",
        "type_matched":  asan.type_matched  if asan else False,
        "matched_frame": asan.matched_frame if asan else "",
        "matched_line":  asan.matched_line  if asan else 0,
        # CodeCourt (real-world mode)
        "court_verdict": court.get("verdict", "N/A") if court else "N/A",
        "court_reason": court.get("reason", "") if court else "",
        "court_rounds": len(court.get("rounds", [])) if court else 0,
        "court_executions": court.get("executions", 0) if court else 0,
        "court_result": court,
    }


# ── Reporter ──────────────────────────────────────────────────────────────────

class Reporter:
    def __init__(self, output_dir: str | Path = "results") -> None:
        self.output_dir = Path(output_dir)
        self.output_dir.mkdir(parents=True, exist_ok=True)

    # ── Public API ────────────────────────────────────────────────────────────

    def generate(self, reports: List[BugReport], report_filename: str = "verification_report.json") -> dict:
        records = [_make_record(r) for r in reports]
        stats   = self._compute_stats(records)

        full_report = {
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "statistics":   stats,
            "results":      records,
        }

        out_path = self.output_dir / report_filename
        save_json(full_report, out_path)
        log.info("Report saved → %s", out_path)

        self._print_summary(stats, records)
        return full_report

    # ── Stats ─────────────────────────────────────────────────────────────────

    @staticmethod
    def _compute_stats(records: list) -> dict:
        total        = len(records)
        llm_ok       = sum(1 for r in records if r["llm_success"])
        verdicts     = Counter(r["verdict"] for r in records)
        strict_tp    = (
            verdicts.get(Verdict.STRICT_TP.value, 0)
            + verdicts.get("TP", 0)
            + verdicts.get("TRUE_POSITIVE", 0)
        )
        family_tp    = verdicts.get(Verdict.FAMILY_TP.value, 0)
        tp           = strict_tp + family_tp
        cross        = verdicts.get(Verdict.CROSS_DETECTION.value, 0)
        likely_fp    = verdicts.get(Verdict.LIKELY_FP.value, 0) + verdicts.get("UNCONFIRMED", 0)
        unconfirmed  = likely_fp
        bug_types    = Counter(r["bug_type"] for r in records)
        court_verdicts = Counter(r["court_verdict"] for r in records if r["court_verdict"] != "N/A")
        verdict_denominator = tp + cross + likely_fp
        type_consistent_tp = sum(
            1 for r in records
            if is_tp_verdict(r["verdict"]) and r.get("type_matched") is True
        )
        type_mismatch_tp = tp - type_consistent_tp

        stats = {
            "total_bugs":            total,
            "llm_success_count":     llm_ok,
            "llm_success_rate":      _pct(llm_ok, total),
            "true_positive_count":   tp,
            "true_positive_rate":    _pct(tp, total),
            "type_consistent_tp_count": type_consistent_tp,
            "type_consistent_tp_rate": _pct(type_consistent_tp, total),
            "type_consistent_tp_share_of_tp": _pct(type_consistent_tp, tp),
            "type_mismatch_tp_count": type_mismatch_tp,
            "type_mismatch_tp_rate": _pct(type_mismatch_tp, total),
            "strict_tp_count":       strict_tp,
            "strict_tp_rate":        _pct(strict_tp, total),
            "family_tp_count":       family_tp,
            "family_tp_rate":        _pct(family_tp, total),
            "strict_tp_share_of_tp": _pct(strict_tp, tp),
            "family_tp_share_of_tp": _pct(family_tp, tp),
            "cross_detection_count": cross,
            "cross_detection_rate":  _pct(cross, total),
            "likely_fp_count":       likely_fp,
            "likely_fp_rate":        _pct(likely_fp, total),
            "unconfirmed_count":     unconfirmed,
            "unconfirmed_rate":      _pct(unconfirmed, total),
            "fp_reduction_rate":     _pct(tp, verdict_denominator),
            "verdicts":              dict(verdicts),
            "bug_type_breakdown":    dict(bug_types),
            "court_verdicts":        dict(court_verdicts),
        }

        return stats

    # ── Pretty printing ───────────────────────────────────────────────────────

    @staticmethod
    def _print_summary(stats: dict, records: list) -> None:
        sep = "=" * 70
        print(f"\n{sep}")
        print("  STATIC VERIFIER  –  PIPELINE RESULTS")
        print(sep)
        print(f"  Total bugs analysed     : {stats['total_bugs']}")
        print(f"  LLM input generation    : {stats['llm_success_count']} / {stats['total_bugs']}"
              f"  ({stats['llm_success_rate']:.1f}%)")
        if stats.get("court_verdicts"):
            print("  CodeCourt verdicts:")
            for verdict, count in sorted(stats["court_verdicts"].items()):
                print(f"    {verdict:<26} {count}")
        print(f"  True Positives (ASan TP): {stats['true_positive_count']}"
              f"  ({stats['true_positive_rate']:.1f}%)")
        print(f"    Type-consistent TP    : {stats['type_consistent_tp_count']}"
              f"  ({stats['type_consistent_tp_rate']:.1f}% of all, "
              f"{stats['type_consistent_tp_share_of_tp']:.1f}% of TP)")
        print(f"    Type-mismatch TP      : {stats['type_mismatch_tp_count']}"
              f"  ({stats['type_mismatch_tp_rate']:.1f}% of all)")
        print(f"    STRICT_TP             : {stats['strict_tp_count']}"
              f"  ({stats['strict_tp_rate']:.1f}% of all, "
              f"{stats['strict_tp_share_of_tp']:.1f}% of TP)")
        print(f"    FAMILY_TP             : {stats['family_tp_count']}"
              f"  ({stats['family_tp_rate']:.1f}% of all, "
              f"{stats['family_tp_share_of_tp']:.1f}% of TP)")
        print(f"  Cross Detection         : {stats['cross_detection_count']}"
              f"  ({stats['cross_detection_rate']:.1f}%)")
        print(f"  Likely FP               : {stats['likely_fp_count']}"
              f"  ({stats['likely_fp_rate']:.1f}%)")
        print(f"  Unconfirmed (FP cand.)  : {stats['unconfirmed_count']}"
              f"  ({stats['unconfirmed_rate']:.1f}%)")
        print(f"  FP Reduction Rate       : {stats['fp_reduction_rate']:.1f}%")

        print()
        print("  Bug type breakdown:")
        for btype, cnt in stats["bug_type_breakdown"].items():
            print(f"    {btype:<30} {cnt}")
        print()
        print("  Per-bug results:")
        court_mode = any(r["court_verdict"] != "N/A" for r in records)
        if court_mode:
            print(f"  {'FILE:LINE':<40} {'TYPE':<22} {'ROUNDS':<7} {'VERDICT'}")
        else:
            print(f"  {'FILE:LINE':<40} {'TYPE':<22} {'LLM':<6} {'VERDICT'}")
        print("  " + "-" * 85)
        for r in records:
            loc = f"{r['file']}:{r['line']}"[-39:]
            llm = "✓" if r["llm_success"] else "✗"
            if court_mode:
                print(f"  {loc:<40} {r['bug_type']:<22} {r['court_rounds']:<7} {r['court_verdict']}")
            else:
                print(f"  {loc:<40} {r['bug_type']:<22} {llm:<6} {r['verdict']}")
        print(sep + "\n")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _pct(num: int, denom: int) -> float:
    return round(num / denom * 100, 2) if denom else 0.0
