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

from pipeline.asan_verifier import ASanResult, Verdict
from pipeline.infer_parser import BugReport
from utils.file_utils import save_json
from utils.logger import get_logger

log = get_logger(__name__)


# ── Per-bug record ────────────────────────────────────────────────────────────

def _make_record(report: BugReport) -> dict:
    llm  = report.llm_result or {}
    asan: ASanResult | None = getattr(report, "_asan_obj", None)

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
        # ASan
        "verdict":     asan.verdict.value if asan else "N/A",
        "crash_type":  asan.crash_type    if asan else "",
        "crash_line":  asan.crash_line    if asan else "",
        "compile_cmd": asan.compile_cmd   if asan else "",
        "run_cmd":     asan.run_cmd       if asan else "",
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
        tp           = verdicts.get(Verdict.TRUE_POSITIVE.value, 0)
        unconfirmed  = verdicts.get(Verdict.UNCONFIRMED.value, 0)
        bug_types    = Counter(r["bug_type"] for r in records)

        return {
            "total_bugs":            total,
            "llm_success_count":     llm_ok,
            "llm_success_rate":      _pct(llm_ok, total),
            "true_positive_count":   tp,
            "true_positive_rate":    _pct(tp, total),
            "unconfirmed_count":     unconfirmed,
            "unconfirmed_rate":      _pct(unconfirmed, total),
            "fp_reduction_rate":     _pct(tp, tp + unconfirmed) if (tp + unconfirmed) else 0.0,
            "verdicts":              dict(verdicts),
            "bug_type_breakdown":    dict(bug_types),
        }

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
        print(f"  True Positives (ASan TP): {stats['true_positive_count']}"
              f"  ({stats['true_positive_rate']:.1f}%)")
        print(f"  Unconfirmed (FP cand.)  : {stats['unconfirmed_count']}"
              f"  ({stats['unconfirmed_rate']:.1f}%)")
        print(f"  FP Reduction Rate       : {stats['fp_reduction_rate']:.1f}%")
        print()
        print("  Bug type breakdown:")
        for btype, cnt in stats["bug_type_breakdown"].items():
            print(f"    {btype:<30} {cnt}")
        print()
        print("  Per-bug results:")
        print(f"  {'FILE:LINE':<40} {'TYPE':<22} {'LLM':<6} {'VERDICT'}")
        print("  " + "-" * 80)
        for r in records:
            loc  = f"{r['file']}:{r['line']}"[-39:]
            llm  = "✓" if r["llm_success"] else "✗"
            print(f"  {loc:<40} {r['bug_type']:<22} {llm:<6} {r['verdict']}")
        print(sep + "\n")


# ── Helpers ───────────────────────────────────────────────────────────────────

def _pct(num: int, denom: int) -> float:
    return round(num / denom * 100, 2) if denom else 0.0
