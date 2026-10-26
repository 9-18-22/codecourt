"""
Static Verifier Pipeline  –  Main Entry Point
==============================================

Usage examples
--------------
# Run full pipeline on an Infer report
python main.py --report infer-out/report.json --source-root src/

# Limit to specific bug types
python main.py --report report.json --source-root . --bug-types NULL_DEREFERENCE USE_AFTER_FREE

# Dry-run: parse and display bugs without calling LLM/ASan
python main.py --report report.json --source-root . --dry-run

# CodeCourt mode for a real-world project
python main.py --codecourt --report infer-out/report.json --source-root src/
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from config import config
from pipeline.asan_verifier import ASanResult, ASanVerifier, Verdict, is_tp_verdict
from pipeline.infer_parser import BugReport, InferParser, summarise_reports
from pipeline.llm_generator import LLMGenerator, LLMResult
from pipeline.reporter import Reporter
from pipeline.codecourt import CodeCourt, CourtOptions
from utils.logger import get_logger, setup_file_logging

log = get_logger(__name__)


# ── Orchestrator ──────────────────────────────────────────────────────────────

class Pipeline:
    """
    Connects InferParser → LLMGenerator → ASanVerifier → Reporter.
    """

    def __init__(
        self,
        report_path: str,
        source_root: str,
        bug_types: list[str] | None = None,
        output_dir: str = "results",
        dry_run: bool = False,
        codecourt: bool = False,
        court_options: CourtOptions | None = None,
    ) -> None:
        self.parser    = InferParser(report_path, source_root, bug_types)
        self.codecourt = codecourt
        self.generator = None if dry_run or codecourt else LLMGenerator()
        self.verifier  = None if dry_run or codecourt else ASanVerifier()
        self.reporter  = Reporter(output_dir)
        self.dry_run   = dry_run
        self.court = CodeCourt(output_dir, court_options) if codecourt and not dry_run else None

    def run(self) -> dict:
        # 1. Parse Infer report
        reports = self.parser.parse()
        if not reports:
            log.warning("No actionable bug reports found.")
            return {}

        print(f"\n{'─'*60}")
        print(summarise_reports(reports))
        print(f"{'─'*60}\n")

        if self.dry_run:
            log.info("Dry-run mode: skipping LLM and ASan steps.")
            return self.reporter.generate(reports)

        # 2. Validate each warning using CodeCourt or the legacy baseline.
        for report in reports:
            if self.codecourt:
                self.court.adjudicate(report)
            else:
                self._process_bug(report)

        # 3. Generate report
        return self.reporter.generate(reports)

    def _process_bug(self, report: BugReport) -> None:
        log.info("Processing bug: %s", report.id)

        # ── Step 2: LLM input generation ─────────────────────────────────────
        llm_result: LLMResult | None = self.generator.generate(report)
        if llm_result is None:
            log.warning("[%s] LLM generation failed; skipping verification.", report.id)
            report.llm_result = None
            return

        report.llm_result = llm_result.to_dict()

        # ── Step 3: ASan dynamic verification ────────────────────────────────
        asan_result: ASanResult = self.verifier.verify(report, llm_result)
        report._asan_obj  = asan_result           # keep object for reporter
        report.asan_result = asan_result.to_dict()

        verdict_emoji = {
            Verdict.STRICT_TP       : "🔴 STRICT TP",
            Verdict.FAMILY_TP       : "🟠 FAMILY TP",
            Verdict.CROSS_DETECTION : "🟣 CROSS DETECTION",
            Verdict.LIKELY_FP       : "🟡 LIKELY FP",
            Verdict.COMPILE_ERROR   : "⚙️  COMPILE ERROR",
            Verdict.RUNTIME_ERROR   : "⚙️  RUNTIME ERROR",
            Verdict.TIMEOUT         : "⏱  TIMEOUT",
            Verdict.SKIPPED         : "⏭  SKIPPED",
        }.get(asan_result.verdict, str(asan_result.verdict))

        log.info("[%s] Verdict: %s  (crash_type=%s)",
                 report.id, verdict_emoji, asan_result.crash_type or "none")


# ── CLI ───────────────────────────────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="static-verifier",
        description="Verify Infer static analysis warnings with LLM + ASan",
    )
    p.add_argument("--report",      help="Path to Infer's report.json")
    p.add_argument("--source-root", help="Root directory of the source code")
    p.add_argument(
        "--bug-types",
        nargs="+",
        help="Limit to these bug types (space-separated)",
    )
    p.add_argument(
        "--output-dir",
        default="results",
        help="Directory for output reports (default: results/)",
    )
    p.add_argument(
        "--dry-run",
        action="store_true",
        help="Parse and list bugs only; skip LLM and ASan",
    )
    p.add_argument(
        "--log-file",
        help="Write detailed logs to this file",
    )

    p.add_argument(
        "--codecourt", action="store_true",
        help="Run execution-evidence adversarial validation for real-world code",
    )
    p.add_argument(
        "--max-rounds", type=int, default=3,
        help="Maximum CodeCourt prosecutor/defense rounds (default: 3)",
    )
    p.add_argument(
        "--max-executions", type=int, default=6,
        help="Maximum program executions per warning, including replays",
    )
    p.add_argument("--court-time-budget", type=float, default=180,
                   help="Maximum seconds per warning")
    p.add_argument("--build-config", help="JSON file with include_dirs, extra_sources, compile_flags, link_flags")
    return p


def main() -> None:
    args = build_parser().parse_args()

    # File logging (optional)
    if args.log_file:
        setup_file_logging(Path(args.log_file))

    config.dataset_mode = "generic_realworld"

    # Validate API key early
    if not args.dry_run and not config.active_api_key:
        print("[ERROR] API_KEY is not set. "
              "Export it before running:\n  export API_KEY=...")
        sys.exit(1)

    if not args.report or not args.source_root:
        print("[ERROR] --report and --source-root are required.")
        build_parser().print_help()
        sys.exit(1)

    build_config = {}
    if args.build_config:
        import json
        try:
            build_config = json.loads(Path(args.build_config).read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            print(f"[ERROR] Invalid --build-config: {exc}")
            sys.exit(1)
    try:
        court_options = CourtOptions(max_rounds=args.max_rounds,
                                     max_executions=args.max_executions,
                                     max_seconds=args.court_time_budget,
                                     timeout_seconds=config.timeout_seconds,
                                     build_config=build_config)
    except ValueError as exc:
        print(f"[ERROR] Invalid CodeCourt option: {exc}")
        sys.exit(1)

    pipeline = Pipeline(
        report_path = args.report,
        source_root = args.source_root,
        bug_types   = args.bug_types,
        output_dir  = args.output_dir,
        dry_run     = args.dry_run,
        codecourt   = args.codecourt,
        court_options = court_options,
    )
    pipeline.run()


if __name__ == "__main__":
    main()
