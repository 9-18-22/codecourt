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

# Benchmark mode (runs on bundled sample C files)
python main.py --benchmark
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

from config import config
from pipeline.asan_verifier import ASanResult, ASanVerifier, Verdict
from pipeline.infer_parser import BugReport, InferParser, summarise_reports
from pipeline.llm_generator import LLMGenerator, LLMResult
from pipeline.reporter import Reporter
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
    ) -> None:
        self.parser    = InferParser(report_path, source_root, bug_types)
        self.generator = None if dry_run else LLMGenerator()
        self.verifier  = None if dry_run else ASanVerifier()
        self.reporter  = Reporter(output_dir)
        self.dry_run   = dry_run

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

        # 2. LLM + ASan per bug
        for report in reports:
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
            Verdict.TRUE_POSITIVE : "🔴 TRUE POSITIVE",
            Verdict.UNCONFIRMED   : "🟡 UNCONFIRMED",
            Verdict.COMPILE_ERROR : "⚙️  COMPILE ERROR",
            Verdict.TIMEOUT       : "⏱  TIMEOUT",
            Verdict.SKIPPED       : "⏭  SKIPPED",
        }.get(asan_result.verdict, str(asan_result.verdict))

        log.info("[%s] Verdict: %s  (crash_type=%s)",
                 report.id, verdict_emoji, asan_result.crash_type or "none")


# ── Benchmark helper ──────────────────────────────────────────────────────────

def run_benchmark() -> None:
    """
    Run the pipeline on the bundled benchmark samples.
    Requires that the samples have already been analysed with Infer.
    """
    benchmark_dir = Path(__file__).parent / "benchmarks"
    report_path   = benchmark_dir / "infer-out" / "report.json"
    source_root   = benchmark_dir / "samples"

    if not report_path.exists():
        print("\n[!] Benchmark Infer report not found.")
        print(f"    Please run Infer on the samples first:")
        print(f"    cd {benchmark_dir}")
        print(f"    bash ../scripts/run_infer.sh samples/ infer-out/")
        sys.exit(1)

    pipeline = Pipeline(
        report_path = str(report_path),
        source_root = str(source_root),
        output_dir  = str(benchmark_dir / "results"),
    )
    pipeline.run()


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
        "--benchmark",
        action="store_true",
        help="Run on bundled benchmark samples",
    )
    p.add_argument(
        "--log-file",
        help="Write detailed logs to this file",
    )
    return p


def main() -> None:
    args = build_parser().parse_args()

    # File logging (optional)
    if args.log_file:
        setup_file_logging(Path(args.log_file))

    # Validate API key early
    if not args.dry_run and not args.benchmark and not config.anthropic_api_key:
        print("[ERROR] ANTHROPIC_API_KEY is not set. "
              "Export it before running:\n  export ANTHROPIC_API_KEY=sk-...")
        sys.exit(1)

    if args.benchmark:
        run_benchmark()
        return

    if not args.report or not args.source_root:
        print("[ERROR] --report and --source-root are required unless --benchmark is used.")
        build_parser().print_help()
        sys.exit(1)

    pipeline = Pipeline(
        report_path = args.report,
        source_root = args.source_root,
        bug_types   = args.bug_types,
        output_dir  = args.output_dir,
        dry_run     = args.dry_run,
    )
    pipeline.run()


if __name__ == "__main__":
    main()
