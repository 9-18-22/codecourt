"""
Benchmark runner
================
Runs the full pipeline on the bundled sample C files and prints a summary.

Usage
-----
  cd static-verifier/
  python benchmarks/run_benchmark.py
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make sure the project root is on sys.path when run as a script
sys.path.insert(0, str(Path(__file__).parent.parent))

from main import Pipeline

BENCHMARK_DIR = Path(__file__).parent
REPORT_PATH   = BENCHMARK_DIR / "infer-out" / "report.json"
SOURCE_ROOT   = BENCHMARK_DIR / "samples"
OUTPUT_DIR    = BENCHMARK_DIR / "results"


def main() -> None:
    if not REPORT_PATH.exists():
        print(f"\n[!] Infer report not found at {REPORT_PATH}")
        print("    Please run Infer first (see scripts/run_infer.sh) or use the")
        print("    bundled mock report.json that is already provided.\n")

    pipeline = Pipeline(
        report_path = str(REPORT_PATH),
        source_root = str(SOURCE_ROOT),
        output_dir  = str(OUTPUT_DIR),
    )
    results = pipeline.run()

    stats = results.get("statistics", {})
    tp_rate = stats.get("true_positive_rate", 0)
    print(f"\n✅ Benchmark complete. True Positive Rate: {tp_rate:.1f}%\n")


if __name__ == "__main__":
    main()
