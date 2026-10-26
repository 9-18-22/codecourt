#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# run_infer.sh
#
# Runs Facebook Infer on a C/C++ source directory using Docker.
# Outputs report.json to the specified output directory.
#
# Usage:
#   bash scripts/run_infer.sh <source_dir> <output_dir>
#
# Example:
#   bash scripts/run_infer.sh /project /project/infer-out/
# ─────────────────────────────────────────────────────────────────────────────

set -euo pipefail

SOURCE_DIR="${1:?Usage: $0 <source_dir> <output_dir>}"
OUTPUT_DIR="${2:?Usage: $0 <source_dir> <output_dir>}"

ABS_SOURCE="$(realpath "$SOURCE_DIR")"
mkdir -p "$OUTPUT_DIR"
ABS_OUTPUT="$(cd "$OUTPUT_DIR" && pwd)"

echo "═══════════════════════════════════════════════════════"
echo "  Running Infer on: $ABS_SOURCE"
echo "  Output dir:       $ABS_OUTPUT"
echo "═══════════════════════════════════════════════════════"

# ── Detect all C/C++ files ────────────────────────────────────────────────────
C_FILES=$(find "$ABS_SOURCE" -name "*.c" -o -name "*.cpp" | sed "s|$ABS_SOURCE/||" | tr '\n' ' ')

if [ -z "$C_FILES" ]; then
    echo "[!] No C/C++ files found in $ABS_SOURCE"
    exit 1
fi
echo "Found source files: $C_FILES"

# ── Run Infer via Docker ──────────────────────────────────────────────────────
docker run --rm \
    -v "$ABS_SOURCE":/src \
    -v "$ABS_OUTPUT":/out \
    -w /src \
    facebook/infer:latest \
    bash -c "
        infer run \
            --results-dir /out \
            -- clang -c $C_FILES
    "

echo ""
echo "✅ Infer analysis complete."
echo "   report.json → $ABS_OUTPUT/report.json"

# ── Summary ───────────────────────────────────────────────────────────────────
if command -v python3 &>/dev/null; then
    python3 - "$ABS_OUTPUT/report.json" <<'EOF'
import json, sys
try:
    with open(sys.argv[1]) as f:
        bugs = json.load(f)
    print(f"\n   Total bugs found: {len(bugs)}")
    from collections import Counter
    types = Counter(b['bug_type'] for b in bugs)
    for t, c in types.most_common():
        print(f"   {t:<35} {c}")
except Exception as e:
    print(f"   (could not summarise report: {e})")
EOF
fi
