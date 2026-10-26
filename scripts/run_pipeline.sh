#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 1 ] || [ "$#" -gt 3 ]; then
  echo "Usage: $0 SOURCE_ROOT [OUTPUT_DIR] [BUILD_CONFIG.json]" >&2
  exit 2
fi

script_dir="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
output_dir="${2:-results/realworld}"
build_config="${3:-}"

if [ ! -d "$1" ]; then
  echo "[ERROR] Source directory does not exist: $1" >&2
  exit 1
fi
source_root="$(cd "$1" && pwd)"

mkdir -p "$output_dir"
output_dir="$(cd "$output_dir" && pwd)"
infer_dir="$output_dir/infer-out"

echo "═══════════════════════════════════════════════════════"
echo "  CodeCourt end-to-end pipeline"
echo "  Source: $source_root"
echo "  Output: $output_dir"
echo "═══════════════════════════════════════════════════════"

"$script_dir/run_infer.sh" "$source_root" "$infer_dir"

command=(python3 "$script_dir/../main.py" --codecourt
         --report "$infer_dir/report.json"
         --source-root "$source_root"
         --output-dir "$output_dir")
if [ -n "$build_config" ]; then
  command+=(--build-config "$build_config")
fi
"${command[@]}"

echo ""
echo "✅ CodeCourt pipeline complete."
echo "   Summary: $output_dir/verification_report.json"
