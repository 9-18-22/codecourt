#!/usr/bin/env bash
set -euo pipefail

if [ "$#" -lt 2 ] || [ "$#" -gt 4 ]; then
  echo "Usage: $0 INFER_REPORT.json SOURCE_ROOT [OUTPUT_DIR] [BUILD_CONFIG.json]" >&2
  exit 2
fi

report_path="$1"
source_root="$2"
output_dir="${3:-results/realworld}"
build_config="${4:-}"

command=(python3 main.py --codecourt --report "$report_path" --source-root "$source_root" --output-dir "$output_dir")
if [ -n "$build_config" ]; then
  command+=(--build-config "$build_config")
fi
"${command[@]}"
