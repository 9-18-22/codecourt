"""
Filesystem helpers used across the pipeline.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
from typing import Any, List, Optional, Tuple

from utils.logger import get_logger

log = get_logger(__name__)


# ── Source code helpers ──────────────────────────────────────────────────────

def read_source_window(
    filepath: str | Path,
    center_line: int,
    window: int = 60,
) -> Tuple[str, int, int]:
    """
    Read ±window lines around *center_line* from *filepath*.

    Returns
    -------
    (code_snippet, first_line_no, last_line_no)
    """
    path = Path(filepath)
    if not path.exists():
        log.warning("Source file not found: %s", path)
        return ("", 0, 0)

    lines = path.read_text(errors="replace").splitlines(keepends=True)
    total = len(lines)
    start = max(0, center_line - window - 1)
    end   = min(total, center_line + window)

    snippet = "".join(lines[start:end])
    return snippet, start + 1, end


def read_full_function(filepath: str | Path, center_line: int) -> str:
    """
    Attempt to extract the complete function that contains *center_line*.
    Falls back to read_source_window if heuristics fail.
    """
    path = Path(filepath)
    if not path.exists():
        return ""

    lines = path.read_text(errors="replace").splitlines()
    n = len(lines)
    target = center_line - 1       # 0-indexed

    # Walk backwards to find function opening brace
    brace_depth = 0
    func_start = target
    for i in range(target, -1, -1):
        brace_depth += lines[i].count("{") - lines[i].count("}")
        if brace_depth > 0:
            func_start = i
            break

    # Walk forwards to find closing brace
    brace_depth = 0
    func_end = target
    for i in range(func_start, n):
        brace_depth += lines[i].count("{") - lines[i].count("}")
        if brace_depth == 0:
            func_end = i
            break

    # Annotate the bug line
    annotated: List[str] = []
    for i, line in enumerate(lines[func_start : func_end + 1], start=func_start + 1):
        marker = "  // <<<< BUG LINE" if i == center_line else ""
        annotated.append(f"{i:4d} | {line}{marker}")

    return "\n".join(annotated)


# ── JSON helpers ─────────────────────────────────────────────────────────────

def load_json(path: str | Path) -> Any:
    with open(path, encoding="utf-8") as f:
        return json.load(f)


def save_json(data: Any, path: str | Path, *, indent: int = 2) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=indent, ensure_ascii=False)
    log.debug("Saved JSON → %s", p)


# ── Path resolution ──────────────────────────────────────────────────────────

def resolve_source_path(
    reported_path: str,
    source_root: Optional[str | Path] = None,
) -> Optional[Path]:
    """
    Try to resolve the file path reported by Infer to an actual file.
    Infer sometimes reports paths relative to the project root.
    """
    p = Path(reported_path)
    if p.is_absolute() and p.exists():
        return p

    if source_root:
        candidate = Path(source_root) / p
        if candidate.exists():
            return candidate

    if p.exists():
        return p

    log.warning("Cannot resolve source path: %s", reported_path)
    return None
