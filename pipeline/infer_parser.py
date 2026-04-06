"""
Infer Report Parser
===================
Parses Infer's ``report.json`` and returns a list of structured BugReport
objects that the rest of the pipeline can consume.

Infer JSON schema (key fields)
-------------------------------
{
  "bug_type":  "NULL_DEREFERENCE",
  "qualifier": "null dereference of `ptr`",
  "severity":  "ERROR",
  "line":      42,
  "column":    -1,
  "procedure": "main",
  "file":      "src/foo.c",
  "bug_trace": [
    {
      "level":         0,
      "filename":      "src/foo.c",
      "line_number":   38,
      "column_number": -1,
      "description":   "ptr set to NULL"
    },
    ...
  ]
}
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional, Tuple

from config import config
from utils.file_utils import load_json, read_full_function, resolve_source_path
from utils.logger import get_logger

log = get_logger(__name__)


# ── Data models ──────────────────────────────────────────────────────────────

@dataclass
class TraceStep:
    filename:    str
    line_number: int
    description: str
    level:       int = 0


@dataclass
class BugReport:
    """One entry from Infer's report.json, enriched with source code."""

    # ── From Infer JSON ──────────────────────────────────────────────────────
    bug_type:   str
    qualifier:  str
    severity:   str
    line:       int
    column:     int
    procedure:  str
    file:       str
    bug_trace:  List[TraceStep] = field(default_factory=list)

    # ── Enriched by the parser ───────────────────────────────────────────────
    source_code:      str = ""          # function / window around bug
    resolved_path:    Optional[Path] = None
    raw:              dict = field(default_factory=dict)  # original JSON entry

    # ── Pipeline results (filled later) ─────────────────────────────────────
    llm_result:  Optional[dict] = None
    asan_result: Optional[dict] = None

    @property
    def id(self) -> str:
        return f"{self.file}:{self.line}:{self.bug_type}"

    @property
    def is_asan_verifiable(self) -> bool:
        return self.bug_type in config.asan_verifiable_types

    @property
    def needs_instrumentation(self) -> bool:
        return self.bug_type in config.instrumentation_types

    def trace_as_text(self) -> str:
        lines = []
        for i, step in enumerate(self.bug_trace):
            lines.append(
                f"  Step {i+1}: [{step.filename}:{step.line_number}] {step.description}"
            )
        return "\n".join(lines) if lines else "  (no trace available)"


# ── Parser ───────────────────────────────────────────────────────────────────

class InferParser:
    """
    Usage
    -----
    parser  = InferParser(report_path="infer-out/report.json", source_root="src/")
    reports = parser.parse()
    """

    SUPPORTED_TYPES = set(config.asan_verifiable_types) | set(
        config.instrumentation_types
    )

    def __init__(
        self,
        report_path: str | Path,
        source_root: Optional[str | Path] = None,
        bug_types: Optional[List[str]] = None,
    ) -> None:
        self.report_path = Path(report_path)
        self.source_root = Path(source_root) if source_root else None
        self.bug_types   = set(bug_types) if bug_types else self.SUPPORTED_TYPES

    # ── Public API ────────────────────────────────────────────────────────────

    def parse(self) -> List[BugReport]:
        """
        Load and parse the report.  Returns a list of filtered BugReport objects
        sorted by file and line number.
        """
        if not self.report_path.exists():
            raise FileNotFoundError(f"Infer report not found: {self.report_path}")

        raw_reports: list = load_json(self.report_path)
        log.info("Loaded %d raw reports from %s", len(raw_reports), self.report_path)

        reports: List[BugReport] = []
        for entry in raw_reports:
            report = self._parse_entry(entry)
            if report is None:
                continue
            self._enrich_source(report)
            reports.append(report)

        reports.sort(key=lambda r: (r.file, r.line))
        log.info(
            "Retained %d reports after filtering (types: %s)",
            len(reports),
            ", ".join(sorted(self.bug_types)),
        )
        return reports

    def parse_from_list(self, raw_reports: list) -> List[BugReport]:
        """Accept already-loaded list (useful in tests)."""
        reports = []
        for entry in raw_reports:
            report = self._parse_entry(entry)
            if report:
                self._enrich_source(report)
                reports.append(report)
        return reports

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _parse_entry(self, entry: dict) -> Optional[BugReport]:
        bug_type = entry.get("bug_type", "")
        if bug_type not in self.bug_types:
            log.debug("Skipping unsupported bug type: %s", bug_type)
            return None

        trace = [
            TraceStep(
                filename=step.get("filename", ""),
                line_number=step.get("line_number", 0),
                description=step.get("description", ""),
                level=step.get("level", 0),
            )
            for step in entry.get("bug_trace", [])
        ]

        return BugReport(
            bug_type  = bug_type,
            qualifier = entry.get("qualifier", ""),
            severity  = entry.get("severity", "ERROR"),
            line      = entry.get("line", 0),
            column    = entry.get("column", -1),
            procedure = entry.get("procedure", ""),
            file      = entry.get("file", ""),
            bug_trace = trace,
            raw       = entry,
        )

    def _enrich_source(self, report: BugReport) -> None:
        """Resolve the source file and attach a relevant code snippet."""
        path = resolve_source_path(report.file, self.source_root)
        if path is None:
            log.warning("Source not found for bug %s", report.id)
            return

        report.resolved_path = path
        report.source_code   = read_full_function(path, report.line)
        log.debug("Attached source (%d chars) for %s", len(report.source_code), report.id)


# ── Pretty printing ───────────────────────────────────────────────────────────

def summarise_reports(reports: List[BugReport]) -> str:
    lines = [f"{'ID':<50} {'TYPE':<25} {'SEVERITY'}", "-" * 90]
    for r in reports:
        lines.append(f"{r.id:<50} {r.bug_type:<25} {r.severity}")
    return "\n".join(lines)
