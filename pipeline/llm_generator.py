"""
LLM Input Generator
====================
Given a BugReport, asks Claude to produce concrete input values that will
drive the program along the faulty execution path and trigger the bug.

Output contract (JSON returned by LLM)
---------------------------------------
{
  "reasoning":        "step-by-step explanation",
  "input_type":       "args" | "stdin" | "file" | "none",
  "args":             ["val1", "val2"],
  "stdin_data":       "some input string",
  "file_inputs":      { "filename.txt": "file content" },
  "env_vars":         { "VAR": "value" },
  "expected_crash":   "SIGSEGV" | "heap-use-after-free" | ...,
  "confidence":       "high" | "medium" | "low",
  "needs_instrumentation": false,
  "instrumentation_code":  null
}
"""

from __future__ import annotations

import json
import re
import time
from typing import Optional

import anthropic

from config import config
from pipeline.infer_parser import BugReport
from utils.logger import get_logger

log = get_logger(__name__)


# ── Prompt templates ─────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a security researcher and expert C/C++ programmer.
Your task is to analyse a bug report from Facebook Infer (a static analysis tool)
and generate CONCRETE input values that, when provided to the program, will
trigger the reported memory bug at runtime.

Rules:
- Output ONLY a single valid JSON object — no markdown fences, no extra text.
- Be precise: reason about every branch condition in the bug trace.
- If the bug cannot be triggered through external inputs alone, set
  "needs_instrumentation" to true and supply "instrumentation_code" with the
  C assertion (e.g. `assert(x != 0);`) to insert at the bug line.
- Confidence: "high" if you are certain the inputs trigger the bug,
  "medium" if likely, "low" if the path is complex and you are guessing.
"""

_USER_PROMPT_TEMPLATE = """\
## Static Analysis Bug Report

| Field     | Value |
|-----------|-------|
| Bug Type  | {bug_type} |
| Qualifier | {qualifier} |
| File      | {file} |
| Line      | {line} |
| Procedure | {procedure} |

## Bug Trace (execution path leading to the bug)
{trace}

## Source Code (line numbers included; bug line marked with <<<< BUG LINE)
```c
{source_code}
```

## Task
Produce a JSON object with the following fields:
- "reasoning"         - step-by-step explanation of how the inputs trigger the bug
- "input_type"        - one of: "args", "stdin", "file", "none"
- "args"              - list of command-line argument strings (empty list if unused)
- "stdin_data"        - string to feed to stdin (empty string if unused)
- "file_inputs"       - dict mapping filename to content (empty dict if unused)
- "env_vars"          - dict of environment variables (empty dict if unused)
- "expected_crash"    - expected ASan / crash signal
- "confidence"        - "high" or "medium" or "low"
- "needs_instrumentation" - true if ASan alone cannot catch this bug type
- "instrumentation_code"  - C assertion string to insert at the bug line (null if not needed)

Respond with ONLY the JSON object.
"""


# ── Result model ──────────────────────────────────────────────────────────────

class LLMResult:
    """Wraps the parsed response from Claude."""

    def __init__(self, raw_json: dict, attempt: int) -> None:
        self.reasoning              : str        = raw_json.get("reasoning", "")
        self.input_type             : str        = raw_json.get("input_type", "none")
        self.args                   : list[str]  = raw_json.get("args", [])
        self.stdin_data             : str        = raw_json.get("stdin_data", "")
        self.file_inputs            : dict       = raw_json.get("file_inputs", {})
        self.env_vars               : dict       = raw_json.get("env_vars", {})
        self.expected_crash         : str        = raw_json.get("expected_crash", "")
        self.confidence             : str        = raw_json.get("confidence", "low")
        self.needs_instrumentation  : bool       = raw_json.get("needs_instrumentation", False)
        self.instrumentation_code   : str | None = raw_json.get("instrumentation_code")
        self.attempt                : int        = attempt
        self.raw                    : dict       = raw_json

    def to_dict(self) -> dict:
        return {**self.raw, "attempt": self.attempt}


# ── Generator ─────────────────────────────────────────────────────────────────

class LLMGenerator:
    """
    Calls Claude to generate triggering inputs for each BugReport.

    Usage
    -----
    gen = LLMGenerator()
    result = gen.generate(report)   # returns LLMResult | None
    """

    def __init__(self) -> None:
        if not config.anthropic_api_key:
            raise ValueError(
                "ANTHROPIC_API_KEY is not set. "
                "Export it as an environment variable before running."
            )
        self._client = anthropic.Anthropic(api_key=config.anthropic_api_key)

    # ── Public API ────────────────────────────────────────────────────────────

    def generate(self, report: BugReport) -> Optional[LLMResult]:
        """
        Attempt to generate inputs for *report*, retrying up to max_retries.
        Returns None if every attempt fails.
        """
        for attempt in range(1, config.max_retries + 1):
            log.info(
                "[%s] LLM attempt %d/%d …",
                report.id, attempt, config.max_retries,
            )
            try:
                result = self._call_llm(report, attempt)
                if result:
                    log.info(
                        "[%s] Generated inputs (confidence=%s, type=%s)",
                        report.id, result.confidence, result.input_type,
                    )
                    return result
            except anthropic.APIError as exc:
                log.warning("[%s] API error on attempt %d: %s", report.id, attempt, exc)
                if attempt < config.max_retries:
                    time.sleep(2 ** attempt)   # exponential back-off
            except Exception as exc:
                log.error("[%s] Unexpected error: %s", report.id, exc, exc_info=True)

        log.warning("[%s] All %d attempts failed.", report.id, config.max_retries)
        return None

    # ── Internal helpers ──────────────────────────────────────────────────────

    def _build_prompt(self, report: BugReport) -> str:
        source = report.source_code or "(source not available)"
        return _USER_PROMPT_TEMPLATE.format(
            bug_type  = report.bug_type,
            qualifier = report.qualifier,
            file      = report.file,
            line      = report.line,
            procedure = report.procedure,
            trace     = report.trace_as_text(),
            source_code = source,
        )

    def _call_llm(self, report: BugReport, attempt: int) -> Optional[LLMResult]:
        prompt = self._build_prompt(report)

        message = self._client.messages.create(
            model      = config.claude_model,
            max_tokens = config.llm_max_tokens,
            system     = _SYSTEM_PROMPT,
            messages   = [{"role": "user", "content": prompt}],
        )

        raw_text = message.content[0].text.strip()
        log.debug("[%s] LLM raw response:\n%s", report.id, raw_text[:500])

        parsed = self._parse_response(raw_text)
        if parsed is None:
            log.warning("[%s] Could not parse LLM response on attempt %d", report.id, attempt)
            return None

        return LLMResult(parsed, attempt)

    @staticmethod
    def _parse_response(text: str) -> Optional[dict]:
        """
        Extract JSON from the LLM response.
        Handles cases where the model wraps it in markdown fences.
        """
        # Strip markdown fences if present
        clean = re.sub(r"```(?:json)?\s*", "", text).replace("```", "").strip()

        # Try direct parse
        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            pass

        # Try extracting the first {...} block
        match = re.search(r"\{.*\}", clean, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        return None
