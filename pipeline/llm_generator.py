"""
LLM Input Generator
====================
Given a BugReport, asks an LLM (Anthropic Claude / Google Gemini / OpenAI GPT)
to produce concrete input values that will drive the program along the faulty
execution path and trigger the bug.

Provider is selected via env var LLM_PROVIDER (defaults to "anthropic" — old
behavior preserved). All three providers see the same prompts and produce
the same JSON output contract.

PATCHED: confidence/guardrail based retry
-----------------------------------------
This module is not the reasoning engine itself. The LLM performs path reasoning;
this module calls the LLM API, parses the JSON response, validates the response,
applies post-response guardrails, and decides whether another generation attempt
is required.

Retry conditions:
  1. API/transport failure
  2. JSON parsing failure
  3. schema/guardrail validation failure
  4. confidence="low"

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
from typing import Optional, Any

from config import config
from pipeline.infer_parser import BugReport
from utils.logger import get_logger

log = get_logger(__name__)


# ── Prompt templates ─────────────────────────────────────────────────────────

_SYSTEM_PROMPT = """\
You are a security researcher and expert C/C++ programmer specializing in
distinguishing TRUE memory bugs from FALSE POSITIVES in static analysis reports.

Your task: analyse a bug report from Facebook Infer and decide whether the
reported bug can ACTUALLY be triggered at runtime. Then produce concrete
inputs (or instrumentation) that would expose the bug if it is real.

## Mindset
Static analyzers like Infer are conservative — they flag many code paths
that are infeasible at runtime (guarded by null checks, unreachable in
practice, freed before use, etc.). A non-trivial fraction of warnings are
false positives. Your job is to make an INDEPENDENT, EVIDENCE-BASED
judgment from the source code itself, NOT to defer to or contradict the
analyzer reflexively.

You must reason carefully:
1. Trace every branch condition on the path Infer reported.
2. Check whether each pointer can ACTUALLY be NULL / freed / overrun at
   the bug line, given the code's control flow and data flow.
3. If you find that the path is infeasible (e.g. the pointer is always
   checked before deref, or the buffer size is always sufficient), set
   confidence to "low" and explain WHY in `reasoning`. Set
   `expected_crash` to "" (empty string) and provide an empty input set —
   this signals "likely false positive".
4. Only generate concrete crash-triggering inputs when you are genuinely
   confident the bug is reachable.

## Output rules
- Output ONLY a single valid JSON object — no markdown fences, no extra text.
- DO NOT fabricate inputs to force a crash if the path is infeasible.
  Bogus inputs will be exposed when ASan does not crash, and they pollute
  the evaluation. Honest "I think this is a false positive" is more
  valuable than a fabricated trigger.
- If the bug needs assertion-based detection (DIVIDE_BY_ZERO,
  INTEGER_OVERFLOW, UNINITIALIZED_VALUE that ASan alone cannot catch),
  set "needs_instrumentation": true and provide `instrumentation_code`.
- Confidence guide:
    "high"   = bug is reachable AND inputs definitely trigger it
    "medium" = bug is plausibly reachable, inputs likely trigger it
    "low"    = path looks infeasible / likely a false positive

## CRITICAL rules for `instrumentation_code` (read carefully)
The string in `instrumentation_code` is inserted *verbatim* one line before
the bug line. The line is auto-injected into the running program; if it
does not compile, the entire test fails with COMPILE_ERROR.

You MUST follow ALL of these:
1. **Pure C only.** No natural-language prefix like "Insert before line N:",
   "Before line X, add:", "Use this:". No markdown fences (```c). No
   leading/trailing comments that describe the intent.
2. **One single statement.** A statement is `something;` (with semicolon).
   Never multiple statements joined with semicolons unless absolutely needed.
3. **Must compile inside the enclosing function body.** This means:
   - You may reference local variables and parameters that are in scope
     at the bug line (e.g. `idx`, `buf`, `p` — IF they are visible there).
   - You may reference globals declared above the bug line.
   - You CANNOT declare new functions, structs, or global variables.
   - You CANNOT reference variables that are only in scope in OTHER
     functions (e.g. `buf` declared in `foo_001()` cannot be referenced
     from `foo_002()`).
4. **No multi-line comments inside the assertion.** `/* ... */` blocks
   that span lines will break the surrounding code.
5. If you cannot write a clean one-line C statement that is valid at the
   bug line, set `needs_instrumentation: false` and `instrumentation_code: null`
   instead — leaving it blank is better than producing broken code.

## Good `instrumentation_code` examples
- `assert(divisor != 0)`
- `assert(idx >= 0 && idx < BUF_SIZE)`
- `if (p != NULL) { assert(0 && "should be unreachable"); }`
- `volatile int __force_read = some_var; (void)__force_read`

## BAD examples (NEVER produce these)
- `"Insert before line 472: int x = buf[idx];"`         ← natural-language prefix
- `"/* Before line N */ assert(p != NULL);"`            ← comment prefix
- `"```c\nassert(x);\n```"`                             ← markdown fence
- `"int tmp = buf[idx]; (void)tmp; /* MSan check */"`   ← references `buf` from another function's scope
- `"for(int i=0; i<5; i++) buf[i]=0; assert(...)"`      ← multi-statement, function-scope-dependent
"""

_USER_PROMPT_TEMPLATE = """\
## Static Analysis Bug Report

| Field          | Value |
|----------------|-------|
| Bug Type       | {bug_type} |
| Qualifier      | {qualifier} |
| File           | {file} |
| Line           | {line} |
| Procedure      | {procedure} |
{dataset_context}

## Bug Trace (execution path leading to the bug, as reported by Infer)
{trace}

## Source Code (line numbers included; bug line marked with <<<< BUG LINE)
```c
{source_code}
```

## Task
Analyse the bug carefully. Reason through the control flow at every step.
If the path looks infeasible, set confidence="low" and leave inputs empty.
Otherwise, produce concrete inputs that trigger the bug.

Produce a JSON object with the following fields:
- "reasoning"             - step-by-step analysis: trace the path, evaluate each
                            branch, conclude whether the bug is reachable or
                            this is a likely false positive
- "input_type"            - one of: "args", "stdin", "file", "none"
                            Use "none" if you assess this as a false positive
                            and no input can trigger it
- "args"                  - list of command-line argument strings (empty list if unused)
- "stdin_data"            - string to feed to stdin (empty string if unused)
- "file_inputs"           - dict mapping filename to content (empty dict if unused)
- "env_vars"              - dict of environment variables (empty dict if unused)
- "expected_crash"        - expected ASan / crash signal, or "" if you assess
                            this as a false positive
- "confidence"            - "high" | "medium" | "low"
- "needs_instrumentation" - true if ASan alone cannot catch this bug type
                            (DIVIDE_BY_ZERO, INTEGER_OVERFLOW, some
                             UNINITIALIZED_VALUE cases)
- "instrumentation_code"  - A SINGLE C statement (string) to insert at the
                            bug line. Pure C only — NO natural-language
                            prefix, NO markdown fences, NO multi-line
                            comments. Must compile inside the enclosing
                            function body. Set to null if you cannot write
                            a clean one-line statement valid at the bug
                            line. See system prompt for examples.

Respond with ONLY the JSON object.
"""

class LLMResult:
    """Wraps the parsed response from the LLM."""

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


class APIError(Exception):
    """Provider-agnostic API failure (network / auth / quota / 5xx)."""


class _AnthropicAdapter:
    def __init__(self) -> None:
        import anthropic
        self._anthropic = anthropic
        if not config.anthropic_api_key:
            raise ValueError("ANTHROPIC_API_KEY is not set.")
        self._client = anthropic.Anthropic(
            api_key=config.anthropic_api_key,
            timeout=getattr(config, "llm_timeout_seconds", 90.0),
        )

    def call(self, system_prompt: str, user_prompt: str) -> str:
        try:
            msg = self._client.messages.create(
                model       = config.claude_model,
                max_tokens  = config.llm_max_tokens,
                temperature = getattr(config, "llm_temperature", 0.7),
                system      = system_prompt,
                messages    = [{"role": "user", "content": user_prompt}],
            )
            return msg.content[0].text.strip()
        except self._anthropic.APIError as e:
            raise APIError(str(e)) from e


class _GeminiAdapter:
    def __init__(self) -> None:
        if not config.gemini_api_key:
            raise ValueError("GEMINI_API_KEY (or GOOGLE_API_KEY) is not set.")
        try:
            from google import genai
            self._client = genai.Client(api_key=config.gemini_api_key)
            self._mode = "genai_new"
        except ImportError:
            import google.generativeai as genai_legacy
            genai_legacy.configure(api_key=config.gemini_api_key)
            self._client = genai_legacy.GenerativeModel(config.gemini_model)
            self._mode = "genai_legacy"

    def call(self, system_prompt: str, user_prompt: str) -> str:
        try:
            temperature = getattr(config, "llm_temperature", 0.7)
            if self._mode == "genai_new":
                from google.genai import types
                resp = self._client.models.generate_content(
                    model    = config.gemini_model,
                    contents = user_prompt,
                    config   = types.GenerateContentConfig(
                        system_instruction = system_prompt,
                        max_output_tokens  = config.llm_max_tokens,
                        response_mime_type = "application/json",
                        temperature        = temperature,
                    ),
                )
                return (resp.text or "").strip()
            else:
                resp = self._client.generate_content(
                    f"{system_prompt}\n\n{user_prompt}",
                    generation_config={
                        "max_output_tokens": config.llm_max_tokens,
                        "response_mime_type": "application/json",
                        "temperature": temperature,
                    },
                )
                return (resp.text or "").strip()
        except Exception as e:
            raise APIError(str(e)) from e


class _OpenAIAdapter:
    def __init__(self) -> None:
        if not config.openai_api_key:
            raise ValueError("OPENAI_API_KEY is not set.")
        from openai import OpenAI
        self._client = OpenAI(
            api_key=config.openai_api_key,
            timeout=getattr(config, "llm_timeout_seconds", 90.0),
        )

    def call(self, system_prompt: str, user_prompt: str) -> str:
        try:
            resp = self._client.chat.completions.create(
                model       = config.openai_model,
                max_tokens  = config.llm_max_tokens,
                temperature = getattr(config, "llm_temperature", 0.7),
                messages    = [
                    {"role": "system", "content": system_prompt},
                    {"role": "user",   "content": user_prompt},
                ],
                response_format = {"type": "json_object"},
            )
            return (resp.choices[0].message.content or "").strip()
        except Exception as e:
            raise APIError(str(e)) from e


def _build_adapter():
    p = config.llm_provider
    if p == "anthropic":
        return _AnthropicAdapter()
    if p == "gemini":
        return _GeminiAdapter()
    if p == "openai":
        return _OpenAIAdapter()
    raise ValueError(f"Unknown LLM_PROVIDER: {p!r}. Use anthropic | gemini | openai.")


class LLMGenerator:
    """
    Calls the configured LLM (anthropic | gemini | openai) to generate
    triggering inputs for each BugReport.

    Important responsibility split:
      - The LLM performs path reasoning and proposes inputs.
      - This class calls the API, parses JSON, validates the response,
        applies guardrails, and controls retry.
    """

    def __init__(self) -> None:
        self._adapter = _build_adapter()
        log.info("LLMGenerator initialized with provider=%s", config.llm_provider)

    def generate(self, report: BugReport) -> Optional[LLMResult]:
        """
        Generate a runtime trigger candidate for *report*.

        Retry policy:
        1. Retry transport/API failures.
        2. Retry invalid JSON / schema-invalid responses.
        3. Retry confidence="low" responses, because the model may be
           non-deterministic and a later sample may find a feasible trigger.

        Returns the first acceptable high/medium confidence result. If all
        attempts are low confidence or validation-failed, returns the best
        available result so downstream ASan can still classify conservatively.
        """
        max_attempts = max(1, int(getattr(config, "max_retries", 3)))
        best_result: Optional[LLMResult] = None
        attempt_history: list[dict[str, Any]] = []
        retry_feedback = ""

        for attempt in range(1, max_attempts + 1):
            log.info(
                "[%s] LLM attempt %d/%d (provider=%s) …",
                report.id, attempt, max_attempts, config.llm_provider,
            )
            try:
                result = self._call_llm(report, attempt, retry_feedback=retry_feedback)
                if result is None:
                    retry_feedback = (
                        "Previous response was not valid JSON or could not be parsed. "
                        "Return one valid JSON object only."
                    )
                    attempt_history.append({
                        "attempt": attempt,
                        "status": "retry",
                        "reason": "parse_error",
                    })
                    continue

                issues = self._validate_result(result)
                acceptable = self._is_acceptable_result(result, issues)
                result.raw["_validation_errors"] = issues
                result.raw["_retry_required"] = not acceptable
                result.raw["_attempt_history"] = list(attempt_history)

                attempt_history.append({
                    "attempt": attempt,
                    "status": "accepted" if acceptable else "retry",
                    "confidence": result.confidence,
                    "input_type": result.input_type,
                    "issues": issues,
                })

                best_issues = []
                if best_result is not None:
                    best_issues = best_result.raw.get("_validation_errors", [])
                if best_result is None or self._score_result(result, issues) > self._score_result(best_result, best_issues):
                    best_result = result

                if acceptable:
                    result.raw["_attempt_history"] = attempt_history
                    log.info(
                        "[%s] Generated inputs (confidence=%s, type=%s)",
                        report.id, result.confidence, result.input_type,
                    )
                    return result

                retry_feedback = self._build_retry_feedback(result, issues)

            except APIError as exc:
                log.warning("[%s] API error on attempt %d: %s", report.id, attempt, exc)
                attempt_history.append({
                    "attempt": attempt,
                    "status": "retry",
                    "reason": "api_error",
                    "message": str(exc)[:300],
                })
                if attempt < max_attempts:
                    time.sleep(2 ** attempt)

            except Exception as exc:
                log.error("[%s] Unexpected error: %s", report.id, exc, exc_info=True)
                attempt_history.append({
                    "attempt": attempt,
                    "status": "retry",
                    "reason": "unexpected_error",
                    "message": str(exc)[:300],
                })

        if best_result is not None:
            best_result.raw["_attempt_history"] = attempt_history
            log.info(
                "[%s] Returning best LLM result after %d attempts (confidence=%s, type=%s)",
                report.id, max_attempts, best_result.confidence, best_result.input_type,
            )
            return best_result

        log.warning("[%s] All %d attempts failed.", report.id, max_attempts)
        return None

    def _build_prompt(self, report: BugReport, retry_feedback: str = "") -> str:
        source = report.source_code or "(source not available)"

        prompt = _USER_PROMPT_TEMPLATE.format(
            bug_type        = report.bug_type,
            qualifier       = report.qualifier,
            file            = report.file,
            line            = report.line,
            procedure       = report.procedure,
            trace           = report.trace_as_text(),
            source_code     = source,
            dataset_context = "",
        )

        if retry_feedback:
            prompt += f"""

## Retry Feedback
{retry_feedback}

Re-analyze the path independently. If a concrete trigger is feasible, return a
different concrete input with confidence high or medium. If the path is truly
infeasible, keep confidence low and input_type none. Do not fabricate crashes.
"""

        return prompt

    def _call_llm(
        self,
        report: BugReport,
        attempt: int,
        retry_feedback: str = "",
    ) -> Optional[LLMResult]:
        prompt = self._build_prompt(report, retry_feedback=retry_feedback)
        raw_text = self._adapter.call(_SYSTEM_PROMPT, prompt)

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
        clean = re.sub(r"```(?:json)?\s*", "", text).replace("```", "").strip()

        try:
            return json.loads(clean)
        except json.JSONDecodeError:
            pass

        match = re.search(r"\{.*\}", clean, re.DOTALL)
        if match:
            try:
                return json.loads(match.group())
            except json.JSONDecodeError:
                pass

        return None

    @staticmethod
    def _validate_result(result: LLMResult) -> list[str]:
        issues: list[str] = []

        if result.input_type not in {"args", "stdin", "file", "none"}:
            issues.append(f"invalid_input_type:{result.input_type}")

        if result.confidence not in {"high", "medium", "low"}:
            issues.append(f"invalid_confidence:{result.confidence}")

        if (
            result.confidence in {"high", "medium"}
            and result.input_type == "none"
            and not result.needs_instrumentation
        ):
            issues.append("confident_but_no_trigger")

        payload_chunks: list[str] = []
        payload_chunks.extend(result.args or [])
        payload_chunks.append(result.stdin_data or "")
        payload_chunks.extend(str(v) for v in (result.file_inputs or {}).values())
        if result.instrumentation_code:
            payload_chunks.append(result.instrumentation_code)

        payload = "\n".join(payload_chunks)
        fake_crash_patterns = [
            r"\babort\s*\(",
            r"\bexit\s*\(",
            r"__builtin_trap\s*\(",
            r"\braise\s*\(\s*SIG",
            r"\bkill\s*\(\s*getpid\s*\(",
            r"\bSIZE_MAX\b",
            r"assert\s*\(\s*0",
            r"\*\s*\(\s*(?:int|char|long|void)\s*\*\s*\)\s*0",
        ]
        for pat in fake_crash_patterns:
            if re.search(pat, payload, re.IGNORECASE):
                issues.append(f"guardrail_fake_crash:{pat}")

        if result.needs_instrumentation and not result.instrumentation_code:
            issues.append("needs_instrumentation_without_code")

        return issues

    @staticmethod
    def _is_acceptable_result(result: LLMResult, issues: list[str]) -> bool:
        if issues:
            return False
        return result.confidence in {"high", "medium"}

    @staticmethod
    def _score_result(result: LLMResult, issues: list[str]) -> float:
        score = {"low": 1.0, "medium": 2.0, "high": 3.0}.get(result.confidence, 0.0)
        if result.input_type in {"args", "stdin", "file"}:
            score += 0.5
        if result.expected_crash:
            score += 0.25
        score -= 2.0 * len(issues)
        return score

    @staticmethod
    def _build_retry_feedback(result: LLMResult, issues: list[str]) -> str:
        reasons = []
        if result.confidence == "low":
            reasons.append("Previous attempt returned confidence=low, so no reliable trigger was produced.")
        if issues:
            reasons.append("Post-response validation failed: " + ", ".join(issues))
        return " ".join(reasons) or "Previous attempt was not accepted; try again with an independent path analysis."
