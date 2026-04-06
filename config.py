"""
Central configuration for the static-verifier pipeline.
All tuneable parameters live here – no magic numbers scattered in modules.
"""

import os
from dataclasses import dataclass, field
from typing import Tuple


@dataclass
class Config:
    # ── Claude API ──────────────────────────────────────────────────────────
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "")
    )
    claude_model: str = "claude-sonnet-4-5"
    llm_max_tokens: int = 2048

    # ── LLM retry ───────────────────────────────────────────────────────────
    max_retries: int = 3

    # ── Dynamic verification ─────────────────────────────────────────────────
    timeout_seconds: int = 10          # per-execution timeout
    compiler: str = "gcc"              # "gcc" or "clang"
    asan_flags: str = "-fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer"

    # ── Bug types that ASan can verify directly ──────────────────────────────
    asan_verifiable_types: Tuple[str, ...] = (
        "NULL_DEREFERENCE",
        "USE_AFTER_FREE",
        "BUFFER_OVERRUN_L1",
        "BUFFER_OVERRUN_L2",
        "BUFFER_OVERRUN_L3",
        "BUFFER_OVERRUN_U",
        "MEMORY_LEAK",          # checked via -fsanitize=leak
    )

    # Bug types that need assertion instrumentation instead
    instrumentation_types: Tuple[str, ...] = (
        "DIVIDE_BY_ZERO",
        "INTEGER_OVERFLOW_L5",
    )

    # ── Source context window ─────────────────────────────────────────────────
    source_context_lines: int = 60     # lines of code sent to LLM around the bug

    # ── Output ───────────────────────────────────────────────────────────────
    output_dir: str = "results"
    report_filename: str = "verification_report.json"


# Singleton – import this everywhere
config = Config()
