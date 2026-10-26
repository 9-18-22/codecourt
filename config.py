"""
Central configuration for the CodeCourt verification pipeline.
All tuneable parameters live here – no magic numbers scattered in modules.
"""

import os
from dataclasses import dataclass, field
from typing import Tuple


@dataclass
class Config:
    # ── LLM Provider ────────────────────────────────────────────────────────
    # Set via env var LLM_PROVIDER. Default "anthropic" preserves old behavior.
    llm_provider: str = field(
        default_factory=lambda: os.getenv("LLM_PROVIDER", "anthropic").lower()
    )

    # ── API Keys (read all three; only the active one is required) ──────────
    anthropic_api_key: str = field(
        default_factory=lambda: os.getenv("ANTHROPIC_API_KEY", "")
    )
    gemini_api_key: str = field(
        default_factory=lambda: os.getenv("GEMINI_API_KEY", "")
                                 or os.getenv("GOOGLE_API_KEY", "")
    )
    openai_api_key: str = field(
        default_factory=lambda: os.getenv("OPENAI_API_KEY", "")
    )

    # ── Model names per provider ────────────────────────────────────────────
    claude_model: str = "claude-sonnet-4-5"
    gemini_model: str = "gemini-2.5-flash-lite"
    openai_model: str = "gpt-4o-mini"

    llm_max_tokens: int = 2048
    llm_timeout_seconds: float = field(
        default_factory=lambda: float(os.getenv("LLM_TIMEOUT_SECONDS", "90"))
    )

    # ── LLM retry ───────────────────────────────────────────────────────────
    max_retries: int = 3

    # ── Dynamic verification ─────────────────────────────────────────────────
    timeout_seconds: int = 10          # per-execution timeout
    compiler: str = "clang"            # "gcc" or "clang"
    asan_flags: str = "-fsanitize=address,undefined -g -O1 -fno-omit-frame-pointer -DINCLUDEMAIN"

    # ── Bug types that ASan can verify directly ──────────────────────────────
    asan_verifiable_types: Tuple[str, ...] = (
        "NULL_DEREFERENCE",
        "NULLPTR_DEREFERENCE",
        "USE_AFTER_FREE",
        "BUFFER_OVERRUN_L1",
        "BUFFER_OVERRUN_L2",
        "BUFFER_OVERRUN_L3",
        "BUFFER_OVERRUN_U",
        "MEMORY_LEAK",
        "MEMORY_LEAK_C",
        "UNINITIALIZED_VALUE",
        "STACK_BUFFER_OVERFLOW",
        "HEAP_BUFFER_OVERFLOW",
    )

    # Bug types that need assertion instrumentation instead
    instrumentation_types: Tuple[str, ...] = (
        "DIVIDE_BY_ZERO",
        "INTEGER_OVERFLOW_L5",
        "INTEGER_OVERFLOW_L2",
        "INTEGER_OVERFLOW_U5",
    )

    # ── Source context window ─────────────────────────────────────────────────
    source_context_lines: int = 60     # lines of code sent to LLM around the bug

    # ── Output ───────────────────────────────────────────────────────────────
    output_dir: str = "results"
    report_filename: str = "verification_report.json"

    # The maintained path targets unlabeled real-world code.
    dataset_mode: str = "generic_realworld"

    # ── Convenience: which API key is needed for the active provider? ───────
    @property
    def active_api_key(self) -> str:
        return {
            "anthropic": self.anthropic_api_key,
            "gemini":    self.gemini_api_key,
            "openai":    self.openai_api_key,
        }.get(self.llm_provider, "")


# Singleton – import this everywhere
config = Config()
