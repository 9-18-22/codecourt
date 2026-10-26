"""Validated experiment contracts shared by agents and the execution runner."""

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path


class InvalidPlan(ValueError):
    pass


def save_json(path: Path, value) -> None:
    path.write_text(json.dumps(value, ensure_ascii=False, indent=2), encoding="utf-8")


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


@dataclass
class ExperimentPlan:
    hypothesis: str
    mode: str = "original"
    args: list[str] = field(default_factory=list)
    stdin_data: str = ""
    file_inputs: dict[str, str] = field(default_factory=dict)
    env_vars: dict[str, str] = field(default_factory=dict)
    mock_code: str = ""
    trigger_code: str = ""
    assumptions: list[str] = field(default_factory=list)
    expected_observation: str = ""

    @classmethod
    def parse(cls, raw: dict) -> "ExperimentPlan":
        if not isinstance(raw, dict):
            raise InvalidPlan("Experiment must be a JSON object")
        values = {k: v for k, v in raw.items() if k in cls.__dataclass_fields__}
        values.setdefault("hypothesis", raw.get("reasoning", ""))
        plan = cls(**values)
        for name in ("hypothesis", "mode", "stdin_data", "mock_code", "trigger_code", "expected_observation"):
            if not isinstance(getattr(plan, name), str):
                raise InvalidPlan(f"{name} must be a string")
        for name in ("args", "assumptions"):
            value = getattr(plan, name)
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise InvalidPlan(f"{name} must be a list of strings")
        for name in ("file_inputs", "env_vars"):
            value = getattr(plan, name)
            if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
                raise InvalidPlan(f"{name} must map strings to strings")
        if plan.mode not in {"original", "harness", "isolated"}:
            raise InvalidPlan("mode must be original, harness or isolated")
        if plan.mode == "original" and (plan.mock_code or plan.trigger_code):
            raise InvalidPlan("original mode cannot inject mock/trigger code")
        if plan.mode != "original" and not plan.trigger_code.strip():
            raise InvalidPlan("harness/isolated mode requires trigger_code (a complete main)")
        for name in plan.file_inputs:
            path = Path(name)
            if not name or path.is_absolute() or ".." in path.parts or path == Path("."):
                raise InvalidPlan(f"Input file must be a relative path within the work directory: {name}")
        for key, value in plan.env_vars.items():
            if (not key or "=" in key or key.startswith(("ASAN_", "UBSAN_", "LSAN_", "LD_", "DYLD_"))
                    or key in {"PATH", "HOME", "TMPDIR", "LLVM_SYMBOLIZER_PATH"}):
                raise InvalidPlan(f"Reserved environment variable: {key}")
            if "\0" in key + value:
                raise InvalidPlan("Environment contains NUL")
        if any("\0" in value for value in plan.args) or any("\0" in key for key in plan.file_inputs):
            raise InvalidPlan("Arguments and file names cannot contain NUL")
        # Line directives could forge source provenance in sanitizer diagnostics.
        import re
        if re.search(r"^\s*#\s*(?:line\b|\d)", plan.mock_code + "\n" + plan.trigger_code, re.M):
            raise InvalidPlan("Generated code cannot supply source location directives")
        return plan

    def to_dict(self) -> dict:
        return asdict(self)

    def fingerprint(self) -> str:
        values = self.to_dict()
        for key in ("hypothesis", "assumptions", "expected_observation"):
            values.pop(key)
        return digest(json.dumps(values, sort_keys=True).encode())


@dataclass
class CourtOptions:
    max_rounds: int = 3
    max_executions: int = 6  # Includes independent replays before confirmation.
    timeout_seconds: float = 10
    compile_timeout_seconds: float = 30
    max_seconds: float = 180  # Checked between agent calls and execution stages.
    build_config: dict = field(default_factory=dict)

    def __post_init__(self):
        import math
        for key in ("max_rounds", "max_executions"):
            if type(getattr(self, key)) is not int or getattr(self, key) < 1:
                raise ValueError(f"{key} must be a positive integer")
        for key in ("timeout_seconds", "compile_timeout_seconds", "max_seconds"):
            if not math.isfinite(getattr(self, key)) or getattr(self, key) <= 0:
                raise ValueError(f"{key} must be finite and positive")
        if not isinstance(self.build_config, dict):
            raise ValueError("build_config must be an object")
        for key, value in self.build_config.items():
            if key not in {"extra_sources", "include_dirs", "compile_flags", "link_flags"}:
                raise ValueError(f"Unknown build config key: {key}")
            if not isinstance(value, list) or not all(isinstance(x, str) for x in value):
                raise ValueError(f"build_config.{key} must be a string list")
