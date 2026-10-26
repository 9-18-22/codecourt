"""Persisted C builds and executions. No source repairs or hidden retries."""

import json
import os
from pathlib import Path
import platform
import re
import shlex
import shutil
import signal
import subprocess
import time

from pipeline.asan_verifier import ASanVerifier
from .models import CourtOptions, ExperimentPlan, InvalidPlan, digest, save_json


def execute(command, cwd, env, stdin, timeout, prefix):
    """Keep complete logs on disk, kill the process group on timeout."""
    start = time.monotonic()
    stdout_path, stderr_path = Path(str(prefix) + ".stdout"), Path(str(prefix) + ".stderr")
    with stdout_path.open("wb") as stdout, stderr_path.open("wb") as stderr:
        try:
            proc = subprocess.Popen(command, cwd=cwd, env=env, stdin=subprocess.PIPE,
                                    stdout=stdout, stderr=stderr, start_new_session=True)
            try:
                proc.communicate(stdin.encode(), timeout=timeout)
                status = "COMPLETED"
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.communicate()
                status = "TIMEOUT"
            returncode = proc.returncode
        except OSError as exc:
            stderr.write(str(exc).encode())
            status, returncode = "EXECUTION_ERROR", None
    return {"status": status, "returncode": returncode,
            "elapsed_seconds": round(time.monotonic() - start, 3),
            "command": command, "cwd": str(cwd),
            "stdout": str(stdout_path), "stderr": str(stderr_path)}


def runtime_environment(overrides):
    # Do not persist or forward provider credentials to generated test programs.
    env = {key: os.environ[key] for key in ("PATH", "LANG", "LC_ALL", "TMPDIR") if key in os.environ}
    env.update(overrides)
    env.update(ASAN_OPTIONS="detect_leaks=0:halt_on_error=1:abort_on_error=0:symbolize=1",
               UBSAN_OPTIONS="halt_on_error=1:print_stacktrace=1:symbolize=1")
    symbolizer = shutil.which("llvm-symbolizer")
    if symbolizer:
        env["ASAN_SYMBOLIZER_PATH"] = symbolizer
    return env


class EvidenceRunner:
    def __init__(self, options: CourtOptions, legacy=None):
        self.options = options
        self.legacy = legacy or ASanVerifier()
        self.compiler = self.legacy._compiler
        self.toolchain_flags = []
        if platform.system() == "Darwin":
            sdk = Path("/Library/Developer/CommandLineTools/SDKs/MacOSX.sdk")
            tools = Path("/Library/Developer/CommandLineTools/usr/bin")
            if sdk.exists():
                self.toolchain_flags.extend(["-isysroot", str(sdk)])
            if (tools / "ld").exists():
                self.toolchain_flags.append(f"-B{tools}")

    def run(self, report, plan: ExperimentPlan, directory: Path, deadline: float) -> dict:
        directory = directory.resolve()
        source = Path(report.resolved_path).resolve()
        original = source.read_bytes()
        text = original.decode("utf-8", errors="replace")
        (directory / "original.c").write_bytes(original)
        save_json(directory / "plan.json", plan.to_dict())
        build = directory / "build"
        work = directory / "work"
        build.mkdir()
        work.mkdir()
        manifest = {
            "source_path": str(source), "source_sha256": digest(original),
            "scope": {"mode": plan.mode, "entry": "original main" if plan.mode == "original" else "generated main",
                      "assumptions": plan.assumptions, "build_config": self.options.build_config},
            "plan": plan.to_dict(), "platform": platform.platform(),
            "compiler": self.compiler, "toolchain_flags": self.toolchain_flags,
            "preprocess": [], "build": None, "runs": [],
            "hashes": {"original.c": digest(original)}, "status": "PREPARING",
        }
        def finish(status):
            manifest["status"] = status
            manifest["source_unchanged"] = source.exists() and digest(source.read_bytes()) == digest(original)
            save_json(directory / "manifest.json", manifest)
            return manifest

        # Original text and original line numbers are preserved. Generated sections
        # have distinct filenames; an agent cannot label mock code as original code.
        target_text = text
        first_line = 1
        if plan.mode == "isolated":
            target_text = self.legacy._extract_function_body(text, report.line, report.procedure)
            if not target_text or text.count(target_text) != 1:
                return finish("PREPARATION_ERROR")
            first_line = text[:text.index(target_text)].count("\n") + 1
        def line_directive(line, filename):
            return f"#line {line} {json.dumps(str(filename))}\n"
        generated = ""
        if plan.mock_code:
            generated += line_directive(1, directory / "mock.c") + plan.mock_code + "\n"
        generated += line_directive(first_line, source) + target_text + "\n"
        if plan.trigger_code:
            generated += line_directive(1, directory / "harness.c") + plan.trigger_code + "\n"
        (directory / "mock.c").write_text(plan.mock_code, encoding="utf-8")
        (directory / "harness.c").write_text(plan.trigger_code, encoding="utf-8")
        generated_source = build / "subject.c"
        generated_source.write_text(generated, encoding="utf-8")
        for name in ("build/subject.c", "mock.c", "harness.c", "plan.json"):
            manifest["hashes"][name] = digest((directory / name).read_bytes())

        env = runtime_environment(plan.env_vars)
        if "MEMORY_LEAK" in report.bug_type or "RESOURCE_LEAK" in report.bug_type:
            env["ASAN_OPTIONS"] = env["ASAN_OPTIONS"].replace("detect_leaks=0", "detect_leaks=1")
        manifest["runtime_environment"] = env
        save_json(directory / "inputs.json", {"files": plan.file_inputs, "stdin": plan.stdin_data, "args": plan.args})
        for name, contents in plan.file_inputs.items():
            destination = work / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(contents, encoding="utf-8")
        manifest["hashes"]["inputs.json"] = digest((directory / "inputs.json").read_bytes())

        build_cfg = self.options.build_config
        # Build config is user-supplied, never LLM-generated. It is part of scope.
        includes = [source.parent, *[Path(p).resolve() for p in build_cfg.get("include_dirs", [])]]
        for candidate in (source.parent / "include", source.parent.parent / "include"):
            if candidate.is_dir() and candidate not in includes:
                includes.append(candidate)
        include_flags = [item for path in includes for item in ("-I", str(path))]
        fixed_flags = ["-fsanitize=address,undefined", "-fno-sanitize-recover=all", "-g", "-O0", "-fno-omit-frame-pointer"]
        cflags = self.toolchain_flags + build_cfg.get("compile_flags", []) + fixed_flags
        sources = [generated_source, *[Path(p).resolve() for p in build_cfg.get("extra_sources", [])]]
        preprocessed = []
        # Freeze transitive includes and macros as .i files for later replay.
        for i, src in enumerate(sources):
            if time.monotonic() >= deadline:
                return finish("BUDGET_EXHAUSTED")
            output = build / f"unit_{i}.i"
            command = [self.compiler, *cflags, *include_flags, "-E", str(src), "-o", str(output)]
            result = execute(command, build, runtime_environment({}), "",
                             min(self.options.compile_timeout_seconds, deadline - time.monotonic()),
                             directory / f"preprocess_{i}")
            manifest["preprocess"].append(result)
            if result["status"] != "COMPLETED" or result["returncode"] != 0:
                return finish("BUILD_TIMEOUT" if result["status"] == "TIMEOUT" else "COMPILE_ERROR")
            preprocessed.append(str(output))
            manifest["hashes"][str(output.relative_to(directory))] = digest(output.read_bytes())
        binary = build / "target"
        command = [self.compiler, *cflags, *preprocessed, *build_cfg.get("link_flags", []), "-o", str(binary)]
        if time.monotonic() >= deadline:
            return finish("BUDGET_EXHAUSTED")
        manifest["build"] = execute(command, build, runtime_environment({}), "",
                                    min(self.options.compile_timeout_seconds, deadline - time.monotonic()),
                                    directory / "compile")
        if manifest["build"]["status"] != "COMPLETED" or manifest["build"]["returncode"] != 0:
            return finish("BUILD_TIMEOUT" if manifest["build"]["status"] == "TIMEOUT" else "COMPILE_ERROR")
        manifest["hashes"]["build/target"] = digest(binary.read_bytes())
        version = execute([self.compiler, "--version"], build, runtime_environment({}), "", 5, directory / "compiler_version")
        manifest["compiler_version"] = Path(version["stdout"]).read_text(errors="replace")
        if time.monotonic() >= deadline:
            return finish("BUDGET_EXHAUSTED")
        manifest["runs"].append(self._execute(plan, binary, work, env, directory / "run_1", deadline))
        run = manifest["runs"][-1]
        if run["status"] != "COMPLETED":
            return finish(run["status"])
        stderr = Path(run["stderr"]).read_text(errors="replace")
        # Legacy classification is retained only as a diagnostic, never a verdict.
        manifest["legacy_observation"] = self.legacy._classify(
            stderr, run["returncode"], shlex.join(command), shlex.join(run["command"]), report).to_dict()
        return finish("EXECUTED")

    def _execute(self, plan, binary, work, env, prefix, deadline):
        return execute([str(binary), *plan.args], work, env, plan.stdin_data,
                       max(0.001, min(self.options.timeout_seconds, deadline - time.monotonic())), prefix)

    def replay(self, plan, directory, manifest, deadline):
        # Fresh work directory: the first run may have consumed/modified its inputs.
        index = len(manifest["runs"]) + 1
        work = directory / f"work_{index}"
        work.mkdir()
        for name, contents in plan.file_inputs.items():
            destination = work / name
            destination.parent.mkdir(parents=True, exist_ok=True)
            destination.write_text(contents, encoding="utf-8")
        result = self._execute(plan, directory / "build/target", work,
                               manifest["runtime_environment"], directory / f"run_{index}", deadline)
        manifest["runs"].append(result)
        save_json(directory / "manifest.json", manifest)
        return result
