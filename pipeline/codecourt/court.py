"""CodeCourt orchestration: propose, execute, challenge, verify and decide."""

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import time

from pipeline.llm_generator import _build_adapter
from utils.logger import get_logger
from .agents import Defense, Prosecutor
from .evidence import artifact_excerpt, validate_defense, verify_execution
from .models import CourtOptions, InvalidPlan, save_json
from .runner import EvidenceRunner

log = get_logger(__name__)


def _warning_key(report):
    """Stable, short artifact key without exposing the absolute source path."""
    readable = re.sub(r"[^a-zA-Z0-9_.-]+", "_", Path(report.file).name).strip("._")
    readable = readable or "source"
    identity = f"{report.file}:{report.line}:{report.bug_type}".encode()
    return f"{readable}_{report.line}_{report.bug_type}_{hashlib.sha256(identity).hexdigest()[:10]}"


def _context(report):
    source_context = report.source_code
    call_sites = ""
    try:
        lines = Path(report.resolved_path).read_text(errors="replace").splitlines()
        indexes = set(range(max(0, report.line - 31), min(len(lines), report.line + 30)))
        if report.procedure:
            pattern = re.compile(rf"\b{re.escape(report.procedure)}\s*\(")
            for index, line in enumerate(lines):
                if pattern.search(line):
                    indexes.update(range(max(0, index - 8), min(len(lines), index + 9)))
        call_sites = "\n".join(f"{i + 1}: {lines[i]}" for i in sorted(indexes))
    except OSError:
        pass
    return {
        "warning": {"id": report.id, "bug_type": report.bug_type,
                    "qualifier": report.qualifier, "file": report.file,
                    "line": report.line, "procedure": report.procedure,
                    "trace": report.trace_as_text()},
        "source_with_line_numbers": source_context,
        "target_and_same_file_call_sites": call_sites,
        "decision_policy": {
            "CONFIRMED_TRUE": "matching sanitizer report in original code, eligible context, repeatable, no unresolved cited objection",
            "UNRESOLVED": "evidence or scope remains incomplete",
            "INVALID_EXPERIMENT": "individual experiment is malformed or changes source provenance",
            "BOUNDED_FALSE_POSITIVE": "disabled until exhaustive or formal bounded evidence is configured",
        },
    }


class CodeCourt:
    def __init__(self, output_dir, options=None, adapter=None, runner=None):
        self.root = Path(output_dir) / "codecourt"
        self.root.mkdir(parents=True, exist_ok=True)
        self.options = options or CourtOptions()
        adapter = adapter or _build_adapter()
        self.prosecutor = Prosecutor(adapter)
        self.defense = Defense(adapter)
        self.runner = runner or EvidenceRunner(self.options)

    def adjudicate(self, report):
        started = time.monotonic()
        deadline = started + self.options.max_seconds
        warning_dir = self.root / _warning_key(report)
        warning_dir.mkdir(parents=True, exist_ok=True)
        context = _context(report)
        save_json(warning_dir / "warning.json", context)
        rounds, fingerprints, executions = [], set(), 0
        feedback = {"instruction": "Design the first independent experiment."}
        final = "UNRESOLVED"
        final_reason = "experiment budget exhausted without confirmation"

        for number in range(1, self.options.max_rounds + 1):
            if time.monotonic() >= deadline or executions >= self.options.max_executions:
                final_reason = "time or execution budget exhausted"
                break
            round_dir = warning_dir / f"round_{number:02d}"
            round_dir.mkdir()
            record = {"round": number, "experiment_status": "PLANNING"}
            try:
                plan = self.prosecutor.propose(context, feedback, round_dir)
                if plan.fingerprint() in fingerprints:
                    raise InvalidPlan("Prosecutor repeated an earlier experiment")
                fingerprints.add(plan.fingerprint())
                record["plan"] = plan.to_dict()
                manifest = self.runner.run(report, plan, round_dir, deadline)
                executions += len(manifest.get("runs", []))
                record["manifest_path"] = str(round_dir / "manifest.json")
                evidence = verify_execution(report, plan, manifest)
                record["evidence"] = evidence
                record["experiment_status"] = "VALID" if evidence["status"] != "INVALID" else "INVALID_EXPERIMENT"

                defense = self.defense.review(context, {
                    "id": f"round_{number:02d}", **plan.to_dict(), "evidence": evidence,
                }, artifact_excerpt(round_dir), round_dir)
                defense_review = validate_defense(defense, round_dir)
                record["defense"] = defense_review
                objections = defense_review["verified_objections"]

                if evidence["status"] == "CANDIDATE_TRUE" and not objections:
                    if executions >= self.options.max_executions or time.monotonic() >= deadline:
                        final_reason = "confirmation candidate found but replay budget unavailable"
                    else:
                        replay = self.runner.replay(plan, round_dir, manifest, deadline)
                        executions += 1
                        replay_evidence = verify_execution(report, plan, manifest)
                        record["replay_evidence"] = replay_evidence
                        if replay_evidence.get("status") == "CANDIDATE_TRUE" and (
                            replay_evidence.get("signature") == evidence.get("signature")
                        ):
                            final = "CONFIRMED_TRUE"
                            final_reason = "matching sanitizer evidence reproduced independently"
                            rounds.append(record)
                            break
                feedback = {
                    "judge": "Address the unresolved checks with a materially different experiment.",
                    "missing_checks": [key for key, passed in evidence.get("checks", {}).items() if not passed],
                    "defense_objections": objections,
                    "requested_experiment": defense_review.get("next_experiment", ""),
                    "previous_status": manifest.get("status"),
                }
            except (InvalidPlan, ValueError) as exc:
                record["experiment_status"] = "INVALID_EXPERIMENT"
                record["error"] = str(exc)
                feedback = {"judge": "The prior experiment was invalid. Correct the stated schema or provenance problem.",
                            "error": str(exc)}
            except Exception as exc:
                # Provider and infrastructure failures do not become program verdicts.
                record["experiment_status"] = "INFRA_ERROR"
                record["error"] = f"{type(exc).__name__}: {exc}"
                final_reason = "agent or execution infrastructure failed"
                rounds.append(record)
                break
            rounds.append(record)

        result = {
            "warning_id": report.id, "verdict": final, "reason": final_reason,
            "rounds": rounds, "executions": executions,
            "limits": {"max_rounds": self.options.max_rounds,
                       "max_executions": self.options.max_executions,
                       "max_seconds": self.options.max_seconds},
            "elapsed_seconds": round(time.monotonic() - started, 3),
            "generated_at": datetime.now(timezone.utc).isoformat(),
            "bounded_false_positive_enabled": False,
        }
        save_json(warning_dir / "court_report.json", result)
        report.court_result = result
        log.info("[%s] CodeCourt verdict: %s", report.id, final)
        return result
