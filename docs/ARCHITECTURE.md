# CodeCourt Architecture

## Runtime boundary

`scripts/run_pipeline.sh` is the end-to-end entry point: it runs Infer in Docker,
then passes the generated report to `main.py`. `main.py` only handles CLI
configuration and starts `Pipeline`.
`Pipeline` parses Infer warnings, then selects either the CodeCourt path or the
legacy baseline path. CodeCourt owns the real-world validation lifecycle.

```text
Source project
        |
        v
  Infer (Docker)
        |
        v
Infer report + source root
        |
        v
    InferParser
        |
        v
    CodeCourt
      |       \
      v        v
 Prosecutor  EvidenceRunner
      |        |
      |        v
      |   EvidenceVerifier
      |        |
      v        v
    Defense -> Judge
                 |
                 v
       court_report.json
```

## Component responsibilities

- `pipeline/infer_parser.py`
  - Converts Infer JSON into `BugReport` objects.
  - Resolves source paths and attaches source context.
- `pipeline/codecourt/models.py`
  - Defines the JSON contract for experiment plans and execution limits.
  - Rejects unsafe paths, reserved environment variables, and source directives.
- `pipeline/codecourt/agents.py`
  - Contains the Prosecutor and Defense prompts and response validation.
  - Agent output is treated as an untrusted proposal.
- `pipeline/codecourt/runner.py`
  - Builds an evidence directory for each experiment.
  - Runs preprocessing, compilation, execution, and independent replay.
  - Uses argument arrays instead of shell command strings.
- `pipeline/codecourt/evidence.py`
  - Performs deterministic checks over saved logs and source hashes.
  - Validates Defense citations against saved artifacts.
- `pipeline/codecourt/court.py`
  - Coordinates rounds, duplicate detection, execution budgets, feedback, and verdicts.
- `pipeline/reporter.py`
  - Produces the aggregate `verification_report.json` and CodeCourt verdict percentages.
- `scripts/run_pipeline.sh`
  - Connects Infer output and CodeCourt into one source-root-to-report command.

## Experiment lifecycle

1. The warning identity and source version are saved.
2. Prosecutor proposes one `ExperimentPlan`.
3. The plan is schema- and safety-validated.
4. Runner writes immutable evidence inputs and builds the target.
5. Runner executes the target and stores raw stdout/stderr.
6. Evidence Verifier checks sanitizer type, source frame, location, procedure, and context.
7. Defense reviews the same artifacts and cites exact lines for objections.
8. Judge either requests a materially different plan or starts an independent replay.
9. Matching replay evidence can produce `CONFIRMED_TRUE`; otherwise the warning remains
   `UNRESOLVED` when the budget ends.

## Evidence layout

```text
<output>/codecourt/<source>_<line>_<type>_<hash>/
  warning.json
  round_01/
    plan.json
    original.c
    mock.c
    harness.c
    inputs.json
    manifest.json
    compile.stdout
    compile.stderr
    run_1.stdout
    run_1.stderr
    run_2.stdout
    run_2.stderr
    prosecutor_request.json
    prosecutor_response.txt
    defense_request.json
    defense_response.txt
    court_report.json
```

The absolute source path is kept inside the manifest for reproducibility, while
the directory name uses a short hash so output paths remain manageable.

## Trust model

- Infer report, source, comments, Agent responses, and runtime logs are data inputs.
- Agent responses never directly set a verdict.
- Compiler flags and extra source files come from the user build configuration.
- A generated mock can support investigation but cannot by itself establish a
  real-world confirmation.
- `BOUNDED_FALSE_POSITIVE` remains disabled until a bounded or formal proof mode exists.
