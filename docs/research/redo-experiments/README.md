# OAN New-Version Experiment Redo Workspace

This directory is the research workspace for re-running the paper experiments
against the newer multi-repository OAN implementation.

## Purpose

The original paper under `docs/research/paper` was written against the legacy
single-repository implementation. The newer OAN implementation is split across
multiple repositories and has more complete reference services, examples,
integration tests, and benchmark scripts.

This workspace records how to redo the existing paper experiments and how to
add follow-up experiments without rewriting the paper source or modifying the
newer repositories unnecessarily.

## Repository Boundary

The newer repositories are treated as read-only experiment subjects by default:

- `../../../../oan-protocol-common`
- `../../../../oan-reference-services`
- `../../../../oan-agent-py`
- `../../../../oan-examples`
- other newer OAN repositories as needed

Do not edit those repositories for experiment bookkeeping, paper notes, copied
results, or ad hoc analysis.

Only modify a newer repository when the experiment reveals an actual code bug
that must be fixed to make the implementation correct. In that case, document:

- the failing scenario;
- the expected behavior;
- the observed behavior;
- the repository and commit involved;
- the fix and verification command.

## Initial Experiment Plan

1. Reproduce the paper's existing experiment categories on the new codebase:
   lifecycle correctness, negative verification, authorization-aware discovery,
   and scalability/overhead.
2. Use `oan-examples` as the primary execution harness:
   smoke tests, end-to-end demo, trusted invocation negative cases,
   multi-registrar discovery, and benchmark scripts.
3. Store generated reports, summaries, copied benchmark outputs, and analysis
   notes under this directory.
4. Keep raw generated data separate from interpreted analysis.
5. Add follow-up degraded-baseline experiments later, especially:
   no authorization-aware filtering, no anchored current-version validation,
   no pre-connection freshness validation, and no registration-credential
   verification.

## Suggested Layout

```text
redo-experiments/
  README.md
  plans/
  runs/
  reports/
  analysis/
  baselines/
```

Suggested use:

- `plans/`: experiment protocols and command plans.
- `runs/`: per-run metadata, environment notes, and copied raw outputs.
- `reports/`: summarized tables and figures for paper revision.
- `analysis/`: interpretation notes and comparison against legacy results.
- `baselines/`: designs and results for degraded internal baselines.

## Primary Commands

From the workspace root:

```powershell
cd D:\Works\VscodeProject\OAN\oan-examples
.\scripts\run-smoke-tests.ps1
.\scripts\run-e2e-demo.ps1
.\trusted-invocation-negative-cases\run.ps1
.\multi-registrar-discovery\run.ps1
```

Benchmark scripts live under `oan-examples/scripts/bench`.

Use environment variables such as `OAN_WORKSPACE_ROOT`,
`OAN_REFERENCE_SERVICES_ROOT`, `OAN_PROTOCOL_COMMON_ROOT`, and
`OAN_AGENT_PY_ROOT` only when the default sibling-repository layout is not used.

