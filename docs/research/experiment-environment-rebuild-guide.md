# OAN Paper Experiment Environment Rebuild Guide

This guide explains how to rebuild the experiment environment used by the
paper under `docs/research/paper` after cloning the OAN repositories again.
It is intended for future paper revisions and follow-up experiments.

## Repository Layout

Use one workspace directory and keep the repositories as siblings:

```text
OAN/
  OAN-v1.0-Legacy/
  oan-examples/
  oan-reference-services/
  oan-protocol-common/
  oan-agent-py/
  ...
```

The paper source and archived experiment records live in:

```text
OAN-v1.0-Legacy/docs/research/
```

The primary new-version experiment harness lives in:

```text
oan-examples/
```

The reference service implementation started by the harness lives in:

```text
oan-reference-services/
```

## Required Tools

Install or verify these tools before running experiments:

- Git
- Node.js and npm
- Rust toolchain
- Python and `uv`
- LaTeX toolchain with `pdflatex` and `bibtex`

The reported paper run used a single Windows host. The multi-node experiments
are logical multi-service runs on one host, not multi-physical-machine
deployments.

## Clone and Update

From the workspace directory:

```powershell
git clone https://github.com/OpenAgenet/OAN-v1.0-Legacy
git clone https://github.com/OpenAgenet/oan-examples
git clone https://github.com/OpenAgenet/oan-reference-services
git clone https://github.com/wolfbrother/oan-protocol-common
git clone https://github.com/OpenAgenet/oan-agent-py
```

Other OAN repositories may be cloned as needed, but the paper experiments are
primarily driven by the repositories above.

Before a new run, update each repository:

```powershell
git -C OAN-v1.0-Legacy pull
git -C oan-examples pull
git -C oan-reference-services pull
git -C oan-protocol-common pull
git -C oan-agent-py pull
```

## Important Directory Boundary

Treat the new-version repositories as experiment subjects. Do not store paper
notes, interpreted analysis, or final paper data in those repositories.

The `oan-examples` benchmark scripts start services from
`oan-reference-services` by default. During a run, they may create runtime
state under `oan-reference-services`, including:

```text
oan-reference-services/.oan-benchmark-*/
oan-reference-services/data/
*.db-wal
*.db-shm
```

These files are runtime byproducts. They should normally not be committed to
`oan-reference-services`.

Archive reusable experiment evidence under:

```text
OAN-v1.0-Legacy/docs/research/redo-experiments/
```

## Default Path Resolution

The scripts assume the sibling layout above. If the repositories are elsewhere,
set explicit environment variables:

```powershell
$env:OAN_WORKSPACE_ROOT = "D:\Works\VscodeProject\OAN"
$env:OAN_REFERENCE_SERVICES_ROOT = "$env:OAN_WORKSPACE_ROOT\oan-reference-services"
$env:OAN_PROTOCOL_COMMON_ROOT = "$env:OAN_WORKSPACE_ROOT\oan-protocol-common"
$env:OAN_AGENT_PY_ROOT = "$env:OAN_WORKSPACE_ROOT\oan-agent-py"
```

## Smoke and Integration Checks

Run these from `oan-examples`:

```powershell
cd D:\Works\VscodeProject\OAN\oan-examples
.\scripts\run-smoke-tests.ps1
.\scripts\run-e2e-demo.ps1
.\trusted-invocation-negative-cases\run.ps1
.\multi-registrar-discovery\run.ps1
```

These checks confirm that the reference services, agent examples, trusted
invocation flow, and multi-registrar discovery path are usable before running
larger measurements.

## Benchmark Runs

The main benchmark scripts are under:

```text
oan-examples/scripts/bench/
```

The important scripts are:

```text
single-node-benchmark.ts
multi-node-benchmark.ts
registrar-submit-path-benchmark.ts
```

The benchmark harness writes working service state under
`oan-reference-services/.oan-benchmark-*` and writes benchmark reports under
`oan-examples/.oan-benchmark-reports/`.

After a successful run, copy the report JSON and summary files needed by the
paper into a timestamped directory under:

```text
OAN-v1.0-Legacy/docs/research/redo-experiments/runs/
```

Then update:

```text
OAN-v1.0-Legacy/docs/research/redo-experiments/reports/
OAN-v1.0-Legacy/docs/research/paper/figs/
OAN-v1.0-Legacy/docs/research/paper/main.tex
```

## Ablation Experiments

The real-system degraded baselines are intentionally isolated inside the Legacy
research workspace:

```text
OAN-v1.0-Legacy/docs/research/redo-experiments/system-ablation/
```

Use this copy for mechanism-removal experiments so that the new-version
repositories remain unchanged unless an actual implementation bug is found.

The current ablation driver is:

```text
OAN-v1.0-Legacy/docs/research/redo-experiments/baselines/run-ablation-baselines.mjs
```

Store raw ablation outputs under:

```text
OAN-v1.0-Legacy/docs/research/redo-experiments/system-ablation/reports/raw/
```

and summarized results under:

```text
OAN-v1.0-Legacy/docs/research/redo-experiments/reports/
```

## Paper Rebuild

After updating tables, figures, or references, rebuild the paper from:

```powershell
cd D:\Works\VscodeProject\OAN\OAN-v1.0-Legacy\docs\research\paper
pdflatex -interaction=nonstopmode main.tex
bibtex main
pdflatex -interaction=nonstopmode main.tex
pdflatex -interaction=nonstopmode main.tex
```

Check that there are no undefined citations or unresolved references. A small
number of layout warnings may remain because of narrow IEEE two-column tables.

## Git Hygiene

Commit paper artifacts and archived experiment evidence in
`OAN-v1.0-Legacy`.

Do not commit runtime byproducts in `oan-reference-services` unless they are
deliberately turned into stable fixtures. In normal experiment runs, these
should remain uncommitted or be cleaned:

```text
.oan-benchmark-*/
data/** runtime outputs
*.db-wal
*.db-shm
```

Only modify and commit a new-version repository when a real code defect is
found and fixed. In that case, include the failing scenario, expected behavior,
observed behavior, fix, and verification command in the commit message.
