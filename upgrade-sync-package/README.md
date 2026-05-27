<!--
Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)

Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Upgrade Sync Package

## 1. Purpose

This folder is a handoff package for the newer upgraded multi-repository version of the project.

The upgraded project has already diverged and has its own commit history, including improvements such as stronger security handling and support for Chinese cryptographic algorithms. This package is **not** intended to overwrite that newer line of work.

Instead, this package extracts a small set of materials from the current repository that may still be useful for the upgraded project, especially in the following areas:

- repeatable research evaluation,
- lifecycle and discovery experiment orchestration,
- scalability bottleneck analysis,
- paper-oriented baseline comparison improvement strategy.

The intended consumer is another large model or engineering assistant working against the upgraded project. It should inspect these materials and decide which parts are worth absorbing, adapting, or re-implementing in the upgraded codebase.

## 2. Important scope note

The materials here mainly come from the recent three commits in this repository that affected:

- research evaluation harnesses,
- generated experiment result artifacts,
- analysis documents derived from those experiments.

They do **not** represent a fresh upgrade of the current repository's core Rust services. In particular:

- there were no direct core-module logic changes in those recent commits,
- there were no new production SDK implementations in those recent commits,
- the value here is mostly in test harness design, experiment structure, result shaping, and engineering analysis.

## 3. What is included

### `docs/`

- `scalability-bottleneck-analysis.md`
  - analyzes where the current prototype's bottlenecks really are,
  - separates hardware factors from lifecycle-ingestion, publication, synchronization, persistence, and test-harness costs,
  - gives a priority order for future optimization.

- `baseline-comparison-improvement-guide.md`
  - explains how to strengthen paper baseline comparison without forcing unfair heterogeneous external-system comparisons,
  - recommends mechanism-level baselines and degraded internal baselines,
  - maps future experiments to specific claimed properties.

### `research-evaluation/`

This is a standalone experiment harness that runs outside the core service implementations.

Included files:

- `common.ps1`
  - common orchestration layer for experiment setup and teardown,
  - workspace reset,
  - temporary config generation,
  - service startup and health checks,
  - registrar/discovery authorization,
  - helper utilities for HTTP calls, timing, result writing, and storage measurement.

- `generate-dataset.mjs`
  - batch dataset generator based on the demo service-agent DID document template,
  - creates multiple synthetic agents with changed DID values, capability tags, descriptions, and ports.

- `run-lifecycle.ps1`
  - end-to-end lifecycle correctness experiment.

- `run-negative.ps1`
  - negative verification regression wrapper built on top of the existing trusted invocation negative-case script.

- `run-auth-discovery.ps1`
  - authorization-aware discovery experiment based on capability-domain scoping.

- `run-scalability.ps1`
  - scalability experiment for registration, publication, notification, synchronization, query latency, throughput, and storage growth.

- `run-all.ps1`
  - all-in-one runner for the evaluation set.

- `debug-discovery-sync.ps1`
  - targeted debugging helper for discovery synchronization problems.

- `debug-root-authorize.ps1`
  - targeted debugging helper for root authorization issues.

### `research-evaluation/results/`

These are sample machine-readable experiment outputs:

- `lifecycle-result.json`
- `negative-result.json`
- `auth-discovery-result.json`
- `scalability-result.json`
- `scalability-result.csv`

These should be treated as example result shapes and historical reference data, not as canonical performance values for the upgraded project.

## 4. What the upgraded project should inspect carefully

The upgraded project should pay attention to the following extracted ideas.

### 4.1 Decoupled research-evaluation harness

The evaluation scripts intentionally avoid modifying the core services. This makes them useful as:

- reproducible research tooling,
- regression harnesses,
- demo orchestration,
- future CI support.

The upgraded project may want to preserve this separation rather than mixing paper experiments into production modules.

### 4.2 One-command lifecycle orchestration

The harness automatically:

- builds a clean temporary workspace,
- generates node configs,
- launches root, registrar, discovery, and CDN,
- waits for readiness,
- authorizes registrar and discovery,
- drives the full lifecycle path.

This pattern is useful for the upgraded project even if ports, config layouts, service names, and security assumptions have changed.

### 4.3 Structured experimental outputs

The scripts emit stable JSON and CSV artifacts instead of relying only on console logs.

This is important because the upgraded project may later need:

- reproducible paper figures,
- benchmark regressions,
- commit-to-commit performance comparisons,
- CI summaries,
- traceable experiment archives.

### 4.4 Stage-level scalability measurement

The scalability flow does not only measure "whether the system is fast." It separately measures:

- registration,
- publication,
- notification,
- synchronization,
- query latency,
- throughput,
- storage growth.

This stage-level measurement is useful for diagnosing lifecycle-ingestion bottlenecks in any future version of the system.

### 4.5 Mechanism-level baseline strategy

The baseline guide recommends:

- property-coverage comparisons,
- degraded internal baselines,
- overhead-vs-property comparisons,
- avoiding risky direct reproduction of heterogeneous external systems.

This is likely still useful for the upgraded project's future papers.

## 5. What should not be copied mechanically

The upgraded project should **not** assume that these scripts or result assumptions can be copied unchanged.

Reasons:

- the upgraded project already has different code and repository structure,
- security logic may already be stronger there,
- cryptographic handling may already differ,
- APIs, ports, config layouts, or DID/VC handling may have evolved,
- multi-repository boundaries may require different orchestration logic.

The correct use of this package is:

- absorb the experiment architecture,
- absorb the result schema ideas,
- absorb the bottleneck-analysis reasoning,
- absorb the baseline-improvement strategy,
- then adapt implementation details to the upgraded project's current reality.

## 6. Recommended absorption order for the upgraded project

The upgraded project should consider the following order.

### Step 1

Review `docs/scalability-bottleneck-analysis.md` and decide whether the same bottleneck classes still exist in the upgraded architecture.

### Step 2

Review `research-evaluation/common.ps1` and the four experiment scripts, then decide whether to rebuild an equivalent harness in:

- PowerShell,
- Rust,
- TypeScript,
- or another orchestration language more appropriate for the upgraded project.

### Step 3

Review the result files and preserve the useful metric schema where it still matches the upgraded project's architecture.

### Step 4

Review `docs/baseline-comparison-improvement-guide.md` when planning future paper revisions or new paper submissions.

## 7. Final instruction for the receiving model

Do not treat this package as a patch set to apply directly.

Treat it as:

- a distilled reference package,
- containing experiment design ideas,
- result-shaping patterns,
- and analytical guidance

that may inform the upgraded project's own implementation and paper-support tooling.
