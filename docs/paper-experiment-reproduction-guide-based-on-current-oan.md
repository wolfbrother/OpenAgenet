<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Reproducing the Paper Experiments with the Current Multi-Repository OAN

## 1. Purpose

This document explains how to reproduce the experiments described in
`docs/research/paper/` of the legacy single-repository version
`OAN-v1.0-Legacy`, but using the current multi-repository OAN workspace.

It is written for two audiences at once:

- human maintainers who need a practical reproduction map
- large models that already have access to the current OAN repositories and need
  a fast way to understand which repository does what and how to rerun the paper
  evaluation

The goal is not to recreate the legacy repository layout. The goal is to
recreate the paper's experiment semantics using the current repositories,
services, scripts, and benchmark outputs.

## 2. Read This First

The paper materials are located at:

- `OAN-v1.0-Legacy/docs/research/paper/main.tex`
- `OAN-v1.0-Legacy/docs/research/paper/main.pdf`

The evaluation section in the paper defines four experiment classes:

1. Lifecycle correctness
2. Negative verification
3. Authorization-aware discovery
4. Scalability and overhead

The current OAN implementation no longer lives in one repository. The
equivalent functionality is now spread across multiple repositories. To
reproduce the experiments, the correct mental model is:

- `OAN-v1.0-Legacy` is the historical paper and reference context
- the runnable implementation is now under the current `OAN/` workspace

## 3. Current Repository Mapping

The most important repositories for reproducing the paper experiments are:

### 3.1 Core Protocol and Data Model

- `oan-protocol-common`

Use this repository for:

- DID, VC, proof, package, bulletin, and protocol object definitions
- shared crypto and verification logic
- understanding canonical object shapes used by Root, Registrar, Discovery, and
  CDN

### 3.2 Reference Runtime Services

- `oan-reference-services`

Use this repository for the actual Rust infrastructure services:

- Root Node
- Registrar Node
- Discovery Node
- CDN Service

This repository is the main runtime substrate for all paper experiments.

### 3.3 Example Flows and Benchmarks

- `oan-examples`

Use this repository for:

- end-to-end happy-path demos
- negative-case executable examples
- multi-Registrar / multi-Discovery examples
- single-node and multi-node benchmark scripts
- smoke/regression scripts

This repository is the main experiment runner.

### 3.4 Python Agent Demo

- `oan-agent-py`

Use this repository when the paper experiment needs:

- User Agent -> Discovery -> Service Agent pre-connection validation
- signed invocation and signed response verification
- demo-level Agent interaction proof that follows discovery

### 3.5 Design and Performance Context

- `oan-design-docs`

Use this repository to understand:

- current architecture
- trust model
- current performance bottleneck interpretation
- current worker/lease-driven propagation semantics

This repository is not the main execution substrate, but it explains the
current implementation state that differs from the paper's earlier version.

## 4. Important Difference Between the Paper Version and the Current Version

The paper in `OAN-v1.0-Legacy` was written against an earlier implementation
generation. The current OAN codebase is not identical, and some mechanisms are
cleaner or more explicit now.

The main differences that matter for reproduction are:

- the system is now split into multiple repositories
- Root -> CDN -> Discovery propagation is now worker/lease-driven
- Root -> Discovery now uses target watermark notifications instead of the older
  per-package mental model
- the current system supports stronger trusted-upstream authentication and
  subject-control proof handling
- benchmark scripts and outputs are now more detailed and stage-oriented
- current benchmark numbers are different from the numbers frozen into the paper

Therefore:

- the experiment semantics should be reproduced
- the exact historical latency numbers should not be expected to match
- the current system should be treated as a newer implementation used to rerun
  the same research questions and hypotheses

## 5. Experiment-to-Repository Mapping

This section is the most important operational map.

### 5.1 Experiment 1: Lifecycle Correctness

Paper location:

- `main.tex`, section `Experiment 1: Lifecycle Correctness`

Paper intent:

- registration
- Root acceptance
- anchoring
- discovery verification and indexing
- governed query
- pre-connection validation between User Agent and Service Agent

Current repository mapping:

- `oan-reference-services`: Root / Registrar / Discovery / CDN runtime
- `oan-agent-py`: User Agent and Service Agent demo interaction
- `oan-examples/scripts/run-e2e-demo.ps1`: best current executable entry
- `oan-examples/scripts/run-smoke-tests.ps1`: regression wrapper with explicit
  assertions

Recommended current command:

```powershell
cd D:\WorkFiles\VscodeProject\OAN\oan-examples
.\scripts\run-e2e-demo.ps1
```

What this already demonstrates:

- draft creation
- draft validation
- DID control challenge and proof
- registration credential issuance
- Registrar -> Root submission
- Root -> CDN publish
- Root -> Discovery notify and sync
- discovery query
- User Agent signed invocation
- Service Agent verification of discovery proof and caller credential
- Service Agent signed response
- User Agent verification of response provenance

What to record for the paper rerun:

- registration success
- accepted DID/version identity
- discovery indexed candidate count
- discovery proof verification
- request/response signature verification
- total propagation time
- query latency

Best current data source:

- the JSON output emitted by `run-e2e-demo.ps1`
- the explicit assertions in `run-smoke-tests.ps1`

### 5.2 Experiment 2: Negative Verification

Paper location:

- `main.tex`, section `Experiment 2: Negative Verification`

Paper intent:

- invalid or malicious inputs should be rejected
- false acceptance rate should be zero within the tested suite

Current repository mapping:

- `oan-examples/trusted-invocation-negative-cases/run.ps1`
- `oan-examples/scripts/run-smoke-tests.ps1`
- `oan-reference-services` and `oan-agent-py` provide the runtime behavior
  being attacked

Recommended current commands:

```powershell
cd D:\WorkFiles\VscodeProject\OAN\oan-examples
.\trusted-invocation-negative-cases\run.ps1
.\scripts\run-smoke-tests.ps1
```

What this already covers well:

- tampered signed content
- invalid request proofs
- replay-related negative cases in the trusted invocation demo path
- current cross-service verification regressions

What the paper listed that should be mapped carefully:

- invalid registration credentials
- wrong VC subject
- unauthorized registrar
- unauthorized discovery scope
- replayed invocation nonce
- expired timestamp
- wrong target identifier

Current practical guidance:

- use `trusted-invocation-negative-cases/run.ps1` for the invocation-side
  rejection experiments
- use `run-smoke-tests.ps1` plus Root/Discovery service tests in
  `oan-reference-services` when you need service-side governance rejection
  evidence

If a stricter paper rerun needs a single aggregated "false acceptance rate"
table, build that table from:

- current negative example output
- current service test results
- any additional targeted script you add under `oan-examples` specifically for
  paper reporting

### 5.3 Experiment 3: Authorization-Aware Discovery

Paper location:

- `main.tex`, section `Experiment 3: Authorization-Aware Discovery`

Paper intent:

- different Discovery services have different authorized domains
- in-scope identities should be indexed and returned
- out-of-scope identities should be excluded
- policy enforcement accuracy should be measured separately from generic query
  behavior

Current repository mapping:

- `oan-reference-services`: Discovery authorization and domain-scoped indexing
- `oan-examples/multi-registrar-discovery/run.ps1`
- `oan-examples/scripts/run-smoke-tests.ps1`

Recommended baseline command:

```powershell
cd D:\WorkFiles\VscodeProject\OAN\oan-examples
.\multi-registrar-discovery\run.ps1
```

Important note:

The current `multi-registrar-discovery` example is a very useful multi-node
integration harness, but by default it authorizes both Discovery nodes with
`authorizedDomains = ["*"]`.

This means:

- it directly demonstrates multi-Registrar / multi-Discovery behavior
- it does not by itself reproduce the full domain-restricted H3 experiment

To reproduce the paper's H3 semantics, use the current example as the base
fixture and then modify or clone it so that:

- Discovery A is authorized only for one capability domain
- Discovery B is authorized for another domain or wildcard
- the submitted Agent set includes in-scope and out-of-scope capability tags
- queries are run against both Discovery nodes

The code points to adjust are already visible in:

- `oan-examples/multi-registrar-discovery/run.ps1`

Specifically, look for:

- Root authorization of Discovery nodes
- `/root/discovery-nodes/{did}/domains`
- assigned `capabilityTags`

Recommended current strategy for H3 rerun:

1. Copy the current multi-node example to a paper-specific variant.
2. Replace wildcard `authorizedDomains` with scoped domains.
3. Create several service agents tagged across multiple domains.
4. Query each Discovery node with the same search pattern.
5. Measure:
   - authorized acceptance count
   - unauthorized rejection count
   - policy enforcement accuracy
   - query latency per Discovery node

### 5.4 Experiment 4: Scalability and Overhead

Paper location:

- `main.tex`, section `Experiment 4: Scalability and Overhead`

Paper intent:

- vary number of identities
- vary Discovery services
- observe registration throughput
- observe registration latency
- observe publication / synchronization / query cost

Current repository mapping:

- `oan-examples/scripts/bench/single-node-benchmark.ts`
- `oan-examples/scripts/bench/multi-node-benchmark.ts`
- `oan-examples/scripts/bench/registrar-submit-path-benchmark.ts`
- `oan-examples/.bench-dist/*.js`
- `oan-examples/.oan-benchmark-reports/`

Recommended current commands:

Single-node:

```powershell
cd D:\WorkFiles\VscodeProject\OAN\oan-examples
node .\.bench-dist\single-node-benchmark.js
```

Multi-node:

```powershell
cd D:\WorkFiles\VscodeProject\OAN\oan-examples
node .\.bench-dist\multi-node-benchmark.js
```

Registrar submit-path focused:

```powershell
cd D:\WorkFiles\VscodeProject\OAN\oan-examples
node .\.bench-dist\registrar-submit-path-benchmark.js
```

Scale control:

```powershell
$env:OAN_BENCH_SCALES="10,50,100,200,500,1000"
node .\.bench-dist\single-node-benchmark.js
```

```powershell
$env:OAN_BENCH_SCALES="100,200,500"
node .\.bench-dist\multi-node-benchmark.js
```

Current benchmark report outputs live under:

- `oan-examples/.oan-benchmark-reports/single-node-e2e/...`
- `oan-examples/.oan-benchmark-reports/multi-node-e2e/...`
- `oan-examples/.oan-benchmark-reports/registrar-submit-path/...`

Useful output files:

- `summary.json`
- `summary.md`

The current `summary.json` files are richer than the paper-era result layout.
They already include stage-level metrics such as:

- `registrar.submitToRoot`
- `root.publishCdnBatch`
- `root.notifyDiscoveryBatch`
- `discovery.sync`
- `discovery.query`
- grouped stage statistics
- root status and discovery status snapshots

## 6. How to Map Current Outputs Back to the Paper Metrics

The paper defines these main metrics:

- registration success rate
- index correctness
- false acceptance rate
- policy enforcement accuracy
- verification cost per representation
- registration throughput
- propagation time
- authorization filtering overhead

The current system can reproduce them as follows.

### 6.1 Registration Success Rate

Use:

- count of successfully submitted and accepted agents in benchmark summaries
- successful lifecycle demo completion

Primary sources:

- `run-e2e-demo.ps1` output
- `summary.json` in benchmark report directories

### 6.2 Index Correctness

Use:

- `missingCount`
- `discoveredCount`
- Discovery status snapshots

Primary sources:

- single-node and multi-node benchmark `summary.json`

### 6.3 False Acceptance Rate

Use:

- negative example rejection outcomes
- service-level regression tests when needed

Primary sources:

- `trusted-invocation-negative-cases/run.ps1`
- `run-smoke-tests.ps1`
- current service tests in `oan-reference-services`

### 6.4 Policy Enforcement Accuracy

Use:

- domain-scoped multi-Discovery experiment described above
- compare expected visibility set vs actual visibility set per Discovery node

This is the one experiment that most likely needs a dedicated paper-specific
wrapper script on top of the current examples.

### 6.5 Registration Throughput and Registration Latency

Use:

- `registrationThroughputPerSec`
- `registrar.submitToRoot`
- stage-group summaries for Root accept path

Primary sources:

- benchmark `summary.json`

### 6.6 Propagation Time

Map paper-era propagation semantics to current stage metrics:

- Root publish latency
- Root notify latency
- Discovery sync latency

Current sources:

- `root.publishCdnBatch`
- `root.notifyDiscoveryBatch`
- `discovery.sync`

### 6.7 Query Latency

Use:

- `discovery.query`

Primary sources:

- benchmark `summary.json`
- scoped H3 query rerun output

## 7. Legacy Figure and Data Regeneration

The legacy paper contains figure-generation helpers under:

- `OAN-v1.0-Legacy/docs/research/paper/figs/generate_evaluation_figures.py`

That script expects a legacy results layout under:

- `examples/research-evaluation/results`

The current OAN benchmark outputs do not use that exact directory structure.

So for paper regeneration with the current repositories, the recommended
approach is:

1. run the current experiments with `oan-examples`
2. collect the needed values from current `summary.json` outputs
3. write a small adapter script that converts the current benchmark outputs into
   the legacy paper data files:
   - `evaluation_latency_breakdown.dat`
   - `evaluation_scalability.dat`
   - `evaluation_scalability_latency.dat`
   - `evaluation_scalability_throughput.dat`
4. regenerate the paper figures

In other words:

- keep the paper's LaTeX and figure structure
- adapt the data ingestion layer, not the current runtime implementation

## 8. Recommended Reproduction Plan

If a large model or a maintainer wants the fastest path to reproduce the paper
with the current OAN, use this sequence.

### Phase A: Understand the Paper Target

Read:

- `OAN-v1.0-Legacy/docs/research/paper/main.tex`

Focus on:

- evaluation matrix
- metric definitions
- the four experiment sections

### Phase B: Understand the Current Runnable System

Read:

- `oan-design-docs/docs/system/design.md`
- `oan-design-docs/docs/system/performance-and-scalability-analysis.md`
- `oan-examples/README.md`

This gives the current architectural and experiment-entry context.

### Phase C: Reproduce Lifecycle and Negative Experiments First

Run:

```powershell
cd D:\WorkFiles\VscodeProject\OAN\oan-examples
.\scripts\run-e2e-demo.ps1
.\trusted-invocation-negative-cases\run.ps1
.\scripts\run-smoke-tests.ps1
```

These cover the fastest validation of H1 and much of H2.

### Phase D: Reproduce Multi-Node and Scalability Runs

Run:

```powershell
cd D:\WorkFiles\VscodeProject\OAN\oan-examples
node .\.bench-dist\single-node-benchmark.js
node .\.bench-dist\multi-node-benchmark.js
```

Use environment variables to restrict or expand scale points as needed.

### Phase E: Add a Paper-Specific Authorization Discovery Wrapper

Because current `multi-registrar-discovery/run.ps1` defaults to wildcard
domains, create a paper-oriented variant that:

- sets different `authorizedDomains`
- seeds in-scope and out-of-scope agents
- records policy accuracy metrics

This is the main custom experiment wrapper still worth adding.

### Phase F: Adapt Current Results to Legacy Paper Figures

Build an adapter that reads:

- current benchmark `summary.json`
- current lifecycle / negative / auth-discovery outputs

and writes:

- legacy `.dat` files expected by the paper figure generation workflow

## 9. Practical Command Notes

### 9.1 If `.bench-dist` Needs Rebuild

The current benchmark JavaScript files are emitted under:

- `oan-examples/.bench-dist`

If they need rebuilding, use the benchmark TypeScript config:

- `oan-examples/tsconfig.bench.json`

The usual approach is to compile the benchmark TypeScript sources into
`.bench-dist` and then run the resulting `.js` files with Node.

### 9.2 Python Agent Dependencies

When the lifecycle experiment involves User Agent and Service Agent flows,
ensure `oan-agent-py` dependencies are ready via `uv`, because the current demo
depends on the Python agent repositories.

### 9.3 Service Binaries

The benchmark scripts expect the Rust reference-service binaries to be
available. They bootstrap temporary benchmark runtime directories and seed data
from `oan-reference-services/data/...`.

## 10. What Is Directly Reusable vs What Still Needs Lightweight Adaptation

### Directly Reusable

- lifecycle demo
- smoke regression
- trusted invocation negative cases
- multi-Registrar / multi-Discovery base integration example
- single-node benchmark
- multi-node benchmark
- submit-path focused benchmark

### Needs Lightweight Adaptation

- paper-style authorization-aware discovery with distinct domain scopes
- legacy figure data regeneration
- a paper-style aggregated false-acceptance table if one unified JSON artifact
  is desired

## 11. Final Guidance for Large Models

If a large model has already loaded the current OAN repositories, it should use
this decision tree:

1. Read the paper evaluation section in `OAN-v1.0-Legacy/docs/research/paper/main.tex`.
2. Map lifecycle to `oan-examples/scripts/run-e2e-demo.ps1`.
3. Map negative verification to
   `oan-examples/trusted-invocation-negative-cases/run.ps1` and
   `oan-examples/scripts/run-smoke-tests.ps1`.
4. Map scalability to `oan-examples/.bench-dist/single-node-benchmark.js` and
   `oan-examples/.bench-dist/multi-node-benchmark.js`.
5. Treat authorization-aware discovery as a small extension of
   `oan-examples/multi-registrar-discovery/run.ps1`, not as a completely new
   system.
6. Treat `oan-reference-services` as the runtime source of truth and
   `oan-design-docs` as the architecture/performance interpretation source.
7. Do not try to recreate the old single-repo filesystem layout. Recreate the
   experiment semantics on top of the current multi-repo system.

That is the fastest correct way to rerun the paper experiments with the current
OAN.
