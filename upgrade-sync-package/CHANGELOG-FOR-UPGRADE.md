<!--
Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)

Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Changelog For Upgrade

This file summarizes the recent useful takeaways from this repository in a compact "problem -> solution idea -> migration suggestion" form for the upgraded multi-repository version.

It is intentionally concise and action-oriented.

## 1. No reusable patch to core Rust services, but strong reusable evaluation assets

### Problem

The recent work in this repository did not directly improve the core Rust service logic, so there is no obvious service-layer patch set to cherry-pick into the upgraded version.

### Solution idea developed here

Instead of changing the service internals, the recent work added:

- a decoupled research-evaluation harness,
- structured experiment outputs,
- scalability bottleneck analysis,
- and a paper baseline-improvement strategy.

### Migration suggestion

Do not search this package for direct production-service patches.

Use it as:

- evaluation-tooling input,
- experiment-design input,
- and analysis-guidance input.

## 2. Research experiments needed a repeatable orchestration layer

### Problem

The system could run, but repeatable lifecycle, authorization, negative-case, and scalability experiments were difficult to reproduce manually.

### Solution idea developed here

A standalone orchestration layer was added in:

- `research-evaluation/common.ps1`

It provides:

- clean temporary workspace creation,
- temporary node config generation,
- automatic startup and teardown of root, registrar, discovery, and CDN,
- health checks,
- initial authorization setup,
- helper functions for POST requests, timing, and storage measurement.

### Migration suggestion

The upgraded project should implement an equivalent harness in the most suitable orchestration language for its current stack.

The exact PowerShell implementation does not need to be preserved, but the following capabilities should be preserved:

- one-command clean environment setup,
- automatic node startup,
- health gating,
- deterministic experiment preparation,
- automatic cleanup.

## 3. Batch experimental data generation was missing

### Problem

Lifecycle and scalability experiments required many DID-document-based agent samples, and manual construction was not scalable.

### Solution idea developed here

A dataset generator was added in:

- `research-evaluation/generate-dataset.mjs`

It clones a template DID document and automatically varies:

- DID values,
- capability tags,
- descriptions,
- service endpoints and ports.

### Migration suggestion

The upgraded project should keep the "template + synthetic variant generation" pattern.

Even if the upgraded project now uses stronger security logic or different DID/VC handling, it still benefits from:

- deterministic synthetic datasets,
- capability-tag-controlled datasets,
- scalable sample generation for lifecycle and discovery tests.

## 4. Lifecycle correctness needed to be validated as an end-to-end path

### Problem

The system needed a small but complete end-to-end experiment that verified:

- registration,
- publication,
- discovery notification,
- synchronization,
- and successful discovery query.

### Solution idea developed here

An end-to-end lifecycle experiment was added in:

- `research-evaluation/run-lifecycle.ps1`

It measures:

- registration latency,
- publish latency,
- notify latency,
- sync latency,
- query latency,
- propagation time,
- candidate count,
- storage size.

### Migration suggestion

The upgraded project should preserve this experiment shape.

Even if the internals have changed, this is still a useful minimal regression and paper-support experiment.

## 5. Negative verification was previously under-structured

### Problem

Negative-case validation existed, but it was not packaged as a paper-oriented, machine-readable experiment summary.

### Solution idea developed here

A wrapper experiment was added in:

- `research-evaluation/run-negative.ps1`

It executes the existing negative-case script, extracts the JSON summary, and writes:

- status,
- elapsed time,
- positive checks,
- negative checks,
- false acceptance summary.

### Migration suggestion

The upgraded project should treat negative cases as first-class regression outputs rather than one-off logs.

Also extend the scope beyond trusted invocation when appropriate, for example:

- root-side registration rejection,
- malformed proof handling,
- discovery-side synchronization rejection.

## 6. Authorization-aware discovery needed explicit quantitative verification

### Problem

Authorization-scoped discovery is a key mechanism, but it needed direct evidence that:

- in-domain results are returned,
- out-of-domain results are hidden,
- and policy enforcement can be quantified.

### Solution idea developed here

A dedicated experiment was added in:

- `research-evaluation/run-auth-discovery.ps1`

It sets authorized domains, constructs mixed-domain datasets, and measures:

- authorized candidate count,
- unauthorized candidate count,
- policy enforcement accuracy,
- authorized query latency,
- unauthorized query latency.

### Migration suggestion

The upgraded project should preserve an experiment of this class.

If the upgraded project now supports more advanced authorization, security, or cryptographic policy, the experiment should be extended rather than removed.

## 7. Scalability evaluation needed stage-level measurements rather than only a single coarse metric

### Problem

A raw throughput number was not enough to explain where the real bottlenecks were.

### Solution idea developed here

A scalability experiment was added in:

- `research-evaluation/run-scalability.ps1`

It separately measures:

- registration total latency,
- average registration latency,
- registration P95,
- throughput,
- publish latency,
- notify latency,
- sync latency,
- query latency,
- storage size.

### Migration suggestion

The upgraded project should preserve this stage-level metric breakdown.

Do not collapse these lifecycle stages into a single number, because the main insight from the current project was that:

- query behavior stayed relatively stable,
- while registration, publication, and synchronization became the dominant bottlenecks.

## 8. Debugging complex lifecycle failures needed targeted helper scripts

### Problem

When lifecycle propagation failed, all-in-one experiment runners were not enough for diagnosis.

### Solution idea developed here

Two focused debug helpers were added:

- `research-evaluation/debug-discovery-sync.ps1`
- `research-evaluation/debug-root-authorize.ps1`

They expose:

- manifest inspection,
- package fetch inspection,
- raw HTTP error bodies,
- node stdout and stderr logs.

### Migration suggestion

The upgraded project should preserve the pattern of minimal targeted debug helpers for fragile lifecycle steps.

This is more useful than relying only on large integrated experiment scripts.

## 9. Result artifacts needed stable machine-readable schemas

### Problem

Console output alone is weak for:

- paper figure generation,
- repeated benchmarking,
- historical comparison,
- future CI summarization.

### Solution idea developed here

The experiments now emit stable JSON and CSV files under:

- `research-evaluation/results/`

### Migration suggestion

The upgraded project should preserve the idea of stable experiment result schemas.

Even if field names evolve, keep the outputs structured and versionable.

## 10. Scalability analysis needed explicit bottleneck reasoning, not just measurements

### Problem

Measurement results alone do not explain whether the main limits come from:

- hardware,
- persistence patterns,
- publication flow,
- synchronization,
- or test orchestration.

### Solution idea developed here

A dedicated analysis document was added:

- `docs/scalability-bottleneck-analysis.md`

It explains:

- why high CPU and low SSD utilization matter,
- why the bottleneck is not only hardware,
- why root publication and discovery sync dominate,
- why the test harness itself contributes to the measured cost,
- what optimization order is recommended.

### Migration suggestion

The upgraded project should reuse this reasoning framework when analyzing its own performance, even if the final conclusions differ because of stronger security logic or different cryptographic handling.

## 11. Paper baseline comparison needed a lower-risk improvement path

### Problem

The paper's baseline comparison was weaker than its mechanism validation, but directly comparing against heterogeneous external systems would be high cost and high risk.

### Solution idea developed here

A dedicated guidance document was added:

- `docs/baseline-comparison-improvement-guide.md`

It recommends:

- property-coverage tables,
- degraded internal baselines,
- mechanism-level comparisons,
- overhead-versus-property comparisons,
- and explicitly not prioritizing external-system reproduction baselines.

### Migration suggestion

The upgraded project's future papers should consider this route first, especially when the architecture has already diverged and direct external-system fairness is still hard to guarantee.

## 12. Recommended absorption priority for the upgraded project

### First priority

Absorb the experiment architecture:

- common harness,
- lifecycle experiment,
- authorization experiment,
- scalability experiment,
- result schema.

### Second priority

Absorb the analytical guidance:

- scalability bottleneck framework,
- baseline-comparison improvement strategy.

### Third priority

Re-implement the useful parts in a way that fits the upgraded project's:

- repository split,
- security model,
- cryptographic stack,
- current APIs,
- and deployment assumptions.

## 13. Final summary

This package is most useful as a source of:

- experiment structure,
- orchestration patterns,
- metric decomposition,
- debugging patterns,
- and paper-support analysis.

It should not be treated as a direct code patch for the upgraded project's production modules.
