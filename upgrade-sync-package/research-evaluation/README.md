<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Research Evaluation

This directory contains repeatable experiment scripts for the paper evaluation
section. The scripts are intentionally implemented outside the core services so
that they can exercise the current OpenAgenet prototype without changing the
root, registrar, discovery, CDN, or Agent implementations.

## Experiments

| Script | Paper experiment | Purpose |
| --- | --- | --- |
| `run-lifecycle.ps1` | Experiment 1 | End-to-end lifecycle correctness and propagation timing |
| `run-negative.ps1` | Experiment 2 | Negative verification regression summary |
| `run-auth-discovery.ps1` | Experiment 3 | Capability-domain authorization-aware discovery |
| `run-scalability.ps1` | Experiment 4 | Registration, publishing, sync, query latency, throughput, and storage-size measurements |
| `run-all.ps1` | All | Runs the four experiment scripts |

Each script writes machine-readable results to `examples/research-evaluation/results`.
Temporary node state is written under `examples/research-evaluation/.work`.

## Usage

```powershell
.\examples\research-evaluation\run-lifecycle.ps1
.\examples\research-evaluation\run-negative.ps1
.\examples\research-evaluation\run-auth-discovery.ps1
.\examples\research-evaluation\run-scalability.ps1 -Scales 100,1000
```

The scalability script accepts smaller scales for quick local checks:

```powershell
.\examples\research-evaluation\run-scalability.ps1 -Scales 10,50
```

For paper-grade experiments, run multiple trials on a clean machine and record
hardware, OS, Rust toolchain, and commit hash together with the generated JSON
and CSV files.

