<!--
Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)

Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Scalability Bottleneck Analysis for the Current OpenAgenet Prototype

## 1. Purpose

This document analyzes the bottlenecks observed during the recent scalability tests of the current OpenAgenet prototype. The goal is not only to explain why throughput drops sharply at larger scales, but also to distinguish among:

- hardware limits,
- current core-system limits,
- current peripheral-service limits, and
- test-script or evaluation-method limits.

The analysis is intended to guide the next round of engineering improvement without changing the conclusions already reported in the paper.

## 2. What was observed during testing

During the recent runs, the following runtime phenomena were observed on the local machine:

- CPU utilization stayed above roughly 80% for a long period during the large-scale runs, then dropped quickly after the test finished.
- Memory usage stayed above 50% and did not drop much after the test.
- SSD utilization remained low, usually only at single-digit percentages.
- Registration throughput dropped significantly as the workload increased.

The measured scalability results were:

| Scale | Registration TPS | Registration P95 | Publish Latency | Sync Latency | Query Latency |
| --- | ---: | ---: | ---: | ---: | ---: |
| 5 | 1.794 | 2503.8 ms | 399.8 ms | 3025.5 ms | 11.6 ms |
| 10 | 9.581 | 398.3 ms | 473.9 ms | 1101.5 ms | 6.6 ms |
| 20 | 8.519 | 181.4 ms | 1248.1 ms | 1466.8 ms | 12.2 ms |
| 50 | 8.158 | 177.3 ms | 1887.1 ms | 2070.7 ms | 23.6 ms |
| 100 | 5.711 | 206.4 ms | 3639.4 ms | 4895.0 ms | 31.4 ms |
| 200 | 4.139 | 400.9 ms | 7007.7 ms | 4757.5 ms | 27.1 ms |
| 500 | 2.613 | 654.9 ms | 21964.8 ms | 9050.1 ms | 21.3 ms |
| 1000 | 0.776 | 3522.6 ms | 142556.5 ms | 27459.3 ms | 30.6 ms |

These results already show an important structural fact:

- query latency remains relatively stable;
- registration, publication, and synchronization become the dominant costs as scale grows.

## 3. Immediate interpretation of CPU, memory, and disk behavior

### 3.1 CPU behavior

The sustained high CPU usage strongly suggests that the dominant bottleneck is compute-side and coordination-side work rather than raw disk bandwidth.

This is consistent with the current prototype design:

- each registration triggers HTTP handling, JSON serialization/deserialization, verification logic, VC handling, and local persistence;
- root publication and discovery synchronization also perform repeated package parsing, proof checking, bulletin verification, and index rebuilding or index update work;
- the evaluation script drives many small API calls in sequence, which adds per-request overhead and prevents the system from amortizing setup cost well.

So the CPU observation is meaningful: the prototype is spending a lot of time doing many medium-cost operations repeatedly, not waiting on the SSD.

### 3.2 Memory behavior

The memory behavior does not currently suggest a memory leak by itself.

After the test, no obvious service listeners remained on ports `8000`-`8003`, and no `cargo`, `rustc`, `root-node`, `registrar-node`, `discovery-node`, `cdn-node`, or `node` runtime processes were found still running. This means the test stack appears to have stopped correctly.

The remaining memory occupancy is therefore more likely explained by:

- normal Windows file-system cache retention,
- Rust allocator/runtime memory not immediately returned while the processes were alive,
- PowerShell and shell-session working sets,
- recently touched JSON, SQLite, and file data still being cached by the OS.

In short: the post-test memory level does not currently look like evidence that the test services were left running.

### 3.3 Disk behavior

Low SSD utilization means the storage subsystem was probably not saturated at the device level.

That does not mean storage is free.

Instead, it suggests the system is paying for:

- many small file reads and writes,
- metadata operations,
- SQLite transaction overhead,
- JSON file rewrite overhead,
- serialization overhead around storage,

rather than large sequential disk throughput.

This kind of pattern can produce poor end-to-end throughput even when Task Manager shows low SSD utilization.

## 4. What the current test is actually measuring

The current scalability script is not a pure benchmark of the Rust core alone. It measures the combined cost of:

1. dataset generation,
2. repeated HTTP requests from PowerShell,
3. registrar draft creation,
4. registrar VC issuance,
5. registrar submission,
6. root-side verification and queueing,
7. root batch publication to CDN,
8. root batch notification to discovery,
9. discovery synchronization from CDN, and
10. final discovery query.

This can be seen from:

- [examples/research-evaluation/run-scalability.ps1](D:/Works/VscodeProject/OpenAgentNet/examples/research-evaluation/run-scalability.ps1)
- [examples/research-evaluation/common.ps1](D:/Works/VscodeProject/OpenAgentNet/examples/research-evaluation/common.ps1)

In particular:

- the test registers agents one by one in a loop;
- each agent registration goes through draft creation, VC issuance, and final submission;
- publication and discovery sync are invoked as explicit batch APIs after registration;
- the whole stack is started from scratch for each scale.

So the result is best understood as an end-to-end prototype workflow benchmark, not a lower-bound capacity benchmark of the core services.

## 5. Main sources of bottleneck

### 5.1 The first bottleneck is not hardware alone

A stronger server would help, but it would not by itself solve the current throughput collapse.

Why:

- query latency stays fairly stable, so the system is not globally collapsing;
- the sharp degradation is concentrated in registration, publish, and sync paths;
- these paths contain architectural and implementation costs that will still exist on stronger hardware;
- at scale `1000`, `publishLatencyMs` reaches about `142.6 s`, which is too large to explain only by "the machine is weak".

This means hardware is a factor, but not the primary explanation.

### 5.2 The second bottleneck is the current end-to-end workflow shape

The current workflow is correctness-oriented and demo-oriented, not throughput-oriented.

Examples:

- registrar uses a multi-step draft workflow before final submission;
- root archives verified packages and also maintains queues and bulletin state;
- discovery verifies root proof and bulletin state before sync;
- CDN, root, registrar, and discovery all perform their own persistence work.

This is good for trust governance, but expensive per identity.

At current scale, the system is still carrying the operational cost of "full governance path per item" without yet adding the amortization mechanisms that production systems normally rely on.

### 5.3 The third bottleneck is small-operation persistence overhead

The codebase uses SQLite, JSON files, local directories, and queue/history files together.

Representative places include:

- root queue and batch logic in [services/root-node/src/main.rs](D:/Works/VscodeProject/OpenAgentNet/services/root-node/src/main.rs)
- discovery sync logic in [services/discovery-node/src/main.rs](D:/Works/VscodeProject/OpenAgentNet/services/discovery-node/src/main.rs)
- SQLite JSON store in [crates/oan-storage/src/lib.rs](D:/Works/VscodeProject/OpenAgentNet/crates/oan-storage/src/lib.rs)

The likely issue is not "SQLite is too slow" in itself. The issue is that the current prototype performs many small persistence and serialization steps:

- queue read,
- queue rewrite,
- archive write,
- bulletin write,
- SQLite upsert,
- package persistence,
- sync-history persistence,
- index persistence.

This pattern creates overhead in CPU, object allocation, and metadata I/O even when raw SSD throughput is low.

### 5.4 The fourth bottleneck is publication and synchronization strategy

The current root batch APIs are explicitly invoked:

- `/root/batches/publish-cdn`
- `/root/batches/notify-discovery`

and the discovery side then explicitly runs:

- `/discovery/sync`

This is correct for controlled experiments, but it exposes the cost of a largely serial batch path:

- root reads queue,
- root pushes packages,
- root marks queue state,
- root prepares discovery notifications,
- discovery fetches and verifies packages,
- discovery writes index and history.

The metrics show that this stage becomes dominant much faster than query handling. That means the current bottleneck is more about propagation pipeline efficiency than about discovery lookup efficiency.

### 5.5 The fifth bottleneck is the evaluation script and orchestration overhead

The current script is intentionally simple and reliable, but it adds real overhead:

- PowerShell invokes many HTTP requests serially;
- each registration is a separate request chain;
- the research stack is reinitialized for each scale;
- there is no concurrent load generation;
- there is no connection pooling strategy tuned for benchmarking;
- there is no warm-up phase separated from the measured phase.

Therefore, part of the poor throughput is due to the test harness, not only the services.

This matters because the current result answers:

> "How fast does the full prototype workflow run in this local evaluation mode?"

more than:

> "What is the maximum sustainable throughput of the core implementation?"

## 6. Stage-by-stage diagnosis from the measured results

### 6.1 Registration path

Registration throughput drops from around `8`-`10/s` at `10`-`50` scale to `0.776/s` at `1000`.

This suggests:

- per-item cost is not staying constant;
- later items likely suffer from growing bookkeeping or persistence overhead;
- the registration path is not yet effectively amortized for large batches.

The key point is that the throughput curve is worse than a simple linear slowdown. That usually indicates accumulating coordination cost, repeated full-state operations, or queue/index maintenance costs becoming more expensive as data grows.

### 6.2 Publish path

Publish latency grows from `399.8 ms` at scale `5` to `142556.5 ms` at scale `1000`.

This is one of the clearest signals in the whole experiment.

It strongly suggests that the root-to-CDN publication path is currently a major hotspot. Possible causes include:

- repeated package construction and serialization,
- per-package HTTP publication overhead,
- per-package archive or queue status updates,
- non-streaming batch handling,
- too much repeated filesystem and manifest work.

This path deserves first-priority optimization.

### 6.3 Sync path

Sync latency grows much more slowly than publish latency, but still becomes substantial, reaching `27459.3 ms` at scale `1000`.

That implies:

- discovery verification and indexing are not free;
- however, discovery sync is probably not the single worst bottleneck;
- the root-side publish path appears worse than discovery query and often worse than sync.

So discovery lookup is not the main problem, but discovery-side ingestion still needs optimization for larger ecosystems.

### 6.4 Query path

Query latency stays within roughly `6.6` to `31.4 ms` across the tested range.

This is encouraging.

It means:

- the current discovery query shape is reasonably lightweight;
- authorization-aware filtering is not the main scalability problem in the current prototype;
- the major pressure lies earlier in the lifecycle pipeline.

This is useful strategically: future optimization should focus on ingest, verification, publication, queue handling, and sync, not first on query logic.

## 7. Is the bottleneck in the core, the SDK/peripheral layer, or the test harness?

The most accurate answer is: all three contribute, but not equally.

### 7.1 Core/system-layer contribution: high

The root publication path, persistence pattern, queue processing, and sync pipeline are real system bottlenecks. These are not just benchmark artifacts.

This is where the largest long-term gain will come from.

### 7.2 Peripheral-service/SDK contribution: medium

The registrar draft flow and surrounding HTTP orchestration add real cost, especially in research/demo mode. Future SDKs and website-backed registration flows should distinguish:

- user-friendly workflow APIs, and
- high-throughput ingestion APIs.

If both continue to use exactly the same chatty multi-step path, throughput will remain limited.

### 7.3 Test-script contribution: medium to high

The PowerShell-based serial benchmark exaggerates per-request overhead and startup cost. It is excellent for reproducibility and debugging, but not ideal for measuring upper-bound throughput.

So the current results are valid, but they are closer to a conservative workflow benchmark than a performance ceiling.

### 7.4 Hardware contribution: medium

A stronger server would likely improve:

- verification throughput,
- HTTP handling,
- SQLite transaction rate,
- batch processing time,
- concurrent sync handling.

However, it would not eliminate the architectural overheads described above. Better hardware can mask some inefficiency, but it cannot replace pipeline optimization.

## 8. Recommended improvement order

The following order is recommended for future work.

### Priority 1: optimize root publication and queue handling

Why first:

- this is where latency explodes most sharply;
- it directly affects end-to-end freshness and system usability;
- it likely yields the biggest gain without changing trust semantics.

Recommended directions:

- reduce repeated full-file queue rewrites;
- prefer SQLite-backed queue iteration over JSON-file queue rewrite patterns;
- support chunked package publication inside one batch;
- reduce per-package status-update overhead;
- separate archive persistence from critical publication latency when possible.

### Priority 2: optimize discovery sync ingestion

Why second:

- sync is a major lifecycle-stage cost;
- future ecosystems with many discovery nodes will magnify this path.

Recommended directions:

- incremental sync rather than broader reprocessing;
- more selective package fetch and verification;
- index update in chunks;
- reduce repeated bulletin and package parsing work;
- introduce better sync cursors and checkpoints.

### Priority 3: split "governed workflow API" from "bulk ingestion API"

Why third:

- the current registrar flow is friendly for UI and demos, but costly for scale tests;
- websites and SDKs will need both convenience and throughput.

Recommended directions:

- keep draft and assist APIs for human-facing registration;
- add a bulk submit path for machine-driven onboarding;
- allow registration credential issuance and submission to be combined in trusted batch flows where policy permits.

### Priority 4: build a better benchmark harness

Why fourth:

- current tests are useful, but they blend system cost and orchestration cost;
- future optimization needs cleaner attribution.

Recommended directions:

- keep the current PowerShell scripts for reproducibility;
- add a dedicated benchmark client in Rust or TypeScript;
- separate warm-up, measured run, and teardown phases;
- add concurrency controls;
- add per-stage profiling output;
- add CPU-time and per-request breakdown logs.

### Priority 5: use stronger hardware only after the above

Why fifth:

- otherwise hardware upgrade may hide bottlenecks instead of explaining them;
- after software optimization, stronger hardware will produce more meaningful capacity gains.

Recommended directions:

- rerun the same benchmark on a higher-core server after pipeline optimization;
- compare "same code, different hardware" and "same hardware, improved code" separately.

## 9. Guidance for interpreting future tests

For future performance work, the following distinctions should be maintained.

### 9.1 Workflow benchmark vs. component benchmark

Do not mix these two questions:

- How fast does the full governance workflow run end-to-end?
- How fast can each service process its own core task?

Both are important, but they answer different engineering questions.

### 9.2 Query scalability vs. lifecycle scalability

The current data suggests the system is much closer to acceptable query scalability than to acceptable lifecycle-ingestion scalability.

So future claims should be careful:

- discovery query path: relatively promising;
- registration, publication, and sync path: still needs serious optimization.

### 9.3 Prototype bottleneck vs. model bottleneck

The poor throughput does not mean the trust-governed model itself is invalid.

It means the current prototype implementation of that model has bottlenecks in:

- persistence shape,
- batch handling,
- orchestration granularity, and
- evaluation harness.

That is an engineering maturity issue more than a conceptual failure.

## 10. Final conclusion

The current scalability slowdown is not caused only by insufficient hardware.

The main bottlenecks are:

1. root-side publish pipeline cost,
2. small-operation persistence and queue handling overhead,
3. discovery-side sync ingestion cost,
4. chatty end-to-end registration workflow,
5. conservative serial evaluation script overhead.

Hardware improvement would help, but it would not be enough on its own.

The best next step is:

- first optimize root publish and discovery sync,
- then separate UI-friendly workflows from high-throughput APIs,
- then add a stronger benchmark harness,
- and only then use a stronger server for a clearer second-round capacity evaluation.

In short, the current test result should be interpreted as:

> the trust-governed OpenAgenet prototype is functionally correct and query behavior is relatively stable, but its lifecycle ingestion and propagation pipeline is still in a prototype-performance stage and requires targeted engineering optimization before it can support much larger production-scale ecosystems efficiently.
