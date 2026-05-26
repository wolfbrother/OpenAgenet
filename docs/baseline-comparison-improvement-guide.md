<!--
Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)

Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Baseline Comparison Improvement Guide for the Current Paper

## 1. Purpose

This document explains how to strengthen the baseline-comparison weakness in the current paper without forcing an unfair or high-risk comparison against heterogeneous external systems.

The main conclusion is:

- do not prioritize full external-system reproduction baselines;
- prioritize mechanism-level baselines and degraded internal baselines;
- use property coverage tables and quantitative overhead evidence to support the argument.

This guide is intended to support future paper revision and experiment extension.

## 2. The actual weakness

The current paper already demonstrates that the proposed model works and that its mechanisms are internally consistent. However, its baseline comparison is still relatively weak.

More precisely, the paper currently looks stronger on:

- mechanism validation,
- lifecycle correctness,
- negative-case rejection,
- authorization-aware discovery behavior, and
- controlled scalability characterization.

It still looks weaker on:

- showing why existing approaches are insufficient in a comparative way,
- showing what would happen if the proposed mechanisms were removed,
- quantifying the value of each added mechanism relative to a simpler baseline.

So the weakness is real, but it should be understood correctly:

- it is not mainly a system-function weakness;
- it is a comparative-evaluation and paper-positioning weakness.

## 3. Why direct comparison with existing systems is difficult

Direct comparison with existing systems is difficult for structural reasons.

### 3.1 Problem mismatch

Most adjacent systems solve only part of the paper's problem:

- DID systems mainly focus on identifier ownership, document resolution, and proof verification;
- service discovery systems mainly focus on endpoint registration and lookup;
- SPIFFE-like systems mainly focus on workload identity;
- Agent frameworks mainly focus on orchestration and communication.

The proposed paper studies a combined problem:

- governed identity lifecycle,
- anchored current-version validation,
- authorization-scoped discoverability, and
- pre-connection identity validation.

Therefore, many candidate systems are not true apples-to-apples baselines.

### 3.2 Fairness mismatch

The proposed model performs extra work that simpler systems do not perform. If one directly compares raw throughput or latency against a plain registry, the comparison may be misleading:

- the simpler registry may appear faster because it solves a simpler problem;
- the proposed model may appear slower because it enforces governance and verification steps that the baseline omits.

This is a fairness problem, not just a performance problem.

### 3.3 Reproduction risk

A strong external baseline usually requires one of the following:

- deploying and adapting a real third-party system, or
- re-implementing a simplified version of it.

Both approaches are risky:

- real systems may not match the paper's setting;
- simplified reproductions may be challenged as biased or incomplete;
- engineering time may be consumed by the baseline instead of the paper's own contribution.

## 4. Recommended strategy

The recommended strategy is to strengthen baseline comparison at the mechanism level rather than forcing full external-system competition.

The strategy has four parts:

1. property-boundary comparison with adjacent approaches;
2. degraded internal baselines;
3. quantitative overhead comparison among internal variants;
4. careful narrative positioning in the paper.

This approach is much more feasible and much more defensible.

## 5. What not to do

The following direction is explicitly not recommended for the current paper revision:

- do not prioritize a full external-system reproduction baseline against DID platforms, service registries, or other agent infrastructures.

Reasons:

- high implementation cost,
- high fairness risk,
- likely low review payoff relative to effort,
- easy for reviewers to attack the baseline instead of discussing the paper's mechanisms.

This does not mean external comparison is never useful. It means it is not the best next step for this paper.

## 6. Recommended baseline types

## 6.1 Baseline Type A: property-coverage baseline

This is a comparison table, not a deployment benchmark.

Its goal is to show that existing routes do not jointly provide the required properties.

Recommended comparison dimensions:

- anchored acceptance,
- current-version freshness,
- authorization-scoped discovery,
- stale-version rejection,
- pre-connection identity validation,
- controlled discoverability after update,
- capability-domain governance.

Recommended baseline families:

- DID resolution systems,
- traditional service discovery systems,
- workload identity systems,
- agent frameworks and communication protocols.

This baseline is low-cost and high-value because it makes the paper's research gap much clearer.

## 6.2 Baseline Type B: degraded internal mechanism baselines

This is the most important addition.

Instead of comparing against a completely different system, compare the full model against reduced variants.

Recommended variants:

- `B1`: no authorization-aware discovery filtering;
- `B2`: no anchored current-version validation;
- `B3`: no pre-connection freshness validation;
- `B4`: no registration-credential verification;
- `B5`: optional simplified publication path with minimal queue or archive checks, if it can be evaluated without distorting semantics too much.

These are highly valuable because:

- the problem definition remains constant;
- the environment remains constant;
- the comparison is fair;
- the paper can directly show which mechanism contributes which property.

## 6.3 Baseline Type C: quantitative overhead baselines

The purpose here is not to show that the proposed model is universally faster.

The purpose is to show:

- what security or governance property is gained, and
- what additional cost is paid.

This is a much stronger and more honest academic story.

## 7. Recommended experiments

## 7.1 Experiment set 1: authorization-aware discovery baseline

Compare:

- full model,
- no authorization-aware filtering baseline.

Measure:

- authorized query latency,
- unauthorized exposure count,
- policy enforcement accuracy,
- false exposure rate.

Expected paper value:

- demonstrates that authorization-aware discovery is not cosmetic;
- shows that the policy benefit is real;
- quantifies the extra query or indexing cost.

## 7.2 Experiment set 2: freshness and anchored-validation baseline

Compare:

- full model,
- no anchored current-version validation baseline,
- no pre-connection freshness validation baseline.

Measure:

- stale acceptance rate,
- stale discovery exposure rate,
- verification latency,
- replay or outdated-version rejection behavior.

Expected paper value:

- shows why plain document resolution is not enough;
- directly supports the paper's lifecycle-governance argument.

## 7.3 Experiment set 3: registration-credential verification baseline

Compare:

- full model,
- no registration-credential verification baseline.

Measure:

- acceptance of forged or malformed registration attempts,
- registration latency overhead,
- false acceptance rate.

Expected paper value:

- ties credential verification to a measurable security gain;
- helps justify the root-side verification path.

## 7.4 Experiment set 4: lifecycle-ingestion overhead baseline

Compare:

- full model,
- one or two reduced-ingestion variants that keep the same functional pipeline but relax one major check.

Possible relaxations:

- simplified queue bookkeeping,
- reduced archival step,
- reduced sync validation path.

This should be done carefully. If a reduced variant changes the semantics too much, it should be excluded.

Measure:

- registration throughput,
- publish latency,
- sync latency,
- query latency,
- storage growth.

Expected paper value:

- separates governance overhead from query overhead;
- shows where the proposed model pays most of its cost.

## 8. Recommended metrics

For the new baselines, the most useful metrics are:

- query latency,
- registration throughput,
- publish latency,
- sync latency,
- verification overhead,
- unauthorized exposure rate,
- stale acceptance rate,
- false acceptance rate,
- policy enforcement accuracy.

The key is that each metric should map to a property claim in the paper.

## 9. Mapping baselines to paper claims

The baseline section should not look like "we compared to something because reviewers expect it."

It should look like "each baseline tests a specific mechanism claim."

Recommended mapping:

- authorization-filtering baseline -> authorization soundness;
- anchored-freshness baseline -> freshness and current-version correctness;
- registration-credential baseline -> registration admissibility and authenticity;
- reduced-ingestion baseline -> cost of governance steps.

This makes the evaluation section more coherent.

## 10. How to position the comparison in the paper

The paper should avoid claiming:

- the proposed model outperforms all adjacent systems;
- the proposed model is faster than simpler registries in absolute terms.

Instead, it should claim:

- adjacent systems do not jointly solve the same problem;
- the proposed mechanisms close a specific governance gap;
- the added mechanisms bring measurable security or governance benefits;
- the additional overhead is observable and bounded in the tested setting.

This positioning is more defensible and more aligned with the actual contribution.

## 11. How to write the comparison table

The comparison table should focus on property coverage, not just implementation category.

A recommended structure is:

| Approach Family | Anchored Acceptance | Current-Version Freshness | Authorization-Scoped Discovery | Pre-Connection Validation | Controlled Discoverability |
| --- | --- | --- | --- | --- | --- |
| DID resolution | partial | partial | no | limited | no |
| service registry | no | weak | limited | no | weak |
| workload identity | partial | partial | no | yes | no |
| proposed model | yes | yes | yes | yes | yes |

This table should be paired with short explanatory text clarifying that the comparison is conceptual and problem-oriented.

## 12. Difficulty assessment

The overall difficulty of improving this weakness is moderate, not extreme, as long as the work stays within the recommended scope.

### Low-difficulty additions

- property comparison table,
- revised discussion of why existing routes are insufficient,
- stronger mapping from baselines to properties.

### Medium-difficulty additions

- degraded internal baselines,
- quantitative overhead comparisons,
- additional figures or tables for authorization and freshness tradeoffs.

### High-difficulty additions

- faithful external-system reproduction baselines,
- cross-system throughput comparison with heterogeneous designs,
- full deployment equivalence studies.

For the current paper, low- and medium-difficulty additions are the best return on effort.

## 13. Suggested implementation order

The following order is recommended.

### Step 1

Strengthen the property-coverage comparison table and the surrounding narrative in Related Work and Discussion.

### Step 2

Add one strong degraded internal baseline:

- no authorization-aware filtering, or
- no anchored freshness validation.

This is the single highest-value next step.

### Step 3

Add one more degraded baseline focused on security admission:

- no registration-credential verification.

### Step 4

Add a compact quantitative table summarizing:

- property gained,
- additional latency or throughput cost.

### Step 5

Only if time permits, add one carefully designed lifecycle-ingestion reduced variant for overhead attribution.

## 14. Practical recommendation for the next revision

If only a limited amount of additional work is feasible, the recommended minimum package is:

1. one improved comparison table,
2. one authorization baseline experiment,
3. one freshness baseline experiment,
4. one small overhead summary table.

That package is realistic and would materially improve the paper.

## 15. Final conclusion

The baseline-comparison weakness in the current paper should not be solved by forcing a risky direct comparison against heterogeneous external systems.

The most practical and academically sound solution is:

- compare at the mechanism level,
- compare within the same problem setting,
- compare properties and overhead together,
- show what each proposed mechanism prevents or enables.

This path is feasible, fair, and well aligned with the paper's actual contribution.
