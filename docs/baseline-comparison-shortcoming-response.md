<!--
Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT)

Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Response to the Baseline-Comparison Shortcoming

## 1. Background

One clear shortcoming of the current paper is that its baseline comparison is still weaker than its mechanism design and validation. The paper currently reads more like:

- a mechanism study,
- a prototype validation paper,
- and a governance-model demonstration,

than a paper that can strongly claim:

- "the proposed approach significantly outperforms existing solutions."

This shortcoming is real, but it should be interpreted carefully.

## 2. Nature of the shortcoming

The weakness is not mainly that the paper lacks implementation or experimental effort. Instead, it is that the comparative evidence is not yet strong enough to convince a strict reviewer that:

- existing approaches are insufficient in a clearly demonstrated way, and
- the proposed model is not only workable, but also necessary and measurably beneficial relative to simpler or adjacent alternatives.

So the issue is primarily:

- a comparative-evaluation weakness,
- a paper-positioning weakness,
- and a mechanism-to-baseline mapping weakness.

It is not primarily a failure of the prototype itself.

## 3. Why this shortcoming is not easy to fix with direct external baselines

Direct comparison with existing external systems is difficult for three main reasons.

### 3.1 Problem mismatch

Most candidate comparison targets solve only part of the paper's problem:

- DID systems focus on identifier ownership and document resolution;
- service registries focus on endpoint registration and lookup;
- workload identity systems focus on service or workload authentication;
- agent frameworks focus on orchestration and communication.

The current paper, however, studies a combined problem:

- trust-governed identity lifecycle,
- anchored current-version validation,
- authorization-scoped discovery,
- and pre-connection validation.

This means many adjacent systems are not true like-for-like baselines.

### 3.2 Fairness mismatch

The proposed model deliberately performs extra governance and verification work.

Therefore, if it is directly compared against a simpler registry or resolution service using only raw throughput or latency:

- the baseline may appear faster simply because it solves a simpler problem;
- the proposed model may appear slower simply because it enforces stronger correctness and governance constraints.

Such a comparison can easily become unfair or misleading.

### 3.3 Reproduction risk

A serious external baseline often requires:

- integrating a third-party system into the paper's workflow, or
- re-implementing a simplified version of an existing approach.

Both are risky:

- the integrated system may not match the paper's setting;
- the re-implementation may be challenged as biased or incomplete;
- a lot of engineering time may be consumed for limited review value.

## 4. Core judgment

The baseline-comparison shortcoming is moderately difficult to improve, but it is not necessary to solve it by forcing full heterogeneous system comparisons.

The right target is not:

- "prove the paper is faster than every adjacent route,"

but rather:

- "show that adjacent routes do not jointly provide the same governed lifecycle and discovery properties, and show that the proposed mechanisms provide these properties at an acceptable overhead."

This reframes the problem from:

- absolute competition,

to:

- problem coverage,
- mechanism necessity,
- and cost-versus-property justification.

## 5. Recommended response strategy

The best response strategy is to strengthen the paper through mechanism-level baselines rather than external system reproduction baselines.

This strategy has three layers.

### 5.1 Property-boundary comparison

Add or strengthen a comparison table showing which adjacent approaches provide which properties.

Recommended dimensions include:

- anchored acceptance,
- current-version freshness,
- authorization-scoped discovery,
- stale-version rejection,
- pre-connection identity validation,
- controlled discoverability after update.

This helps explain why the problem cannot be reduced to plain DID resolution or plain service discovery.

### 5.2 Degraded internal baselines

Instead of comparing against a fully different external system, compare the full model against reduced versions of itself.

Recommended internal baselines include:

- no authorization-aware discovery filtering,
- no anchored current-version validation,
- no pre-connection freshness validation,
- no registration-credential verification.

This keeps:

- the same problem setting,
- the same implementation environment,
- and much better fairness.

### 5.3 Overhead-versus-property comparison

The paper should quantify not only what a mechanism costs, but also what property it provides.

For example:

- authorization-aware discovery adds some overhead, but prevents unauthorized exposure;
- freshness validation adds checks, but prevents stale identity acceptance;
- registration-credential verification adds cost, but blocks forged admission.

This style of comparison is much more convincing than raw speed comparison alone.

## 6. What should not be prioritized

At the current stage, the paper should not prioritize:

- full reproduction of heterogeneous external systems as baselines,
- direct throughput competition against simpler service registries,
- or strong claims that the proposed model is categorically superior in absolute performance.

These directions are high cost and high risk.

They can distract from the real contribution of the paper, which is:

- mechanism design for governed identity lifecycle and controlled discovery.

## 7. Practical experimental suggestions

The following baseline-oriented experiments are the most practical and valuable.

### 7.1 Authorization baseline

Compare:

- full model,
- no authorization-aware discovery filtering.

Measure:

- unauthorized exposure count,
- policy enforcement accuracy,
- authorized query latency,
- unauthorized query latency.

### 7.2 Freshness baseline

Compare:

- full model,
- no anchored current-version validation,
- no pre-connection freshness validation.

Measure:

- stale acceptance rate,
- stale discovery exposure rate,
- verification latency.

### 7.3 Registration admissibility baseline

Compare:

- full model,
- no registration-credential verification.

Measure:

- false acceptance rate,
- malformed registration acceptance,
- added registration latency.

These experiments are all aligned with the paper's claimed properties and can be explained clearly.

## 8. How the paper should position itself

The paper should not try to say:

- "we outperform all existing approaches."

Instead, it should say something closer to:

- existing approaches do not jointly address governed lifecycle freshness and controlled discoverability;
- the proposed model closes this gap;
- the added mechanisms bring measurable security and governance benefits;
- the measured overhead is acceptable in the tested prototype setting.

This positioning is more honest, more defensible, and more academically coherent.

## 9. Difficulty assessment

The improvement difficulty can be divided into three levels.

### Low difficulty

- strengthen Related Work differentiation,
- add a better property-coverage comparison table,
- improve narrative around why existing systems are insufficient.

### Medium difficulty

- implement degraded internal baselines,
- add overhead-versus-property tables,
- add more direct mechanism-level comparisons.

### High difficulty

- reproduce full external baselines,
- create fair heterogeneous throughput comparisons,
- make strong superiority claims across systems with different problem definitions.

For the current paper, low- and medium-difficulty improvements have the best return on effort.

## 10. Final conclusion

The correct response to the baseline-comparison shortcoming is not to force a direct battle with heterogeneous external systems.

The better path is:

- clarify the problem boundary,
- compare properties rather than only speed,
- use degraded internal baselines,
- and connect each mechanism to a measurable gain and measurable cost.

In short, the paper should aim to demonstrate:

- not that it is universally faster,
- but that it addresses a governance-and-discovery problem that adjacent routes do not jointly solve, and that it does so with explainable and acceptable overhead.
