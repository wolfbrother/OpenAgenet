<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Tests

Cross-language tests for Rust crates, TypeScript packages, Python agents, integration flows, and end-to-end demos.

## Current matrix

- Rust unit tests: `cargo test --workspace`
- Rust formatting: `cargo fmt --all --check`
- Rust linting: `cargo clippy --workspace --all-targets --all-features -- -D warnings`
- Python syntax checks: `python -m compileall agents`
- E2E happy path: `.\scripts\run-e2e-demo.ps1`
- Negative trusted invocation regression: `.\examples\trusted-invocation-negative-cases\run.ps1`

## Coverage focus

- DID and credential parsing
- Root authorization and bulletin flows
- Discovery verification and filtering
- CDN manifest and package serving
- trusted invocation signing and verification
- negative security edge cases
