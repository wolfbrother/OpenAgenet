<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Registrar Node

Onboards Service Agents, helps assemble complete DID Documents, and submits
registration packages to Root Node.

## Role

Registrar Node supports Service Agent registration drafts, capability tag
selection, registration credential issuance, and submission of complete Agent
DID Documents to Root Node for verification.

## Local Run

```powershell
cargo run -p registrar-node
```

The default local API listens on port `8001` when using the sample
configuration and demo scripts.
