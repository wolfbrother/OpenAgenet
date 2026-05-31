<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Root Node

Trust anchor for local OpenAgenet deployments and the governance hub of the
reference implementation.

## Role

Root Node authorizes infrastructure participants, verifies Registrar-submitted
Agent packages, appends signed bulletin events, archives verified Agent DID
Document versions, and coordinates CDN publishing plus Discovery notification.

## Local Run

```powershell
cargo run -p root-node
```

The default local API listens on port `8000` when using the sample
configuration and demo scripts.

