<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# CDN Service

Single local distribution service for verified DID Documents, metadata, and
manifest content.

This service is not a `did:ans` authorized infrastructure node. It represents a
traditional CDN/object-storage service that may be operated by the Root
operator or outsourced.

## Role

CDN stores and serves Root-verified DID Documents, metadata, verified packages,
and manifests. Relying parties still verify Root proofs, hashes, and bulletin
state instead of trusting CDN directly.

## Local Run

```powershell
cargo run -p cdn-node
```

The default local API listens on port `8003` when using the sample
configuration and demo scripts.
