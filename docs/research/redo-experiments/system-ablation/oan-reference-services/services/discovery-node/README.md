<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Discovery Node

Builds a verified local capability index from CDN packages and serves signed
discovery responses.

## Role

Discovery Node syncs Root-verified packages from CDN, verifies bulletin and
package proof material, filters packages by authorized domains, builds a local
capability index, and returns signed discovery responses.

## Local Run

```powershell
cargo run -p discovery-node
```

The default local API listens on port `8002` when using the sample
configuration and demo scripts.
