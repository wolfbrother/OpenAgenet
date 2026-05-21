<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Full Trusted Invocation

This example exercises the current Rust infrastructure services end to end:

1. start Root, Registrar, Discovery, and CDN services
2. submit the demo Service Agent through Registrar
3. let Root verify and queue the DID Document package
4. run Root's CDN publish batch
5. run Root's Discovery notification batch
6. let Discovery sync from CDN and verify Root proof plus bulletin events
7. query Discovery for the demo Service Agent by capability tag
8. call the demo Service Agent `/agent/hello` endpoint
9. show Service Agent deployment organization, author, and contact metadata

Run from the repository root:

```powershell
.\scripts\run-e2e-demo.ps1
```

The script uses the development identities under `data/`. It is intended for local
demo validation only.
