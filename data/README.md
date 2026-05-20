<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Data

Local runtime data for development.

Most files in this directory are generated and should not be committed, except placeholders and documentation.

Infrastructure services use local SQLite database files in their own data directories:

- `root/root.db`
- `registrar/registrar.db`
- `discovery/discovery.db`
- `cdn/cdn.db`

JSON files remain the canonical local artifacts for DID Documents, bulletin events, verified packages, manifests, and locally held credentials.
