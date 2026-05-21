<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Configs

Local configuration files for OAN nodes and agents.

## Local Ports

| Role | Port | Endpoint | DID semantic code |
| --- | ---: | --- | --- |
| Root Node | 8000 | `http://localhost:8000` | `AGRT` |
| Registrar Node | 8001 | `http://localhost:8001` | `AGRG` |
| Discovery Node | 8002 | `http://localhost:8002` | `AGDS` |
| CDN Service | 8003 | `http://localhost:8003` | n/a |
| Demo Service Agent | 9001 | `http://localhost:9001` | `AGDM` |
| Service Agent MCP | 9001 | `http://localhost:9001/mcp` | `AGDM` |
| Service Agent A2A | 9001 | `http://localhost:9001/a2a` | `AGDM` |
| User Agent | n/a | CLI/script process | `AGUS` |
| Web Console | 3000 | `http://localhost:3000` | n/a |

## Database

The open-source reference implementation uses SQLite for all infrastructure services.

| Service | Database URL |
| --- | --- |
| Root Node | `sqlite:./data/root/root.db` |
| Registrar Node | `sqlite:./data/registrar/registrar.db` |
| Discovery Node | `sqlite:./data/discovery/discovery.db` |
| CDN Service | `sqlite:./data/cdn/cdn.db` |

Each service owns its own local database file. Production deployments may later add a PostgreSQL profile, but the MVP stays SQLite-only.

## Bootstrap Discovery

The Rust services use a two-layer discovery model:

```text
Config file
  - Provides local bind address and the minimum upstream entry point.
  - Registrar Node and Discovery Node need the Root endpoint at startup.

Root bulletin
  - Provides runtime service facts such as CDN_SERVICE_INFO_UPDATED.
  - Discovery Node reads CDN manifest/package URLs from the Root bulletin before syncing.
  - CDN Service is not trusted or authorized by this entry; clients still verify Root proof and hashes.
```

This lets the system establish usable connections from configuration plus bulletin state. If CDN Service moves, Root can publish a new `CDN_SERVICE_INFO_UPDATED` event and Discovery Node can reconnect without changing its own config.

