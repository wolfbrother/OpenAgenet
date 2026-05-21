<!-- Copyright (c) 2026 China Academy of Information and Communications Technology (CAICT) -->
<!--
Author: JINLIANG XU
Email: xujinliang@caict.ac.cn; jlxufly@gmail.com
-->

# Multi Registrar and Discovery Example

This example runs OpenAgentNet with multiple Registrar Nodes and multiple
Discovery Nodes without disturbing the existing single-node demo.

## Layout

- one Root Node
- two Registrar Nodes
- two Discovery Nodes
- one CDN Service

## Run

```powershell
.\examples\multi-registrar-discovery\run.ps1
```

## Port map

- Root: `8100`
- Registrar A: `8101`
- Registrar B: `8102`
- Discovery A: `8103`
- Discovery B: `8104`
- CDN: `8105`

## What it demonstrates

- Root can authorize multiple Registrar Nodes.
- Root can authorize multiple Discovery Nodes.
- Discovery Nodes can independently sync from the same CDN service.
- The example keeps separate runtime data under `.oan-multi-node-demo`.

