# OAN Reference Services

Reference Rust services for OpenAgenet infrastructure nodes.

This repository will contain the reference implementations of the OAN infrastructure roles:

- Root Node
- Registrar Node
- Discovery Node
- CDN Node

## Role

These services demonstrate the official reference behavior for trusted registration, Root-governed authorization, verified package distribution, Discovery synchronization, and management APIs.

The protocol core should come from released `oan-protocol-common` crates rather than being redefined here.

## Non-Goals

This repository should not contain official trial-network secrets, detailed design records, or release signing authority.
