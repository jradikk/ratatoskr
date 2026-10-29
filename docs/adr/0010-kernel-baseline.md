# ADR-0010: Kernel baseline 5.10 and feature probing

- Status: Accepted
- Date: 2026-10-29

## Context

All target platforms (Talos, Ubuntu, cloud images) ship ≥ 5.10. Features we need: GENEVE collect_md, WireGuard (in-tree since 5.6), clsact/tc BPF, BPF tunnel-key helpers, LPM tries, nftables.

## Decision

Require ≥ 5.10. Agent and gateway check the version and also probe features by creating throwaway devices in their own netns. On failure they refuse to start with a clear Event. No L3 GENEVE (`innerprotoinherit`, 5.18+), so the Ethernet inner header and fixed MACs are needed.

## Alternatives considered

- Require 5.15+ for nicer features: would exclude some vSphere/Ubuntu 20.04-era fleets.

## Consequences

Some cleanups (L3 GENEVE, bpf kfuncs for conntrack) wait for a future baseline bump.
