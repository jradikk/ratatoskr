# ADR-0004: Two client datapaths behind one Go interface

- Status: Accepted
- Date: 2026-10-29

## Context

`iproute` is quick to build and easy to debug. eBPF scales better (one LPM lookup per packet instead of linear `ip rule` evaluation) and can attach identity TLVs.

## Decision

`pkg/datapath` defines `ClientConfig` (compiled, datapath-agnostic) and a `Datapath` interface (`Ensure(netns, cfg)`, `Remove(netns)`, `Probe()`). `iproute` ships first; `ebpf` arrives in M6. The controller and CRDs never see which is active; the choice is a Helm value.

## Alternatives considered

- eBPF only: slower to reach a working MVP and harder to debug on old kernels.
- iproute only: rule count grows linearly with policy size, and there are no TLVs.

## Consequences

Policy compilation (`pkg/policy`) is shared and unit-tested once. Both datapaths share the e2e suites. TLVs exist only in ebpf mode (MTU accounts for this per mode).
