# ADR-0004: Two client datapaths behind one Go interface

- Status: Accepted
- Date: 2026-10-29

## Context

`iproute` is inspectable and uses kernel routing plus nftables; a tc/eBPF
selector offers a different policy implementation. Both must share one
validated client config and fail closed without requiring a CRD change.

## Decision

`pkg/datapath.Backend` defines `ApplyClient(context.Context, ClientConfig)`,
`RemoveClient(context.Context, ClientConfig)`, `ApplyGateway(context.Context,
GatewayConfig)` and `Close()`. The caller enters the intended network namespace
on a locked OS thread **before** constructing a backend. `iproute` uses netlink
routes/rules and nftables; `ebpf` selects client traffic with clsact/tc and an
external GENEVE device, while the gateway side currently delegates to iproute.
The chart `datapath` choice is explicit; unsupported eBPF + WireGuard is
rejected, never silently downgraded to plaintext.

## Alternatives considered

- eBPF only: requires compatible kernel features everywhere and is harder to
  inspect than routes/nftables.
- iproute only: limits future packet-selection options.

## Consequences

Policy compilation and fail-closed acceptance are shared contracts, but the
two backends have separate packet tests. The `Backend` API does not provide
`Ensure(netns,cfg)`, `Probe()` or implicit namespace switching.
