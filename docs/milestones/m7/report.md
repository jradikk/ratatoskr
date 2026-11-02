# M7 — gateway replica HA and bounded observability component report

Status: **local code/component validation passed; cluster failover and traffic acceptance deferred to the final project gate**. No claim is made that an OpenVPN replica failover preserved established connections or that a Prometheus collector scraped this release.

## Implemented

- `spec.replicas` 1–32 now renders the requested gateway Deployment count. Controller publishes only owner-chain-verified, distinct gateway PodIPs; each healthy pod must pass its private `/info` probe, measured MTU check and (for WireGuard) public identity validation. `readyReplicas` counts independently healthy replicas and the gateway is Ready if at least one is healthy. A shared conservative MTU chooses the smallest healthy replica budget.
- Workload admission and the node agent use shared deterministic rendezvous hashing for sticky selection from healthy gateway PodIPs; selected WireGuard identity is bound to that exact IP. Endpoint addition/removal minimally changes assignment. Agent clients reconcile changed endpoints in-place; fixed-remote init clients receive a rollout condition after a previously healthy endpoint disappears or rotates identity. A new endpoint alone does not invalidate existing init clients.
- Helm supports optional multi-replica controller/webhook with scoped Lease leader election, and refuses controller replicas >1 without election. Gateway serves a **private loopback-only** `/metrics` on `127.0.0.1:9902`: `ratatoskr_gateway_upstream_healthy` is a zero-label gauge reflecting effective upstream/datapath readiness. A later follow-up (`ddb0ddf`) added the zero-label `ratatoskr_gateway_effective_mtu_bytes`, derived from the same atomically published measured state and set to zero when not ready or unknown. No externally accessible metrics Service was created, and no inferred peer/flow counters are represented as measurements.

## Validation

Repository-wide `make test` (race/coverage), `make lint` (0 issues), `make vet`, `make build`, `make test-privileged`, strict Helm lint and chart static render/security tests passed on October 29, 2026. Focused tests verify affinity ordering/minimal churn, endpoint identity binding, deployment replica rendering, owner-chain protection and private metrics binding. No CI/e2e or live VPN test ran: per the user's instruction those are reserved for the final gate.

## Deferred / limitations

- HA tests with 1–3 live gateway replicas, VPN health failover, dual exit IPs, endpoint churn, established-flow behavior and complete packet captures are pending. Re-hashing onto another replica changes the upstream exit IP and **breaks established connections**; it is not transparent failover.
- `/metrics` cannot currently be scraped from outside a gateway Pod without a separately authorized sidecar/proxy and network-policy review. Per-workload bytes/flows/drops, WireGuard handshake age and authenticated live peer count are not implemented; do not claim the original broader M7 observability target is complete.
- Subsequent commits `5aa03fb` and `d5ae6af` added eBPF deny-all lockdown before fallible policy changes and a namespace-wide agent IPv6 guard/quarantine, respectively. Their privileged component tests passed, but final multi-pod runtime verification is still required. Init-driver late IPv6 handling is not covered by the agent guard.
