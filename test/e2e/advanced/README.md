# Advanced M4/M7 acceptance authoring (offline)

This directory adds a **cluster-free** strict acceptance predicate for one
`driver=agent`, `datapath=iproute`, `encryption=wireguard` lifecycle and a Go
unit contract for sticky endpoint choice across 1–3 healthy replicas. Neither
runs a workload, uses credentials, reads Secrets, changes a cluster, or provides
traffic-gate evidence. No matrix cell is marked covered by these synthetic tests.

Run offline only:

```sh
PYTHONDONTWRITEBYTECODE=1 python3 -m unittest discover -s test/e2e/advanced -p 'test_*.py'
go test ./test/e2e/advanced
```

## M4/M5 integration contract (not an executable live runner)

A future **parent-authorized final-gate collector** must construct a dictionary
for `wireguard.validate(evidence)`. Its four ordered stage objects are
`registered`, `plain`, `authenticated`, and `revoked`; see `test_wireguard.sample`
for the complete schema. The identity object binds the exact selected client
Pod UID/PodIP, gateway Pod UID/PodIP and GatewayID. Every stage must be measured
against that same identity and a fresh marked attempt, and the collector must
record packet identity (not counters alone) to prevent unrelated traffic from
satisfying checks. Samples in unit tests are fabricated and MUST NOT be reused
as evidence. Never serialize tokens, private keys, raw TLS material, packet
payloads, or provider logs in evidence.

The final-gate owner must explicitly approve a compatible existing release,
agent/iproute driver, CNI/network policy, a disposable selected Pod and a
gateway with a safe fake upstream or separately approved profile. It must
verify Pod-bound TokenReview audience/UID, authenticated TLS with pinned
controller-attested gateway identity, `/32` WG peers/routes and agent marker;
in a **controlled forged-packet test** prove that plaintext outer GENEVE UDP/6081
arrives on gateway eth0 and is dropped before gnv0/delivery; then prove a
separate authenticated selected marker travels over WG with peer counters and
no plaintext UDP/6081 on the underlay; finally opt out/delete the disposable
Pod or exercise TTL and verify peer removal, route withdrawal, unreachable
fallback and failure of a fresh selected attempt without baseline escape.
A forged plaintext packet must never be sent outside this explicitly approved
isolated fixture; passive observation alone cannot prove rejection. Match the
outer PodIPs, VNI/inner source, protocol, interface, and marker correlation in
the collector—the predicate is not a capture parser. Capture must be header-only.

Blockers for live integration: there is no approved live collector or owned
packet injector here, no stable disposable gateway/Pod fixture, no approved
network capture context, no credential/TokenReview observation adapter and no
parent authorization to mutate the cluster. Until implemented and run, this
scenario is **NOT COVERED**. `test/e2e/matrix/coverage.json` remains unchanged.

## HA boundary

The Go test checks deterministic 1–3 endpoint selection, reordering stability,
absence-of-endpoint error and new endpoint selection after removing a chosen
replica. It **does not** establish live endpoint status publication, agent
reprogramming or continued traffic. A future live HA gate must bind each
selected Pod UID to the actual ready PodIP/exit identity, remove one endpoint
under approved fixture ownership, prove that only clients of the failed
replica reselect and can establish **new** connections with the replacement
exit IP, and observe that old connections may break. It must separately verify
fail-closed behavior when no endpoint is healthy. Never assert established-flow
continuity across replica failover.
