# ADR-0012: Init-driver restart and fixed GENEVE endpoints

- Status: Accepted; Service-VIP proposal rejected
- Date: 2026-10-29

## Context

The `init` driver programs a selected Pod's fixed-remote GENEVE device once.
If the selected gateway replica is replaced, its PodIP can change, while an
already-running client's tunnel still has the old remote address.

## Rejected proposal: Service VIP as GENEVE remote

A stable UDP/6081 Service VIP would preserve the client's transmit
destination, not the source of the return GENEVE packets. Linux fixed-remote
GENEVE matches the return packet's outer source against its configured remote
and VNI. A replacement gateway emits packets sourced from its new PodIP;
ordinary Kubernetes Service destination translation does not change that
source to the VIP. Forcing VIP-sourced replies is not a portable Pod-network
contract and violates the PodIP-to-PodIP outer address design.

## Decision

Init clients configure the actual selected **Gateway PodIP** as their remote.
When that PodIP changes, steered traffic fails closed until affected init Pods
are recreated or rolled out. The controller records `ClientRestartRequired`
for affected init clients. Agent-mode clients instead reconcile selected
endpoints in their still-running Pod namespace after a current Gateway
applied-config acknowledgement.

## Consequences

Do not claim an existing init client survives gateway PodIP replacement or
turn a Service VIP into a GENEVE remote. Reprogramming agent clients does not
claim established-flow continuity across different upstream exit identities.
