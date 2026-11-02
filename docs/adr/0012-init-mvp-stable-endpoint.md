# ADR-0012: M2 init-driver restart and fixed GENEVE endpoints

- Status: Accepted; Service-VIP proposal rejected
- Date: 2026-10-29

## Context

The original M2 criterion required client pods to recover from a gateway pod
restart without restarting those clients. The M2 `init` driver programs each
pod's fixed-remote GENEVE device **once**, and no node agent exists until M5.
A replacement gateway pod can receive a new PodIP. Neither a Kubernetes annotation update nor a controller
reconcile changes a route/device already installed inside a running pod netns.
Thus directly using the gateway PodIP in M2 contradicts its restart acceptance.

## Rejected proposal: Service VIP as GENEVE remote

A stable UDP/6081 ClusterIP Service would preserve the **transmit destination**
across replacement pods, but it would not preserve the source of the **return**
GENEVE packets. The gateway return route must use the client PodIP, so the
replacement gateway transmits replies with its own new PodIP as outer source.
The client non-`collect_md` GENEVE device was created with the Service VIP as
its fixed `remote`. Linux `drivers/net/geneve.c` (`geneve_lookup` and
`geneve_lookup_skb`, checked against upstream v7.0) matches the received outer
source address **against that configured remote** as well as the VNI. Replies
from the actual gateway PodIP do not match the Service VIP and are dropped.
Neither kube-proxy nor the CNI's ordinary Service destination translation fixes
this reverse-path source mismatch. Forcing the gateway to source replies from a
Service VIP is not a CNI-agnostic pod-network contract. This proposal also
conflicts with the design invariant that outer GENEVE addresses are pod IPs.
Do **not** implement this Service-IP exception or claim restart recovery from it.

## Decision (user-selected option 1, October 29, 2026)

Keep the milestone order and the M2 `init` driver. Each selected client pod's
fixed-remote GENEVE device addresses the **gateway PodIP**, not a Service VIP.
When the gateway PodIP changes, an already-running client has a stale endpoint:
steered traffic must fail closed, and a rollout/recreation of those client pods
is required before they can use the replacement endpoint. Record the need for
rollout in gateway status/Events and the operations runbook; never claim the
original no-client-restart M2 acceptance as passing.

M5 `agent` mode must update the client pod netns endpoint in place and meet
recovery without restarting client pods. Its failure/connection impact is
checked at the final e2e gate. This change to M2's original criterion was
explicitly approved by the user; it does not relax final production fail-close
or agent-mode recovery requirements.
