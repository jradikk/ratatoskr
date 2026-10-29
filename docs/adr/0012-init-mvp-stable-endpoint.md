# ADR-0012: Stable single-replica endpoint for the M2 init-driver MVP

- Status: Rejected; not implemented
- Date: 2026-10-29

## Context

M2 requires client pods to recover from a gateway pod restart without restarting
those clients. The M2 `init` driver programs each pod's fixed-remote GENEVE
device **once**, and no node agent exists until M5. A replacement gateway pod
can receive a new PodIP. Neither a Kubernetes annotation update nor a controller
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

## Decisions awaiting user clarification

1. **Keep milestones in order:** M2 init mode fails closed when a gateway PodIP
   changes; amend M2's restart acceptance to allow restarting selected client
   pods. M5 agent mode then satisfies seamless client-pod recovery with in-place
   endpoint updates. This changes an explicit M2 acceptance criterion.
2. **Keep the M2 restart criterion:** bring a netns-capable endpoint updater
   forward into M2 (agent or a NET_ADMIN restartable init sidecar), changing the
   requested driver milestone split and capability/lifecycle model.

Neither change is adopted. The implementation must not silently choose either.
