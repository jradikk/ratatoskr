# Spec issues and resolutions

Problems found in the build specification, with the resolution adopted. Each is
reflected in `design.md` and the ADRs.

| # | Issue | Resolution |
|---|---|---|
| S1 | The OpenVPN Secret contract allows only `client.ovpn` (+`auth.txt`), but real provider configs reference external `ca`/`cert`/`key`/`tls-auth` files. | Mount **all** Secret keys into one directory. The sanitizer resolves file references relative to it and rejects absolute paths or `..` escapes. Inline configs keep working. |
| S2 | "outer source == inner source" anti-spoofing does not hold in `wireguard` mode if GENEVE is addressed to WireGuard overlay IPs. | GENEVE outer addresses are **always pod IPs**. In encrypted mode the `/32` routes between client and gateway pod IPs go through WireGuard, whose allowed-IPs bind each peer to its pod IP. The check is identical in both modes; the gateway also drops plain GENEVE arriving on `eth0` when encrypted. |
| S3 | Live step 11 ("capture on a node interface; only WireGuard, no GENEVE") cannot prove anything on flannel. Pod-to-pod traffic between nodes is VXLAN-encapsulated, and same-node traffic never reaches the node interface at all. | The test pins the client and gateway to **different nodes** and captures on the client pod's host-side veth, where traffic is unencapsulated by the CNI. It asserts that only WireGuard UDP reaches the gateway pod IP and that no UDP/6081 appears. |
| S4 | Live step 7 builds an include rule from ipinfo.io's resolved IPs. These CDN addresses change and may overlap with api.ipify.org's. | Resolve both names inside the test pod at test time. If the address sets overlap, mark the step **inconclusive** instead of failing it. |
| S5 | In agent mode, an unprivileged init container has no API access, so it cannot read pod annotations. A Downward API volume would work, but it is refreshed lazily (up to ~1 min). | The agent creates a marker link (`rtk-ready`, a dummy interface) in the pod netns once the datapath is programmed. The wait-init polls `/sys/class/net/rtk-ready`, which needs no privileges, tokens or network. The annotation is still written for observability. |
| S6 | Firewall-mark collisions with Istio (`0x539`/`0xfff`) and Cilium (`0x0f00`, `0xf000` ranges). | Ratatoskr uses only bits in a configurable mask (default `0x00f00000`). |
| S7 | DNS `gateway` mode must rebuild search domains, but the cluster domain is not always `cluster.local`. | Chart value `clusterDomain`. |
| S8 | Replies to inbound connections from non-excluded sources (e.g. a LoadBalancer with `externalTrafficPolicy: Local` that preserves client IPs) would be steered into the tunnel, breaking ingress to labeled pods. | A connmark on connections entering via `eth0` routes their replies through `main`. |
| S9 | `allowCloudMetadata` is listed under "exclusions (never steered)", which makes `false` vs `true` ambiguous. | `false` (default): `169.254.169.254` is **blocked** in labeled pods (`prohibit` route). `true`: it is reachable via the normal node path. It is never steered in either case. |
| S10 | The M8 matrix (Cilium/Calico + Istio ambient, 1+2 nodes) does not fit the dev VM (3.8 GiB RAM, no swap). | M0–M7 run on flannel. Before M8, the VM needs ~8 GiB, or the matrix runs variant by variant with `FORCE=1` and reduced Istio resources. |
