# tc client datapath (M6 component)

`client.c` is compiled by `go generate ./pkg/datapath/ebpf` via bpf2go. The
prebuilt BPF object is embedded in the Go package. The Go backend attaches the
program using netlink's clsact egress filter (not TCX, which is too new for the
Linux 5.10 target); it keeps fd-backed maps/program in the pod netns and does
not pin or mount bpffs. The runtime needs kernel eBPF load permissions (BPF and
NET_ADMIN on modern kernels; platform-specific CAP_SYS_ADMIN fallback on older
kernels) and a seccomp profile allowing `bpf(2)` and netlink. No production
shell commands are used.

Linux v5.10 `net/core/filter.c` supports `bpf_skb_set_tunnel_key` (including the
legacy 24-byte layout) and aligned `bpf_skb_set_tunnel_opt`; `drivers/net/geneve.c`
reads `TUNNEL_GENEVE_OPT` and emits TLV bytes from the external GENEVE device.
The v5.10 `bpf_tunnel_key` does **not** have `local_ipv4`; its helper sets only
remote IPv4. `ApplyClient` therefore refuses a healthy endpoint unless the
kernel's actual underlay route sources the client PodIP. The GENEVE outer source
must equal the inner source for the gateway's mandatory flower verifier.

In `wireguard` mode the backend rejects client/gateway configuration *before*
creating tunnel/filter state. Use iproute for encrypted workloads; there is
no plaintext fallback or optional WireGuardManager implementation here. IPv6
address discovery on eth0 rejects dual-stack Pods, and tc drops IPv6 it sees.
No-endpoint selected IPv4 is dropped, not sent to baseline. Policy CIDR/port
maps are rebuilt before atomically replacing the tc filter. Updates after a
process crash replace the named filter without deleting unrelated CNI state.

Component tests cover BPF_PROG_TEST_RUN selectors, healthy GENEVE redirect,
no-endpoint local socket drops, IPv4/metadata exclusions, TLV map and route
source checks. Full multi-pod networking and packet capture remain a separate
project gate; tests on this host's kernel do **not** prove every v5.10 backport
combination. Kernel helper errors fail closed in tc (`TC_ACT_SHOT`).
