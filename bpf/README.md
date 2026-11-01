# eBPF client selector

[client.c](client.c) implements the IPv4 tc egress selector used by
[pkg/datapath/ebpf](../pkg/datapath/ebpf/). The Go backend attaches it with a
netlink clsact filter in the caller's locked workload netns. It uses an external
GENEVE device for encapsulation; gateway termination remains the iproute
GENEVE/flower/kill-switch backend.

## Behavior and safety

- CIDR/port selectors decide which authorized IPv4 traffic is steered. Metadata
  and cluster exclusions retain their configured handling.
- Selected traffic with no healthy endpoint is dropped, never sent through
  ordinary egress. IPv6 is dropped; Pods with non-link-local eth0 IPv6 are
  refused by the backend. Malformed headers and helper failures also fail closed.
- GENEVE metadata carries gateway identity for gateway verification. The actual
  underlay route must source the client PodIP: the backend refuses a healthy
  remote with a conflicting source rather than emitting unauthenticated traffic.
- Policy maps are populated before filter replacement. An owned terminal-drop
  update guard protects failed updates; incompatible preexisting egress filters
  are rejected. Do not delete unrelated CNI filters to make attachment succeed.
- `wireguard` client/gateway modes are rejected. Use `iproute` for encrypted
  client-to-gateway transport; there is no plaintext fallback.

The runtime targets Linux 5.10+ and uses clsact rather than TCX. Kernel helpers,
capabilities and seccomp must permit BPF loading and netlink operations. The
chart requests `NET_ADMIN`, `BPF` and `PERFMON` for eBPF programming; the agent
also needs its namespace-entry privileges. Older/differently restricted kernels
may deny loading. Do not silently switch backends or escalate privileges.

Objects are held through file descriptors and the tc attachment; the backend
does not mount bpffs or pin persistent maps there. Production programming uses
Go netlink/BPF libraries, not shell commands.

## Building and contributing

The generated [Go bindings](../pkg/datapath/ebpf/client_bpfel.go) embed
`client_bpfel.o`, so ordinary builds do not require clang. Keep C source,
generated bindings and object synchronized when changing map layouts or logic.

From the repository root, non-privileged checks are:

```sh
go test ./pkg/datapath/ebpf/...
go vet ./pkg/datapath/ebpf/...
clang -target bpfel -O1 -g -Wall -Werror -I/usr/include/aarch64-linux-gnu \
  -fsyntax-only bpf/client.c
```

Regeneration uses `go generate ./pkg/datapath/ebpf` and bpf2go from the module.
The current [generate directive](../pkg/datapath/ebpf/generate.go) uses clang,
little-endian `bpfel` and Debian ARM64 headers at
`/usr/include/aarch64-linux-gnu`. On another build host, supply the corresponding
Linux header include path; do not assume the existing directive is portable to
all distributions/architectures. Regeneration intentionally modifies generated
source/object artifacts and should be reviewed as part of a code change.

Tests with the `privileged` build tag exercise kernel programs/network
namespaces and require a separately authorized compatible environment. Do not
run them merely to preview documentation. Unit and compile checks do not prove
CNI integration, every Linux 5.10 backport or end-to-end traffic behavior.
