# M6 — tc eBPF datapath component report

Status: **implementation and local component gates pass; full packet-level/5.10 e2e acceptance remains deferred to the final project gate**. No claim is made that a VPN-backed eBPF workload or Linux 5.10 runtime passed.

## Implemented

- `bpf/client.c`, generated bpf2go ELF and `pkg/datapath/ebpf` add the second `datapath.Backend` behind the same client/gateway configuration. An IPv4 tc egress program uses bounded CIDR/port maps, an external collect_md GENEVE device, a gateway VNI and hashed identity TLV. Selected traffic with no healthy endpoint drops; metadata is denied unless explicitly allowed; IPv6 packets drop. Unencrypted gateway termination reuses the existing validated iproute gateway ingress verifier and upstream kill switch.
- The init driver, node agent, gateway, controller, webhook and chart select `DATAPATH=ebpf` explicitly. Unrecognized modes fail rather than silently choosing iproute. eBPF + WireGuard is **unsupported and rejected** before registration, not downgraded to plaintext. Agent-mode workloads retain their capability-free waiter; BPF/PERFMON privileges are confined to the programming init (init mode), agent (agent mode) or gateway container. No bpffs mount or persisted key/credential is needed.
- Linux 5.10 source inspection confirmed the 24-byte tunnel-key ABI and GENEVE option helper support; the Go backend verifies the kernel route to each endpoint would source the workload PodIP rather than assuming `local_ipv4` works on 5.10. Runtime kernel availability is still checked by actual BPF load.
- A security review reproduced an earlier-priority tc pass bypass. The backend now rejects preempting foreign egress filters before attach. Restart adoption verifies the attached eBPF program and map state, not only a readiness marker; endpoint changes revoke the old healthy selector before fallible replacement. A failed update leaves selected traffic dropped instead of retaining the old endpoint.

## Validation on October 29, 2026

- Repository-wide `make test` (race/coverage), `make lint` (0 issues), `make vet`, `make build`, `make test-privileged`, strict Helm lint and chart static render checks for both drivers × both datapaths passed after security hardening. `go generate ./pkg/datapath/ebpf` and focused eBPF unit/privileged tests also passed; generated ELF is checked in. All privileged tests used disposable network namespaces on this host's kernel 7.0.
- eBPF component tests exercise `BPF_PROG_TEST_RUN` selectors, port/CIDR policy, no-endpoint drops, healthy tc redirect to external GENEVE, underlay source validation, tc-filter bypass rejection, attached-map verification on a fresh backend, and revocation on a failed endpoint change. They are **not** a multi-pod, full upstream or Linux 5.10 traffic proof.
- CI and live e2e were deliberately not run per the user's final-gate-only instruction. No live VPN inputs or credentials were read into this report.

## Known constraints and final-gate checks

- The eBPF implementation is IPv4-only; it rejects assigned global IPv6 on eth0 at programming time and drops IPv6 seen by tc. IPv6 added *later* or CNI-specific interfaces/routes require runtime verification before claiming complete dual-stack fail-close.
- eBPF has no WireGuard support (use iproute for encrypted mode). Seccomp and node capability support for `bpf(2)`/NET_ADMIN differ by runtime; an actual restricted-node k3d program load and Linux 5.10 validation remain pending.
- Healthy-to-healthy **policy-only** changes retain the prior selector until atomic filter replacement; a failed update can temporarily retain stale policy. This must be addressed or explicitly failed at the final production gate, not represented as a complete policy-revocation guarantee.
- No complete eBPF capture of outer source, destination, VNI, TLV or return traffic through a live gateway/upstream has yet been run. Final CI/live e2e must cover both datapaths; unavailable VPN inputs count as skipped, never passed.
