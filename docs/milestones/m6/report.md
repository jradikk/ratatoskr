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

- eBPF is IPv4-only. Later commit `d5ae6af` adds an agent-mode namespace-wide IPv6 drop guard and quarantine for late dual-stack; disposable-netns tests passed. Init mode and actual multi-pod/5.10 runtime behavior remain unverified.
- eBPF has no WireGuard support (use iproute for encrypted mode). Runtime seccomp/BPF permissions on a restricted node and Linux 5.10 still require validation.
- Later commit `5aa03fb` atomically locks down the old selector before fallible policy updates, with privileged failure-injection coverage and isolated capture of outer source, destination, VNI and TLV. It does **not** establish complete eBPF traffic through a live gateway/upstream.
- Final CI/live e2e must cover both datapaths; unavailable VPN inputs count as skipped, never passed.
