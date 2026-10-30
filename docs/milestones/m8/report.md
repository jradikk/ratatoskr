# M8 — compatibility coverage inventory and deferred scenario scaffold

Status: **static validation passed; compatibility acceptance INCOMPLETE**.
No fake/live e2e has run and no CNI/mesh matrix cell is claimed passed.

## Audit and implementation

The clean child checkout was synchronized by creating a new branch directly at
parent commit `67237a9`. The parent had already integrated M1's separate commit,
so the old child branch could not fast-forward; no reset, merge, parent files or
uncommitted work were overwritten. This assignment changes only `test/e2e/**`
and `docs/milestones/m8/**`.

Before this change, `test/e2e/ci/run.sh` and `test/e2e/live/run.sh` merely called
M1's flannel/no-mesh/init/iproute/unencrypted direct-config runner. They exercised
neither CRD admission nor agent/WireGuard/HA/CNI/mesh fixtures. M2–M7 component
reports consistently deferred full traffic validation; those reports are not
traffic evidence for M8.

- `test/e2e/matrix/coverage.json` inventories 25 named scenarios derived from
  `docs/design.md` and M2–M7 reports. It declares 96 combinations per mode:
  flannel/Cilium/Cilium-WireGuard/Calico × none/sidecar/ambient × init/agent ×
  iproute/eBPF × none/WireGuard. eBPF+WireGuard is explicitly unsupported, never
  silently downgraded. This enumeration is a coverage inventory, not a promise
  that every combination is currently supported or tested.
- Only two direct-config final-gate scaffolds exist: flannel/no-mesh/init/none
  with iproute or eBPF. Other cells and missing scenarios are **SKIPPED / not
  covered**. Implemented-but-unexecuted entries are DEFERRED, never PASSED.
- CI/live entrypoints now produce **static inventory by default**. Static
  preflight only checks local tool/file presence and Linux/profile-presence
  booleans; it does not read credentials, contact Kubernetes, inspect/build/import
  images, allocate clusters, or claim that resource/kernel capabilities passed.
  A static/incomplete/skipped report returns **exit 4**, not green. Final execution
  additionally requires `--execute` and `RATATOSKR_E2E_FINAL_GATE=1`.
- Selected executable cells run serially under a process lock and keep the
  mandatory `hack/k3d-up.sh` creation resource/module preflight, one-cluster rule,
  bounded M1 cleanup and local-image-only contract. No VM changes or alternate
  CNI installation are attempted by these new scenarios. No resource preflight
  is bypassed or duplicated on cluster reuse.
- Final-gate extended fake scenarios test include/exclude CIDR and TCP-port
  selectors against the **same reachable** remote service, withdraw the healthy
  endpoint and require selected requests to fail while API/DNS remain usable,
  then restore the original steering. Removing only that remote /32 from pod
  exclusions prevents a negative test from passing simply because its destination
  was always unreachable. These are direct datapath checks, **not CRD compiler,
  admission or endpoint-reconciliation proofs**.
- A 4.5 MiB deterministic fake payload is checked for exact length and SHA256
  (the existing fixture repeats the nine-byte `ratatoskr` 512×1024 times, exactly
  4,718,592 bytes; the older 4 MiB task description was inaccurate);
  private temporary payload files are deleted. Gateway measured MTU/MSS relations
  are asserted, without claiming PMTU/fragmentation coverage. Private loopback
  health gauge 1/0/1 and lack of PodIP:9902 exposure are checked in the fake
  fault/recovery stages; full telemetry is not invented.
- Complete eBPF fake/live YAML files explicitly select DATAPATH and confine
  BPF/PERFMON to the programming tools/gateway containers. No SYS_ADMIN, host
  mount, privileged workload, private key or token projection is added. Runtime
  seccomp/BPF/TUN capability success remains unverified, not inferred from YAML.
- Live Secret and ipinfo handling is retained from M1: profile/auth from
  outside-repo files; optional literal IPINFO_TOKEN becomes a private temporary
  file and --from-file Secret, then only a projected Secret/private curl config
  inside the client. No raw output/provider logs are retained. Missing profile
  skips before cluster work; 429/unavailable external probes remain inconclusive.

## Exact validation on October 30, 2026

Only static validation was run:

- Individual `bash -n` checks on CI/live entrypoints, M1 runner and `extended.sh`.
- `sh -n test/e2e/m1/ipinfo.sh`.
- `python3 test/e2e/m1/static-check.py`: rendered/parsed **25 complete YAML
  documents across nine templates**, including capability, token-mount, entrypoint,
  namespace, Secret and default sanitizer contract assertions.
- `python3 test/e2e/matrix/static-check.py`: both fake/live inventories contain
  **96 unique cells / two implemented subsets**; static evidence cannot become a
  passed matrix, empty inner checkpoint reports cannot count as covered, and all
  five selector JSON variants preserve required exclusions without mutating input.
  Authored Python sources are compiled without invoking runner main or creating
  bytecode files. Subprocess execution is forbidden while building the inventory.
- `git diff --check`: passed.

**Not run:** runner main (even inventory/skip CLI paths), fake/live traffic,
cluster operations, Docker/image builds/imports, real VPN/profile/token reads,
Go/component tests or host/VM changes. Syntax/static checks do not validate
Kubernetes admission, actual BPF loads, VPN routing, fail-close or mesh behavior.

## Required final-gate extensions / blockers

The full M2–M8 matrix remains incomplete. Unimplemented requirements include:

- Controller/CRD selection and admission, forbidden namespace/label mutations,
  init gateway replacement with explicit rollout (ADR-0012).
- Gateway cluster/external UDP/TCP DNS and upstream-only SERVFAIL behavior;
  controlled metadata endpoint, spoofed inner/outer sources/VNI/TLV packet tests,
  PMTU/fragmentation and full outer packet captures.
- Authenticated WireGuard registration, private-key handling/peer deletion,
  handshake/return path and plaintext GENEVE denial.
- Restricted agent workloads, healthy CRI/setns marker-up, agent adoption/restarts
  and endpoint updates without workload recreation.
- eBPF policy-only update failure revocation, late IPv6 runtime safety, actual
  Linux 5.10 loading and CNI-specific interface/underlay source verification.
- 1–3 gateway replicas, HA affinity/failover and endpoint churn. Existing flows
  may break across replicas; transparent continuity must not be claimed.
- Full observability counters/handshake/peer metrics absent from components.
- All alternative CNI and mesh traffic fixtures and live provider disruption.

The precise original live steps **1–13 are unavailable in this workspace**;
this inventory does not invent an equivalent checklist. Obtain/approve that
checklist before declaring final live acceptance. Component limitations already
recorded in M6/M7 remain production blockers unless fixed or explicitly scoped
out. Completing these scenarios requires coordinated component changes beyond
this task's scope.

Even if both implemented direct-config subsets later pass, the matrix runner
returns INCOMPLETE/nonzero because missing cells/scenarios remain not covered.
All e2e execution remains deferred to the final project gate.
