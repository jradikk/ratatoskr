# M8 — compatibility coverage inventory and deferred scenario scaffold

Status: **static and two direct-config flannel/init fake subsets passed; scoped agent/WireGuard, HA and outage evidence added; full compatibility acceptance remains INCOMPLETE**.
This report records the M8 authoring-stage static checks and later final-gate follow-ups. Initial fake subsets failed; numbered-client-GENEVE and guarded eBPF update fixes restored positive traffic. A corrected fixture then tested selected and nonselected TCP/8080 against the **same reachable remote PodIP**: both iproute and eBPF inner suites passed serially, including directly reachable endpoint withdrawal. Separately gated flannel/no-mesh agent/iproute runs observed synthetic WireGuard peer startup/revocation, fresh-connection two-replica HA, witnessed outage/recovery with packet-correlated selected-destination fail-close, and independent owned-Pod TokenReview UID/ServiceAccount/audience semantics (not an observed gateway TokenReview call). These subsets do not cover plaintext GENEVE denial or the remaining scenario requirements. The 96-cell matrix returned INCOMPLETE/exit 4; its inventory remains unchanged. The live VPN tier skipped because its profile was unset. No full compatibility/release acceptance is claimed; see `docs/milestones/m9/final-gate.md`.

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
- Final-gate extended fake scenarios now use the **same reachable remote
  PodIP:8080** through both the ordinary CNI path and the fake upstream. Only
  that remote /32 is removed from pod-CIDR exclusions. Its HTTP echo returns
  the client PodIP on the direct path and fake exit IP `198.19.0.2` when
  steered, proving matching include versus wrong-port, wrong-CIDR and exclude
  behavior without relying on aggregate GENEVE counters, inner-only timeouts
  or packet classification before tc egress. Endpoint withdrawal also blocks
  this otherwise directly reachable destination; DNS/API survive, and the
  full tunnel recovers. The owned numbered client GENEVE addresses permit
  reverse-source validation without relaxing `rp_filter`. These are still
  **direct datapath checks**, not CRD compiler, admission, agent, mesh or
  multi-gateway reconciliation proofs. A serial final-gate run at
  `/tmp/ratatoskr-m8-fake-_cj0w5sf/` recorded both inner suites passed while
  the outer matrix remained INCOMPLETE/exit 4.
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

**Not run during M8 authoring:** runner main, fake/live traffic, cluster
operations, Docker/image builds/imports, real VPN/profile/token reads or
Go/component tests. Syntax/static checks alone cannot validate Kubernetes
admission, BPF loads, VPN routing, fail-close or mesh behavior. The subsequent
final-gate executions and their **failures/skips** are recorded separately in
`docs/milestones/m9/final-gate.md`; they do not retroactively turn this static
inventory into a passed compatibility matrix.

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
- eBPF policy-update lockdown and agent late-IPv6 quarantine were subsequently
  implemented and component-tested (`5aa03fb`, `d5ae6af`). The final eBPF fake
  traffic gate later **failed** at the tunneled echo. A subsequent flannel Pod
  reproduction saw gateway flower acceptance and client GENEVE return reception;
  the client's socket still timed out. A subsequent healthy three-netns
  production-component fixture attributed returned SYN-ACK drops to
  `SKB_DROP_REASON_IP_RPFILTER` by matching skb pointers; the earlier
  pre-ingress metadata explanation was too broad. Init-driver late IPv6, actual Linux 5.10 loading
  and CNI-specific interface/underlay source verification remain unverified.
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
At M8 authoring time, e2e execution was deferred to the final project gate.
That later gate is documented as **failed/incomplete**, not passed.
