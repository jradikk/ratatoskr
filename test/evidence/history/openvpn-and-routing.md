# M1 implementation report

Status: **implemented; final e2e validation deferred by user instruction**.
This is component/build evidence, not a successful packet-level datapath proof.

## Built

- Shared Go datapath contract, IPv4/full-tunnel `iproute` backend, and gateway/init commands.
- GENEVE client routes with unreachable fallback; explicit exclusions; no changes to the main default route.
- Gateway collect_md termination and return-route metadata, flower outer/inner source and VNI checks, nft SNAT/kill switch, MSS clamping, and marked recovery-probe routing.
- Owned routing rules are protocol-tagged; updates/removal preserve foreign CNI/mesh rules.
- OpenVPN plugin with allowlist sanitization, private runtime config, restart/backoff, tunnel-bound/marked exit probes, and localhost health API. Default probes use api.ipify.org to reserve ipinfo calls for live assertions.
- Test-only fake IPIP upstream, tools image, complete manual proof manifests and bounded fake/live runners. `make m1-images` prepares local images without executing traffic tests or pushing images.
- Docker build-context secret exclusions.

## Component evidence

- Final local gate passed: `make test` (race enabled), `make lint`, `make vet`, `make build`, targeted privileged netns tests, static rendering/contract checks for 13 complete YAML documents, shell syntax checks, Linux amd64/arm64 command builds, `make m1-images`, and `git diff --check`.
- Privileged throwaway-netns tests passed: idempotent programming, multiple selected clients, foreign-rule preservation, unreachable lookup with no endpoint, explicit opt-out restoring main routing, and unhealthy upstream default-drop with recovery routes retained.
- k3d/containerd TUN component pod succeeded with **NET_ADMIN + MKNOD**, without privileged mode, a VPN profile or external traffic.
- k3d init component pod succeeded with **NET_ADMIN only**, without SYS_ADMIN or e2e traffic. Already-correct/disabled reverse-path-filter sysctls are not needlessly written through runtime read-only proc mounts; required unavailable changes fail explicitly.
- Component namespaces were removed.

## Deferred / open

- **Neither `make e2e` nor `make e2e-live` has been run.** All actual GENEVE/VPN traffic assertions are reserved for the final project gate; no throughput, spoof-packet, failover or MTU result is claimed here.
- The runners currently cover only the documented M1 subset. Extend them as M2–M9 features are implemented; a subset report must never be presented as the complete final suite.
- Live inputs were unset during M1. At final validation, provide `RATATOSKR_E2E_OVPN`, optionally `RATATOSKR_E2E_OVPN_AUTH`, `RATATOSKR_E2E_EXPECT_COUNTRY` and `IPINFO_TOKEN`. Values/configs/credentials must not appear in logs or this repository.
- Separate provider certificate/key file projection is not yet supported by the initial live harness, although the plugin accepts safely mounted references.
- Runtime TUN policies other than the tested k3d/containerd setup, and the hostPath fallback, are not yet verified.
- Selective policy, DNS gateway mode, WireGuard, agent driver, eBPF steering, HA/observability and compatibility matrix remain later milestones.
