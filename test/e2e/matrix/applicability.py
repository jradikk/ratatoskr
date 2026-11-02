"""Pure, non-certifying applicability inventory for the compatibility matrix.

No Kubernetes, runner, filesystem, network, or evidence mutation. The only
explicitly unsupported combination is eBPF + WireGuard; all remaining cells
are *candidates* requiring traffic, not verified supported or passed modes.
"""
from itertools import product

AXES = ("cni", "mesh", "driver", "datapath", "encryption")
VALUES = {"cni": ("flannel", "cilium", "cilium-wg", "calico"),
          "mesh": ("none", "sidecar", "ambient"),
          "driver": ("init", "agent"),
          "datapath": ("iproute", "ebpf"),
          "encryption": ("none", "wireguard")}
MODES = ("fake", "live")
INIT = frozenset({"init-gateway-replacement"})
AGENT = frozenset({"agent-restricted-workload", "agent-restart-endpoint-update"})
WG = frozenset({"wireguard-registration", "wireguard-plaintext-denial"})
EBPF = frozenset({"ebpf-tunnel", "ebpf-revocation-failure"})
EBPF_PLAIN = frozenset({"ebpf-tunnel"})  # Assertion explicitly says unencrypted.
PROVIDER = frozenset({"public-exit-country", "live-provider-disruption"})
# Descriptive subsystem is part of the reviewed scenario identity.
COMPONENTS = {
    "direct-cluster-baseline": "direct datapath",
    "controller-admission-selection": "controller and admission",
    "init-gateway-replacement": "init driver",
    "selective-cidr-port": "policy selection",
    "no-endpoint-revocation": "fail-closed routing",
    "metadata-prohibition": "metadata isolation",
    "gateway-dns": "DNS forwarding",
    "payload-integrity": "payload integrity",
    "measured-mtu-mss": "MTU and MSS",
    "pmtu-fragmentation": "PMTU and fragmentation",
    "spoof-geneve": "tunnel isolation",
    "wireguard-registration": "WireGuard registration",
    "wireguard-plaintext-denial": "WireGuard plaintext denial",
    "agent-restricted-workload": "restricted node agent",
    "agent-restart-endpoint-update": "node agent recovery",
    "ebpf-tunnel": "eBPF datapath",
    "ebpf-revocation-failure": "eBPF revocation",
    "ipv6-runtime-guard": "IPv6 runtime safety",
    "ha-affinity-failover": "gateway failover",
    "private-health-metric": "private health telemetry",
    "full-observability": "observability",
    "upstream-fail-close-recovery": "upstream recovery",
    "public-exit-country": "provider exit",
    "live-provider-disruption": "provider recovery",
    "cni-mesh-compatibility": "CNI and mesh compatibility",
}

EXPECTED_SCENARIOS = frozenset({
    "direct-cluster-baseline", "controller-admission-selection", "init-gateway-replacement",
    "selective-cidr-port", "no-endpoint-revocation", "metadata-prohibition", "gateway-dns",
    "payload-integrity", "measured-mtu-mss", "pmtu-fragmentation", "spoof-geneve",
    "wireguard-registration", "wireguard-plaintext-denial", "agent-restricted-workload",
    "agent-restart-endpoint-update", "ebpf-tunnel", "ebpf-revocation-failure",
    "ipv6-runtime-guard", "ha-affinity-failover", "private-health-metric", "full-observability",
    "upstream-fail-close-recovery", "public-exit-country", "live-provider-disruption",
    "cni-mesh-compatibility",
})
EXPECTED_IMPLEMENTATIONS = {
    "direct-config": frozenset({"direct-cluster-baseline", "ebpf-tunnel",
                                "upstream-fail-close-recovery", "public-exit-country"}),
    "fake-extended": frozenset({"selective-cidr-port", "payload-integrity"}),
    "extended": frozenset({"measured-mtu-mss", "private-health-metric"}),
}
EXPECTED_IMPLEMENTATIONS["unimplemented"] = EXPECTED_SCENARIOS.difference(
    *EXPECTED_IMPLEMENTATIONS.values())
EXPECTED_MODES = {"selective-cidr-port": "fake", "no-endpoint-revocation": "fake",
                  "payload-integrity": "fake", "upstream-fail-close-recovery": "fake",
                  "public-exit-country": "live", "live-provider-disruption": "live"}


class InvalidInventory(ValueError):
    """Unknown axes, scenarios or changed constraints require human review."""


def validate(coverage):
    """Refuse schema/axis/scenario drift rather than shrink the acceptance gate."""
    if (type(coverage) is not dict or set(coverage) != {"schemaVersion", "source", "axes", "scenarios", "apiScenarios"} or
            type(coverage.get("schemaVersion")) is not int or
            coverage["schemaVersion"] != 1 or
            type(coverage.get("axes")) is not dict or
            set(coverage["axes"]) != set(AXES) or
            any(type(coverage["axes"][axis]) is not list or
                coverage["axes"][axis] != list(VALUES[axis]) for axis in AXES) or
            type(coverage.get("scenarios")) is not list or
            len(coverage["scenarios"]) != len(EXPECTED_SCENARIOS)):
        raise InvalidInventory("Compatibility inventory schema/axes require review")
    found = set()
    for item in coverage["scenarios"]:
        if (type(item) is not dict or set(item) != {"id", "component", "implementation", "mode", "assertion"} or
                type(item["id"]) is not str or item["id"] not in EXPECTED_SCENARIOS or
                item["id"] in found or type(item["assertion"]) is not str or
                not item["assertion"] or type(item["component"]) is not str or
                item["component"] != COMPONENTS.get(item["id"]) or type(item["implementation"]) is not str or
                not item["implementation"] or
                item["id"] not in EXPECTED_IMPLEMENTATIONS.get(item["implementation"], ()) or
                item["mode"] != EXPECTED_MODES.get(item["id"], "both")):
            raise InvalidInventory("Compatibility scenario definition requires review")
        found.add(item["id"])
    if found != EXPECTED_SCENARIOS:
        raise InvalidInventory("Compatibility scenario set requires review")
    # Do not implicitly recategorize a newly introduced API scenario as traffic.
    if (type(coverage.get("apiScenarios")) is not list or
            len(coverage["apiScenarios"]) != 6 or
            any(type(item) is not dict or
                set(item) != {"id", "component", "implementation", "mode", "assertion"} or
                item.get("mode") != "both" or item.get("component") != "API and admission" or
                item.get("implementation") != "api-admission"
                for item in coverage["apiScenarios"]) or
            {item.get("id") for item in coverage["apiScenarios"]} != {
                "api-crd-server-dry-run", "api-authorized-mutation-validation",
                "api-unauthorized-denial", "api-security-fields",
                "api-ebpf-wireguard-rejection", "api-independent-update-validation"}):
        raise InvalidInventory("Compatibility API scenarios require review")
    return coverage


def cells(coverage, mode):
    """Return exactly 96 unique, canonical candidate identities per mode."""
    validate(coverage)
    if type(mode) is not str or mode not in MODES:
        raise InvalidInventory("Unknown matrix mode")
    return tuple({"mode": mode, **dict(zip(AXES, combination))}
                 for combination in product(*(VALUES[axis] for axis in AXES)))


def _cell(cell, coverage):
    if (type(cell) is not dict or set(cell) != {*AXES, "mode"} or
            type(cell["mode"]) is not str or cell["mode"] not in MODES or
            any(type(cell[axis]) is not str or cell[axis] not in VALUES[axis] or
                cell[axis] not in coverage["axes"][axis] for axis in AXES)):
        raise InvalidInventory("Unknown matrix cell or changed axis")


def decide(coverage, cell, scenario=None):
    """Return a requirement, NEVER a success: accepted is always False."""
    validate(coverage)
    _cell(cell, coverage)
    if scenario is not None and (type(scenario) is not str or scenario not in EXPECTED_SCENARIOS):
        raise InvalidInventory("Unknown matrix scenario")
    unsupported = cell["datapath"] == "ebpf" and cell["encryption"] == "wireguard"
    if scenario is None:
        return {"decision": "refusal-required" if unsupported else "traffic-required",
                "reason": "ebpf-wireguard-unsupported" if unsupported else "candidate-not-verified-supported",
                "accepted": False}
    if unsupported:
        return {"decision": "not-applicable", "reason": "cell-requires-unsupported-refusal",
                "accepted": False}
    declared = next(item["mode"] for item in coverage["scenarios"] if item["id"] == scenario)
    if declared != "both" and declared != cell["mode"]:
        reason = "scenario-mode-" + declared + "-only"
    elif scenario in INIT and cell["driver"] != "init":
        reason = "scenario-init-driver-only"
    elif scenario in AGENT and cell["driver"] != "agent":
        reason = "scenario-agent-driver-only"
    elif scenario in WG and cell["encryption"] != "wireguard":
        reason = "scenario-wireguard-only"
    elif scenario in EBPF and cell["datapath"] != "ebpf":
        reason = "scenario-ebpf-only"
    elif scenario in EBPF_PLAIN and cell["encryption"] != "none":
        reason = "scenario-unencrypted-only"
    elif scenario in PROVIDER and cell["mode"] != "live":
        reason = "scenario-live-provider-only"
    else:
        return {"decision": "traffic-required", "reason": "applicable-evidence-not-evaluated",
                "accepted": False}
    return {"decision": "not-applicable", "reason": reason, "accepted": False}
