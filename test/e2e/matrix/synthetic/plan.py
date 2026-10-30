#!/usr/bin/env python3
"""Pure dry-run synthetic gate contract; NEVER creates resources or awards PASS.

No kubectl, subprocess, PKI, network or filesystem IO. Validate an already
collected evidence inventory before a future live runner could consider PASS.
`run.py` intentionally does not import this module.
"""
from dataclasses import dataclass
import re

from typing import Mapping

try:
    from . import lifecycle, run
except ImportError:  # static unit tests load directly without package import
    import lifecycle
    import run


class Incomplete(Exception):
    """Constant safe diagnostics only; no live objects or secrets in errors."""


# Stable, non-secret event names; order is part of the security contract.
STAGES = (
    "release-preflight", "owned-namespaces", "fixture-created", "healthy-gateway",
    "healthy-selected", "outage-disabled", "outage-withdrawn",
    "outage-selected-blocked", "outage-witness-running", "outage-witness-complete",
    "outage-direct-preserved", "outage-restored", "recovery-gateway",
    "recovery-selected", "cleanup-verified",
)
# A transport may expose only this identity tuple for each Secret/Pod POST.
ORDER = (
    ("Secret", "synthetic-server", "server"),
    ("Secret", "synthetic-client", "server"),
    ("Secret", "synthetic-witness", "server"),
    ("ConfigMap", "synthetic-exit-health", "server"),
    ("Pod", "synthetic-vpn", "server"),
    ("Service", "synthetic-vpn", "server"),
    ("EgressGateway", "synthetic", "server"),
    ("EgressPolicy", "synthetic", "apps"),
    ("Pod", "synthetic-probe-healthy", "apps"),
    ("Pod", "synthetic-probe-outage", "apps"),
    ("Pod", "synthetic-witness", "server"),
    ("Pod", "synthetic-probe-recovery", "apps"),
)
# Placeholder variant documents contain no PKI material; the actual manifest
# generator is deliberately NOT called by this dry-run-only planner.


def validate_images(expected):
    if not isinstance(expected, dict) or set(expected) != set(run.COMPONENTS) or not all(
            isinstance(v, str) and run.ID_PATTERN.fullmatch(v) for v in expected.values()):
        raise Incomplete("Nine explicitly approved immutable runtime IDs required.")
    return dict(expected)


def validate_owner(owner):
    if (not isinstance(owner, lifecycle.Lifecycle) or owner.closed or owner.deadline is None or
            not re.fullmatch(r"[0-9a-f]{32}", owner.token) or
            owner.names != ("rtk-syn-" + owner.token[:16],
                            "rtk-syn-" + owner.token[:16] + "-apps") or
            set(owner.owned) != set(owner.names) or
            any(owner.created.get(name) != owner.owned.get(name) or
                not lifecycle.UID.fullmatch(owner.owned[name]) for name in owner.names) or
            owner.clock() >= owner.deadline):
        raise Incomplete("Lifecycle namespace UID ownership or deadline unverified.")
    return owner.names


def manifest_order(names, expected):
    """Compute non-secret (kind, namespace, name) ordering; no API calls."""
    validate_images(expected)
    if (not isinstance(names, tuple) or len(names) != 2 or
            not all(isinstance(name, str) and lifecycle.NAME.fullmatch(name) for name in names) or
            names[1] != names[0] + "-apps"):
        raise Incomplete("Only unique owned synthetic namespaces are allowed.")
    # Require distinct immutable witness and selected image expectations; no
    # mutable tag, although two components may legitimately share a digest.
    return tuple((kind, names[1] if scope == "apps" else names[0], name)
                 for kind, name, scope in ORDER)


def validate_checkpoint(name, data, expected, owner, created):
    """Validate only bounded non-secret checkpoints, never raw Pod/Secret JSON."""
    if type(data) is not dict:
        raise Incomplete("Checkpoint evidence is not a plain object.")
    names = owner.names
    if name == "release-preflight":
        if data != {"runtimeIDs": {k: expected[k] for k in ("controller", "webhook", "agent")},
                    "flannelNodes": 3, "probeConfigured": True}:
            raise Incomplete("Release preflight evidence incomplete.")
    elif name == "owned-namespaces":
        if data != {"namespaceUIDs": dict(owner.owned)}:
            raise Incomplete("Namespace UID evidence differs from Lifecycle.")
    elif name == "fixture-created":
        wanted = manifest_order(names, expected)
        if set(created) != set(wanted[:8]):
            raise Incomplete("Fixture CREATE-response UIDs not verified.")
        if (any(not lifecycle.UID.fullmatch(created[item]) for item in wanted[:8]) or
                data != {"createdUIDs": tuple((item[0], item[1], item[2], created[item])
                                              for item in wanted[:8])}):
            raise Incomplete("Fixture CREATE-response UIDs not verified.")
    elif name in {"healthy-selected", "outage-selected-blocked", "recovery-selected"}:
        phase = name.split("-")[0]
        key = ("Pod", names[1], "synthetic-probe-" + phase)
        if (key not in created or data != {
                "podUID": created[key], "imageID": expected["selected"],
                "exitCode": 42 if phase == "outage" else 0,
                "waitInitExited": True, "agentReady": True,
                "directAPIAndDNS": True}):
            raise Incomplete("Selected application Pod UID/image/exit/security evidence incomplete.")
    elif name == "outage-witness-running":
        key = ("Pod", names[0], "synthetic-witness")
        if (key not in created or data != {"podUID": created[key], "imageID": expected["witness"],
                                               "distinctAuthenticatedCN": True,
                                               "markerOverOwnVPN": True}):
            raise Incomplete("Witness running UID/image/independent tunnel evidence missing.")
    elif name == "outage-witness-complete":
        key = ("Pod", names[0], "synthetic-witness")
        if (key not in created or data != {"podUID": created[key], "exitCode": 0,
                                               "completedBeforeRestore": True}):
            raise Incomplete("Witness completion not bounded by outage.")
    elif name in {"healthy-gateway", "recovery-gateway"}:
        if data != {"runtimeIDs": {k: expected[k] for k in ("gateway", "plugin", "server")},
                    "gatewayOwnerChain": True, "measuredMTU": True,
                    "sourceServiceEndpoint": True,
                    "authenticatedSession": True, "sameGatewayUID": True,
                    "sameServerUID": True}:
            raise Incomplete("Gateway owner/image/TLS evidence missing.")
    elif name == "outage-disabled":
        if data != {"probeDisabledUIDCAS": True, "serverExitObserved503": True}:
            raise Incomplete("Probe-only disable not confirmed at live server.")
    elif name == "outage-withdrawn":
        if data != {"gatewayReadyFalse": True, "noHealthyEndpoint": True,
                    "agentUnreachableRoute": True}:
            raise Incomplete("Gateway withdrawal and agent route missing.")
    elif name == "outage-direct-preserved":
        if data != {"apiTLSAnonymous403": True, "dnsExact": True,
                    "clusterRouteDirect": True}:
            raise Incomplete("Direct API/DNS path not preserved during withdrawal.")
    elif name == "outage-restored":
        if data != {"probeRestoredUIDCAS": True, "serverExitObserved200": True}:
            raise Incomplete("Probe-only restore not verified.")
    elif name == "cleanup-verified":
        if (not owner.closed or data != {"namespacesAbsent": list(names), "privatePKIAbsent": True,
                                          "noOrphanSecrets": True}):
            raise Incomplete("Cleanup verification missing or incomplete.")
    else:
        raise Incomplete("Unknown synthetic checkpoint.")


@dataclass(frozen=True)
class DryRunPlan:
    """Monotonic evidence state machine; never executes or reports PASS."""
    owner: lifecycle.Lifecycle
    expected: Mapping[str, str]

    def __post_init__(self):
        validate_owner(self.owner)
        object.__setattr__(self, "expected", validate_images(self.expected))
        object.__setattr__(self, "_index", 0)
        object.__setattr__(self, "_created", {})
        object.__setattr__(self, "_uids", dict(self.owner.owned))

    @property
    def order(self):
        return manifest_order(self.owner.names, self.expected)

    @property
    def next_stage(self):
        return STAGES[self._index] if self._index < len(STAGES) else None

    def record_create(self, identity):
        """Record ONLY exact UID returned by a separate CREATE response."""
        if (self.owner.names != tuple(self._uids) or self.owner.owned != self._uids or
                any(self.owner.created.get(n) != uid for n, uid in self._uids.items()) or
                self.owner.closed):
            raise Incomplete("Lifecycle namespace UIDs changed during fixture creation.")
        if self.owner.clock() >= self.owner.deadline:
            raise Incomplete("Synthetic evidence deadline expired.")
        if (not isinstance(identity, dict) or set(identity) != {"kind", "namespace", "name", "uid"} or
                not all(isinstance(identity[k], str) for k in identity) or
                not lifecycle.UID.fullmatch(identity["uid"])):
            raise Incomplete("Fixture CREATE identity malformed.")
        key = (identity["kind"], identity["namespace"], identity["name"])
        if key not in self.order or key in self._created:
            raise Incomplete("Unexpected, duplicate or ambiguous fixture CREATE identity.")
        target = len(self._created)
        if target < 8 and self.next_stage != "fixture-created":
            raise Incomplete("Base fixture CREATE not authorized by evidence stage.")
        if key != self.order[target]:
            raise Incomplete("Fixture CREATE ordering differs from safe plan.")
        required_stage = {8: "healthy-selected", 9: "outage-selected-blocked",
                          10: "outage-witness-running", 11: "recovery-selected"}
        if target in required_stage and self.next_stage != required_stage[target]:
            raise Incomplete("Phase Pod CREATE not ordered after required Gateway status.")
        self._created[key] = identity["uid"]

    def checkpoint(self, name, evidence):
        if (self.owner.names != tuple(self._uids) or self.owner.owned != self._uids or
                any(self.owner.created.get(n) != uid for n, uid in self._uids.items())):
            raise Incomplete("Lifecycle namespace UIDs changed during synthetic plan.")
        if self.owner.clock() >= self.owner.deadline and name != "cleanup-verified":
            raise Incomplete("Synthetic evidence deadline expired.")
        if name != self.next_stage:
            raise Incomplete("Checkpoint order differs from required gate sequence.")
        validate_checkpoint(name, evidence, self.expected, self.owner, self._created)
        object.__setattr__(self, "_index", self._index + 1)

    def final_result(self):
        # Passing 15 pure checkpoints does NOT mean the Kubernetes e2e ran.
        # A future live runner must separately validate every runtime assertion
        # and cleanup in finally; no return value can represent PASS here.
        raise Incomplete("Dry-run plan cannot award synthetic e2e PASS; live runner remains unwired.")
