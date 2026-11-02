"""Strict, offline, scenario-scoped evidence assessment for future matrix runs.

This module never invokes Kubernetes or a runner. It deliberately cannot emit
full-cell PASS: a scenario proof does not establish all compatibility promises.
The caller must supply independently reviewed expected source/image identities,
scenario definitions and nonempty checkpoint requirements; evidence cannot
self-certify those expectations. This is not an artifact signature or trust root.
"""

import re

AXES = ("cni", "mesh", "driver", "datapath", "encryption")
_SHA = re.compile(r"[0-9a-f]{40}")
# Kubernetes imageID may be a bare digest, runtime://sha256:..., or a
# registry reference with an immutable digest (optionally docker-pullable://).
_DIGEST = re.compile(r"(?:sha256:|(?:containerd|docker|cri-o)://sha256:)[0-9a-f]{64}|(?:docker-pullable://)?[^\s@]+@sha256:[0-9a-f]{64}")
_STATUSES = frozenset(("PASSED", "FAILED", "SKIPPED", "INCONCLUSIVE"))


class EvidenceError(ValueError):
    """Malformed, stale, ambiguous or out-of-scope evidence; never a pass."""


def _is_string(value):
    return isinstance(value, str) and bool(value)


def _identity(images):
    if not isinstance(images, dict) or not images:
        raise EvidenceError("nonempty component image identities required")
    if any(not _is_string(name) or not _is_string(image) or
           not _DIGEST.fullmatch(image) for name, image in images.items()):
        raise EvidenceError("image IDs must be exact immutable digests")


def _scenario_specs(spec, mode):
    if not isinstance(spec, dict) or type(spec.get("schemaVersion")) is not int or spec["schemaVersion"] != 1 or spec.get("axes") is None:
        raise EvidenceError("unknown coverage schema")
    axes = spec["axes"]
    if (not isinstance(axes, dict) or any(not isinstance(axes.get(axis), list) or
                                            not axes[axis] or any(not _is_string(v) for v in axes[axis])
                                            for axis in AXES)):
        raise EvidenceError("incomplete coverage axes")
    scenarios = spec.get("scenarios")
    if not isinstance(scenarios, list):
        raise EvidenceError("missing traffic scenarios")
    result = {}
    for item in scenarios:
        if not isinstance(item, dict) or not _is_string(item.get("id")) or item.get("mode") not in ("fake", "live", "both"):
            raise EvidenceError("invalid scenario specification")
        if item["id"] in result:
            raise EvidenceError("duplicate scenario specification")
        if item["mode"] in (mode, "both"):
            result[item["id"]] = item
    return axes, result


def evaluate_cell(evidence, *, source_sha, image_ids, expected_cell, coverage, requirements):
    """Assess a bounded scenario subset, never mark a whole cell PASSED.

    Required evidence envelope (all identities supplied independently):
      sourceSHA: 40 lowercase hex; images: {component: immutable imageID};
      cell: {mode: fake|live, cni, mesh, driver, datapath, encryption};
      scope: {kind: "scenario-subset", scenarios: [known IDs]};
      checkpoints: [{name, scenario, status}];
      cleanup: {status: "PASSED", ownedResourcesAbsent: true}.

    `expected_cell` and `requirements` are *independent* caller expectations:
    a complete cell identity and scenario ID to nonempty required checkpoints.
    Missing/unmapped requirements cannot be inferred from evidence. Each
    checkpoint is bound to exactly one declared scenario.
    Unknown fields are rejected to avoid an unreviewed scope or status channel.
    """
    if not _SHA.fullmatch(source_sha or ""):
        raise EvidenceError("expected source SHA must be full lowercase SHA-1")
    _identity(image_ids)
    if not isinstance(evidence, dict) or set(evidence) != {
        "sourceSHA", "images", "cell", "scope", "checkpoints", "cleanup"
    }:
        raise EvidenceError("missing or unknown evidence envelope fields")
    _identity(evidence["images"])
    if evidence["sourceSHA"] != source_sha or evidence["images"] != image_ids:
        raise EvidenceError("stale source SHA or image identity mismatch")
    cell = evidence["cell"]
    if not isinstance(cell, dict) or set(cell) != {*AXES, "mode"} or cell["mode"] not in ("fake", "live"):
        raise EvidenceError("unknown or incomplete cell identity")
    if not isinstance(expected_cell, dict) or cell != expected_cell:
        raise EvidenceError("evidence cell differs from independently expected cell")
    axes, scenarios = _scenario_specs(coverage, cell["mode"])
    if any(not _is_string(cell[axis]) or cell[axis] not in axes[axis] for axis in AXES):
        raise EvidenceError("unknown compatibility cell axis")
    if cell["datapath"] == "ebpf" and cell["encryption"] == "wireguard":
        raise EvidenceError("unsupported ebpf + wireguard cell cannot be covered")
    scope = evidence["scope"]
    if not isinstance(scope, dict) or set(scope) != {"kind", "scenarios"} or scope["kind"] != "scenario-subset":
        raise EvidenceError("explicit scenario-subset scope required")
    selected = scope["scenarios"]
    if not isinstance(selected, list) or not selected or any(not _is_string(s) for s in selected) or len(selected) != len(set(selected)):
        raise EvidenceError("nonempty unique scenario IDs required")
    if any(s not in scenarios or s.startswith("ebpf-") and cell["datapath"] != "ebpf" for s in selected):
        raise EvidenceError("scenario not applicable to this cell/mode")
    if any(s.startswith("wireguard-") and cell["encryption"] != "wireguard" for s in selected):
        raise EvidenceError("WireGuard scenarios require the wireguard cell")
    if any(s.startswith("agent-") and cell["driver"] != "agent" for s in selected):
        raise EvidenceError("agent scenarios require an agent-driver cell")
    if "init-gateway-replacement" in selected and cell["driver"] != "init":
        raise EvidenceError("init rollout scenario requires an init-driver cell")
    if "public-exit-country" in selected and cell["mode"] != "live":
        raise EvidenceError("public exit scenario requires a live cell")
    if "live-provider-disruption" in selected and cell["mode"] != "live":
        raise EvidenceError("provider disruption requires a live cell")
    if "cni-mesh-compatibility" in selected and cell["cni"] == "flannel" and cell["mesh"] == "none":
        raise EvidenceError("compatibility scenario needs an alternative CNI or mesh")
    if not isinstance(requirements, dict) or set(requirements) != set(selected):
        raise EvidenceError("independent requirements must cover exact scenario scope")
    declared = set()
    for scenario, names in requirements.items():
        if not isinstance(names, (tuple, list)) or not names or any(not _is_string(n) for n in names) or len(names) != len(set(names)):
            raise EvidenceError("each scenario needs unique nonempty required checkpoints")
        if declared.intersection(names):
            raise EvidenceError("checkpoint names must bind to one scenario only")
        declared.update(names)
    checks = evidence["checkpoints"]
    if not isinstance(checks, list) or any(not isinstance(c, dict) or set(c) != {"name", "scenario", "status"} or
                                           not _is_string(c.get("name")) or c.get("scenario") not in selected or
                                           c.get("status") not in _STATUSES for c in checks):
        raise EvidenceError("unknown, malformed or unscoped checkpoint")
    seen = set()
    by_scenario = {scenario: {} for scenario in selected}
    for c in checks:
        key = (c["scenario"], c["name"])
        if key in seen or c["name"] not in requirements[c["scenario"]]:
            raise EvidenceError("duplicate or undeclared checkpoint")
        seen.add(key)
        by_scenario[c["scenario"]][c["name"]] = c["status"]
    cleanup = evidence["cleanup"]
    if (not isinstance(cleanup, dict) or set(cleanup) != {"status", "ownedResourcesAbsent"} or
            cleanup["status"] not in _STATUSES or type(cleanup["ownedResourcesAbsent"]) is not bool):
        raise EvidenceError("exact bounded cleanup evidence required")
    cleaned = cleanup["status"] == "PASSED" and cleanup["ownedResourcesAbsent"] is True
    result = {}
    for scenario in selected:
        statuses = [by_scenario[scenario].get(name) for name in requirements[scenario]]
        if not cleaned:
            status = "FAILED" if cleanup["status"] == "FAILED" or cleanup["ownedResourcesAbsent"] is False else "INCOMPLETE"
        elif "FAILED" in statuses:
            status = "FAILED"
        elif "INCONCLUSIVE" in statuses:
            status = "INCONCLUSIVE"
        elif statuses and all(value == "PASSED" for value in statuses):
            status = "PASSED"
        else:
            status = "INCOMPLETE"
        result[scenario] = status
    # A subset can prove its own checkpoints, never full compatibility. Even
    # every declared scenario passing requires separate complete-cell review.
    return {"cell": "/".join(cell[axis] for axis in AXES), "mode": cell["mode"],
            "scope": "scenario-subset", "status": "FAILED" if "FAILED" in result.values() else "INCOMPLETE",
            "scenarios": result, "fullCellCovered": False}
