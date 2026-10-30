#!/usr/bin/env python3
"""Isolated bounded partial synthetic Gateway smoke; NEVER an M8 e2e PASS.

Only a parent-approved, externally preflighted release and imported images.
The CLI entrypoint remains in run.py behind four explicit gates. No selected,
witness, fail-close or recovery resources are created here.
"""
from pathlib import Path
import time

try:
    from . import adapter, evidence, lifecycle, prepare, run
except ImportError:
    import adapter
    import evidence
    import lifecycle
    import prepare
    import run


class Blocked(lifecycle.LifecycleError):
    """Static sanitized message only; never include Secret/API material.

    Lifecycle preserves this typed error after verified cleanup, while cleanup
    failures still override it. Unknown exception text remains suppressed.
    """


BASE = (("Secret", "synthetic-server"), ("Secret", "synthetic-client"),
        ("Secret", "synthetic-witness"), ("ConfigMap", "synthetic-exit-health"),
        ("Pod", "synthetic-vpn"), ("Service", "synthetic-vpn"),
        ("EgressGateway", "synthetic"), ("EgressPolicy", "synthetic"))


def private_contents(directory):
    """Read only whitelisted generated files; never return an on-disk manifest."""
    if not isinstance(directory, Path):
        raise Blocked("Private PKI directory missing.")
    names = ("ca.crt", "server.crt", "server.key", "client.crt", "client.key",
             "witness.crt", "witness.key")
    values = []
    try:
        for name in names:
            file = directory / name
            if file.is_symlink() or not file.is_file() or file.stat().st_size > 16_384:
                raise ValueError()
            if name.endswith(".key") and file.stat().st_mode & 0o777 != 0o600:
                raise ValueError()
            values.append(file.read_text(encoding="ascii"))
    except (OSError, ValueError, UnicodeError):
        raise Blocked("Private PKI inputs unavailable or unsafe.") from None
    return tuple(values)


def source_ready(server, service, image_id):
    evidence.assert_source_service(service, server, image_id)
    meta = server["metadata"]
    if meta.get("uid") in (None, "") or meta.get("deletionTimestamp"):
        raise Blocked("Synthetic source Pod UID or runtime image mismatch.")
    return server


def gateway_ready(api, gateway_uid, namespace, image_ids):
    """Read only owner-linked resources, never Secrets or raw Pod logs."""
    try:
        gateway = api.get("egressgateway", "synthetic", namespace)
        if (gateway["metadata"].get("uid") != gateway_uid or
                not evidence.condition(gateway, "Ready", "True", gateway["metadata"]["generation"])):
            raise Blocked("Gateway UID or Ready condition not current.")
        deployment = api.get("deployment", "synthetic", namespace)
        children = [api.get(kind, "synthetic", namespace) for kind in ("service", "configmap", "networkpolicy")]
        pods = api.list_owned_gateway_pods(namespace, gateway_uid)
        rs_ref = next((r for r in pods["metadata"].get("ownerReferences", [])
                       if r.get("kind") == "ReplicaSet" and r.get("controller") is True), None)
        if rs_ref is None or not rs_ref.get("name"):
            raise Blocked("Gateway ReplicaSet owner missing.")
        rs = api.get("replicaset", rs_ref["name"], namespace)
        if rs["metadata"].get("uid") != rs_ref.get("uid"):
            raise Blocked("Gateway ReplicaSet UID differs from Pod owner.")
        evidence.assert_gateway_chain(gateway, deployment, rs, pods, children, image_ids)
        return gateway, pods
    except (adapter.AdapterError, evidence.EvidenceError, KeyError, TypeError, ValueError,
            AttributeError, StopIteration):
        raise Blocked("Owned Gateway chain, status, measured MTU or runtime IDs unverified.") from None


def observe(api, owner, ids, created, *, clock=time.monotonic, sleep=time.sleep):
    """Poll strict real Kubernetes evidence under the Lifecycle deadline."""
    namespace = owner.names[0]
    server_uid = created[("Pod", namespace, "synthetic-vpn")]
    gateway_uid = created[("EgressGateway", namespace, "synthetic")]
    deadline = min(owner.deadline, clock() + 110)
    stage = "source-pod"
    while clock() < deadline:
        try:
            if owner.closed or owner.clock() >= owner.deadline:
                raise Blocked("Partial smoke Lifecycle deadline expired.")
            server = api.get("pod", "synthetic-vpn", namespace)
            service = api.get("service", "synthetic-vpn", namespace)
            if server["metadata"].get("uid") != server_uid:
                raise Blocked("Synthetic source Pod UID changed.")
            source_ready(server, service, ids["server"])
            stage = "gateway-chain"
            gateway, gateway_pod = gateway_ready(api, gateway_uid, namespace, ids)
            stage = "source-endpoint"
            # EndpointSlice list is verified against server Pod UID/IP by
            # the adapter; no guessed/generated name is ever authorized.
            source = api.source_endpoint(namespace, service, server)
            evidence.assert_source_endpoint(source, service, server)
            stage = "authenticated-session"
            session = api.server_session(namespace, server_uid, expected_image_id=ids["server"])
            sessions = session.get("sessions")
            if (not isinstance(sessions, list) or len(sessions) != 1 or
                    sessions[0].get("cn") != "synthetic-client" or
                    sessions[0].get("cipher") not in ("AES-256-GCM", "AES-128-GCM") or
                    type(sessions[0].get("received")) is not int or
                    type(sessions[0].get("sent")) is not int or
                    sessions[0]["received"] <= 0 or sessions[0]["sent"] <= 0):
                raise Blocked("Authenticated server-side OpenVPN session unverified.")
            if gateway_pod["metadata"].get("uid") in (None, ""):
                raise Blocked("Gateway Pod UID absent.")
            return True
        except (adapter.AdapterError, evidence.EvidenceError, Blocked, KeyError,
                TypeError, ValueError, AttributeError):
            remaining = deadline - clock()
            if remaining > 0:
                sleep(min(2, remaining))
    raise Blocked("Partial Gateway smoke timed out at non-secret checkpoint " + stage + ".")


def execute(ids, *, lifecycle_factory=lifecycle.Lifecycle, adapter_factory=adapter.FixtureAPI,
            observer=observe):
    """Only call after triple-opt-in preflight+node CRI and fourth CLI gate."""
    if not isinstance(ids, dict) or set(ids) != set(run.COMPONENTS):
        raise Blocked("Nine immutable expected image IDs required.")
    for value in ids.values():
        if not isinstance(value, str) or not run.ID_PATTERN.fullmatch(value):
            raise Blocked("Mutable or malformed expected image ID.")
    # `with` owns cleanup even on Secret CREATE timeout or failed observation.
    with lifecycle_factory() as owner:
        owner.create_namespaces()
        owner.generate_pki()
        api = adapter_factory(owner)
        objects = prepare.manifests(owner.names[0], "ratatoskr-synthetic-openvpn:local",
                                    private_contents(owner.private_dir), owner.token)
        selected = [obj for obj in objects if (obj["kind"], obj["metadata"].get("name")) in BASE]
        if (len(selected) != len(BASE) or
                [(obj["kind"], obj["metadata"]["name"]) for obj in selected] != list(BASE) or
                [obj["metadata"].get("namespace") for obj in selected] !=
                [owner.names[1] if kind == "EgressPolicy" else owner.names[0]
                 for kind, _name in BASE] or
                any(obj["kind"] == "Pod" and obj["metadata"]["name"] != "synthetic-vpn"
                    for obj in selected)):
            raise Blocked("Partial Gateway fixture ordering differs from allowlist.")
        created = {}
        for obj in selected:
            identity = api.create(obj)
            key = (identity["kind"], identity["namespace"], identity["name"])
            if key in created:
                raise Blocked("Duplicate or ambiguous fixture CREATE UID.")
            created[key] = identity["uid"]
        if not observer(api, owner, ids, created):
            raise Blocked("Partial Gateway smoke evidence incomplete.")
    # Returning here requires Lifecycle-confirmed cleanup of BOTH namespaces.
    # This is a partial smoke, NEVER a full synthetic e2e PASS.
    return False
