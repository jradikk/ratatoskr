#!/usr/bin/env python3
"""Isolated bounded partial synthetic Gateway smoke; NEVER an M8 e2e PASS.

Only a parent-approved, externally preflighted release and imported images.
The CLI entrypoint remains in run.py behind four explicit gates. No selected,
witness, fail-close or recovery resources are created here.
"""
from pathlib import Path
from datetime import datetime, timezone
import ipaddress
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


class TerminalFailure(Blocked):
    """UID-pinned one-shot selected Pod failed; clean up without retrying."""


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
    step = "gateway-status"
    try:
        gateway = api.get("egressgateway", "synthetic", namespace)
        if (gateway["metadata"].get("uid") != gateway_uid or
                not evidence.condition(gateway, "Ready", "True", gateway["metadata"]["generation"])):
            raise Blocked("Gateway UID or Ready condition not current.")
        step = "gateway-owned-resources"
        deployment = api.get("deployment", "synthetic", namespace)
        children = [api.get(kind, "synthetic", namespace) for kind in ("service", "configmap", "networkpolicy")]
        step = "gateway-pod-list"
        pods = api.list_owned_gateway_pods(namespace, gateway_uid)
        rs_ref = next((r for r in pods["metadata"].get("ownerReferences", [])
                       if r.get("kind") == "ReplicaSet" and r.get("controller") is True), None)
        if rs_ref is None or not rs_ref.get("name"):
            raise Blocked("Gateway ReplicaSet owner missing.")
        step = "gateway-replicaset"
        rs = api.get("replicaset", rs_ref["name"], namespace)
        if rs["metadata"].get("uid") != rs_ref.get("uid"):
            raise Blocked("Gateway ReplicaSet UID differs from Pod owner.")
        step = "gateway-chain-assertion"
        evidence.assert_gateway_chain(gateway, deployment, rs, pods, children, image_ids)
        return gateway, pods
    except (adapter.AdapterError, evidence.EvidenceError, KeyError, TypeError, ValueError,
            AttributeError, StopIteration):
        # Step is one of our own fixed non-secret checkpoint labels, never
        # an API field, exception, address, profile or Pod log.
        raise Blocked("Gateway verification blocked at " + step + ".") from None


def observe(api, owner, ids, created, *, clock=time.monotonic, sleep=time.sleep):
    """Poll strict real Kubernetes evidence under the Lifecycle deadline."""
    namespace = owner.names[0]
    server_uid = created[("Pod", namespace, "synthetic-vpn")]
    gateway_uid = created[("EgressGateway", namespace, "synthetic")]
    deadline = min(owner.deadline, clock() + 110)
    stage = "source-pod"
    gateway_step = "gateway-status"
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
            return {"gatewayUID": gateway_uid, "serverUID": server_uid,
                    "gatewayPodUID": gateway_pod["metadata"]["uid"],
                    "gatewayID": gateway["status"]["gatewayID"],
                    "endpoint": gateway["status"]["endpoints"][0]["podIP"],
                    "session": dict(sessions[0])}
        except (adapter.AdapterError, evidence.EvidenceError, Blocked, KeyError,
                TypeError, ValueError, AttributeError) as failure:
            if stage == "gateway-chain" and isinstance(failure, Blocked):
                for candidate in ("gateway-status", "gateway-owned-resources", "gateway-pod-list",
                                  "gateway-replicaset", "gateway-chain-assertion"):
                    if str(failure) == "Gateway verification blocked at " + candidate + ".":
                        gateway_step = candidate
                        break
            remaining = deadline - clock()
            if remaining > 0:
                sleep(min(2, remaining))
    label = gateway_step if stage == "gateway-chain" else stage
    raise Blocked("Partial Gateway smoke timed out at non-secret checkpoint " + label + ".")


def api_service_ip(api):
    """Read-only known Kubernetes Service IPv4; never infer from mutable env."""
    try:
        service = api.get("service", "kubernetes", "default")
        meta, spec = service["metadata"], service["spec"]
        addr = ipaddress.ip_address(spec["clusterIP"])
        if (meta.get("name") != "kubernetes" or meta.get("namespace") != "default" or
                addr.version != 4 or addr.is_unspecified or addr.is_multicast or addr.is_loopback or
                spec.get("type") not in (None, "ClusterIP")):
            raise ValueError()
        return str(addr)
    except (KeyError, ValueError, TypeError, AttributeError):
        raise Blocked("Preflight Kubernetes Service ClusterIP missing or invalid.") from None


def healthy_selected(api, owner, ids, created, baseline, api_ip, *, clock=time.monotonic, sleep=time.sleep):
    """Pod-status-only selected proof; no workload exec, logs or Secret reads.

    OpenVPN server bytes may also grow from health probes/keepalives. Counter
    delta is supporting local evidence, NOT attributable tunnel proof alone.
    """
    namespace, apps = owner.names
    if (not isinstance(baseline, dict) or
            baseline.get("gatewayUID") != created[("EgressGateway", namespace, "synthetic")] or
            baseline.get("serverUID") != created[("Pod", namespace, "synthetic-vpn")] or
            not isinstance(baseline.get("gatewayID"), int) or baseline["gatewayID"] <= 0 or
            not isinstance(baseline.get("endpoint"), str)):
        raise Blocked("Healthy selected phase lost fixture UID provenance.")
    before = baseline.get("session")
    if (not isinstance(before, dict) or before.get("cn") != "synthetic-client" or
            any(type(before.get(k)) is not int or before[k] <= 0 for k in ("received", "sent"))):
        raise Blocked("Authenticated OpenVPN baseline session invalid.")
    original = prepare.selected_probe_pod(apps, namespace, "healthy", api_ip)
    result = api.create(original)
    key = (result["kind"], result["namespace"], result["name"])
    if key != ("Pod", apps, "synthetic-probe-healthy") or not lifecycle.UID.fullmatch(result.get("uid", "")):
        raise Blocked("Healthy selected Pod CREATE-return UID invalid.")
    uid = result["uid"]
    deadline = min(owner.deadline, clock() + 115)
    stage = "selected-pod-status"
    while clock() < deadline:
        try:
            if owner.closed or owner.clock() >= owner.deadline:
                raise Blocked("Selected Pod Lifecycle deadline exceeded.")
            pod = api.get("pod", "synthetic-probe-healthy", apps)
            if pod["metadata"].get("uid") != uid:
                raise Blocked("Healthy selected Pod UID changed.")
            status = pod.get("status", {})
            if status.get("phase") == "Failed":
                # Only UID-pinned terminal status and fixed exit categories are
                # surfaced. Never print status messages, probe output or logs.
                init = [s for s in status.get("initContainerStatuses", []) if s.get("name") == "ratatoskr-init"]
                app = [s for s in status.get("containerStatuses", []) if s.get("name") == "client"]
                init_exit = init[0].get("state", {}).get("terminated", {}).get("exitCode") if init else None
                app_exit = app[0].get("state", {}).get("terminated", {}).get("exitCode") if app else None
                app_failure = {11: "direct-before-failed", 12: "marker-failed",
                               13: "direct-after-failed", 21: "direct-before-dns-failed",
                               22: "direct-before-route-failed", 23: "direct-before-tls-connect-failed",
                               24: "direct-before-tls-verify-failed", 25: "direct-before-tls-status-failed",
                               26: "direct-before-api-unauthorized", 27: "direct-before-api-success",
                               28: "direct-before-api-other", 31: "direct-after-dns-failed",
                               32: "direct-after-route-failed",
                               33: "direct-after-tls-connect-failed", 34: "direct-after-tls-verify-failed",
                               35: "direct-after-tls-status-failed", 36: "direct-after-api-unauthorized",
                               37: "direct-after-api-success", 38: "direct-after-api-other",
                               41: "marker-unreachable", 43: "marker-connect-timeout", 44: "marker-refused",
                               45: "marker-response-invalid", 46: "marker-other-failed",
                               47: "marker-response-timeout"}
                label = ("wait-init-failed" if init_exit not in (None, 0) else
                         app_failure.get(app_exit, "app-failed") if app_exit not in (None, 0) else
                         "pod-failed-unknown")
                raise TerminalFailure("Healthy selected Pod failed at selected-pod-status-" + label + ".")
            if status.get("phase") != "Succeeded":
                raise Blocked("Healthy selected Pod not completed.")
            evidence.assert_selected_probe(pod, namespace=apps, phase="healthy",
                                           expected_uid=uid, expected_image_id=ids["selected"],
                                           expected_api_ip=api_ip)
            stage = "agent-routing-config"
            config_raw = pod["metadata"].get("annotations", {}).get(evidence.PREFIX + "agent-config", "")
            if not isinstance(config_raw, str) or len(config_raw) > 4096:
                raise Blocked("Selected agent routing configuration unavailable.")
            import json
            config = json.loads(config_raw)
            if (not isinstance(config, dict) or config.get("gatewayID") != baseline["gatewayID"] or
                    config.get("endpoint") != baseline["endpoint"] or
                    config.get("identity", {}).get("uid") != uid or
                    config.get("podIP") != pod["status"].get("podIP") or
                    config.get("identity", {}).get("namespace") != apps or
                    config.get("identity", {}).get("pod") != "synthetic-probe-healthy" or
                    config.get("identity", {}).get("policy") != "synthetic" or
                    config.get("policy", {}).get("mode") != "include" or
                    config.get("policy", {}).get("rules") != [{
                        "cidrs": ["10.88.0.1/32"],
                        "ports": [{"protocol": "TCP", "port": 8080}]}]):
                raise Blocked("Selected agent routing config does not match healthy Gateway and Pod UID.")
            stage = "gateway-still-ready"
            gateway = api.get("egressgateway", "synthetic", namespace)
            if (gateway["metadata"].get("uid") != baseline["gatewayUID"] or
                    not evidence.condition(gateway, "Ready", "True", gateway["metadata"]["generation"]) or
                    gateway.get("status", {}).get("gatewayID") != baseline["gatewayID"] or
                    not any(e.get("upstreamHealthy") is True and e.get("podIP") == baseline["endpoint"]
                            for e in gateway.get("status", {}).get("endpoints", []))):
                raise Blocked("Gateway endpoint changed during healthy selected Pod.")
            stage = "authenticated-session-growth"
            server = api.get("pod", "synthetic-vpn", namespace)
            if server["metadata"].get("uid") != baseline["serverUID"]:
                raise Blocked("Server Pod UID changed during selected Pod.")
            observed = api.server_session(namespace, baseline["serverUID"],
                                          expected_image_id=ids["server"])
            sessions = observed.get("sessions")
            if (not isinstance(sessions, list) or len(sessions) != 1 or
                    sessions[0].get("cn") != "synthetic-client" or
                    any(sessions[0].get(k) != before.get(k) for k in
                        ("cn", "virtualIPv4", "connected", "peer", "cipher")) or
                    any(type(sessions[0].get(k)) is not int or sessions[0][k] <= before[k]
                        for k in ("received", "sent"))):
                raise Blocked("Authenticated OpenVPN session bytes or identity did not advance.")
            # Validate the selected Pod identity again after the separate
            # server status API read; stale/replaced Pods cannot be adopted.
            if api.get("pod", "synthetic-probe-healthy", apps)["metadata"].get("uid") != uid:
                raise Blocked("Selected Pod UID changed during session read.")
            return {"podUID": uid, "healthyExit": True, "directAPITLSAndDNS": True,
                    "serverSessionBytesAdvanced": True}
        except TerminalFailure:
            raise
        except (adapter.AdapterError, evidence.EvidenceError, Blocked, KeyError,
                TypeError, ValueError, AttributeError):
            remaining = deadline - clock()
            if remaining > 0:
                sleep(min(2, remaining))
    raise Blocked("Healthy selected traffic smoke timed out at " + stage + ".")


def execute(ids, *, lifecycle_factory=lifecycle.Lifecycle, adapter_factory=adapter.FixtureAPI,
            observer=observe, selected_observer=healthy_selected, api_ip=None):
    """Only call after triple-opt-in preflight+node CRI and fourth CLI gate."""
    if not isinstance(ids, dict) or set(ids) != set(run.COMPONENTS):
        raise Blocked("Nine immutable expected image IDs required.")
    for value in ids.values():
        if not isinstance(value, str) or not run.ID_PATTERN.fullmatch(value):
            raise Blocked("Mutable or malformed expected image ID.")
    if api_ip is None:
        raise Blocked("Preflight Kubernetes Service ClusterIP required before mutation.")
    try:
        addr = ipaddress.ip_address(api_ip)
        if addr.version != 4 or addr.is_unspecified or addr.is_multicast or addr.is_loopback:
            raise ValueError()
    except (TypeError, ValueError):
        raise Blocked("Preflight API ClusterIP invalid before mutation.") from None
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
        baseline = observer(api, owner, ids, created)
        if not isinstance(baseline, dict) or set(baseline) != {
                "gatewayUID", "serverUID", "gatewayPodUID", "gatewayID", "endpoint", "session"}:
            raise Blocked("Partial Gateway baseline evidence incomplete.")
        evidence_result = selected_observer(api, owner, ids, created, baseline, str(addr))
        if evidence_result != {"podUID": evidence_result.get("podUID") if isinstance(evidence_result, dict) else None,
                               "healthyExit": True, "directAPITLSAndDNS": True,
                               "serverSessionBytesAdvanced": True} or not lifecycle.UID.fullmatch(evidence_result["podUID"]):
            raise Blocked("Healthy restricted selected Pod evidence incomplete.")
    # Returning here requires Lifecycle-confirmed cleanup of BOTH namespaces.
    # This is a partial smoke, NEVER a full synthetic e2e PASS.
    return False
