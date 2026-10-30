#!/usr/bin/env python3
"""Explicitly gated, parent-rolled init-driver NONRESTRICTED partial smoke.

Never changes a Helm release. This only reuses the Gateway baseline; no agent,
restricted Pod, fail-close, WireGuard or M8 PASS evidence is awarded.
"""
import ipaddress
import time

try:
    from . import adapter, evidence, init_evidence, lifecycle, partial_gateway, prepare, run
except ImportError:
    import adapter
    import evidence
    import init_evidence
    import lifecycle
    import partial_gateway
    import prepare
    import run


class Blocked(lifecycle.LifecycleError):
    """Static, sanitized diagnostics only."""


def selected(api, owner, ids, created, baseline, api_ip, *, clock=time.monotonic, sleep=time.sleep):
    """Status-only UID-pinned production init + nonroot one-shot helper."""
    namespace, apps = owner.names
    if (owner.apps_psa != "privileged" or not isinstance(baseline, dict) or
            baseline.get("gatewayUID") != created[("EgressGateway", namespace, "synthetic")] or
            baseline.get("serverUID") != created[("Pod", namespace, "synthetic-vpn")] or
            not isinstance(baseline.get("gatewayID"), int) or
            not isinstance(baseline.get("endpoint"), str)):
        raise Blocked("Init-driver namespace/Gateway baseline not verified.")
    before = baseline.get("session")
    if (not isinstance(before, dict) or before.get("cn") != "synthetic-client" or
            any(type(before.get(k)) is not int or before[k] <= 0 for k in ("received", "sent"))):
        raise Blocked("Initial authenticated OpenVPN session unavailable.")
    identity = api.create(prepare.selected_probe_pod(apps, namespace, "healthy", api_ip))
    uid = identity.get("uid")
    if (identity.get("kind"), identity.get("namespace"), identity.get("name")) != (
            "Pod", apps, "synthetic-probe-healthy") or not isinstance(uid, str) or not lifecycle.UID.fullmatch(uid):
        raise Blocked("Init selected Pod CREATE UID/namespace/name unverified.")
    # Bounded result. A failed init, bad image, admission denial or API outage
    # remains an incomplete/failed partial smoke, never a reason to retry POST.
    deadline = min(owner.deadline, clock() + 115)
    stage = "init-selected-pod"
    phase_detail = "pending"
    while clock() < deadline:
        try:
            if owner.closed or owner.clock() >= owner.deadline:
                raise Blocked("Init selected Lifecycle deadline expired.")
            pod = api.get("pod", "synthetic-probe-healthy", apps)
            if pod["metadata"].get("uid") != uid:
                raise Blocked("Init selected Pod UID changed.")
            current = pod.get("status", {})
            if current.get("phase") != "Succeeded":
                init_statuses = [s for s in current.get("initContainerStatuses", [])
                                 if s.get("name") == "ratatoskr-init"]
                if init_statuses:
                    state = init_statuses[0].get("state", {})
                    waiting = state.get("waiting", {}).get("reason")
                    phase_detail = ("init-exited-nonzero" if state.get("terminated", {}).get("exitCode") not in (None, 0)
                                    else "init-waiting" if waiting in ("CrashLoopBackOff", "CreateContainerError",
                                                                        "CreateContainerConfigError", "ErrImagePull", "ImagePullBackOff")
                                    else "init-running" if state.get("running") is not None
                                    else "init-pending")
                else:
                    phase_detail = "init-not-started"
                if current.get("phase") == "Failed":
                    app_statuses = [s for s in current.get("containerStatuses", [])
                                    if s.get("name") == "client"]
                    init_exit = (init_statuses[0].get("state", {}).get("terminated", {}).get("exitCode")
                                 if init_statuses else None)
                    app_exit = (app_statuses[0].get("state", {}).get("terminated", {}).get("exitCode")
                                if app_statuses else None)
                    phase_detail = ("init-failed" if init_exit not in (None, 0) else
                                    "app-failed" if app_exit not in (None, 0) else "pod-failed-unknown")
                raise Blocked("Init selected Pod status not converged.")
            stage = "init-evidence"
            init_evidence.assert_init_pod(pod, namespace=apps, name="synthetic-probe-healthy", uid=uid,
                                          init_image="ghcr.io/skaldhall/ratatoskr-init:dev",
                                          init_image_id=ids["init"], app_image=ids["selected"],
                                          gateway_id=baseline["gatewayID"], endpoint=baseline["endpoint"],
                                          api_ip=api_ip)
            stage = "init-gateway-still-ready"
            gateway = api.get("egressgateway", "synthetic", namespace)
            if (gateway["metadata"].get("uid") != baseline["gatewayUID"] or
                    not evidence.condition(gateway, "Ready", "True", gateway["metadata"]["generation"]) or
                    gateway.get("status", {}).get("gatewayID") != baseline["gatewayID"] or
                    not any(e.get("upstreamHealthy") is True and e.get("podIP") == baseline["endpoint"]
                            for e in gateway.get("status", {}).get("endpoints", []))):
                raise Blocked("Init selected Gateway status/endpoint changed.")
            stage = "init-authenticated-session"
            server = api.get("pod", "synthetic-vpn", namespace)
            if server["metadata"].get("uid") != baseline["serverUID"]:
                raise Blocked("Init selected source server Pod UID changed.")
            sessions = api.server_session(namespace, baseline["serverUID"],
                                          expected_image_id=ids["server"]).get("sessions")
            if (not isinstance(sessions, list) or len(sessions) != 1 or
                    sessions[0].get("cn") != "synthetic-client" or
                    any(sessions[0].get(k) != before.get(k) for k in
                        ("cn", "virtualIPv4", "connected", "peer", "cipher")) or
                    any(type(sessions[0].get(k)) is not int or sessions[0][k] <= before[k]
                        for k in ("received", "sent"))):
                raise Blocked("Init selected authenticated server session not preserved/grown.")
            if api.get("pod", "synthetic-probe-healthy", apps)["metadata"].get("uid") != uid:
                raise Blocked("Init selected Pod UID changed during status reads.")
            return {"podUID": uid, "initImageID": ids["init"],
                    "appImageID": ids["selected"], "healthyExit": True}
        except (adapter.AdapterError, init_evidence.Blocked, evidence.EvidenceError,
                Blocked, KeyError, TypeError, ValueError, AttributeError):
            remaining = deadline - clock()
            if remaining > 0:
                sleep(min(2, remaining))
    label = stage + ("-" + phase_detail if stage == "init-selected-pod" else "")
    raise Blocked("Init-driver partial traffic timed out at " + label + ".")


def api_service_ip(api):
    return partial_gateway.api_service_ip(api)


def execute(ids, *, api_ip=None, lifecycle_factory=lifecycle.Lifecycle,
            adapter_factory=adapter.FixtureAPI, observer=partial_gateway.observe,
            selected_observer=selected):
    if not isinstance(ids, dict) or set(ids) != set(run.COMPONENTS) | {"init"} or not all(
            isinstance(v, str) and run.ID_PATTERN.fullmatch(v) for v in ids.values()):
        raise Blocked("Ten approved immutable image IDs required for init traffic.")
    if api_ip is None:
        raise Blocked("Preflight API Service IPv4 required before mutation.")
    try:
        ip = ipaddress.ip_address(api_ip)
        if ip.version != 4 or ip.is_unspecified or ip.is_multicast or ip.is_loopback:
            raise ValueError()
    except (TypeError, ValueError):
        raise Blocked("Invalid API ClusterIP preflight before mutation.") from None
    # Only a disposable privileged-labelled app namespace can admit NET_ADMIN
    # programming init. The helper application itself remains nonroot/cap-free.
    with lifecycle_factory(apps_psa="privileged") as owner:
        if owner.apps_psa != "privileged":
            raise Blocked("Init traffic may not create workloads in restricted app namespace.")
        owner.create_namespaces()
        owner.generate_pki()
        api = adapter_factory(owner)
        objects = prepare.manifests(owner.names[0], "ratatoskr-synthetic-openvpn:local",
                                    partial_gateway.private_contents(owner.private_dir), owner.token)
        chosen = [obj for obj in objects if (obj["kind"], obj["metadata"].get("name")) in partial_gateway.BASE]
        if (len(chosen) != len(partial_gateway.BASE) or
                [(obj["kind"], obj["metadata"]["name"]) for obj in chosen] != list(partial_gateway.BASE) or
                [obj["metadata"].get("namespace") for obj in chosen] !=
                [owner.names[1] if kind == "EgressPolicy" else owner.names[0]
                 for kind, _ in partial_gateway.BASE]):
            raise Blocked("Init base fixture order/namespace differs from safe plan.")
        created = {}
        for obj in chosen:
            identity = api.create(obj)
            key = (identity["kind"], identity["namespace"], identity["name"])
            if key in created or key != (obj["kind"], obj["metadata"]["namespace"],
                                        obj["metadata"]["name"]) or not lifecycle.UID.fullmatch(identity["uid"]):
                raise Blocked("Init fixture CREATE-return UID or identity invalid.")
            created[key] = identity["uid"]
        baseline = observer(api, owner, ids, created)
        if not isinstance(baseline, dict) or set(baseline) != {
                "gatewayUID", "serverUID", "gatewayPodUID", "gatewayID", "endpoint", "session"}:
            raise Blocked("Init Gateway baseline evidence incomplete.")
        result = selected_observer(api, owner, ids, created, baseline, str(ip))
        if (not isinstance(result, dict) or set(result) != {"podUID", "initImageID", "appImageID", "healthyExit"} or
                not isinstance(result["podUID"], str) or not lifecycle.UID.fullmatch(result["podUID"]) or
                result["initImageID"] != ids["init"] or result["appImageID"] != ids["selected"] or
                result["healthyExit"] is not True):
            raise Blocked("Init selected one-shot status evidence incomplete.")
    return False  # no PASS even if all checks and cleanup succeed
