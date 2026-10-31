#!/usr/bin/env python3
"""Explicit final-gate-only restricted agent outage/recovery, never full M8 PASS."""
import ipaddress
import json
import time

try:
    from . import adapter, evidence, failclose_capture, lifecycle, partial_gateway, prepare, run
except ImportError:
    import adapter
    import evidence
    import failclose_capture
    import lifecycle
    import partial_gateway
    import prepare
    import run


class Blocked(lifecycle.LifecycleError):
    """Only fixed sanitized stage names; no untrusted API/exec output."""


class RestoreBlocked(Blocked):
    """Owned probe switch restoration unverified despite namespace cleanup."""


def deadline(owner, clock, seconds):
    end = min(owner.deadline, clock() + seconds)
    if owner.closed or owner.clock() >= owner.deadline or end <= clock():
        raise Blocked("Outage/recovery deadline expired.")
    return end


def poll(owner, stage, predicate, *, seconds=60, clock=time.monotonic, sleep=time.sleep):
    end = deadline(owner, clock, seconds)
    while clock() < end:
        try:
            answer = predicate()
            if answer is not None:
                return answer
        except (adapter.AdapterError, evidence.EvidenceError, KeyError, TypeError, ValueError, AttributeError):
            pass
        remaining = end - clock()
        if remaining > 0:
            sleep(min(2, remaining))
    raise Blocked("Outage/recovery did not converge at " + stage + ".")


def gateway_state(api, namespace, uid, pod_uid, *, healthy, endpoint):
    gw = api.get("egressgateway", "synthetic", namespace)
    if (gw["metadata"].get("uid") != uid or gw["metadata"].get("deletionTimestamp") or
            gw.get("status", {}).get("observedGeneration") != gw["metadata"].get("generation")):
        return None
    status = gw["status"]
    matched = [item for item in status.get("endpoints", []) if item.get("podIP") == endpoint]
    if healthy:
        if not (evidence.condition(gw, "Ready", "True", gw["metadata"]["generation"]) and
                status.get("readyReplicas") == 1 and len(matched) == 1 and
                matched[0].get("upstreamHealthy") is True):
            return None
    elif not (evidence.condition(gw, "Ready", "False", gw["metadata"]["generation"]) and
              # Go's `json:"readyReplicas,omitempty"` omits legitimate zero.
              # Reject bools/strings/negatives; never treat a missing Ready=False
              # condition or a healthy endpoint as withdrawal.
              type(status.get("readyReplicas", 0)) is int and status.get("readyReplicas", 0) == 0 and
              not any(item.get("upstreamHealthy") for item in status.get("endpoints", []))):
        return None
    pod = api.list_owned_gateway_pods(namespace, uid)
    if pod["metadata"].get("uid") != pod_uid:
        raise Blocked("Gateway Pod UID changed during outage/recovery.")
    return gw


def selected_ready(api, apps, name, uid, image_id, baseline, *, api_ip):
    pod = api.get("pod", name, apps)
    if pod["metadata"].get("uid") != uid:
        raise Blocked("Running selected Pod UID changed.")
    if not (pod.get("status", {}).get("phase") == "Running" and pod["spec"].get("containers", [{}])[0].get("command") == ["python3", "/usr/local/bin/check.py", "hold"]):
        return None
    # This long-lived Pod uses the selected checker image, not the tools image;
    # all other restricted admission/readiness checks still apply unchanged.
    evidence.assert_restricted_client(pod, apps, baseline["gatewayID"], baseline["endpoint"], image_id)
    values = {x.get("name"): x.get("value") for x in pod["spec"]["containers"][0].get("env", [])}
    if (pod["spec"]["containers"][0].get("image") != "ratatoskr-synthetic-client:local" or
            pod["spec"]["containers"][0].get("imagePullPolicy") != "Never" or
            values.get("API_IP") != api_ip):
        raise Blocked("Running selected Pod direct API destination changed.")
    raw = pod["metadata"].get("annotations", {}).get(evidence.PREFIX + "agent-config", "")
    if not isinstance(raw, str) or len(raw) > 4096:
        return None
    cfg = json.loads(raw)
    if (cfg.get("identity", {}).get("uid") != uid or cfg.get("gatewayID") != baseline["gatewayID"] or
            cfg.get("endpoint") != baseline["endpoint"] or cfg.get("policy", {}).get("rules") !=
            [{"cidrs": ["10.88.0.1/32"], "ports": [{"protocol": "TCP", "port": 8080}]}]):
        raise Blocked("Running selected Pod agent selection differs from authorized gateway.")
    return pod


def selected_wait_category(pod, uid, image_id, baseline, gateway=None):
    """Fixed diagnostic only. Never turns pending status into acceptance proof.

    This reads only public status/shape, not Pod logs, ConfigMap data or tokens.
    The caller already has the Pod from the exact UID-owned namespace.
    """
    meta, spec, status = pod.get("metadata", {}), pod.get("spec", {}), pod.get("status", {})
    if meta.get("uid") != uid or meta.get("deletionTimestamp"):
        return "uid-changed"
    if status.get("phase") == "Failed":
        return "pod-failed"
    init = [v for v in status.get("initContainerStatuses", []) if v.get("name") == "ratatoskr-init"]
    if len(init) > 1:
        return "admission-contract"
    if init:
        terminated = init[0].get("state", {}).get("terminated")
        if isinstance(terminated, dict) and terminated.get("exitCode") != 0:
            return "wait-init-failed"
    if not spec.get("nodeName") or not status.get("podIP"):
        return "unscheduled"
    if not init or init[0].get("state", {}).get("terminated", {}).get("exitCode") != 0:
        # The agent refuses to open a selected path until the Gateway confirms
        # that this PodIP is present in its applied, UID-bound config.
        if gateway is not None and (gateway.get("metadata", {}).get("uid") != baseline["gatewayUID"] or
                                    gateway.get("metadata", {}).get("deletionTimestamp")):
            return "gateway-identity-changed"
        if gateway is None:
            return "wait-init-pending"
        endpoints = gateway.get("status", {}).get("endpoints", [])
        matched = [e for e in endpoints if e.get("podIP") == baseline["endpoint"]]
        if len(matched) != 1 or (matched[0].get("podUID") != baseline["gatewayPodUID"] or
                                 not isinstance(matched[0].get("appliedClientConfigHash"), str) or
                                 len(matched[0]["appliedClientConfigHash"]) != 64):
            return "gateway-ack-pending"
        return "wait-init-pending"
    containers = [v for v in status.get("containerStatuses", []) if v.get("name") == "client"]
    if len(containers) != 1 or containers[0].get("imageID") != image_id:
        return "app-image-pending"
    if status.get("phase") != "Running" or not containers[0].get("ready"):
        return "app-not-ready"
    if meta.get("annotations", {}).get(evidence.PREFIX + "datapath-ready") != "true":
        return "agent-readiness-pending"
    if not evidence.condition(pod, "Ready", "True"):
        return "pod-ready-pending"
    return "contract-or-config-mismatch"


def observe_running_selected(api, apps, uid, image_id, baseline, api_ip, diagnosis):
    """Keep a fixed last-seen category for a bounded timeout only."""
    diagnosis["category"] = "api-unavailable"
    pod = api.get("pod", "synthetic-client", apps)
    gw = None
    if (pod.get("status", {}).get("phase") != "Running" or
            not any(v.get("state", {}).get("terminated", {}).get("exitCode") == 0
                    for v in pod.get("status", {}).get("initContainerStatuses", [])
                    if v.get("name") == "ratatoskr-init")):
        try:
            gw = api.get("egressgateway", "synthetic", apps[:-5])
        except adapter.AdapterError:
            pass  # API unavailability cannot be evidence of a missing ack.
    diagnosis["category"] = selected_wait_category(pod, uid, image_id, baseline, gw)
    # The strict acceptance predicate remains the sole success condition.
    return selected_ready(api, apps, "synthetic-client", uid, image_id, baseline, api_ip=api_ip)


def marker_ready(api, namespace, uid, image_id):
    """Only the exact selected Pod netns's UP dummy marker qualifies."""
    raw = api.exec(namespace, "synthetic-client", uid, "client", "agent-marker",
                   expected_image_id=image_id)
    if not isinstance(raw, str) or len(raw) > 4096:
        raise Blocked("Selected agent marker output invalid.")
    value = json.loads(raw)
    if not isinstance(value, list) or len(value) != 1:
        raise Blocked("Selected agent marker missing.")
    evidence.assert_agent_marker(value[0])
    return True


def selected_fail_closed(api, namespace, uid, image_id, api_ip):
    """Only observed agent withdrawal AND actual unreachable+direct API qualify.

    The gateway controller can withdraw status before the node agent processes
    its watch. A pre-withdrawal tunnel timeout is not fail-close evidence.
    Pending readiness alone is likewise not proof of unreachable routing.
    """
    pod = api.get("pod", "synthetic-client", namespace)
    meta = pod.get("metadata", {})
    if meta.get("uid") != uid or meta.get("deletionTimestamp"):
        raise Blocked("Running selected Pod identity changed during outage.")
    if meta.get("annotations", {}).get(evidence.PREFIX + "datapath-ready") != "pending":
        return None
    if pod.get("status", {}).get("phase") != "Running":
        return None
    # probe_running only returns True for exit 0 of fixed outage-check, which
    # requires ENETUNREACH/EHOSTUNREACH for the selected marker destination
    # AND independently verified direct DNS, TLS and denied Kubernetes API.
    if api.probe_running("synthetic-client", uid, image_id, "outage", api_ip) is not True:
        return None
    return pod


def witness_ready(api, namespace, uid, image_id, server_uid, server_image_id):
    pod = api.get("pod", "synthetic-witness", namespace)
    if pod["metadata"].get("uid") != uid:
        raise Blocked("Independent witness Pod UID changed.")
    statuses = pod.get("status", {}).get("containerStatuses", [])
    if (pod.get("status", {}).get("phase") != "Running" or len(statuses) != 1 or
            statuses[0].get("name") != "witness" or statuses[0].get("imageID") != image_id or
            statuses[0].get("ready") is not True):
        return None
    if (pod.get("spec", {}).get("containers", [{}])[0].get("args") != ["--hold"] or
            pod["metadata"].get("labels", {}).get(evidence.PREFIX + "gateway") or
            pod["spec"].get("automountServiceAccountToken") is not False):
        raise Blocked("Independent witness fixture changed.")
    sessions = api.server_session(namespace, server_uid, expected_image_id=server_image_id)
    values = sessions.get("sessions", [])
    if len(values) != 2 or [s.get("cn") for s in values] != ["synthetic-client", "synthetic-witness"]:
        return None
    if values[0].get("virtualIPv4") == values[1].get("virtualIPv4"):
        raise Blocked("Independent witness tunnel identity duplicated.")
    return pod


def execute(ids, *, api_ip, lifecycle_factory=lifecycle.Lifecycle,
            adapter_factory=adapter.FixtureAPI, observer=partial_gateway.observe,
            healthy=partial_gateway.healthy_selected, clock=time.monotonic, sleep=time.sleep):
    if (not isinstance(ids, dict) or set(ids) != set(run.COMPONENTS) or
            not all(isinstance(value, str) and run.ID_PATTERN.fullmatch(value) for value in ids.values())):
        raise Blocked("Nine immutable expected runtime image IDs required.")
    try:
        address = ipaddress.ip_address(api_ip)
        if address.version != 4 or address.is_unspecified or address.is_loopback or address.is_multicast:
            raise ValueError()
    except (ValueError, TypeError):
        raise Blocked("Preflight API IPv4 invalid.") from None
    with lifecycle_factory(duration=900) as owner:
        stage = "namespace-create"
        try:
            owner.create_namespaces()
            stage = "private-pki"
            owner.generate_pki()
            stage = "fixture-adapter"
            api = adapter_factory(owner)
            ns, apps = owner.names
            stage = "fixture-manifests"
            objects = prepare.manifests(ns, "ratatoskr-synthetic-openvpn:local",
                                        partial_gateway.private_contents(owner.private_dir), owner.token)
            base = [x for x in objects if (x["kind"], x["metadata"].get("name")) in partial_gateway.BASE]
            if [(x["kind"], x["metadata"]["name"]) for x in base] != list(partial_gateway.BASE):
                raise Blocked("Outage fixture allowlist differs.")
            created = {}
            stage = "fixture-create"
            for item in base:
                identity = api.create(item)
                created[(identity["kind"], identity["namespace"], identity["name"])] = identity["uid"]
            stage = "baseline-owner-health"
            baseline = observer(api, owner, ids, created)
            if (not isinstance(baseline, dict) or set(baseline) !=
                    {"gatewayUID", "serverUID", "gatewayPodUID", "gatewayID", "endpoint", "session"} or
                    baseline["gatewayUID"] != created[("EgressGateway", ns, "synthetic")] or
                    baseline["serverUID"] != created[("Pod", ns, "synthetic-vpn")]):
                raise Blocked("Healthy controller-owned baseline incomplete.")
            stage = "healthy-one-shot"
            first = healthy(api, owner, ids, created, baseline, str(address))
            if (not isinstance(first, dict) or first.get("healthyExit") is not True or
                    first.get("directAPITLSAndDNS") is not True or
                    first.get("serverSessionBytesAdvanced") is not True or
                    not lifecycle.UID.fullmatch(first.get("podUID", ""))):
                raise Blocked("Healthy one-shot evidence missing before outage.")
            stage = "running-selected-create"
            running = api.create(prepare.running_probe_pod(apps, ns, str(address)))
            uid = running["uid"]
            if (running["kind"], running["namespace"], running["name"]) != ("Pod", apps, "synthetic-client"):
                raise Blocked("Running selected Pod CREATE identity mismatch.")
            stage = "running-selected-ready"
            diagnosis = {"category": "api-unavailable"}
            try:
                poll(owner, "running-selected", lambda: observe_running_selected(api, apps, uid,
                     ids["selected"], baseline, str(address), diagnosis),
                     seconds=90, clock=clock, sleep=sleep)
            except Blocked as failure:
                if str(failure) != "Outage/recovery did not converge at running-selected.":
                    raise
                # category comes only from our private, fixed allowlist above;
                # never surface Kubernetes fields or underlying error strings.
                raise Blocked("Running selected did not converge at " + diagnosis["category"] + ".") from None
            stage = "running-selected-marker"
            marker_ready(api, apps, uid, ids["selected"])
            stage = "running-selected-healthy"
            api.probe_running("synthetic-client", uid, ids["selected"], "healthy", str(address))
            witness_items = [item for item in objects if item["kind"] == "Pod" and
                             item["metadata"].get("name") == "synthetic-witness" and
                             item["metadata"].get("namespace") == ns]
            if len(witness_items) != 1:
                raise Blocked("Independent witness Pod fixture missing or ambiguous.")
            witness = witness_items[0]
            stage = "independent-witness-create"
            witness_id = api.create(witness)
            if (witness_id["kind"], witness_id["namespace"], witness_id["name"]) != ("Pod", ns, "synthetic-witness"):
                raise Blocked("Independent witness CREATE identity mismatch.")
            # The witness is intentionally selected independently and connects with
            # its own client cert; it cannot inherit gateway steering.
            stage = "independent-witness-ready"
            poll(owner, "independent-witness", lambda: witness_ready(api, ns, witness_id["uid"],
                 ids["witness"], baseline["serverUID"], ids["server"]), seconds=85, clock=clock, sleep=sleep)
            stage = "probe-switch-identity"
            switch_uid, _, state = api.exit_health_snapshot()
            if switch_uid != created[("ConfigMap", ns, "synthetic-exit-health")] or state != "true":
                raise Blocked("Probe-only ConfigMap CREATE UID changed.")
            endpoint = baseline["endpoint"]
            stage = "probe-switch-disable"
            with api.exit_health_outage():
                # API CAS does not prove projected ConfigMap volume changed. The
                # independent authenticated witness must see an exact tunnel-bound
                # HTTP 503 (empty body) from /exit before checking controller state.
                stage = "exit-projection"
                poll(owner, "exit-projection", lambda: (
                     True if api.probe_running("synthetic-witness", witness_id["uid"], ids["witness"],
                                               "exit-off", str(address)) else None),
                     seconds=85, clock=clock, sleep=sleep)
                stage = "gateway-withdrawal"
                poll(owner, "gateway-withdrawal", lambda: gateway_state(api, ns, baseline["gatewayUID"],
                     baseline["gatewayPodUID"], healthy=False, endpoint=endpoint), seconds=85, clock=clock, sleep=sleep)
                stage = "withdrawn-witness-marker"
                api.probe_running("synthetic-witness", witness_id["uid"], ids["witness"], "outage", str(address))
                # The running selected Pod had its wait-init exit successfully BEFORE
                # withdrawal; a newly created outage Pod could remain blocked at init.
                stage = "withdrawn-selected-fail-close"
                # An immediate EHOST/ENETUNREACH is independently sufficient;
                # a TCP timeout is *never* promoted without UID-bound closed
                # routes, a live eth0 capture with positive API SYN, and zero
                # matching selected SYN through that same source netns.
                def fail_close():
                    try:
                        return selected_fail_closed(api, apps, uid, ids["selected"], str(address))
                    except adapter.AdapterError:
                        pod = api.get("pod", "synthetic-client", apps)
                        if (pod["metadata"].get("uid") != uid or
                                pod["metadata"].get("annotations", {}).get(evidence.PREFIX + "datapath-ready") != "pending" or
                                pod.get("status", {}).get("phase") != "Running"):
                            return None
                        def fixed_probe():
                            if api.probe_running("synthetic-client", uid, ids["selected"],
                                                 "outage-capture", str(address)) is not True:
                                raise failclose_capture.Blocked("Selected bounded timeout probe did not complete.")
                        if failclose_capture.prove(api, apps, uid, ids["selected"], baseline["gatewayID"],
                                                    str(address), trigger=fixed_probe):
                            return pod
                    return None
                poll(owner, "withdrawn-selected-fail-close", fail_close, seconds=85,
                     clock=clock, sleep=sleep)
                stage = "outage-still-withdrawn"
                poll(owner, "outage-still-withdrawn", lambda: gateway_state(api, ns, baseline["gatewayUID"],
                     baseline["gatewayPodUID"], healthy=False, endpoint=endpoint), seconds=8, clock=clock, sleep=sleep)
                stage = "withdrawn-witness-marker-recheck"
                api.probe_running("synthetic-witness", witness_id["uid"], ids["witness"], "outage", str(address))
            stage = "gateway-recovery"
            poll(owner, "gateway-recovery", lambda: gateway_state(api, ns, baseline["gatewayUID"],
                 baseline["gatewayPodUID"], healthy=True, endpoint=endpoint), seconds=85, clock=clock, sleep=sleep)
            stage = "agent-recovery"
            poll(owner, "agent-recovery", lambda: selected_ready(api, apps, "synthetic-client", uid,
                 ids["selected"], baseline, api_ip=str(address)), seconds=85, clock=clock, sleep=sleep)
            stage = "recovered-selected-healthy"
            api.probe_running("synthetic-client", uid, ids["selected"], "healthy", str(address))
            stage = "recovered-selected-identity"
            if api.get("pod", "synthetic-client", apps)["metadata"].get("uid") != uid:
                raise Blocked("Recovered selected Pod UID changed.")
        except failclose_capture.Blocked:
            raise Blocked("Synthetic outage body blocked at " + stage + "-source-capture.") from None
        except adapter.RestorationError:
            # The context manager's finally failed: never imply a routine
            # selected-probe failure when the probe switch is unconfirmed.
            raise RestoreBlocked("Synthetic outage probe-switch restoration unverified.") from None
        except (adapter.AdapterError, evidence.EvidenceError, KeyError, IndexError, TypeError,
                ValueError, AttributeError, StopIteration):
            raise Blocked("Synthetic outage body blocked at " + stage + ".") from None
    return False  # Cleanup verified by Lifecycle; full M8 stays INCOMPLETE.
