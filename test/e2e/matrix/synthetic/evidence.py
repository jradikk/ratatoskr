#!/usr/bin/env python3
"""Pure assertions for a future authorized VPN traffic runner.

No kubectl, credentials, sockets, subprocess or PASS/report entrypoint. Evidence
must be collected inside a bounded Lifecycle and disposed without logging it.
"""
import ipaddress

PREFIX = "ratatoskr.skaldhall.io/"
PROBE = "http://10.88.0.1:8080/exit"
MARKER = "ratatoskr-synthetic-vpn-v1\n"
EXIT = "10.88.0.1\n"


class EvidenceError(Exception):
    """Safe constant message only; never format untrusted object data."""


def need(condition, text):
    if not condition:
        raise EvidenceError(text)


def owner(obj, kind, uid):
    return any(ref.get("kind") == kind and ref.get("uid") == uid and
               ref.get("controller") is True for ref in obj.get("metadata", {}).get("ownerReferences", []))


def condition(obj, name, status, generation=None):
    conditions = [c for c in obj.get("status", {}).get("conditions", []) if c.get("type") == name]
    return (len(conditions) == 1 and conditions[0].get("status") == status and
            (generation is None or conditions[0].get("observedGeneration") == generation))


def runtime_image(pod, container, image_id):
    matches = [s for s in pod.get("status", {}).get("containerStatuses", []) if s.get("name") == container]
    spec = [c for c in pod.get("spec", {}).get("containers", []) if c.get("name") == container]
    need(len(matches) == 1 and len(spec) == 1 and spec[0].get("imagePullPolicy") == "Never" and
         matches[0].get("ready") is True and matches[0].get("imageID") == image_id,
         "Runtime image ID, readiness or local pull policy mismatch.")


def ipv4(value):
    try:
        address = ipaddress.ip_address(value)
        if address.version == 4 and not (address.is_unspecified or address.is_multicast or address.is_loopback):
            return address
    except ValueError:
        pass
    raise EvidenceError("Untrusted endpoint is not a usable IPv4 address.") from None


def assert_source_service(service, server, server_image):
    need(service["metadata"].get("namespace") == server["metadata"].get("namespace") and
         service["metadata"].get("name") == "synthetic-vpn" and
         server["metadata"].get("name") == "synthetic-vpn", "Synthetic source identity mismatch.")
    ports = service["spec"].get("ports", [])
    need(len(ports) == 1 and ports[0].get("protocol") == "UDP" and
         ports[0].get("port") == 1194 and ports[0].get("targetPort") == 1194 and
         all(p.get("port") != 8080 for p in ports), "Synthetic service exposes an unexpected port.")
    selector = service["spec"].get("selector", {})
    need(selector == {"app": "synthetic-vpn"} and
         server["metadata"].get("labels", {}).get("app") == "synthetic-vpn" and
         condition(server, "Ready", "True"), "Synthetic server Service does not select Ready Pod.")
    runtime_image(server, "server", server_image)
    return ipv4(service["spec"]["clusterIP"])


def assert_source_endpoint(slice_obj, service, server):
    """The UDP Service must resolve to exactly the trusted server Pod UID/IP."""
    refs = slice_obj.get("endpoints", [])
    need(slice_obj.get("metadata", {}).get("namespace") == service["metadata"].get("namespace") and
         slice_obj.get("metadata", {}).get("labels", {}).get("kubernetes.io/service-name") == "synthetic-vpn" and
         slice_obj.get("addressType") == "IPv4" and len(refs) == 1 and
         refs[0].get("conditions", {}).get("ready") is True and
         refs[0].get("targetRef", {}).get("kind") == "Pod" and
         refs[0]["targetRef"].get("name") == "synthetic-vpn" and
         refs[0]["targetRef"].get("uid") == server["metadata"].get("uid") and
         refs[0].get("addresses") == [server.get("status", {}).get("podIP")],
         "VPN source Service endpoint does not reference the Ready server Pod.")
    ports = slice_obj.get("ports", [])
    need(len(ports) == 1 and ports[0].get("protocol") == "UDP" and ports[0].get("port") == 1194,
         "VPN source endpoint exposes an unexpected port.")
    ipv4(refs[0]["addresses"][0])


def assert_agent_marker(link):
    """Observed in the workload network namespace, never the host/agent Pod."""
    need(link.get("ifname") == "rtk-ready" and
         link.get("linkinfo", {}).get("info_kind") == "dummy" and
         "UP" in link.get("flags", []), "Agent in-netns readiness marker is absent or not UP.")


def assert_gateway_chain(gateway, deployment, replica_set, pod, children, ids):
    """Strict one-replica controller-owned graph + observed measured status."""
    meta, status = gateway["metadata"], gateway.get("status", {})
    uid, generation = meta["uid"], meta["generation"]
    need(meta.get("name") == "synthetic" and uid and not meta.get("deletionTimestamp") and
         status.get("observedGeneration") == generation and
         isinstance(status.get("gatewayID"), int) and status["gatewayID"] > 0 and
         status.get("readyReplicas") == 1 and condition(gateway, "Ready", "True", generation),
         "Gateway UID, observed generation or Ready status invalid.")
    mtu = status.get("mtu", {})
    need(isinstance(mtu.get("geneveMTU"), int) and mtu["geneveMTU"] >= 576 and
         isinstance(mtu.get("effectiveMTU"), int) and 576 <= mtu["effectiveMTU"] <= mtu["geneveMTU"] and
         condition(gateway, "MTUUnknown", "False", generation), "Gateway measured MTU unavailable.")
    for resource in (deployment, *children):
        need(owner(resource, "EgressGateway", uid) and
             resource["metadata"].get("namespace") == meta.get("namespace") and
             resource["metadata"].get("name") == "synthetic", "Gateway child owner/name/namespace mismatch.")
    need(len(children) == 3, "Expected owned Service, ConfigMap and NetworkPolicy.")
    need({c.get("kind") for c in children} == {"Service", "ConfigMap", "NetworkPolicy"},
         "Owned Gateway resource types differ from contract.")
    dep_meta = deployment["metadata"]
    need(owner(replica_set, "Deployment", dep_meta["uid"]) and
         replica_set["metadata"].get("namespace") == meta.get("namespace") and
         owner(pod, "ReplicaSet", replica_set["metadata"]["uid"]) and
         pod["metadata"].get("namespace") == meta.get("namespace") and
         not pod["metadata"].get("deletionTimestamp") and condition(pod, "Ready", "True"),
         "Gateway Deployment→ReplicaSet→Pod owner or readiness mismatch.")
    need(deployment.get("spec", {}).get("replicas") == 1 and
         deployment.get("status", {}).get("readyReplicas") == 1 and
         deployment.get("status", {}).get("updatedReplicas") == 1 and
         deployment.get("status", {}).get("observedGeneration", 0) >= dep_meta["generation"],
         "Gateway Deployment rollout incomplete.")
    endpoints = status.get("endpoints", [])
    need(len(endpoints) == 1 and endpoints[0].get("podName") == pod["metadata"]["name"] and
         endpoints[0].get("podIP") == pod.get("status", {}).get("podIP") and
         endpoints[0].get("upstreamHealthy") is True and
         endpoints[0].get("upstreamExitIP") == "10.88.0.1", "Gateway healthy endpoint identity mismatch.")
    ipv4(endpoints[0]["podIP"])
    upstream = [c for c in pod["spec"]["containers"] if c.get("name") == "upstream"]
    need(len(upstream) == 1 and upstream[0].get("args") == ["--probe-url", PROBE] and
         upstream[0].get("imagePullPolicy") == "Never", "Rendered plugin probe URL or pull policy differs.")
    runtime_image(pod, "gateway", ids["gateway"])
    runtime_image(pod, "upstream", ids["plugin"])
    return status["gatewayID"], endpoints[0]["podIP"]


def assert_restricted_client(pod, namespace, gateway_id, endpoint, tools_id):
    meta, spec, status = pod["metadata"], pod["spec"], pod.get("status", {})
    need(meta.get("namespace") == namespace and meta.get("name") == "synthetic-client" and
         not meta.get("deletionTimestamp") and spec.get("automountServiceAccountToken") is False and
         spec.get("hostNetwork") is not True and condition(pod, "Ready", "True") and
         meta.get("annotations", {}).get(PREFIX + "datapath-ready") == "true", "Client readiness or identity mismatch.")
    init = spec.get("initContainers", [])
    need(len(init) == 1 and init[0].get("name") == "ratatoskr-init" and
         init[0].get("args") == ["-wait-agent"] and
         init[0].get("securityContext", {}).get("capabilities") == {"drop": ["ALL"]} and
         init[0].get("securityContext", {}).get("runAsNonRoot") is True and
         init[0].get("securityContext", {}).get("allowPrivilegeEscalation") is False,
         "Production wait-init not restricted or absent.")
    public_ca = {"name": "api-public-ca", "configMap": {"name": "kube-root-ca.crt",
                 "items": [{"key": "ca.crt", "path": "ca.crt"}], "defaultMode": 292}}
    public_mount = {"name": "api-public-ca", "mountPath": "/var/run/ratatoskr/api-ca", "readOnly": True}
    volumes = spec.get("volumes", [])
    need(len(spec.get("containers", [])) == 1 and len(volumes) == 2 and
         public_ca in volumes and
         len([v for v in volumes if v.get("name") == "ratatoskr-agent-api-shadow" and
              set(v) == {"name", "emptyDir"} and isinstance(v["emptyDir"], dict) and
              set(v["emptyDir"]) <= {"medium", "sizeLimit"} and
              v["emptyDir"].get("medium", "") == ""]) == 1 and
         not any("secret" in v or "hostPath" in v or "projected" in v for v in volumes) and
         all(c.get("securityContext", {}).get("capabilities") == {"drop": ["ALL"]} and
             c.get("securityContext", {}).get("allowPrivilegeEscalation") is False and
             c.get("securityContext", {}).get("runAsNonRoot") is True and
             not c.get("envFrom") and c.get("volumeMounts") == [public_mount] for c in spec["containers"]),
         "Workload credentials, host access or capabilities present.")
    need(any(s.get("name") == "ratatoskr-init" and s.get("state", {}).get("terminated", {}).get("exitCode") == 0
             for s in status.get("initContainerStatuses", [])), "Agent wait-init has not completed successfully.")
    runtime_image(pod, "client", tools_id)
    need(gateway_id > 0 and ipv4(endpoint), "Client selected Gateway invalid.")
    return status.get("podIP")


def assert_selected_probe(pod, *, namespace, phase, expected_uid, expected_image_id,
                          expected_api_ip, outage_started=None, outage_ended=None):
    """UID-pinned Pod-status-only evidence; no kubectl exec/logs.

    Outage Pod exit 42 means only verified network-unreachable with direct API
    before and after; fail-close still additionally requires withdrawal and a
    concurrent independent reachable-target witness in the caller.
    """
    from datetime import datetime, timedelta, timezone
    name = "synthetic-probe-" + phase
    if phase not in ("healthy", "outage", "recovery"):
        raise EvidenceError("Selected probe phase not allowlisted.")
    meta, spec, status = pod.get("metadata", {}), pod.get("spec", {}), pod.get("status", {})
    if (meta.get("name") != name or meta.get("namespace") != namespace or
            meta.get("uid") != expected_uid or not expected_uid or
            meta.get("deletionTimestamp") or
            meta.get("labels", {}).get("app") != "synthetic-client" or
            not namespace.endswith("-apps") or
            meta.get("labels", {}).get(PREFIX + "gateway") != "synthetic" or
            meta.get("labels", {}).get(PREFIX + "gateway-namespace") != namespace[:-5] or
            status.get("phase") != ("Failed" if phase == "outage" else "Succeeded") or
            spec.get("restartPolicy") != "Never" or spec.get("automountServiceAccountToken") is not False or
            spec.get("activeDeadlineSeconds") != 120 or spec.get("hostNetwork") is True or
            len(spec.get("initContainers", [])) != 1 or len(spec.get("containers", [])) != 1):
        raise EvidenceError("Selected probe Pod UID, phase or restricted admission invalid.")
    wait = spec["initContainers"][0]
    sc = wait.get("securityContext", {})
    if (wait.get("name") != "ratatoskr-init" or wait.get("args") != ["-wait-agent"] or
            sc.get("capabilities") != {"drop": ["ALL"]} or sc.get("runAsNonRoot") is not True or
            sc.get("runAsUser") != 65532 or sc.get("allowPrivilegeEscalation") is not False or
            len(wait.get("volumeMounts", [])) != 1 or
            wait["volumeMounts"][0].get("name") != "ratatoskr-agent-api-shadow"):
        raise EvidenceError("Selected probe wait-init did not match agent contract.")
    values = [x for x in status.get("initContainerStatuses", []) if x.get("name") == "ratatoskr-init"]
    if len(values) != 1 or values[0].get("state", {}).get("terminated", {}).get("exitCode") != 0:
        raise EvidenceError("Selected probe wait-init did not complete.")
    app = spec["containers"][0]
    if (app.get("name") != "client" or app.get("image") != "ratatoskr-synthetic-client:local" or
            app.get("imagePullPolicy") != "Never" or
            app.get("args") != ["outage" if phase == "outage" else "healthy", expected_api_ip] or
            app.get("securityContext", {}).get("capabilities") != {"drop": ["ALL"]} or
            app.get("securityContext", {}).get("runAsNonRoot") is not True or
            app.get("securityContext", {}).get("allowPrivilegeEscalation") is not False or
            app.get("volumeMounts") != [{"name": "api-public-ca", "mountPath": "/var/run/ratatoskr/api-ca",
                                         "readOnly": True}]):
        raise EvidenceError("Selected probe app image/args/security differs from approved fixture.")
    public_ca = {"name": "api-public-ca", "configMap": {"name": "kube-root-ca.crt",
                 "items": [{"key": "ca.crt", "path": "ca.crt"}], "defaultMode": 292}}
    shadow = {"name": "ratatoskr-agent-api-shadow", "emptyDir": {}}
    if (len(spec.get("volumes", [])) != 2 or public_ca not in spec["volumes"] or
            shadow not in spec["volumes"] or
            app.get("env") not in (
                [{"name": "POD_IP", "valueFrom": {"fieldRef": {"fieldPath": "status.podIP"}}}],
                [{"name": "POD_IP", "valueFrom": {"fieldRef": {"apiVersion": "v1", "fieldPath": "status.podIP"}}}])):
        raise EvidenceError("Selected probe API CA/agent shadow/env differs from fixture.")
    statuses = [x for x in status.get("containerStatuses", []) if x.get("name") == "client"]
    if len(statuses) != 1 or statuses[0].get("imageID") != expected_image_id:
        raise EvidenceError("Selected probe runtime image ID mismatch.")
    terminated = statuses[0].get("state", {}).get("terminated", {})
    expected_exit = 42 if phase == "outage" else 0
    try:
        began = datetime.fromisoformat(terminated["startedAt"].replace("Z", "+00:00"))
        ended = datetime.fromisoformat(terminated["finishedAt"].replace("Z", "+00:00"))
    except (KeyError, AttributeError, ValueError):
        raise EvidenceError("Selected probe termination timestamps malformed.") from None
    if (terminated.get("exitCode") != expected_exit or ended < began or
            ended - began > timedelta(seconds=120) or ended > datetime.now(timezone.utc) + timedelta(seconds=2)):
        raise EvidenceError("Selected probe did not terminate with expected outcome.")
    if (meta.get("annotations", {}).get(PREFIX + "datapath-ready") != "true" or
            not isinstance(status.get("podIP"), str)):
        raise EvidenceError("Selected probe lacks agent readiness annotation or PodIP.")
    if phase == "outage":
        if (not isinstance(outage_started, datetime) or not isinstance(outage_ended, datetime) or
                outage_started.tzinfo is None or outage_ended.tzinfo is None or
                began < outage_started or ended > outage_ended):
            raise EvidenceError("Selected fail-close was not bounded by verified outage.")
    return {"phase": phase, "verifiedExit": expected_exit, "uid": expected_uid}


def assert_selected_tunnel(before, after, marker, link, gateway_id, endpoint):
    """Only post-traffic egress counter delta AND exact GENEVE identity suffice."""
    need(marker == MARKER and link.get("ifname") == "rtk0" and link.get("linkinfo", {}).get("info_kind") == "geneve" and
         link.get("linkinfo", {}).get("info_data", {}).get("id") == gateway_id and
         link["linkinfo"]["info_data"].get("remote") == endpoint and
         link.get("operstate") == "UP", "Selected marker or tunnel identity mismatch.")
    need(isinstance(before, int) and isinstance(after, int) and after > before >= 0,
         "Marker request did not increase GENEVE egress bytes.")


def assert_direct_paths(exclusions, dns_ip, api_ip, dns_name, api_code, route, client_ip):
    try:
        ranges = [ipaddress.ip_network(x["cidr"], strict=True) for x in exclusions
                  if x.get("source") in {"serviceCIDR", "dns", "apiserver"}]
        dns, api = ipv4(dns_ip), ipv4(api_ip)
        need(any(dns in c for c in ranges) and any(api in c for c in ranges),
             "DNS or API ClusterIP is not a verified Gateway exclusion.")
    except (KeyError, ValueError, TypeError):
        raise EvidenceError("Gateway exclusion evidence malformed.") from None
    need(dns_name == "kubernetes.default.svc.cluster.local" and api_code == 403,
         "Verified TLS anonymous API denial or direct DNS path failed.")
    need(isinstance(route, dict) and route.get("dst") == str(api) and
         route.get("dev") == "eth0" and route.get("prefsrc") == client_ip and
         route.get("type") not in ("unreachable", "prohibit", "blackhole") and
         route.get("dev") != "rtk0", "API HTTPS flow is not routed directly via client CNI.")


def assert_fail_close(down, marker_failed, direct_ok):
    need(down.get("status", {}).get("readyReplicas") == 0 and
         condition(down, "Ready", "False", down["metadata"]["generation"]) and
         not any(e.get("upstreamHealthy") for e in down.get("status", {}).get("endpoints", [])) and
         marker_failed is True and direct_ok is True, "Selected path did not fail closed with direct cluster paths intact.")


def assert_recovery(gateway, former_uid, marker, before, after):
    need(gateway["metadata"].get("uid") == former_uid and
         condition(gateway, "Ready", "True", gateway["metadata"]["generation"]) and
         gateway.get("status", {}).get("readyReplicas") == 1 and
         marker == MARKER and after > before >= 0, "Server/agent routing did not recover after interruption.")
