#!/usr/bin/env python3
"""Pure init-driver, nonrestricted Pod evidence contract. Never awards PASS."""
import json

try:
    from . import evidence
except ImportError:
    import evidence


class Blocked(Exception):
    """Static diagnostics only; never print projected config or API response."""


def assert_init_pod(pod, *, namespace, name, uid, init_image, init_image_id, app_image,
                    gateway_id, endpoint, api_ip):
    """No Pod logs/exec: verify real webhook init, config and one-shot exit."""
    meta, spec, status = pod["metadata"], pod["spec"], pod.get("status", {})
    if (meta.get("uid") != uid or not uid or meta.get("namespace") != namespace or
            meta.get("name") != name or meta.get("deletionTimestamp") or
            name != "synthetic-probe-healthy" or
            spec.get("automountServiceAccountToken") is not False or
            spec.get("restartPolicy") != "Never" or spec.get("hostNetwork") is True or
            spec.get("activeDeadlineSeconds") != 120 or
            status.get("phase") != "Succeeded" or
            meta.get("labels", {}).get(evidence.PREFIX + "gateway") != "synthetic" or
            meta.get("labels", {}).get(evidence.PREFIX + "gateway-namespace") != namespace.removesuffix("-apps") or
            meta.get("annotations", {}).get(evidence.PREFIX + "datapath-ready") != "true"):
        raise Blocked("Init-driver selected Pod identity/readiness invalid.")
    init = spec.get("initContainers", [])
    if len(init) != 1:
        raise Blocked("Init-driver expected exactly one production programming init.")
    init = init[0]
    sc = init.get("securityContext", {})
    if (init.get("name") != "ratatoskr-init" or init.get("image") != init_image or
            init.get("args") != ["-config=/var/run/ratatoskr/client.json"] or
            init.get("command") not in (None, []) or sc.get("privileged") is not False or
            sc.get("capabilities") != {"add": ["NET_ADMIN"]} or
            init.get("volumeMounts") != [{"name": "ratatoskr-client-config",
                                           "mountPath": "/var/run/ratatoskr", "readOnly": True}]):
        raise Blocked("Init-driver injected NET_ADMIN init security/config mismatched.")
    env = {v.get("name"): v for v in init.get("env", [])}
    if (set(env) != {"POD_IP", "POD_UID", "POD_NAME", "DATAPATH"} or
            env["DATAPATH"] != {"name": "DATAPATH", "value": "iproute"} or
            any(env[k].get("valueFrom", {}).get("fieldRef", {}).get("fieldPath") != path
                for k, path in (("POD_IP", "status.podIP"), ("POD_UID", "metadata.uid"),
                                ("POD_NAME", "metadata.name")))):
        raise Blocked("Init-driver Downward-API identity fields mismatched.")
    volumes = spec.get("volumes", [])
    projection = [v for v in volumes if v.get("name") == "ratatoskr-client-config"]
    if (len(projection) != 1 or len(volumes) != 2 or
            projection[0].get("downwardAPI", {}).get("items", [{}])[0].get("path") != "client.json" or
            projection[0]["downwardAPI"]["items"][0].get("fieldRef", {}).get("fieldPath") !=
            "metadata.annotations['ratatoskr.skaldhall.io/client-config']" or
            not any(v.get("name") == "api-public-ca" and
                    v.get("configMap", {}).get("name") == "kube-root-ca.crt" for v in volumes) or
            any("secret" in v or "hostPath" in v or "projected" in v for v in volumes)):
        raise Blocked("Init-driver config volume or public CA mismatch.")
    raw = meta.get("annotations", {}).get(evidence.PREFIX + "client-config", "")
    if not isinstance(raw, str) or len(raw) > 4096:
        raise Blocked("Init-driver client config annotation absent or oversized.")
    try:
        cfg = json.loads(raw)
        if (cfg.get("gatewayID") != gateway_id or cfg.get("endpoint") != endpoint or
                cfg.get("podIP") != status.get("podIP") or
                cfg.get("identity", {}).get("uid") != uid or
                cfg.get("identity", {}).get("pod") != name or
                cfg.get("identity", {}).get("namespace") != namespace or
                cfg.get("identity", {}).get("policy") != "synthetic" or
                cfg.get("policy", {}).get("mode") != "include" or
                cfg.get("policy", {}).get("rules") != [{"cidrs": ["10.88.0.1/32"],
                    "ports": [{"protocol": "TCP", "port": 8080}]}]):
            raise ValueError()
    except (ValueError, TypeError, AttributeError):
        raise Blocked("Init-driver projected UID/policy/endpoint differs from Gateway.") from None
    initial = [v for v in status.get("initContainerStatuses", []) if v.get("name") == "ratatoskr-init"]
    app = [v for v in spec.get("containers", []) if v.get("name") == "client"]
    runtime = [v for v in status.get("containerStatuses", []) if v.get("name") == "client"]
    if (len(initial) != 1 or initial[0].get("imageID") != init_image_id or
            initial[0].get("state", {}).get("terminated", {}).get("exitCode") != 0 or
            len(app) != 1 or len(runtime) != 1 or app[0].get("image") != "ratatoskr-synthetic-client:local" or
            app[0].get("args") != ["healthy", api_ip] or
            app[0].get("securityContext", {}).get("capabilities") != {"drop": ["ALL"]} or
            app[0].get("securityContext", {}).get("runAsNonRoot") is not True or
            app[0].get("securityContext", {}).get("runAsUser") != 65532 or
            app[0].get("securityContext", {}).get("allowPrivilegeEscalation") is not False or
            app[0].get("imagePullPolicy") != "Never" or
            runtime[0].get("imageID") != app_image or
            runtime[0].get("state", {}).get("terminated", {}).get("exitCode") != 0):
        raise Blocked("Init-driver production init or unprivileged app did not succeed.")
    return {"uid": uid, "initDriverNonrestricted": True, "healthyExit": True}
