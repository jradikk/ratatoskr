#!/usr/bin/env python3
"""Bounded final-gate API/admission checks against an EXISTING flannel release."""
import copy
import json
import os
from pathlib import Path
import re
import subprocess
import time
import uuid

PREFIX = "ratatoskr.skaldhall.io/"
CHECKS = ("api-release-preflight", "api-crd-server-dry-run", "api-authorized-mutation-validation",
          "api-unauthorized-denial", "api-security-fields", "api-ebpf-wireguard-rejection", "api-cleanup")


class Blocked(Exception):
    pass


class API:
    def __init__(self, context="k3d-ratatoskr-flannel", budget=240):
        if context != "k3d-ratatoskr-flannel":
            raise Blocked("Only existing flannel context is supported.")
        self.context = context
        self.deadline = time.monotonic() + budget

    def call(self, *args, allow_error=False, cleanup=False):
        remaining = 35 if cleanup else min(20, self.deadline - time.monotonic())
        if remaining <= 0:
            raise Blocked("API scenario total deadline exceeded.")
        try:
            environment = {key: value for key, value in os.environ.items() if key not in
                           {"IPINFO_TOKEN", "RATATOSKR_E2E_OVPN", "RATATOSKR_E2E_OVPN_AUTH"}}
            result = subprocess.run(["kubectl", "--context", self.context, "--request-timeout=15s", *args],
                                    capture_output=True, text=True, timeout=remaining, check=False, env=environment)
        except (OSError, subprocess.TimeoutExpired):
            raise Blocked("kubectl unavailable or API operation timed out.") from None
        if result.returncode and not allow_error:
            raise Blocked("API operation failed; no raw API error or object retained.")
        return result

    def get(self, *args):
        try:
            return json.loads(self.call("get", *args, "-o", "json").stdout)
        except ValueError:
            raise Blocked("API response was not valid JSON.") from None


def pod(namespace, name, gateway=None, gateway_namespace=None):
    labels = {} if gateway is None else {PREFIX + "gateway": gateway,
                                        PREFIX + "gateway-namespace": gateway_namespace}
    return {"apiVersion": "v1", "kind": "Pod", "metadata": {"name": name, "namespace": namespace, "labels": labels},
            "spec": {"automountServiceAccountToken": False, "restartPolicy": "Never",
                     "containers": [{"name": "app", "image": "ratatoskr-tools:m1-local", "imagePullPolicy": "Never",
                                     "command": ["sleep", "infinity"], "securityContext": {
                                         "runAsNonRoot": True, "runAsUser": 65532, "allowPrivilegeEscalation": False,
                                         "capabilities": {"drop": ["ALL"]}, "seccompProfile": {"type": "RuntimeDefault"}}}]}}


def gateway(namespace, name, allowed, encryption="none"):
    return {"apiVersion": "ratatoskr.skaldhall.io/v1alpha1", "kind": "EgressGateway",
            "metadata": {"name": name, "namespace": namespace},
            "spec": {"replicas": 1, "encryption": encryption, "failMode": "closed", "dns": {"mode": "cluster"},
                     "allowedNamespaces": {"namespaceSelector": {"matchLabels": {"ratatoskr-e2e-admission": allowed}}},
                     "upstream": {"type": "openvpn", "secretRef": {"name": name + "-deliberately-absent"}}}}


def assert_security(original, mutated, driver, datapath, image, gateway_id):
    spec = mutated["spec"]
    if spec.get("hostNetwork") or spec.get("automountServiceAccountToken") is not False:
        raise Blocked("Unexpected host network or API token automount.")
    if spec["containers"] != original["spec"]["containers"]:
        # API defaults are allowed, but workload privilege, image and mounts are not changed.
        app = spec["containers"][0]
        for key in ("image", "securityContext", "command"):
            if app.get(key) != original["spec"]["containers"][0][key]:
                raise Blocked("Workload security/image changed during admission.")
        if app.get("volumeMounts"):
            raise Blocked("Unexpected workload credential/config mount.")
    init = spec.get("initContainers", [{}])[0]
    if init.get("name") != "ratatoskr-init" or init.get("image") != image or init.get("command"):
        raise Blocked("Missing or unexpected programming/wait init.")
    sc = init.get("securityContext", {})
    if sc.get("privileged") is True:
        raise Blocked("Injected init must never be privileged.")
    volumes = spec.get("volumes", [])
    if any("secret" in v or "hostPath" in v or "projected" in v for v in volumes):
        raise Blocked("Unexpected credential or host volume in unencrypted admission.")
    if driver == "init":
        caps = ["NET_ADMIN"] if datapath == "iproute" else ["NET_ADMIN", "BPF", "PERFMON"]
        if sc.get("privileged") is not False or sc.get("capabilities", {}).get("add") != caps or sc.get("capabilities", {}).get("drop"):
            raise Blocked("Programming init capability/privileged fields differ from contract.")
        if init.get("args") != ["-config=/var/run/ratatoskr/client.json"]:
            raise Blocked("Programming init argument differs from contract.")
        env = {e["name"]: e for e in init.get("env", [])}
        if env.get("DATAPATH", {}).get("value") != datapath:
            raise Blocked("Programming init DATAPATH differs from deployed configuration.")
        for name, path in (("POD_IP", "status.podIP"), ("POD_UID", "metadata.uid"), ("POD_NAME", "metadata.name")):
            if env.get(name, {}).get("valueFrom", {}).get("fieldRef", {}).get("fieldPath") != path:
                raise Blocked("Downward API identity field missing.")
        mounts = init.get("volumeMounts", [])
        if len(mounts) != 1 or mounts[0].get("name") != "ratatoskr-client-config" or mounts[0].get("readOnly") is not True or mounts[0].get("mountPath") != "/var/run/ratatoskr":
            raise Blocked("Read-only client config mount missing.")
        if len(volumes) != 1 or volumes[0].get("name") != "ratatoskr-client-config" or "downwardAPI" not in volumes[0]:
            raise Blocked("Downward API config volume missing.")
        items = volumes[0]["downwardAPI"].get("items", [])
        if len(items) != 1 or items[0].get("path") != "client.json" or items[0].get("fieldRef", {}).get("fieldPath") != "metadata.annotations['" + PREFIX + "client-config']":
            raise Blocked("Client config annotation projection differs from contract.")
    elif driver == "agent":
        if init.get("args") != ["-wait-agent"] or sc.get("runAsNonRoot") is not True or sc.get("runAsUser") != 65532 or sc.get("allowPrivilegeEscalation") is not False:
            raise Blocked("Agent wait-init restricted fields missing.")
        if sc.get("capabilities") != {"drop": ["ALL"]} or sc.get("seccompProfile") != {"type": "RuntimeDefault"}:
            raise Blocked("Agent wait-init capabilities/seccomp differ from contract.")
        if len(volumes) != 1 or volumes[0].get("name") != "ratatoskr-agent-api-shadow" or "emptyDir" not in volumes[0] or init.get("env"):
            raise Blocked("Agent waiter has unexpected projection/environment.")
        mounts = init.get("volumeMounts", [])
        if len(mounts) != 1 or mounts[0].get("name") != "ratatoskr-agent-api-shadow" or mounts[0].get("readOnly") is not True or mounts[0].get("mountPath") != "/var/run/secrets/kubernetes.io/serviceaccount":
            raise Blocked("Agent API-token shadow mount missing.")
    else:
        raise Blocked("Unknown deployed driver.")
    annotations = mutated["metadata"].get("annotations", {})
    cfg = json.loads(annotations.get(PREFIX + "client-config", "{}"))
    if annotations.get(PREFIX + "datapath-ready") != "pending" or cfg.get("gatewayID") != gateway_id or cfg.get("mtu") != 0 or cfg.get("encryption") != "none":
        raise Blocked("Authorized configuration or pending readiness missing.")
    if cfg.get("endpoint") not in (None, "", "invalid IP"):
        raise Blocked("Missing-Secret gateway unexpectedly supplied a healthy endpoint.")
    identity = cfg.get("identity", {})
    if identity.get("namespace") != original["metadata"]["namespace"] or identity.get("pod") != original["metadata"]["name"]:
        raise Blocked("Admitted client identity differs from authorized Pod.")


def release_preflight(api, expected_ids):
    if set(expected_ids) != {"controller", "webhook"} or not all(re.fullmatch(r".*sha256:[a-fA-F0-9]{64}", value) for value in expected_ids.values()):
        raise Blocked("Expected immutable controller/webhook runtime image IDs required; mutable tags cannot prove freshness.")
    nodes = api.get("nodes")["items"]
    control_planes = sum("node-role.kubernetes.io/control-plane" in n["metadata"].get("labels", {}) for n in nodes)
    if len(nodes) != 3 or control_planes != 1 or not all(any(c.get("type") == "Ready" and c.get("status") == "True" for c in n.get("status", {}).get("conditions", [])) for n in nodes):
        raise Blocked("Existing three-node cluster is not Ready.")
    env = api.get("configmap", "ratatoskr-testenv", "-n", "kube-system").get("data", {})
    if env.get("variant") != "flannel" or env.get("mesh") != "none":
        raise Blocked("Existing cluster must be flannel/no-mesh; no lifecycle change is attempted.")
    mutation = api.get("mutatingwebhookconfiguration", "ratatoskr-pods")
    validation = api.get("validatingwebhookconfiguration", "ratatoskr-validation")
    hooks = mutation.get("webhooks", []) + validation.get("webhooks", [])
    required = {("pods.ratatoskr.skaldhall.io", "/mutate-v1alpha1-pod"),
                ("pods.ratatoskr.skaldhall.io", "/validate-v1alpha1"),
                ("egressgateways.ratatoskr.skaldhall.io", "/validate-v1alpha1"),
                ("egresspolicies.ratatoskr.skaldhall.io", "/validate-v1alpha1")}
    present = {(h["name"], h.get("clientConfig", {}).get("service", {}).get("path")) for h in hooks}
    if not required <= present or any(h.get("failurePolicy") != "Fail" or h.get("sideEffects") != "None" or not h.get("clientConfig", {}).get("caBundle") for h in hooks):
        raise Blocked("Fail-closed dry-run-safe webhook registration missing or stale.")
    for hook in hooks:
        target = "pods" if hook["name"].startswith("pods.") else "egressgateways" if hook["name"].startswith("egressgateways.") else "egresspolicies"
        required_operations = {"CREATE"} if hook.get("clientConfig", {}).get("service", {}).get("path") == "/mutate-v1alpha1-pod" else {"CREATE", "UPDATE"}
        if not any(target in rule.get("resources", []) and required_operations <= set(rule.get("operations", [])) for rule in hook.get("rules", [])):
            raise Blocked("Webhook rules do not cover required API operations.")
        if target == "pods" and hook.get("objectSelector") != {"matchExpressions": [{"key": PREFIX + "gateway", "operator": "Exists"}]}:
            raise Blocked("Pod webhook selector differs from expected opt-in contract.")
    namespace = mutation["webhooks"][0]["clientConfig"]["service"]["namespace"]
    modes = []
    for component in ("controller", "webhook"):
        deployment = api.get("deployment", "ratatoskr-" + component, "-n", namespace)
        status, spec = deployment.get("status", {}), deployment["spec"]
        if status.get("observedGeneration", 0) < deployment["metadata"]["generation"] or status.get("availableReplicas", 0) != spec.get("replicas", 1):
            raise Blocked("Controller/webhook deployment is not fully available.")
        container = next(c for c in spec["template"]["spec"]["containers"] if c["name"] == component)
        values = {e["name"]: e.get("value") for e in container.get("env", [])}
        modes.append((values.get("DRIVER"), values.get("DATAPATH")))
        selector = ",".join(k + "=" + v for k, v in spec["selector"]["matchLabels"].items())
        pods = api.get("pods", "-n", namespace, "-l", selector)["items"]
        live = [p for p in pods if not p["metadata"].get("deletionTimestamp")]
        if len(live) != spec.get("replicas", 1):
            raise Blocked("Deployment rollout is not stable.")
        for p in live:
            rs_owner = next((r for r in p["metadata"].get("ownerReferences", []) if r.get("controller") and r["kind"] == "ReplicaSet"), None)
            if not rs_owner:
                raise Blocked("Component pod owner chain missing.")
            rs = api.get("replicaset", rs_owner["name"], "-n", namespace)
            if rs["metadata"]["uid"] != rs_owner["uid"] or not any(r.get("controller") and r.get("uid") == deployment["metadata"]["uid"] for r in rs["metadata"].get("ownerReferences", [])):
                raise Blocked("Component pod does not belong to current deployment.")
            cs = next((c for c in p.get("status", {}).get("containerStatuses", []) if c["name"] == component), {})
            if not cs.get("ready") or cs.get("imageID") != expected_ids[component]:
                raise Blocked("Component runtime image ID differs from expected build; refresh deployment explicitly.")
        if component == "webhook":
            init_image = values.get("INIT_IMAGE")
            operator_namespace = values.get("OPERATOR_NAMESPACE") or namespace
    if modes[0] != modes[1] or modes[0][0] not in ("init", "agent") or modes[0][1] not in ("iproute", "ebpf") or not init_image:
        raise Blocked("Controller/webhook mode configuration differs or is unsupported.")
    for hook in hooks:
        if hook.get("clientConfig", {}).get("service", {}).get("namespace") != namespace:
            raise Blocked("Webhook registrations do not resolve to the same release namespace.")
    return namespace, operator_namespace, *modes[0], init_image


def execute(directory, expected_ids):
    """Called only by authorized matrix execution; no CLI/import-time cluster access."""
    directory.mkdir(parents=True, exist_ok=False)
    api = API()
    checks = []
    created = []
    report = {"scope": "existing-flannel-api-admission-only", "status": "FAILED", "traffic": "NOT_TESTED", "checks": checks}
    def record(name, status, detail):
        checks.append({"name": name, "status": status, "detail": detail})
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    def manifest(name, value):
        # Complete Kubernetes object in JSON (a YAML subset); no partial patches or Secret bytes.
        path = directory / (name + ".json")
        path.write_text(json.dumps(value, indent=2) + "\n")
        return str(path)
    def wait_gateway(namespace, name, reason):
        deadline = min(api.deadline, time.monotonic() + 50)
        while time.monotonic() < deadline:
            g = api.get("egressgateway", name, "-n", namespace)
            ready = next((c for c in g.get("status", {}).get("conditions", []) if c["type"] == "Ready"), {})
            if g.get("status", {}).get("gatewayID", 0) and ready.get("status") == "False" and ready.get("reason") == reason and ready.get("observedGeneration") == g["metadata"]["generation"]:
                if g.get("status", {}).get("endpoints"):
                    raise Blocked("Blocked gateway published healthy endpoints.")
                return g
            time.sleep(1)
        raise Blocked("Controller allocation/blocked condition did not converge; stale deployment or reconciliation failure.")
    try:
        namespace, operator, driver, datapath, init_image = release_preflight(api, expected_ids)
        report.update(driver=driver, datapath=datapath)
        record(CHECKS[0], "PASSED", "Existing release Ready, registered fail-closed webhooks and runtime image IDs match explicit expectations.")
        root = Path(__file__).resolve().parents[3]
        crds = sorted((root / "charts/ratatoskr/crds").glob("*.yaml"))
        if len(crds) != 2:
            raise Blocked("Expected exactly two checked-in CRD files.")
        for file in crds:
            api.call("apply", "--dry-run=server", "-f", str(file), "-o", "name")
        suffix = uuid.uuid4().hex[:10]
        allowed, denied = "rtk-api-allow-" + suffix, "rtk-api-deny-" + suffix
        for name, value in ((allowed, suffix), (denied, "denied")):
            path = manifest(name, {"apiVersion": "v1", "kind": "Namespace", "metadata": {"name": name, "labels": {"ratatoskr-e2e-admission": value}}})
            created.append(path)  # Also clean up ambiguous create timeouts.
            api.call("create", "-f", path)
        name = "rtk-api-gateway-" + suffix
        path = manifest("gateway", gateway(allowed, name, suffix))
        api.call("create", "--dry-run=server", "-f", path, "-o", "name")
        api.call("create", "-f", path)
        g = wait_gateway(allowed, name, "SecretUnavailable")
        policy = {"apiVersion": "ratatoskr.skaldhall.io/v1alpha1", "kind": "EgressPolicy", "metadata": {"name": "policy", "namespace": allowed},
                  "spec": {"gatewayRef": {"name": name, "namespace": allowed}, "workloadSelector": {"matchLabels": {"case": suffix}},
                           "mode": "include", "rules": [{"cidrs": ["198.19.0.1/32"], "ports": [{"protocol": "TCP", "port": 8080}]}]}}
        api.call("create", "--dry-run=server", "-f", manifest("policy", policy), "-o", "name")
        record(CHECKS[1], "PASSED", "Both checked-in CRDs and complete Gateway/Policy instances accepted by server dry-run.")
        original = pod(allowed, "authorized", name, allowed)
        result = api.call("create", "--dry-run=server", "-f", manifest("authorized", original), "-o", "json")
        mutated = json.loads(result.stdout)
        assert_security(original, mutated, driver, datapath, init_image, g["status"]["gatewayID"])
        record(CHECKS[2], "PASSED", "Authorized Pod CREATE dry-run passed mutation and configured validation; no Pod was persisted.")
        record(CHECKS[4], "PASSED", "Injected init/waiter security, image, identity/config projection and pending fail-close state asserted.")
        cases = [("forbidden-namespace", pod(denied, "forbidden", name, allowed), "is not allowed by gateway"),
                 ("missing-gateway", pod(allowed, "missing", "does-not-exist-" + suffix, allowed), "resolve EgressGateway"),
                 ("host-network", copy.deepcopy(original), "hostNetwork pods cannot use Ratatoskr"),
                 ("reserved-init", copy.deepcopy(original), "reserved init container ratatoskr-init already exists")]
        cases[2][1]["spec"]["hostNetwork"] = True
        cases[3][1]["spec"]["initContainers"] = [{"name": "ratatoskr-init", "image": "ratatoskr-tools:m1-local"}]
        for label, obj, expected in cases:
            result = api.call("create", "--dry-run=server", "-f", manifest(label, obj), "-o", "json", allow_error=True)
            if result.returncode == 0 or "admission webhook" not in result.stderr or expected not in result.stderr:
                raise Blocked("Unauthorized request was not denied by expected Ratatoskr admission assertion.")
        record(CHECKS[3], "PASSED", "Four unauthorized cases denied with expected Ratatoskr reasons, not generic API errors.")
        if datapath == "ebpf":
            wgname = "rtk-api-wg-" + suffix
            wgpath = manifest("unsupported-wg", gateway(operator, wgname, suffix, "wireguard"))
            created.append(wgpath)
            api.call("create", "-f", wgpath)
            wait_gateway(operator, wgname, "Unsupported")
            result = api.call("get", "deployment", wgname, "-n", operator, "--ignore-not-found", "-o", "name")
            if result.stdout.strip():
                raise Blocked("Unsupported eBPF+WireGuard rendered a gateway Deployment.")
            record(CHECKS[5], "PASSED", "Existing eBPF controller rejected WireGuard as Unsupported before missing-Secret lookup; no Deployment rendered.")
        else:
            record(CHECKS[5], "SKIPPED", "Deployed datapath is iproute; eBPF+WireGuard controller rejection not covered, no release reconfiguration.")
        if api.get("pods", "-n", allowed)["items"] or api.get("deployments", "-n", allowed)["items"]:
            raise Blocked("API-only fixture unexpectedly created workload/gateway Pods or Deployment.")
        report["status"] = "INCOMPLETE" if datapath != "ebpf" else "PASSED"
    except (Blocked, ValueError, KeyError, StopIteration) as error:
        record("api-blocker", "FAILED", str(error) if isinstance(error, Blocked) else "Unexpected API object shape; no raw object retained.")
    finally:
        clean = True
        for path in reversed(created):
            try:
                api.call("delete", "-f", path, "--ignore-not-found", "--wait=true", "--timeout=25s", cleanup=True)
            except Blocked:
                clean = False
        record(CHECKS[6], "PASSED" if clean else "FAILED", "Temporary namespaces/Gateway removed." if clean else "Fixture cleanup failed; operator cleanup required.")
        if not clean:
            report["status"] = "FAILED"
        (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    return report
