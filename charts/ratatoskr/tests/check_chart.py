#!/usr/bin/env python3
"""Chart-local static assertions. Requires helm and PyYAML (no Kubernetes)."""
from pathlib import Path
import subprocess
import sys

import yaml

CHART = Path(__file__).resolve().parents[1]
ROOT = CHART.parents[1]
NAMESPACE = "ratatoskr-system"


def helm(*args, succeeds=True):
    result = subprocess.run(["helm", *args], text=True, capture_output=True)
    assert (result.returncode == 0) == succeeds, result.stdout + result.stderr
    return result.stdout


def render(*extra):
    output = helm("template", "ratatoskr", str(CHART), "--namespace", NAMESPACE, *extra)
    docs = list(yaml.safe_load_all(output))
    assert all(isinstance(doc, dict) for doc in docs)
    assert "PRIVATE KEY" not in output and "tls.key" not in output
    return {(d["kind"], d["metadata"]["name"]): d for d in docs}


def rule(doc, resource, api_group=None):
    matching = [r for r in doc["rules"] if resource in r["resources"]]
    if api_group is not None:
        matching = [r for r in matching if api_group in r["apiGroups"]]
    assert len(matching) == 1, (resource, matching)
    return matching[0]


def check_agent(docs, socket, datapath):
    role = docs["ClusterRole", "ratatoskr-agent"]
    assert role["rules"] == [
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch", "patch"]},
        {"apiGroups": [""], "resources": ["namespaces"], "verbs": ["get"]},
        {"apiGroups": ["ratatoskr.skaldhall.io"], "resources": ["egressgateways"],
         "verbs": ["get", "list", "watch"]},
        {"apiGroups": ["ratatoskr.skaldhall.io"], "resources": ["egresspolicies"], "verbs": ["list"]},
        {"apiGroups": [""], "resources": ["serviceaccounts/token"], "verbs": ["create"]},
    ]
    assert docs["ClusterRoleBinding", "ratatoskr-agent"]["subjects"] == [
        {"kind": "ServiceAccount", "name": "ratatoskr-agent", "namespace": NAMESPACE}
    ]
    ds = docs["DaemonSet", "ratatoskr-agent"]["spec"]
    pod = ds["template"]["spec"]
    assert ds["selector"]["matchLabels"] == ds["template"]["metadata"]["labels"]
    assert pod["serviceAccountName"] == "ratatoskr-agent"
    assert pod["automountServiceAccountToken"] is True
    assert pod["hostPID"] is True and pod["hostNetwork"] is True
    assert pod["dnsPolicy"] == "ClusterFirstWithHostNet"
    assert len(pod["containers"]) == 1
    container = pod["containers"][0]
    assert container["image"].endswith("/ratatoskr-agent:dev")
    assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
    assert container["readinessProbe"]["httpGet"]["path"] == "/readyz"
    assert container["ports"] == [{"name": "health", "containerPort": 8081}]
    bpf_enabled = datapath == "ebpf"
    assert container["securityContext"] == {
        "runAsUser": 0, "privileged": False, "allowPrivilegeEscalation": False,
        "seccompProfile": {"type": "RuntimeDefault"},
        "capabilities": {"drop": ["ALL"], "add": ["NET_ADMIN", "SYS_ADMIN"] +
                         (["BPF", "PERFMON"] if bpf_enabled else [])},
    }
    env = {e["name"]: e for e in container["env"]}
    assert set(env) == {"NODE_NAME", "CRI_SOCKET", "OPERATOR_NAMESPACE", "DATAPATH"}
    assert env["DATAPATH"]["value"] == datapath
    assert env["NODE_NAME"]["valueFrom"]["fieldRef"]["fieldPath"] == "spec.nodeName"
    assert env["CRI_SOCKET"]["value"] == socket
    assert env["OPERATOR_NAMESPACE"]["value"] == NAMESPACE
    assert pod["volumes"] == [
        {"name": "cri-socket", "hostPath": {"path": socket, "type": "Socket"}},
        {"name": "netns", "hostPath": {"path": "/var/run/netns", "type": "DirectoryOrCreate"}},
    ]
    assert container["volumeMounts"] == [
        {"name": "cri-socket", "mountPath": socket, "readOnly": True},
        {"name": "netns", "mountPath": "/var/run/netns", "readOnly": True},
    ]


def check(docs, driver, datapath="iproute", socket="/run/containerd/containerd.sock"):
    expected = {
        ("ConfigMap", "ratatoskr-config"),
        ("ServiceAccount", "ratatoskr-controller"),
        ("ServiceAccount", "ratatoskr-webhook"),
        ("ServiceAccount", "ratatoskr-gateway"),
        ("Role", "ratatoskr-gateway-publish"),
        ("RoleBinding", "ratatoskr-gateway-publish"),
        ("Deployment", "ratatoskr-controller"),
        ("Deployment", "ratatoskr-webhook"),
        ("Service", "ratatoskr-controller"),
        ("Service", "ratatoskr-webhook"),
        ("ClusterRole", "ratatoskr-controller"),
        ("ClusterRole", "ratatoskr-webhook"),
        ("ClusterRole", "ratatoskr-gateway"),
        ("ClusterRoleBinding", "ratatoskr-controller"),
        ("ClusterRoleBinding", "ratatoskr-webhook"),
        ("ClusterRoleBinding", "ratatoskr-gateway"),
        ("Role", "ratatoskr-webhook-tls"),
        ("RoleBinding", "ratatoskr-webhook-tls"),
        ("NetworkPolicy", "ratatoskr-webhook-ingress"),
        ("MutatingWebhookConfiguration", "ratatoskr-pods"),
        ("ValidatingWebhookConfiguration", "ratatoskr-validation"),
    }
    if driver == "agent":
        expected |= {
            ("ServiceAccount", "ratatoskr-agent"),
            ("ClusterRole", "ratatoskr-agent"),
            ("ClusterRoleBinding", "ratatoskr-agent"),
            ("DaemonSet", "ratatoskr-agent"),
        }
    assert set(docs) == expected, set(docs) ^ expected
    assert not any(kind == "Secret" for kind, _ in docs)
    if driver == "agent":
        check_agent(docs, socket, datapath)
    # Host mounts and capabilities are only granted to the node-local agent;
    # the controller/webhook never receive the node CRI or netns paths.
    for kind, name in (("Deployment", "ratatoskr-controller"),
                       ("Deployment", "ratatoskr-webhook")):
        pod = docs[kind, name]["spec"]["template"]["spec"]
        assert not any("hostPath" in v for v in pod.get("volumes", []))
        assert not pod.get("hostPID") and not pod.get("hostNetwork")
    # Labeled workload Pods are admitted dynamically by Go; Helm must not
    # statically install privileged clients or add capabilities to operator
    # workloads other than the dedicated agent DaemonSet.
    for (kind, name), document in docs.items():
        if kind not in ("Pod", "Deployment", "DaemonSet") or name == "ratatoskr-agent":
            continue
        pod_spec = (document["spec"] if kind == "Pod" else
                    document["spec"]["template"]["spec"])
        for container in pod_spec.get("containers", []) + pod_spec.get("initContainers", []):
            security = container.get("securityContext", {})
            assert not security.get("privileged")
            assert not security.get("capabilities", {}).get("add")
    gateway_sa = docs["ServiceAccount", "ratatoskr-gateway"]
    assert gateway_sa["automountServiceAccountToken"] is False
    gateway_role = docs["ClusterRole", "ratatoskr-gateway"]
    assert rule(gateway_role, "tokenreviews")["verbs"] == ["create"]
    assert rule(gateway_role, "pods")["verbs"] == ["get", "list", "watch"]
    publish_role = docs["Role", "ratatoskr-gateway-publish"]
    assert publish_role["metadata"]["namespace"] == NAMESPACE
    assert rule(publish_role, "pods")["verbs"] == ["patch"]
    assert rule(gateway_role, "namespaces")["verbs"] == ["get"]
    assert rule(gateway_role, "egressgateways")["verbs"] == ["get"]
    assert docs["ClusterRoleBinding", "ratatoskr-gateway"]["subjects"] == [
        {"kind": "ServiceAccount", "name": "ratatoskr-gateway", "namespace": NAMESPACE}
    ]
    for component in ("controller", "webhook"):
        deployment = docs["Deployment", "ratatoskr-" + component]["spec"]
        pod = deployment["template"]
        service = docs["Service", "ratatoskr-" + component]["spec"]
        assert deployment["selector"]["matchLabels"] == service["selector"]
        assert all(pod["metadata"]["labels"].get(k) == v for k, v in service["selector"].items())
        assert pod["spec"]["serviceAccountName"] == "ratatoskr-" + component
        container = pod["spec"]["containers"][0]
        assert container["livenessProbe"]["httpGet"]["path"] == "/healthz"
        assert container["readinessProbe"]["httpGet"]["path"] == "/readyz"
        assert container["ports"][-1]["containerPort"] == 8081
    webhook = docs["Deployment", "ratatoskr-webhook"]["spec"]["template"]["spec"]
    assert webhook["initContainers"][0]["args"] == ["--bootstrap-tls", "--tls-dir=/tls/identity"]
    assert webhook["containers"][0]["args"] == ["--tls-dir=/tls/identity"]
    assert webhook["securityContext"]["fsGroup"] == 65532
    assert webhook["initContainers"][0]["image"] == webhook["containers"][0]["image"]
    assert webhook["volumes"] == [{"name": "tls", "emptyDir": {"medium": "Memory"}}]
    env = {x["name"]: x for x in webhook["initContainers"][0]["env"]}
    assert env["NAMESPACE"]["valueFrom"]["fieldRef"]["fieldPath"] == "metadata.namespace"
    assert {k: env[k]["value"] for k in (
        "SERVICE_NAME", "TLS_SECRET_NAME", "MUTATING_WEBHOOK_NAME", "VALIDATING_WEBHOOK_NAME"
    )} == {
        "SERVICE_NAME": "ratatoskr-webhook", "TLS_SECRET_NAME": "ratatoskr-webhook-tls",
        "MUTATING_WEBHOOK_NAME": "ratatoskr-pods", "VALIDATING_WEBHOOK_NAME": "ratatoskr-validation"
    }
    assert docs["Service", "ratatoskr-webhook"]["spec"]["ports"] == [
        {"name": "https", "port": 443, "targetPort": "https"}
    ]
    assert next(p["containerPort"] for p in webhook["containers"][0]["ports"]
                if p["name"] == "https") == 9443
    ctrl_env = {e["name"]: e for e in docs["Deployment", "ratatoskr-controller"]
                ["spec"]["template"]["spec"]["containers"][0]["env"]}
    for name in ("OPERATOR_NAMESPACE", "GATEWAY_IMAGE", "OPENVPN_IMAGE",
                 "IMAGE_PULL_POLICY", "DRIVER", "DATAPATH", "CLUSTER_DOMAIN",
                 "SERVICE_CIDRS", "POD_CIDRS", "GATEWAY_UPSTREAM_DNS_IP"):
        assert name in ctrl_env, name
    assert ctrl_env["OPENVPN_IMAGE"]["value"].endswith("/ratatoskr-upstream-openvpn:dev")
    assert ctrl_env["DRIVER"]["value"] == driver
    assert ctrl_env["DATAPATH"]["value"] == datapath
    for spec in (webhook["containers"][0], webhook["initContainers"][0]):
        env = {e["name"]: e for e in spec["env"]}
        assert env["OPERATOR_NAMESPACE"]["value"] == NAMESPACE
    serving_env = {e["name"]: e for e in webhook["containers"][0]["env"]}
    assert serving_env["DRIVER"]["value"] == driver
    assert serving_env["DATAPATH"]["value"] == datapath
    assert docs["ConfigMap", "ratatoskr-config"]["data"]["datapath"] == datapath
    mutating = docs["MutatingWebhookConfiguration", "ratatoskr-pods"]["webhooks"]
    validating = docs["ValidatingWebhookConfiguration", "ratatoskr-validation"]["webhooks"]
    assert len(mutating) == 1 and len(validating) == 3
    assert mutating[0]["clientConfig"]["service"]["path"] == "/mutate-v1alpha1-pod"
    assert all(h["clientConfig"]["service"]["path"] == "/validate-v1alpha1" for h in validating)
    for hook in mutating + validating:
        assert hook["failurePolicy"] == "Fail"
        assert hook["clientConfig"]["service"]["name"] == "ratatoskr-webhook"
        assert hook["clientConfig"]["service"]["namespace"] == NAMESPACE
        assert hook["clientConfig"]["service"]["port"] == 443
        assert "caBundle" not in hook["clientConfig"]
    for hook in (mutating[0], validating[0]):
        assert hook["objectSelector"]["matchExpressions"] == [{
            "key": "ratatoskr.skaldhall.io/gateway", "operator": "Exists"
        }]
        assert hook["rules"][0]["resources"] == ["pods"]
        assert hook["rules"][0]["apiGroups"] == [""]
    assert mutating[0]["rules"][0]["operations"] == ["CREATE"]
    assert validating[0]["rules"][0]["operations"] == ["CREATE", "UPDATE"]
    for hook, resource in zip(validating[1:], ("egressgateways", "egresspolicies")):
        assert hook["rules"][0]["operations"] == ["CREATE", "UPDATE"]
        assert hook["rules"][0]["apiGroups"] == ["ratatoskr.skaldhall.io"]
        assert hook["rules"][0]["resources"] == [resource]
    controller = docs["ClusterRole", "ratatoskr-controller"]
    assert rule(controller, "secrets")["verbs"] == ["get"]
    assert rule(controller, "nodes")["verbs"] == ["get", "list", "watch"]
    assert rule(controller, "endpointslices")["verbs"] == ["get", "list", "watch"]
    assert rule(controller, "servicecidrs")["verbs"] == ["get", "list", "watch"]
    assert set(rule(controller, "networkpolicies")["verbs"]) == {"get", "list", "watch", "create", "update", "patch", "delete"}
    assert rule(controller, "replicasets")["verbs"] == ["get", "list", "watch"]
    assert [r for r in controller["rules"] if r["resources"] == ["pods"]] == [
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["patch"]}
    ]
    assert rule(controller, "egressgateways/status")["verbs"] == ["get", "update", "patch"]
    assert set(rule(controller, "deployments")["verbs"]) == {
        "get", "list", "watch", "create", "update", "patch", "delete"
    }
    webhook_role = docs["ClusterRole", "ratatoskr-webhook"]
    assert rule(webhook_role, "services")["verbs"] == ["get"]
    assert rule(webhook_role, "pods")["verbs"] == ["list"]
    for resource, name in (
        ("mutatingwebhookconfigurations", "ratatoskr-pods"),
        ("validatingwebhookconfigurations", "ratatoskr-validation"),
    ):
        r = rule(webhook_role, resource)
        assert r["resourceNames"] == [name] and r["verbs"] == ["get", "update", "patch"]
    tls_role = docs["Role", "ratatoskr-webhook-tls"]
    assert tls_role["metadata"]["namespace"] == NAMESPACE
    tls_rules = [r for r in tls_role["rules"] if "secrets" in r["resources"]]
    assert tls_rules == [
        {"apiGroups": [""], "resources": ["secrets"], "verbs": ["create"]},
        {"apiGroups": [""], "resources": ["secrets"],
         "resourceNames": ["ratatoskr-webhook-tls"], "verbs": ["get", "update", "patch"]},
    ]
    for role in (controller, webhook_role, tls_role):
        for r in role["rules"]:
            assert "*" not in r["resources"] and "*" not in r["verbs"]
    policy = docs["NetworkPolicy", "ratatoskr-webhook-ingress"]["spec"]
    assert policy["podSelector"]["matchLabels"] == docs["Service", "ratatoskr-webhook"]["spec"]["selector"]
    assert {p["port"] for p in policy["ingress"][0]["ports"]} == {9443, 8081}


if __name__ == "__main__":
    helm("lint", str(CHART), "--strict")
    helm("lint", str(CHART), "--strict", "-f", str(ROOT / "hack" / "dev-values.yaml"))
    helm("lint", str(CHART), "--strict", "--set", "datapath=ebpf")
    helm("lint", str(CHART), "--strict", "--set", "driver=init", "--set", "datapath=ebpf")
    check(render(), "agent")
    check(render("-f", str(ROOT / "hack" / "dev-values.yaml")), "init")
    check(render("-f", str(ROOT / "hack" / "dev-values.yaml"),
                 "--set", "driver=agent"), "agent", socket="/run/k3s/containerd/containerd.sock")
    check(render("--set", "driver=init"), "init")
    check(render("--set", "datapath=ebpf"), "agent", "ebpf")
    check(render("--set", "driver=init", "--set", "datapath=ebpf"), "init", "ebpf")
    for args in (("--set", "driver=unknown"), ("--set", "datapath=unknown"),
                 ("--set", "operatorNamespace=somewhere-else")):
        helm("template", "ratatoskr", str(CHART), "--namespace", NAMESPACE,
             *args, succeeds=False)
    print("chart lint/template, RBAC, security and webhook scope checks passed (agent/init × iproute/ebpf)")
