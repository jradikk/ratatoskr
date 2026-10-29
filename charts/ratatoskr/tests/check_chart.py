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


def check(docs):
    assert set(docs) == {
        ("ConfigMap", "ratatoskr-config"),
        ("ServiceAccount", "ratatoskr-controller"),
        ("ServiceAccount", "ratatoskr-webhook"),
        ("Deployment", "ratatoskr-controller"),
        ("Deployment", "ratatoskr-webhook"),
        ("Service", "ratatoskr-controller"),
        ("Service", "ratatoskr-webhook"),
        ("ClusterRole", "ratatoskr-controller"),
        ("ClusterRole", "ratatoskr-webhook"),
        ("ClusterRoleBinding", "ratatoskr-controller"),
        ("ClusterRoleBinding", "ratatoskr-webhook"),
        ("Role", "ratatoskr-webhook-tls"),
        ("RoleBinding", "ratatoskr-webhook-tls"),
        ("NetworkPolicy", "ratatoskr-webhook-ingress"),
        ("MutatingWebhookConfiguration", "ratatoskr-pods"),
        ("ValidatingWebhookConfiguration", "ratatoskr-validation"),
    }, set(docs)
    assert not any(kind == "Secret" for kind, _ in docs)
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
    assert ctrl_env["DRIVER"]["value"] == "init"
    assert ctrl_env["DATAPATH"]["value"] == "iproute"
    for spec in (webhook["containers"][0], webhook["initContainers"][0]):
        env = {e["name"]: e for e in spec["env"]}
        assert env["OPERATOR_NAMESPACE"]["value"] == NAMESPACE
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
    assert [r for r in controller["rules"] if r["resources"] == ["pods"]] == [
        {"apiGroups": [""], "resources": ["pods"], "verbs": ["patch"]}
    ]
    assert rule(controller, "egressgateways/status")["verbs"] == ["get", "update", "patch"]
    assert set(rule(controller, "deployments")["verbs"]) == {
        "get", "list", "watch", "create", "update", "patch", "delete"
    }
    webhook_role = docs["ClusterRole", "ratatoskr-webhook"]
    assert rule(webhook_role, "services")["verbs"] == ["get"]
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
    check(render())
    check(render("-f", str(ROOT / "hack" / "dev-values.yaml")))
    for args in (("--set", "driver=agent"), ("--set", "datapath=ebpf"),
                 ("--set", "operatorNamespace=somewhere-else")):
        helm("template", "ratatoskr", str(CHART), "--namespace", NAMESPACE,
             *args, succeeds=False)
    print("chart lint/template, RBAC and webhook scope checks passed (default + dev)")
