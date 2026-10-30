#!/usr/bin/env python3
"""Read-only, fail-closed synthetic final-gate preflight; traffic remains uncovered.

This module intentionally cannot create any Kubernetes object. Do not promote its
preflight result to e2e evidence: see README for the missing runtime gate.
"""
import argparse
import json
import os
import re
import subprocess
import sys
import time

CONTEXT = "k3d-ratatoskr-flannel"
PROBE = "http://10.88.0.1:8080/exit"
COMPONENTS = ("controller", "webhook", "agent", "gateway", "plugin", "server", "tools")
ID_PATTERN = re.compile(r"(?:[A-Za-z0-9_.-]+://)?sha256:[a-fA-F0-9]{64}\Z")


class Blocked(Exception):
    """Sanitized, non-secret preflight failure."""


def expected_ids(environ):
    ids = {component: environ.get("EXPECTED_" + component.upper() + "_IMAGE_ID", "")
           for component in COMPONENTS}
    if not all(ID_PATTERN.fullmatch(value) for value in ids.values()):
        raise Blocked("Seven explicit immutable runtime image IDs are required; no mutable tag or missing ID is accepted.")
    return ids


class ReadOnlyAPI:
    def __init__(self, budget=120, clock=time.monotonic):
        self.clock = clock
        self.deadline = clock() + budget

    def get(self, resource, name=None, namespace=None, selector=None):
        remaining = min(15, self.deadline - self.clock())
        if remaining <= 0:
            raise Blocked("Final-gate preflight total deadline exceeded.")
        args = ["kubectl", "--context", CONTEXT, "--request-timeout=10s", "get", resource]
        if name:
            args.append(name)
        if namespace:
            args += ["-n", namespace]
        if selector:
            args += ["-l", selector]
        args += ["-o", "json"]
        # Never inherit provider tokens or shell tracing/debug variables. No raw API
        # stderr, Pod logs, profiles, Secret objects, or manifests are recorded.
        env = {key: os.environ[key] for key in ("PATH", "HOME", "KUBECONFIG") if key in os.environ}
        try:
            result = subprocess.run(args, capture_output=True, text=True, timeout=remaining,
                                    check=False, env=env)
            if result.returncode:
                raise Blocked("Read-only Kubernetes preflight failed.")
            return json.loads(result.stdout)
        except (OSError, subprocess.TimeoutExpired, ValueError):
            raise Blocked("Read-only Kubernetes preflight unavailable or malformed.") from None


def owner_is(obj, kind, uid):
    return any(ref.get("kind") == kind and ref.get("uid") == uid and
               ref.get("controller") is True for ref in obj.get("metadata", {}).get("ownerReferences", []))


def ready(obj):
    return any(c.get("type") == "Ready" and c.get("status") == "True"
               for c in obj.get("status", {}).get("conditions", []))


def verify_workload(api, namespace, kind, name, component, expected, count):
    workload = api.get(kind, name, namespace)
    spec, status = workload["spec"], workload.get("status", {})
    selector = spec["selector"]["matchLabels"]
    if not selector or status.get("observedGeneration", 0) < workload["metadata"]["generation"]:
        raise Blocked("Release workload rollout is stale.")
    if kind == "deployment":
        if spec.get("replicas", 1) != count or status.get("availableReplicas") != count:
            raise Blocked("Release Deployment is not fully available.")
    elif (status.get("desiredNumberScheduled") != count or
          status.get("numberReady") != count or status.get("updatedNumberScheduled") != count):
        raise Blocked("Release agent DaemonSet is not fully rolled out.")
    selector_string = ",".join(k + "=" + v for k, v in sorted(selector.items()))
    pods = api.get("pods", namespace=namespace, selector=selector_string)["items"]
    live = [pod for pod in pods if not pod["metadata"].get("deletionTimestamp")]
    if len(live) != count:
        raise Blocked("Release workload Pod count differs from expected rollout.")
    for pod in live:
        if kind == "deployment":
            rs_ref = next((r for r in pod["metadata"].get("ownerReferences", [])
                           if r.get("kind") == "ReplicaSet" and r.get("controller") is True), None)
            if not rs_ref:
                raise Blocked("Release Deployment owner chain missing.")
            rs = api.get("replicaset", rs_ref["name"], namespace)
            if rs["metadata"]["uid"] != rs_ref["uid"] or not owner_is(rs, "Deployment", workload["metadata"]["uid"]):
                raise Blocked("Release Deployment owner chain mismatch.")
        elif not owner_is(pod, "DaemonSet", workload["metadata"]["uid"]):
            raise Blocked("Release agent Pod owner mismatch.")
        statuses = [s for s in pod.get("status", {}).get("containerStatuses", []) if s.get("name") == component]
        if not ready(pod) or len(statuses) != 1 or not statuses[0].get("ready") or statuses[0].get("imageID") != expected:
            raise Blocked("Release runtime image ID or Pod readiness mismatch.")
    return workload


def preflight(api, ids):
    nodes = api.get("nodes")["items"]
    if (len(nodes) != 3 or
        sum("node-role.kubernetes.io/control-plane" in n["metadata"].get("labels", {}) for n in nodes) != 1 or
        not all(ready(n) for n in nodes)):
        raise Blocked("Existing three-node cluster is not Ready.")
    env = api.get("configmap", "ratatoskr-testenv", "kube-system").get("data", {})
    if env.get("variant") != "flannel" or env.get("mesh") != "none":
        raise Blocked("Existing cluster is not preflighted flannel/no-mesh.")
    mutation = api.get("mutatingwebhookconfiguration", "ratatoskr-pods")
    validation = api.get("validatingwebhookconfiguration", "ratatoskr-validation")
    hooks = mutation.get("webhooks", []) + validation.get("webhooks", [])
    paths = {(h.get("name"), h.get("clientConfig", {}).get("service", {}).get("path")) for h in hooks}
    needed = {("pods.ratatoskr.skaldhall.io", "/mutate-v1alpha1-pod"),
              ("pods.ratatoskr.skaldhall.io", "/validate-v1alpha1"),
              ("egressgateways.ratatoskr.skaldhall.io", "/validate-v1alpha1"),
              ("egresspolicies.ratatoskr.skaldhall.io", "/validate-v1alpha1")}
    if not needed <= paths or not hooks or any(h.get("failurePolicy") != "Fail" or
            h.get("sideEffects") != "None" or not h.get("clientConfig", {}).get("caBundle") for h in hooks):
        raise Blocked("Registered fail-closed admission webhooks missing.")
    namespace = mutation["webhooks"][0]["clientConfig"]["service"]["namespace"]
    if not namespace or any(h["clientConfig"]["service"].get("namespace") != namespace for h in hooks):
        raise Blocked("Release webhook namespaces differ.")
    controller = verify_workload(api, namespace, "deployment", "ratatoskr-controller", "controller", ids["controller"], 1)
    webhook = verify_workload(api, namespace, "deployment", "ratatoskr-webhook", "webhook", ids["webhook"], 1)
    agent = verify_workload(api, namespace, "daemonset", "ratatoskr-agent", "agent", ids["agent"], 3)
    def environment(workload, component):
        container = next(c for c in workload["spec"]["template"]["spec"]["containers"] if c["name"] == component)
        return {item["name"]: item.get("value") for item in container.get("env", [])}
    values = environment(controller, "controller")
    webhook_values = environment(webhook, "webhook")
    agent_values = environment(agent, "agent")
    if (values.get("DRIVER") != "agent" or values.get("DATAPATH") != "iproute" or
            webhook_values.get("DRIVER") != "agent" or webhook_values.get("DATAPATH") != "iproute" or
            agent_values.get("DATAPATH") != "iproute" or not webhook_values.get("INIT_IMAGE") or
            values.get("GATEWAY_UPSTREAM_PROBE_URL") != PROBE or
            values.get("IMAGE_PULL_POLICY") != "Never" or
            not values.get("GATEWAY_IMAGE") or not values.get("OPENVPN_IMAGE")):
        raise Blocked("Controller/webhook/agent mode, local images or trusted probe configuration differs.")
    return namespace


def main(argv=None, environ=None, api_factory=ReadOnlyAPI):
    parser = argparse.ArgumentParser(description="Read-only synthetic VPN final-gate preflight (never e2e PASS)")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    if not args.execute or env.get("RATATOSKR_E2E_FINAL_GATE") != "1":
        print("SKIPPED: requires --execute and RATATOSKR_E2E_FINAL_GATE=1; no cluster accessed.")
        return 2
    try:
        ids = expected_ids(env)
        preflight(api_factory(), ids)
    except (Blocked, KeyError, IndexError, StopIteration, TypeError, AttributeError):
        # API objects/errors are untrusted: never print their content.
        print("FAILED: synthetic final-gate preflight blocked; no resources created. Inspect release/operator preflight privately.")
        return 1
    print("INCOMPLETE: existing flannel/agent release and probe preflight passed; gateway/plugin/server/tools runtime IDs, TLS tunnel, DNS/API, fail-close and cleanup evidence NOT TESTED. No resources created.")
    return 4


if __name__ == "__main__":
    sys.exit(main())
