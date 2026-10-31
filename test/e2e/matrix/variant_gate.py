"""Fail-closed variant lifecycle and preflight for *future* approved runners.

Only explicitly gated calls touch k3d/Kubernetes. This module reports a
verified environment, NEVER a passed traffic scenario or matrix cell. Current
runner allowlist is synthetic/flannel/none only; adding a CNI or mesh fixture
requires a separately reviewed adapter and packet-level checkpoints.
"""
import json
import os
from pathlib import Path
import re
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[3]
VARIANTS = frozenset(("flannel", "cilium", "cilium-wg", "calico"))
MESHES = frozenset(("none", "sidecar", "ambient"))
AGENT_CAPS = {"NET_ADMIN", "SYS_ADMIN"}
DIGEST = re.compile(r"(?:[A-Za-z0-9_.-]+://)?sha256:[a-f0-9]{64}\Z")
APPROVED_RUNNERS = {("flannel", "none", "synthetic-agent-iproute")}


class Blocked(Exception):
    """Fixed category without raw cluster/provider response."""


def _command(argv, *, timeout=15):
    env = {key: os.environ[key] for key in ("PATH", "HOME", "KUBECONFIG") if key in os.environ}
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout, env=env, check=False)
        if proc.returncode or len(proc.stdout) > 131072:
            raise Blocked("lifecycle or read-only preflight command failed")
        return proc.stdout
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("lifecycle or read-only preflight command unavailable") from None


def _json(raw, label):
    try:
        value = json.loads(raw)
        if not isinstance(value, (dict, list)):
            raise ValueError()
        return value
    except (TypeError, ValueError):
        raise Blocked(label + " response malformed") from None


def _context(variant):
    return "k3d-ratatoskr-" + variant


def _kubectl(variant, *args, call=_command):
    return _json(call(["kubectl", "--context", _context(variant), "--request-timeout=10s",
                       "get", *args, "-o", "json"]), "Kubernetes")


def _nodes(variant, *, call):
    data = _kubectl(variant, "nodes", call=call)
    try:
        items = data["items"]
        names = [n["metadata"]["name"] for n in items]
        control = [n for n in items if "node-role.kubernetes.io/control-plane" in n["metadata"].get("labels", {})]
        if (len(names) != 3 or len(set(names)) != 3 or
                set(names) != {"k3d-ratatoskr-" + variant + suffix for suffix in ("-server-0", "-agent-0", "-agent-1")} or
                len(control) != 1 or control[0]["metadata"]["name"] != "k3d-ratatoskr-" + variant + "-server-0" or
                any(n["metadata"].get("deletionTimestamp") or
                    not any(c.get("type") == "Ready" and c.get("status") == "True" for c in n["status"]["conditions"])
                    for n in items)):
            raise ValueError()
    except (TypeError, KeyError, ValueError, AttributeError):
        raise Blocked("exact three-node Ready topology required") from None
    return names


def _agent(variant, names, *, call, expected_agent_image_id):
    ds = _kubectl(variant, "daemonset", "ratatoskr-agent", "-n", "ratatoskr-system", call=call)
    try:
        pod = ds["spec"]["template"]["spec"]
        containers = [c for c in pod["containers"] if c.get("name") == "agent"]
        if (len(containers) != 1 or not pod.get("hostPID") or not pod.get("hostNetwork") or
                pod.get("serviceAccountName") != "ratatoskr-agent" or
                pod.get("automountServiceAccountToken") is not True):
            raise ValueError()
        sc = containers[0]["securityContext"]
        caps = sc["capabilities"]
        mode = next((v.get("value") for v in containers[0].get("env", []) if v.get("name") == "DATAPATH"), None)
        permitted = AGENT_CAPS | ({"BPF", "PERFMON"} if mode == "ebpf" else set())
        if (mode not in ("iproute", "ebpf") or sc.get("runAsUser") != 0 or
                sc.get("privileged") is not False or sc.get("allowPrivilegeEscalation") is not False or
                sc.get("seccompProfile") != {"type": "RuntimeDefault"} or
                caps.get("drop") != ["ALL"] or set(caps.get("add", [])) != permitted or
                len(caps["add"]) != len(permitted) or
                ds["status"].get("observedGeneration", 0) < ds["metadata"]["generation"] or
                any(ds["status"].get(k) != 3 for k in ("desiredNumberScheduled", "updatedNumberScheduled", "numberReady"))):
            raise ValueError()
        mounts = {v["name"]: v for v in containers[0]["volumeMounts"]}
        volumes = {v["name"]: v for v in pod["volumes"]}
        cri = next(e.get("value") for e in containers[0]["env"] if e.get("name") == "CRI_SOCKET")
        if (not cri.startswith("/") or mounts["cri-socket"] != {"name": "cri-socket", "mountPath": cri, "readOnly": True} or
                volumes["cri-socket"]["hostPath"] != {"path": cri, "type": "Socket"} or
                mounts["netns"] != {"name": "netns", "mountPath": "/var/run/netns", "readOnly": True} or
                volumes["netns"]["hostPath"].get("path") != "/var/run/netns" or
                len(mounts) != 2 or len(volumes) != 2):
            raise ValueError()
    except (TypeError, ValueError, KeyError, AttributeError, IndexError, StopIteration):
        raise Blocked("node-agent privileges, mounts or rollout differ from scoped contract") from None
    listed = _kubectl(variant, "pods", "-n", "ratatoskr-system", "-l",
                      "app.kubernetes.io/name=ratatoskr,app.kubernetes.io/component=agent", call=call)
    try:
        pods = listed["items"]
        if len(pods) != 3 or {p["spec"]["nodeName"] for p in pods} != set(names):
            raise ValueError()
        for p in pods:
            refs = p["metadata"]["ownerReferences"]
            if (p["metadata"].get("deletionTimestamp") or not any(r.get("kind") == "DaemonSet" and
                r.get("controller") is True and r.get("uid") == ds["metadata"]["uid"] for r in refs) or
                not any(c.get("type") == "Ready" and c.get("status") == "True" for c in p["status"]["conditions"])):
                raise ValueError()
            status = [c for c in p["status"]["containerStatuses"] if c.get("name") == "agent"]
            if (len(status) != 1 or status[0].get("ready") is not True or
                    status[0].get("imageID") != expected_agent_image_id):
                raise ValueError()
    except (TypeError, KeyError, ValueError, AttributeError):
        raise Blocked("node-agent Pods are not owner-linked, Ready and immutable") from None
    return mode


def preflight(variant, mesh, *, expected_agent_image_id, call=_command):
    """Read only exact context/node/variant/mesh/agent state; no traffic claim."""
    if not isinstance(expected_agent_image_id, str) or not DIGEST.fullmatch(expected_agent_image_id):
        raise Blocked("approved immutable node-agent runtime image ID required")
    if variant not in VARIANTS or mesh not in MESHES:
        raise Blocked("undeclared variant or mesh")
    raw = _json(call(["k3d", "cluster", "list", "-o", "json"]), "k3d")
    try:
        clusters = [c["name"] for c in raw]
        if clusters != ["ratatoskr-" + variant]:
            raise ValueError()
    except (TypeError, KeyError, ValueError):
        raise Blocked("single exact Ratatoskr cluster required") from None
    nodes = _nodes(variant, call=call)
    cm = _kubectl(variant, "configmap", "ratatoskr-testenv", "-n", "kube-system", call=call)
    if (cm.get("metadata", {}).get("name") != "ratatoskr-testenv" or
            cm.get("data") != {"variant": variant, "mesh": mesh}):
        raise Blocked("declared variant or mesh differs from cluster testenv")
    mode = _agent(variant, nodes, call=call, expected_agent_image_id=expected_agent_image_id)
    return {"cluster": "ratatoskr-" + variant, "context": _context(variant),
            "variant": variant, "mesh": mesh, "agentDatapath": mode,
            "status": "PREFLIGHT_ONLY", "trafficCovered": False}


def dispatch(variant, mesh, runner, *, execute=False, authorization=None,
             expected_agent_image_id=None, call=_command, approved_runner=None, environ=None):
    """Mandatory k3d-up lifecycle, then exact preflight, then approved runner.

    The runner is independently supplied trusted code; its result is returned
    untouched and may not be used by this adapter to award scenario coverage.
    No lifecycle/cluster call occurs without both opt-ins and a known runner.
    """
    environment = os.environ if environ is None else environ
    if (not execute or authorization != "1" or
            environment.get("RATATOSKR_E2E_FINAL_GATE") != "1" or
            (variant, mesh, runner) not in APPROVED_RUNNERS):
        raise Blocked("explicit final-gate opt-in and approved runner required")
    if not isinstance(expected_agent_image_id, str) or not DIGEST.fullmatch(expected_agent_image_id):
        raise Blocked("approved immutable node-agent runtime image ID required")
    if approved_runner is None:
        raise Blocked("reviewed runner callback required")
    script = ROOT / "hack/k3d-up.sh"
    config = ROOT / "hack/k3d" / (variant + ".yaml")
    if not script.is_file() or not config.is_file():
        raise Blocked("mandatory lifecycle or pinned variant config missing")
    # The script alone owns resource/module preflight, one-cluster enforcement,
    # reuse, CNI/mesh installation, node waits, and ratatoskr-testenv stamping.
    call(["bash", str(script), variant, "--mesh=" + mesh], timeout=1200)
    verified = preflight(variant, mesh, expected_agent_image_id=expected_agent_image_id, call=call)
    if runner != "synthetic-agent-iproute" or verified["agentDatapath"] != "iproute":
        raise Blocked("approved synthetic agent/iproute runtime required")
    return approved_runner(verified)
