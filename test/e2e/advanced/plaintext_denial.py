"""Optional, fail-closed plaintext GENEVE denial evidence for owned WG fixture.

No cluster action on import. Runtime is only reachable through wg_fixture's
explicit final-gate/WM/optional plaintext opt-ins. Raw nft/packet/CRI bytes are
never logged or persisted. CNI denial before gateway eth0 is INCONCLUSIVE.
"""
import json
import os
import re
import subprocess
import selectors
import signal
import time
from pathlib import Path

try:
    from . import wg_fixture as wg, wg_transport
except ImportError:
    import wg_fixture as wg
    import wg_transport

RUNTIME = wg.node_images.RUNTIME
HEX = re.compile(r"[0-9a-f]{64}\Z")
COUNT = re.compile(r"[0-9]{1,20}\Z")


class Blocked(Exception):
    """Only fixture-authored, non-secret reason categories."""


def sandbox_id(raw, uid, namespace, name):
    try:
        items = json.loads(raw)["items"]
        if not isinstance(items, list) or len(items) > 512:
            raise ValueError()
        found = [p for p in items if p.get("state") == "SANDBOX_READY" and
                 p.get("metadata", {}).get("uid") == uid and
                 p["metadata"].get("namespace") == namespace and
                 p["metadata"].get("name") == name and
                 p.get("labels", {}).get("io.kubernetes.pod.uid") == uid]
        if len(found) != 1 or not HEX.fullmatch(found[0].get("id", "")):
            raise ValueError()
        return found[0]["id"]
    except (ValueError, KeyError, AttributeError, TypeError):
        raise Blocked("Plaintext CRI READY sandbox ownership unavailable.") from None


def sandbox_pid(raw, sid, uid, namespace, name, ip):
    try:
        obj = json.loads(raw)
        status, details = obj["status"], obj["info"]
        meta = status["metadata"]
        if (status["id"] != sid or status["state"] != "SANDBOX_READY" or
                (meta["uid"], meta["namespace"], meta["name"]) != (uid, namespace, name) or
                status["labels"].get("io.kubernetes.pod.uid") != uid or
                status["network"]["ip"] != ip):
            raise ValueError()
        if isinstance(details, dict) and isinstance(details.get("info"), str):
            details = json.loads(details["info"])
        pid = details["pid"]
        netns = [v.get("path") for v in details["runtimeSpec"]["linux"]["namespaces"]
                 if v.get("type") == "network"]
        if type(pid) is not int or not 1 < pid < 2**31 or len(netns) != 1 or not netns[0].startswith("/var/run/netns/"):
            raise ValueError()
        return pid
    except (ValueError, KeyError, AttributeError, TypeError):
        raise Blocked("Plaintext CRI sandbox UID/IP/PID invalid.") from None


def proof(raw, *, source, gateway, vni):
    """Only packet-correlated ingress+owned nft drop+no GENEVE delivery."""
    try:
        obj = json.loads(raw)
        if not isinstance(obj, dict) or set(obj) != {"source", "gateway", "vni", "ethIn", "gnvIn",
                                                 "dropBefore", "dropAfter", "sent"}:
            raise ValueError()
        if (obj["source"] != source or obj["gateway"] != gateway or obj["vni"] != vni or
                type(obj["ethIn"]) is not int or obj["ethIn"] < 1 or obj["ethIn"] > 3 or
                type(obj["gnvIn"]) is not int or obj["gnvIn"] != 0 or
                type(obj["sent"]) is not int or obj["sent"] != 3 or
                any(type(obj[k]) is not int or obj[k] < 0 or obj[k] > (1 << 64)-1
                    for k in ("dropBefore", "dropAfter")) or
                obj["dropAfter"]-obj["dropBefore"] < obj["ethIn"]):
            raise ValueError()
        return True
    except (ValueError, UnicodeError, KeyError, TypeError, AttributeError):
        raise Blocked("Plaintext arrival/owned drop/no-gnv delivery unverified.") from None


def _node_cmd(node, args, transport):
    try:
        return transport(["docker", "exec", node, "/bin/crictl", "--runtime-endpoint", RUNTIME, *args],
                         timeout=6, max_output=65536)
    except wg.node_images.Blocked:
        raise Blocked("Plaintext CRI inspection unavailable.") from None


def _host_pid(node, transport):
    try:
        raw = transport(["docker", "inspect", "-f", "{{json .State.Pid}}", node],
                        timeout=6, max_output=64)
        if not re.fullmatch(rb"[1-9][0-9]{0,9}\n?", raw):
            raise ValueError()
        pid = int(raw)
        if not 1 < pid < 2**31:
            raise ValueError()
        return pid
    except (wg.node_images.Blocked, ValueError, TypeError):
        raise Blocked("Plaintext node host PID unavailable.") from None


def _bounded_root(argv):
    """Drain only <=512 root-output bytes; kill/reap isolated process group."""
    proc = None
    selector = selectors.DefaultSelector()
    result = bytearray()
    deadline = time.monotonic() + 30
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, start_new_session=True,
                                env={k: os.environ[k] for k in ("PATH", "HOME", "DOCKER_HOST") if k in os.environ})
        os.set_blocking(proc.stdout.fileno(), False)
        selector.register(proc.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Blocked("Plaintext root helper deadline exceeded.")
            for key, _ in selector.select(remaining):
                try:
                    chunk = os.read(key.fileobj.fileno(), min(512 + 1 - len(result), 513))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    result.extend(chunk)
                    if len(result) > 512:
                        raise Blocked("Plaintext root helper output exceeded cap.")
        if proc.wait(timeout=max(.001, deadline-time.monotonic())) != 0:
            raise Blocked("Plaintext root helper or CNI ingress blocked.")
        return bytes(result)
    except (OSError, subprocess.TimeoutExpired):
        raise Blocked("Plaintext root helper unavailable.") from None
    finally:
        selector.close()
        if proc is not None:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait(timeout=2)
            proc.stdout.close()


def run(owner, source_api, operator, gateway_uid, selected_uid, selected_ip, gateway_pod,
        gateway_id, ids, *, transport=None, root=None):
    """Recheck both UID-bound Pod→CRI netns before/after fixed root helper."""
    if transport is None:
        transport = wg.node_images._bounded
    if not (owner.names[1] in owner.owned and owner.names[0] in owner.owned and
            type(gateway_id) is int and 1 <= gateway_id <= 0xffffff and
            isinstance(selected_uid, str) and wg.lifecycle.UID.fullmatch(selected_uid) and
            isinstance(gateway_uid, str) and wg.lifecycle.UID.fullmatch(gateway_uid)):
        raise Blocked("Plaintext owned fixture identity incomplete.")
    gateway_name = gateway_pod["metadata"].get("name", "")
    gateway_pod_uid = gateway_pod["metadata"].get("uid", "")
    if not (gateway_pod["metadata"].get("namespace") == wg.SYSTEM and
            gateway_pod_uid and wg.lifecycle.UID.fullmatch(gateway_pod_uid) and
            gateway_pod["metadata"].get("labels", {}).get(wg.PREFIX + "gateway-uid") == gateway_uid and
            gateway_pod["status"].get("podIP")):
        raise Blocked("Plaintext gateway Pod identity missing.")
    gateway_ip = wg.ipv4(gateway_pod["status"]["podIP"])
    selected_ip = wg.ipv4(selected_ip)
    def recheck():
        client = source_api.get("pod", wg.CLIENT, owner.names[1])
        gateway = operator.get_object("pod", gateway_name, wg.SYSTEM)
        if (client["metadata"].get("uid") != selected_uid or
                client["metadata"].get("labels", {}).get(wg.OWN) != owner.token or
                client["metadata"].get("annotations", {}).get(wg.PREFIX + "datapath-ready") != "true" or
                client["status"].get("phase") != "Running" or client["status"].get("podIP") != selected_ip or
                gateway["metadata"].get("uid") != gateway_pod_uid or
                gateway["metadata"].get("labels", {}).get(wg.PREFIX + "gateway-uid") != gateway_uid or
                gateway["status"].get("podIP") != gateway_ip):
            raise Blocked("Plaintext selected or gateway Pod UID/IP changed.")
        states = []
        for pod, namespace, name, uid, image in ((client, owner.names[1], wg.CLIENT, selected_uid, ids["selected"]),
                                                  (gateway, wg.SYSTEM, gateway_name, gateway_pod_uid, ids["gateway"])):
            node = pod["spec"].get("nodeName")
            matches = [c for c in pod["status"].get("containerStatuses", []) if c.get("name") ==
                       ("client" if name == wg.CLIENT else "gateway")]
            if (pod["metadata"].get("namespace") != namespace or
                    pod["metadata"].get("name") != name or
                    node not in wg.node_images.NODES or len(matches) != 1 or
                    matches[0].get("ready") is not True or matches[0].get("imageID") != image or
                    not wg_transport.CONTAINER.fullmatch(matches[0].get("containerID", ""))):
                raise Blocked("Plaintext selected/gateway runtime CRI identity invalid.")
            sid = sandbox_id(_node_cmd(node, ["pods", "-o", "json"], transport), uid, namespace, name)
            pid = sandbox_pid(_node_cmd(node, ["inspectp", "-o", "json", sid], transport),
                              sid, uid, namespace, name, pod["status"]["podIP"])
            states.append((node, sid, pid, uid))
        return tuple(states)
    before = recheck()
    if root is None:
        path = Path(__file__).with_name("plaintext_root.py")
        args = ["sudo", "-n", "/usr/bin/python3", str(path),
                str(_host_pid(before[0][0], transport)), str(before[0][2]),
                str(_host_pid(before[1][0], transport)), str(before[1][2]),
                selected_ip, gateway_ip, str(gateway_id)]
        raw = _bounded_root(args)
    else:
        raw = root(before)
    if recheck() != before:
        raise Blocked("Plaintext selected/gateway CRI sandbox changed during probe.")
    return proof(raw, source=selected_ip, gateway=gateway_ip, vni=gateway_id)
