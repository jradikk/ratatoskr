"""Explicit-gated, read-only M7 failover collector against an existing release.

The operator removes/fails an already-owned gateway replica OUTSIDE this tool.
No live traffic, Kubernetes writes, logs, Secrets, or arbitrary exec are used.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import selectors
import signal
import subprocess
import sys
import time

PREFIX = "ratatoskr.skaldhall.io/"
UID = re.compile(r"[a-f0-9-]{8,64}\Z", re.I)
NAME = re.compile(r"[a-z0-9]([-a-z0-9]*[a-z0-9])?\Z")


class Blocked(Exception):
    pass


def need(ok):
    if not ok:
        raise Blocked("Identity, ownership, endpoint or failover assertion blocked.")


def ip4(ip):
    try:
        v = ipaddress.ip_address(ip)
    except (ValueError, TypeError):
        raise Blocked("Invalid endpoint IPv4.") from None
    need(v.version == 4 and not (v.is_unspecified or v.is_multicast or v.is_loopback))
    return str(v)


def owner(obj, kind, uid):
    return any(r.get("kind") == kind and r.get("uid") == uid and
               r.get("controller") is True for r in
               obj.get("metadata", {}).get("ownerReferences", []))


def fetch(context, kind, namespace, name):
    """Bounded kubectl JSON GET; never return CLI stderr, args from strict names."""
    need(all(type(x) is str and NAME.fullmatch(x) and len(x) <= 63
             for x in (context, kind, namespace, name)))
    argv = ["kubectl", "--context", context, "-n", namespace, "get", kind,
            name, "-o", "json", "--request-timeout=4s"]
    env = {k: os.environ[k] for k in ("PATH", "HOME", "KUBECONFIG") if k in os.environ}
    env["KUBECTL_KUBERC"] = "false"
    proc = None
    chunks = bytearray()
    end = time.monotonic() + 6
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env=env, start_new_session=True)
        with selectors.DefaultSelector() as selector:
            selector.register(proc.stdout, selectors.EVENT_READ)
            while selector.get_map():
                remaining = end - time.monotonic()
                if remaining <= 0:
                    raise Blocked("Read-only Kubernetes GET timed out.")
                for key, _ in selector.select(remaining):
                    chunk = os.read(key.fileobj.fileno(), min(4096, 262145 - len(chunks)))
                    if chunk:
                        chunks.extend(chunk)
                        if len(chunks) > 262144:
                            raise Blocked("Read-only Kubernetes GET exceeded size bound.")
                    else:
                        selector.unregister(key.fileobj)
            remaining = end - time.monotonic()
            if remaining <= 0 or proc.wait(timeout=remaining) != 0:
                raise Blocked("Read-only Kubernetes GET failed.")
        obj = json.loads(chunks)
        need(type(obj) is dict and obj.get("metadata", {}).get("namespace") == namespace
             and obj["metadata"].get("name") == name)
        return obj
    except (OSError, ValueError, subprocess.TimeoutExpired) as exc:
        raise Blocked("Read-only Kubernetes GET unavailable.") from None
    finally:
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise Blocked("Read-only Kubernetes child could not be reaped.") from None
            proc.stdout.close()


def endpoints(gw):
    meta, status = gw["metadata"], gw.get("status", {})
    need(not meta.get("deletionTimestamp") and
         status.get("observedGeneration") == meta.get("generation") and
         type(status.get("gatewayID")) is int and status["gatewayID"] > 0 and
         any(c.get("type") == "Ready" and c.get("status") == "True" and
             c.get("observedGeneration") == meta.get("generation")
             for c in status.get("conditions", [])))
    entries = status.get("endpoints")
    need(type(entries) is list and 1 <= len(entries) <= 3)
    active = {}
    for e in entries:
        need(type(e) is dict)
        if e.get("upstreamHealthy") is not True:
            continue
        ip = ip4(e.get("podIP"))
        need(ip not in active and UID.fullmatch(e.get("podUID", "")) and
             NAME.fullmatch(e.get("podName", "")) and
             re.fullmatch(r"[0-9a-f]{64}", e.get("appliedClientConfigHash", "")))
        active[ip] = e
    need(active and len(active) <= 3 and status.get("readyReplicas") == len(active))
    return active


def selected(pod, gateway, endpoint_ips):
    meta = pod["metadata"]
    need(not meta.get("deletionTimestamp") and UID.fullmatch(meta.get("uid", "")) and
         meta.get("labels", {}).get(PREFIX + "gateway") == gateway and
         pod.get("spec", {}).get("hostNetwork") is not True and
         ip4(pod.get("status", {}).get("podIP")))
    annotations = meta.get("annotations", {})
    need(annotations.get(PREFIX + "datapath-ready") == "true" and
         annotations.get(PREFIX + "agent-backend") == "iproute" and
         re.fullmatch(r"[0-9a-f]{64}", annotations.get(PREFIX + "agent-hash", "")))
    raw = annotations.get(PREFIX + "agent-config", "")
    need(type(raw) is str and len(raw) < 65536)
    cfg = json.loads(raw)
    need(type(cfg) is dict and type(cfg.get("identity")) is dict and
         cfg["identity"].get("uid") == meta["uid"] and
         cfg["identity"].get("namespace") == meta.get("namespace") and
         cfg["identity"].get("pod") == meta.get("name") and
         cfg.get("podIP") == pod["status"]["podIP"] and
         cfg.get("encryption") in ("none", "wireguard") and
         hashlib.sha256(raw.encode()).hexdigest() ==
         annotations[PREFIX + "agent-hash"])
    endpoint = ip4(cfg.get("endpoint"))
    need(endpoint in endpoint_ips)
    return endpoint


def snapshot(api, context, gateway_ns, gateway_name, pod_ns, pod_name,
             *, gateway_uid=None, pod_uid=None):
    gw = api(context, "egressgateway", gateway_ns, gateway_name)
    need(UID.fullmatch(gw["metadata"].get("uid", "")))
    if gateway_uid is not None:
        need(gateway_uid == gw["metadata"]["uid"])
    dep = api(context, "deployment", gateway_ns, gateway_name)
    need(owner(dep, "EgressGateway", gw["metadata"]["uid"]))
    active = endpoints(gw)
    for e in active.values():
        pod = api(context, "pod", gateway_ns, e["podName"])
        need(pod["metadata"].get("uid") == e["podUID"] and
             pod.get("status", {}).get("podIP") == e["podIP"] and
             not pod["metadata"].get("deletionTimestamp"))
        rsref = next((r for r in pod["metadata"].get("ownerReferences", [])
                      if r.get("kind") == "ReplicaSet" and r.get("controller") is True), None)
        need(rsref is not None and NAME.fullmatch(rsref.get("name", "")))
        rs = api(context, "replicaset", gateway_ns, rsref["name"])
        need(rs["metadata"].get("uid") == rsref.get("uid") and
             owner(rs, "Deployment", dep["metadata"]["uid"]))
    client = api(context, "pod", pod_ns, pod_name)
    if pod_uid is not None:
        need(client["metadata"].get("uid") == pod_uid)
    chosen = selected(client, gateway_name, active)
    ns_label = client["metadata"].get("labels", {}).get(PREFIX + "gateway-namespace")
    ns_annotation = client["metadata"].get("annotations", {}).get(PREFIX + "gateway-namespace")
    need(ns_label == gateway_ns or ns_annotation == gateway_ns)
    need(not (ns_label and ns_annotation and ns_label != ns_annotation))
    return {"gatewayUID": gw["metadata"]["uid"], "podUID": client["metadata"]["uid"],
            "gatewayID": gw["status"]["gatewayID"], "clientIP": client["status"]["podIP"],
            "active": frozenset(active), "chosen": chosen}


def observe(api, args, *, clock=time.monotonic, sleep=time.sleep):
    before = snapshot(api, *args)
    need(2 <= len(before["active"]) <= 3)
    deadline = clock() + 90
    while clock() < deadline:
        sleep(min(3, max(0, deadline - clock())))
        try:
            after = snapshot(api, *args, gateway_uid=before["gatewayUID"],
                             pod_uid=before["podUID"])
        except (Blocked, KeyError, TypeError, ValueError):
            continue  # transient reconciliation cannot count as a pass
        need(after["gatewayID"] == before["gatewayID"] and
             after["clientIP"] == before["clientIP"])
        if before["chosen"] not in after["active"]:
            if not (after["active"] < before["active"] and
                    after["chosen"] in after["active"] and
                    after["chosen"] != before["chosen"]):
                continue
            # Require a second read: a single transient status is not failover.
            sleep(2)
            try:
                again = snapshot(api, *args, gateway_uid=before["gatewayUID"],
                                 pod_uid=before["podUID"])
            except (Blocked, KeyError, TypeError, ValueError):
                continue
            if again == after:
                return {"observed": "control-plane-agent-failover", "traffic": "not-tested",
                        "establishedFlowContinuity": "not-asserted"}
    raise Blocked("Bounded affected-replica failover not observed.")


def main(argv=None):
    parser = argparse.ArgumentParser(description="Read-only M7 failover observation")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--context", required=True)
    parser.add_argument("--gateway-namespace", required=True)
    parser.add_argument("--gateway-name", required=True)
    parser.add_argument("--pod-namespace", required=True)
    parser.add_argument("--pod-name", required=True)
    args = parser.parse_args(argv)
    if not args.execute or os.environ.get("RATATOSKR_E2E_FINAL_GATE") != "1":
        parser.error("Explicit --execute and RATATOSKR_E2E_FINAL_GATE=1 required")
    try:
        result = observe(fetch, (args.context, args.gateway_namespace, args.gateway_name,
                                 args.pod_namespace, args.pod_name))
        print(json.dumps(result, sort_keys=True))
        return 0
    except (Blocked, KeyError, TypeError, ValueError):
        print("HA read-only observation blocked (no traffic acceptance evidence).", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
