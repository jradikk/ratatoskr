"""Bounded read-only final-gate fail-close: public CRI/netns and packet headers only."""
import ipaddress
import json
import os
import re
import selectors
import signal
import subprocess
import time

try:
    from . import lifecycle, node_images
except ImportError:
    import lifecycle
    import node_images


class Blocked(Exception):
    """Fixed safe diagnostics; never include raw CRI/capture output."""


CID = re.compile(r"containerd://([a-f0-9]{64})\Z")
HEX = re.compile(r"[a-f0-9]{64}\Z")
NS = re.compile(r"net:\[([1-9][0-9]{0,18})\]\Z")
TABLE_BASE = 0x52540000
PROTOCOL = 186
METRIC = 4294967295
PRIORITY = 10998
DEST = "10.88.0.1"


def identity(pod, namespace, uid, image_id):
    try:
        meta, spec, status = pod["metadata"], pod["spec"], pod["status"]
        containers = [v for v in status["containerStatuses"] if v.get("name") == "client"]
        ip = ipaddress.ip_address(status["podIP"])
        if (meta["namespace"] != namespace or meta["name"] != "synthetic-client" or
                meta["uid"] != uid or meta.get("deletionTimestamp") or not lifecycle.UID.fullmatch(uid) or
                spec["nodeName"] not in node_images.NODES or status.get("phase") != "Running" or
                len(containers) != 1 or containers[0].get("imageID") != image_id or
                containers[0].get("ready") is not True or not CID.fullmatch(containers[0].get("containerID", "")) or
                ip.version != 4 or ip.is_unspecified or ip.is_multicast):
            raise ValueError()
        return spec["nodeName"], str(ip), containers[0]["containerID"]
    except (ValueError, KeyError, TypeError, AttributeError):
        raise Blocked("Selected Pod UID/image/node/CRI identity unavailable.") from None


def sandbox_list(raw, uid, namespace):
    try:
        items = json.loads(raw)["items"]
        if not isinstance(items, list) or len(items) > 512:
            raise ValueError()
        matches = [v for v in items if v.get("state") == "SANDBOX_READY" and
                   v.get("metadata", {}).get("name") == "synthetic-client" and
                   v["metadata"].get("namespace") == namespace and v["metadata"].get("uid") == uid and
                   v.get("labels", {}).get("io.kubernetes.pod.uid") == uid]
        if len(matches) != 1 or not HEX.fullmatch(matches[0]["id"]):
            raise ValueError()
        return matches[0]["id"]
    except (KeyError, ValueError, TypeError, AttributeError):
        raise Blocked("Unique READY CRI sandbox identity unavailable.") from None


def sandbox_status(raw, sid, uid, namespace, ip):
    try:
        obj = json.loads(raw)
        value, info = obj["status"], obj["info"]
        md = value["metadata"]
        if (value["id"] != sid or value["state"] != "SANDBOX_READY" or
                (md["name"], md["namespace"], md["uid"]) != ("synthetic-client", namespace, uid) or
                value["labels"].get("io.kubernetes.pod.uid") != uid or value["network"]["ip"] != ip):
            raise ValueError()
        if isinstance(info, dict) and isinstance(info.get("info"), str):
            info = json.loads(info["info"])
        pid = info["pid"]
        nets = [v.get("path") for v in info["runtimeSpec"]["linux"]["namespaces"]
                if v.get("type") == "network"]
        if (type(pid) is not int or not 1 < pid < 2**31 or len(nets) != 1 or
                not isinstance(nets[0], str) or not nets[0].startswith("/var/run/netns/")):
            raise ValueError()
        return pid
    except (KeyError, ValueError, TypeError, AttributeError):
        raise Blocked("CRI sandbox UID/IP/PID/netns invalid.") from None


def route_proof(raw, table):
    try:
        values = json.loads(raw)
        if not isinstance(values, list) or len(values) > 32:
            raise ValueError()
        defaults = [v for v in values if v.get("dst", "default") in ("default", "0.0.0.0/0")]
        if (len(defaults) != 1 or
                defaults[0].get("type") not in ("unreachable", 7, "7") or
                defaults[0].get("protocol") not in (PROTOCOL, str(PROTOCOL)) or
                defaults[0].get("metric") != METRIC or
                any(v.get("table", table) not in (table, str(table)) for v in values)):
            raise ValueError()
        return True
    except (KeyError, ValueError, TypeError, AttributeError):
        raise Blocked("Owned unreachable default/no-unicast route unverified.") from None


def rule_proof(raw, table):
    try:
        values = json.loads(raw)
        if not isinstance(values, list) or len(values) > 1100:
            raise ValueError()
        hits = [v for v in values if v.get("priority") == PRIORITY]
        if len(hits) != 1 or not isinstance(hits[0].get("fwmark"), str):
            raise ValueError()
        hit = hits[0]
        # iproute2 `-N -j` emits separate fwmark/fwmask fields. An older
        # combined spelling is accepted only if the separate mask is absent;
        # ambiguous or conflicting forms cannot certify an owned selector.
        mark, sep, combined_mask = hit["fwmark"].partition("/")
        separate_mask = hit.get("fwmask")
        if sep:
            if separate_mask is not None:
                raise ValueError()
            mask = combined_mask
        else:
            if not isinstance(separate_mask, str):
                raise ValueError()
            mask = separate_mask
        if (not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", mark) or
                not re.fullmatch(r"0x[0-9a-fA-F]{1,8}", mask) or
                hit.get("protocol") not in (PROTOCOL, str(PROTOCOL)) or
                hit.get("table") not in (table, str(table)) or
                int(mark, 16) != 0x200000 or int(mask, 16) != 0xf00000):
            raise ValueError()
        return True
    except (KeyError, ValueError, TypeError, AttributeError):
        raise Blocked("Owned RPDB marked table selector unverified.") from None


def capture_category(raw, source, api_ip):
    """Fixed diagnostic only, never a positive-control or no-egress proof.

    Do not surface a captured address, port outside the two fixed categories,
    payload, API object or packet line. Unknown formatting stays untrusted.
    """
    if not isinstance(raw, bytes) or len(raw) > 4096:
        return "oversize-or-invalid"
    try:
        observed = raw.decode("ascii").splitlines()
        if len(observed) > 32:
            return "oversize-or-invalid"
        # tcpdump can leave one empty/whitespace line on stdout at SIGINT.
        # It is not a packet and never supplies the positive SYN control.
        lines = [line for line in observed if line.strip()]
        if not lines:
            return "empty"
        api, selected, other_443, other_6443, unknown = 0, 0, 0, 0, 0
        pattern = re.compile(r"^[0-9]+\.[0-9]+ IP " + re.escape(source) +
                             r"\.[0-9]{1,5} > ([0-9]{1,3}(?:\.[0-9]{1,3}){3})\.([0-9]{1,5}): Flags \[S\](?:,.*)?$")
        for line in lines:
            match = pattern.fullmatch(line)
            if match is None:
                unknown += 1
                continue
            target, port = match.groups()
            if (target, port) == (api_ip, "443"):
                api += 1
            elif (target, port) == (DEST, "8080"):
                selected += 1
            elif port == "443":
                other_443 += 1
            elif port == "6443":
                other_6443 += 1
            else:
                unknown += 1
        if selected:
            return "selected-egress-observed"
        if api and not (other_443 or other_6443 or unknown):
            return "api443-control-present"
        if other_6443 and not (api or other_443 or unknown):
            return "other6443-not-authorized"
        if other_443 and not (api or other_6443 or unknown):
            return "other443-not-authorized"
        return "unrecognized-or-mixed"
    except (UnicodeError, ValueError, TypeError):
        return "oversize-or-invalid"


def capture_proof(raw, source, api_ip):
    if not isinstance(raw, bytes) or len(raw) > 4096:
        raise Blocked("Header-only capture exceeded limit.")
    try:
        observed = raw.decode("ascii").splitlines()
        if len(observed) > 32:  # Count even blank lines against capture cap.
            raise ValueError()
        lines = [line for line in observed if line.strip()]
        pat = re.compile(r"^[0-9]+\.[0-9]+ IP " + re.escape(source) + r"\.[0-9]{1,5} > (" +
                         re.escape(api_ip) + "|" + re.escape(DEST) + r")\.(443|8080): Flags \[S\](?:,.*)?$")
        if not lines:
            raise ValueError()
        api, selected = 0, 0
        for line in lines:
            match = pat.fullmatch(line)
            if match is None:
                raise ValueError()
            target, port = match.groups()
            if (target, port) == (api_ip, "443"):
                api += 1
            elif (target, port) == (DEST, "8080"):
                selected += 1
            else:
                raise ValueError()
        if api < 1 or selected:
            raise ValueError()
        return True
    except (UnicodeError, ValueError, TypeError, AttributeError):
        raise Blocked("API SYN positive control missing or selected SYN egress detected (" +
                      capture_category(raw, source, api_ip) + ").") from None


def node_exec(argv, *, limit=65536, transport=node_images._bounded):
    try:
        return transport(argv, timeout=6, max_output=limit)
    except node_images.Blocked:
        raise Blocked("Read-only CRI/netns inspection unavailable.") from None


def local_exec(argv, *, limit=8192, timeout=6):
    try:
        result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, env={k: os.environ[k] for k in ("PATH", "HOME", "DOCKER_HOST")
                                                         if k in os.environ}, timeout=timeout, check=False)
        if result.returncode or len(result.stdout) > limit:
            raise ValueError()
        return result.stdout
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise Blocked("Host namespace/tool inspection unavailable.") from None


def node_pid(raw):
    try:
        value = json.loads(raw)
        if not isinstance(value, list) or len(value) != 1:
            raise ValueError()
        pid = value[0]["State"]["Pid"]
        if type(pid) is not int or not 1 < pid < 2**31:
            raise ValueError()
        return pid
    except (ValueError, KeyError, IndexError, TypeError, AttributeError):
        raise Blocked("Node host PID invalid.") from None


def root_collect(node_host_pid, sandbox_pid, table, source, api_ip, trigger, *,
                 launcher=subprocess.Popen, clock=time.monotonic):
    """Fixed sudo helper protocol: READY -> approved trigger -> STOP -> JSON.

    Root opens/pins nsfs itself; caller never traverses root's proc path.
    A failed/early helper or extra output is never no-egress evidence.
    """
    path = os.path.join(os.path.dirname(__file__), "root_capture.py")
    args = ["sudo", "-n", "/usr/bin/python3", path, str(node_host_pid), str(sandbox_pid),
            str(table), source, api_ip]
    proc = None
    selector = selectors.DefaultSelector()
    stdout, stderr = bytearray(), bytearray()
    end = clock() + 32
    try:
        proc = launcher(args, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                        stderr=subprocess.PIPE, start_new_session=True,
                        env={k: os.environ[k] for k in ("PATH", "HOME") if k in os.environ})
        for stream in (proc.stdout, proc.stderr):
            os.set_blocking(stream.fileno(), False)
            selector.register(stream, selectors.EVENT_READ)
        ready, sent = False, False
        while selector.get_map():
            if clock() >= end:
                raise Blocked("Root source capture deadline exceeded.")
            if proc.poll() is not None and not ready:
                raise Blocked("Root source netns pin or capture readiness failed.")
            for key, _ in selector.select(min(.1, end-clock())):
                try:
                    chunk = os.read(key.fileobj.fileno(), 2048)
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                    continue
                target = stderr if key.fileobj is proc.stderr else stdout
                target.extend(chunk)
                if len(stdout) > 86016 or len(stderr) > 1024:
                    raise Blocked("Root source capture output exceeded cap.")
            if not ready and stdout:
                if not b"READY\n".startswith(stdout):
                    raise Blocked("Root source capture readiness malformed.")
                if stdout != b"READY\n":
                    continue  # READY may arrive across multiple pipe reads.
                ready = True
                trigger()
                proc.stdin.write(b"STOP\n")
                proc.stdin.flush()
                proc.stdin.close()
                sent = True
        if not ready or not sent or proc.wait(timeout=max(.001, end-clock())) != 0:
            raise Blocked("Root source capture did not complete.")
        raw = bytes(stdout)
        if not raw.startswith(b"READY\n"):
            raise Blocked("Root source capture result malformed.")
        try:
            result = json.loads(raw[len(b"READY\n"):])
            if not isinstance(result, dict) or set(result) != {"routeBefore", "ruleBefore", "capture", "routeAfter", "ruleAfter"}:
                raise ValueError()
            if any(not isinstance(v, str) for v in result.values()):
                raise ValueError()
            return result
        except (ValueError, UnicodeError, TypeError):
            raise Blocked("Root source capture result malformed.") from None
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise Blocked("Root source capture unavailable.") from None
    finally:
        selector.close()
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            proc.wait(timeout=2)
            if proc.stdin:
                proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()


def prove(api, namespace, uid, image_id, gateway_id, api_ip, *, transport=node_images._bounded,
          trigger=None, local=local_exec, collect_fn=root_collect):
    """Require exact UID-bound closed routes and live positive-control capture.

    `trigger` is the existing fixed helper `outage-capture` probe; its exit0
    alone is never sufficient. No cluster API, node CRI or host process runs
    until explicitly invoked by the final-gate outage runner.
    """
    if (not isinstance(uid, str) or not lifecycle.UID.fullmatch(uid) or type(gateway_id) is not int or
            not 1 <= gateway_id <= 0xffffff or trigger is None):
        raise Blocked("Selected capture identity or approved probe missing.")
    try:
        api_ip = str(ipaddress.IPv4Address(api_ip))
    except (ValueError, TypeError):
        raise Blocked("Direct API IPv4 invalid for capture.") from None
    pod = api.get("pod", "synthetic-client", namespace)
    node, source, container_id = identity(pod, namespace, uid, image_id)
    prefix = ["docker", "exec", node, "/bin/crictl", "--runtime-endpoint", node_images.RUNTIME]
    def inspect(what, sid=None):
        argv = prefix + (["pods", "-o", "json"] if what == "pods" else
                         ["inspectp", "-o", "json", sid])
        try:
            return transport(argv, timeout=6, max_output=65536)
        except node_images.Blocked:
            raise Blocked("Selected CRI sandbox inspection unavailable.") from None
    sid = sandbox_list(inspect("pods"), uid, namespace)
    pid = sandbox_status(inspect("status", sid), sid, uid, namespace, source)
    def recheck():
        current = api.get("pod", "synthetic-client", namespace)
        if (identity(current, namespace, uid, image_id) != (node, source, container_id) or
                sandbox_list(inspect("pods"), uid, namespace) != sid or
                sandbox_status(inspect("status", sid), sid, uid, namespace, source) != pid):
            raise Blocked("Selected Pod/CRI sandbox identity changed during capture.")
    recheck()
    raw = local(["docker", "inspect", "-f", "{{json .State.Pid}}", node], limit=64)
    try:
        if not isinstance(raw, bytes) or not re.fullmatch(rb"[1-9][0-9]{0,9}\n?", raw):
            raise ValueError()
        host_pid = int(raw)
        if host_pid <= 1:
            raise ValueError()
    except (ValueError, TypeError):
        raise Blocked("Node host PID unavailable.") from None
    recheck()
    table = TABLE_BASE | (gateway_id & 0xffff)
    result = collect_fn(host_pid, pid, table, source, api_ip, trigger)
    recheck()
    for field in ("routeBefore", "routeAfter"):
        route_proof(result[field].encode("ascii"), table)
    for field in ("ruleBefore", "ruleAfter"):
        rule_proof(result[field].encode("ascii"), table)
    capture_proof(result["capture"].encode("ascii"), source, api_ip)
    recheck()
    return True
