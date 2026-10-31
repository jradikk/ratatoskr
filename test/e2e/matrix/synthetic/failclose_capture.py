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
                defaults[0].get("type") != "unreachable" or
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
        mark, sep, mask = hits[0]["fwmark"].partition("/")
        if (not sep or hits[0].get("protocol") not in (PROTOCOL, str(PROTOCOL)) or
                hits[0].get("table") not in (table, str(table)) or
                int(mark, 16) != 0x200000 or int(mask, 16) != 0xf00000):
            raise ValueError()
        return True
    except (KeyError, ValueError, TypeError, AttributeError):
        raise Blocked("Owned RPDB marked table selector unverified.") from None


def capture_proof(raw, source, api_ip):
    if not isinstance(raw, bytes) or len(raw) > 4096:
        raise Blocked("Header-only capture exceeded limit.")
    try:
        lines = raw.decode("ascii").splitlines()
        pat = re.compile(r"^[0-9]+\.[0-9]+ IP " + re.escape(source) + r"\.[0-9]{1,5} > (" +
                         re.escape(api_ip) + "|" + re.escape(DEST) + r")\.(443|8080): Flags \[S\](?:,.*)?$")
        if not 1 <= len(lines) <= 32:
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
        raise Blocked("API SYN positive control missing or selected SYN egress detected.") from None


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


def namespace_path(node_host_pid, sandbox_node_pid, *, readlink=os.readlink, open_fd=os.open, fstat=os.fstat):
    if (type(node_host_pid) is not int or type(sandbox_node_pid) is not int or
            not 1 < node_host_pid < 2**31 or not 1 < sandbox_node_pid < 2**31):
        raise Blocked("Node/sandbox PID invalid.")
    path = f"/proc/{node_host_pid}/root/proc/{sandbox_node_pid}/ns/net"
    fd = None
    try:
        fd = open_fd(path, os.O_RDONLY | os.O_CLOEXEC)
        link = readlink(path)
        info = fstat(fd)
        match = NS.fullmatch(link)
        if not match or info.st_ino != int(match.group(1)):
            raise ValueError()
        return fd
    except (OSError, ValueError, TypeError):
        if fd is not None:
            os.close(fd)
        raise Blocked("Selected source nsfs identity cannot be pinned.") from None


def capture(argv, trigger, *, timeout=14):
    """Bounded header-only tcpdump after listening readiness; no pcap retained."""
    proc = None
    sel = selectors.DefaultSelector()
    out, err = bytearray(), bytearray()
    end = time.monotonic() + timeout
    try:
        proc = subprocess.Popen(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.PIPE, start_new_session=True,
                                env={k: os.environ[k] for k in ("PATH", "HOME") if k in os.environ})
        for stream in (proc.stdout, proc.stderr):
            os.set_blocking(stream.fileno(), False)
            sel.register(stream, selectors.EVENT_READ)
        ready = False
        completed = False
        stop_at = None
        stopped = False
        while sel.get_map():
            remaining = end - time.monotonic()
            if remaining <= 0:
                raise Blocked("Source SYN capture deadline exceeded.")
            if completed and not stopped and time.monotonic() >= stop_at:
                try:
                    os.killpg(proc.pid, signal.SIGINT)
                except ProcessLookupError:
                    raise Blocked("Source SYN capture exited before bounded completion.") from None
                stopped = True
            if proc.poll() is not None and not completed:
                raise Blocked("Source SYN capture exited before probe readiness.")
            for key, _ in sel.select(min(remaining, .2)):
                try:
                    data = os.read(key.fileobj.fileno(), 1024)
                except BlockingIOError:
                    continue
                if not data:
                    sel.unregister(key.fileobj)
                    continue
                target = err if key.fileobj is proc.stderr else out
                target.extend(data)
                if len(err) > 2048 or len(out) > 4096:
                    raise Blocked("Header-only source capture cap exceeded.")
                if not ready and b"listening on eth0" in err:
                    ready = True
            if ready and not completed:
                # The caller controls only the fixed approved helper probe;
                # any failure remains a non-pass and the process is reaped.
                trigger()
                completed = True
                stop_at = time.monotonic() + .5
        if not ready or not completed or not stopped or proc.poll() not in (0, 130, -signal.SIGINT):
            raise Blocked("Source SYN capture not started/completed.")
        return bytes(out)
    except (OSError, ValueError, subprocess.TimeoutExpired):
        raise Blocked("Source SYN capture unavailable.") from None
    finally:
        sel.close()
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGTERM)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=2)
            except subprocess.TimeoutExpired:
                os.killpg(proc.pid, signal.SIGKILL)
                proc.wait(timeout=2)
            proc.stdout.close()
            proc.stderr.close()


def prove(api, namespace, uid, image_id, gateway_id, api_ip, *, transport=node_images._bounded,
          trigger=None, local=local_exec, capture_fn=capture):
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
    fd = namespace_path(host_pid, pid)
    try:
        # nsenter changes network only; ip is read-only and cap/output bounded.
        # sudo closes inherited FDs, so retain the open FD locally and use
        # its proc path for nsenter; recheck inode + CRI identity afterward.
        path = f"/proc/{host_pid}/root/proc/{pid}/ns/net"
        def same_namespace():
            try:
                if os.stat(path).st_ino != os.fstat(fd).st_ino:
                    raise ValueError()
            except (OSError, ValueError):
                raise Blocked("Pinned source netns changed during observation.") from None
        same_namespace()
        ns = ["sudo", "-n", "nsenter", "--net=" + path, "--"]
        table = TABLE_BASE | (gateway_id & 0xffff)
        route_proof(local(ns + ["/usr/sbin/ip", "-j", "-4", "route", "show", "table", str(table)],
                          limit=8192), table)
        rule_proof(local(ns + ["/usr/sbin/ip", "-j", "-4", "rule", "show"], limit=65536), table)
        recheck()
        same_namespace()
        # Fixed BPF: selected destination and known API positive-control only.
        bpf = ("tcp and src host " + source + " and (dst host " + DEST + " and dst port 8080 or dst host " + api_ip +
               " and dst port 443) and tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn")
        command = ns + ["/usr/bin/tcpdump", "-i", "eth0", "-nn", "-l", "-tt", "-s", "96", "-Q", "out", bpf]
        raw = capture_fn(command, trigger, timeout=14)
        recheck()
        same_namespace()
        capture_proof(raw, source, api_ip)
        route_proof(local(ns + ["/usr/sbin/ip", "-j", "-4", "route", "show", "table", str(table)],
                          limit=8192), table)
        rule_proof(local(ns + ["/usr/sbin/ip", "-j", "-4", "rule", "show"], limit=65536), table)
        recheck()
        same_namespace()
        return True
    finally:
        os.close(fd)
