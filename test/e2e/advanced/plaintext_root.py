#!/usr/bin/env python3
"""Fixed root-only GENEVE plaintext probe; no shell, pcap or packet output."""
import fcntl
import ipaddress
import json
import os
import re
import selectors
import signal
import socket
import struct
import subprocess
import sys
import time

NS_GET_NSTYPE = 0xB703
CLONE_NEWNET = 0x40000000
MARK = 0x00400000
HEX_NFT = 65536

# Fixed stage-only diagnostics; never output raw nft JSON, packets or errors.
STAGES = frozenset({"validate", "pin-source", "pin-gateway", "guard-before",
                    "gnv-before", "capture-start", "send", "capture-finish",
                    "guard-after", "gnv-after", "header-parse", "unknown"})
_stage = "validate"


def checkpoint(stage):
    global _stage
    if stage not in STAGES:
        raise ValueError()
    _stage = stage


def validated(argv):
    if (len(argv) != 7 or not all(re.fullmatch(r"[1-9][0-9]{0,9}", a) for a in
                                  (argv[0], argv[1], argv[2], argv[3], argv[6]))):
        raise ValueError()
    host_src, pid_src, host_gw, pid_gw, vni = map(int, (argv[0], argv[1], argv[2], argv[3], argv[6]))
    source, gateway = [str(ipaddress.IPv4Address(x)) for x in argv[4:6]]
    if (min(host_src, pid_src, host_gw, pid_gw) <= 1 or max(host_src, pid_src, host_gw, pid_gw) >= 2**31 or
            not 1 <= vni <= 0xffffff or source != argv[4] or gateway != argv[5] or source == gateway):
        raise ValueError()
    return host_src, pid_src, host_gw, pid_gw, source, gateway, vni


def pin(host, pid):
    path = f"/proc/{host}/root/proc/{pid}/ns/net"
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        link = os.readlink(path)
        if (fcntl.ioctl(fd, NS_GET_NSTYPE) != CLONE_NEWNET or
                not re.fullmatch(r"net:\[([1-9][0-9]{0,18})\]", link) or
                os.fstat(fd).st_ino != int(link[5:-1])):
            raise ValueError()
        return fd
    except BaseException:
        os.close(fd)
        raise


def run(argv, fd, *, limit=HEX_NFT, timeout=4):
    result = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                            pass_fds=(fd,) if fd >= 0 else (), env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    if result.returncode or len(result.stdout) > limit:
        raise ValueError()
    return result.stdout


def guard(raw):
    """Single exact INPUT rule with iif != rtkwg0, UDP6081, counter then drop."""
    value = json.loads(raw)["nftables"]
    if (not isinstance(value, list) or len(value) not in (2, 3) or
            any(not isinstance(entry, dict) or len(entry) != 1 or
                not set(entry) <= {"metainfo", "chain", "rule"} for entry in value)):
        raise ValueError()
    chains = [e["chain"] for e in value if "chain" in e]
    rules = [e["rule"] for e in value if "rule" in e]
    if (len(chains) != 1 or len(rules) != 1 or
            {k: chains[0].get(k) for k in ("family", "table", "name", "type", "hook", "prio", "policy")} !=
            {"family": "inet", "table": "ratatoskr_wg", "name": "input", "type": "filter",
             "hook": "input", "prio": 0, "policy": "accept"}):
        raise ValueError()
    rule = rules[0]
    expr = rule["expr"]
    if ((rule.get("family"), rule.get("table"), rule.get("chain")) != ("inet", "ratatoskr_wg", "input") or
            len(expr) != 4 or expr[0] != {"match": {"op": "!=", "left": {"meta": {"key": "iifname"}},
                                                     "right": "rtkwg0"}} or
            expr[1] != {"match": {"op": "==", "left": {"payload": {"protocol": "udp", "field": "dport"}},
                                                     "right": 6081}} or expr[3] != {"drop": None}):
        raise ValueError()
    counter = expr[2]["counter"]
    packets = counter["packets"]
    if (type(packets) is not int or not 0 <= packets <= 2**64-1 or
            type(counter.get("bytes")) is not int or counter["bytes"] < 0):
        raise ValueError()
    return packets


def rx_packets(raw):
    values = json.loads(raw)
    if (not isinstance(values, list) or len(values) != 1 or values[0].get("ifname") != "gnv0"):
        raise ValueError()
    value = values[0].get("stats64", values[0].get("stats", {})).get("rx", {}).get("packets")
    if type(value) is not int or not 0 <= value < 2**64:
        raise ValueError()
    return value


def frame(vni, source, gateway):
    """Synthetic valid GENEVE/TEB + Ethernet + IPv4/UDP, no credentials."""
    outer = bytes([0, 0, 0x65, 0x58]) + (vni << 8).to_bytes(4, "big")
    ethernet = bytes.fromhex("0200000000020200000000030800")
    src, dst = socket.inet_aton(source), socket.inet_aton(gateway)
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, 17, 0, src, dst)
    return outer + ethernet + ip + b"\x00" * 8


def route_next_hop(raw, source, gateway):
    """Use only kernel-selected eth0 next hop for this owned PodIP/destination."""
    values = json.loads(raw)
    if not isinstance(values, list) or len(values) != 1:
        raise ValueError()
    route = values[0]
    if (route.get("dst") != gateway or route.get("dev") != "eth0" or
            route.get("prefsrc") != source or route.get("type") in ("unreachable", "prohibit", "blackhole")):
        raise ValueError()
    return str(ipaddress.IPv4Address(route.get("gateway", gateway)))


def mac(raw):
    if not isinstance(raw, str) or not re.fullmatch(r"[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5}", raw):
        raise ValueError()
    value = bytes.fromhex(raw.replace(":", ""))
    if value == bytes(6) or value[0] & 1:
        raise ValueError()
    return value


def link_mac(raw):
    values = json.loads(raw)
    if not isinstance(values, list) or len(values) != 1 or values[0].get("ifname") != "eth0":
        raise ValueError()
    return mac(values[0].get("address"))


def neighbor_mac(raw, next_hop):
    values = json.loads(raw)
    if not isinstance(values, list) or len(values) > 16:
        raise ValueError()
    # `ip neigh show ... dev eth0` omits the redundant dev field. The
    # fixed query supplies the interface; an explicitly different dev is denied.
    neighbors = [entry for entry in values if entry.get("dst") == next_hop and
                 entry.get("dev", "eth0") == "eth0"]
    # Measured iproute2 `ip -j neigh` emits `state:["REACHABLE"]` (also
    # `["PERMANENT"]`) rather than a scalar. Accept one exact live state only;
    # never treat FAILED/INCOMPLETE or an ambiguous multi-state list as a MAC.
    state = neighbors[0].get("state") if len(neighbors) == 1 else None
    if (len(neighbors) != 1 or
            state not in (["REACHABLE"], ["STALE"], ["DELAY"], ["PROBE"], ["PERMANENT"])):
        raise ValueError()
    return mac(neighbors[0].get("lladdr"))


def ip_checksum(data):
    words = sum(int.from_bytes(data[i:i+2], "big") for i in range(0, len(data), 2))
    while words >> 16:
        words = (words & 0xffff) + (words >> 16)
    return (~words) & 0xffff


def packet(source, gateway, vni, src_mac, dst_mac):
    """Fixed synthetic L2 IPv4/UDP6081 frame, never a supplied payload."""
    payload = frame(vni, source, gateway)
    src_ip, dst_ip = socket.inet_aton(source), socket.inet_aton(gateway)
    udp = struct.pack("!HHHH", 40000, 6081, 8+len(payload), 0) + payload
    ip = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 20+len(udp), 0, 0, 64, 17, 0, src_ip, dst_ip)
    ip = ip[:10] + struct.pack("!H", ip_checksum(ip)) + ip[12:]
    return dst_mac + src_mac + b"\x08\x00" + ip + udp


def send_in_source(fd, source, gateway, vni):
    """Pin selected netns; bypass only its OUTPUT hook via fixed AF_PACKET L2."""
    argv = ["/usr/bin/nsenter", "--net=/proc/self/fd/" + str(fd), "--", "/usr/bin/python3",
            os.path.abspath(__file__), "--send", source, gateway, str(vni)]
    run(argv, fd, limit=0, timeout=4)


def send(argv):
    if (len(argv) != 3 or not re.fullmatch(r"[1-9][0-9]{0,7}", argv[2]) or
            argv[0] != str(ipaddress.IPv4Address(argv[0])) or
            argv[1] != str(ipaddress.IPv4Address(argv[1]))):
        raise ValueError()
    source, gateway, vni = argv[0], argv[1], int(argv[2])
    if not 1 <= vni <= 0xffffff or source == gateway:
        raise ValueError()
    # SO_MARK on a datagram still enters the production OUTPUT guard; AF_PACKET
    # is deliberately used ONLY by this separately opted-in negative proof.
    route = run(["/usr/sbin/ip", "-j", "-4", "route", "get", gateway,
                 "mark", "0x400000"], -1, limit=4096, timeout=2)
    next_hop = route_next_hop(route, source, gateway)
    own = link_mac(run(["/usr/sbin/ip", "-j", "link", "show", "dev", "eth0"],
                       -1, limit=4096, timeout=2))
    neighbor = neighbor_mac(run(["/usr/sbin/ip", "-j", "neigh", "show", "to", next_hop,
                                  "dev", "eth0"], -1, limit=4096, timeout=2), next_hop)
    raw = packet(source, gateway, vni, own, neighbor)
    sock = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.htons(0x0800))
    try:
        sock.bind(("eth0", 0))
        for _ in range(3):
            if sock.send(raw) != len(raw):
                raise ValueError()
    finally:
        sock.close()


def collect(args):
    host_src, pid_src, host_gw, pid_gw, source, gateway, vni = args
    checkpoint("pin-source")
    src_fd, gw_fd = pin(host_src, pid_src), None
    proc = None
    try:
        checkpoint("pin-gateway")
        gw_fd = pin(host_gw, pid_gw)
        base = ["/usr/bin/nsenter", "--net=/proc/self/fd/" + str(gw_fd), "--"]
        nft = base + ["/usr/sbin/nft", "-j", "list", "chain", "inet", "ratatoskr_wg", "input"]
        checkpoint("guard-before")
        before = guard(run(nft, gw_fd))
        link = base + ["/usr/sbin/ip", "-j", "-s", "link", "show", "dev", "gnv0"]
        checkpoint("gnv-before")
        rx_before = rx_packets(run(link, gw_fd))
        bpf = "udp and src host " + source + " and dst host " + gateway + " and dst port 6081"
        checkpoint("capture-start")
        proc = subprocess.Popen(base + ["/usr/bin/tcpdump", "-i", "eth0", "-nn", "-l", "-tt", "-s", "96", "-Q", "in", bpf],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
                                pass_fds=(gw_fd,), start_new_session=True,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        selector = selectors.DefaultSelector()
        output, errors = bytearray(), bytearray()
        try:
            for stream in (proc.stdout, proc.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            ready, stopped = False, False
            deadline = time.monotonic() + 12
            stop_at = None
            while selector.get_map():
                if time.monotonic() >= deadline:
                    raise ValueError()
                for key, _ in selector.select(.1):
                    try:
                        data = os.read(key.fileobj.fileno(), 1024)
                    except BlockingIOError:
                        continue
                    if not data:
                        selector.unregister(key.fileobj)
                        continue
                    target = errors if key.fileobj is proc.stderr else output
                    target.extend(data)
                    if len(errors) > 2048 or len(output) > 4096:
                        raise ValueError()
                    if b"listening on" in errors:
                        ready = True
                if ready and stop_at is None:
                    if proc.poll() is not None:
                        raise ValueError()
                    checkpoint("send")
                    send_in_source(src_fd, source, gateway, vni)
                    checkpoint("capture-finish")
                    stop_at = time.monotonic() + .5
                if stop_at is not None and not stopped and time.monotonic() >= stop_at:
                    os.killpg(proc.pid, signal.SIGINT)
                    stopped = True
            if not ready or not stopped or proc.wait(timeout=1) not in (0, 130, -signal.SIGINT):
                raise ValueError()
        finally:
            selector.close()
        checkpoint("guard-after")
        after = guard(run(nft, gw_fd))
        checkpoint("gnv-after")
        rx_after = rx_packets(run(link, gw_fd))
        if rx_after < rx_before:
            raise ValueError()
        checkpoint("header-parse")
        lines = [line for line in output.decode("ascii").splitlines() if line.strip()]
        # Only fixed tuple/header shape may be returned, never payload/pcap.
        match = re.compile(r"^[0-9]+\.[0-9]+ IP " + re.escape(source) +
                           r"\.[0-9]{1,5} > " + re.escape(gateway) + r"\.6081: UDP, length [0-9]{1,4}$")
        if (len(output.decode("ascii").splitlines()) > 6 or
                any(not match.fullmatch(line) for line in lines)):
            raise ValueError()
        # The encrypted NetworkPolicy deliberately denies plaintext UDP6081.
        # If it intercepts before gateway eth0, zero ingress is not nft proof:
        # return fixed zero count and let the parent fail closed/inconclusive.
        return {"source": source, "gateway": gateway, "vni": vni,
                "ethIn": len(lines), "gnvIn": rx_after - rx_before, "dropBefore": before,
                "dropAfter": after, "sent": 3}
    finally:
        if proc is not None:
            try: os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError: pass
            proc.wait(timeout=2)
            proc.stdout.close(); proc.stderr.close()
        os.close(src_fd)
        if gw_fd is not None: os.close(gw_fd)


def main():
    checkpoint("validate")
    try:
        if sys.argv[1:2] == ["--send"]:
            send(sys.argv[2:]); return 0
        result = collect(validated(sys.argv[1:]))
        print(json.dumps(result, separators=(",", ":")))
        return 0
    except (OSError, ValueError, UnicodeError, KeyError, TypeError, AttributeError,
            subprocess.TimeoutExpired):
        # A bounded, authored category is the *only* root failure output.
        print(json.dumps({"blocked": _stage}, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    sys.exit(main())
