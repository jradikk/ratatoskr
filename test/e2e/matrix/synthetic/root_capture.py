#!/usr/bin/env python3
"""Fixed-argv root-only read-only netns capture. No shell, file output or API tokens.

Invoked only as `sudo -n python3 <this file> <host-node-pid> <node-sandbox-pid>
<table> <source-ip> <api-ip>`. Stdout protocol: READY, then after one STOP on
stdin, a bounded JSON object of exact iproute/capture stdout. Never print raw
CRI, private values, tcpdump stderr or exceptions.
"""
import fcntl
import ipaddress
import json
import os
import re
import select
import selectors
import signal
import subprocess
import sys
import time

NS_GET_NSTYPE = 0xB703
CLONE_NEWNET = 0x40000000
PROTO = 186
METRIC = 4294967295
TABLE_BASE = 0x52540000


def validated(argv):
    if len(argv) != 5 or any(not re.fullmatch(r"[1-9][0-9]{0,9}", v) for v in argv[:3]):
        raise ValueError()
    host, sandbox, table = map(int, argv[:3])
    if not (1 < host < 2**31 and 1 < sandbox < 2**31 and
            table & 0xffff0000 == TABLE_BASE and table & 0xffff != 0):
        raise ValueError()
    source, api = (str(ipaddress.IPv4Address(value)) for value in argv[3:])
    if source != argv[3] or api != argv[4] or source == api or api == "10.88.0.1":
        raise ValueError()
    return host, sandbox, table, source, api


def pin_netns(host, sandbox):
    path = f"/proc/{host}/root/proc/{sandbox}/ns/net"
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        link = os.readlink(path)
        if (fcntl.ioctl(fd, NS_GET_NSTYPE) != CLONE_NEWNET or
                not re.fullmatch(r"net:\[([1-9][0-9]{0,18})\]", link) or
                int(link[5:-1]) != os.fstat(fd).st_ino):
            raise ValueError()
        return fd
    except BaseException:
        os.close(fd)
        raise


def bounded(argv, fd, *, timeout, limit):
    proc = subprocess.run(argv, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                          stderr=subprocess.DEVNULL, timeout=timeout, check=False,
                          pass_fds=(fd,), env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    if proc.returncode or len(proc.stdout) > limit:
        raise ValueError()
    return proc.stdout.decode("ascii")


def collect(host, sandbox, table, source, api, *, clock=time.monotonic):
    fd = pin_netns(host, sandbox)
    capture = None
    try:
        prefix = ["/usr/bin/nsenter", "--net=/proc/self/fd/" + str(fd), "--"]
        # -N forces numeric route/rule protocol IDs. Without it protocol 186
        # is rendered as the host rt_protos alias `bgp`, which the strict
        # owner-protocol parser must not infer from an editable name mapping.
        route = prefix + ["/usr/sbin/ip", "-N", "-j", "-4", "route", "show", "table", str(table)]
        rule = prefix + ["/usr/sbin/ip", "-N", "-j", "-4", "rule", "show"]
        before_route = bounded(route, fd, timeout=4, limit=8192)
        before_rule = bounded(rule, fd, timeout=4, limit=65536)
        bpf = ("tcp and src host " + source + " and (dst host 10.88.0.1 and dst port 8080 or dst host " + api +
               " and dst port 443) and tcp[tcpflags] & (tcp-syn|tcp-ack) = tcp-syn")
        capture = subprocess.Popen(prefix + ["/usr/bin/tcpdump", "-i", "eth0", "-nn", "-l", "-tt", "-s", "96",
                                             "-Q", "out", bpf], stdin=subprocess.DEVNULL,
                                   stdout=subprocess.PIPE, stderr=subprocess.PIPE, pass_fds=(fd,),
                                   start_new_session=True, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        selector = selectors.DefaultSelector()
        packets, diagnostic = bytearray(), bytearray()
        try:
            for stream in (capture.stdout, capture.stderr):
                os.set_blocking(stream.fileno(), False)
                selector.register(stream, selectors.EVENT_READ)
            ready = False
            stopped = False
            deadline = clock() + 20
            stop_at = None
            while selector.get_map():
                if clock() >= deadline:
                    raise ValueError()
                if ready and stop_at is None:
                    if capture.poll() is not None:
                        raise ValueError()
                    sys.stdout.write("READY\n")
                    sys.stdout.flush()
                    # Parent runs exactly one approved helper probe after READY.
                    readable, _, _ = select.select([sys.stdin], [], [], min(12, deadline - clock()))
                    if not readable or sys.stdin.readline(8) != "STOP\n":
                        raise ValueError()
                    stop_at = clock() + .5
                if stop_at is not None and not stopped and clock() >= stop_at:
                    os.killpg(capture.pid, signal.SIGINT)
                    stopped = True
                for key, _ in selector.select(.1):
                    try:
                        chunk = os.read(key.fileobj.fileno(), 1024)
                    except BlockingIOError:
                        continue
                    if not chunk:
                        selector.unregister(key.fileobj)
                        continue
                    target = diagnostic if key.fileobj is capture.stderr else packets
                    target.extend(chunk)
                    if len(diagnostic) > 2048 or len(packets) > 4096:
                        raise ValueError()
                    if b"listening on eth0" in diagnostic:
                        ready = True
            if not ready or not stopped or capture.wait(timeout=1) not in (0, 130, -signal.SIGINT):
                raise ValueError()
        finally:
            selector.close()
        after_route = bounded(route, fd, timeout=4, limit=8192)
        after_rule = bounded(rule, fd, timeout=4, limit=65536)
        return {"routeBefore": before_route, "ruleBefore": before_rule,
                "capture": packets.decode("ascii"), "routeAfter": after_route, "ruleAfter": after_rule}
    finally:
        if capture is not None:
            try:
                os.killpg(capture.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            capture.wait(timeout=2)
            capture.stdout.close()
            capture.stderr.close()
        os.close(fd)


def main():
    try:
        args = validated(sys.argv[1:])
        result = collect(*args)
        raw = json.dumps(result, separators=(",", ":"))
        if len(raw) > 86000:
            raise ValueError()
        print(raw, flush=True)
        return 0
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        return 1


if __name__ == "__main__":
    sys.exit(main())
