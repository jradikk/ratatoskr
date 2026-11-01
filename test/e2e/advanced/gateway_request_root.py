#!/usr/bin/env python3
"""Send one pinned-CA TLS request from the verified node network namespace.

The owned-fixture caller pins node-host PID/Pod UID and supplies the exact published
Gateway PodIP, CA, and wrong-audience token on bounded stdin only. This helper
pins a namespace FD before setns, drops root before opening the socket, and
prints only fixed status/reason categories, never input, HTTP headers or body.
"""
import fcntl
import ipaddress
import json
import os
import re
import sys

# Import while still in the parent mount namespace; no cluster access on import.
try:
    from . import gateway_negative
except ImportError:
    import gateway_negative

NS_GET_NSTYPE = 0xB703
CLONE_NEWNET = 0x40000000


def enter_node(host):
    if (type(host) is not str or not re.fullmatch(r"[1-9][0-9]{0,9}", host) or
            not 1 < int(host) < 2**31):
        raise ValueError()
    # Docker State.Pid is the node container init PID in the host PID namespace.
    # This is its HOST-network namespace, matching the production node agent.
    path = f"/proc/{host}/ns/net"
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        link = os.readlink(path)
        if (fcntl.ioctl(fd, NS_GET_NSTYPE) != CLONE_NEWNET or
                not re.fullmatch(r"net:\[([1-9][0-9]{0,18})\]", link) or
                os.fstat(fd).st_ino != int(link[5:-1])):
            raise ValueError()
        os.setns(fd, CLONE_NEWNET)
    finally:
        os.close(fd)
    # Network access needs no privileged UID. Root only enters the pinned netns.
    # Drop supplementary groups before fixed unprivileged UID/GID.
    os.setgroups([])
    os.setgid(65532)
    os.setuid(65532)
    # No root privilege remains before opening a socket.


def read_input(stream):
    raw = stream.read(20501)
    if len(raw) > 20500:
        raise ValueError()
    obj = json.loads(raw)
    if (type(obj) is not dict or set(obj) != {"gatewayPodIP", "registrationCACert", "token"} or
            type(obj["gatewayPodIP"]) is not str or
            type(obj["registrationCACert"]) is not str or
            type(obj["token"]) is not str):
        raise ValueError()
    ip = ipaddress.ip_address(obj["gatewayPodIP"])
    if (ip.version != 4 or ip.is_unspecified or ip.is_loopback or ip.is_multicast or
            str(ip) != obj["gatewayPodIP"] or
            not 0 < len(obj["registrationCACert"]) <= 4096 or
            not gateway_negative.PEM.fullmatch(obj["registrationCACert"]) or
            not 0 < len(obj["token"]) <= 16384 or
            any(c in obj["token"] for c in " \t\r\n")):
        raise ValueError()
    return obj


def main(argv=None, stream=None):
    args = sys.argv[1:] if argv is None else argv
    stream = sys.stdin.buffer if stream is None else stream
    try:
        if len(args) != 1:
            raise ValueError()
        obj = read_input(stream)
    except (OSError, ValueError, UnicodeError, TypeError, OverflowError):
        print('{"blocked":"input"}')
        return 0
    try:
        enter_node(*args)
    except (OSError, ValueError, AttributeError):
        print('{"blocked":"netns"}')
        return 0
    try:
        status = gateway_negative.send(obj["gatewayPodIP"], obj["registrationCACert"], obj["token"])
    except gateway_negative.ConnectBlocked:
        print('{"blocked":"connect"}')
        return 0
    except gateway_negative.TLSBlocked:
        print('{"blocked":"tls"}')
        return 0
    except (gateway_negative.Blocked, OSError, ValueError, UnicodeError):
        print('{"blocked":"http"}')
        return 0
    print(json.dumps({"status": status}, separators=(",", ":")))
    return 0


if __name__ == "__main__":
    sys.exit(main())
