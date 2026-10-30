#!/usr/bin/env python3
"""Fixed one-shot restricted client. Exit 0 healthy, 42 verified unreachable.

No shell, no credential reads, no request/response/error output. A generic
failure exits 1 and is NEVER fail-close evidence. No Kubernetes API token.
"""
import errno
import ipaddress
import json
import os
import socket
import ssl
import subprocess
import sys
import time

HOST = "kubernetes.default.svc.cluster.local"
CA = "/var/run/ratatoskr/api-ca/ca.crt"
MARKER = b"ratatoskr-synthetic-vpn-v1\n"
BLOCKED = 42
MAX_RESPONSE = 2048


class Invalid(Exception):
    pass


def ip4(value):
    addr = ipaddress.ip_address(value)
    if addr.version != 4 or addr.is_loopback or addr.is_unspecified or addr.is_multicast:
        raise Invalid()
    return str(addr)


def bounded_http(sock, request, *, deadline):
    sock.settimeout(max(0.001, deadline - time.monotonic()))
    sock.sendall(request)
    body = bytearray()
    while True:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise Invalid()
        sock.settimeout(remaining)
        chunk = sock.recv(min(1024, MAX_RESPONSE + 1 - len(body)))
        if not chunk:
            break
        body.extend(chunk)
        if len(body) > MAX_RESPONSE:
            raise Invalid()
    if time.monotonic() > deadline:
        raise Invalid()
    header, sep, payload = bytes(body).partition(b"\r\n\r\n")
    if not sep or not header.startswith((b"HTTP/1.0 ", b"HTTP/1.1 ")):
        raise Invalid()
    return header.split(b"\r\n", 1)[0], payload


def direct_api(api_ip, pod_ip):
    # Resolve the fixed in-cluster name in a child process with a hard timeout;
    # socket.getaddrinfo in this process could otherwise hang indefinitely.
    env = {"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"}
    dns = subprocess.run(["/usr/bin/getent", "ahostsv4", HOST],
                         stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                         stderr=subprocess.DEVNULL, timeout=3, check=False, env=env)
    if dns.returncode or not dns.stdout or len(dns.stdout) > 2048:
        raise Invalid()
    try:
        lines = dns.stdout.decode("ascii").splitlines()
        answers = {ip4(line.split()[0]) for line in lines if line.split()}
    except (UnicodeError, ValueError, IndexError):
        raise Invalid() from None
    if not answers or answers != {api_ip}:
        raise Invalid()
    cmd = ["/usr/sbin/ip", "-j", "-4", "route", "get", api_ip,
           "ipproto", "tcp", "dport", "443"]
    result = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL, timeout=3, check=False,
                            env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
    if result.returncode or len(result.stdout) > 4096:
        raise Invalid()
    routes = json.loads(result.stdout)
    if (not isinstance(routes, list) or len(routes) != 1 or
            routes[0].get("dst") != api_ip or routes[0].get("dev") != "eth0" or
            routes[0].get("prefsrc") != pod_ip):
        raise Invalid()
    deadline = time.monotonic() + 5
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
        raw.settimeout(max(0.001, deadline - time.monotonic()))
        raw.connect((api_ip, 443))
        context = ssl.create_default_context(cafile=CA)
        raw.settimeout(max(0.001, deadline - time.monotonic()))
        with context.wrap_socket(raw, server_hostname=HOST) as tls:
            if time.monotonic() > deadline:
                raise Invalid()
            first, _ = bounded_http(tls, b"GET /api/v1/namespaces/default/pods HTTP/1.0\r\n"
                                    b"Host: kubernetes.default.svc.cluster.local\r\n"
                                    b"Connection: close\r\n\r\n", deadline=deadline)
            if first not in (b"HTTP/1.0 403 Forbidden", b"HTTP/1.1 403 Forbidden"):
                raise Invalid()


def marker_result():
    deadline = time.monotonic() + 5
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            sock.connect(("10.88.0.1", 8080))
            first, body = bounded_http(sock, b"GET /marker HTTP/1.0\r\nHost: 10.88.0.1\r\n"
                                       b"Connection: close\r\n\r\n", deadline=deadline)
        if first in (b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK") and body == MARKER:
            return "healthy"
        raise Invalid()
    except OSError as exc:
        # A timeout, DNS error, 503, connection refused, or generic network
        # failure is NOT proof of fail-closed routing while marker is live.
        if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            return "unreachable"
        raise Invalid() from None


def main(argv=None, environ=None):
    argv = sys.argv[1:] if argv is None else argv
    env = os.environ if environ is None else environ
    try:
        if len(argv) != 2 or argv[0] not in ("healthy", "outage"):
            raise Invalid()
        mode, approved_api = argv
        api_ip, pod_ip = ip4(approved_api), ip4(env.get("POD_IP"))
        direct_api(api_ip, pod_ip)
        result = marker_result()
        direct_api(api_ip, pod_ip)
        if mode == "healthy" and result == "healthy":
            return 0
        if mode == "outage" and result == "unreachable":
            return BLOCKED
    except (Invalid, OSError, ValueError, KeyError, TypeError, ssl.SSLError,
            subprocess.TimeoutExpired):
        pass
    return 1


if __name__ == "__main__":
    sys.exit(main())
