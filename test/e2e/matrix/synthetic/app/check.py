#!/usr/bin/env python3
"""Fixed one-shot restricted client. Exit 0 healthy, 42 verified unreachable.

No shell, no credential reads, no request/response/error output. Failure
codes 11–13, 21–28 and 31–38 name only fixed failed stages, never qualify
as fail-close evidence. Invalid invocation exits 1. No Kubernetes API token.
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


class DirectFailure(Invalid):
    """Only a fixed subcheck stage, never an underlying exception or response."""

    def __init__(self, stage):
        if stage not in ("dns", "route", "tls-connect", "tls-verify", "tls-status"):
            raise Invalid()
        self.stage = stage


class TLSStatusFailure(DirectFailure):
    """Only an allowlisted HTTP status category, not an API body or header."""

    def __init__(self, category):
        if category not in ("unauthorized", "success", "other"):
            raise Invalid()
        super().__init__("tls-status")
        self.category = category


class MarkerFailure(Invalid):
    """Fixed tunnel-probe failure class; no network error or response details."""

    def __init__(self, category):
        if category not in ("unreachable", "connect-timeout", "response-timeout",
                            "refused", "response", "other"):
            raise Invalid()
        self.category = category


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
    try:
        dns = subprocess.run(["/usr/bin/getent", "ahostsv4", HOST],
                             stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                             stderr=subprocess.DEVNULL, timeout=3, check=False, env=env)
    except (OSError, subprocess.TimeoutExpired):
        raise DirectFailure("dns") from None
    if dns.returncode or not dns.stdout or len(dns.stdout) > 2048:
        raise DirectFailure("dns")
    try:
        lines = dns.stdout.decode("ascii").splitlines()
        answers = {ip4(line.split()[0]) for line in lines if line.split()}
    except (UnicodeError, ValueError, IndexError):
        raise DirectFailure("dns") from None
    if not answers or answers != {api_ip}:
        raise DirectFailure("dns")
    cmd = ["/usr/sbin/ip", "-j", "-4", "route", "get", api_ip,
           "ipproto", "tcp", "dport", "443"]
    try:
        result = subprocess.run(cmd, stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, timeout=3, check=False,
                                env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        if result.returncode or len(result.stdout) > 4096:
            raise DirectFailure("route")
        routes = json.loads(result.stdout)
        if (not isinstance(routes, list) or len(routes) != 1 or
                routes[0].get("dst") != api_ip or routes[0].get("dev") != "eth0" or
                routes[0].get("prefsrc") != pod_ip):
            raise DirectFailure("route")
    except (OSError, subprocess.TimeoutExpired, ValueError, KeyError, TypeError):
        raise DirectFailure("route") from None
    deadline = time.monotonic() + 5
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as raw:
            raw.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                raw.connect((api_ip, 443))
            except OSError:
                raise DirectFailure("tls-connect") from None
            try:
                context = ssl.create_default_context(cafile=CA)
                raw.settimeout(max(0.001, deadline - time.monotonic()))
                tls = context.wrap_socket(raw, server_hostname=HOST)
            except (OSError, ssl.SSLError, ValueError):
                raise DirectFailure("tls-verify") from None
            with tls:
                try:
                    if time.monotonic() > deadline:
                        raise Invalid()
                    first, _ = bounded_http(tls, b"GET /api/v1/namespaces/default/pods HTTP/1.0\r\n"
                                            b"Host: kubernetes.default.svc.cluster.local\r\n"
                                            b"Connection: close\r\n\r\n", deadline=deadline)
                    # Anonymous authentication can be disabled at the API
                    # server, returning 401 instead of an RBAC 403. Both are
                    # denial, never proof of privileged API access. The TLS
                    # peer/SNI and public CA have already been verified.
                    if first not in (b"HTTP/1.0 401 Unauthorized", b"HTTP/1.1 401 Unauthorized",
                                     b"HTTP/1.0 403 Forbidden", b"HTTP/1.1 403 Forbidden"):
                        if first.startswith((b"HTTP/1.0 401 ", b"HTTP/1.1 401 ")):
                            raise TLSStatusFailure("unauthorized")
                        if first.startswith((b"HTTP/1.0 200 ", b"HTTP/1.1 200 ")):
                            raise TLSStatusFailure("success")
                        raise TLSStatusFailure("other")
                except TLSStatusFailure:
                    raise
                except (Invalid, OSError, ssl.SSLError, ValueError):
                    raise DirectFailure("tls-status") from None
    except DirectFailure:
        raise
    except (OSError, ssl.SSLError, Invalid, ValueError):
        raise DirectFailure("tls-status") from None


def marker_result():
    deadline = time.monotonic() + 5
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.settimeout(max(0.001, deadline - time.monotonic()))
            try:
                sock.connect(("10.88.0.1", 8080))
            except (socket.timeout, TimeoutError):
                raise MarkerFailure("connect-timeout") from None
            try:
                first, body = bounded_http(sock, b"GET /marker HTTP/1.0\r\nHost: 10.88.0.1\r\n"
                                           b"Connection: close\r\n\r\n", deadline=deadline)
            except (socket.timeout, TimeoutError):
                raise MarkerFailure("response-timeout") from None
        if first in (b"HTTP/1.0 200 OK", b"HTTP/1.1 200 OK") and body == MARKER:
            return "healthy"
        raise MarkerFailure("response")
    except MarkerFailure:
        raise
    except OSError as exc:
        # Only ENETUNREACH/EHOSTUNREACH qualify as outage evidence; a timeout,
        # refusal or malformed response remains failure, never fail-close.
        if exc.errno in (errno.ENETUNREACH, errno.EHOSTUNREACH):
            return "unreachable"
        if isinstance(exc, (socket.timeout, TimeoutError)) or exc.errno == errno.ETIMEDOUT:
            raise MarkerFailure("response-timeout") from None
        if exc.errno == errno.ECONNREFUSED:
            raise MarkerFailure("refused") from None
        raise MarkerFailure("other") from None


def main(argv=None, environ=None):
    argv = sys.argv[1:] if argv is None else argv
    env = os.environ if environ is None else environ
    try:
        if len(argv) != 2 or argv[0] not in ("healthy", "outage"):
            raise Invalid()
        mode, approved_api = argv
        api_ip, pod_ip = ip4(approved_api), ip4(env.get("POD_IP"))
    except (Invalid, OSError, ValueError, KeyError, TypeError):
        return 1
    failures = (Invalid, OSError, ValueError, KeyError, TypeError, ssl.SSLError,
                subprocess.TimeoutExpired)
    try:
        direct_api(api_ip, pod_ip)
    except TLSStatusFailure as exc:
        return {"unauthorized": 26, "success": 27, "other": 28}[exc.category]
    except DirectFailure as exc:
        return {"dns": 21, "route": 22, "tls-connect": 23,
                "tls-verify": 24, "tls-status": 25}[exc.stage]
    except failures:
        return 11  # Unknown direct-path failure before selected probe.
    try:
        result = marker_result()
    except MarkerFailure as exc:
        return {"unreachable": 41, "connect-timeout": 43, "refused": 44,
                "response": 45, "other": 46, "response-timeout": 47}[exc.category]
    except failures:
        return 12  # Unknown marker failure; never an outage success.
    try:
        direct_api(api_ip, pod_ip)
    except TLSStatusFailure as exc:
        return {"unauthorized": 36, "success": 37, "other": 38}[exc.category]
    except DirectFailure as exc:
        return {"dns": 31, "route": 32, "tls-connect": 33,
                "tls-verify": 34, "tls-status": 35}[exc.stage]
    except failures:
        return 13  # Unknown direct-path failure after marker.
    if (mode == "healthy" and result != "healthy") or (mode == "outage" and result != "unreachable"):
        return 12
    return 0 if mode == "healthy" else BLOCKED


if __name__ == "__main__":
    sys.exit(main())
