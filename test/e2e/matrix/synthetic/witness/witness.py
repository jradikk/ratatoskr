#!/usr/bin/env python3
"""Independent one-shot OpenVPN witness; no shell or credential output.

Never run outside the separately scoped synthetic witness Pod. Successful Pod
termination requires exact marker through SO_BINDTODEVICE=tun0, not merely
an OpenVPN process. No HTTP control or cluster credentials.
"""
import os
from pathlib import Path
import socket
import stat
import subprocess
import signal
import sys
import time

PROFILE = Path("/etc/synthetic/client.ovpn")
TUN = Path("/dev/net/tun")


class Invalid(Exception):
    pass


def profile_is_private(path=PROFILE):
    # Kubernetes Secret volume symlinks resolve to an immutable, root-only
    # file; never read profile contents or display its path in an error.
    try:
        resolved = path.resolve(strict=True)
        info = resolved.stat()
        return (resolved.is_relative_to(Path("/etc/synthetic")) and
                stat.S_ISREG(info.st_mode) and info.st_mode & 0o077 == 0)
    except (OSError, RuntimeError):
        return False


def ensure_tun(path=TUN):
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if not path.exists():
        os.mknod(path, stat.S_IFCHR | 0o600, os.makedev(10, 200))
    info = path.stat()
    if not stat.S_ISCHR(info.st_mode) or info.st_rdev != os.makedev(10, 200):
        raise Invalid()


def fetch_marker(timeout=3):
    """Bind socket to tunnel and enforce one absolute request deadline."""
    conn = None
    deadline = time.monotonic() + timeout
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        conn = sock
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BINDTODEVICE, b"tun0\0")
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        sock.connect(("10.88.0.1", 8080))
        sock.settimeout(max(0.001, deadline - time.monotonic()))
        sock.sendall(b"GET /marker HTTP/1.0\r\nHost: 10.88.0.1\r\nConnection: close\r\n\r\n")
        result = bytearray()
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise Invalid()
            sock.settimeout(remaining)
            chunk = sock.recv(min(1024, 2049 - len(result)))
            if not chunk:
                break
            result.extend(chunk)
            if len(result) > 2048:
                raise Invalid()
        head, sep, body = bytes(result).partition(b"\r\n\r\n")
        if (time.monotonic() > deadline or not sep or
                not head.startswith(b"HTTP/1.0 200 ") and
                not head.startswith(b"HTTP/1.1 200 ") or
                body != b"ratatoskr-synthetic-vpn-v1\n"):
            raise Invalid()
        return True
    except (OSError, Invalid):
        return False
    finally:
        if conn is not None:
            conn.close()


def main(argv=None):
    argv = sys.argv[1:] if argv is None else argv
    if argv not in ([], ["--hold"], ["--probe"]):
        return 2
    if argv == ["--probe"]:
        return 0 if fetch_marker(timeout=3) else 1
    child = None
    try:
        if not profile_is_private():
            raise Invalid()
        ensure_tun()
        child = subprocess.Popen(["/usr/sbin/openvpn", "--config", str(PROFILE),
                                  "--dev", "tun0", "--dev-node", str(TUN),
                                  "--disable-dco", "--verb", "0"],
                                 stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                                 stderr=subprocess.DEVNULL, env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"},
                                 start_new_session=True)
        deadline = time.monotonic() + 90
        while time.monotonic() < deadline:
            if child.poll() is not None:
                raise Invalid()
            if fetch_marker(timeout=2):
                if argv == ["--hold"]:
                    # A separate UID-pinned exec checks marker during withdrawal.
                    # Bounded Pod lifetime; never report success merely on hold.
                    until = time.monotonic() + 300
                    while time.monotonic() < until:
                        if child.poll() is not None:
                            raise Invalid()
                        time.sleep(1)
                    return 0
                # Hold authenticated tunnel briefly for bounded server-side
                # status read of the distinct CN while this Pod is Running.
                hold = time.monotonic() + 12
                while time.monotonic() < hold:
                    if child.poll() is not None or not fetch_marker(timeout=2):
                        raise Invalid()
                    time.sleep(1)
                return 0
            time.sleep(1)
        raise Invalid()
    except (Invalid, OSError):
        return 1
    finally:
        if child is not None:
            try:
                os.killpg(child.pid, signal.SIGTERM)
                try:
                    child.wait(timeout=5)
                except subprocess.TimeoutExpired:
                    os.killpg(child.pid, signal.SIGKILL)
                    child.wait(timeout=5)
            except OSError:
                # Do not emit PID, process argv or profile into Pod logs.
                pass


if __name__ == "__main__":
    sys.exit(main())
