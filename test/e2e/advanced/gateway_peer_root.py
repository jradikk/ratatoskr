#!/usr/bin/env python3
"""Fixed root-only public WireGuard peer-key digest in pinned gateway netns.

Never read device private key: wg show rtkwg0 peers is the ONLY wg operation.
Never print raw public keys, errors or namespace identities; return a SHA256 of
exactly one canonical public peer key, or one fixed blocked category.
"""
import base64
import fcntl
import hashlib
import json
import os
import re
import selectors
import signal
import subprocess
import time
import sys
sys.dont_write_bytecode = True  # root helper must not create repo-owned cache artifacts

NS_GET_NSTYPE = 0xB703
CLONE_NEWNET = 0x40000000
PUB = re.compile(rb"[A-Za-z0-9+/]{43}=")


def digest(raw):
    if type(raw) is not bytes or len(raw) > 256:
        raise ValueError()
    lines = raw.splitlines()
    if len(lines) != 1 or not PUB.fullmatch(lines[0]) or \
            len(base64.b64decode(lines[0], validate=True)) != 32:
        raise ValueError()
    return hashlib.sha256(lines[0]).hexdigest()


def bounded_peers(fd):
    """Exact public-only command, bounded output/deadline, kill/reap group."""
    proc = None
    selector = selectors.DefaultSelector()
    data = bytearray()
    deadline = time.monotonic() + 5
    try:
        proc = subprocess.Popen(["/usr/bin/nsenter", "--net=/proc/self/fd/" + str(fd),
                                 "--", "/usr/bin/wg", "show", "rtkwg0", "peers"],
                                stdin=subprocess.DEVNULL, stdout=subprocess.PIPE,
                                stderr=subprocess.DEVNULL, start_new_session=True,
                                pass_fds=(fd,), env={"PATH": "/usr/sbin:/usr/bin:/sbin:/bin"})
        os.set_blocking(proc.stdout.fileno(), False)
        selector.register(proc.stdout, selectors.EVENT_READ)
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ValueError()
            for key, _ in selector.select(remaining):
                try:
                    chunk = os.read(key.fileobj.fileno(), min(257 - len(data), 257))
                except BlockingIOError:
                    continue
                if not chunk:
                    selector.unregister(key.fileobj)
                else:
                    data.extend(chunk)
                    if len(data) > 256:
                        raise ValueError()
        if proc.wait(timeout=max(.001, deadline - time.monotonic())) != 0:
            raise ValueError()
        return digest(bytes(data))
    finally:
        selector.close()
        if proc is not None:
            try:
                os.killpg(proc.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                proc.wait(timeout=1)
            except subprocess.TimeoutExpired:
                raise ValueError() from None
            proc.stdout.close()


def run(host, pid):
    if not all(re.fullmatch(r"[1-9][0-9]{0,9}", value) and 1 < int(value) < 2**31
               for value in (host, pid)):
        raise ValueError()
    path = f"/proc/{host}/root/proc/{pid}/ns/net"
    fd = os.open(path, os.O_RDONLY | os.O_CLOEXEC)
    try:
        link = os.readlink(path)
        if (fcntl.ioctl(fd, NS_GET_NSTYPE) != CLONE_NEWNET or
                not re.fullmatch(r"net:\[([1-9][0-9]{0,18})\]", link) or
                os.fstat(fd).st_ino != int(link[5:-1])):
            raise ValueError()
        # The namespace FD is pinned across the single public-only command.
        return bounded_peers(fd)
    finally:
        os.close(fd)


def main(argv=None):
    try:
        args = sys.argv[1:] if argv is None else argv
        if len(args) != 2:
            raise ValueError()
        print(json.dumps({"peerDigest": run(*args)}, separators=(",", ":")))
        return 0
    except (OSError, ValueError, UnicodeError, subprocess.TimeoutExpired):
        print('{"blocked":"peer-key"}')
        return 1


if __name__ == "__main__":
    sys.exit(main())
