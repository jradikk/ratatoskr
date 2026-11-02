#!/usr/bin/env python3
"""Emit ONLY strict sanitized OpenVPN 2.6 status-v3 client evidence.

Never print status file, real address, profile, key, username or an exception.
The server container alone reads the Pod-local tmpfs status path; this script
is called with fixed argv by a UID/image-pinned adapter, not over a Service.
"""
import ipaddress
import json
import os
from pathlib import Path
import stat
import sys
import time

STATUS = Path("/run/synthetic/openvpn.status")
CNS = ("synthetic-client", "synthetic-witness")
MAX_SIZE = 16 * 1024
HEADER = ("Common Name", "Real Address", "Virtual Address", "Virtual IPv6 Address",
          "Bytes Received", "Bytes Sent", "Connected Since", "Connected Since (time_t)",
          "Username", "Client ID", "Peer ID", "Data Channel Cipher")
CIPHERS = frozenset(("AES-256-GCM", "AES-128-GCM"))


class Invalid(Exception):
    """Never serialize message or raw status to stdout/stderr."""


def parse(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_SIZE or b"\x00" in raw:
        raise Invalid()
    try:
        text = raw.decode("utf-8", errors="strict")
        lines = text.splitlines()
        if len(lines) > 64 or len(lines) < 5 or any(len(line) > 1024 for line in lines):
            raise Invalid()
        header = [line.split("\t") for line in lines if line.startswith("HEADER\tCLIENT_LIST\t")]
        clients = [line.split("\t") for line in lines if line.startswith("CLIENT_LIST\t")]
        if (len(header) != 1 or tuple(header[0][2:]) != HEADER or len(clients) not in (1, 2) or
                not lines[0].startswith("TITLE\t") or lines[-1] != "END" or
                any(line.startswith(("ERROR", "WARNING")) for line in lines)):
            raise Invalid()
        timestamps = [line.split("\t") for line in lines if line.startswith("TIME\t")]
        if len(timestamps) != 1 or len(timestamps[0]) != 3:
            raise Invalid()
        updated, now = int(timestamps[0][2]), int(time.time())
        if now - updated > 8 or updated > now + 2:
            raise Invalid()
        found = {}
        used_addresses = set()
        for client in clients:
            row = client
            if (len(row) != 1 + len(HEADER) or row[1] not in CNS or row[1] in found or
                    row[4] != "" or row[9] != "UNDEF" or row[12] not in CIPHERS or
                    not (row[10] == "" or row[10].isascii() and row[10].isdecimal() and len(row[10]) <= 10)):
                raise Invalid()
            address = ipaddress.ip_address(row[3])
            if (address.version != 4 or address not in ipaddress.ip_network("10.88.0.0/24") or
                    address == ipaddress.ip_address("10.88.0.1") or address in used_addresses):
                raise Invalid()
            used_addresses.add(address)
            received, sent, connected, peer = (int(row[5]), int(row[6]), int(row[8]), int(row[11]))
            if (min(received, sent, connected, peer) < 0 or max(received, sent) > 2**64 - 1 or
                    connected == 0 or updated < connected):
                raise Invalid()
            # Fixed-key/known-CN sanitized JSON. Real addresses, usernames,
            # Client ID, profiles, and credentials NEVER cross exec.
            found[row[1]] = {"cn": row[1], "virtualIPv4": str(address),
                             "received": received, "sent": sent, "connected": connected,
                             "peer": peer, "cipher": row[12]}
        if "synthetic-client" not in found or not any(line == "END" for line in lines):
            raise Invalid()
        return {"sessions": [found[cn] for cn in CNS if cn in found]}
    except (UnicodeError, ValueError, IndexError, TypeError, OverflowError):
        raise Invalid() from None


def read_status(path=STATUS):
    fd = None
    try:
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_CLOEXEC)
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size < 1 or info.st_size > MAX_SIZE or info.st_mode & 0o077:
            raise Invalid()
        raw = os.read(fd, MAX_SIZE + 1)
        if len(raw) != info.st_size or os.fstat(fd).st_size != info.st_size:
            raise Invalid()
        return parse(raw)
    except (OSError, Invalid):
        raise Invalid() from None
    finally:
        if fd is not None:
            os.close(fd)


def main():
    try:
        value = read_status()
        sys.stdout.write(json.dumps(value, separators=(",", ":")) + "\n")
        return 0
    except Invalid:
        # No raw OpenVPN parser exception/status in Pod log or exec stderr.
        return 1


if __name__ == "__main__":
    sys.exit(main())
