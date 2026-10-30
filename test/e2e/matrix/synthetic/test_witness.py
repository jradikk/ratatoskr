#!/usr/bin/env python3
"""No VPN, Kubernetes, PKI or Docker execution; witness socket mocks only."""
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("synthetic_witness", HERE / "witness" / "witness.py")
witness = importlib.util.module_from_spec(spec)
spec.loader.exec_module(witness)


class FakeSocket:
    def __init__(self, raw):
        self.data = raw
        self.opt = []
        self.closed = False
        self.destination = None
    def settimeout(self, timeout):
        self.timeout = timeout
    def setsockopt(self, *args):
        self.opt.append(args)
    def connect(self, address):
        self.destination = address
    def sendall(self, data):
        self.request = data
    def recv(self, n):
        head, self.data = self.data[:n], self.data[n:]
        return head
    def close(self):
        self.closed = True


class WitnessTests(unittest.TestCase):
    def test_marker_requires_bound_tunnel_and_exact_http_body(self):
        good = b"HTTP/1.0 200 OK\r\nContent-Length: 28\r\n\r\nratatoskr-synthetic-vpn-v1\n"
        socket = FakeSocket(good)
        with patch.object(witness.socket, "socket", return_value=socket):
            self.assertTrue(witness.fetch_marker())
        self.assertEqual(socket.opt, [(witness.socket.SOL_SOCKET, witness.socket.SO_BINDTODEVICE, b"tun0\0")])
        self.assertEqual(socket.destination, ("10.88.0.1", 8080))
        self.assertEqual(socket.request, b"GET /marker HTTP/1.0\r\nHost: 10.88.0.1\r\nConnection: close\r\n\r\n")
        self.assertTrue(socket.closed)
        for response in (b"HTTP/1.0 200 OK\r\n\r\nWRONG",
                         b"HTTP/1.0 503 Unavailable\r\n\r\nratatoskr-synthetic-vpn-v1\n",
                         b"HTTP/1.0 200 OK\r\n\r\nratatoskr-synthetic-vpn-v1\nMORE",
                         b"HTTP/1.0 200 OK\r\n\r\n" + b"A" * 2049):
            with self.subTest(response=response[:30]):
                with patch.object(witness.socket, "socket", return_value=FakeSocket(response)):
                    self.assertFalse(witness.fetch_marker())

    def test_profile_mode_and_no_cli_credentials(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "client.ovpn"
            path.write_bytes(b"fixture-private-placeholder")
            path.chmod(0o600)
            # Real profile must be within canonical /etc/synthetic; a temp
            # file outside is always rejected, never read or printed.
            self.assertFalse(witness.profile_is_private(path))
            path.chmod(0o644)
            self.assertFalse(witness.profile_is_private(path))
        self.assertEqual(witness.main(["--debug", "PRIVATE-CREDENTIAL"]), 2)

    def test_main_fixed_argv_and_one_shot_success(self):
        class Child:
            def __init__(self):
                self.waited = False
                self.pid = 12345
            def poll(self):
                return None
            def terminate(self):
                pass
            def wait(self, timeout):
                self.waited = True
        child = Child()
        seen = []
        def start(argv, **kwargs):
            seen.append((argv, kwargs))
            return child
        with patch.object(witness, "profile_is_private", return_value=True), patch.object(witness, "ensure_tun"), \
             patch.object(witness.subprocess, "Popen", side_effect=start), \
             patch.object(witness.os, "killpg"), \
             patch.object(witness, "fetch_marker", return_value=True), \
             patch.object(witness.time, "sleep", return_value=None), \
             patch.object(witness.time, "monotonic", side_effect=[0, 0, 0, 13]):
            self.assertEqual(witness.main([]), 0)
        self.assertEqual(seen[0][0], ["/usr/sbin/openvpn", "--config", "/etc/synthetic/client.ovpn",
                                      "--dev", "tun0", "--dev-node", "/dev/net/tun", "--verb", "0"])
        self.assertIs(seen[0][1]["stdout"], witness.subprocess.DEVNULL)
        self.assertIs(seen[0][1]["stderr"], witness.subprocess.DEVNULL)
        self.assertTrue(child.waited)


if __name__ == "__main__":
    unittest.main()
