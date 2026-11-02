"""Hermetic TLS socket/status checks, no real network."""
import base64
import ssl
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import gateway_negative as neg

IP = "10.42.0.7"
CA = "-----BEGIN CERTIFICATE-----\ntest\n-----END CERTIFICATE-----\n"
BEARER = "never-print-this-token"


class Socket:
    def __init__(self, status): self.read = iter(status); self.written = None; self.timeout = None
    def __enter__(self): return self
    def __exit__(self, *_): pass
    def settimeout(self, timeout): self.timeout = timeout
    def sendall(self, data): self.written = data
    def recv(self, size):
        assert size == 1
        return bytes([next(self.read, 0)]) if self.read else b""


class TLS:
    def __init__(self, connection): self.connection = connection; self.ip = None
    def wrap_socket(self, sock, server_hostname):
        self.ip = server_hostname
        assert sock is self.connection
        return sock
    def load_verify_locations(self, cadata): assert cadata == CA


class HTTPTest(unittest.TestCase):
    def test_tls_requires_pinned_ip_strict_tls13_no_proxy_or_redirect(self):
        connection = Socket(b"HTTP/1.1 401 Unauthorized\r\n")
        tls = TLS(connection)
        tls.minimum_version = tls.maximum_version = tls.verify_mode = tls.check_hostname = None
        with patch.object(neg.socket, "create_connection", return_value=connection) as dial, \
                patch.object(neg.ssl, "SSLContext", return_value=tls):
            self.assertEqual(neg.send(IP, CA, BEARER), 401)
        dial.assert_called_once_with((IP, 9443), timeout=5)
        self.assertEqual(tls.ip, IP)
        self.assertEqual(tls.minimum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(tls.maximum_version, ssl.TLSVersion.TLSv1_3)
        self.assertEqual(tls.verify_mode, ssl.CERT_REQUIRED)
        self.assertTrue(tls.check_hostname)
        self.assertEqual(connection.timeout, 8)
        self.assertIn(b"POST /v1/peers HTTP/1.1\r\n", connection.written)
        self.assertIn(("Authorization: Bearer " + BEARER).encode(), connection.written)
        self.assertIn(neg.TEST_KEY.encode(), connection.written)
        self.assertNotIn(b"privateKey", connection.written)
        self.assertEqual(len(base64.b64decode(neg.TEST_KEY, validate=True)), 32)

    def test_only_exact_http_rejection_and_no_headers_are_read(self):
        for line, permitted in ((b"HTTP/1.1 403 Forbidden\r\n", True),
                                (b"HTTP/1.1 302 Found\r\n", False),
                                (b"HTTP/1.1 201 Created\r\n", False),
                                (b"HTTP/1.1 401 Unauthorized", False),
                                (b"HTTP/1.1 401 Unauthorized\r\nX-Secret: key\r\n", True)):
            connection = Socket(line)
            tls = TLS(connection)
            with patch.object(neg.socket, "create_connection", return_value=connection), \
                    patch.object(neg.ssl, "SSLContext", return_value=tls):
                if permitted:
                    self.assertIn(neg.send(IP, CA, BEARER), (401, 403))
                else:
                    with self.assertRaises(neg.Blocked):
                        neg.send(IP, CA, BEARER)
            self.assertEqual(bytes(connection.read), b"X-Secret: key\r\n" if b"X-Secret" in line else b"")


if __name__ == "__main__":
    unittest.main()
