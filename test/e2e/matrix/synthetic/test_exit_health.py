#!/usr/bin/env python3
"""Fixture-only exit health tests; no network/cluster/PKI operations."""
import contextlib
import importlib.util
import io
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_exit_serve", Path(__file__).parent / "server" / "serve.py")
serve = importlib.util.module_from_spec(spec)
spec.loader.exec_module(serve)


class FakeHandler(serve.Handler):
    def __init__(self, path):
        self.path = path
        self.status = None
        self.headers = {}
        self.wfile = io.BytesIO()
    def send_response(self, status):
        self.status = status
    def send_header(self, name, value):
        self.headers[name] = value
    def end_headers(self):
        pass
    def send_error(self, status):
        self.status = status


class ExitTests(unittest.TestCase):
    def test_missing_or_invalid_projection_fails_closed_only_exit(self):
        with tempfile.TemporaryDirectory() as tmp:
            flag = Path(tmp) / "exit-enabled"
            for value in (None, b"", b"false", b"true\n", b"trueEXTRA", b"garbage", b"1"):
                with self.subTest(value=value):
                    if value is None:
                        flag.unlink(missing_ok=True)
                    else:
                        flag.write_bytes(value)
                    with patch.object(serve, "EXIT_ENABLED", flag):
                        exit_handler = FakeHandler("/exit")
                        exit_handler.do_GET()
                        self.assertEqual(exit_handler.status, 503)
                        self.assertEqual(exit_handler.wfile.getvalue(), b"")
                        self.assertEqual(exit_handler.headers["Cache-Control"], "no-store")
                        marker = FakeHandler("/marker")
                        marker.do_GET()
                        self.assertEqual(marker.status, 200)
                        self.assertEqual(marker.wfile.getvalue(), b"ratatoskr-synthetic-vpn-v1\n")
            flag.write_bytes(b"true")
            with patch.object(serve, "EXIT_ENABLED", flag):
                exit_handler = FakeHandler("/exit")
                exit_handler.do_GET()
                self.assertEqual((exit_handler.status, exit_handler.wfile.getvalue()), (200, b"10.88.0.1\n"))

    def test_no_http_control_path_or_logging(self):
        for path in ("/health", "/toggle", "/exit?enabled=true", "/marker?enabled=false"):
            request = FakeHandler(path)
            request.do_GET()
            self.assertEqual(request.status, 404)
        self.assertFalse(hasattr(serve.Handler, "do_POST"))
        output = io.StringIO()
        with contextlib.redirect_stderr(output):
            serve.Handler.log_message(None, "SECRET", "PROFILE")
        self.assertEqual(output.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
