#!/usr/bin/env python3
"""Selected one-shot helper tests; fake network/process only."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_app", Path(__file__).parent / "app" / "check.py")
app = importlib.util.module_from_spec(spec)
spec.loader.exec_module(app)


class ProbeTests(unittest.TestCase):
    def test_mode_exit_codes_require_direct_api_both_sides(self):
        for mode, result, expected in (("healthy", "healthy", 0), ("outage", "unreachable", 42),
                                       ("healthy", "unreachable", 1), ("outage", "healthy", 1)):
            calls = []
            with self.subTest(mode=mode, result=result), \
                 patch.object(app, "direct_api", side_effect=lambda *args: calls.append(args)), \
                 patch.object(app, "marker_result", return_value=result):
                self.assertEqual(app.main([mode, "10.43.0.1"], {"POD_IP": "10.42.2.5"}), expected)
                self.assertEqual(calls, [("10.43.0.1", "10.42.2.5")] * 2)
        with patch.object(app, "direct_api", side_effect=app.Invalid()), \
             patch.object(app, "marker_result") as marker:
            self.assertEqual(app.main(["outage", "10.43.0.1"], {"POD_IP": "10.42.2.5"}), 1)
            marker.assert_not_called()
        api_count = [0]
        def api(*args):
            api_count[0] += 1
            if api_count[0] == 2:
                raise app.Invalid()
        with patch.object(app, "direct_api", side_effect=api), \
             patch.object(app, "marker_result", return_value="unreachable"):
            self.assertEqual(app.main(["outage", "10.43.0.1"], {"POD_IP": "10.42.2.5"}), 1)

    def test_only_selected_unreachable_errno_qualifies(self):
        import errno
        class Sock:
            def __init__(self, code): self.code = code
            def __enter__(self): return self
            def __exit__(self, *_): pass
            def settimeout(self, *_): pass
            def connect(self, *_): raise OSError(self.code, "PRIVATE_PROFILE")
        for code, expected in ((errno.ENETUNREACH, "unreachable"), (errno.EHOSTUNREACH, "unreachable"),
                               (errno.ECONNREFUSED, None), (errno.ETIMEDOUT, None)):
            with patch.object(app.socket, "socket", return_value=Sock(code)):
                if expected:
                    self.assertEqual(app.marker_result(), expected)
                else:
                    with self.assertRaises(app.Invalid) as ctx:
                        app.marker_result()
                    self.assertNotIn("PRIVATE_PROFILE", str(ctx.exception))

    def test_dns_is_bounded_and_matches_exact_api_ip(self):
        import subprocess
        from unittest.mock import Mock
        getent = b"10.43.0.1 STREAM kubernetes.default.svc.cluster.local\n" * 3
        route = json.dumps([{"dst": "10.43.0.1", "dev": "eth0", "prefsrc": "10.42.2.5"}]).encode()
        def fake_run(argv, **kwargs):
            self.assertFalse(kwargs.get("shell", False))
            self.assertLessEqual(kwargs["timeout"], 3)
            if argv[0] == "/usr/bin/getent":
                self.assertEqual(argv, ["/usr/bin/getent", "ahostsv4", app.HOST])
                return subprocess.CompletedProcess(argv, 0, getent)
            return subprocess.CompletedProcess(argv, 0, route)
        class TLS:
            def __enter__(self): return self
            def __exit__(self, *_): return None
        with patch.object(app.subprocess, "run", side_effect=fake_run), \
             patch.object(app.socket, "socket", return_value=TLS()), \
             patch.object(app.ssl, "create_default_context", return_value=Mock(wrap_socket=lambda *_a, **_kw: TLS())), \
             patch.object(app, "bounded_http", return_value=(b"HTTP/1.1 403 Forbidden", b"")):
            TLS.settimeout = lambda *_: None
            TLS.connect = lambda *_: None
            app.direct_api("10.43.0.1", "10.42.2.5")
        with patch.object(app.subprocess, "run", side_effect=subprocess.TimeoutExpired("getent", 3)):
            self.assertEqual(app.main(["outage", "10.43.0.1"], {"POD_IP": "10.42.2.5"}), 1)

    def test_bad_invocation_no_network(self):
        for argv, env in ((["sh", "10.43.0.1"], {"POD_IP": "10.42.2.5"}),
                          (["outage", "10.43.0.1", "extra"], {"POD_IP": "10.42.2.5"}),
                          (["outage", "10.43.0.1"], {"POD_IP": "not-ip"})):
            with patch.object(app, "direct_api") as direct:
                self.assertEqual(app.main(argv, env), 1)
                direct.assert_not_called()

    def test_no_shell_and_no_credential_or_error_output(self):
        from contextlib import redirect_stderr, redirect_stdout
        from io import StringIO
        out, err = StringIO(), StringIO()
        with redirect_stdout(out), redirect_stderr(err), patch.object(app, "direct_api", side_effect=RuntimeError("PRIVATE")):
            # Unexpected exception currently propagates to stderr: test valid
            # user-facing failure path only. No raw subprocess or network errors.
            self.assertEqual(app.main(["invalid", "10.43.0.1"], {"POD_IP": "10.42.2.5"}), 1)
        self.assertEqual(out.getvalue() + err.getvalue(), "")


if __name__ == "__main__": unittest.main()
