"""Offline fake-profile tests only; never read caller env/private home files."""
import importlib.util
import os
from pathlib import Path
import stat
import subprocess
import sys
import tempfile
import unittest

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("bundle", HERE / "bundle.py")
bundle = importlib.util.module_from_spec(spec)
spec.loader.exec_module(bundle)


class BundleTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ratatoskr-bundle-unit-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name) / "repo"
        self.inputs = Path(self.temp.name) / "inputs"
        self.private = Path(self.temp.name) / "private"
        for path in (self.root, self.inputs, self.private):
            path.mkdir(mode=0o700)
        self.env = {"RATATOSKR_E2E_EXPECT_COUNTRY": "DE"}

    def source(self, env, name, data):
        path = self.inputs / name
        path.write_bytes(data)
        path.chmod(0o600)
        self.env[env] = str(path)
        return path

    def profile(self, text):
        return self.source("RATATOSKR_E2E_OVPN", "synthetic.ovpn", text.encode())

    def materials(self):
        for env, name in (("RATATOSKR_E2E_OVPN_CA", "synthetic-ca"),
                          ("RATATOSKR_E2E_OVPN_CERT", "synthetic-cert"),
                          ("RATATOSKR_E2E_OVPN_KEY", "synthetic-key"),
                          ("RATATOSKR_E2E_OVPN_AUTH", "synthetic-auth")):
            self.source(env, name, b"SYNTHETIC_PLACEHOLDER\n")

    def stage(self):
        return bundle.stage(self.root, self.private, self.env)

    def test_external_bundle_normalizes_only_explicit_inputs(self):
        self.materials()
        self.profile("client\nremote vpn.example.invalid 1194\nca 'provider ca.crt'\ncert assets/cert.crt\nkey different.key\nauth-user-pass login.conf\nredirect-gateway def1\ndhcp-option DNS 192.0.2.53\ndev tun9\n")
        before = {p: (p.read_bytes(), p.stat().st_mode) for p in self.inputs.iterdir()}
        output = self.stage()
        self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
        self.assertEqual(set(p.name for p in output.iterdir()), {"client.ovpn", "ca.crt", "client.crt", "client.key", "auth.txt"})
        text = (output / "client.ovpn").read_text()
        for expected in ('ca "ca.crt"', 'cert "client.crt"', 'key "client.key"', 'auth-user-pass auth.txt'):
            self.assertIn(expected, text)
        self.assertNotIn("provider", text)
        self.assertNotIn("redirect-gateway", text)
        self.assertNotIn("dhcp-option", text)
        for p in output.iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)
        self.assertEqual(before, {p: (p.read_bytes(), p.stat().st_mode) for p in self.inputs.iterdir()})
        self.assertEqual(list(self.root.iterdir()), [])
        self.assertNotIn("IPINFO_TOKEN", self.env)

    def test_inline_profile_without_external_materials(self):
        self.profile("client\n<ca>\nSYNTHETIC_INLINE_CA\n</ca>\n<cert>\nSYNTHETIC_INLINE_CERT\n</cert>\n<key>\nSYNTHETIC_INLINE_KEY\n</key>\n<tls-auth>\nSYNTHETIC_INLINE_TLS_AUTH\n</tls-auth>\n")
        output = self.stage()
        self.assertEqual(set(p.name for p in output.iterdir()), {"client.ovpn"})
        self.assertIn("SYNTHETIC_INLINE_KEY", (output / "client.ovpn").read_text())

    def test_supplied_materials_without_directives_are_added(self):
        self.materials()
        self.profile("client\n")
        text = (self.stage() / "client.ovpn").read_text()
        self.assertIn('ca "ca.crt"', text)
        self.assertIn('cert "client.crt"', text)
        self.assertIn('key "client.key"', text)
        self.assertIn("auth-user-pass auth.txt", text)

    def test_unsafe_options_paths_and_missing_material_are_rejected(self):
        cases = ["config extra.ovpn", "up script", "down script", "plugin library", "tls-verify script",
                 "setenv TOKEN synthetic-sensitive-marker", "cd dir", "script-security 3\nup script", "iproute executable",
                 "ca ../outside", "ca /absolute", "key C:/key", 'cert "path\\\\key"',
                 "auth-user-pass ../auth", "auth-user-pass /absolute", "tls-auth external.key 1",
                 "ca missing-file", "ca", "cert one two", "remote \"unterminated", "remote dangling\\",
                 "<auth-user-pass>\nSYNTHETIC\n</auth-user-pass>", "<ca>\nSYNTHETIC", "<ca>\n<key>\n</key>\n</ca>",
                 "<connection>\nremote vpn.example.invalid\n</connection>", "ca [inline]", "client\x00"]
        for text in cases:
            with self.subTest(case=text.split()[0]):
                self.profile(text)
                with self.assertRaises(bundle.BundleError) as caught:
                    self.stage()
                self.assertEqual(str(caught.exception), "live upstream bundle rejected; check supported inputs and profile")
                self.assertFalse((self.private / "upstream").exists())

    def test_unsafe_source_files_and_bounds(self):
        self.profile("client\n")
        self.env["RATATOSKR_E2E_OVPN"] = "relative.ovpn"
        with self.assertRaises(bundle.BundleError):
            self.stage()
        inside = self.root / "synthetic.ovpn"
        inside.write_text("client\n")
        self.env["RATATOSKR_E2E_OVPN"] = str(inside)
        with self.assertRaises(bundle.BundleError):
            self.stage()
        link = self.inputs / "linked-profile"
        link.symlink_to(inside)
        self.env["RATATOSKR_E2E_OVPN"] = str(link)
        with self.assertRaises(bundle.BundleError):
            self.stage()
        fifo = self.inputs / "fifo"
        os.mkfifo(fifo, 0o600)
        self.env["RATATOSKR_E2E_OVPN"] = str(fifo)
        with self.assertRaises(bundle.BundleError):
            self.stage()
        self.profile("x" * (bundle.MAX_BYTES + 1))
        with self.assertRaises(bundle.BundleError):
            self.stage()
        self.profile("client\n")
        self.source("RATATOSKR_E2E_OVPN_KEY", "large-key", b"x" * (bundle.MAX_BYTES + 1))
        with self.assertRaises(bundle.BundleError):
            self.stage()

    def test_duplicate_conflict_and_existing_bundle_rejected(self):
        self.materials()
        for text in ("ca a\nca b", "<ca>\nSYNTHETIC\n</ca>", "ca [inline]\n<ca>\nSYNTHETIC\n</ca>"):
            self.profile(text)
            with self.assertRaises(bundle.BundleError):
                self.stage()
        self.profile("client\n")
        output = self.stage()
        original = (output / "client.ovpn").read_bytes()
        with self.assertRaises(bundle.BundleError):
            self.stage()
        self.assertEqual((output / "client.ovpn").read_bytes(), original)

    def test_rollback_on_partial_write_failure(self):
        self.materials()
        self.profile("client\n")
        original_open = bundle.os.open
        def fail_key(path, flags, *args, **kwargs):
            if Path(path) == self.private / "upstream" / "client.key":
                raise OSError("synthetic-sensitive-marker")
            return original_open(path, flags, *args, **kwargs)
        from unittest.mock import patch
        with patch.object(bundle.os, "open", side_effect=fail_key):
            with self.assertRaises(bundle.BundleError):
                self.stage()
        self.assertFalse((self.private / "upstream").exists())

    def test_cli_fixed_error_without_raw_data_or_trace(self):
        self.profile("setenv TOKEN synthetic-sensitive-marker")
        result = subprocess.run([sys.executable, str(HERE / "bundle.py"), str(self.root), str(self.private)],
                                env=self.env, capture_output=True, timeout=3, check=False)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, b"")
        self.assertNotIn(b"synthetic-sensitive-marker", result.stderr)
        self.assertNotIn(b"Traceback", result.stderr)
        self.assertNotIn(str(self.inputs).encode(), result.stderr)

    def test_permissive_original_modes_remain_untouched(self):
        self.materials()
        self.profile("client\nca ca.crt\ncert client.crt\nkey client.key\nauth-user-pass login.conf\n")
        for p in self.inputs.iterdir():
            p.chmod(0o644)
        output = self.stage()
        for p in self.inputs.iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o644)
        for p in output.iterdir():
            self.assertEqual(stat.S_IMODE(p.stat().st_mode), 0o600)

    def test_inline_directive_and_payload_are_preserved(self):
        self.profile('client\nca [inline]\n<ca>\nSYNTHETIC\n</ca>\n')
        output = self.stage()
        self.assertIn('ca "[inline]"', (output / "client.ovpn").read_text())
        self.assertIn('<ca>\nSYNTHETIC\n</ca>', (output / "client.ovpn").read_text())

    def test_private_directory_permissions(self):
        self.profile("client\n")
        self.private.chmod(0o755)
        with self.assertRaises(bundle.BundleError):
            self.stage()


if __name__ == "__main__":
    unittest.main()
