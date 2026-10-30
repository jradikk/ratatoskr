#!/usr/bin/env python3
"""No cluster, OpenSSL, PKI or network calls; scripted lifecycle API only."""
import contextlib
import importlib.util
import json
from pathlib import Path
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_lifecycle", Path(__file__).with_name("lifecycle.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
TOKEN = "a" * 32


class FakeAPI:
    def __init__(self):
        self.data = {}
        self.calls = []
        self.fail_create = set()
        self.fail_delete = set()
        self.fail_get = set()
        self.replace_on_delete = set()

    def get(self, name, timeout):
        self.calls.append(("get", name, timeout))
        if name in self.fail_get:
            raise module.LifecycleError("test failure")
        return self.data.get(name)

    def create(self, name, token, apps, timeout):
        self.calls.append(("create", name, timeout))
        if name in self.data:
            raise module.LifecycleError("existing")
        self.data[name] = {"kind": "Namespace", "metadata": {"name": name, "uid": "b" * 32,
                            "labels": {module.LABEL: token}}}
        if name in self.fail_create:
            raise module.LifecycleError("ambiguous create timeout")
        return "b" * 32

    def delete_if_uid(self, name, uid, timeout):
        self.calls.append(("delete", name, timeout))
        if name in self.fail_delete:
            raise module.LifecycleError("delete failed")
        if uid != self.data[name]["metadata"]["uid"]:
            raise module.LifecycleError("UID changed")
        if name in self.replace_on_delete:
            self.data[name] = {"kind": "Namespace", "metadata": {"name": name, "uid": "c" * 32,
                                 "labels": {module.LABEL: TOKEN}}}
        else:
            del self.data[name]


class LifecycleTests(unittest.TestCase):
    def runner(self, api):
        return module.Lifecycle(api, token_factory=lambda: TOKEN)

    def test_lifecycle_app_namespace_matches_gateway_selector(self):
        life = self.runner(FakeAPI())
        apps = module._namespace(life.names[1], life.token, True)
        self.assertEqual(apps["metadata"]["labels"]["ratatoskr-synthetic"], life.names[0])
        self.assertEqual(apps["metadata"]["labels"]["pod-security.kubernetes.io/enforce"], "restricted")

    def test_success_private_dir_both_namespace_deletions(self):
        api = FakeAPI()
        with self.runner(api) as life:
            directory = life.private_dir
            self.assertEqual(directory.stat().st_mode & 0o777, 0o700)
            self.assertTrue(directory.is_absolute())
            names = life.create_namespaces()
            self.assertEqual(len(names), 2)
            self.assertNotEqual(names[0], names[1])
            self.assertEqual(set(life.owned), set(names))
        self.assertFalse(directory.exists())
        self.assertEqual(api.data, {})
        self.assertEqual([x[1] for x in api.calls if x[0] == "delete"], list(reversed(names)))

    def test_preexisting_name_is_never_deleted(self):
        api = FakeAPI()
        apps = self.runner(api).names[1]
        api.data[apps] = {"kind": "Namespace", "metadata": {"name": apps, "uid": "e" * 32}}
        with self.assertRaisesRegex(module.LifecycleError, "already exists"):
            with self.runner(api) as life:
                directory = life.private_dir
                life.create_namespaces()
        self.assertFalse(directory.exists())
        self.assertEqual(list(api.data), [apps])
        self.assertFalse(any(x[0] in ("create", "delete") for x in api.calls))

    def test_ambiguous_create_uid_unconfirmed_refuses_delete(self):
        api = FakeAPI()
        api.fail_create.add(self.runner(api).names[0])
        with self.assertRaisesRegex(module.LifecycleError, "cleanup unverified"):
            with self.runner(api) as life:
                directory = life.private_dir
                life.create_namespaces()
        self.assertFalse(directory.exists())
        self.assertEqual(set(api.data), {self.runner(api).names[0]})
        self.assertFalse(any(x[0] == "delete" for x in api.calls))

    def test_foreign_identity_not_deleted_even_after_ambiguous_create(self):
        api = FakeAPI()
        name = self.runner(api).names[0]
        api.fail_create.add(name)
        original = api.create
        def foreign(name, token, apps, timeout):
            original(name, token, apps, timeout)  # raises after remote commit
        api.create = foreign
        api.data[name] = None
        # Simulate a CREATE that produced an object with a foreign label, not ours.
        def foreign_after_create(name, token, apps, timeout):
            api.data[name] = {"kind": "Namespace", "metadata": {
                "name": name, "uid": "c" * 32, "labels": {module.LABEL: "foreign"}}}
            raise module.LifecycleError("ambiguous")
        api.create = foreign_after_create
        del api.data[name]
        with self.assertRaisesRegex(module.LifecycleError, "cleanup unverified"):
            with self.runner(api) as life:
                directory = life.private_dir
                life.create_namespaces()
        self.assertFalse(directory.exists())
        self.assertIn(name, api.data)
        self.assertFalse(any(x[0] == "delete" for x in api.calls))

    def test_failing_body_still_cleans_both(self):
        api = FakeAPI()
        with self.assertRaisesRegex(module.LifecycleError, "body failed") as ctx:
            with self.runner(api) as life:
                directory = life.private_dir
                life.create_namespaces()
                raise ValueError("SECRET body failed")
        self.assertNotIn("SECRET", str(ctx.exception))
        self.assertFalse(directory.exists())
        self.assertFalse(api.data)

    def test_delete_error_overrides_body_pass_and_cleans_other(self):
        api = FakeAPI()
        api.fail_delete.add(self.runner(api).names[1])
        with self.assertRaisesRegex(module.LifecycleError, "cleanup unverified"):
            with self.runner(api) as life:
                directory = life.private_dir
                life.create_namespaces()
        self.assertFalse(directory.exists())
        self.assertEqual(set(api.data), api.fail_delete)
        self.assertEqual(len([x for x in api.calls if x[0] == "delete"]), 2)

    def test_replaced_namespace_is_not_deleted(self):
        api = FakeAPI()
        api.replace_on_delete.add(self.runner(api).names[1])
        with self.assertRaisesRegex(module.LifecycleError, "cleanup unverified"):
            with self.runner(api) as life:
                life.create_namespaces()
        self.assertEqual(set(api.data), api.replace_on_delete)
        self.assertEqual(len([x for x in api.calls if x[0] == "delete"]), 2)

    def test_signal_cleanup_and_restore(self):
        api = FakeAPI()
        previous = signal.getsignal(signal.SIGTERM)
        with self.assertRaises(module.Interrupted):
            with self.runner(api) as life:
                directory = life.private_dir
                life.create_namespaces()
                life._signal(signal.SIGTERM, None)  # synthetic, no real signal
        self.assertFalse(directory.exists())
        self.assertFalse(api.data)
        self.assertIs(signal.getsignal(signal.SIGTERM), previous)

    def test_budget_expires_but_cleanup_has_separate_budget(self):
        api = FakeAPI()
        now = [0]
        life = module.Lifecycle(api, token_factory=lambda: TOKEN, clock=lambda: now[0])
        with self.assertRaisesRegex(module.LifecycleError, "deadline"):
            with life:
                directory = life.private_dir
                life.create_namespaces()
                now[0] = 241
                life._time(life.deadline)
        self.assertFalse(directory.exists())
        self.assertFalse(api.data)

    def test_pki_generator_uses_private_umask_and_strict_key_modes(self):
        observed = []
        def fake_pki(folder, deadline):
            current = module.os.umask(0o077)
            module.os.umask(current)
            observed.append((folder, deadline, current))
            for name in ("ca.key", "server.key", "client.key", "witness.key"):
                (folder / name).write_bytes(b"not-a-real-private-key")
        api = FakeAPI()
        life = module.Lifecycle(api, token_factory=lambda: TOKEN, pki_generator=fake_pki)
        with life:
            directory = life.private_dir
            self.assertEqual(life.generate_pki(), directory)
            self.assertEqual(observed[0][2], 0o077)
            self.assertEqual(observed[0][1], life.deadline)
            self.assertTrue(all((directory / name).stat().st_mode & 0o777 == 0o600
                                for name in ("ca.key", "server.key", "client.key", "witness.key")))
        self.assertFalse(directory.exists())

    def test_pki_key_mode_violation_erases_private_dir(self):
        def unsafe(folder, deadline):
            for name in ("ca.key", "server.key", "client.key", "witness.key"):
                (folder / name).write_bytes(b"fixture")
            (folder / "server.key").chmod(0o644)
        life = module.Lifecycle(FakeAPI(), token_factory=lambda: TOKEN, pki_generator=unsafe)
        with self.assertRaisesRegex(module.LifecycleError, "generation failed"):
            with life:
                directory = life.private_dir
                life.generate_pki()
        self.assertFalse(directory.exists())

    def test_replaced_private_directory_is_not_deleted(self):
        api = FakeAPI()
        with tempfile.TemporaryDirectory(prefix="synthetic-test-") as parent:
            original = Path(parent) / "owned"
            replacement = Path(parent) / "replacement"
            def make_temp(prefix):
                original.mkdir(mode=0o700)
                return str(original)
            life = module.Lifecycle(api, token_factory=lambda: TOKEN, make_temp=make_temp)
            with self.assertRaisesRegex(module.LifecycleError, "cleanup unverified"):
                with life:
                    original.rename(replacement)
                    original.mkdir(mode=0o700)
            self.assertTrue(original.exists())
            self.assertTrue(replacement.exists())

    def test_fixed_argv_json_stdin_and_sanitized_error(self):
        recorded = []
        def fake(argv, **kwargs):
            recorded.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout=json.dumps({"kind": "Namespace", "metadata": {
                "name": "rtk-syn-" + TOKEN[:16], "uid": "b" * 32, "labels": {module.LABEL: TOKEN}}}))
        api = module.KubectlAPI(run=fake)
        name = "rtk-syn-" + TOKEN[:16]
        with mock.patch.dict(module.os.environ, {"IPINFO_TOKEN": "SECRET", "KUBECONFIG": "/test/config"}):
            api.create(name, TOKEN, False)
            api.delete_if_uid(name, "b" * 32)
        self.assertEqual(recorded[0][0], ["kubectl", "--context", module.CONTEXT,
                         "--request-timeout=10s", "create", "-f", "-", "-o", "json"])
        self.assertEqual(recorded[1][0][-3:], ["--raw=/api/v1/namespaces/" + name, "-f", "-"])
        self.assertEqual(json.loads(recorded[1][1]["input"])["preconditions"], {"uid": "b" * 32})
        self.assertEqual(json.loads(recorded[0][1]["input"])["metadata"]["name"], name)
        self.assertNotIn("IPINFO_TOKEN", recorded[0][1]["env"])
        self.assertTrue(all(x[1]["timeout"] <= 15 and x[1]["capture_output"] for x in recorded))
        def fail(argv, **kwargs):
            return subprocess.CompletedProcess(argv, 1, stdout="PRIVATE", stderr="SECRET")
        with self.assertRaises(module.LifecycleError) as ctx:
            module.KubectlAPI(run=fail).delete_if_uid(name, "b" * 32)
        self.assertNotIn("PRIVATE", str(ctx.exception))
        self.assertNotIn("SECRET", str(ctx.exception))
        with self.assertRaises(module.LifecycleError):
            api.delete_if_uid(name, "bad")
        self.assertEqual(len(recorded), 2)
        expired = module.KubectlAPI(run=fake, deadline=0, clock=lambda: 1)
        with self.assertRaisesRegex(module.LifecycleError, "total deadline"):
            expired.get(name)
        self.assertEqual(len(recorded), 2)


if __name__ == "__main__":
    unittest.main()
