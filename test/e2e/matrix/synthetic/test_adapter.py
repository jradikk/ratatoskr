#!/usr/bin/env python3
"""All adapters injected with fake transport/namespace API; no kubectl/PKI."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_adapter", HERE / "adapter.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
TOKEN = "a" * 32
UID = "b" * 32
POD_UID = "c" * 32
IMAGE = "containerd://sha256:" + "d" * 64


class NamespaceAPI:
    def __init__(self):
        self.calls = []
    def get(self, name, timeout):
        self.calls.append((name, timeout))
        return {"metadata": {"name": name, "uid": UID, "labels": {a.lifecycle.LABEL: TOKEN}}}


class FakeTransport:
    def __init__(self):
        self.calls = []
        self.image = IMAGE
        self.uid = POD_UID
        self.fail = None

    def __call__(self, argv, *, payload, timeout, max_output):
        self.calls.append((argv, payload, timeout, max_output))
        if self.fail is not None:
            raise self.fail
        if argv[4] == "get":
            obj = {"kind": "Pod", "metadata": {"name": argv[6], "namespace": argv[8], "uid": self.uid},
                   "spec": {"nodeName": "test-worker", "containers": [
                       {"name": "client", "imagePullPolicy": "Never"},
                       {"name": "server", "imagePullPolicy": "Never"}]},
                   "status": {"containerStatuses": [{"name": "client", "ready": True, "imageID": self.image},
                                                    {"name": "server", "ready": True, "imageID": self.image}]}}
            return json.dumps(obj).encode()
        if "exec" in argv:
            if a.SERVER_COMMAND[1] in argv:
                return json.dumps({"cn": "synthetic-client", "virtualIPv4": "10.88.0.2", "received": 22,
                                   "sent": 33, "connected": 100, "peer": 7, "cipher": "AES-256-GCM"}).encode()
            return b"safe-result\n"
        return b"pod/synthetic-client\n"


def make():
    owner = a.lifecycle.Lifecycle(NamespaceAPI(), token_factory=lambda: TOKEN)
    owner.deadline = owner.clock() + 180
    owner.names = ("rtk-syn-" + TOKEN[:16], "rtk-syn-" + TOKEN[:16] + "-apps")
    owner.seen_absent = set(owner.names)
    owner.attempted = set(owner.names)
    owner.created = {name: UID for name in owner.names}
    owner.owned = dict(owner.created)
    fake = FakeTransport()
    return a.FixtureAPI(owner, fake), fake


class AdapterTests(unittest.TestCase):
    def test_pod_read_checks_uid_and_exact_immutable_image_id(self):
        adapter, fake = make()
        ns = adapter.owner.names[1]
        self.assertEqual(adapter.pod_image_id(ns, "synthetic-client", "client", POD_UID), IMAGE)
        self.assertEqual(fake.calls[0][0], ["kubectl", "--context", a.CONTEXT, "--request-timeout=10s",
                                            "get", "pod", "synthetic-client", "--namespace", ns, "-o", "json"])
        for invalid in ("latest", "", "sha256:bad"):
            fake.image = invalid
            with self.assertRaises(a.AdapterError):
                adapter.pod_image_id(ns, "synthetic-client", "client", POD_UID)
        fake.image = IMAGE
        with self.assertRaises(a.AdapterError):
            adapter.pod_image_id(ns, "synthetic-client", "client", "e" * 32)

    def test_stdin_create_no_secret_in_argv_or_errors(self):
        adapter, fake = make()
        ns = adapter.owner.names[0]
        obj = {"apiVersion": "v1", "kind": "Secret", "type": "Opaque",
               "metadata": {"name": "synthetic-server", "namespace": ns},
               "data": {"ca.crt": "PUBLIC", "server.crt": "PUBLIC", "server.conf": "PRIVATE", "server.key": "PRIVATE-CREDENTIAL"}}
        adapter.create(obj)
        argv, data, timeout, limit = fake.calls[-1]
        self.assertEqual(argv[-5:], ["create", "-f", "-", "-o", "name"])
        self.assertNotIn("PRIVATE-CREDENTIAL", " ".join(argv))
        self.assertIn(b"PRIVATE-CREDENTIAL", data)
        self.assertLessEqual(timeout, 12)
        self.assertEqual(limit, 1024)
        fake.fail = RuntimeError("PRIVATE-CREDENTIAL printed by API")
        with self.assertRaises(a.AdapterError) as ctx:
            adapter.create(obj)
        self.assertNotIn("PRIVATE-CREDENTIAL", str(ctx.exception))

    def test_preexisting_replacement_or_foreign_namespace_denied(self):
        adapter, fake = make()
        ns = adapter.owner.names[0]
        adapter.owner.owned.pop(ns)
        with self.assertRaises(a.AdapterError):
            adapter.create({"kind": "Secret", "metadata": {"name": "synthetic-server", "namespace": ns}})
        self.assertFalse(fake.calls)
        adapter.owner.owned[ns] = UID
        original = adapter.owner.api.get
        adapter.owner.api.get = lambda name, timeout: {"metadata": {"name": name, "uid": "f" * 32,
                                                           "labels": {a.lifecycle.LABEL: TOKEN}}}
        with self.assertRaises(a.AdapterError):
            adapter.create({"kind": "Secret", "metadata": {"name": "synthetic-server", "namespace": ns}})
        self.assertFalse(fake.calls)
        adapter.owner.api.get = original
        adapter.owner.closed = True
        with self.assertRaises(a.AdapterError):
            adapter.get("pod", "synthetic-vpn", ns)

    def test_malicious_names_commands_and_object_types_never_reach_subprocess(self):
        adapter, fake = make()
        ns = adapter.owner.names[1]
        for name in ("--all", "../synthetic", "synthetic;exit", "synthetic-../../unsafe"):
            with self.assertRaises(a.AdapterError):
                adapter.get("pod", name, ns)
        for obj in ({"kind": "Namespace", "metadata": {"name": "synthetic", "namespace": ns}},
                    {"kind": "Pod", "metadata": {"name": "--all", "namespace": ns}},
                    {"kind": "Secret", "metadata": {"name": "synthetic-server", "namespace": ns}},
                    {"kind": "Pod", "metadata": {"name": "synthetic-client", "namespace": ns},
                     "data": {"blob": "x" * 100000}}):
            with self.assertRaises(a.AdapterError):
                adapter.create(obj)
        for command in ("sh", "cat /etc/synthetic/server.key", "vpn-marker;sh", "logs"):
            with self.assertRaises(a.AdapterError):
                adapter.exec(ns, "synthetic-client", POD_UID, "client", command, expected_image_id=IMAGE)
        with self.assertRaises(a.AdapterError):
            adapter.exec(ns, "synthetic-vpn", POD_UID, "server", "vpn-marker", expected_image_id=IMAGE)
        self.assertFalse(fake.calls)

    def test_exec_fixed_argv_uid_check_and_output_bound(self):
        adapter, fake = make()
        ns = adapter.owner.names[1]
        self.assertEqual(adapter.exec(ns, "synthetic-client", POD_UID, "client", "vpn-marker", expected_image_id=IMAGE), "safe-result\n")
        commands = [call for call in fake.calls if "exec" in call[0]]
        self.assertEqual(len(commands), 1)
        argv, data, timeout, limit = commands[0]
        self.assertEqual(argv, ["kubectl", "--context", a.CONTEXT, "--request-timeout=10s",
                                "--namespace", ns, "exec", "synthetic-client", "-c", "client", "--",
                                *a.COMMANDS["vpn-marker"]])
        self.assertNotIn("sh", argv)
        self.assertIsNone(data)
        self.assertEqual(limit, 4096)
        fake.uid = "e" * 32
        with self.assertRaises(a.AdapterError):
            adapter.exec(ns, "synthetic-client", POD_UID, "client", "vpn-marker", expected_image_id=IMAGE)
        fake.uid = POD_UID
        fake.fail = ValueError("SECRET-ERROR")
        with self.assertRaises(a.AdapterError) as ctx:
            adapter.exec(ns, "synthetic-client", POD_UID, "client", "vpn-marker", expected_image_id=IMAGE)
        self.assertNotIn("SECRET-ERROR", str(ctx.exception))
        fake.fail = None
        original = fake.__call__
        adapter.transport = lambda argv, **kwargs: b"a" * 4097
        with self.assertRaises(a.AdapterError):
            adapter.exec(ns, "synthetic-client", POD_UID, "client", "vpn-marker", expected_image_id=IMAGE)

    def test_exec_requires_expected_runtime_image(self):
        adapter, fake = make()
        namespace = adapter.owner.names[1]
        for image in ("", "sha256:bad", "latest", "containerd://sha256:" + "e" * 64):
            with self.assertRaises(a.AdapterError):
                adapter.exec(namespace, "synthetic-client", POD_UID, "client", "vpn-marker", expected_image_id=image)
        self.assertFalse(any("exec" in call[0] for call in fake.calls))

    def test_server_session_only_pinned_sanitized_exec(self):
        adapter, fake = make()
        ns = adapter.owner.names[0]
        data = adapter.server_session(ns, POD_UID, expected_image_id=IMAGE)
        self.assertEqual((data["cn"], data["received"], data["sent"]), ("synthetic-client", 22, 33))
        argv = next(call[0] for call in fake.calls if a.SERVER_COMMAND[1] in call[0])
        self.assertEqual(argv[-len(a.SERVER_COMMAND):], list(a.SERVER_COMMAND))
        self.assertNotIn("cat", argv)
        self.assertNotIn("logs", argv)
        with self.assertRaises(a.AdapterError):
            adapter.server_session(adapter.owner.names[1], POD_UID, expected_image_id=IMAGE)
        with self.assertRaises(a.AdapterError):
            adapter.server_session(ns, POD_UID, expected_image_id="latest")
        fake.uid = "f" * 32
        with self.assertRaises(a.AdapterError):
            adapter.server_session(ns, POD_UID, expected_image_id=IMAGE)
        fake.uid = POD_UID
        old_transport = adapter.transport
        adapter.transport = lambda argv, **kw: b'{"cn":"synthetic-client","privateKey":"SECRET"}' if a.SERVER_COMMAND[1] in argv else old_transport(argv, **kw)
        with self.assertRaises(a.AdapterError) as ctx:
            adapter.server_session(ns, POD_UID, expected_image_id=IMAGE)
        self.assertNotIn("SECRET", str(ctx.exception))

    def test_direct_api_command_is_tls_verified_anonymous_fixed_and_bounded(self):
        adapter, fake = make()
        ns = adapter.owner.names[1]
        self.assertEqual(adapter.exec(ns, "synthetic-client", POD_UID, "client", "direct-api-tls",
                                      expected_image_id=IMAGE), "safe-result\n")
        argv = next(call[0] for call in fake.calls if "--cacert" in call[0])
        self.assertEqual(argv[-len(a.COMMANDS["direct-api-tls"]):], list(a.COMMANDS["direct-api-tls"]))
        command = a.COMMANDS["direct-api-tls"]
        self.assertEqual(command[:2], ("curl", "--disable"))
        self.assertEqual(command[command.index("--cacert") + 1], "/var/run/ratatoskr/api-ca/ca.crt")
        self.assertNotIn("--insecure", command)
        self.assertNotIn("-k", command)
        self.assertNotIn("--location", command)
        self.assertNotIn("--header", command)
        self.assertNotIn("--user", command)
        self.assertNotIn("sh", command)
        self.assertTrue(command[-1].startswith("https://kubernetes.default.svc.cluster.local/"))
        route = a.COMMANDS["direct-api-route"]
        self.assertEqual(route[-4:], ("ipproto", "tcp", "dport", "443"))

    def test_deadline_denies_transport(self):
        adapter, fake = make()
        adapter.owner.deadline = adapter.owner.clock() - 1
        with self.assertRaises(a.AdapterError):
            adapter.get("pod", "synthetic-client", adapter.owner.names[1])
        self.assertFalse(fake.calls)

    def test_stdin_pipe_blocked_by_child_obeys_timeout(self):
        payload = b"not-a-key" * 8192
        argv = [sys.executable, "-c", "import time;time.sleep(5)"]
        with self.assertRaises(a.AdapterError) as ctx:
            a._bounded(argv, payload=payload, timeout=0.05, max_output=32)
        self.assertNotIn("not-a-key", str(ctx.exception))

    def test_real_transport_simulated_subprocess_bounds_and_no_leaks(self):
        argv = [sys.executable, "-c", "import sys; print('SECRET'); sys.exit(1)"]
        with self.assertRaises(a.AdapterError) as ctx:
            a._bounded(argv, timeout=2, max_output=32)
        self.assertNotIn("SECRET", str(ctx.exception))
        # Child inherited only PATH/HOME/KUBECONFIG and no private env vars.
        argv = [sys.executable, "-c", "import os,sys;sys.stdout.write(os.getenv('PRIVATE_MARKER','absent'))"]
        with patch.dict(a.os.environ, {"PRIVATE_MARKER": "SECRET"}):
            self.assertEqual(a._bounded(argv, timeout=2, max_output=32), b"absent")
        argv = [sys.executable, "-c", "import sys;sys.stdout.write('x'*20000)"]
        with self.assertRaises(a.AdapterError):
            a._bounded(argv, timeout=2, max_output=32)
        argv = [sys.executable, "-c", "import time;time.sleep(5)"]
        with self.assertRaises(a.AdapterError):
            a._bounded(argv, timeout=0.05, max_output=32)


if __name__ == "__main__":
    unittest.main()
