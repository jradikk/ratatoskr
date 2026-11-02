#!/usr/bin/env python3
"""Adversarial pure fake UID/image/argv/exit checks for running workload probes."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_adapter_running", HERE / "adapter.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
TOKEN = "a" * 32
UID = "b" * 32
IMAGE = "sha256:" + "c" * 64


class NamespaceAPI:
    def get(self, name, timeout):
        return {"metadata": {"name": name, "uid": UID, "labels": {a.lifecycle.LABEL: TOKEN}}}


class Wire:
    def __init__(self, names):
        self.names = names
        self.calls = []
        self.current_uid = UID
        self.current_image = IMAGE
        self.output = b""
        self.failure = False
        self.phase = "Running"
        self.command = ["python3", "/usr/local/bin/check.py", "hold"]
    def __call__(self, argv, *, payload=None, timeout, max_output):
        self.calls.append((argv, payload, timeout, max_output))
        if "exec" in argv:
            if self.failure:
                raise a.AdapterError("TOKEN-OR-SECRET-UNTRUSTED")
            if self.output:
                return self.output
            return b""
        assert argv[4] == "get"
        name = argv[6]
        container = "client" if name == "synthetic-client" else "witness"
        spec = {"name": container, "imagePullPolicy": "Never",
                "image": "ratatoskr-synthetic-client:local" if container == "client" else
                         "ratatoskr-synthetic-witness:local"}
        if container == "client":
            spec.update(command=self.command, env=[{"name": "API_IP", "value": "10.43.0.1"}])
        else:
            spec.update(args=["--hold"])
        return json.dumps({"metadata": {"name": name, "namespace": argv[8], "uid": self.current_uid},
                           "spec": {"nodeName": "test-worker", "containers": [spec]},
                           "status": {"phase": self.phase, "containerStatuses": [
                               {"name": container, "ready": True, "imageID": self.current_image}]}}).encode()


def fixture():
    owner = a.lifecycle.Lifecycle(NamespaceAPI(), token_factory=lambda: TOKEN)
    owner.deadline = owner.clock() + 180
    owner.seen_absent = set(owner.names)
    owner.attempted = set(owner.names)
    owner.created = {name: UID for name in owner.names}
    owner.owned = dict(owner.created)
    wire = Wire(owner.names)
    return a.FixtureAPI(owner, transport=wire), wire


class RunningTests(unittest.TestCase):
    def test_exact_uid_image_and_fixed_probe_argv(self):
        api, wire = fixture()
        self.assertTrue(api.probe_running("synthetic-client", UID, IMAGE, "healthy", "10.43.0.1"))
        self.assertTrue(api.probe_running("synthetic-client", UID, IMAGE, "outage", "10.43.0.1"))
        self.assertTrue(api.probe_running("synthetic-witness", UID, IMAGE, "outage", "10.43.0.1"))
        self.assertTrue(api.probe_running("synthetic-witness", UID, IMAGE, "exit-off", "10.43.0.1"))
        executed = [call for call in wire.calls if "exec" in call[0]]
        self.assertEqual(len(executed), 4)
        self.assertEqual([call[0][-4:] for call in executed], [
            ["python3", "/usr/local/bin/check.py", "healthy", "10.43.0.1"],
            ["python3", "/usr/local/bin/check.py", "outage-check", "10.43.0.1"],
            ["--", "python3", "/usr/local/bin/witness.py", "--probe"],
            ["--", "python3", "/usr/local/bin/witness.py", "--exit-off"]])
        self.assertTrue(all(call[2] <= 12 and call[3] == 0 and call[1] is None for call in executed))

    def test_bad_uid_image_phase_cmd_or_probe_output_never_passes(self):
        for alter in (lambda api, w: setattr(w, "current_uid", "d" * 32),
                      lambda api, w: setattr(w, "current_image", "sha256:bad"),
                      lambda api, w: setattr(w, "phase", "Failed"),
                      lambda api, w: setattr(w, "command", ["sh", "-c", "sleep 600"]),
                      lambda api, w: setattr(w, "output", b"private"),
                      lambda api, w: setattr(w, "failure", True)):
            with self.subTest(alter=alter):
                api, wire = fixture()
                alter(api, wire)
                with self.assertRaises(a.AdapterError) as result:
                    api.probe_running("synthetic-client", UID, IMAGE, "outage", "10.43.0.1")
                self.assertNotIn("private", str(result.exception))
                self.assertNotIn("TOKEN-OR-SECRET", str(result.exception))
        api, wire = fixture()
        for name, phase, ip in (("foreign", "outage", "10.43.0.1"),
                                ("synthetic-client", "raw-shell", "10.43.0.1"),
                                ("synthetic-client", "outage", "127.0.0.1"),
                                ("synthetic-witness", "healthy", "10.43.0.1"),
                                ("synthetic-client", "exit-off", "10.43.0.1")):
            with self.assertRaises(a.AdapterError):
                api.probe_running(name, UID, IMAGE, phase, ip)


if __name__ == "__main__":
    unittest.main()
