#!/usr/bin/env python3
"""Fake API-only UID/resourceVersion probe outage tests."""
import importlib.util
import json
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_adapter_probe", HERE / "adapter.py")
a = importlib.util.module_from_spec(spec)
spec.loader.exec_module(a)
TOKEN = "a" * 32
UID = "b" * 32


class NamespaceAPI:
    def get(self, name, timeout):
        return {"metadata": {"name": name, "uid": UID, "labels": {a.lifecycle.LABEL: TOKEN}}}


class Transport:
    def __init__(self, namespace):
        self.namespace = namespace
        self.uid = "c" * 32
        self.version = 17
        self.state = "true"
        self.calls = []
        self.poison = None
        self.fail_after_commit = False

    def object(self):
        value = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
            "name": "synthetic-exit-health", "namespace": self.namespace,
            "uid": self.uid, "resourceVersion": str(self.version),
            "labels": {a.lifecycle.LABEL: TOKEN}}, "data": {"exit-enabled": self.state}}
        if self.poison:
            self.poison(value)
        return value

    def __call__(self, argv, *, payload, timeout, max_output):
        self.calls.append((argv, payload, timeout, max_output))
        if argv[4] == "get":
            assert (argv[5], argv[6], argv[8]) == ("configmap", "synthetic-exit-health", self.namespace)
            return json.dumps(self.object()).encode()
        if argv[4] == "create":
            assert argv[5:] == ["-f", "-", "-o", "name"]
            assert json.loads(payload)["metadata"]["namespace"] == self.namespace
            return b"configmap/synthetic-exit-health"
        assert argv[4:6] == ["replace", "--raw=/api/v1/namespaces/" + self.namespace + "/configmaps/synthetic-exit-health"]
        body = json.loads(payload)
        assert body["metadata"]["uid"] == self.uid
        assert body["metadata"]["resourceVersion"] == str(self.version)
        self.state = body["data"]["exit-enabled"]
        self.version += 1
        if self.fail_after_commit:
            self.fail_after_commit = False
            raise a.AdapterError("simulated lost response")
        return json.dumps(self.object()).encode()


def fixture():
    owner = a.lifecycle.Lifecycle(NamespaceAPI(), token_factory=lambda: TOKEN)
    owner.deadline = owner.clock() + 180
    owner.seen_absent = set(owner.names)
    owner.attempted = set(owner.names)
    owner.created = {n: UID for n in owner.names}
    owner.owned = dict(owner.created)
    wire = Transport(owner.names[0])
    return a.FixtureAPI(owner, transport=wire), wire


class AdapterProbeTests(unittest.TestCase):
    def test_exact_uid_version_update_and_restore_with_no_secret_or_shell(self):
        api, wire = fixture()
        with api.exit_health_outage() as uid:
            self.assertEqual(uid, wire.uid)
            self.assertEqual((wire.state, wire.version), ("false", 18))
        self.assertEqual((wire.state, wire.version), ("true", 19))
        updates = [c for c in wire.calls if c[0][4] == "replace"]
        self.assertEqual(len(updates), 2)
        self.assertEqual([json.loads(c[1])["metadata"]["resourceVersion"] for c in updates], ["17", "18"])
        self.assertEqual([json.loads(c[1])["data"] for c in updates],
                         [{"exit-enabled": "false"}, {"exit-enabled": "true"}])
        self.assertTrue(all(c[2] <= 12 and c[3] <= 4096 for c in updates))
        self.assertTrue(all("SECRET" not in str(c[0]) and "sh" not in c[0] for c in updates))

    def test_create_only_owned_initial_probe_configmap(self):
        api, wire = fixture()
        namespace = api.owner.names[0]
        obj = {"apiVersion": "v1", "kind": "ConfigMap", "metadata": {
            "name": "synthetic-exit-health", "namespace": namespace,
            "labels": {a.lifecycle.LABEL: TOKEN}}, "data": {"exit-enabled": "true"}}
        # Fixture creation uses a separate API path; capture exact stdin and
        # refuse an unowned or already-disabled initial object.
        api.create(obj)
        creations = [c for c in wire.calls if c[0][4] == "create"]
        self.assertEqual(len(creations), 1)
        self.assertEqual(json.loads(creations[0][1]), obj)
        for wrong in (
            dict(obj, data={"exit-enabled": "false"}),
            dict(obj, data={"exit-enabled": "true", "private": "SECRET"}),
            dict(obj, metadata=dict(obj["metadata"], labels={a.lifecycle.LABEL: "d" * 32})),
            dict(obj, metadata=dict(obj["metadata"], namespace=api.owner.names[1])),
        ):
            with self.assertRaises(a.AdapterError) as error:
                api.create(wrong)
            self.assertNotIn("SECRET", str(error.exception))
        self.assertEqual(len([c for c in wire.calls if c[0][4] == "create"]), 1)

    def test_body_failure_still_restores(self):
        api, wire = fixture()
        with self.assertRaisesRegex(ValueError, "test only"):
            with api.exit_health_outage():
                raise ValueError("test only")
        self.assertEqual(wire.state, "true")

    def test_lost_response_after_commit_restores_and_blocks_success(self):
        api, wire = fixture()
        wire.fail_after_commit = True
        with self.assertRaises(a.AdapterError):
            with api.exit_health_outage():
                self.fail("should not enter outage body")
        self.assertEqual(wire.state, "true")
        self.assertEqual(len([c for c in wire.calls if c[0][4] == "replace"]), 2)

    def test_foreign_uid_label_or_version_blocks_overwrite(self):
        for tamper in (
            lambda wire: setattr(wire, "uid", "d" * 32),
            lambda wire: setattr(wire, "version", 18),
            lambda wire: setattr(wire, "poison", lambda obj: obj["metadata"]["labels"].update(extra="foreign")),
        ):
            with self.subTest(tamper=tamper):
                api, wire = fixture()
                uid, version, _ = api.exit_health_snapshot()
                tamper(wire)
                with self.assertRaises(a.AdapterError):
                    api._replace_exit_health(uid, version, False)
                self.assertEqual(wire.state, "true")
                self.assertFalse(any(c[0][4] == "replace" for c in wire.calls))

    def test_replacement_during_outage_blocks_restore_no_false_pass(self):
        api, wire = fixture()
        with self.assertRaisesRegex(a.AdapterError, "restoration unverified"):
            with api.exit_health_outage():
                wire.uid = "d" * 32
        self.assertEqual(wire.state, "false")  # cannot write a foreign object
        self.assertEqual(len([c for c in wire.calls if c[0][4] == "replace"]), 1)

    def test_insufficient_budget_prevents_mutation(self):
        api, wire = fixture()
        api.owner.deadline = api.owner.clock() + 10
        with self.assertRaises(a.AdapterError):
            with api.exit_health_outage():
                self.fail("must not execute")
        self.assertEqual(wire.calls, [])

    def test_malformed_input_or_external_mutation_fails_closed(self):
        for change in (lambda w: setattr(w, "state", "malicious"),
                       lambda w: setattr(w, "state", "false"),
                       lambda w: setattr(w, "uid", "bad"),
                       lambda w: setattr(w, "version", -1)):
            api, wire = fixture()
            change(wire)
            with self.assertRaises(a.AdapterError):
                with api.exit_health_outage():
                    self.fail("should not start")
            self.assertFalse(any(c[0][4] == "replace" for c in wire.calls))


if __name__ == "__main__":
    unittest.main()
