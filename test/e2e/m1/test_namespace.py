"""Fake API/argv tests only: no kubectl, cluster, files from home or live tests."""
import importlib.util
import json
from pathlib import Path
import subprocess
import tempfile
import unittest

spec = importlib.util.spec_from_file_location("m1_namespace", Path(__file__).with_name("namespace.py"))
ns = importlib.util.module_from_spec(spec)
spec.loader.exec_module(ns)
TOKEN = "a" * 32
NAME = "ratatoskr-m1-live-" + TOKEN
UID = "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee"
OTHER = "11111111-2222-3333-4444-555555555555"


def obj(uid=UID, token=TOKEN):
    result = ns.namespace_object(NAME, TOKEN)
    result["metadata"]["uid"] = uid
    result["metadata"]["labels"][ns.LABEL] = token
    return result


class FakeAPI:
    def __init__(self):
        self.item = None
        self.calls = []
        self.ambiguous = False
        self.conflict = False
        self.replace_before_delete = False
        self.replace_after_delete = False
        self.terminating = 0
        self.delete_fail = False

    def get(self, name, timeout=12):
        self.calls.append(("get", name))
        if self.terminating:
            self.terminating -= 1
            if not self.terminating:
                self.item = None
        return self.item

    def create(self, name, token):
        self.calls.append(("create", name))
        if self.conflict:
            self.item = obj(OTHER, "foreign")
            raise ns.NamespaceError("conflict")
        self.item = obj()
        if self.ambiguous:
            raise ns.NamespaceError("ambiguous create timeout")
        return UID

    def delete(self, name, uid, timeout=12):
        self.calls.append(("delete", name, uid))
        if self.replace_before_delete:
            self.item = obj(OTHER)
        if self.delete_fail or self.item["metadata"]["uid"] != uid:
            raise ns.NamespaceError("precondition conflict")
        if self.replace_after_delete:
            self.item = obj(OTHER)
        elif not self.terminating:
            self.item = None


class NamespaceTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ratatoskr-m1-namespace-unit-")
        self.addCleanup(self.temp.cleanup)
        self.private = Path(self.temp.name)
        self.api = FakeAPI()

    def create(self):
        ns.create_namespace(self.api, self.private, NAME, TOKEN)

    def cleanup(self):
        ns.cleanup_namespace(self.api, self.private, sleep=lambda _: None)

    def test_random_uuid_namespace_and_owner_identity(self):
        identities = {ns.identity("live") for _ in range(100)}
        self.assertEqual(len(identities), 100)
        for name, token in identities:
            ns.validate_identity(name, token)
            self.assertEqual(len(token), 32)
            self.assertFalse(name.endswith(token))
        self.assertLessEqual(len(NAME), 63)

    def test_success_single_create_and_exact_uid_delete(self):
        self.create()
        record = self.private / "namespace-owner.json"
        self.assertEqual(record.stat().st_mode & 0o777, 0o600)
        self.cleanup()
        self.assertIsNone(self.api.item)
        self.assertEqual([x for x in self.api.calls if x[0] == "create"], [("create", NAME)])
        self.assertEqual([x for x in self.api.calls if x[0] == "delete"], [("delete", NAME, UID)])
        self.assertFalse(record.exists())

    def test_preexisting_namespace_never_created_or_deleted(self):
        self.api.item = obj(OTHER, "foreign")
        with self.assertRaises(ns.NamespaceError):
            self.create()
        self.cleanup()
        self.assertEqual(self.api.item["metadata"]["uid"], OTHER)
        self.assertFalse(any(x[0] in ("create", "delete") for x in self.api.calls))

    def test_create_race_foreign_namespace_never_adopted(self):
        self.api.conflict = True
        with self.assertRaises(ns.NamespaceError):
            self.create()
        with self.assertRaises(ns.NamespaceError):
            self.cleanup()
        self.assertEqual(self.api.item["metadata"]["uid"], OTHER)
        self.assertEqual(len([x for x in self.api.calls if x[0] == "create"]), 1)
        self.assertFalse(any(x[0] == "delete" for x in self.api.calls))

    def test_ambiguous_create_even_matching_owner_not_adopted(self):
        self.api.ambiguous = True
        with self.assertRaises(ns.NamespaceError):
            self.create()
        before = list(self.api.calls)
        with self.assertRaises(ns.NamespaceError):
            self.cleanup()
        self.assertEqual(self.api.calls, before)
        self.assertEqual(self.api.item["metadata"]["uid"], UID)

    def test_replaced_before_cleanup_get_never_deleted(self):
        self.create()
        self.api.item = obj(OTHER)
        with self.assertRaises(ns.NamespaceError):
            self.cleanup()
        self.assertFalse(any(x[0] == "delete" for x in self.api.calls))

    def test_owner_label_changed_never_deleted(self):
        self.create()
        self.api.item = obj(UID, "foreign")
        with self.assertRaises(ns.NamespaceError):
            self.cleanup()
        self.assertFalse(any(x[0] == "delete" for x in self.api.calls))

    def test_replaced_between_get_delete_protected_by_uid(self):
        self.create()
        self.api.replace_before_delete = True
        with self.assertRaises(ns.NamespaceError):
            self.cleanup()
        self.assertEqual(self.api.item["metadata"]["uid"], OTHER)
        self.assertEqual([x for x in self.api.calls if x[0] == "delete"], [("delete", NAME, UID)])

    def test_replaced_after_delete_no_second_delete(self):
        self.create()
        self.api.replace_after_delete = True
        with self.assertRaises(ns.NamespaceError):
            self.cleanup()
        self.assertEqual(self.api.item["metadata"]["uid"], OTHER)
        self.assertEqual(len([x for x in self.api.calls if x[0] == "delete"]), 1)

    def test_namespace_deletion_waits_for_absence(self):
        self.create()
        self.api.terminating = 4
        self.cleanup()
        self.assertIsNone(self.api.item)
        self.assertEqual(len([x for x in self.api.calls if x[0] == "delete"]), 1)

    def test_delete_error_never_falls_back_to_name_only(self):
        self.create()
        self.api.delete_fail = True
        with self.assertRaises(ns.NamespaceError):
            self.cleanup()
        self.assertEqual(len([x for x in self.api.calls if x[0] == "delete"]), 1)
        self.assertIsNotNone(self.api.item)

    def test_no_record_cleanup_makes_no_api_call(self):
        self.cleanup()
        self.assertEqual(self.api.calls, [])

    def test_adapter_raw_delete_uses_uid_precondition_and_sanitized_env(self):
        calls = []
        def runner(argv, **kwargs):
            calls.append((argv, kwargs))
            return subprocess.CompletedProcess(argv, 0, stdout="{}", stderr="")
        api = ns.KubectlAPI(run=runner)
        api.delete(NAME, UID)
        argv, kwargs = calls[0]
        self.assertEqual(argv[-3:], ["--raw=/api/v1/namespaces/" + NAME, "-f", "-"])
        self.assertEqual(json.loads(kwargs["input"])["preconditions"], {"uid": UID})
        self.assertNotIn("IPINFO_TOKEN", kwargs["env"])
        self.assertTrue(kwargs["capture_output"])
        self.assertLessEqual(kwargs["timeout"], 12)

    def test_adapter_create_response_requires_owner_and_uid(self):
        for result in [obj(UID, "foreign"), obj("bad-uid"), {}, "malformed"]:
            def runner(argv, **kwargs):
                return subprocess.CompletedProcess(argv, 0, stdout=json.dumps(result), stderr="")
            with self.subTest(response=type(result).__name__):
                with self.assertRaises(ns.NamespaceError):
                    ns.KubectlAPI(run=runner).create(NAME, TOKEN)

    def test_adapter_ambiguous_timeout_suppresses_output(self):
        def runner(argv, **kwargs):
            raise subprocess.TimeoutExpired(argv, 12, output="synthetic-sensitive", stderr="synthetic-sensitive")
        with self.assertRaises(ns.NamespaceError) as caught:
            ns.KubectlAPI(run=runner).create(NAME, TOKEN)
        self.assertNotIn("synthetic-sensitive", str(caught.exception))

    def test_namespace_is_not_readopted_by_resource_templates(self):
        for path in Path(__file__).with_name("templates").glob("*.yaml.tmpl"):
            if path.name != "namespace.yaml.tmpl":
                self.assertNotIn("kind: Namespace", path.read_text())

    def test_repeated_create_cannot_overwrite_ownership_record(self):
        self.create()
        with self.assertRaises(OSError):
            self.create()
        self.assertEqual(len([x for x in self.api.calls if x[0] == "create"]), 1)
        self.cleanup()

    def test_shell_has_no_name_only_namespace_delete_or_apply(self):
        text = Path(__file__).with_name("run.sh").read_text()
        self.assertNotIn('NAMESPACE_CREATED=yes', text)
        self.assertNotIn('delete namespace "$NAMESPACE"', text)
        self.assertNotIn('apply -f "$PRIVATE/namespace.yaml"', text)
        self.assertIn('namespace.py" create', text)
        self.assertIn('namespace.py" cleanup', text)


if __name__ == "__main__":
    unittest.main()
