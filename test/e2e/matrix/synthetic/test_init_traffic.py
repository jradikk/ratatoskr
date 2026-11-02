#!/usr/bin/env python3
"""All fake-only init traffic tests; never run kubectl, Docker or PKI."""
import contextlib
import io
import importlib.util
from pathlib import Path
import sys
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_init_traffic", HERE / "init_traffic.py")
runner = importlib.util.module_from_spec(spec)
spec.loader.exec_module(runner)
from test_init_smoke import InitAPI, INIT_ID, INIT_IDS
from test_partial_gateway import FakeOwner, FakeAdapter, UID, IDS as BASE_IDS
import test_run


class InitOwner(FakeOwner):
    def __init__(self, apps_psa):
        super().__init__()
        self.apps_psa = apps_psa
        self.calls = []
    def create_namespaces(self):
        self.calls.append("namespaces")
        super().create_namespaces()
    def generate_pki(self):
        self.calls.append("pki")
        super().generate_pki()
    def __exit__(self, exc_type, exc, tb):
        self.calls.append("cleanup")
        return super().__exit__(exc_type, exc, tb)


class InitTests(unittest.TestCase):
    def setUp(self):
        self.owner = InitOwner("privileged")
        self.adapter = FakeAdapter(self.owner)
        self.baseline = {"gatewayUID": UID, "serverUID": UID, "gatewayPodUID": UID,
                         "gatewayID": 7, "endpoint": "10.42.1.7", "session": {"cn": "synthetic-client"}}
        self.result = {"podUID": UID, "initImageID": INIT_ID,
                       "appImageID": INIT_IDS["selected"], "healthyExit": True}

    def execute(self, **kwargs):
        with patch.object(runner.partial_gateway, "private_contents", return_value=("x",) * 7):
            return runner.execute(INIT_IDS, api_ip="10.43.0.1",
                                  lifecycle_factory=lambda **options: self.owner,
                                  adapter_factory=lambda owner: self.adapter,
                                  observer=lambda *_args: self.baseline,
                                  selected_observer=lambda *_args: self.result, **kwargs)

    def test_privileged_app_namespace_base_order_selected_and_cleanup(self):
        self.assertIs(self.execute(), False)
        self.assertEqual(self.owner.calls, ["namespaces", "pki", "cleanup"])
        self.assertEqual([(x["kind"], x["name"]) for x in self.adapter.created], list(runner.partial_gateway.BASE))
        self.assertTrue(self.owner.cleanup_attempted)

    def test_wrong_init_id_or_missing_preflight_ip_never_mutates(self):
        for invalid in (dict(INIT_IDS, init="latest"), BASE_IDS):
            with self.subTest(invalid=invalid), self.assertRaises(runner.Blocked):
                runner.execute(invalid, api_ip="10.43.0.1",
                               lifecycle_factory=lambda **_opts: self.fail("lifecycle must not run"))
        with self.assertRaises(runner.Blocked):
            runner.execute(INIT_IDS, lifecycle_factory=lambda **_opts: self.fail("no mutation"))
        self.assertFalse(self.owner.created_namespaces)

    def test_cleanup_failure_overrides_happy_evidence(self):
        self.owner.fail_cleanup = True
        with self.assertRaises(runner.lifecycle.LifecycleError):
            self.execute()
        self.assertTrue(self.owner.cleanup_attempted)

    def test_wrong_psa_blocks_pki_resource_creation_and_cleans(self):
        self.owner.apps_psa = "restricted"
        with self.assertRaises(runner.Blocked):
            self.execute()
        self.assertTrue(self.owner.cleanup_attempted)
        self.assertFalse(self.owner.generated_pki)
        self.assertFalse(self.adapter.created)

    def test_ambiguous_secret_create_still_cleans_without_second_post(self):
        self.adapter.fail_at = 2
        with self.assertRaises(runner.adapter.AdapterError):
            self.execute()
        self.assertEqual(len(self.adapter.created), 2)
        self.assertTrue(self.owner.cleanup_attempted)

    def test_bad_uid_or_selected_privilege_evidence_blocks(self):
        self.result["podUID"] = "foreign"
        with self.assertRaises(runner.Blocked):
            self.execute()
        self.assertTrue(self.owner.cleanup_attempted)
        self.result = {"podUID": UID, "initImageID": "wrong",
                       "appImageID": BASE_IDS["selected"], "healthyExit": True}
        self.owner = InitOwner("privileged")
        self.adapter = FakeAdapter(self.owner)
        with self.assertRaises(runner.Blocked):
            self.execute()

    def test_uid_pinned_terminal_failure_exits_immediately_without_retry_or_status_leak(self):
        expected = dict(INIT_IDS)
        for phase, init_exit, app_exit, label in (
                ("Failed", 1, None, "init-failed"),
                ("Failed", 0, 13, "app-failed"),
                ("Failed", None, None, "pod-failed-unknown")):
            with self.subTest(label=label):
                owner = InitOwner("privileged")
                owner.deadline = float("inf")
                owner.clock = lambda: 0
                creations = []
                sleeps = []
                class PodAPI:
                    def create(self, obj):
                        creations.append(obj["kind"])
                        return {"kind": "Pod", "namespace": owner.names[1],
                                "name": "synthetic-probe-healthy", "uid": UID}
                    def get(self, resource, name, namespace):
                        self.assertions = (resource, name, namespace)
                        statuses = ([] if init_exit is None else [{"name": "ratatoskr-init", "state": {
                            "terminated": {"exitCode": init_exit}}}])
                        app = ([] if app_exit is None else [{"name": "client", "state": {
                            "terminated": {"exitCode": app_exit}}}])
                        return {"metadata": {"uid": UID}, "status": {"phase": phase,
                                "initContainerStatuses": statuses, "containerStatuses": app,
                                "message": "sensitive remote message must not be printed"}}
                baseline = dict(self.baseline, session={"cn": "synthetic-client",
                              "received": 1, "sent": 1})
                api = PodAPI()
                with self.assertRaisesRegex(runner.TerminalFailure,
                                            "Init-driver partial traffic failed at init-selected-pod-" + label):
                    runner.selected(api, owner, expected,
                                    {("EgressGateway", owner.names[0], "synthetic"): UID,
                                     ("Pod", owner.names[0], "synthetic-vpn"): UID},
                                    baseline, "10.43.0.1", clock=lambda: 0,
                                    sleep=lambda duration: sleeps.append(duration))
                self.assertEqual(creations, ["Pod"])
                self.assertEqual(api.assertions, ("pod", "synthetic-probe-healthy", owner.names[1]))
                self.assertEqual(sleeps, [])

    def test_terminal_failure_keeps_uid_scoped_cleanup_and_failure_classification(self):
        self.baseline["session"] = {"cn": "synthetic-client", "received": 1, "sent": 1}
        def fail_selected(*args):
            raise runner.TerminalFailure("Init-driver partial traffic failed at init-selected-pod-init-failed.")
        with patch.object(runner.partial_gateway, "private_contents", return_value=("x",) * 7):
            with self.assertRaisesRegex(runner.TerminalFailure, "init-selected-pod-init-failed"):
                runner.execute(INIT_IDS, api_ip="10.43.0.1",
                               lifecycle_factory=lambda **_options: self.owner,
                               adapter_factory=lambda owner: self.adapter,
                               observer=lambda *_args: self.baseline,
                               selected_observer=fail_selected)
        self.assertEqual(self.owner.calls, ["namespaces", "pki", "cleanup"])
        self.assertTrue(self.owner.cleanup_attempted)
        self.assertEqual([(x["kind"], x["name"]) for x in self.adapter.created],
                         list(runner.partial_gateway.BASE))

    def test_fifth_sixth_guard_before_api_and_always_incomplete(self):
        ids = {"EXPECTED_" + k.upper() + "_IMAGE_ID": v for k, v in INIT_IDS.items()}
        env = {**ids, "RATATOSKR_E2E_FINAL_GATE": "1", "RATATOSKR_E2E_PARTIAL_VPN_SMOKE": "1",
               "RATATOSKR_E2E_INIT_SMOKE": "1", "RATATOSKR_E2E_INIT_TRAFFIC": "1"}
        args = ["--execute", "--allow-partial-vpn-smoke", "--execute-init-smoke", "--execute-init-traffic"]
        seen = []
        def api():
            seen.append("api")
            return InitAPI()
        def nodes(_ids, *, init):
            self.assertTrue(init)
            self.assertEqual(_ids["init"], INIT_ID)
            seen.append("cri")
        for option in args:
            reduced = [v for v in args if v != option]
            # Read-only --execute-init-smoke intentionally contacts the API.
            if option == "--execute-init-traffic":
                continue
            with self.subTest(missing=option), contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(runner.run.main(reduced, env, api, nodes), 2)
        self.assertEqual(seen, [])
        seen.clear()
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertEqual(runner.run.main(args, dict(env, RATATOSKR_E2E_INIT_TRAFFIC="0"), api, nodes), 2)
        self.assertEqual(seen, [])
        # run.py and this module are loaded under distinct fake import names.
        # Patch the exact module referenced by run.main, never real Kubernetes.
        import init_traffic as dispatched
        with patch.object(dispatched, "api_service_ip", return_value="10.43.0.1"), \
             patch.object(runner.lifecycle, "Lifecycle", side_effect=AssertionError("No live lifecycle in fake test")):
            with patch.object(dispatched, "execute",
                              side_effect=lambda _ids, *, api_ip: seen.append(("init", api_ip)) or False):
                with contextlib.redirect_stdout(io.StringIO()) as output:
                    rc = runner.run.main(args, env, api, nodes)
                    self.assertEqual(rc, 4, output.getvalue())
            self.assertIn(("init", "10.43.0.1"), seen)
            self.assertIn("INCOMPLETE", output.getvalue())
            self.assertIn("nonrestricted", output.getvalue())
        self.assertEqual(seen, ["api", "cri", ("init", "10.43.0.1")])


if __name__ == "__main__": unittest.main()
