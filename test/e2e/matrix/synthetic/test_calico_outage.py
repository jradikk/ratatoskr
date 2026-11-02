"""Offline existing-Calico witnessed outage gates and inherited preflight."""
import contextlib
import io
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
import calico_outage as outage
import environment
import test_calico_healthy as healthy

INPUT = {**healthy.INPUT, "RATATOSKR_E2E_CALICO_OUTAGE": "1"}


class CalicoOutageTests(unittest.TestCase):
    def test_default_and_missing_gates_no_cluster_or_fixture(self):
        for args, env in (([], {}), (["--execute-calico-outage"], {}),
                          ([], INPUT),
                          (["--execute-calico-outage"], {"RATATOSKR_E2E_CALICO_OUTAGE": "1"}),
                          (["--execute-calico-outage"], {"RATATOSKR_E2E_FINAL_GATE": "1"})):
            with self.subTest(args=args), patch.object(outage, "execute",
                                                side_effect=AssertionError("no IO")):
                output = io.StringIO()
                with contextlib.redirect_stdout(output):
                    self.assertEqual(outage.main(args, environ=env), 2)
                self.assertIn("SKIPPED", output.getvalue())
        self.assertEqual(outage.main([], environ=INPUT), 2)

    def test_exact_shared_preflight_before_outage_environment_and_scope(self):
        api = healthy.CalicoAPI()
        sequence = []
        def verify(images, *, environment, observed_nodes):
            sequence.append("images")
            self.assertEqual(environment, outage.environment.CALICO)
            self.assertEqual(observed_nodes, environment.nodes)
            self.assertEqual(images, {k: healthy.IDS[k] for k in outage.calico_healthy.node_images.TAGS})
            return True
        def smoke(ids, *, api_ip, environment):
            sequence.append("outage")
            self.assertEqual(ids, healthy.IDS)
            self.assertEqual(api_ip, "10.43.0.1")
            self.assertEqual(environment, outage.environment.CALICO)
            return False
        self.assertEqual(outage.execute(INPUT, api_factory=lambda *, environment: api,
                                        verifier=verify, smoke=smoke),
                         {"environment": "calico/none", "subset": "agent/iproute/witnessed-outage-recovery",
                          "result": "INCOMPLETE", "fullMatrix": False})
        self.assertEqual(sequence, ["images", "outage"])
        self.assertTrue(all(ctx == environment.CALICO.context for ctx, *_ in api.calls))
        self.assertIn("configmap", [row[1] for row in api.calls])
        self.assertIn("service", [row[1] for row in api.calls])

    def test_wrong_context_node_cni_mesh_release_image_or_ids_block_before_fixture(self):
        for change in ("context", "nodes", "variant", "mesh", "release", "images", "ids"):
            api = healthy.CalicoAPI()
            values = dict(INPUT)
            if change == "context": api = healthy.CalicoAPI(environment=environment.FLANNEL)
            if change == "nodes":
                api.fake.objects[("nodes", None, None, None)] = {"items": [
                    healthy.test_run.node(i == 0, name) for i, name in enumerate(environment.FLANNEL.nodes)]}
            if change == "variant":
                api.fake.objects[("configmap", "ratatoskr-testenv", "kube-system", None)]["data"]["variant"] = "flannel"
            if change == "mesh":
                api.fake.objects[("configmap", "ratatoskr-testenv", "kube-system", None)]["data"]["mesh"] = "ambient"
            if change == "release":
                api.fake.objects[("deployment", "ratatoskr-controller", "operator", None)]["spec"]["template"]["spec"]["containers"][0]["env"][0]["value"] = "init"
            if change == "ids": values["EXPECTED_AGENT_IMAGE_ID"] = "agent:latest"
            def verify(*_args, **_kwargs):
                if change == "images": raise outage.calico_healthy.node_images.Blocked("wrong CRI ID")
                return True
            with self.subTest(change=change), self.assertRaisesRegex(outage.Blocked, "preflight"):
                outage.execute(values, api_factory=lambda *, environment: api,
                               verifier=verify, smoke=lambda *_a, **_kw: self.fail("no outage write"))
            if change in ("ids", "context"):
                self.assertEqual(api.calls, [])
            if change in ("nodes", "variant", "mesh"):
                self.assertTrue(all(row[1] in ("nodes", "configmap") for row in api.calls))

    def test_incomplete_cleanup_or_false_evidence_never_exit_four(self):
        for result in (True, None, "PASSED"):
            with self.subTest(result=result), self.assertRaisesRegex(outage.Blocked, "fixture-or-cleanup"):
                outage.execute(INPUT, api_factory=lambda *, environment: healthy.CalicoAPI(),
                               verifier=lambda *_a, **_kw: True,
                               smoke=lambda *_a, **_kw: result)
        with self.assertRaisesRegex(outage.Blocked, "fixture-or-cleanup") as raised:
            outage.execute(INPUT, api_factory=lambda *, environment: healthy.CalicoAPI(),
                           verifier=lambda *_a, **_kw: True,
                           smoke=lambda *_a, **_kw: (_ for _ in ()).throw(RuntimeError("PRIVATE")))
        self.assertNotIn("PRIVATE", str(raised.exception))
        with patch.object(outage, "execute", return_value={"result": "INCOMPLETE"}):
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                self.assertEqual(outage.main(["--execute-calico-outage"], environ=INPUT), 4)
            self.assertIn("INCOMPLETE", output.getvalue())
            self.assertNotIn("PASS", output.getvalue())


if __name__ == "__main__":
    unittest.main()
