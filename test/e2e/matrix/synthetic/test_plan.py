#!/usr/bin/env python3
"""Dry-run-only synthetic gate planning tests; no Kubernetes/PKI/subprocess."""
import importlib.util
from pathlib import Path
import sys
import unittest

HERE = Path(__file__).resolve().parent
sys.path.insert(0, str(HERE))
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_plan", HERE / "plan.py")
plan = importlib.util.module_from_spec(spec)
sys.modules["synthetic_plan"] = plan
spec.loader.exec_module(plan)
TOKEN = "a" * 32
UID = "b" * 32
DIGEST = "containerd://sha256:" + "d" * 64
IDS = {k: DIGEST for k in plan.run.COMPONENTS}


def owner():
    result = plan.lifecycle.Lifecycle(api=object(), token_factory=lambda: TOKEN)
    result.deadline = result.clock() + 120
    result.created = {name: UID for name in result.names}
    result.owned = dict(result.created)
    return result


def data(stage, gate):
    names = gate.owner.names
    expected = gate.expected
    created = gate._created
    order = gate.order
    if stage == "release-preflight":
        return {"runtimeIDs": {k: expected[k] for k in ("controller", "webhook", "agent")},
                "flannelNodes": 3, "probeConfigured": True}
    if stage == "owned-namespaces":
        return {"namespaceUIDs": dict(gate.owner.owned)}
    if stage == "fixture-created":
        return {"createdUIDs": tuple((kind, ns, name, created[(kind, ns, name)])
                                      for kind, ns, name in order[:8])}
    if stage in ("healthy-gateway", "recovery-gateway"):
        return {"runtimeIDs": {k: expected[k] for k in ("gateway", "plugin", "server")},
                "gatewayOwnerChain": True, "measuredMTU": True, "sourceServiceEndpoint": True,
                "authenticatedSession": True, "sameGatewayUID": True, "sameServerUID": True}
    if stage in ("healthy-selected", "outage-selected-blocked", "recovery-selected"):
        phase = stage.split("-")[0]
        return {"podUID": created[("Pod", names[1], "synthetic-probe-" + phase)],
                "imageID": expected["selected"], "exitCode": 42 if phase == "outage" else 0,
                "waitInitExited": True, "agentReady": True, "directAPIAndDNS": True}
    if stage == "outage-disabled":
        return {"probeDisabledUIDCAS": True, "serverExitObserved503": True}
    if stage == "outage-withdrawn":
        return {"gatewayReadyFalse": True, "noHealthyEndpoint": True,
                "agentUnreachableRoute": True}
    if stage == "outage-witness-running":
        return {"podUID": created[("Pod", names[0], "synthetic-witness")],
                "imageID": expected["witness"], "distinctAuthenticatedCN": True,
                "markerOverOwnVPN": True}
    if stage == "outage-witness-complete":
        return {"podUID": created[("Pod", names[0], "synthetic-witness")],
                "exitCode": 0, "completedBeforeRestore": True}
    if stage == "outage-direct-preserved":
        return {"apiTLSAnonymous403": True, "dnsExact": True, "clusterRouteDirect": True}
    if stage == "outage-restored":
        return {"probeRestoredUIDCAS": True, "serverExitObserved200": True}
    if stage == "cleanup-verified":
        return {"namespacesAbsent": list(names), "privatePKIAbsent": True,
                "noOrphanSecrets": True}
    raise AssertionError(stage)


def record_to(plan_obj, count):
    while len(plan_obj._created) < count:
        kind, namespace, name = plan_obj.order[len(plan_obj._created)]
        plan_obj.record_create({"kind": kind, "namespace": namespace,
                                "name": name, "uid": UID})


def run_to(target, gate):
    for stage in plan.STAGES:
        if stage == target:
            return
        if stage == "fixture-created":
            record_to(gate, 8)
        if stage in ("healthy-selected", "outage-selected-blocked",
                     "outage-witness-running", "recovery-selected"):
            record_to(gate, {"healthy-selected": 9, "outage-selected-blocked": 10,
                             "outage-witness-running": 11, "recovery-selected": 12}[stage])
        if stage == "cleanup-verified":
            gate.owner.closed = True
        gate.checkpoint(stage, data(stage, gate))


class PlanTests(unittest.TestCase):
    def test_exact_nine_images_and_namespaces(self):
        gate = plan.DryRunPlan(owner(), IDS)
        self.assertEqual(len(gate.order), 12)
        self.assertEqual(gate.order[8][2], "synthetic-probe-healthy")
        self.assertEqual(gate.order[9][2], "synthetic-probe-outage")
        self.assertEqual(gate.order[10][2], "synthetic-witness")
        self.assertEqual(gate.order[11][2], "synthetic-probe-recovery")
        for component in IDS:
            missing = dict(IDS)
            del missing[component]
            with self.assertRaises(plan.Incomplete):
                plan.DryRunPlan(owner(), missing)
            mutable = dict(IDS, **{component: "image:latest"})
            with self.assertRaises(plan.Incomplete):
                plan.DryRunPlan(owner(), mutable)

    def test_healthy_outage_witness_recovery_cleanup_order_never_passes(self):
        gate = plan.DryRunPlan(owner(), IDS)
        run_to("cleanup-verified", gate)
        with self.assertRaises(plan.Incomplete):
            gate.final_result()
        self.assertEqual(gate.next_stage, "cleanup-verified")
        with self.assertRaises(plan.Incomplete):
            gate.checkpoint("cleanup-verified", data("cleanup-verified", gate))
        gate.owner.closed = True
        gate.checkpoint("cleanup-verified", data("cleanup-verified", gate))
        self.assertIsNone(gate.next_stage)
        with self.assertRaisesRegex(plan.Incomplete, "cannot award"):
            gate.final_result()

    def test_wrong_checkpoint_missing_or_image_uid_mismatch(self):
        gate = plan.DryRunPlan(owner(), IDS)
        with self.assertRaises(plan.Incomplete):
            gate.checkpoint("outage-withdrawn", {})
        baseline = data("release-preflight", gate)
        baseline["runtimeIDs"]["controller"] = "sha256:" + "e" * 64
        with self.assertRaises(plan.Incomplete):
            gate.checkpoint("release-preflight", baseline)
        gate.checkpoint("release-preflight", data("release-preflight", gate))
        gate.checkpoint("owned-namespaces", data("owned-namespaces", gate))
        with self.assertRaises(plan.Incomplete):
            gate.checkpoint("fixture-created", {})
        record_to(gate, 8)
        gate.checkpoint("fixture-created", data("fixture-created", gate))
        gate.checkpoint("healthy-gateway", data("healthy-gateway", gate))
        record_to(gate, 9)
        altered = data("healthy-selected", gate)
        altered["imageID"] = "sha256:" + "e" * 64
        with self.assertRaises(plan.Incomplete):
            gate.checkpoint("healthy-selected", altered)
        altered = data("healthy-selected", gate)
        altered["podUID"] = "f" * 32
        with self.assertRaises(plan.Incomplete):
            gate.checkpoint("healthy-selected", altered)

    def test_create_order_duplicates_ambiguous_response_and_namespace_change(self):
        gate = plan.DryRunPlan(owner(), IDS)
        with self.assertRaises(plan.Incomplete):
            record_to(gate, 1)
        gate.checkpoint("release-preflight", data("release-preflight", gate))
        gate.checkpoint("owned-namespaces", data("owned-namespaces", gate))
        kind, ns, name = gate.order[1]
        with self.assertRaises(plan.Incomplete):
            gate.record_create({"kind": kind, "namespace": ns, "name": name, "uid": UID})
        kind, ns, name = gate.order[0]
        with self.assertRaises(plan.Incomplete):
            gate.record_create({"kind": kind, "namespace": ns, "name": name, "uid": ""})
        record_to(gate, 1)
        with self.assertRaises(plan.Incomplete):
            gate.record_create({"kind": kind, "namespace": ns, "name": name, "uid": UID})
        gate.owner.owned[gate.owner.names[0]] = "f" * 32
        with self.assertRaises(plan.Incomplete):
            record_to(gate, 2)

    def test_timeout_and_cleanup_fail_closed(self):
        gate = plan.DryRunPlan(owner(), IDS)
        gate.owner.deadline = gate.owner.clock() - 1
        with self.assertRaises(plan.Incomplete):
            gate.checkpoint("release-preflight", data("release-preflight", gate))
        gate = plan.DryRunPlan(owner(), IDS)
        run_to("cleanup-verified", gate)
        gate.owner.closed = True
        with self.assertRaises(plan.Incomplete):
            gate.checkpoint("cleanup-verified", {"namespacesAbsent": [gate.owner.names[0]],
                                                 "privatePKIAbsent": True, "noOrphanSecrets": True})
        with self.assertRaises(plan.Incomplete):
            gate.final_result()


if __name__ == "__main__":
    unittest.main()
