"""Offline fake-only adversarial checks for the executable WG fixture."""
import contextlib
import io
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import wg_fixture as w

TOKEN = "a" * 32
UID = "b" * 32
IDS = {key: "containerd://sha256:" + "c" * 64 for key in w.run.COMPONENTS}


class FakeOwner(w.lifecycle.Lifecycle):
    def __init__(self):
        super().__init__(api=object(), token_factory=lambda: TOKEN)
        self.deadline = 10_000_000
        self.private_dir = Path("/absent")
        self.owned[self.names[0]] = UID
        self.created_namespaces = False
        self.cleaned = False
    def __enter__(self):
        return self
    def __exit__(self, *_args):
        self.cleaned = True
        return False
    def create_namespaces(self):
        self.created_namespaces = True
    def generate_pki(self):
        return self.private_dir


class FakeOperator:
    def __init__(self, owner):
        self.owner = owner
        self.name = "rtk-wg-" + owner.token[:16]
        self.created = []
        self.attempted = set()
        self.cleaned = False
    def create(self, kind, manifest):
        self.created.append((kind, manifest["metadata"]["namespace"]))
        return UID
    def cleanup(self):
        self.cleaned = True


class FakeSource:
    def __init__(self, owner):
        self.owner = owner
        self.created = []
    def create(self, obj):
        self.created.append((obj["kind"], obj["metadata"]["name"]))
        return {"kind": obj["kind"], "name": obj["metadata"]["name"],
                "namespace": obj["metadata"]["namespace"], "uid": UID}


class WireGuardFixtureTest(unittest.TestCase):
    def test_live_observer_peer_startup_and_revoke_offline(self):
        owner = FakeOwner()
        owner.clock = lambda: 0
        operator = FakeOperator(owner)
        gateway_uid = UID
        gateway_ip = "10.42.0.7"
        endpoint = {"podName": "gateway-child", "podUID": UID, "podIP": gateway_ip,
                    "upstreamHealthy": True, "appliedClientConfigHash": "d" * 64,
                    "wireguardPublicKey": "e" * 43 + "=", "registrationCACert": "-----BEGIN CERTIFICATE-----x"}
        gateway = {"metadata": {"name": operator.name, "namespace": w.SYSTEM,
                                "uid": gateway_uid, "generation": 1},
                   "spec": {"encryption": "wireguard"},
                   "status": {"observedGeneration": 1, "gatewayID": 42, "readyReplicas": 1,
                              "conditions": [{"type": "Ready", "status": "True"}],
                              "endpoints": [endpoint]}}
        dependency = {"metadata": {"uid": "d" * 32,
                         "ownerReferences": [{"kind": "EgressGateway", "uid": UID, "controller": True}]}}
        gateway_pod = {"metadata": {"uid": UID, "name": "gateway-child",
                       "labels": {w.PREFIX + "gateway-uid": UID},
                       "ownerReferences": [{"kind": "ReplicaSet", "uid": "f" * 32,
                                            "name": "gateway-rs", "controller": True}]},
                       "status": {"podIP": gateway_ip}}
        replica = {"metadata": {"uid": "f" * 32,
                  "ownerReferences": [{"kind": "Deployment", "uid": "d" * 32,
                                       "controller": True}]}}
        body = {"identity": {"namespace": owner.names[1], "pod": w.CLIENT, "uid": UID},
                "encryption": "wireguard", "endpoint": gateway_ip, "gatewayID": 42,
                "gatewayPublicKey": endpoint["wireguardPublicKey"],
                "registrationCACert": endpoint["registrationCACert"], "podIP": "10.42.1.8"}
        raw = json.dumps(body)
        selected = {"metadata": {"namespace": owner.names[1], "name": w.CLIENT,
                     "uid": UID, "labels": {w.OWN: TOKEN},
                     "annotations": {w.PREFIX + "agent-config": raw,
                         w.PREFIX + "agent-hash": w.hashlib.sha256(raw.encode()).hexdigest(),
                         w.PREFIX + "datapath-ready": "true",
                         w.PREFIX + "agent-backend": "iproute"}},
                    "status": {"phase": "Running", "podIP": "10.42.1.8",
                               "containerStatuses": [{"name": "client", "ready": True,
                                                       "imageID": IDS["selected"]}]}}
        source_uid = UID
        class Source:
            created = {("Pod", owner.names[0], w.SERVER): source_uid}
            def __init__(self): self.deleted = False
            def get(self, kind, name, namespace):
                if (kind, name) == ("pod", w.SERVER):
                    return {"metadata": {"uid": UID}, "status": {}}
                if (kind, name) == ("service", w.SERVER):
                    return {"metadata": {"uid": UID}}
                if (kind, name) == ("pod", w.CLIENT):
                    return selected
                raise AssertionError("unexpected source GET")
            def source_endpoint(self, *_args): return {"kind": "EndpointSlice"}
            def probe_running(self, *_args): return True
        source = Source()
        class Gateway(FakeOperator):
            def get_object(self, kind, name, namespace):
                return {"egressgateway": gateway, "deployment": dependency,
                        "pod": gateway_pod, "replicaset": replica}[kind]
            def create_selected(self, _source, _workload): return UID
            def delete_selected(self, _source): source.deleted = True
        gw = Gateway(owner)
        samples = iter([{"sample_ok": 1, "installed_peers": 0, "receive_bytes": 0,
                         "transmit_bytes": 0},
                        {"sample_ok": 1, "installed_peers": 1, "handshaken_peers": 1,
                         "receive_bytes": 12, "transmit_bytes": 16},
                        {"sample_ok": 1, "installed_peers": 0}])
        workload = w.selected_pod(owner, gw.name, "10.43.0.1")
        with patch.dict(w.os.environ, {"RATATOSKR_E2E_TOKENREVIEW": "1"}), \
                patch.object(w.tokenreview, "execute", return_value={"gatewayTokenReviewObserved": False}) as review, \
                patch.object(w.partial_gateway, "source_ready", return_value=True):
            result = w.observe(owner, source, gw, UID, workload, IDS,
                               metrics_reader=lambda *_args: next(samples),
                               clock=lambda: 0, sleep=lambda _seconds: self.fail("no retry needed"))
        review.assert_called_once()
        self.assertEqual(review.call_args.args, (owner.names[1], UID, "default", owner.token, gw.name))
        self.assertEqual(review.call_args.kwargs["remaining"](), owner.deadline - 40)
        self.assertTrue(result["encryptedStartup"] and result["peerRemoved"] and source.deleted)
        self.assertEqual(result["tokenReview"], "not-independently-observed")
        self.assertEqual(result["plainGeneve"], "not-tested")

    def test_observer_typed_stage_not_replaced_by_peer_lifecycle(self):
        owner = FakeOwner()
        operator = FakeOperator(owner)
        with patch.object(w, "manifests", return_value=([{"kind": k, "metadata": {
                "name": n, "namespace": owner.names[0]}} for k, n in
                (("Secret", "synthetic-server"), ("ConfigMap", "synthetic-exit-health"),
                 ("Pod", "synthetic-vpn"), ("Service", "synthetic-vpn"))],
                {"metadata": {"namespace": w.SYSTEM}}, {"metadata": {"namespace": w.SYSTEM}})):
            def fail(*_args):
                raise w.StageBlocked("peer-registration")
            with self.assertRaises(w.StageBlocked) as raised:
                w.execute(IDS, api_ip="10.43.0.1", owner_factory=lambda **kwargs: owner,
                          operator_factory=lambda _owner: operator, source_factory=FakeSource,
                          observer=fail)
        self.assertEqual(raised.exception.checkpoint, "peer-registration")
        self.assertTrue(owner.cleaned and operator.cleaned)

    def test_cleanup_phase_keeps_original_trusted_body_checkpoint(self):
        owner = FakeOwner()
        operator = FakeOperator(owner)
        def fail_cleanup():
            operator.cleaned = True
            raise w.CleanupBlocked("gateway-ambiguous")
        operator.cleanup = fail_cleanup
        with patch.object(w, "manifests", return_value=([{"kind": k, "metadata": {
                "name": n, "namespace": owner.names[0]}} for k, n in
                (("Secret", "synthetic-server"), ("ConfigMap", "synthetic-exit-health"),
                 ("Pod", "synthetic-vpn"), ("Service", "synthetic-vpn"))],
                {"metadata": {"namespace": w.SYSTEM}}, {"metadata": {"namespace": w.SYSTEM}})):
            def fail(*_args):
                raise RuntimeError("PRIVATE PROFILE DATA")
            with self.assertRaises(w.StageBlocked) as raised:
                w.execute(IDS, api_ip="10.43.0.1", owner_factory=lambda **kwargs: owner,
                          operator_factory=lambda _owner: operator, source_factory=FakeSource,
                          observer=fail)
        self.assertEqual(str(raised.exception),
                         "WireGuard synthetic fixture blocked at peer-lifecycle. "
                         "UID-owned cleanup unverified at gateway-ambiguous.")
        self.assertNotIn("PRIVATE PROFILE DATA", str(raised.exception))
        self.assertTrue(owner.cleaned and operator.cleaned)

    def test_cleanup_phase_without_body_failure_is_fixed_label(self):
        owner = FakeOwner()
        operator = FakeOperator(owner)
        def fail_cleanup():
            raise w.CleanupBlocked("secret-delete")
        operator.cleanup = fail_cleanup
        with patch.object(w, "manifests", return_value=([{"kind": k, "metadata": {
                "name": n, "namespace": owner.names[0]}} for k, n in
                (("Secret", "synthetic-server"), ("ConfigMap", "synthetic-exit-health"),
                 ("Pod", "synthetic-vpn"), ("Service", "synthetic-vpn"))],
                {"metadata": {"namespace": w.SYSTEM}}, {"metadata": {"namespace": w.SYSTEM}})):
            with self.assertRaises(w.StageBlocked) as raised:
                w.execute(IDS, api_ip="10.43.0.1", owner_factory=lambda **kwargs: owner,
                          operator_factory=lambda _owner: operator, source_factory=FakeSource,
                          observer=lambda *_args: {"encryptedStartup": True, "peerRegistered": True,
                              "peerRemoved": True, "plainGeneve": "not-tested",
                              "tokenReview": "not-independently-observed"})
        self.assertEqual(str(raised.exception),
                         "WireGuard synthetic fixture blocked at cleanup-unverified. "
                         "UID-owned cleanup unverified at secret-delete.")
        self.assertTrue(owner.cleaned)

    def test_stage_diagnostic_survives_verified_cleanup_and_hides_sensitive_exception(self):
        owner = FakeOwner()
        operator = FakeOperator(owner)
        def factory(actual):
            operator.owner = actual
            return operator
        with patch.object(w, "manifests", return_value=([{"kind": k, "metadata": {
                "name": n, "namespace": owner.names[0]}} for k, n in
                (("Secret", "synthetic-server"), ("ConfigMap", "synthetic-exit-health"),
                 ("Pod", "synthetic-vpn"), ("Service", "synthetic-vpn"))],
                {"metadata": {"namespace": w.SYSTEM}}, {"metadata": {"namespace": w.SYSTEM}})):
            def fail(*_args):
                raise RuntimeError("private-key-material must never reach stdout")
            with self.assertRaises(w.StageBlocked) as raised:
                w.execute(IDS, api_ip="10.43.0.1", owner_factory=lambda **kwargs: owner,
                          operator_factory=factory, source_factory=FakeSource,
                          observer=fail)
        self.assertEqual(str(raised.exception), "WireGuard synthetic fixture blocked at peer-lifecycle.")
        self.assertNotIn("private-key-material", str(raised.exception))
        self.assertTrue(owner.cleaned and operator.cleaned)
        with self.assertRaises(w.Blocked):
            w.StageBlocked("private-key-material")

    def test_source_create_stage_classification_and_cleanup_override(self):
        owner = FakeOwner()
        class FailingSource(FakeSource):
            def create(self, obj):
                raise RuntimeError("SENSITIVE-API-RESPONSE")
        op = FakeOperator(owner)
        with patch.object(w, "manifests", return_value=([{"kind": "Secret", "metadata": {
                "name": "synthetic-server", "namespace": owner.names[0]}}], {}, {})):
            with self.assertRaises(w.StageBlocked) as raised:
                w.execute(IDS, api_ip="10.43.0.1", owner_factory=lambda **kwargs: owner,
                          operator_factory=lambda actual: op, source_factory=FailingSource)
        self.assertEqual(str(raised.exception), "WireGuard synthetic fixture blocked at source-create.")
        self.assertTrue(owner.cleaned and op.cleaned)

    def test_selected_fixture_short_grace_preserves_restricted_security(self):
        owner = FakeOwner()
        selected = w.selected_pod(owner, "rtk-wg-" + TOKEN[:16], "10.43.0.1")
        self.assertEqual(selected["spec"]["terminationGracePeriodSeconds"], 5)
        self.assertFalse(selected["spec"]["automountServiceAccountToken"])
        app = selected["spec"]["containers"][0]
        self.assertTrue(app["securityContext"]["runAsNonRoot"])
        self.assertEqual(app["securityContext"]["capabilities"], {"drop": ["ALL"]})
        self.assertNotIn("hostNetwork", selected["spec"])
        self.assertEqual(app["command"], ["python3", "/usr/local/bin/check.py", "hold"])

    def test_phase_deadlines_are_bounded_and_reserve_cleanup(self):
        owner = FakeOwner()
        owner.clock = lambda: 100
        owner.deadline = 240
        owner.deadline = 490  # 390s total from clock=100.
        self.assertEqual(w._phase_deadline(owner, lambda: 100, 85, 255, "source-ready"), 185)
        self.assertEqual(w._phase_deadline(owner, lambda: 180, 150, 105, "peer-registration"), 330)
        self.assertEqual(w._phase_deadline(owner, lambda: 335, 35, 35, "peer-revocation"), 370)
        with self.assertRaises(w.StageBlocked) as caught:
            w._phase_deadline(owner, lambda: 386, 150, 105, "peer-registration")
        self.assertEqual(caught.exception.checkpoint, "peer-registration")

    def test_default_entrypoint_never_calls_cluster(self):
        with patch.dict(w.os.environ, {}, clear=True), patch.object(w.run, "ReadOnlyAPI") as api:
            with contextlib.redirect_stdout(io.StringIO()):
                self.assertEqual(w.main([]), 2)
            api.assert_not_called()

    def test_operator_resource_uid_preconditions_and_no_name_only_cleanup(self):
        owner = FakeOwner()
        calls = []
        identities = {}
        def transport(argv, *, payload, timeout, max_output, discard_output=False):
            self.assertEqual(argv[1:3], ["--context", w.lifecycle.CONTEXT])
            calls.append((argv, payload, discard_output))
            if "--ignore-not-found" in argv:
                kind = argv[argv.index("get") + 1]
                name = argv[argv.index(kind) + 1]
                uid = identities.get(kind)
                return (name + "\t" + uid + "\t" + TOKEN + "\t").encode() if uid else b""
            if "create" in argv:
                obj = json.loads(payload)
                kind = obj["kind"].lower()
                identities[kind] = UID
                return (obj["apiVersion"] + "\t" + obj["kind"] + "\t" + w.SYSTEM +
                        "\t" + obj["metadata"]["name"] + "\t" + UID + "\n").encode()
            if "delete" in argv:
                self.assertTrue(discard_output)
                self.assertEqual(max_output, 0)
                options = json.loads(payload)
                self.assertEqual(options["preconditions"]["uid"], UID)
                self.assertIn("--raw=", " ".join(argv))
                identities.pop("secret" if "/secrets/" in " ".join(argv) else "egressgateway")
                return b""
            self.fail("unexpected Kubernetes action")
        op = w.OperatorFixture(owner, transport=transport)
        name = op.name
        for kind, suffix, api in (("Secret", "-upstream", "v1"),
                                  ("EgressGateway", "", "ratatoskr.skaldhall.io/v1alpha1")):
            op.create(kind, {"apiVersion": api, "kind": kind, "metadata": {
                "name": name + suffix, "namespace": w.SYSTEM, "labels": {w.OWN: TOKEN}}})
        op.cleanup()
        self.assertFalse(identities)
        self.assertEqual(sum("delete" in argv for argv, _, _ in calls), 2)
        self.assertTrue(all(w.SYSTEM in str(argv) for argv, _, _ in calls
                            if "get" in argv or "delete" in argv))

    def test_selected_pod_double_delete_after_real_create_is_idempotent(self):
        owner = FakeOwner()
        calls = []
        current = {}
        owner.owned[owner.names[1]] = UID
        op = w.OperatorFixture(owner, transport=lambda argv, **kwargs:
                               transport(argv, **kwargs))
        def transport(argv, *, payload, timeout, max_output, discard_output=False):
            calls.append(tuple(argv))
            if "--ignore-not-found" in argv:
                if "pod" in argv:
                    return (w.CLIENT + "\t" + UID + "\t" + TOKEN).encode() if current.get("pod") else b""
                return b""
            if "create" in argv:
                obj = json.loads(payload)
                self.assertEqual(obj["metadata"]["name"], w.CLIENT)
                current["pod"] = True
                return ("v1\tPod\t" + owner.names[1] + "\t" + w.CLIENT + "\t" + UID).encode()
            if "delete" in argv:
                self.assertTrue(discard_output)
                self.assertEqual(max_output, 0)
                self.assertEqual(json.loads(payload)["preconditions"]["uid"], UID)
                current.pop("pod")
                return b""
            self.fail("unexpected transport call")
        class Namespace:
            def _namespace(self, name):
                return name
        source = Namespace()
        payload = w.selected_pod(owner, op.name, "10.43.0.1")
        self.assertEqual(op.create_selected(source, payload), UID)
        op.delete_selected(source)
        self.assertEqual(op.deleted_selected_uid, UID)
        op.delete_selected(source)  # execute.finally after successful observe.
        self.assertEqual(sum("delete" in argv for argv in calls), 1)
        self.assertNotIn("pod", current)

    def test_selected_pod_absent_after_confirmed_create_and_replacement_safety(self):
        owner = FakeOwner()
        owner.owned[owner.names[1]] = UID
        op = w.OperatorFixture(owner, transport=lambda *_args, **_kwargs: b"")
        op.attempted.add("Pod")
        op.created["Pod"] = UID
        class Namespace:
            def _namespace(self, name): return name
        op.delete_selected(Namespace())  # Independently removed same owned UID.
        self.assertEqual(op.deleted_selected_uid, UID)
        op.get_selected_uid = lambda: "c" * 32
        with self.assertRaises(w.Blocked):
            op.delete_selected(Namespace())  # Replacement must never be adopted/deleted.
        op.created.pop("Pod")
        with self.assertRaises(w.Blocked):
            op.delete_selected(Namespace())  # Ambiguous POST never legitimizes absence.

    def test_ambiguous_create_not_deleted_or_retried(self):
        owner = FakeOwner()
        calls = []
        def failed(argv, *, payload, timeout, max_output):
            calls.append(argv)
            if "get" in argv:
                return b""
            raise w.adapter.AdapterError("ambiguous remote POST")
        op = w.OperatorFixture(owner, transport=failed)
        manifest = {"apiVersion": "v1", "kind": "Secret", "metadata": {
            "name": op.name + "-upstream", "namespace": w.SYSTEM, "labels": {w.OWN: TOKEN}}}
        with self.assertRaises(w.Blocked):
            op.create("Secret", manifest)
        with self.assertRaises(w.Blocked):
            op.cleanup()
        self.assertFalse(any("delete" in argv for argv in calls))

    def test_manifest_reuses_private_pki_and_disposable_namespaces(self):
        owner = FakeOwner()
        with patch.object(w.partial_gateway, "private_contents", return_value=("CA", "SERVER", "SERVER_KEY", "CLIENT", "CLIENT_KEY", "WITNESS", "WITNESS_KEY")):
            source, secret, gateway = w.manifests(owner, owner.private_dir)
        self.assertEqual([(o["kind"], o["metadata"]["name"]) for o in source],
                         [("Secret", "synthetic-server"), ("ConfigMap", "synthetic-exit-health"),
                          ("Pod", "synthetic-vpn"), ("Service", "synthetic-vpn")])
        self.assertEqual(gateway["metadata"]["namespace"], w.SYSTEM)
        self.assertEqual(gateway["spec"]["encryption"], "wireguard")
        self.assertEqual(secret["metadata"]["namespace"], w.SYSTEM)
        self.assertEqual(gateway["spec"]["allowedNamespaces"]["namespaceSelector"]["matchLabels"],
                         {"ratatoskr-synthetic": owner.names[0]})

    def test_execute_bounded_partial_only_and_cleanup_failure_overrides(self):
        owner, operator = FakeOwner(), FakeOperator(FakeOwner())
        def factory(_owner):
            operator.owner = _owner
            return operator
        with patch.object(w, "manifests", return_value=([{"kind": k, "metadata": {
                "name": n, "namespace": owner.names[0]}} for k, n in
                (("Secret", "synthetic-server"), ("ConfigMap", "synthetic-exit-health"),
                 ("Pod", "synthetic-vpn"), ("Service", "synthetic-vpn"))],
                {"metadata": {"namespace": w.SYSTEM}}, {"metadata": {"namespace": w.SYSTEM}})):
            result = w.execute(IDS, api_ip="10.43.0.1", owner_factory=lambda **kwargs: owner,
                               operator_factory=factory, source_factory=FakeSource,
                               observer=lambda *_args: {"encryptedStartup": True,
                                   "peerRegistered": True, "peerRemoved": True,
                                   "plainGeneve": "not-tested", "tokenReview": "not-independently-observed"})
        self.assertIs(result, False)
        self.assertTrue(operator.cleaned and owner.cleaned)
        self.assertEqual(operator.created, [("Secret", w.SYSTEM), ("EgressGateway", w.SYSTEM)])


if __name__ == "__main__":
    unittest.main()
