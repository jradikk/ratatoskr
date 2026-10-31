"""HA fixture authoring tests: fake APIs only; no cluster or PKI execution."""
import base64
import io
import unittest
from contextlib import redirect_stdout
from unittest.mock import patch

import ha_fixture as f
import ha_live as h
from test_ha_live import A, B, CLIENT_NS, GATEWAY, GW_UID, records


class FakeOwner:
    names = (GATEWAY, CLIENT_NS)
    token = "a" * 32
    deadline = 200
    closed = False


class FakeFixtureAPI:
    def __init__(self):
        self.frame = records((A, B), A)
        self.frame[("pod", CLIENT_NS, "synthetic-client")] = self.frame.pop(("pod", CLIENT_NS, "probe"))
        self.frame[("pod", CLIENT_NS, "synthetic-client")]["metadata"]["name"] = "synthetic-client"
        client_annotations = self.frame[("pod", CLIENT_NS, "synthetic-client")]["metadata"]["annotations"]
        import json
        import hashlib
        client_config = json.loads(client_annotations[h.PREFIX + "agent-config"])
        client_config["identity"]["pod"] = "synthetic-client"
        raw = json.dumps(client_config)
        client_annotations[h.PREFIX + "agent-config"] = raw
        client_annotations[h.PREFIX + "agent-hash"] = hashlib.sha256(raw.encode()).hexdigest()
        self.frame[("egressgateway", GATEWAY, "synthetic")]["spec"] = {"replicas": 2, "encryption": "none"}
        self.frame[("deployment", GATEWAY, "synthetic")]["spec"] = {"replicas": 2}
        self.frame[("deployment", GATEWAY, "synthetic")]["status"] = {"readyReplicas": 2}
        for index in range(2):
            pod = self.frame[("pod", GATEWAY, f"synthetic-{index}")]
            pod["status"]["containerStatuses"] = [
                {"name": "gateway", "ready": True, "imageID": "image-gateway"},
                {"name": "upstream", "ready": True, "imageID": "image-plugin"}]
        self.actions = []

    def get(self, kind, name, namespace):
        return self.frame[(kind, namespace, name)]

    def _namespace(self, namespace):
        if namespace != GATEWAY:
            raise ValueError()

    def _call(self, args, *, payload=None, max_output=None):
        self.actions.append((args, payload))
        return b'{"kind":"Status","status":"Success"}'


class HAFixtureTest(unittest.TestCase):
    def test_local_duplicate_cn_only_and_two_replicas(self):
        contents = ("ca", "cert", "key", "clientcert", "clientkey", "witnesscert", "witnesskey")
        objects = f.fixture_manifests("rtk-syn-" + "a" * 16, "a" * 32, contents)
        config = base64.b64decode(objects[0]["data"]["server.conf"]).decode()
        self.assertEqual(config, f.prepare.server_config() + "duplicate-cn\n")
        self.assertEqual(objects[6]["spec"]["replicas"], 2)
        self.assertEqual(f.prepare.server_config().count("duplicate-cn"), 0)
        self.assertEqual(objects[1]["data"].keys(), {"client.ovpn"})

    def test_uid_preconditioned_exact_chosen_replica_delete(self):
        api = FakeFixtureAPI()
        before = h.snapshot(lambda _ctx, kind, ns, name: api.get(kind, name, ns),
                            "fixture", GATEWAY, "synthetic", CLIENT_NS, "synthetic-client")
        f.remove_chosen_gateway_pod(api, FakeOwner(), GW_UID, before)
        self.assertEqual(len(api.actions), 1)
        args, payload = api.actions[0]
        self.assertIn("/pods/synthetic-0", args[1])
        self.assertEqual(__import__("json").loads(payload)["preconditions"]["uid"],
                         api.get("pod", "synthetic-0", GATEWAY)["metadata"]["uid"])
        api.frame[("pod", GATEWAY, "synthetic-0")]["metadata"]["uid"] = "changed"
        with self.assertRaises((f.Blocked, h.Blocked)):
            f.remove_chosen_gateway_pod(api, FakeOwner(), GW_UID, before)
        self.assertEqual(len(api.actions), 1)

    def test_removed_client_reselect_is_not_new_traffic_proof(self):
        api = FakeFixtureAPI()
        before = h.snapshot(lambda _ctx, kind, ns, name: api.get(kind, name, ns),
                            "fixture", GATEWAY, "synthetic", CLIENT_NS, "synthetic-client")
        api.frame[("egressgateway", GATEWAY, "synthetic")]["status"]["endpoints"] = [
            api.frame[("egressgateway", GATEWAY, "synthetic")]["status"]["endpoints"][1]]
        api.frame[("egressgateway", GATEWAY, "synthetic")]["status"]["readyReplicas"] = 1
        import json
        import hashlib
        annotations = api.frame[("pod", CLIENT_NS, "synthetic-client")]["metadata"]["annotations"]
        config = json.loads(annotations[h.PREFIX + "agent-config"])
        config["endpoint"] = B
        raw = json.dumps(config)
        annotations[h.PREFIX + "agent-config"] = raw
        annotations[h.PREFIX + "agent-hash"] = hashlib.sha256(raw.encode()).hexdigest()
        self.assertEqual(f.reselected(api, FakeOwner(), before)["chosen"], B)

    def test_missing_gate_never_constructs_kube_api(self):
        with patch.object(f.run, "ReadOnlyAPI") as api, redirect_stdout(io.StringIO()):
            result = f.main([], environ={})
        self.assertEqual(result, 2)
        api.assert_not_called()


if __name__ == "__main__":
    unittest.main()
