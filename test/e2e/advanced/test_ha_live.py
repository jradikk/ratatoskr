"""Offline fake Kubernetes GET adapter for the gated read-only collector."""
import copy
import hashlib
import json
import io
import unittest
from contextlib import redirect_stderr
from unittest.mock import patch

import ha_live as h

GATEWAY = "ratatoskr-system"
NAME = "synthetic"
CLIENT_NS = "synthetic-app"
CLIENT = "probe"
GW_UID = "abcd1234-abcd-1234-abcd-abcd1234abcd"
DEP_UID = "deadbeef-abcd-1234-abcd-abcd1234abcd"
RS_UID = "abcdabcd-abcd-1234-abcd-abcd1234abcd"
CLIENT_UID = "dead1234-abcd-1234-abcd-abcd1234abcd"
A, B, C = "10.42.2.4", "10.42.2.5", "10.42.2.6"


def resource(kind, namespace, name, uid, owner=None):
    metadata = {"namespace": namespace, "name": name, "uid": uid}
    if owner:
        metadata["ownerReferences"] = [{"kind": owner[0], "uid": owner[1], "controller": True}]
    return {"kind": kind, "metadata": metadata}


def records(active=(A, B, C), choice=A):
    gw = resource("EgressGateway", GATEWAY, NAME, GW_UID)
    gw["metadata"]["generation"] = 7
    gw["status"] = {"observedGeneration": 7, "gatewayID": 13,
                    "conditions": [{"type": "Ready", "status": "True", "observedGeneration": 7}],
                    "readyReplicas": len(active), "endpoints": [
                        {"podName": f"synthetic-{index}", "podUID": f"abcd1234-abcd-1234-abcd-abcd1234abc{index}",
                         "podIP": ip, "upstreamHealthy": True,
                         "appliedClientConfigHash": "a" * 64}
                        for index, ip in enumerate((A, B, C)) if ip in active]}
    dep = resource("Deployment", GATEWAY, NAME, DEP_UID, ("EgressGateway", GW_UID))
    rs = resource("ReplicaSet", GATEWAY, "synthetic-rs", RS_UID, ("Deployment", DEP_UID))
    client = resource("Pod", CLIENT_NS, CLIENT, CLIENT_UID)
    config = json.dumps({"identity": {"uid": CLIENT_UID, "namespace": CLIENT_NS, "pod": CLIENT},
                         "podIP": "10.42.1.8", "endpoint": choice, "encryption": "none"})
    client["metadata"].update(labels={h.PREFIX + "gateway": NAME,
                                      h.PREFIX + "gateway-namespace": GATEWAY},
                              annotations={h.PREFIX + "datapath-ready": "true",
                                           h.PREFIX + "agent-backend": "iproute",
                                           h.PREFIX + "agent-hash": hashlib.sha256(config.encode()).hexdigest(),
                                           h.PREFIX + "agent-config": config})
    client["spec"] = {"hostNetwork": False}
    client["status"] = {"podIP": "10.42.1.8"}
    out = {("egressgateway", GATEWAY, NAME): gw,
           ("deployment", GATEWAY, NAME): dep,
           ("replicaset", GATEWAY, "synthetic-rs"): rs,
           ("pod", CLIENT_NS, CLIENT): client}
    for index, ip in enumerate((A, B, C)):
        pod = resource("Pod", GATEWAY, f"synthetic-{index}",
                       f"abcd1234-abcd-1234-abcd-abcd1234abc{index}",
                       ("ReplicaSet", RS_UID))
        pod["metadata"]["ownerReferences"][0]["name"] = "synthetic-rs"
        pod["status"] = {"podIP": ip}
        out[("pod", GATEWAY, pod["metadata"]["name"])] = pod
    return out


class FakeAPI:
    def __init__(self, frames):
        self.frames = frames
        self.index = 0
        self.calls = []

    def __call__(self, context, kind, namespace, name):
        self.calls.append((context, kind, namespace, name))
        if kind == "egressgateway":
            self.index = min(self.index + 1, len(self.frames))
        return copy.deepcopy(self.frames[self.index - 1][(kind, namespace, name)])


class HACollectorTest(unittest.TestCase):
    args = ("fixture", GATEWAY, NAME, CLIENT_NS, CLIENT)

    def test_read_only_removed_chosen_replica_reselects(self):
        api = FakeAPI([records(), records((B, C), B), records((B, C), B)])
        now = [0]
        def clock():
            return now[0]
        def sleep(seconds):
            now[0] += seconds
        result = h.observe(api, self.args, clock=clock, sleep=sleep)
        self.assertEqual(result["traffic"], "not-tested")
        self.assertEqual(result["establishedFlowContinuity"], "not-asserted")
        self.assertTrue(all(kind in {"egressgateway", "deployment", "pod", "replicaset"}
                            for _, kind, _, _ in api.calls))

    def test_false_failovers_block(self):
        bad = [
            [records(), records((A, B), A)],  # non-affected Pod remains pinned
            [records(), records((B, C), A)],  # agent has not reprogrammed
            [records(), records((B, C), B), records((A, B, C), A)],  # status reverted
        ]
        for frames in bad:
            with self.subTest(frames=len(frames)):
                api = FakeAPI(frames)
                now = [0]
                with self.assertRaises(h.Blocked):
                    h.observe(api, self.args, clock=lambda: now[0],
                              sleep=lambda seconds: now.__setitem__(0, now[0] + seconds))

    def test_rejects_unowned_replica_and_stale_ack(self):
        for mutate in (lambda d: d[("replicaset", GATEWAY, "synthetic-rs")]["metadata"].update(ownerReferences=[]),
                       lambda d: d[("egressgateway", GATEWAY, NAME)]["status"]["endpoints"][0].update(appliedClientConfigHash="")):
            with self.subTest(mutate=mutate):
                frame = records()
                mutate(frame)
                with self.assertRaises(h.Blocked):
                    h.snapshot(FakeAPI([frame]), *self.args)

    def test_default_invocation_rejects_before_cluster_io(self):
        with patch.dict("ha_live.os.environ", {}, clear=True), patch("ha_live.fetch") as fetch:
            with redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
                h.main(["--context", "fixture", "--gateway-namespace", GATEWAY,
                        "--gateway-name", NAME, "--pod-namespace", CLIENT_NS,
                        "--pod-name", CLIENT])
            fetch.assert_not_called()


if __name__ == "__main__":
    unittest.main()
