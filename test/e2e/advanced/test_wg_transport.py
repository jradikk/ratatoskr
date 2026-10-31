"""Cluster-free fixed node command and metric parsing adversarial tests."""
import json
import sys
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import wg_fixture as fixture
import wg_transport as wt

UID = "a" * 32
IDENTITY = "b" * 64
IMAGE = "containerd://sha256:" + "c" * 64
NODE = wt.NODES[0]


def pod():
    return {"metadata": {"name": "rtk-wg-abcd-gateway", "uid": UID},
            "spec": {"nodeName": NODE},
            "status": {"containerStatuses": [{"name": "gateway", "ready": True,
                "imageID": IMAGE, "containerID": "containerd://" + IDENTITY}]}}


class Operator:
    def get_object(self, kind, name, namespace):
        assert kind == "pod" and namespace == fixture.SYSTEM
        return pod()


class MetricsTest(unittest.TestCase):
    def test_exact_cri_nsenter_shape_and_output_bounds(self):
        calls = []
        def transport(argv, *, timeout, max_output):
            calls.append((argv, timeout, max_output))
            if "inspect" in argv:
                return json.dumps({"status": {"id": IDENTITY, "state": "CONTAINER_RUNNING",
                    "metadata": {"name": "gateway"}, "labels": {"io.kubernetes.pod.uid": UID}},
                    "info": {"pid": 2345}}).encode()
            return (b"# HELP ratatoskr_gateway_wireguard_installed_peers measured\n"
                    b"ratatoskr_gateway_wireguard_sample_ok 1\n"
                    b"ratatoskr_gateway_wireguard_installed_peers 1\n"
                    b"ratatoskr_gateway_wireguard_handshaken_peers 1\n"
                    b"ratatoskr_gateway_wireguard_receive_bytes 17\n"
                    b"ratatoskr_gateway_wireguard_transmit_bytes 19\n")
        result = wt.read_metrics(Operator(), pod(), IMAGE, transport=transport)
        self.assertEqual(result["installed_peers"], 1)
        self.assertEqual(len(calls), 3)
        self.assertEqual(calls[1][0], ["docker", "exec", NODE, "nsenter", "-t", "2345", "-n",
                                         "--", "busybox", "wget", "-q", "-O", "-",
                                         "http://127.0.0.1:9902/metrics"])
        self.assertEqual(calls[1][1:], (5, 8192))
        self.assertTrue(all("secret" not in str(cmd).lower() and "--privileged" not in cmd
                            for cmd, _, _ in calls))

    def test_real_gateway_metrics_include_known_public_non_peer_gauges(self):
        raw = (b"# HELP ratatoskr_gateway_upstream_healthy probe\n"
               b"ratatoskr_gateway_upstream_healthy 1\n"
               b"ratatoskr_gateway_effective_mtu_bytes 1400\n"
               b"ratatoskr_gateway_wireguard_sample_ok 1\n"
               b"ratatoskr_gateway_wireguard_installed_peers 0\n"
               b"ratatoskr_gateway_wireguard_handshaken_peers 0\n"
               b"ratatoskr_gateway_wireguard_latest_handshake_age_seconds -1\n"
               b"ratatoskr_gateway_wireguard_receive_bytes 0\n"
               b"ratatoskr_gateway_wireguard_transmit_bytes 0\n")
        result = wt.parse_metrics(raw)
        self.assertEqual(result["installed_peers"], 0)
        self.assertEqual(set(result), {"sample_ok", "installed_peers", "handshaken_peers",
                                       "receive_bytes", "transmit_bytes"})

    def test_unknown_sample_and_peer_keys_rejected(self):
        for data in (b"ratatoskr_gateway_wireguard_sample_ok 0\n",
                     b"ratatoskr_gateway_wireguard_sample_ok 1\n",
                     b"ratatoskr_gateway_wireguard_sample_ok 1\n"
                     b"ratatoskr_gateway_wireguard_installed_peers{pod_uid=\"x\"} 1\n",
                     b"ratatoskr_gateway_wireguard_sample_ok 1\n"
                     b"ratatoskr_gateway_wireguard_public_key abc\n",
                     b"x" * 8193):
            with self.subTest(data=data[:20]), self.assertRaises(fixture.Blocked):
                wt.parse_metrics(data)

    def test_wrong_pod_uid_or_container_id_or_node_blocks_before_exec(self):
        p = pod()
        p["spec"]["nodeName"] = "other-node"
        with self.assertRaises(fixture.Blocked):
            wt.read_metrics(Operator(), p, IMAGE, transport=lambda *_a, **_k: self.fail("no docker"))
        wrong = {"status": {"id": IDENTITY, "state": "CONTAINER_RUNNING",
                            "metadata": {"name": "gateway"}, "labels": {"io.kubernetes.pod.uid": "other"}},
                 "info": {"pid": 2345}}
        with self.assertRaises(fixture.Blocked):
            wt.read_metrics(Operator(), pod(), IMAGE,
                            transport=lambda *_a, **_k: json.dumps(wrong).encode())


if __name__ == "__main__":
    unittest.main()
