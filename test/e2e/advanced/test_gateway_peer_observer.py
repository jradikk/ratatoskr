"""Read-only CRI UID/pid pinning around public-only peer fingerprint."""
import hashlib
import json
import sys
import unittest
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parent))
sys.dont_write_bytecode = True
import gateway_negative as neg
import wg_fixture as wg
import wg_transport as wt

UID = "a" * 32
CID = "b" * 64
IMAGE = "containerd://sha256:" + "c" * 64
NODE = wt.NODES[0]
DIGEST = hashlib.sha256(b"valid-peer-public-key").hexdigest()


def pod(uid=UID):
    return {"metadata": {"name": "rtk-wg-owned-pod", "uid": uid},
            "spec": {"nodeName": NODE}, "status": {"containerStatuses": [
                {"name": "gateway", "ready": True, "imageID": IMAGE,
                 "containerID": "containerd://" + CID}]}}


def inspection(uid=UID, pid=1234):
    return {"status": {"id": CID, "state": "CONTAINER_RUNNING",
                       "metadata": {"name": "gateway"},
                       "labels": {"io.kubernetes.pod.uid": uid}},
            "info": {"pid": pid}}


class Operator:
    def __init__(self): self.current = pod()
    def get_object(self, kind, name, ns):
        assert (kind, name, ns) == ("pod", "rtk-wg-owned-pod", wg.SYSTEM)
        return self.current


class ObserverTest(unittest.TestCase):
    def test_exact_cri_shape_and_digest_without_key_or_secret_output(self):
        commands = []
        def transport(argv, *, timeout, max_output):
            commands.append((argv, timeout, max_output))
            return json.dumps(inspection()).encode()
        root_calls = []
        def root(node, pid):
            root_calls.append((node, pid))
            return {"peerDigest": DIGEST}
        value = neg.peer_digest(Operator(), pod(), IMAGE, transport=transport, root=root)
        self.assertEqual(value, DIGEST)
        self.assertEqual(root_calls, [(NODE, 1234)])
        self.assertEqual(len(commands), 2)
        for argv, timeout, max_output in commands:
            self.assertEqual(argv, ["docker", "exec", NODE, "/bin/crictl",
                                    "--runtime-endpoint", wt.RUNTIME, "inspect", "-o", "json", CID])
            self.assertEqual((timeout, max_output), (5, 65536))
            self.assertNotIn("wg", argv)
            self.assertNotIn("private", " ".join(argv))

    def test_wrong_uid_replaced_pid_or_pod_and_probe_key_are_rejected(self):
        for current, reply, peer in ((pod(), inspection(uid="f" * 32), DIGEST),
                                      (pod(), inspection(pid=1235), DIGEST),
                                      (pod(uid="f" * 32), inspection(), DIGEST),
                                      (pod(), inspection(), hashlib.sha256(neg.TEST_KEY.encode()).hexdigest())):
            responses = [inspection(), reply]
            op = Operator(); op.current = current
            def transport(_argv, *, timeout, max_output):
                return json.dumps(responses.pop(0)).encode()
            with self.subTest(peer=peer, current=current["metadata"]["uid"]), \
                    self.assertRaises((wg.Blocked, neg.Blocked)):
                neg.peer_digest(op, pod(), IMAGE, transport=transport,
                                root=lambda *_: {"peerDigest": peer})


if __name__ == "__main__":
    unittest.main()
