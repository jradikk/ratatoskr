#!/usr/bin/env python3
"""Fake-only bounded fixed-node CRI preflight; no Docker/cluster execution."""
import importlib.util
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_node_images", Path(__file__).with_name("node_images.py"))
module = importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
DIGEST = "sha256:" + "a" * 64
APPROVED = {component: DIGEST for component in module.TAGS}


def inventory():
    return {"images": [{"id": DIGEST, "repoTags": [tag]} for tag in module.TAGS.values()]}


class CRITests(unittest.TestCase):
    def test_all_three_fixed_nodes_exact_argv_and_ids(self):
        calls = []
        def transport(argv, *, timeout, max_output):
            calls.append((argv, timeout, max_output))
            return json.dumps(inventory()).encode()
        self.assertTrue(module.verify(APPROVED, transport=transport))
        self.assertEqual([args[0][2] for args in calls], list(module.NODES))
        self.assertEqual(len(calls), 3)
        for args, timeout, max_output in calls:
            self.assertEqual(args[:2], ["docker", "exec"])
            self.assertEqual(args[3:], ["/bin/crictl", "--runtime-endpoint", module.RUNTIME,
                                        "images", "-o", "json"])
            self.assertLessEqual(timeout, 12)
            self.assertEqual(max_output, module.MAX_JSON)
        prefixed = {k: "containerd://" + v for k, v in APPROVED.items()}
        self.assertTrue(module.verify(prefixed, transport=transport))

    def test_init_only_seventh_exact_tag_and_image_id_on_three_nodes(self):
        approved = dict(APPROVED, init=DIGEST)
        items = inventory()
        items["images"].append({"id": DIGEST, "repoTags": [module.INIT_TAG]})
        calls = []
        def transport(argv, *, timeout, max_output):
            calls.append(argv)
            return json.dumps(items).encode()
        self.assertTrue(module.verify(approved, init=True, transport=transport))
        self.assertEqual(len(calls), 3)
        wrong = json.loads(json.dumps(items))
        wrong["images"][-1]["id"] = "sha256:" + "b" * 64
        with self.assertRaises(module.Blocked):
            module.inspect(wrong, approved, init=True)
        with self.assertRaises(module.Blocked):
            module.inspect(items, APPROVED, init=True)
        with self.assertRaises(module.Blocked):
            module.inspect(items, approved, init=False)

    def test_missing_duplicate_mismatch_malformed_fail_closed(self):
        wrong = []
        a = inventory()
        a["images"].pop()
        wrong.append(a)
        a = inventory()
        a["images"].append(dict(a["images"][0]))
        wrong.append(a)
        a = inventory()
        a["images"][0]["id"] = "sha256:" + "b" * 64
        wrong.append(a)
        a = inventory()
        a["images"][0]["repoTags"] *= 2
        wrong.append(a)
        wrong += [[], {"images": None}, {"images": []}, {"images": [{}]},
                  {"images": [{"id": DIGEST, "repoTags": ["no-match"]}]}]
        for item in wrong:
            with self.subTest(item=str(item)[:25]), self.assertRaises(module.Blocked):
                module.inspect(item, APPROVED)
        for k in APPROVED:
            with self.assertRaises(module.Blocked):
                module.approved(dict(APPROVED, **{k: "image:latest"}))
        with self.assertRaises(module.Blocked):
            module.approved({"server": DIGEST})

    def test_timeout_output_cap_and_sanitized_errors(self):
        times = [0, 0, 0, 61]
        def fake_clock():
            return times.pop(0) if times else 61
        with self.assertRaises(module.Blocked):
            module.verify(APPROVED, transport=lambda *_args, **_kw: json.dumps(inventory()).encode(),
                          clock=fake_clock, budget=60)
        for result in (b"SECRET not-json", b"a" * (module.MAX_JSON + 1)):
            with self.assertRaises(module.Blocked) as context:
                module.verify(APPROVED, transport=lambda *_args, **_kw: result)
            self.assertNotIn("SECRET", str(context.exception))
        def failed(*_args, **_kwargs):
            raise module.Blocked("Node CRI query failed.")
        with self.assertRaises(module.Blocked):
            module.verify(APPROVED, transport=failed)

    def test_local_process_never_inherits_secret_env_or_logs_stderr(self):
        argv = [sys.executable, "-c", "import os,sys;sys.stdout.write(os.getenv('PRIVATE','absent'))"]
        with patch.dict(module.os.environ, {"PRIVATE": "SECRET"}):
            self.assertEqual(module._bounded(argv, timeout=2, max_output=32), b"absent")
        with self.assertRaises(module.Blocked) as ctx:
            module._bounded([sys.executable, "-c", "import sys;sys.stderr.write('SECRET');sys.exit(1)"],
                            timeout=2, max_output=32)
        self.assertNotIn("SECRET", str(ctx.exception))
        with self.assertRaises(module.Blocked):
            module._bounded([sys.executable, "-c", "import sys;sys.stdout.write('x'*20000)"],
                            timeout=2, max_output=32)
        with self.assertRaises(module.Blocked):
            module._bounded([sys.executable, "-c", "import time;time.sleep(4)"],
                            timeout=0.05, max_output=32)


if __name__ == "__main__":
    unittest.main()
