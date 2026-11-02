"""Tiny synthetic files only; never build, extract or inspect real credentials."""
import copy
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import shutil
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("artifact_manifest", HERE / "artifact_manifest.py")
mod = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mod)
SHA = "a" * 40
VERSION = "1.2.3-rc.1"


def encode(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


class Fixture:
    def __init__(self):
        self.temp = tempfile.TemporaryDirectory(prefix="artifact-manifest-tests-")
        root = Path(self.temp.name)
        self.checkout = root / "checkout"
        self.checkout.mkdir()
        self.input = root / "private-input"
        self.input.mkdir()
        self.manifest = {"schemaVersion": 1, "reviewedVersion": VERSION,
                         "sourceSHA": SHA, "artifacts": []}
        paths = mod._roles(VERSION)
        hashes = {}
        for role, (name, image) in paths.items():
            if not image:
                data = ("synthetic:" + role).encode()
                hashes[role] = hashlib.sha256(data).hexdigest()
            else:
                data = encode({"schemaVersion": 1, "kind": role.split(":")[0],
                               "subject": {"role": image, "sha256": hashes[image]},
                               "sourceSHA": SHA, "reviewedVersion": VERSION})
            (self.input / name).write_bytes(data)
            self.manifest["artifacts"].append({"role": role, "name": name,
                                               "size": len(data), "sha256": hashlib.sha256(data).hexdigest()})
        self.manifest["artifacts"].reverse()  # order intentionally irrelevant

    def close(self):
        self.temp.cleanup()

    def raw(self):
        return encode(self.manifest)

    def validate(self, raw=None, **options):
        args = dict(reviewed_version=VERSION, source_sha=SHA)
        args.update(options)
        return mod.validate_manifest(self.raw() if raw is None else raw, **args)

    def verify(self, raw=None, **options):
        args = dict(input_dir=self.input, checkout=self.checkout,
                    reviewed_version=VERSION, source_sha=SHA)
        args.update(options)
        return mod.verify_files(self.raw() if raw is None else raw, **args)


class ManifestTests(unittest.TestCase):
    def setUp(self):
        self.f = Fixture()
        self.addCleanup(self.f.close)

    def test_29_exact_roles_and_read_only_files(self):
        self.assertEqual(len(self.f.manifest["artifacts"]), 29)
        manifest_digest = hashlib.sha256(self.f.raw()).hexdigest()
        self.assertEqual(self.f.validate(expected_manifest_sha256=manifest_digest)["status"],
                         "METADATA_ONLY_NOT_ATTESTED")
        with patch.object(mod.os, "open", wraps=os.open) as opened:
            verified = self.f.verify(expected_manifest_sha256=manifest_digest)
            self.assertEqual(opened.call_count, 30)  # directory FD plus 29 flat files
            self.assertTrue(all(call.args[1] & os.O_NOFOLLOW for call in opened.call_args_list))
        self.assertEqual(verified["status"], "BYTES_MATCH_MANIFEST_NOT_ATTESTED")
        self.assertFalse(verified["releaseReady"])
        self.assertEqual(set(verified["artifactRoles"]), set(mod._roles(VERSION)))

    def test_duplicate_and_nonstandard_json_claims_are_rejected(self):
        raw = self.f.raw()
        duplicate = raw.replace(b'"schemaVersion":1', b'"schemaVersion":2,"schemaVersion":1', 1)
        with self.assertRaises(mod.Rejected):
            self.f.validate(duplicate)
        for raw_claim in (b'{"nested":{"sourceSHA":"wrong","sourceSHA":"right"}}',
                          b'{"value":NaN}', b'{"value":Infinity}', b'{"value":-Infinity}'):
            with self.subTest(raw_claim=raw_claim), self.assertRaises(mod.Rejected):
                mod._json(raw_claim)

    def test_duplicate_provenance_claim_cannot_be_overwritten(self):
        item = next(i for i in self.f.manifest["artifacts"] if i["role"] == "provenance:gateway")
        path = self.f.input / item["name"]
        data = path.read_bytes().replace(b'"sourceSHA":', b'"sourceSHA":"wrong","sourceSHA":', 1)
        path.write_bytes(data)
        item["size"] = len(data)
        item["sha256"] = hashlib.sha256(data).hexdigest()
        with self.assertRaises(mod.Rejected):
            self.f.verify()

    def test_manifest_scope_identity_and_missing_role(self):
        for mut in (lambda m: m.update(schemaVersion=2),
                    lambda m: m.update(sourceSHA="b" * 40),
                    lambda m: m.update(reviewedVersion="1.2.3"),
                    lambda m: m["artifacts"].pop(),
                    lambda m: m["artifacts"][0].update(role="invented"),
                    lambda m: m["artifacts"][0].update(role=m["artifacts"][1]["role"]),
                    lambda m: m["artifacts"][0].update(name="../private.key"),
                    lambda m: m["artifacts"][0].update(name="/tmp/absolute"),
                    lambda m: m["artifacts"][0].update(name="secret.ovpn"),
                    lambda m: m["artifacts"][0].update(size=True),
                    lambda m: m["artifacts"][0].update(size=0),
                    lambda m: m["artifacts"][0].update(sha256="b" * 63)):
            manifest = copy.deepcopy(self.f.manifest)
            mut(manifest)
            with self.assertRaises(mod.Rejected):
                self.f.validate(encode(manifest))
        for opts in ({"reviewed_version": "dev"}, {"source_sha": "a" * 7},
                     {"expected_manifest_sha256": "b" * 64}):
            with self.assertRaises(mod.Rejected):
                self.f.validate(**opts)

    def test_six_oci_archives_required_even_when_ten_binaries_exist(self):
        item = next(i for i in self.f.manifest["artifacts"] if i["role"] == "image:upstream-openvpn")
        self.f.manifest["artifacts"].remove(item)
        with self.assertRaises(mod.Rejected):
            self.f.validate()
        self.f.manifest["artifacts"].append(item)
        item = next(i for i in self.f.manifest["artifacts"] if i["role"] == "binary:controller:arm64")
        item["role"] = "binary:controller:riscv64"
        with self.assertRaises(mod.Rejected):
            self.f.validate()

    def test_tampered_bytes_and_wrong_document_subject(self):
        target = next(i for i in self.f.manifest["artifacts"] if i["role"] == "binary:gateway:arm64")
        (self.f.input / target["name"]).write_bytes(b"tampered")
        with self.assertRaises(mod.Rejected):
            self.f.verify()
        (self.f.input / target["name"]).write_bytes(b"synthetic:" + target["role"].encode())
        doc = next(i for i in self.f.manifest["artifacts"] if i["role"] == "provenance:gateway")
        bad = {"schemaVersion": 1, "kind": "provenance", "subject": {"role": "image:gateway", "sha256": "b" * 64},
               "sourceSHA": SHA, "reviewedVersion": VERSION}
        raw = encode(bad)
        (self.f.input / doc["name"]).write_bytes(raw)
        doc.update(size=len(raw), sha256=hashlib.sha256(raw).hexdigest())
        with self.assertRaises(mod.Rejected):
            self.f.verify()

    def test_symlink_hardlink_directory_zero_and_oversize(self):
        item = self.f.manifest["artifacts"][0]
        name = item["name"]
        original = self.f.input / name
        original.unlink()
        original.symlink_to("missing")
        with self.assertRaises(mod.Rejected):
            self.f.verify()
        original.unlink()
        original.write_bytes(b"synthetic:" + item["role"].encode() if item["role"].startswith("binary:") else b"x")
        os.link(original, self.f.input / "hardlinked")
        with self.assertRaises(mod.Rejected):
            self.f.verify()
        (self.f.input / "hardlinked").unlink()
        original.unlink()
        original.mkdir()
        with self.assertRaises(mod.Rejected):
            self.f.verify()
        original.rmdir()
        original.write_bytes(b"")
        with self.assertRaises(mod.Rejected):
            self.f.verify()
        original.write_bytes(b"x" * 64)
        with patch.object(mod, "_MAX_FILE", 32):
            with self.assertRaises(mod.Rejected):
                self.f.verify()

    def test_external_root_mandatory_and_symlink_parent_rejected(self):
        for root in (self.f.checkout, self.f.checkout / "child", Path("relative")):
            with self.assertRaises(mod.Rejected):
                self.f.verify(input_dir=root)
        alias = self.f.checkout.parent / "alias"
        alias.symlink_to(self.f.input, target_is_directory=True)
        with self.assertRaises(mod.Rejected):
            self.f.verify(input_dir=alias)

    def test_detect_changed_stat_during_read(self):
        actual = mod.os.fstat
        calls = 0
        def mutate(fd):
            nonlocal calls
            calls += 1
            st = actual(fd)
            if calls % 2 == 0:
                # mock a distinct mtime value without writing input bytes
                return type("Stat", (), {"st_dev": st.st_dev, "st_ino": st.st_ino,
                    "st_mode": st.st_mode, "st_nlink": st.st_nlink, "st_size": st.st_size,
                    "st_mtime_ns": st.st_mtime_ns + 1, "st_ctime_ns": st.st_ctime_ns})()
            return st
        with patch.object(mod.os, "fstat", side_effect=mutate):
            with self.assertRaises(mod.Rejected):
                self.f.verify()


if __name__ == "__main__":
    unittest.main()
