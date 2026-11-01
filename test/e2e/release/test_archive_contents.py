"""Tiny synthetic OCI archives only; no images, credentials or extraction."""
import copy
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tarfile
import tempfile
import unittest
from unittest.mock import patch

HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("archive_contents", HERE / "archive_contents.py")
oci = importlib.util.module_from_spec(spec)
spec.loader.exec_module(oci)


def encoded(obj):
    return json.dumps(obj, sort_keys=True, separators=(",", ":")).encode()


def descriptor(data, media, platform=None):
    result = {"mediaType": media, "digest": "sha256:" + hashlib.sha256(data).hexdigest(), "size": len(data)}
    if platform is not None:
        result["platform"] = {"os": "linux", "architecture": platform}
    return result


def blobs_and_entries():
    entries = [("oci-layout", encoded({"imageLayoutVersion": "1.0.0"}))]
    index = {"schemaVersion": 2, "mediaType": oci.IMAGE_INDEX, "manifests": []}
    for arch in ("amd64", "arm64"):
        layer = (arch + "-synthetic-layer").encode()
        config = encoded({"os": "linux", "architecture": arch, "config": {"Env": []}})
        manifest = encoded({"schemaVersion": 2, "mediaType": oci.IMAGE_MANIFEST,
                            "config": descriptor(config, oci.IMAGE_CONFIG),
                            "layers": [descriptor(layer, "application/vnd.oci.image.layer.v1.tar+gzip")]})
        for blob in (layer, config, manifest):
            entries.append(("blobs/sha256/" + hashlib.sha256(blob).hexdigest(), blob))
        index["manifests"].append(descriptor(manifest, oci.IMAGE_MANIFEST, arch))
    entries.append(("index.json", encoded(index)))
    return entries


def archive(entries):
    # Tests write a tiny, private temporary input file only; verifier extracts nothing.
    tmp = tempfile.TemporaryDirectory(prefix="oci-verifier-test-")
    path = Path(tmp.name) / "fixture.tar"
    with tarfile.open(path, "w") as t:
        for entry in entries:
            if len(entry) == 2:
                name, data = entry
                item = tarfile.TarInfo(name)
                item.size = len(data)
                t.addfile(item, io.BytesIO(data))
            else:
                item = entry[2]
                t.addfile(item, io.BytesIO(entry[1]) if item.isfile() else None)
    return tmp, path


class ArchiveTests(unittest.TestCase):
    def check(self, entries, *, valid=False):
        temp, path = archive(entries)
        self.addCleanup(temp.cleanup)
        with path.open("rb") as f:
            if valid:
                return oci.verify(f)
            with self.assertRaises(oci.Rejected):
                oci.verify(f)

    def test_two_platforms_and_no_attestation_claim(self):
        result = self.check(blobs_and_entries(), valid=True)
        self.assertEqual(result["platforms"], ("linux/amd64", "linux/arm64"))
        self.assertEqual(result["blobCount"], 6)
        self.assertTrue(result["contentVerified"])
        self.assertFalse(result["signatureVerified"])
        self.assertFalse(result["releaseReady"])

    def test_tar_member_path_types_and_duplicates(self):
        base = blobs_and_entries()
        for name in ("../escape", "/root/secret", "a\\b", "a/../escape", "./index.json", "a//b", "unknown"):
            with self.subTest(name=name):
                self.check(base + [(name, b"x")])
        self.check(base + [base[-1]])
        for kind in (tarfile.SYMTYPE, tarfile.LNKTYPE, tarfile.CHRTYPE, tarfile.BLKTYPE, tarfile.FIFOTYPE):
            item = tarfile.TarInfo("member")
            item.type = kind
            item.linkname = "index.json"
            self.check(base + [("member", b"", item)])
        item = tarfile.TarInfo("member")
        item.pax_headers = {"path": "member"}
        item.size = 1
        self.check(base + [("member", b"x", item)])

    def test_blob_bytes_or_descriptor_size_mismatch(self):
        base = blobs_and_entries()
        changed = copy.deepcopy(base)
        changed[1] = (changed[1][0], b"wrong")
        self.check(changed)
        changed = copy.deepcopy(base)
        index = json.loads(changed[-1][1])
        index["manifests"][0]["size"] += 1
        changed[-1] = ("index.json", encoded(index))
        self.check(changed)
        changed = copy.deepcopy(base)
        changed.pop(1)
        self.check(changed)
        changed = copy.deepcopy(base)
        changed.insert(-1, ("blobs/sha256/" + "0" * 64, b"unreferenced"))
        self.check(changed)

    def test_index_platform_and_document_strictness(self):
        base = blobs_and_entries()
        for edit in (lambda d: d["manifests"].append(copy.deepcopy(d["manifests"][0])),
                     lambda d: d["manifests"][1]["platform"].update(architecture="amd64"),
                     lambda d: d["manifests"][1]["platform"].update(architecture="s390x"),
                     lambda d: d["manifests"][0].update(mediaType="application/vnd.docker.distribution.manifest.v2+json"),
                     lambda d: d.update(schemaVersion=True),
                     lambda d: d.pop("mediaType")):
            changed = copy.deepcopy(base)
            index = json.loads(changed[-1][1])
            edit(index)
            changed[-1] = ("index.json", encoded(index))
            self.check(changed)
        changed = copy.deepcopy(base)
        changed[-1] = ("index.json", b'{"schemaVersion":2,"schemaVersion":2}')
        self.check(changed)
        changed = copy.deepcopy(base)
        changed[0] = ("oci-layout", encoded({"imageLayoutVersion": "1.0.1"}))
        self.check(changed)

    def test_config_platform_and_layer_media(self):
        base = blobs_and_entries()
        for config_override in ({"os": "linux", "architecture": "arm64"}, {"os": "windows", "architecture": "amd64"}):
            changed = copy.deepcopy(base)
            config = encoded(config_override)
            original_manifest = json.loads(changed[3][1])
            changed[2] = ("blobs/sha256/" + hashlib.sha256(config).hexdigest(), config)
            original_manifest["config"] = descriptor(config, oci.IMAGE_CONFIG)
            manifest = encoded(original_manifest)
            changed[3] = ("blobs/sha256/" + hashlib.sha256(manifest).hexdigest(), manifest)
            index = json.loads(changed[-1][1])
            index["manifests"][0] = descriptor(manifest, oci.IMAGE_MANIFEST, "amd64")
            changed[-1] = ("index.json", encoded(index))
            self.check(changed)
        changed = copy.deepcopy(base)
        manifest = json.loads(changed[3][1])
        manifest["layers"][0]["mediaType"] = "application/x-unreviewed-layer"
        raw = encoded(manifest)
        changed[3] = ("blobs/sha256/" + hashlib.sha256(raw).hexdigest(), raw)
        index = json.loads(changed[-1][1])
        index["manifests"][0] = descriptor(raw, oci.IMAGE_MANIFEST, "amd64")
        changed[-1] = ("index.json", encoded(index))
        self.check(changed)

    def test_ustar_only_rejects_hidden_extended_or_tail_bytes(self):
        base = blobs_and_entries()
        temp, path = archive(base)
        self.addCleanup(temp.cleanup)
        raw = bytearray(path.read_bytes())
        raw[156] = ord("S")  # GNU sparse typeflag; recompute header checksum.
        raw[148:156] = b"        "
        raw[148:156] = ("%06o\\0 " % sum(raw[:512])).encode()
        path.write_bytes(raw)
        with path.open("rb") as f, self.assertRaises(oci.Rejected):
            oci.verify(f)
        temp, path = archive(base)
        self.addCleanup(temp.cleanup)
        with path.open("ab") as f:
            f.write(b"hidden")
        with path.open("rb") as f, self.assertRaises(oci.Rejected):
            oci.verify(f)
        temp, path = archive(base)
        self.addCleanup(temp.cleanup)
        raw = bytearray(path.read_bytes())
        raw[0] = ord("X")  # invalid header checksum/name mismatch
        path.write_bytes(raw)
        with path.open("rb") as f, self.assertRaises(oci.Rejected):
            oci.verify(f)

    def test_limits_no_write_or_extract(self):
        base = blobs_and_entries()
        with patch.object(oci, "MAX_MEMBERS", 3):
            self.check(base)
        with patch.object(oci, "MAX_SMALL", 4):
            self.check(base)
        with patch.object(oci, "MAX_JSON", 12):
            self.check(base)
        with patch.object(oci.tarfile.TarFile, "extractall", side_effect=AssertionError("extract forbidden")):
            self.check(base, valid=True)
        temp, path = archive(base)
        self.addCleanup(temp.cleanup)
        os.link(path, path.with_name("hardlink.tar"))
        with path.open("rb") as f, self.assertRaises(oci.Rejected):
            oci.verify(f)


if __name__ == "__main__":
    unittest.main()
