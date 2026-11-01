"""Offline, strict OCI-layout archive verifier. No extraction or trust claim.

Only one separately supplied regular, single-link tar FD is read. It validates
a conservative two-platform OCI image layout; external SBOM/provenance and
cryptographic signature verification remain distinct release gates.
"""
import gzip
import hashlib
import json
import os
import re
import stat
import tarfile

HASH = re.compile(r"[0-9a-f]{64}\Z")
BLOB = re.compile(r"blobs/sha256/[0-9a-f]{64}\Z")
IMAGE_INDEX = "application/vnd.oci.image.index.v1+json"
IMAGE_MANIFEST = "application/vnd.oci.image.manifest.v1+json"
IMAGE_CONFIG = "application/vnd.oci.image.config.v1+json"
LAYERS = {"application/vnd.oci.image.layer.v1.tar", "application/vnd.oci.image.layer.v1.tar+gzip",
          "application/vnd.oci.image.layer.nondistributable.v1.tar",
          "application/vnd.oci.image.layer.nondistributable.v1.tar+gzip"}
MAX_EXPANDED_LAYER = 1 << 30
MAX_EXPANDED_TOTAL = 4 << 30
MAX_LAYER_MEMBERS = 4096
ARCHES = frozenset(("amd64", "arm64"))
MAX_MEMBERS = 4096
MAX_SMALL = 64 << 20
MAX_BLOB = 1 << 30
MAX_TOTAL = 4 << 30
MAX_JSON = 2 << 20


class Rejected(ValueError):
    """Sanitized archive rejection; no raw entry or image config disclosed."""


def _json(raw):
    if not isinstance(raw, bytes) or not raw or len(raw) > MAX_JSON:
        raise Rejected("OCI JSON missing or oversized")
    def unique(pairs):
        result = {}
        for key, value in pairs:
            if key in result:
                raise Rejected("duplicate OCI JSON key")
            result[key] = value
        return result
    def constant(_value):
        raise Rejected("nonstandard OCI JSON constant")
    try:
        doc = json.loads(raw, object_pairs_hook=unique, parse_constant=constant)
    except (UnicodeError, ValueError, RecursionError):
        raise Rejected("OCI JSON malformed") from None
    if type(doc) is not dict:
        raise Rejected("OCI JSON document must be an object")
    return doc


def _descriptor(value, media, *, platform=False):
    if (type(value) is not dict or set(value) != ({"mediaType", "digest", "size", "platform"}
            if platform else {"mediaType", "digest", "size"}) or
            value.get("mediaType") not in media or type(value.get("size")) is not int or
            not 0 < value["size"] <= MAX_BLOB or type(value.get("digest")) is not str or
            not value["digest"].startswith("sha256:") or not HASH.fullmatch(value["digest"][7:])):
        raise Rejected("OCI descriptor invalid or unsupported")
    if platform:
        p = value["platform"]
        if type(p) is not dict or set(p) != {"os", "architecture"} or p["os"] != "linux" or p["architecture"] not in ARCHES:
            raise Rejected("OCI manifest platform unsupported")
    return "blobs/sha256/" + value["digest"][7:]


def _headers(fileobj, size):
    """Reject hidden GNU/PAX/sparse/extended headers before tarfile normalizes.

    Accept only ordinary uncompressed ustar files. 512-byte aligned data and
    trailing zero blocks are verified without following or extracting entries.
    """
    names = []
    offset = 0
    while offset + 512 <= size:
        fileobj.seek(offset)
        header = fileobj.read(512)
        if len(header) != 512:
            raise Rejected("OCI tar header truncated")
        if header == bytes(512):
            if size - offset < 1024:
                raise Rejected("OCI tar termination malformed")
            fileobj.seek(offset)
            while chunk := fileobj.read(1 << 20):
                if any(chunk):
                    raise Rejected("OCI tar contains nonzero trailing bytes")
            return names
        if (len(names) >= MAX_MEMBERS or header[156:157] not in (b"0", b"\x00") or
                header[257:263] != b"ustar\x00" or header[263:265] != b"00" or
                any(header[345:500])):
            raise Rejected("OCI tar extended or unsupported header")
        try:
            stored_sum = int(header[148:156].strip(b"\x00 "), 8)
            computed_sum = sum(header[:148]) + sum(b"        ") + sum(header[156:])
            name = header[:100].split(b"\x00", 1)[0].decode("ascii")
            size_text = header[124:136].strip(b"\x00 ").decode("ascii")
            member_size = int(size_text, 8)
        except (UnicodeError, ValueError):
            raise Rejected("OCI tar member name or size malformed") from None
        if (stored_sum != computed_sum or not name or len(name) > 100 or name.startswith("/") or "\\" in name or
                any(part in ("", ".", "..") for part in name.split("/")) or
                name not in ("oci-layout", "index.json") and not BLOB.fullmatch(name) or
                member_size <= 0 or member_size > MAX_BLOB or name in names):
            raise Rejected("OCI tar member name or size unsafe")
        names.append(name)
        offset += 512 + ((member_size + 511) // 512) * 512
        if offset > size:
            raise Rejected("OCI tar member extends beyond archive")
    raise Rejected("OCI tar termination missing")



class _Slice:
    """Read only one compressed blob's byte span from the already-open FD."""
    def __init__(self, source, offset, length):
        self.source, self.offset, self.length, self.position = source, offset, length, 0

    def read(self, size=-1):
        size = self.length - self.position if size < 0 else min(size, self.length - self.position)
        if size <= 0:
            return b""
        self.source.seek(self.offset + self.position)
        chunk = self.source.read(size)
        self.position += len(chunk)
        return chunk


def _layer(source, offset, length, media, *, remaining, member_budget):
    """Hash bounded uncompressed tar bytes while checking every layer entry."""
    compressed = _Slice(source, offset, length)
    stream = gzip.GzipFile(fileobj=compressed, mode="rb") if media.endswith("+gzip") else compressed
    digest = hashlib.sha256()
    expanded = 0
    seen = set()
    count = 0

    def take(size):
        nonlocal expanded
        if size < 0 or size > MAX_EXPANDED_LAYER - expanded or size > remaining - expanded:
            raise Rejected("expanded OCI layer exceeds limit")
        chunk = stream.read(size)
        if len(chunk) != size:
            raise Rejected("OCI layer truncated")
        expanded += size
        digest.update(chunk)
        return chunk

    try:
        while True:
            header = take(512)
            if not any(header):
                if not any(take(512)):
                    # Consume all remaining decompressed padding under bounds;
                    # gzip also checks its own CRC and complete trailer here.
                    while block := stream.read(min(1 << 20, MAX_EXPANDED_LAYER - expanded + 1,
                                                   remaining - expanded + 1)):
                        if expanded + len(block) > min(MAX_EXPANDED_LAYER, remaining) or any(block):
                            raise Rejected("OCI layer has nonzero trailing bytes or exceeds bound")
                        digest.update(block)
                        expanded += len(block)
                    if not media.endswith("+gzip") and compressed.position != length:
                        raise Rejected("OCI layer contains unread bytes")
                    return digest.hexdigest(), expanded, count
                raise Rejected("OCI layer missing double-zero termination")
            if (count >= member_budget or count >= MAX_LAYER_MEMBERS or
                    header[156:157] not in (b"0", b"\x00", b"5") or
                    header[257:263] != b"ustar\x00" or header[263:265] != b"00" or
                    any(header[345:500]) or any(header[157:257])):
                raise Rejected("OCI layer extended, link or unsupported tar header")
            try:
                checksum = int(header[148:156].strip(b"\x00 "), 8)
                size = int(header[124:136].strip(b"\x00 "), 8)
                name = header[:100].split(b"\x00", 1)[0].decode("ascii")
            except (UnicodeError, ValueError):
                raise Rejected("OCI layer header malformed") from None
            directory = header[156:157] == b"5"
            canonical = name[:-1] if directory and name.endswith("/") else name
            if (checksum != sum(header[:148]) + sum(b"        ") + sum(header[156:]) or
                    not canonical or len(name) > 100 or canonical.startswith("/") or
                    "\\" in canonical or any(part in ("", ".", "..") for part in canonical.split("/")) or
                    canonical in seen or directory and size != 0):
                raise Rejected("OCI layer path or header unsafe")
            seen.add(canonical)
            count += 1
            # Empty regular files, including overlay .wh.* whiteouts, are valid.
            payload = size + (-size % 512)
            while payload:
                chunk = min(payload, 1 << 20)
                take(chunk)
                payload -= chunk
    except Rejected:
        raise
    except (OSError, EOFError, gzip.BadGzipFile):
        raise Rejected("OCI layer gzip or tar stream malformed") from None
    finally:
        if media.endswith("+gzip"):
            stream.close()


def verify(fileobj):
    """Return structural/digest verification only; never attest a release.

    `fileobj` must be an independently approved, seekable binary FD opened
    O_NOFOLLOW by its caller. No symlinks/hardlinks/sparse files or extra OCI
    blobs/attestation-platform manifests are allowed under this first policy.
    """
    if not hasattr(fileobj, "fileno") or not hasattr(fileobj, "seek"):
        raise Rejected("seekable regular archive FD required")
    try:
        before = os.fstat(fileobj.fileno())
        if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1 or not 0 < before.st_size <= MAX_TOTAL:
            raise Rejected("archive must be nonempty single-link regular file within bound")
        expected_names = _headers(fileobj, before.st_size)
        fileobj.seek(0)
        members, blobs, offsets = {}, {}, {}
        total = 0
        try:
            with tarfile.open(fileobj=fileobj, mode="r:") as archive:
                for member in archive:
                    name = member.name
                    if (len(members) >= MAX_MEMBERS or type(name) is not str or not name or
                            name.startswith("/") or "\\" in name or "\x00" in name or
                            any(part in ("", ".", "..") for part in name.split("/")) or
                            name in members or not member.isfile() or member.pax_headers or
                            member.type not in (tarfile.REGTYPE, tarfile.AREGTYPE) or
                            member.name.startswith("./") or member.size <= 0):
                        raise Rejected("OCI tar member unsafe or duplicate")
                    limit = MAX_BLOB if BLOB.fullmatch(name) else MAX_SMALL
                    if member.size > limit or member.size > MAX_TOTAL - total:
                        raise Rejected("OCI tar member or total exceeds bound")
                    if name not in ("oci-layout", "index.json") and not BLOB.fullmatch(name):
                        raise Rejected("OCI tar contains unapproved member")
                    if name in ("oci-layout", "index.json") and member.size > MAX_JSON:
                        raise Rejected("OCI root JSON exceeds bound")
                    total += member.size
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise Rejected("OCI member unreadable")
                    h = hashlib.sha256()
                    small = bytearray() if member.size <= MAX_JSON else None
                    read = 0
                    while chunk := stream.read(min(1 << 20, member.size - read + 1)):
                        read += len(chunk)
                        if read > member.size:
                            raise Rejected("OCI member exceeds declared size")
                        h.update(chunk)
                        if small is not None:
                            small.extend(chunk)
                    if read != member.size:
                        raise Rejected("OCI member truncated")
                    members[name] = (read, h.hexdigest(), bytes(small) if small is not None else None)
                    offsets[name] = member.offset_data
                    if BLOB.fullmatch(name):
                        if h.hexdigest() != name.rsplit("/", 1)[1]:
                            raise Rejected("OCI blob path digest differs from bytes")
                        blobs[name] = members[name]
        except (tarfile.TarError, OSError, EOFError):
            raise Rejected("OCI tar unreadable or malformed") from None
        if list(members) != expected_names:
            raise Rejected("OCI tar header/member mismatch")
        after = os.fstat(fileobj.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns,
            before.st_nlink) != (after.st_dev, after.st_ino, after.st_size, after.st_mtime_ns,
                                after.st_ctime_ns, after.st_nlink):
            raise Rejected("OCI archive changed during verification")
        if "oci-layout" not in members or "index.json" not in members:
            raise Rejected("OCI layout or index missing")
        layout = _json(members["oci-layout"][2])
        if layout != {"imageLayoutVersion": "1.0.0"}:
            raise Rejected("OCI layout version unsupported")
        index = _json(members["index.json"][2])
        if (type(index.get("schemaVersion")) is not int or index["schemaVersion"] != 2 or
                index.get("mediaType") != IMAGE_INDEX or type(index.get("manifests")) is not list or
                len(index["manifests"]) != 2 or set(index) != {"schemaVersion", "mediaType", "manifests"}):
            raise Rejected("OCI index schema or manifest count unsupported")
        seen, referenced = set(), set()
        expanded_total, layer_count = 0, 0
        def blob(desc, media, *, platform=False):
            path = _descriptor(desc, media, platform=platform)
            if path not in blobs or blobs[path][0] != desc["size"]:
                raise Rejected("OCI descriptor blob absent or size mismatch")
            referenced.add(path)
            return blobs[path][2]
        for manifest_desc in index["manifests"]:
            raw = blob(manifest_desc, {IMAGE_MANIFEST}, platform=True)
            if raw is None:
                raise Rejected("OCI image manifest JSON exceeds bound")
            architecture = manifest_desc["platform"]["architecture"]
            if architecture in seen:
                raise Rejected("duplicate OCI architecture")
            seen.add(architecture)
            manifest = _json(raw)
            if (set(manifest) != {"schemaVersion", "mediaType", "config", "layers"} or
                    type(manifest.get("schemaVersion")) is not int or manifest["schemaVersion"] != 2 or
                    manifest.get("mediaType") != IMAGE_MANIFEST or type(manifest.get("layers")) is not list or
                    not manifest["layers"]):
                raise Rejected("OCI image manifest schema invalid")
            config = _json(blob(manifest["config"], {IMAGE_CONFIG}))
            if config.get("os") != "linux" or config.get("architecture") != architecture:
                raise Rejected("OCI image config platform differs from descriptor")
            rootfs = config.get("rootfs")
            if (type(rootfs) is not dict or set(rootfs) != {"type", "diff_ids"} or
                    rootfs["type"] != "layers" or type(rootfs["diff_ids"]) is not list or
                    len(rootfs["diff_ids"]) != len(manifest["layers"]) or
                    any(type(d) is not str or not d.startswith("sha256:") or
                        not HASH.fullmatch(d[7:]) for d in rootfs["diff_ids"])):
                raise Rejected("OCI config rootfs layer diffIDs missing or malformed")
            for layer, diff_id in zip(manifest["layers"], rootfs["diff_ids"]):
                path = _descriptor(layer, LAYERS)
                blob(layer, LAYERS)
                if path not in members:
                    raise Rejected("OCI layer blob missing")
                member_offset = offsets[path]
                uncompressed, used, count = _layer(fileobj, member_offset, layer["size"],
                    layer["mediaType"], remaining=MAX_EXPANDED_TOTAL - expanded_total,
                    member_budget=MAX_LAYER_MEMBERS - layer_count)
                expanded_total += used
                layer_count += count
                if uncompressed != diff_id[7:]:
                    raise Rejected("OCI layer bytes do not match config rootfs diffID")
        if seen != ARCHES or referenced != set(blobs):
            raise Rejected("OCI platform missing or unreferenced blob present")
        final = os.fstat(fileobj.fileno())
        if (before.st_dev, before.st_ino, before.st_size, before.st_mtime_ns, before.st_ctime_ns,
            before.st_nlink) != (final.st_dev, final.st_ino, final.st_size, final.st_mtime_ns,
                                final.st_ctime_ns, final.st_nlink):
            raise Rejected("OCI archive changed during layer verification")
        return {"contentVerified": True, "signatureVerified": False, "releaseReady": False,
                "platforms": ("linux/amd64", "linux/arm64"), "blobCount": len(blobs)}
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        if isinstance(error, Rejected):
            raise
        raise Rejected("OCI content verification failed") from None
