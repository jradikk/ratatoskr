#!/usr/bin/env python3
"""Bounded offline staging of explicit live inputs. Never prints input data."""
import os
from pathlib import Path
import shutil
import stat
import sys

MAX_BYTES = 1 << 20
ENV_FILES = {
    "RATATOSKR_E2E_OVPN_CA": "ca.crt",
    "RATATOSKR_E2E_OVPN_CERT": "client.crt",
    "RATATOSKR_E2E_OVPN_KEY": "client.key",
    "RATATOSKR_E2E_OVPN_AUTH": "auth.txt",
}
FILE_OPTIONS = {"ca": "ca.crt", "cert": "client.crt", "key": "client.key"}
INLINE = {"ca", "cert", "key", "tls-auth", "tls-crypt", "tls-crypt-v2", "extra-certs", "dh"}
# Deliberately mirrors the plugin transport/TLS allowlist. Other external TLS
# file types need explicit new env inputs; never follow arbitrary profile paths.
ALLOWED = set("""client tls-client remote proto port rport lport nobind resolv-retry
connect-retry connect-retry-max connect-timeout server-poll-timeout remote-random
remote-random-hostname float persist-key persist-tun ping ping-restart ping-exit
keepalive inactive explicit-exit-notify cipher data-ciphers data-ciphers-fallback
auth auth-nocache auth-retry remote-cert-tls remote-cert-ku remote-cert-eku
verify-x509-name peer-fingerprint tls-version-min tls-version-max tls-cipher
tls-ciphersuites reneg-sec reneg-bytes reneg-pkts hand-window tran-window
key-direction tun-mtu link-mtu mssfix fragment sndbuf rcvbuf fast-io tcp-nodelay
topology ifconfig-nowarn mute-replay-warnings replay-window single-session
tls-timeout ca cert key tls-auth tls-crypt tls-crypt-v2 extra-certs dh crl-verify
auth-user-pass""".split())
# These non-executing controls are removed, never passed to the plugin. Hooks,
# includes, env setters and arbitrary plugins instead fail the bundle outright.
STRIP = set("""redirect-gateway redirect-private dhcp-option script-security dev
dev-type dev-node daemon syslog verb mute status status-version route-nopull
route-noexec pull-filter pull disable-dco""".split())


class BundleError(Exception):
    """All diagnostics are intentionally fixed and non-sensitive."""


def reject():
    raise BundleError("live upstream bundle rejected; check supported inputs and profile") from None


def tokens(line):
    """Match the plugin's OpenVPN quote/escape/comment parser, not shell syntax."""
    result, word, quote = [], [], None
    active = False
    i = 0
    while i < len(line):
        ch = line[i]
        if ch == "\\" and quote != "'":
            i += 1
            if i == len(line) or line[i] not in '\\" \t':
                reject()
            word.append(line[i])
            active = True
        elif quote:
            if ch == quote:
                quote = None
            else:
                word.append(ch)
        elif ch in "\"'":
            quote, active = ch, True
        elif ch in " \t":
            if active:
                result.append("".join(word))
                word, active = [], False
        elif ch in "#;" and not active:
            break
        else:
            if ord(ch) < 32 or ord(ch) == 127:
                reject()
            word.append(ch)
            active = True
        i += 1
    if quote:
        reject()
    if active:
        result.append("".join(word))
    return result


def quoted(value):
    return '"' + value.replace("\\", "\\\\").replace('"', '\\"') + '"'


def safe_reference(value):
    # References are syntax only: explicit env-selected files are the ONLY
    # sources opened. Even a harmless profile reference never triggers IO.
    return (value and not value.startswith("/") and not any(c in value for c in "\\:")
            and all(part not in ("", "..") for part in value.split("/"))
            and value != ".")


def normalize(raw, supplied):
    if len(raw) > MAX_BYTES or b"\0" in raw:
        reject()
    try:
        text = raw.decode("utf-8")
    except UnicodeError:
        reject()
    if any(ord(ch) < 32 and ch not in "\n\r\t" for ch in text):
        reject()
    lines, block, block_tags, referenced, inline_refs = [], None, set(), set(), set()
    auth = False
    for line in text.split("\n"):
        line = line.removesuffix("\r")
        if block:
            if line.strip() == f"</{block}>":
                lines.append(f"</{block}>")
                block = None
            elif line.lstrip().startswith("<"):
                reject()
            else:
                lines.append(line)
            continue
        args = tokens(line)
        if not args:
            continue
        name = args[0].removeprefix("--")
        if name.startswith("<"):
            tag = name[1:-1]
            if len(args) != 1 or not name.endswith(">") or tag not in INLINE:
                reject()
            if (tag in block_tags or (tag in FILE_OPTIONS and FILE_OPTIONS[tag] in supplied)
                    or (tag in referenced and tag not in inline_refs)):
                reject()
            block_tags.add(tag)
            block = tag
            lines.append(f"<{tag}>")
            continue
        if name in STRIP or name.startswith("route") or name.startswith("log") or name.startswith("management"):
            continue
        if name not in ALLOWED:
            reject()
        if name == "auth-user-pass":
            if len(args) > 2 or "auth.txt" not in supplied or auth:
                reject()
            if len(args) == 2 and not safe_reference(args[1]):
                reject()
            auth = True
            continue
        if name in FILE_OPTIONS:
            if len(args) != 2 or name in referenced:
                reject()
            if args[1] == "[inline]":
                if FILE_OPTIONS[name] in supplied:
                    reject()
                inline_refs.add(name)
                referenced.add(name)
            else:
                if not safe_reference(args[1]) or FILE_OPTIONS[name] not in supplied or name in block_tags:
                    reject()
                args[1] = FILE_OPTIONS[name]
                referenced.add(name)
        elif name in INLINE or name == "crl-verify":
            if len(args) not in (2, 3) or (len(args) == 3 and (name != "tls-auth" or args[2] not in ("0", "1"))):
                reject()
            if args[1] == "[inline]" and name in INLINE:
                inline_refs.add(name)
                referenced.add(name)
            elif name != "dh" or args[1] != "none":
                reject()
        lines.append(" ".join([name] + [quoted(arg) for arg in args[1:]]))
    if block:
        reject()
    # [inline] must actually have its corresponding block, and a supplied file
    # must not conflict with inline data. No ambiguity or duplicate directives.
    if not inline_refs.issubset(block_tags):
        reject()
    for name, filename in FILE_OPTIONS.items():
        if filename in supplied and name not in referenced:
            lines.append(f"{name} {quoted(filename)}")
    if auth or "auth.txt" in supplied:
        lines.append("auth-user-pass auth.txt")
    output = ("\n".join(lines) + "\n").encode("utf-8")
    if len(output) > MAX_BYTES:
        reject()
    return output


def read_input(value, root, private):
    path = Path(value)
    resolved = path.resolve(strict=True)
    if (not path.is_absolute() or resolved == root or root in resolved.parents
            or resolved == private or private in resolved.parents):
        reject()
    # Open once, non-blocking to reject FIFOs without hanging; bound the bytes
    # from this same FD. fstat rejects devices/directories, symlink targets must
    # match the previously resolved regular source (operator inputs immutable).
    expected = resolved.stat()
    fd = os.open(resolved, os.O_RDONLY | os.O_NONBLOCK | os.O_NOFOLLOW)
    with os.fdopen(fd, "rb") as source:
        observed = os.fstat(source.fileno())
        if ((observed.st_dev, observed.st_ino) != (expected.st_dev, expected.st_ino)
                or not stat.S_ISREG(observed.st_mode)):
            reject()
        data = source.read(MAX_BYTES + 1)
    if not data or len(data) > MAX_BYTES:
        reject()
    return data


def stage(root, private, env):
    """Returns a private bundle path; removes every staged file on failure."""
    if Path(private).is_symlink():
        reject()
    root, private = Path(root).resolve(strict=True), Path(private).resolve(strict=True)
    if private == root or root in private.parents or private in root.parents:
        reject()
    if not private.is_dir() or stat.S_IMODE(private.stat().st_mode) != 0o700:
        reject()
    bundle = private / "upstream"
    created = False
    try:
        country = env.get("RATATOSKR_E2E_EXPECT_COUNTRY", "")
        if country and (len(country) != 2 or not country.isascii() or not country.isalpha() or not country.isupper()):
            reject()
        profile = read_input(env.get("RATATOSKR_E2E_OVPN", ""), root, private)
        supplied = {}
        for name, filename in ENV_FILES.items():
            if env.get(name):
                supplied[filename] = read_input(env[name], root, private)
        normalized = normalize(profile, supplied)
        bundle.mkdir(mode=0o700)
        created = True
        for filename, data in {"client.ovpn": normalized, **supplied}.items():
            fd = os.open(bundle / filename, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
            with os.fdopen(fd, "wb") as target:
                target.write(data)
        return bundle
    except (OSError, ValueError, BundleError):
        if created:
            try:
                shutil.rmtree(bundle)
            except OSError:
                raise BundleError("live upstream bundle cleanup failed; remove private staging directory") from None
        reject()


def main():
    try:
        if len(sys.argv) != 3:
            reject()
        stage(sys.argv[1], sys.argv[2], os.environ)
    except (OSError, ValueError, BundleError):
        print("live upstream bundle failed; check inputs and remove private staging on cleanup failure", file=sys.stderr)
        return 2
    return 0


if __name__ == "__main__":
    sys.exit(main())
