# OpenVPN upstream (M1)

Linux-only, standard-library Go supervisor plus OpenVPN 2.6+ runtime image.
This directory is standalone: it does not use or modify the shared component
commands, Go dependencies, Makefile or gateway datapath.

## Pod contract

Run in the **gateway pod's shared network namespace**, as UID 0 with
`NET_ADMIN` and `MKNOD`; do not use privileged mode. Mount the upstream Secret
read-only at `/etc/ratatoskr/upstream`, and an ephemeral, private writable
`emptyDir` at `/run/ratatoskr` (mode 0700). With `readOnlyRootFilesystem`, also
provide a writable `/dev/net` when using the default mknod path. Do not mount
host networking or host root paths.

- `client.ovpn` is required. `auth.txt` is optional. Referenced CA/cert/key and
  TLS-auth files must be in the same mount. No example credentials or real VPN
  configuration is included here.
- OpenVPN creates the L3 TUN interface `upstream0`. The plugin never installs a
  default route, changes policy rules or rewrites `/etc/resolv.conf`.
- Configured routes are stripped, pushed routes/DNS are disabled, and route
  execution is disabled. OpenVPN still configures the interface's address/MTU
  and kernel-connected routes inherent in assigning an address. Static provider
  `ifconfig` directives are rejected (a subnet /0 could create a main default);
  server-pushed interface addressing remains OpenVPN-managed and must be sane.
- The **gateway** owns table 100 and its default through `upstream0`. Probe
  sockets use both `SO_BINDTODEVICE=upstream0` and `SO_MARK=0x00100000`.
  The gateway must install a rule matching mark `0x00100000/0x00f00000` into
  table **100**; the constants are `ProbeMark`, `ProbeMarkMask` and
  `ProbeRoutingTable` in `runtime_linux.go`. Binding a socket alone is not a
  replacement for this rule while the pod main default remains on eth0.
- Keep that route/rule usable while unhealthy. Gate steered **FORWARD** traffic
  with the gateway kill switch, not the plugin's locally originated recovery
  probes. Otherwise recovery deadlocks. Missing binding, mark permission or
  policy routing fails the probe closed; there is no unbound fallback.
- `GET /healthz` and `GET /info` listen exclusively on **127.0.0.1:9901**.
  Kubernetes probes from outside the pod cannot directly address this listener;
  the gateway consumes it in the shared netns.

ADR-0007 requires creation of `/dev/net/tun` (character device 10:200) if absent.
The implementation verifies the device number and attempts an O_RDWR open
before starting. It leaves existing hostPath permissions unchanged. This needs
CAP_MKNOD for creation plus runtime device-cgroup permission; creating the node
alone does not prove it is usable. If the runtime denies access, the process
fails rather than changing the privilege model. Use the chart's
`gateway.tunDevice: hostPath` fallback as appropriate. Runtime/container
capability verification is separate from these unit tests and is coordinated
by the parent; full e2e is deferred to the final project gate.

## Start and probe endpoint

Build from the repository root:

```sh
go test ./plugins/upstream/openvpn/...
go build -o /tmp/openvpn-upstream ./plugins/upstream/openvpn/cmd/openvpn
docker build -f plugins/upstream/openvpn/Dockerfile -t ratatoskr-openvpn:local .
```

Entrypoint flags (directory paths must be absolute):

```text
--secret-dir /etc/ratatoskr/upstream
--runtime-dir /run/ratatoskr
--probe-url https://<literal-IPv4>/exit
```

`--probe-url` is required: provision an operator-controlled endpoint returning a
plain-text exit IPv4 address (at most 64 bytes) with HTTP 200. HTTP is supported,
but HTTPS is recommended to authenticate the responder; a literal IPv4 HTTPS
endpoint needs a certificate with that IP SAN. No environment proxy, redirects,
keepalive connection reuse or DNS lookup is used by the probe. This avoids
leaking probe DNS traffic over eth0. Endpoint credentials are not supported;
prefer a public/no-auth IP reporting endpoint. Do not put tokens in URLs or
command-line flags. OpenVPN's own provider hostname resolution can still use
existing pod DNS; the plugin never modifies it.

`/healthz` returns 200 only while the child is running and an up-interface,
marked/bound exit-IP probe succeeded within 20 seconds. Before the first
success, on any failed probe, child exit or stale success it returns 503.
`/info` always returns JSON with `exitIP`, `mtu`, `handshakeAge`, `details`;
exitIP/MTU are cleared when unhealthy. `handshakeAge` is **null**, explicitly
unavailable: no management channel is opened, and a probe timestamp is not
misrepresented as a TLS handshake timestamp. Health is cached between probes.

Default supervision: probe immediately and every 10s (5s timeout); restart after
60s continuous failure, including startup. Allow a probe timeout and scheduling
interval beyond the failure threshold. Restart delay is 1s, 2s, 4s, ... capped
at 30s, reset only after 60s sustained health. Start failures and unexpected
exits also back off. On shutdown/restart, signal the isolated process group
SIGTERM, wait up to 5s, then SIGKILL and wait at most another 1s for reaping.
Never start a replacement before the old child is reaped; inability to reap is
fatal. Cancellation interrupts probing/backoff. Injected starters/probes must
honor context cancellation. No real process or external network is needed for
supervisor tests.

## Sanitization and data handling

The sanitizer uses a positive transport/TLS option allowlist and canonical
quoted output, rather than passing unrecognized options to OpenVPN. It strips
redirect/DNS/route directives, all script hooks covered by the design,
script-security, interface/daemon/log/status/management/plugin controls, and
provider pull filters. Unknown directives are rejected, including script hooks
not on the strip list, config includes, `cd`, `chroot`, environment setters,
engines, PKCS#11 providers, server mode and alternate executables. Broad
allowlist extensions require a security review.

The forced argv controls are appended after the sanitized configuration:

```text
--dev upstream0 --dev-type tun --route-nopull --route-noexec
--pull-filter ignore redirect-gateway --pull-filter ignore dhcp-option
--script-security 1 --disable-dco --auth-nocache --verb 0
```

Inline `ca`, `cert`, `key`, `tls-auth`, `tls-crypt`, `tls-crypt-v2`, `extra-certs`
and `dh` blocks are preserved, without interpreting their payload as options.
Relative file references (including quoted names) are retained; absolute paths,
backslashes, drive prefixes, traversal and includes are rejected. Referenced
files and the input config must resolve inside the mount and be regular files.
Kubernetes projected-Secret symlinks resolving **inside** the mount work.
References are validated before every start. Use an immutable/read-only Secret
for each child lifetime: validation cannot eliminate a malicious concurrent
symlink/file replacement TOCTOU race. Replace/roll the pod to rotate configs.

`auth-user-pass` is rewritten to `auth.txt`; if that optional file exists it is
added even without a provider directive. A directive requiring auth without
that file is rejected; the supervisor never prompts. Inline credentials and
provider-specified credential paths are not accepted. Inputs are limited to
1 MiB and parser errors are fixed strings without input or filenames.

Provider profiles using `<connection>` blocks, compression, PKCS#12, interactive
key passwords, proxy credentials, static `ifconfig`/`ifconfig-ipv6`, scripts or unknown options are deliberately
unsupported. Adapt only non-secret directives outside this repository; do not
copy provider profiles or credentials into issues, test fixtures or commits.

The sanitized config is a private **0600 runtime-only temporary file** because
OpenVPN must read inline material. It is removed on launch failure/child exit.
No material is copied into the repository; all OpenVPN stdout/stderr and
inherited environment are discarded. The entrypoint emits only a fixed generic
failure message, never flag values, URLs, process output or parser input. No
health payload contains provider credentials, raw config or remote addresses.
Docker copies only this plugin and go.mod into its build stage, not Secret data.
Never use this source directory as the Secret mount/runtime directory.

## Verification scope and primary references

Unit tests use synthetic placeholders, temporary directories, fake processes,
fake HTTP transports and fake socket controls. They cover deterministic parsing,
inline blocks, traversal/symlinks, forced argv, health freshness, failure and
exit invalidation, timeout/cancellation, capped/resetting backoff, and refusal to
overlap an unreaped process. They do **not** verify a real VPN, actual TUN device
policy, gateway policy routing or default-route/DNS preservation in a cluster.
No e2e or real-secret tests belong to M1's local unit gate.

Primary behavior references consulted:

- OpenVPN's official 2.6 manual (`build.openvpn.net/man/openvpn-2.6/openvpn.8.html`):
  configuration quoting/inline files, route-nopull, route-noexec, pull-filter,
  script-security and disable-dco.
- Linux man-pages `socket(7)` (`man7.org/linux/man-pages/man7/socket.7.html`):
  SO_BINDTODEVICE and SO_MARK; marking requires NET_ADMIN (or NET_RAW on newer
  kernels), which is already part of this upstream's pod contract.
- Repository `docs/design.md` §6 and `docs/adr/0007-tun-device-access.md`.
