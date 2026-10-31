#!/usr/bin/env python3
"""Explicitly gated disposable WireGuard/agent synthetic integration fixture.

No cluster access on import/default invocation. A positive observation is a
partial encrypted startup and peer lifecycle, NOT M8 PASS: plaintext packet
injection and independent TokenReview attestation remain separate gates.
Never print raw API responses, Secret manifests, credentials or profiles.
"""
import argparse
import hashlib
import ipaddress
import json
import os
import re
import signal
import subprocess
import sys
import time
from pathlib import Path

HERE = Path(__file__).resolve().parents[1] / "matrix" / "synthetic"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import adapter  # noqa: E402 - existing bounded/allowlisted kubectl transport
import lifecycle  # noqa: E402
import node_images  # noqa: E402
import partial_gateway  # noqa: E402
import prepare  # noqa: E402
import run  # noqa: E402

SYSTEM = "ratatoskr-system"
OWN = lifecycle.LABEL
PREFIX = "ratatoskr.skaldhall.io/"
HEX64 = re.compile(r"[0-9a-f]{64}\Z")
SERVER = "synthetic-vpn"
CLIENT = "synthetic-client"


class Blocked(lifecycle.LifecycleError):
    """Only fixed diagnostics; never include raw Kubernetes or key material."""


# Only these authored, non-secret checkpoints may cross cleanup and reach CLI.
CHECKPOINTS = frozenset({"namespace-create", "private-pki", "fixture-adapter",
    "fixture-manifests", "source-create", "operator-secret-create",
    "operator-gateway-create", "source-ready", "gateway-owned",
    "peer-baseline", "peer-registration", "peer-revocation",
    "peer-lifecycle", "cleanup-unverified"})


class StageBlocked(Blocked):
    """Fixed checkpoint only; never wrap raw API output, profile or exception."""
    def __init__(self, checkpoint):
        if checkpoint not in CHECKPOINTS:
            raise Blocked("WireGuard checkpoint classification invalid.")
        super().__init__("WireGuard synthetic fixture blocked at " + checkpoint + ".")


def need(condition, message):
    if not condition:
        raise Blocked(message)


def ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
        need(ip.version == 4 and not (ip.is_unspecified or ip.is_loopback or ip.is_multicast),
             "WireGuard PodIP invalid.")
        return str(ip)
    except (ValueError, TypeError):
        raise Blocked("WireGuard PodIP invalid.") from None


def created_identity(raw, kind, namespace, name):
    """Only five server-returned fields may cross a Kubernetes CREATE pipe."""
    try:
        fields = raw.decode("ascii").rstrip("\n").split("\t")
        need(fields[:4] == ["v1" if kind in ("Pod", "Secret") else
                            "ratatoskr.skaldhall.io/v1alpha1", kind, namespace, name]
             and len(fields) == 5 and lifecycle.UID.fullmatch(fields[4]),
             "Operator fixture CREATE UID or identity missing.")
        return fields[4]
    except (UnicodeError, AttributeError):
        raise Blocked("Operator fixture CREATE identity malformed.") from None


class OperatorFixture:
    """Unique operator-namespace Gateway+Secret, exact UID precondition cleanup.

    No write operation targets a release resource. An ambiguous CREATE cannot
    authorize name-only deletion: it requires private orphan remediation.
    """
    def __init__(self, owner, transport=adapter._bounded):
        need(isinstance(owner, lifecycle.Lifecycle) and owner.deadline is not None and
             not owner.closed and owner.names[0] in owner.owned,
             "Owned namespace Lifecycle required before operator fixture.")
        self.owner, self.transport = owner, transport
        self.name = "rtk-wg-" + owner.token[:16]
        self.created = {}
        self.attempted = set()
        self.deleted_selected_uid = None

    def _call(self, args, *, payload=None, output=2048):
        remaining = min(10, getattr(self, "cleanup_deadline", self.owner.deadline) - self.owner.clock())
        need(remaining > 0, "WireGuard fixture deadline expired.")
        try:
            response = self.transport(["kubectl", "--context", lifecycle.CONTEXT,
                                       "--request-timeout=10s", *args], payload=payload,
                                      timeout=remaining, max_output=output)
            need(isinstance(response, bytes) and len(response) <= output,
                 "WireGuard fixture output bound or type violated.")
            return response
        except (adapter.AdapterError, OSError, ValueError):
            raise Blocked("WireGuard fixture Kubernetes operation failed.") from None

    def get_object(self, kind, name, namespace, *, output=32768):
        """Bounded allowlisted read of public metadata/status, never Secrets."""
        need(kind in ("egressgateway", "deployment", "replicaset", "pod", "configmap", "service")
             and namespace in (SYSTEM, *self.owner.names) and
             isinstance(name, str) and re.fullmatch(r"[a-z0-9][-a-z0-9]{0,62}", name),
             "Public WG fixture GET target not allowlisted.")
        if kind in ("egressgateway", "deployment", "configmap", "service"):
            need(name == self.name, "Operator resource name differs from owned Gateway.")
        if namespace == self.owner.names[1]:
            need(kind == "pod" and name == CLIENT,
                 "Owned apps GET must target only selected workload.")
        if namespace == self.owner.names[0]:
            need((kind, name) in {("pod", SERVER), ("service", SERVER)},
                 "Owned source GET target differs from fixture.")
        if kind == "pod" and namespace == SYSTEM:
            need(name.startswith(self.name + "-") and name != CLIENT,
                 "Operator Gateway Pod name differs from owned Deployment.")
        if kind == "replicaset":
            need(namespace == SYSTEM and name.startswith(self.name + "-"),
                 "Operator ReplicaSet name differs from owned Deployment.")
        raw = self._call(["get", kind, name, "-n", namespace, "-o", "json"], output=output)
        try:
            obj = json.loads(raw)
            meta = obj["metadata"]
            need(meta.get("namespace") == namespace and meta.get("name") == name and
                 lifecycle.UID.fullmatch(meta.get("uid", "")) and not meta.get("deletionTimestamp"),
                 "Public WG fixture GET identity invalid.")
            return obj
        except (KeyError, TypeError, ValueError, AttributeError):
            raise Blocked("Public WG fixture GET malformed.") from None

    def _identity(self, kind):
        name = self.name if kind == "EgressGateway" else self.name + "-upstream"
        path = ("/apis/ratatoskr.skaldhall.io/v1alpha1" if kind == "EgressGateway" else
                "/api/v1") + "/namespaces/" + SYSTEM + "/" + (
                    "egressgateways" if kind == "EgressGateway" else "secrets") + "/" + name
        return name, path

    def _get(self, kind, *, allow_terminating=False):
        name, _path = self._identity(kind)
        # A fixed JSONPath returns ONLY public identity fields; no Secret.data
        # enters subprocess stdout. Ownership also requires the unique label.
        template = ('jsonpath={.metadata.name}{"\\t"}{.metadata.uid}{"\\t"}'
                    '{.metadata.labels.ratatoskr\\.skaldhall\\.io/synthetic-lifecycle}'
                    '{"\\t"}{.metadata.deletionTimestamp}')
        raw = self._call(["get", kind.lower(), name, "-n", SYSTEM,
                          "--ignore-not-found", "-o", template], output=256)
        if not raw.strip():
            return None
        try:
            fields = raw.decode("ascii").rstrip("\n").split("\t")
            need(len(fields) == 4 and fields[0] == name and
                 lifecycle.UID.fullmatch(fields[1]) and fields[2] == self.owner.token and
                 (allow_terminating or fields[3] == ""),
                 "Operator fixture resource identity changed.")
            return fields[1]
        except (UnicodeError, AttributeError):
            raise Blocked("Operator fixture metadata unavailable.") from None

    def create(self, kind, payload):
        need(kind in ("Secret", "EgressGateway") and kind not in self.attempted,
             "Operator fixture CREATE attempted twice or kind unsupported.")
        name, _ = self._identity(kind)
        need(self._get(kind) is None, "Operator fixture name already exists; no adoption.")
        meta = payload.get("metadata", {})
        need(payload.get("kind") == kind and meta.get("name") == name and
             meta.get("namespace") == SYSTEM and meta.get("labels") == {OWN: self.owner.token},
             "Operator fixture manifest ownership invalid.")
        self.attempted.add(kind)
        raw = self._call(["create", "-f", "-", "-o", adapter.CREATE_IDENTITY],
                         payload=json.dumps(payload, separators=(",", ":"), allow_nan=False).encode(),
                         output=256)
        uid = created_identity(raw, kind, SYSTEM, name)
        need(self._get(kind) == uid, "Operator fixture CREATE recheck changed UID.")
        self.created[kind] = uid
        return uid

    def get_selected_uid(self):
        """Bounded metadata-only Pod GET with explicit absent result and no logs."""
        apps = self.owner.names[1]
        need(apps in self.owner.owned, "Selected workload namespace not owned.")
        template = 'jsonpath={.metadata.name}{"\\t"}{.metadata.uid}{"\\t"}{.metadata.labels.ratatoskr\\.skaldhall\\.io/synthetic-lifecycle}'
        raw = self._call(["get", "pod", CLIENT, "-n", apps, "--ignore-not-found",
                          "-o", template], output=256)
        if not raw.strip():
            return None
        try:
            name, uid, token = raw.decode("ascii").rstrip("\n").split("\t")
            need(name == CLIENT and lifecycle.UID.fullmatch(uid) and token == self.owner.token,
                 "Selected workload metadata UID or owner label changed.")
            return uid
        except (UnicodeError, ValueError, AttributeError):
            raise Blocked("Selected workload metadata response malformed.") from None

    def create_selected(self, source_api, payload):
        """Only one approved long-lived workload; server-returned UID is pinned."""
        apps = self.owner.names[1]
        try:
            api_ip = payload["spec"]["containers"][0]["env"][1]["value"]
            need(payload == selected_pod(self.owner, self.name, api_ip) and
                 source_api._namespace(apps) == apps,
                 "Selected encrypted workload manifest/namespace invalid.")
            need(self.get_selected_uid() is None and "Pod" not in self.attempted,
                 "Selected workload preexists or CREATE retried.")
        except (KeyError, IndexError, TypeError, AttributeError, adapter.AdapterError):
            raise Blocked("Selected encrypted workload preflight failed.") from None
        self.attempted.add("Pod")
        self.deleted_selected_uid = None
        raw = self._call(["create", "-f", "-", "-o", adapter.CREATE_IDENTITY],
                         payload=json.dumps(payload, separators=(",", ":"), allow_nan=False).encode(),
                         output=256)
        uid = created_identity(raw, "Pod", apps, CLIENT)
        try:
            need(self.get_selected_uid() == uid,
                 "Selected workload UID changed on CREATE recheck.")
        except (KeyError, TypeError, AttributeError, adapter.AdapterError):
            raise Blocked("Selected workload UID recheck unavailable.") from None
        self.created["Pod"] = uid
        return uid

    def delete_selected(self, source_api):
        """Revoke only our exact Pod UID; never delete a replacement by name."""
        if "Pod" not in self.attempted:
            return
        apps = self.owner.names[1]
        uid = self.created.get("Pod")
        need(uid is not None and lifecycle.UID.fullmatch(uid),
             "Selected workload CREATE UID ambiguous; no name-only deletion.")
        observed = self.get_selected_uid()
        if observed is None:
            # A previously verified CREATE (or already confirmed first DELETE)
            # may have been removed before cleanup. Absence is success only
            # with the exact server-returned UID already recorded; an ambiguous
            # POST has no such UID and remains a hard cleanup failure.
            self.deleted_selected_uid = uid
            return
        need(observed == uid and self.deleted_selected_uid is None,
             "Selected workload UID changed or reappeared after deletion.")
        options = {"apiVersion": "v1", "kind": "DeleteOptions",
                   "preconditions": {"uid": uid}, "propagationPolicy": "Foreground"}
        self._call(["delete", "--raw=/api/v1/namespaces/" + apps + "/pods/" + CLIENT,
                    "-f", "-"], payload=json.dumps(options).encode(), output=1024)
        end = min(getattr(self, "cleanup_deadline", self.owner.deadline), self.owner.clock() + 25)
        while self.owner.clock() < end:
            try:
                observed = self.get_selected_uid()
                if observed is None:
                    self.deleted_selected_uid = uid
                    return
                need(observed == uid, "Selected workload replacement UID appeared during cleanup.")
            except (adapter.AdapterError, Blocked):
                raise Blocked("Selected workload UID cleanup GET failed.") from None
            time.sleep(1)
        raise Blocked("Selected workload UID-conditional deletion unverified.")

    def cleanup(self):
        # Cleanup gets its own bounded grace after body deadline, just as the
        # namespace Lifecycle does. A timed-out create remains ambiguous.
        self.cleanup_deadline = self.owner.clock() + 65
        failures = []
        for kind in ("EgressGateway", "Secret"):
            if kind not in self.attempted:
                continue
            try:
                uid = self.created.get(kind)
                need(uid is not None and self._get(kind, allow_terminating=True) == uid,
                     "Ambiguous operator fixture CREATE; manual orphan inspection required.")
                _name, path = self._identity(kind)
                options = {"apiVersion": "v1", "kind": "DeleteOptions",
                           "preconditions": {"uid": uid}, "propagationPolicy": "Foreground"}
                self._call(["delete", "--raw=" + path, "-f", "-"],
                           payload=json.dumps(options).encode(), output=1024)
                end = self.owner.clock() + 25
                while self.owner.clock() < end:
                    if self._get(kind, allow_terminating=True) is None:
                        break
                    time.sleep(1)
                else:
                    raise Blocked("Owned operator resource cleanup unverified.")
            except (Blocked, adapter.AdapterError, lifecycle.LifecycleError):
                failures.append(kind)
        if failures:
            raise Blocked("Owned operator Gateway/Secret cleanup unverified; manual inspection required.")


def manifests(owner, private):
    """Reuse private synthetic OpenVPN server/PKI; Gateway alone lives in SYSTEM."""
    contents = partial_gateway.private_contents(private)
    source = prepare.manifests(owner.names[0], "ratatoskr-synthetic-openvpn:local",
                               contents, owner.token)
    base = [(x["kind"], x["metadata"].get("name")) for x in source]
    expected = [("Namespace", owner.names[0]), ("Namespace", owner.names[1]),
                ("Secret", "synthetic-server"), ("Secret", "synthetic-client"),
                ("Secret", "synthetic-witness"), ("ConfigMap", "synthetic-exit-health"),
                ("Pod", "synthetic-vpn"), ("Pod", "synthetic-witness"),
                ("Service", "synthetic-vpn"), ("EgressGateway", "synthetic"),
                ("EgressPolicy", "synthetic")]
    need(base == expected, "Synthetic OpenVPN fixture changed unexpectedly.")
    server = [x for x in source if (x["kind"], x["metadata"].get("name")) in
              {("Secret", "synthetic-server"), ("ConfigMap", "synthetic-exit-health"),
               ("Pod", SERVER), ("Service", SERVER)}]
    ca, _server_cert, _server_key, client_cert, client_key, _witness_cert, _witness_key = contents
    remote = f"synthetic-vpn.{owner.names[0]}.svc.cluster.local"
    secret = prepare.secret(SYSTEM, "rtk-wg-" + owner.token[:16] + "-upstream",
                            {"client.ovpn": prepare.client_config(remote, ca, client_cert, client_key)})
    secret["metadata"]["labels"] = {OWN: owner.token}
    gateway = {"apiVersion": "ratatoskr.skaldhall.io/v1alpha1", "kind": "EgressGateway",
               "metadata": {"name": "rtk-wg-" + owner.token[:16], "namespace": SYSTEM,
                            "labels": {OWN: owner.token}},
               "spec": {"replicas": 1, "encryption": "wireguard", "failMode": "closed",
                        "dns": {"mode": "cluster"}, "upstream": {"type": "openvpn",
                        "secretRef": {"name": secret["metadata"]["name"]}},
                        "allowedNamespaces": {"namespaceSelector": {
                            "matchLabels": {"ratatoskr-synthetic": owner.names[0]}}}}}
    server.sort(key=lambda obj: {("Secret", "synthetic-server"): 0,
                                 ("ConfigMap", "synthetic-exit-health"): 1,
                                 ("Pod", SERVER): 2,
                                 ("Service", SERVER): 3}[(obj["kind"], obj["metadata"]["name"])])
    return server, secret, gateway


def selected_pod(owner, gateway_name, api_ip):
    ipv4(api_ip)
    workload = prepare.running_probe_pod(owner.names[1], owner.names[0], api_ip)
    workload["metadata"]["labels"][PREFIX + "gateway"] = gateway_name
    workload["metadata"]["labels"][PREFIX + "gateway-namespace"] = SYSTEM
    workload["metadata"]["labels"][OWN] = owner.token
    return workload


def verify_encrypted_ready(gateway, pod, gateway_uid, client_uid, gateway_name):
    """Pure post-creation identity/health assertion, no credential exposure."""
    try:
        meta, status = gateway["metadata"], gateway["status"]
        endpoints = [e for e in status["endpoints"] if e.get("upstreamHealthy") is True]
        need(len(endpoints) == 1 and status.get("readyReplicas") == 1,
             "Encrypted endpoint not unique or healthy.")
        endpoint = endpoints[0]
        client_meta = pod["metadata"]
        raw = client_meta["annotations"][PREFIX + "agent-config"]
        need(isinstance(raw, str) and len(raw) <= 65536 and
             client_meta["annotations"].get(PREFIX + "agent-hash") == hashlib.sha256(raw.encode()).hexdigest(),
             "Selected agent config hash missing or changed.")
        config = json.loads(raw)
        need(meta.get("name") == gateway_name and meta.get("namespace") == SYSTEM and
             meta.get("uid") == gateway_uid and
             status.get("observedGeneration") == meta.get("generation") and
             status.get("gatewayID", 0) > 0 and
             endpoint.get("podUID") and ipv4(endpoint.get("podIP")) and
             HEX64.fullmatch(endpoint.get("appliedClientConfigHash", "")) and
             endpoint.get("wireguardPublicKey") and endpoint.get("registrationCACert") and
             client_meta.get("uid") == client_uid and
             client_meta.get("annotations", {}).get(PREFIX + "datapath-ready") == "true" and
             client_meta.get("annotations", {}).get(PREFIX + "agent-backend") == "iproute" and
             config.get("encryption") == "wireguard" and config.get("endpoint") == endpoint["podIP"] and
             config.get("gatewayID") == status["gatewayID"] and
             config.get("podIP") == pod.get("status", {}).get("podIP") and
             config.get("gatewayPublicKey") == endpoint["wireguardPublicKey"] and
             config.get("registrationCACert") == endpoint["registrationCACert"] and
             config.get("identity", {}).get("namespace") == client_meta.get("namespace") and
             config.get("identity", {}).get("pod") == client_meta.get("name") and
             config.get("identity", {}).get("uid") == client_uid,
             "Encrypted endpoint, Pod identity, or agent readiness unverified.")
        return endpoint["podIP"]
    except (KeyError, TypeError, ValueError, StopIteration):
        raise Blocked("Encrypted endpoint or client config malformed.") from None


def observe(owner, source_api, operator, gateway_uid, workload, ids, *,
            clock=time.monotonic, sleep=time.sleep, metrics_reader=None):
    """Execute bounded positive peer startup+revocation, never plaintext PASS."""
    try:
        from . import wg_transport
    except ImportError:
        import wg_transport
    if metrics_reader is None:
        metrics_reader = wg_transport.read_metrics
    deadline = min(owner.deadline, clock() + 135)
    source_uid = source_api.created[("Pod", owner.names[0], SERVER)]
    need(isinstance(source_uid, str) and lifecycle.UID.fullmatch(source_uid),
         "OpenVPN source CREATE-return UID missing.")
    step = "source-ready"
    gateway_pod = None
    initial = None
    # Verify source Pod/Service endpoint and owned Gateway status first. The
    # gateway's upstream health probe and selected marker independently test
    # VPN reachability; we do not inspect OpenVPN private session contents.
    while clock() < deadline:
        try:
            server = source_api.get("pod", SERVER, owner.names[0])
            service = source_api.get("service", SERVER, owner.names[0])
            need(server["metadata"].get("uid") == source_uid,
                 "OpenVPN source Pod UID changed.")
            partial_gateway.source_ready(server, service, ids["server"])
            source_api.source_endpoint(owner.names[0], service, server)
            step = "gateway-owned"
            gw = operator.get_object("egressgateway", operator.name, SYSTEM)
            need(gw["metadata"].get("uid") == gateway_uid and
                 gw["spec"].get("encryption") == "wireguard" and
                 gw["status"].get("observedGeneration") == gw["metadata"].get("generation") and
                 gw["status"].get("readyReplicas") == 1 and
                 any(c.get("type") == "Ready" and c.get("status") == "True" for c in
                     gw["status"].get("conditions", [])),
                 "Owned encrypted Gateway not Ready.")
            endpoint = [e for e in gw["status"].get("endpoints", [])
                        if e.get("upstreamHealthy") is True]
            need(len(endpoint) == 1, "Encrypted Gateway has no unique healthy endpoint.")
            endpoint = endpoint[0]
            endpoint_ip = ipv4(endpoint["podIP"])
            need(lifecycle.UID.fullmatch(endpoint.get("podUID", "")) and
                 re.fullmatch(r"[A-Za-z0-9+/]{43}=", endpoint.get("wireguardPublicKey", "")) and
                 endpoint.get("registrationCACert", "").startswith("-----BEGIN CERTIFICATE-----") and
                 HEX64.fullmatch(endpoint.get("appliedClientConfigHash", "")),
                 "Gateway public identity or applied config ack missing.")
            deployment = operator.get_object("deployment", operator.name, SYSTEM)
            need(any(ref.get("kind") == "EgressGateway" and ref.get("uid") == gateway_uid and
                     ref.get("controller") is True for ref in
                     deployment["metadata"].get("ownerReferences", [])),
                 "Encrypted Gateway Deployment not UID-owned.")
            gateway_pod = operator.get_object("pod", endpoint["podName"], SYSTEM)
            need(gateway_pod["metadata"].get("uid") == endpoint["podUID"] and
                 gateway_pod["status"].get("podIP") == endpoint_ip and
                 gateway_pod["metadata"].get("labels", {}).get(PREFIX + "gateway-uid") == gateway_uid,
                 "Gateway Pod identity mismatch.")
            rsref = next((ref for ref in gateway_pod["metadata"].get("ownerReferences", [])
                          if ref.get("kind") == "ReplicaSet" and ref.get("controller") is True), None)
            need(rsref is not None and lifecycle.UID.fullmatch(rsref.get("uid", "")),
                 "Gateway Pod ReplicaSet owner missing.")
            replica = operator.get_object("replicaset", rsref["name"], SYSTEM)
            need(replica["metadata"]["uid"] == rsref["uid"] and any(
                ref.get("kind") == "Deployment" and ref.get("uid") == deployment["metadata"]["uid"] and
                ref.get("controller") is True for ref in replica["metadata"].get("ownerReferences", [])),
                "Gateway ReplicaSet/Deployment UID chain invalid.")
            step = "peer-baseline"
            initial = metrics_reader(operator, gateway_pod, ids["gateway"])
            need(initial.get("sample_ok") == 1 and initial.get("installed_peers") == 0,
                 "Unexpected preexisting kernel WG peer in new Gateway.")
            break
        except (Blocked, adapter.AdapterError, partial_gateway.Blocked, KeyError,
                TypeError, ValueError, AttributeError):
            sleep(min(2, max(0, deadline - clock())))
    else:
        raise StageBlocked(step)

    step = "peer-registration"
    try:
        client_uid = operator.create_selected(source_api, workload)
    except (KeyboardInterrupt, SystemExit, lifecycle.Interrupted):
        raise
    except BaseException:
        raise StageBlocked(step) from None
    while clock() < deadline:
        try:
            pod = source_api.get("pod", CLIENT, owner.names[1])
            need(pod["metadata"].get("uid") == client_uid and
                 pod["status"].get("phase") == "Running" and
                 pod["metadata"].get("labels", {}).get(OWN) == owner.token,
                 "Selected encrypted workload UID/state changed.")
            chosen = verify_encrypted_ready(operator.get_object("egressgateway", operator.name, SYSTEM),
                                            pod, gateway_uid, client_uid, operator.name)
            need(chosen == endpoint_ip, "Selected encrypted Pod chose a different gateway.")
            running = pod["status"].get("containerStatuses", [])
            need(len([c for c in running if c.get("name") == "client" and
                      c.get("ready") is True and c.get("imageID") == ids["selected"]]) == 1,
                 "Selected restricted client runtime image unverified.")
            need(source_api.probe_running(CLIENT, client_uid, ids["selected"],
                                          "healthy", workload["spec"]["containers"][0]["env"][1]["value"]) is True,
                 "Encrypted selected marker not delivered.")
            measured = metrics_reader(operator, gateway_pod, ids["gateway"])
            need(measured.get("sample_ok") == 1 and
                 measured.get("installed_peers") == 1 and
                 measured.get("handshaken_peers", 0) >= 1 and
                 measured.get("receive_bytes", 0) > initial["receive_bytes"] and
                 measured.get("transmit_bytes", 0) > initial["transmit_bytes"],
                 "Authenticated kernel WireGuard peer/bytes not observed.")
            break
        except (Blocked, adapter.AdapterError, KeyError, TypeError, ValueError, AttributeError):
            sleep(min(2, max(0, deadline - clock())))
    else:
        raise StageBlocked(step)
    step = "peer-revocation"
    try:
        operator.delete_selected(source_api)
    except (KeyboardInterrupt, SystemExit, lifecycle.Interrupted):
        raise
    except BaseException:
        raise StageBlocked(step) from None
    while clock() < deadline:
        try:
            after = metrics_reader(operator, gateway_pod, ids["gateway"])
            need(after.get("sample_ok") == 1 and after.get("installed_peers") == 0,
                 "Selected Pod peer not revoked after UID delete.")
            break
        except (Blocked, adapter.AdapterError, KeyError, TypeError, ValueError, AttributeError):
            sleep(min(2, max(0, deadline - clock())))
    else:
        raise StageBlocked(step)
    return {"encryptedStartup": True, "peerRegistered": True,
            "peerRemoved": True, "plainGeneve": "not-tested",
            "tokenReview": "not-independently-observed"}


def execute(ids, *, owner_factory=lifecycle.Lifecycle, operator_factory=OperatorFixture,
            source_factory=adapter.FixtureAPI, api_ip=None, observer=None):
    """One partial encrypted lifecycle, with sanitized stages AFTER UID cleanup."""
    need(isinstance(ids, dict) and set(ids) == set(run.COMPONENTS) and
         all(isinstance(x, str) and run.ID_PATTERN.fullmatch(x) for x in ids.values()),
         "Immutable runtime image IDs required.")
    need(api_ip is not None, "Preflight Kubernetes Service IP required.")
    ipv4(api_ip)
    with owner_factory() as owner:
        stage = "namespace-create"
        operator = None
        source_api = None
        failure = None
        cleanup_failure = False
        result = None
        try:
            owner.create_namespaces()
            stage = "private-pki"
            owner.generate_pki()
            stage = "fixture-adapter"
            operator = operator_factory(owner)
            source_api = source_factory(owner)
            stage = "fixture-manifests"
            server, secret, gateway = manifests(owner, owner.private_dir)
            stage = "source-create"
            created = {(obj["kind"], obj["metadata"]["name"]): source_api.create(obj) for obj in server}
            need(set(created) == {("Secret", "synthetic-server"),
                                  ("ConfigMap", "synthetic-exit-health"),
                                  ("Pod", SERVER), ("Service", SERVER)} and
                 all(isinstance(x, dict) and x.get("namespace") == owner.names[0] and
                     x.get("kind") == kind and x.get("name") == name and
                     lifecycle.UID.fullmatch(x.get("uid", ""))
                     for (kind, name), x in created.items()),
                 "OpenVPN source resource identities missing.")
            stage = "operator-secret-create"
            operator.create("Secret", secret)
            stage = "operator-gateway-create"
            gateway_uid = operator.create("EgressGateway", gateway)
            stage = "peer-lifecycle"
            observed = observe if observer is None else observer
            result = observed(owner, source_api, operator, gateway_uid,
                              selected_pod(owner, operator.name, api_ip), ids)
            need(result == {"encryptedStartup": True, "peerRegistered": True,
                            "peerRemoved": True, "plainGeneve": "not-tested",
                            "tokenReview": "not-independently-observed"},
                 "Encrypted peer lifecycle observation incomplete.")
        except (KeyboardInterrupt, SystemExit, lifecycle.Interrupted):
            raise
        except BaseException:
            # Never expose an exception that could contain API JSON, Secret
            # material, kubectl stderr or a profile; only authored stage names.
            failure = StageBlocked(stage)
        finally:
            # Even if observer fails after creating Pod, UID-precondition delete
            # and owner-namespace cleanup must run before surfacing failure.
            if operator is not None:
                try:
                    if source_api is not None and "Pod" in operator.attempted:
                        operator.cleanup_deadline = owner.clock() + 65
                        operator.delete_selected(source_api)
                except BaseException:
                    cleanup_failure = True
                try:
                    operator.cleanup()
                except BaseException:
                    cleanup_failure = True
            if cleanup_failure:
                failure = StageBlocked("cleanup-unverified")
        if failure is not None:
            raise failure
    return False  # Explicitly never full M8 PASS, even after success.


def main(argv=None):
    parser = argparse.ArgumentParser(description="Gated synthetic WireGuard acceptance (partial)")
    parser.add_argument("--execute", action="store_true")
    args = parser.parse_args(argv)
    if not (args.execute and os.environ.get("RATATOSKR_E2E_FINAL_GATE") == "1" and
            os.environ.get("RATATOSKR_E2E_WG_SYNTHETIC") == "1"):
        print("SKIPPED: explicit WireGuard fixture authorization required; no cluster accessed.")
        return 2
    try:
        ids = run.expected_ids(os.environ)
        release_ns = run.preflight(run.ReadOnlyAPI(), ids)
        need(release_ns == SYSTEM, "Expected operator namespace differs; no mutation.")
        node_images.verify({component: ids[component] for component in node_images.TAGS})
        api_ip = partial_gateway.api_service_ip(run.ReadOnlyAPI())
        execute(ids, api_ip=api_ip)
    except StageBlocked as err:
        # StageBlocked messages contain only CHECKPOINTS-authored fixed labels.
        print("FAILED: " + str(err) + " UID-owned cleanup verified or explicitly blocked; no M8 PASS.")
        return 1
    except (Blocked, lifecycle.LifecycleError, adapter.AdapterError, run.Blocked,
            node_images.Blocked, KeyError, ValueError, TypeError, AttributeError):
        print("FAILED: WireGuard synthetic preflight or cleanup blocked; no M8 PASS.")
        return 1
    print("INCOMPLETE: encrypted startup and peer lifecycle observed; plaintext rejection and independent TokenReview unverified; no M8 PASS.")
    return 4


if __name__ == "__main__":
    sys.exit(main())
