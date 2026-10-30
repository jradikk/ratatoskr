#!/usr/bin/env python3
"""Isolated no-PASS, no-resource-mutation synthetic evidence collector.

Caller must supply an already-authorized Lifecycle/FixtureAPI with trusted
fixture Pods. This module has NO CLI, never generates PKI or creates resources,
and cannot certify full e2e. In particular it cannot interrupt or recover the
server and kubectl exec has no atomic Pod UID precondition.
"""
import ipaddress
import json
import re
import time

try:
    from . import adapter, evidence, lifecycle
except ImportError:  # standalone import for local pure unit tests
    import adapter
    import evidence
    import lifecycle


class Incomplete(Exception):
    """Static sanitized evidence gap; never contains live JSON or credentials."""


def _parse_json(raw, *, limit=4096):
    if not isinstance(raw, str) or len(raw) > limit:
        raise Incomplete("Command output exceeds bounded JSON limit.")
    try:
        obj = json.loads(raw)
        if not isinstance(obj, list) or len(obj) != 1 or not isinstance(obj[0], dict):
            raise ValueError()
        return obj[0]
    except (ValueError, TypeError):
        raise Incomplete("Command output does not match single-object JSON.") from None


def _tx_bytes(raw):
    link = _parse_json(raw)
    if link.get("ifname") != "rtk0":
        raise Incomplete("GENEVE egress counter is not from rtk0.")
    try:
        value = link["stats64"]["tx"]["bytes"]
        if type(value) is not int or value < 0:
            raise ValueError()
        return value
    except (KeyError, TypeError, ValueError):
        raise Incomplete("Client GENEVE TX stats64 bytes unavailable.") from None


def _geneve(raw, gateway_id, endpoint):
    link = _parse_json(raw)
    evidence.need(link.get("ifname") == "rtk0" and
                  link.get("linkinfo", {}).get("info_kind") == "geneve" and
                  link.get("operstate") == "UP", "Client GENEVE interface is not up.")
    data = link.get("linkinfo", {}).get("info_data", {})
    # Linux iproute2 `ip -j -d link`: for GENEVE info_data records
    # `id` and `remote`; numeric VNI, literal IPv4 endpoint.
    evidence.need(type(data.get("id")) is int and data["id"] == gateway_id and
                  data.get("remote") == endpoint, "GENEVE remote or VNI mismatch.")
    return link


def _dns(raw, api_ip):
    # getent ahostsv4 returns multiple socket-type lines for the same IP.
    # Any different address implies DNS result poisoning, not success.
    lines = raw.splitlines()
    evidence.need(0 < len(lines) <= 9 and all(len(line) < 200 for line in lines),
                  "DNS answer missing or unexpectedly large.")
    try:
        parsed = [ipaddress.ip_address(line.split()[0]) for line in lines]
        if any(address.version != 4 for address in parsed):
            raise ValueError()
        addresses = {str(address) for address in parsed}
    except (ValueError, IndexError):
        raise Incomplete("DNS answer is not IPv4.") from None
    evidence.need(addresses == {api_ip}, "DNS answer does not match API ClusterIP.")
    return "kubernetes.default.svc.cluster.local"


def _uid(obj):
    uid = obj.get("metadata", {}).get("uid")
    if not isinstance(uid, str) or not lifecycle.UID.fullmatch(uid):
        raise Incomplete("Fixture Pod UID missing or invalid.")
    return uid


class Collector:
    """Only observes independently supplied fixture references; never returns PASS."""
    def __init__(self, owner, api, image_ids, *, clock=time.monotonic, sleep=time.sleep):
        if (not isinstance(owner, lifecycle.Lifecycle) or
                not isinstance(api, adapter.FixtureAPI) or getattr(api, "owner", None) is not owner or
                owner.closed or owner.deadline is None or
                set(owner.owned) != set(owner.names)):
            raise Incomplete("Owned fixture Lifecycle and adapter required.")
        if (not isinstance(image_ids, dict) or
                set(image_ids) != {"controller", "webhook", "agent", "gateway", "plugin", "server", "tools"} or
                not all(isinstance(v, str) and re.fullmatch(
                    r"(?:[A-Za-z0-9_.-]+://)?sha256:[a-fA-F0-9]{64}", v) for v in image_ids.values())):
            raise Incomplete("Seven immutable expected runtime image IDs required.")
        self.owner, self.api, self.ids = owner, api, dict(image_ids)
        self.clock, self.sleep = clock, sleep

    def _deadline(self, seconds):
        end = min(self.owner.deadline, self.clock() + seconds)
        if self.owner.closed or self.clock() >= end:
            raise Incomplete("Synthetic evidence collection deadline exceeded.")
        return end

    def _exec(self, uid, name):
        try:
            return self.api.exec(self.owner.names[1], "synthetic-client", uid, "client", name,
                                 expected_image_id=self.ids["tools"])
        except adapter.AdapterError:
            raise Incomplete("Bounded client command unavailable or UID/image mismatch.") from None

    def _get(self, kind, name, namespace):
        try:
            return self.api.get(kind, name, namespace)
        except adapter.AdapterError:
            raise Incomplete("Owned Kubernetes object unavailable.") from None

    def poll(self, probe, *, budget=35, interval=1):
        if not 0 < budget <= 60 or not 0 < interval <= 3:
            raise Incomplete("Polling bounds invalid.")
        end = self._deadline(budget)
        while self.clock() < end:
            try:
                result = probe()
                if result is not None:
                    return result
            except (adapter.AdapterError, evidence.EvidenceError, Incomplete):
                pass  # transient eventual consistency; never log untrusted data
            remaining = end - self.clock()
            if remaining > 0:
                self.sleep(min(interval, remaining))
        raise Incomplete("Synthetic evidence did not converge before deadline.")

    def gateway_status(self, *, budget=35):
        """Poll existing Gateway only; status alone never proves TLS/session."""
        namespace = self.owner.names[0]
        def observed():
            gateway = self._get("egressgateway", "synthetic", namespace)
            meta, status = gateway.get("metadata", {}), gateway.get("status", {})
            if (meta.get("namespace") != namespace or meta.get("name") != "synthetic" or
                    not isinstance(meta.get("uid"), str) or not lifecycle.UID.fullmatch(meta["uid"]) or
                    not isinstance(meta.get("generation"), int) or
                    status.get("observedGeneration") != meta["generation"] or
                    not evidence.condition(gateway, "Ready", "True", meta["generation"])):
                return None
            return gateway
        return self.poll(observed, budget=budget)

    def assert_gateway_graph(self, gateway, deployment, replica_set, pod, children):
        """Validate supplied owner-linked snapshot; does not GET Secrets."""
        if gateway.get("metadata", {}).get("namespace") != self.owner.names[0]:
            raise Incomplete("Gateway namespace is not owned by Lifecycle.")
        return evidence.assert_gateway_chain(gateway, deployment, replica_set, pod, children, self.ids)

    def source_and_client(self, server, service, endpoint_slice, client, gateway_id, endpoint):
        ns, apps = self.owner.names
        evidence.need(server["metadata"].get("namespace") == ns and
                      client["metadata"].get("namespace") == apps and
                      server["metadata"].get("uid") and client["metadata"].get("uid"),
                      "Fixture Pod namespaces or UIDs differ from owned lifecycle.")
        evidence.need(_uid(server) == _uid(self._get("pod", "synthetic-vpn", ns)) and
                      _uid(client) == _uid(self._get("pod", "synthetic-client", apps)),
                      "Fixture Pod UID changed during evidence collection.")
        try:
            images_match = (self.api.pod_image_id(ns, "synthetic-vpn", "server", _uid(server)) == self.ids["server"] and
                            self.api.pod_image_id(apps, "synthetic-client", "client", _uid(client)) == self.ids["tools"])
        except adapter.AdapterError:
            raise Incomplete("Fixture runtime image lookup unavailable.") from None
        evidence.need(images_match, "Live fixture Pod runtime image IDs differ from approved builds.")
        evidence.assert_source_service(service, server, self.ids["server"])
        evidence.assert_source_endpoint(endpoint_slice, service, server)
        evidence.assert_restricted_client(client, apps, gateway_id, endpoint, self.ids["tools"])
        uid = _uid(client)
        marker = _parse_json(self._exec(uid, "agent-marker"))
        evidence.assert_agent_marker(marker)
        return uid

    def _session(self, server_uid):
        try:
            value = self.api.server_session(self.owner.names[0], server_uid,
                                            expected_image_id=self.ids["server"])
            if not isinstance(value, dict) or not isinstance(value.get("sessions"), list):
                raise Incomplete("Sanitized server session format invalid.")
            return value["sessions"]
        except adapter.AdapterError:
            raise Incomplete("Authenticated server-side session evidence unavailable.") from None

    def session_traffic(self, server_uid, client_uid, gateway_id, endpoint):
        """Correlate exact authenticated server session with selected request.

        Server `session.py` exports only whitelisted identity/counters; no raw
        OpenVPN status, cert or private key leaves the Pod. This remains local
        evidence, not a final gate PASS (see final_result()).
        """
        sessions_before = self._session(server_uid)
        self._validate_sessions(sessions_before)
        session_before = sessions_before[0]
        before_link = _geneve(self._exec(client_uid, "geneve-link"), gateway_id, endpoint)
        evidence.need(type(before_link.get("ifindex")) is int and before_link["ifindex"] > 0,
                      "GENEVE device index unavailable.")
        first = _tx_bytes(self._exec(client_uid, "geneve-bytes"))
        baseline = _tx_bytes(self._exec(client_uid, "geneve-bytes"))
        evidence.need(first == baseline, "GENEVE background traffic invalidates marker counter attribution.")
        sessions_idle = self._session(server_uid)
        self._validate_sessions(sessions_idle)
        session_idle = sessions_idle[0]
        evidence.need(session_before == session_idle,
                      "Server session changed without selected request; counter attribution unsafe.")
        body = self._exec(client_uid, "vpn-marker")
        after = _tx_bytes(self._exec(client_uid, "geneve-bytes"))
        after_link = _geneve(self._exec(client_uid, "geneve-link"), gateway_id, endpoint)
        sessions_after = self._session(server_uid)
        self._validate_sessions(sessions_after)
        session_after = sessions_after[0]
        evidence.need(before_link["ifindex"] == after_link.get("ifindex"),
                      "GENEVE device identity changed during selected request.")
        evidence.assert_selected_tunnel(baseline, after, body, after_link, gateway_id, endpoint)
        identity = ("cn", "virtualIPv4", "connected", "peer", "cipher")
        evidence.need(all(session_idle[k] == session_after[k] for k in identity) and
                      session_after["received"] > session_idle["received"] and
                      session_after["sent"] > session_idle["sent"],
                      "Authenticated OpenVPN client identity/counters did not advance.")
        return {"geneveBytesIncreased": True, "authenticatedSessionBytesIncreased": True}

    @classmethod
    def _validate_sessions(cls, values):
        if (not isinstance(values, list) or len(values) not in (1, 2) or
                not isinstance(values[0], dict) or values[0].get("cn") != "synthetic-client" or
                len(values) == 2 and (not isinstance(values[1], dict) or
                                     values[1].get("cn") != "synthetic-witness")):
            raise Incomplete("Unexpected OpenVPN session identities.")
        for value in values:
            cls._validate_session(value)
        if len({v["virtualIPv4"] for v in values}) != len(values):
            raise Incomplete("Duplicated OpenVPN virtual client address.")

    @staticmethod
    def _validate_session(value):
        if (not isinstance(value, dict) or
                set(value) != {"cn", "virtualIPv4", "received", "sent", "connected", "peer", "cipher"} or
                value.get("cn") not in {"synthetic-client", "synthetic-witness"} or
                value.get("cipher") not in {"AES-256-GCM", "AES-128-GCM"} or
                any(type(value.get(k)) is not int or value[k] < 0 for k in ("received", "sent", "connected", "peer")) or
                not isinstance(value.get("virtualIPv4"), str)):
            raise Incomplete("Sanitized authenticated server session identity invalid.")
        try:
            ip = ipaddress.ip_address(value["virtualIPv4"])
            if ip.version != 4 or ip not in ipaddress.ip_network("10.88.0.0/24") or ip == ipaddress.ip_address("10.88.0.1"):
                raise ValueError()
        except ValueError:
            raise Incomplete("Authenticated server virtual IPv4 identity invalid.") from None

    def witness_session(self, server_uid, witness_uid, expected_image_id, outage_started):
        """Capture a distinct authenticated CN while exact witness Pod runs."""
        from datetime import datetime, timezone
        if (not isinstance(outage_started, datetime) or outage_started.tzinfo is None or
                not isinstance(witness_uid, str) or not lifecycle.UID.fullmatch(witness_uid) or
                not isinstance(expected_image_id, str) or not re.fullmatch(
                    r"(?:[A-Za-z0-9_.-]+://)?sha256:[a-fA-F0-9]{64}", expected_image_id)):
            raise Incomplete("Witness running identity/timing invalid.")
        pod = self._get("pod", "synthetic-witness", self.owner.names[0])
        statuses = pod.get("status", {}).get("containerStatuses", [])
        if (_uid(pod) != witness_uid or pod["metadata"].get("deletionTimestamp") or
                pod.get("status", {}).get("phase") != "Running" or
                len(statuses) != 1 or statuses[0].get("name") != "witness" or
                statuses[0].get("imageID") != expected_image_id or
                not isinstance(statuses[0].get("state", {}).get("running", {}).get("startedAt"), str)):
            raise Incomplete("Witness not running with approved Pod UID/image.")
        try:
            began = datetime.fromisoformat(statuses[0]["state"]["running"]["startedAt"].replace("Z", "+00:00"))
        except ValueError:
            raise Incomplete("Witness running timestamp malformed.") from None
        if began < outage_started or began > datetime.now(timezone.utc):
            raise Incomplete("Witness was not started during outage.")
        sessions = self._session(server_uid)
        self._validate_sessions(sessions)
        if len(sessions) != 2 or sessions[1]["cn"] != "synthetic-witness":
            raise Incomplete("Distinct authenticated witness session absent.")
        result = {key: sessions[1][key] for key in ("cn", "virtualIPv4", "connected", "peer", "cipher")}
        if result["connected"] < int(began.timestamp()) - 1:
            raise Incomplete("Authenticated witness session predates its Pod.")
        result["podUID"] = witness_uid
        result["outageStart"] = outage_started.isoformat()
        return result

    def witness_status(self, witness_uid, expected_image_id, outage_started, observed_session):
        """One-shot witness succeeds only with prior live authenticated session.

        Caller must capture observed_session during the outage, while witness
        is Running. That Pod later exits 0 only after repeated exact marker
        reads through its independent tunnel; no Pod logs are inspected.
        """
        from datetime import datetime, timedelta
        namespace = self.owner.names[0]
        if not isinstance(outage_started, datetime) or outage_started.tzinfo is None:
            raise Incomplete("Trusted timezone-aware outage timestamp required.")
        if not isinstance(expected_image_id, str) or not re.fullmatch(
                r"(?:[A-Za-z0-9_.-]+://)?sha256:[a-fA-F0-9]{64}", expected_image_id):
            raise Incomplete("Immutable witness runtime image ID required.")
        if not isinstance(witness_uid, str) or not lifecycle.UID.fullmatch(witness_uid):
            raise Incomplete("Witness Pod UID missing or invalid.")
        pod = self._get("pod", "synthetic-witness", namespace)
        meta, status = pod["metadata"], pod.get("status", {})
        if (_uid(pod) != witness_uid or meta.get("deletionTimestamp") or
                status.get("phase") != "Succeeded" or
                pod.get("spec", {}).get("restartPolicy") != "Never" or
                pod.get("spec", {}).get("automountServiceAccountToken") is not False):
            raise Incomplete("Witness Pod ownership/termination evidence invalid.")
        cs = status.get("containerStatuses", [])
        if len(cs) != 1 or cs[0].get("name") != "witness" or cs[0].get("imageID") != expected_image_id:
            raise Incomplete("Witness runtime image ID mismatch.")
        terminated = cs[0].get("state", {}).get("terminated", {})
        start, finish = terminated.get("startedAt"), terminated.get("finishedAt")
        try:
            began = datetime.fromisoformat(start.replace("Z", "+00:00"))
            ended = datetime.fromisoformat(finish.replace("Z", "+00:00"))
        except (ValueError, AttributeError):
            raise Incomplete("Witness Pod termination timestamps invalid.") from None
        if (terminated.get("exitCode") != 0 or began < outage_started or
                ended < began or ended - began > timedelta(seconds=120) or
                ended > datetime.now(began.tzinfo) + timedelta(seconds=2)):
            raise Incomplete("Witness did not complete exact marker during outage.")
        if (not isinstance(observed_session, dict) or
                set(observed_session) != {"cn", "virtualIPv4", "connected", "peer", "cipher", "podUID", "outageStart"} or
                observed_session.get("cn") != "synthetic-witness" or
                observed_session.get("podUID") != witness_uid or
                observed_session.get("outageStart") != outage_started.isoformat() or
                observed_session.get("cipher") not in ("AES-256-GCM", "AES-128-GCM") or
                type(observed_session.get("connected")) is not int or
                type(observed_session.get("peer")) is not int):
            raise Incomplete("Prior authenticated witness session missing or malformed.")
        return {"witnessSucceededDuringOutage": True, "distinctSession": True}

    def selected_traffic(self, client_uid, gateway_id, endpoint):
        """Legacy local-only link test; use session_traffic for server proof."""
        before_link = _geneve(self._exec(client_uid, "geneve-link"), gateway_id, endpoint)
        evidence.need(type(before_link.get("ifindex")) is int and before_link["ifindex"] > 0,
                      "GENEVE device index unavailable.")
        before = _tx_bytes(self._exec(client_uid, "geneve-bytes"))
        # Check that idle selected-link traffic did not already advance.
        baseline = _tx_bytes(self._exec(client_uid, "geneve-bytes"))
        evidence.need(baseline == before, "GENEVE background traffic invalidates marker counter attribution.")
        body = self._exec(client_uid, "vpn-marker")
        after = _tx_bytes(self._exec(client_uid, "geneve-bytes"))
        after_link = _geneve(self._exec(client_uid, "geneve-link"), gateway_id, endpoint)
        evidence.need(before_link["ifindex"] == after_link["ifindex"],
                      "GENEVE device identity changed during probe.")
        evidence.assert_selected_tunnel(baseline, after, body, after_link, gateway_id, endpoint)
        evidence.need(self._exec(client_uid, "vpn-exit") == evidence.EXIT,
                      "Upstream tunnel exit marker mismatch.")
        return after - baseline

    def direct_dns(self, client_uid, api_ip, exclusions):
        # DNS alone is never evidence of TLS, source route or anonymous denial.
        address = str(evidence.ipv4(api_ip))
        name = _dns(self._exec(client_uid, "direct-dns"), address)
        try:
            excluded = any(ipaddress.ip_address(address) in ipaddress.ip_network(x["cidr"], strict=True)
                           for x in exclusions if x.get("source") in ("serviceCIDR", "apiserver"))
        except (ValueError, KeyError, TypeError):
            raise Incomplete("Gateway exclusion CIDR evidence is malformed.") from None
        evidence.need(excluded, "API ClusterIP is not excluded from selected datapath.")
        return name

    def direct_api_tls(self, client_uid, client_ip, api_ip, dns_ip, exclusions):
        """Public CA-only TLS, anonymous 403, exact DNS/remote IP and CNI route."""
        api_address = str(evidence.ipv4(api_ip))
        dns_address = str(evidence.ipv4(dns_ip))
        client_address = str(evidence.ipv4(client_ip))
        dns_name = _dns(self._exec(client_uid, "direct-dns"), api_address)
        route = _parse_json(self._exec(client_uid, "direct-api-route"))
        response = self._exec(client_uid, "direct-api-tls")
        fields = response.strip().split()
        if len(fields) != 2 or fields[0] != api_address or fields[1] != "403":
            raise Incomplete("Anonymous TLS request did not deny at expected API ClusterIP.")
        evidence.assert_direct_paths(exclusions, dns_address, api_address, dns_name, 403,
                                     route, client_address)
        return {"verifiedCA": True, "anonymousDenied": True, "directClusterRoute": True}

    def final_result(self):
        # Session and public-CA API checks are cluster-unvalidated and unwired;
        # safe server outage/recovery and atomic Pod UID binding are also absent.
        raise Incomplete("Full synthetic VPN final gate cannot certify PASS: missing live TLS/API validation, safe outage/recovery and UID-atomic exec proof.")
