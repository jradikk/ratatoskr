#!/usr/bin/env python3
"""Explicit final-gate, UID-owned two-replica HA *new-connection* traffic fixture.

Never execute while authoring. Uses fixture-only synthetic OpenVPN duplicate-cn;
no provider profile, user namespace, Helm, node security or production RBAC edits.
"""
import argparse
import base64
import copy
import json
import os
from pathlib import Path
import re
import sys
import time

# The existing release preflight, bounded transport and UID-owned namespace
# lifecycle are reused unchanged. Do not import arbitrary files or stdin code.
SYNTHETIC = Path(__file__).resolve().parents[1] / "matrix" / "synthetic"
if str(SYNTHETIC) not in sys.path:
    sys.path.insert(0, str(SYNTHETIC))
import adapter  # noqa: E402
import lifecycle  # noqa: E402
import node_images  # noqa: E402
import partial_gateway  # noqa: E402
import prepare  # noqa: E402
import run  # noqa: E402
import ha_live  # noqa: E402


class Blocked(lifecycle.LifecycleError):
    """Fixed safe diagnostics only; never expose Kubernetes or PKI bytes."""


class StageError(Blocked):
    """Only code-authored checkpoint labels may cross the cleanup boundary."""

    LABELS = frozenset({"owned-namespaces-create", "fixture-private-pki",
                        "fixture-manifests", "fixture-object-create",
                        "gateway-two-replica-baseline", "selected-pod-create",
                        "selected-agent-ready", "initial-marker",
                        "uid-owned-replica-delete", "selected-agent-reselection",
                        "selected-reselection-stability", "post-failover-marker"})

    def __init__(self, label):
        if label not in self.LABELS:
            raise ValueError("Unknown HA checkpoint")
        super().__init__("HA fixture blocked at " + label + ".")


BASE = partial_gateway.BASE
IMAGE = "ratatoskr-synthetic-client:local"


class HAFixtureAPI(adapter.FixtureAPI):
    """Permit only status-identified, owner-verified synthetic gateway Pod GETs.

    The base adapter intentionally allows only fixed workload Pod names. HA
    controller Pods have generated names. This read-only exception never adds
    dynamic CREATE/exec or name-only DELETE authority.
    """

    def get(self, kind, name, namespace):
        if kind != "pod" or name in adapter.RESOURCES["pod"]:
            return super().get(kind, name, namespace)
        if (namespace != self.owner.names[0] or
                not isinstance(name, str) or not adapter.GENERATED.fullmatch(name)):
            raise adapter.AdapterError("Dynamic gateway Pod GET not allowlisted.")
        self._namespace(namespace)
        gateway = super().get("egressgateway", "synthetic", namespace)
        deployment = super().get("deployment", "synthetic", namespace)
        gateway_uid = gateway.get("metadata", {}).get("uid")
        if (not lifecycle.UID.fullmatch(gateway_uid or "") or
                not ha_live.owner(deployment, "EgressGateway", gateway_uid) or
                gateway.get("metadata", {}).get("deletionTimestamp")):
            raise adapter.AdapterError("Dynamic gateway Pod owner unavailable.")
        matching = [e for e in gateway.get("status", {}).get("endpoints", [])
                    if e.get("podName") == name and e.get("upstreamHealthy") is True]
        if (len(matching) != 1 or
                not lifecycle.UID.fullmatch(matching[0].get("podUID", "")) or
                not re.fullmatch(r"[a-f0-9]{64}", matching[0].get("appliedClientConfigHash", ""))):
            raise adapter.AdapterError("Dynamic Pod not in current applied Gateway status.")
        raw = self._call(["get", "pod", name, "--namespace", namespace, "-o", "json"],
                         max_output=32768)
        try:
            pod = json.loads(raw)
            meta = pod["metadata"]
            refs = [r for r in meta.get("ownerReferences", [])
                    if r.get("kind") == "ReplicaSet" and r.get("controller") is True]
            if (pod.get("kind") != "Pod" or meta.get("name") != name or
                    meta.get("namespace") != namespace or
                    meta.get("uid") != matching[0]["podUID"] or
                    pod.get("status", {}).get("podIP") != matching[0].get("podIP") or
                    meta.get("deletionTimestamp") or len(refs) != 1 or
                    not adapter.GENERATED.fullmatch(refs[0].get("name", ""))):
                raise ValueError()
            rs = super().get("replicaset", refs[0]["name"], namespace)
            if (rs.get("metadata", {}).get("uid") != refs[0].get("uid") or
                    not ha_live.owner(rs, "Deployment", deployment["metadata"]["uid"])):
                raise ValueError()
            return pod
        except (ValueError, TypeError, KeyError, AttributeError):
            raise adapter.AdapterError("Dynamic gateway Pod UID/owner invalid.") from None

    def list_owned_gateway_pods(self, namespace, gateway_uid):
        """Bounded 2-replica variant of the base adapter's one-Pod list."""
        if (namespace != self.owner.names[0] or
                not isinstance(gateway_uid, str) or not lifecycle.UID.fullmatch(gateway_uid)):
            raise adapter.AdapterError("HA Gateway UID or namespace invalid.")
        self._namespace(namespace)
        selector = ("ratatoskr.skaldhall.io/gateway-name=synthetic,"
                    "ratatoskr.skaldhall.io/gateway-uid=" + gateway_uid)
        raw = self._call(["get", "pods", "--namespace", namespace, "-l", selector, "-o", "json"],
                         max_output=32768)
        try:
            items = json.loads(raw)
            pods = items["items"]
            if items.get("kind") != "List" or not isinstance(pods, list) or len(pods) != 2:
                raise ValueError()
            names = set()
            for pod in pods:
                meta = pod["metadata"]
                name = meta["name"]
                if (pod.get("kind") != "Pod" or name in names or
                        not adapter.GENERATED.fullmatch(name) or
                        meta.get("namespace") != namespace or
                        meta.get("labels", {}).get("ratatoskr.skaldhall.io/gateway-name") != "synthetic" or
                        meta.get("labels", {}).get("ratatoskr.skaldhall.io/gateway-uid") != gateway_uid or
                        not lifecycle.UID.fullmatch(meta.get("uid", "")) or
                        meta.get("deletionTimestamp")):
                    raise ValueError()
                names.add(name)
            return pods
        except (ValueError, TypeError, KeyError, AttributeError):
            raise adapter.AdapterError("HA Gateway Pod list identity/count invalid.") from None


def fixture_manifests(namespace, token, contents):
    """Copy stock synthetic manifests; only change ephemeral server and replicas."""
    objects = prepare.manifests(namespace, "ratatoskr-synthetic-openvpn:local", contents, token)
    selected = [copy.deepcopy(o) for o in objects if
                (o["kind"], o["metadata"].get("name")) in BASE]
    if ([(o["kind"], o["metadata"].get("name")) for o in selected] != list(BASE) or
            selected[0]["kind"] != "Secret" or selected[6]["kind"] != "EgressGateway"):
        raise Blocked("Synthetic base manifest shape changed.")
    server = selected[0]
    original = prepare.server_config()
    try:
        packaged = base64.b64decode(server["data"]["server.conf"], validate=True).decode()
    except (KeyError, ValueError, UnicodeError):
        raise Blocked("Synthetic server profile shape changed.") from None
    if packaged != original or "duplicate-cn" in original:
        raise Blocked("Synthetic server configuration unexpectedly changed.")
    # Only the fixture-generated OpenVPN server accepts concurrent test replicas
    # with the same *fixture* CN; production upstream Secret is never read.
    server["data"]["server.conf"] = base64.b64encode((original + "duplicate-cn\n").encode()).decode()
    selected[6]["spec"]["replicas"] = 2
    return selected


def bounded_poll(owner, operation, *, stage, seconds, clock=time.monotonic, sleep=time.sleep):
    deadline = min(owner.deadline, clock() + seconds)
    while clock() < deadline:
        if owner.closed:
            raise Blocked("Owned lifecycle closed during HA observation.")
        try:
            value = operation()
            if value is not None:
                return value
        except (Blocked, ha_live.Blocked, adapter.AdapterError, KeyError,
                TypeError, ValueError, AttributeError, json.JSONDecodeError):
            pass
        remaining = deadline - clock()
        if remaining > 0:
            sleep(min(2, remaining))
    raise Blocked("HA fixture did not converge at " + stage + ".")


def owned_gateway_baseline(api, owner, ids):
    namespace = owner.names[0]
    gw = api.get("egressgateway", "synthetic", namespace)
    meta = gw.get("metadata", {})
    if (not lifecycle.UID.fullmatch(meta.get("uid", "")) or
            gw.get("spec", {}).get("replicas") != 2 or
            gw.get("spec", {}).get("encryption") != "none"):
        raise Blocked("Two-replica owned Gateway identity/config invalid.")
    deployment = api.get("deployment", "synthetic", namespace)
    if not ha_live.owner(deployment, "EgressGateway", meta["uid"]):
        raise Blocked("Gateway Deployment ownership invalid.")
    if (deployment.get("spec", {}).get("replicas") != 2 or
            deployment.get("status", {}).get("readyReplicas") != 2):
        raise Blocked("Gateway replica rollout not ready.")
    active = ha_live.endpoints(gw)
    if len(active) != 2:
        raise Blocked("Gateway endpoints not both ready and config-applied.")
    for ip, ep in active.items():
        pod = api.get("pod", ep["podName"], namespace)
        if (pod["metadata"].get("uid") != ep["podUID"] or
                pod.get("status", {}).get("podIP") != ip or
                pod["metadata"].get("deletionTimestamp")):
            raise Blocked("Gateway Pod identity stale.")
        rsref = next((r for r in pod["metadata"].get("ownerReferences", [])
                      if r.get("kind") == "ReplicaSet" and r.get("controller") is True), None)
        if rsref is None or not ha_live.NAME.fullmatch(rsref.get("name", "")):
            raise Blocked("Gateway Pod ReplicaSet owner absent.")
        rs = api.get("replicaset", rsref["name"], namespace)
        if (rs["metadata"].get("uid") != rsref.get("uid") or
                not ha_live.owner(rs, "Deployment", deployment["metadata"].get("uid"))):
            raise Blocked("Gateway ReplicaSet ownership invalid.")
        statuses = {s.get("name"): s for s in pod.get("status", {}).get("containerStatuses", [])}
        if any(statuses.get(name, {}).get("imageID") != ids[component] or
               statuses[name].get("ready") is not True
               for name, component in (("gateway", "gateway"), ("upstream", "plugin"))):
            raise Blocked("Gateway replica runtime images not approved.")
    return meta["uid"]


def source_server_identity(api, owner, created, ids):
    namespace = owner.names[0]
    expected = created[("Pod", namespace, "synthetic-vpn")]
    server = api.get("pod", "synthetic-vpn", namespace)
    statuses = [s for s in server.get("status", {}).get("containerStatuses", [])
                if s.get("name") == "server"]
    if (server.get("metadata", {}).get("uid") != expected or
            server.get("metadata", {}).get("deletionTimestamp") or
            server.get("status", {}).get("phase") != "Running" or
            len(statuses) != 1 or statuses[0].get("ready") is not True or
            statuses[0].get("imageID") != ids["server"]):
        raise Blocked("Synthetic source server identity or runtime image changed.")
    return expected


def remove_chosen_gateway_pod(api, owner, gateway_uid, before):
    """UID-preconditioned deletion of ONLY the exact chosen fixture Gateway Pod."""
    namespace = owner.names[0]
    api._namespace(namespace)
    gw = api.get("egressgateway", "synthetic", namespace)
    if gw["metadata"].get("uid") != gateway_uid or gateway_uid != before["gatewayUID"]:
        raise Blocked("Gateway UID changed before controlled failure.")
    candidates = [e for e in gw.get("status", {}).get("endpoints", [])
                  if e.get("podIP") == before["chosen"] and e.get("upstreamHealthy") is True]
    if len(candidates) != 1:
        raise Blocked("Chosen replica identity unavailable.")
    ep = candidates[0]
    if not ha_live.NAME.fullmatch(ep.get("podName", "")) or not lifecycle.UID.fullmatch(ep.get("podUID", "")):
        raise Blocked("Chosen replica name or UID invalid.")
    # Recheck entire gateway/client chain, including live agent config, directly
    # before destructive action: never delete a similarly named foreign Pod.
    fresh = ha_live.snapshot(lambda _ctx, kind, ns, name: api.get(kind, name, ns),
                             "fixture", namespace, "synthetic", owner.names[1], "synthetic-client",
                             gateway_uid=gateway_uid, pod_uid=before["podUID"])
    if fresh != before:
        raise Blocked("Chosen replica or client changed before deletion.")
    pod = api.get("pod", ep["podName"], namespace)
    if (pod["metadata"].get("uid") != ep["podUID"] or
            pod["metadata"].get("deletionTimestamp") or
            pod.get("status", {}).get("podIP") != before["chosen"]):
        raise Blocked("Chosen replica Pod changed before deletion.")
    options = {"apiVersion": "v1", "kind": "DeleteOptions", "preconditions": {"uid": ep["podUID"]},
               "propagationPolicy": "Foreground"}
    raw = api._call(["delete", "--raw=/api/v1/namespaces/" + namespace + "/pods/" + ep["podName"],
                     "-f", "-"], payload=json.dumps(options, separators=(",", ":")).encode(),
                    max_output=4096)
    try:
        reply = json.loads(raw)
        if reply.get("kind") not in ("Pod", "Status"):
            raise ValueError()
        if reply["kind"] == "Pod" and reply.get("metadata", {}).get("uid") != ep["podUID"]:
            raise ValueError()
        if reply["kind"] == "Status" and reply.get("status") != "Success":
            raise ValueError()
    except (ValueError, TypeError, KeyError):
        raise Blocked("Chosen replica UID-conditional delete response unverified.") from None


def reselected(api, owner, before):
    after = ha_live.snapshot(lambda _ctx, kind, ns, name: api.get(kind, name, ns),
                             "fixture", owner.names[0], "synthetic", owner.names[1], "synthetic-client",
                             gateway_uid=before["gatewayUID"], pod_uid=before["podUID"])
    if (after["gatewayID"] != before["gatewayID"] or after["clientIP"] != before["clientIP"] or
            before["chosen"] in after["active"] or after["chosen"] == before["chosen"] or
            after["chosen"] not in (before["active"] - {before["chosen"]}) or
            not (before["active"] - {before["chosen"]}) <= after["active"] or
            len(after["active"]) not in (1, 2)):
        raise Blocked("Affected client did not reselect a remaining healthy replica.")
    return after


def execute(ids, api_ip, *, lifecycle_factory=lifecycle.Lifecycle,
            adapter_factory=HAFixtureAPI, clock=time.monotonic, sleep=time.sleep):
    if (set(ids) != set(run.COMPONENTS) or
            any(not run.ID_PATTERN.fullmatch(v) for v in ids.values())):
        raise Blocked("Immutable approved image IDs missing.")
    ha_live.ip4(api_ip)
    with lifecycle_factory(duration=650, cleanup_budget=140) as owner:
        stage = "owned-namespaces-create"
        try:
            owner.create_namespaces()
            stage = "fixture-private-pki"
            owner.generate_pki()
            api = adapter_factory(owner)
            stage = "fixture-manifests"
            contents = partial_gateway.private_contents(owner.private_dir)
            created = {}
            stage = "fixture-object-create"
            for obj in fixture_manifests(owner.names[0], owner.token, contents):
                identity = api.create(obj)
                key = identity["kind"], identity["namespace"], identity["name"]
                if key in created or not lifecycle.UID.fullmatch(identity.get("uid", "")):
                    raise Blocked("Fixture object CREATE UID ambiguous.")
                created[key] = identity["uid"]
            stage = "gateway-two-replica-baseline"
            gw_uid = created[("EgressGateway", owner.names[0], "synthetic")]
            bounded_poll(owner, lambda: gw_uid if owned_gateway_baseline(api, owner, ids) == gw_uid and
                         source_server_identity(api, owner, created, ids) else None,
                         stage="gateway-two-replica-baseline", seconds=170, clock=clock, sleep=sleep)
            # The fixture engineer's reviewed long-lived restricted workload helper
            # reuses the approved one-shot client image (no new image/probe surface).
            stage = "selected-pod-create"
            pod_manifest = prepare.running_probe_pod(owner.names[1], owner.names[0], api_ip)
            identity = api.create(pod_manifest)
            if (identity["kind"], identity["namespace"], identity["name"]) != ("Pod", owner.names[1], "synthetic-client"):
                raise Blocked("Selected fixture Pod CREATE identity invalid.")
            uid = identity["uid"]
            def get_snapshot():
                snap = ha_live.snapshot(lambda _ctx, kind, ns, name: api.get(kind, name, ns),
                                        "fixture", owner.names[0], "synthetic",
                                        owner.names[1], "synthetic-client", gateway_uid=gw_uid, pod_uid=uid)
                if len(snap["active"]) != 2 or source_server_identity(api, owner, created, ids) is None:
                    raise Blocked("Healthy baseline requires two replicas and source server.")
                pod = api.get("pod", "synthetic-client", owner.names[1])
                if api.pod_image_id(owner.names[1], "synthetic-client", "client", uid) != ids["selected"]:
                    raise Blocked("Selected fixture image mismatch.")
                if pod.get("spec", {}).get("containers", [{}])[0].get("imagePullPolicy") != "Never":
                    raise Blocked("Selected fixture image pull policy mismatch.")
                return snap
            stage = "selected-agent-ready"
            before = bounded_poll(owner, get_snapshot, stage="selected-agent-ready",
                                  seconds=155, clock=clock, sleep=sleep)
            stage = "initial-marker"
            if api.probe_running("synthetic-client", uid, ids["selected"], "healthy", api_ip) is not True:
                raise Blocked("Initial selected traffic marker/direct path failed.")
            if source_server_identity(api, owner, created, ids) is None:
                raise Blocked("Source server changed during initial marker.")
            # Reaffirm same Pod/Gateway identity after first independent new TCP probe.
            if get_snapshot() != before:
                raise Blocked("Fixture identity changed before controlled failover.")
            stage = "uid-owned-replica-delete"
            remove_chosen_gateway_pod(api, owner, gw_uid, before)
            stage = "selected-agent-reselection"
            after = bounded_poll(owner, lambda: reselected(api, owner, before),
                                 stage="selected-agent-reselection", seconds=135, clock=clock, sleep=sleep)
            stage = "selected-reselection-stability"
            sleep(2)
            if reselected(api, owner, before) != after:
                raise Blocked("HA endpoint/agent choice changed after observation.")
            stage = "post-failover-marker"
            # A NEW TCP connection after agent reselection is required: no claim
            # that an established flow survives a different gateway/VPN exit.
            if api.probe_running("synthetic-client", uid, ids["selected"], "healthy", api_ip) is not True:
                raise Blocked("Post-failover selected traffic marker/direct path failed.")
            if source_server_identity(api, owner, created, ids) is None:
                raise Blocked("Source server changed during post-failover marker.")
            if reselected(api, owner, before) != after:
                raise Blocked("Fixture identity changed during post-failover marker.")
        except Blocked:
            raise
        except (KeyboardInterrupt, SystemExit):
            raise
        except Exception:
            # Translate every other body failure inside Lifecycle: __exit__
            # otherwise erases the stage. No raw exception reaches CLI, even
            # from a malformed API object or an unexpected fixture bug.
            raise StageError(stage) from None
    return {"haNewConnectionMarker": True, "establishedFlowContinuity": "not-asserted",
            "wireguard": "not-tested"}


def main(argv=None, environ=None, *, readonly_factory=run.ReadOnlyAPI, executor=execute):
    parser = argparse.ArgumentParser(description="Explicit bounded synthetic HA traffic fixture")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--execute-ha-fixture", action="store_true")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    if (not args.execute or not args.execute_ha_fixture or
            env.get("RATATOSKR_E2E_FINAL_GATE") != "1" or
            env.get("RATATOSKR_E2E_HA_FIXTURE") != "1"):
        print("SKIPPED: explicit HA final gate absent; no cluster accessed.")
        return 2
    try:
        ids = run.expected_ids(env)
        readonly = readonly_factory()
        run.preflight(readonly, ids)
        node_images.verify({component: ids[component] for component in node_images.TAGS})
        service_ip = partial_gateway.api_service_ip(readonly)
        result = executor(ids, service_ip)
        if result != {"haNewConnectionMarker": True, "establishedFlowContinuity": "not-asserted",
                      "wireguard": "not-tested"}:
            raise Blocked("HA marker verification incomplete.")
        print("PARTIAL: two-replica synthetic HA new-connection marker verified after UID-owned replica withdrawal; established flows, distinct exit IP and WireGuard NOT TESTED.")
        return 4  # Always incomplete M8; never mark full matrix PASS.
    except (KeyboardInterrupt, SystemExit):
        print("FAILED: synthetic HA gate interrupted; inspect UID-owned namespace cleanup.")
        return 1
    except Blocked as failure:
        print("FAILED: " + str(failure) + " UID-owned cleanup attempted; inspect privately.")
        return 1
    except lifecycle.LifecycleError:
        print("FAILED: HA namespace/private-PKI lifecycle or cleanup unverified; no PASS.")
        return 1
    except BaseException:
        print("FAILED: synthetic HA gate blocked; inspect UID-owned namespace cleanup privately.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
