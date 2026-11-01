#!/usr/bin/env python3
"""Final-gated, one-replica gateway replacement with the SAME selected Pod.

Fixture namespaces only. No agent DaemonSet restart, established-flow or full
matrix claim. Authoring/import never contacts the cluster.
"""
import argparse
import hashlib
import json
import os
import re
import sys
import time

try:
    from . import ha_fixture as ha
except ImportError:
    import ha_fixture as ha

adapter = ha.adapter
lifecycle = ha.lifecycle
partial_gateway = ha.partial_gateway
prepare = ha.prepare
run = ha.run
node_images = ha.node_images
import evidence  # noqa: E402


class Blocked(lifecycle.LifecycleError):
    """Only constant, non-secret checkpoint labels cross the cleanup boundary."""


class SelectedUIDChanged(Blocked):
    """Terminal identity failure: never poll/adopt a replacement client."""


class LifecycleAPI(ha.HAFixtureAPI):
    """Reuse strict generated-Pod GET and single UID-preconditioned DELETE.

    The stock FixtureAPI list is intentionally limited to one owned replica;
    unlike HA's override, it never accepts a second Pod as a valid baseline.
    """
    list_owned_gateway_pods = adapter.FixtureAPI.list_owned_gateway_pods


def gateway_state(api, owner, ids, expected_uid):
    """Complete one-replica ownership, runtime and exact applied-byte checks."""
    ns = owner.names[0]
    gateway, pod = partial_gateway.gateway_ready(api, expected_uid, ns, ids)
    status = gateway["status"]
    if gateway.get("spec", {}).get("replicas") != 1 or len(status.get("endpoints", [])) != 1:
        raise Blocked("Gateway singleton contract invalid.")
    ep = status["endpoints"][0]
    digest = ep.get("appliedClientConfigHash")
    cm = api.get("configmap", "synthetic", ns)
    raw = cm.get("data", {}).get("gateway.json")
    if (not isinstance(digest, str) or not re.fullmatch(r"[0-9a-f]{64}", digest) or
            not evidence.owner(cm, "EgressGateway", expected_uid) or
            cm.get("metadata", {}).get("deletionTimestamp") or
            not isinstance(raw, str) or len(raw) > 1 << 20 or
            hashlib.sha256(raw.encode()).hexdigest() != digest or
            ep.get("podUID") != pod["metadata"].get("uid") or
            ep.get("podName") != pod["metadata"].get("name")):
        raise Blocked("Gateway endpoint applied acknowledgement invalid.")
    config = json.loads(raw)
    if (not isinstance(config, dict) or type(status.get("gatewayID")) is not int or
            config.get("gatewayID") != status.get("gatewayID") or
            config.get("encryption") != "none" or
            not isinstance(config.get("clients"), list) or
            not all(isinstance(ip, str) for ip in config["clients"])):
        raise Blocked("Gateway applied client membership invalid.")
    return {"gatewayUID": expected_uid, "gatewayID": status["gatewayID"],
            "podUID": pod["metadata"]["uid"], "podName": pod["metadata"]["name"],
            "endpoint": ep["podIP"], "hash": digest, "clients": config["clients"]}


def selected_state(api, owner, ids, gateway, uid):
    apps = owner.names[1]
    pod = api.get("pod", "synthetic-client", apps)
    if pod.get("metadata", {}).get("uid") != uid:
        raise SelectedUIDChanged("Selected Pod UID changed; refusing replacement adoption.")
    evidence.assert_restricted_client(pod, apps, gateway["gatewayID"], gateway["endpoint"],
                                      ids["selected"])
    chosen = ha.ha_live.selected(pod, "synthetic", {gateway["endpoint"]})
    if (chosen != gateway["endpoint"] or gateway["clients"].count(pod["status"].get("podIP")) != 1 or
            pod["status"].get("phase") != "Running" or
            not evidence.condition(pod, "Ready", "True") or
            not any(s.get("name") == "ratatoskr-init" and
                    s.get("state", {}).get("terminated", {}).get("exitCode") == 0
                    for s in pod["status"].get("initContainerStatuses", [])) or
            api.pod_image_id(apps, "synthetic-client", "client", uid) != ids["selected"] or
            pod.get("spec", {}).get("containers", [{}])[0].get("imagePullPolicy") != "Never"):
        raise Blocked("Selected Pod not ready for acknowledged gateway endpoint.")
    return pod


def await_stage(owner, stage, predicate, *, seconds, clock=time.monotonic, sleep=time.sleep):
    """Bounded reconciliation; a changed selected UID is terminal, not retryable."""
    limit = min(owner.deadline, clock() + seconds)
    while clock() < limit:
        if owner.closed or owner.clock() >= owner.deadline:
            raise Blocked("Owned lifecycle deadline expired.")
        try:
            result = predicate()
            if result is not None:
                return result
        except SelectedUIDChanged:
            raise
        except Blocked:
            pass
        except (adapter.AdapterError, evidence.EvidenceError, ha.ha_live.Blocked,
                KeyError, ValueError, TypeError, AttributeError):
            pass
        remaining = limit - clock()
        if remaining > 0:
            sleep(min(2, remaining))
    raise Blocked("Gateway replacement did not converge at " + stage + ".")


def replace(api, owner, ids, created, api_ip, *, clock=time.monotonic, sleep=time.sleep):
    """One owner-checked DELETE; new Pod UID/IP and existing client reprogram."""
    ns, apps = owner.names
    gw_uid = created[("EgressGateway", ns, "synthetic")]
    source_uid = created[("Pod", ns, "synthetic-vpn")]
    def baseline():
        current = gateway_state(api, owner, ids, gw_uid)
        server = partial_gateway.source_ready(api.get("pod", "synthetic-vpn", ns),
                                              api.get("service", "synthetic-vpn", ns), ids["server"])
        return current if server["metadata"]["uid"] == source_uid else None
    before = await_stage(owner, "gateway-baseline", baseline, seconds=170, clock=clock, sleep=sleep)
    identity = api.create(prepare.running_probe_pod(apps, ns, api_ip))
    if ((identity.get("kind"), identity.get("namespace"), identity.get("name")) !=
            ("Pod", apps, "synthetic-client") or
            not isinstance(identity.get("uid"), str) or not lifecycle.UID.fullmatch(identity["uid"])):
        raise Blocked("Selected CREATE identity unavailable.")
    uid = identity["uid"]
    def initial():
        current = gateway_state(api, owner, ids, gw_uid)
        if any(current[key] != before[key] for key in ("gatewayUID", "gatewayID", "podUID", "endpoint")):
            raise Blocked("Initial Gateway Pod changed before controlled deletion.")
        selected_state(api, owner, ids, current, uid)
        return current
    before = await_stage(owner, "selected-ready", initial, seconds=160, clock=clock, sleep=sleep)
    if api.probe_running("synthetic-client", uid, ids["selected"], "healthy", api_ip) is not True:
        raise Blocked("Baseline fixed probe failed.")
    selected_state(api, owner, ids, before, uid)
    if gateway_state(api, owner, ids, gw_uid) != before:
        raise Blocked("Gateway changed before controlled deletion.")
    # delete_chosen_gateway_pod GETs the generated Pod's current status and
    # rechecks Deployment→ReplicaSet→Pod ownership before sending exactly one
    # UID-preconditioned, five-second-grace DELETE.
    api.delete_chosen_gateway_pod(ns, before["podName"], before["podUID"])
    def replacement():
        # Check exact old selected UID BEFORE any retryable gateway transition.
        if api.get("pod", "synthetic-client", apps)["metadata"].get("uid") != uid:
            raise SelectedUIDChanged("Selected Pod UID changed; refusing replacement adoption.")
        current = gateway_state(api, owner, ids, gw_uid)
        if (current["gatewayID"] != before["gatewayID"] or
                current["podUID"] == before["podUID"] or
                current["endpoint"] == before["endpoint"]):
            return None
        selected_state(api, owner, ids, current, uid)
        return current
    after = await_stage(owner, "replacement-ready", replacement, seconds=135, clock=clock, sleep=sleep)
    sleep(2)
    if replacement() != after:
        raise Blocked("Replacement endpoint or selected client unstable.")
    if api.probe_running("synthetic-client", uid, ids["selected"], "healthy", api_ip) is not True:
        raise Blocked("Replacement fixed probe failed.")
    if replacement() != after:
        raise Blocked("Replacement identity changed during fixed probe.")
    if partial_gateway.source_ready(api.get("pod", "synthetic-vpn", ns),
                                    api.get("service", "synthetic-vpn", ns), ids["server"])["metadata"]["uid"] != source_uid:
        raise Blocked("Source server changed during replacement probe.")
    return {"sameSelectedPodUID": True, "newGatewayPodUIDAndIP": True,
            "newConnectionMarker": True, "establishedFlowContinuity": "not-asserted",
            "agentRestart": "not-tested"}


def execute(ids, api_ip, *, lifecycle_factory=lifecycle.Lifecycle, adapter_factory=LifecycleAPI,
            clock=time.monotonic, sleep=time.sleep):
    if (not isinstance(ids, dict) or set(ids) != set(run.COMPONENTS) or
            any(not isinstance(v, str) or not run.ID_PATTERN.fullmatch(v) for v in ids.values())):
        raise Blocked("Immutable approved image IDs missing.")
    ha.ha_live.ip4(api_ip)
    with lifecycle_factory(duration=700, cleanup_budget=150) as owner:
        stage = "fixture-create"
        try:
            owner.create_namespaces()
            owner.generate_pki()
            api = adapter_factory(owner)
            contents = partial_gateway.private_contents(owner.private_dir)
            created = {}
            for obj in prepare.manifests(owner.names[0], "ratatoskr-synthetic-openvpn:local", contents, owner.token):
                if (obj.get("kind"), obj.get("metadata", {}).get("name")) not in partial_gateway.BASE:
                    continue
                identity = api.create(obj)
                key = identity["kind"], identity["namespace"], identity["name"]
                if (key in created or not isinstance(identity.get("uid"), str) or
                        not lifecycle.UID.fullmatch(identity["uid"])):
                    raise Blocked("Fixture CREATE identity ambiguous.")
                created[key] = identity["uid"]
            if len(created) != len(partial_gateway.BASE):
                raise Blocked("Fixture owner manifest incomplete.")
            return replace(api, owner, ids, created, api_ip, clock=clock, sleep=sleep)
        except (Blocked, KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            raise Blocked("Gateway replacement blocked at " + stage + ".") from None


def main(argv=None, environ=None, *, readonly_factory=run.ReadOnlyAPI, executor=execute):
    parser = argparse.ArgumentParser(description="Gated existing-client singleton gateway replacement")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--execute-agent-gateway-replacement", action="store_true")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    if (not args.execute or not args.execute_agent_gateway_replacement or
            env.get("RATATOSKR_E2E_FINAL_GATE") != "1" or
            env.get("RATATOSKR_E2E_AGENT_GATEWAY_REPLACEMENT") != "1"):
        print("SKIPPED: explicit gateway-replacement final gate absent; no cluster accessed.")
        return 2
    try:
        ids = run.expected_ids(env)
        readonly = readonly_factory()
        run.preflight(readonly, ids)
        node_images.verify({component: ids[component] for component in node_images.TAGS})
        ip = partial_gateway.api_service_ip(readonly)
        result = executor(ids, ip)
        if result != {"sameSelectedPodUID": True, "newGatewayPodUIDAndIP": True,
                      "newConnectionMarker": True, "establishedFlowContinuity": "not-asserted",
                      "agentRestart": "not-tested"}:
            raise Blocked("Existing-client replacement marker incomplete.")
        print("PARTIAL: existing selected Pod healthy on replacement Gateway Pod; established flows and agent restart NOT TESTED.")
        return 4
    except (KeyboardInterrupt, SystemExit):
        print("FAILED: gateway replacement interrupted; inspect UID-owned namespace cleanup.")
        return 1
    except BaseException:
        print("FAILED: gateway replacement blocked; inspect UID-owned cleanup privately.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
