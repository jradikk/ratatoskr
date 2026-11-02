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


class StageError(Blocked):
    """Only code-authored stage and reason labels may reach stdout."""

    STAGES = frozenset({"fixture-create", "gateway-baseline", "selected-create",
                        "selected-ready", "baseline-probe", "gateway-delete",
                        "replacement-ready", "replacement-probe", "selected-uid",
                        "agent-baseline", "agent-restart-ready", "agent-restart-probe"})
    REASONS = frozenset({"blocked", "gateway-owner", "gateway-applied-hash",
                         "gateway-client-membership", "selected-readiness", "adapter-read",
                         "agent-owner", "agent-runtime", "agent-node"})

    def __init__(self, stage, reason="blocked"):
        if stage not in self.STAGES or reason not in self.REASONS:
            raise ValueError("Unknown gateway replacement checkpoint")
        self.stage, self.reason = stage, reason
        super().__init__("Gateway replacement blocked at " + stage + "/" + reason + ".")


class SelectedUIDChanged(StageError):
    """Terminal identity failure: never poll/adopt a replacement client."""

    def __init__(self):
        super().__init__("selected-uid")


class LifecycleAPI(ha.HAFixtureAPI):
    """Reuse strict generated-Pod GET and single UID-preconditioned DELETE.

    The stock FixtureAPI list is intentionally limited to one owned replica;
    unlike HA's override, it never accepts a second Pod as a valid baseline.
    """
    list_owned_gateway_pods = adapter.FixtureAPI.list_owned_gateway_pods


def gateway_state(api, owner, ids, expected_uid):
    """Complete one-replica ownership, runtime and exact applied-byte checks."""
    ns = owner.names[0]
    try:
        gateway, pod = partial_gateway.gateway_ready(api, expected_uid, ns, ids)
    except partial_gateway.Blocked:
        raise StageError("gateway-baseline", "gateway-owner") from None
    status = gateway["status"]
    if gateway.get("spec", {}).get("replicas") != 1 or len(status.get("endpoints", [])) != 1:
        raise StageError("gateway-baseline", "gateway-owner")
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
        raise StageError("gateway-baseline", "gateway-applied-hash")
    config = json.loads(raw)
    if (not isinstance(config, dict) or type(status.get("gatewayID")) is not int or
            config.get("gatewayID") != status.get("gatewayID") or
            config.get("encryption") != "none" or
            not isinstance(config.get("clients"), list) or
            not all(isinstance(ip, str) for ip in config["clients"])):
        raise StageError("gateway-baseline", "gateway-client-membership")
    return {"gatewayUID": expected_uid, "gatewayID": status["gatewayID"],
            "podUID": pod["metadata"]["uid"], "podName": pod["metadata"]["name"],
            "endpoint": ep["podIP"], "hash": digest, "clients": config["clients"]}


def selected_state(api, owner, ids, gateway, uid):
    apps = owner.names[1]
    pod = api.get("pod", "synthetic-client", apps)
    if pod.get("metadata", {}).get("uid") != uid:
        raise SelectedUIDChanged()
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
        raise StageError("selected-ready", "selected-readiness")
    return pod


def await_stage(owner, stage, predicate, *, seconds, clock=time.monotonic, sleep=time.sleep):
    """Bounded reconciliation; emit only fixed last-failure labels at expiry."""
    if stage not in ("gateway-baseline", "selected-ready", "replacement-ready", "agent-restart-ready"):
        raise ValueError("Unknown poll checkpoint")
    limit = min(owner.deadline, clock() + seconds)
    reason = "blocked"
    while clock() < limit:
        if owner.closed or owner.clock() >= owner.deadline:
            raise StageError(stage)
        try:
            result = predicate()
            if result is not None:
                return result
            reason = "blocked"
        except SelectedUIDChanged:
            raise
        except StageError as exc:
            reason = exc.reason
        except Blocked:
            reason = "blocked"
        except adapter.AdapterError:
            reason = "adapter-read"
        except (evidence.EvidenceError, ha.ha_live.Blocked,
                KeyError, ValueError, TypeError, AttributeError):
            reason = "blocked"
        remaining = limit - clock()
        if remaining > 0:
            sleep(min(2, remaining))
    raise StageError(stage, reason)


def checkpoint(stage, operation):
    """Sanitize a non-poll failure without exposing adapter/API exception data."""
    if stage not in StageError.STAGES:
        raise ValueError("Unknown gateway replacement checkpoint")
    try:
        return operation()
    except (KeyboardInterrupt, SystemExit, lifecycle.Interrupted):
        raise
    except SelectedUIDChanged:
        raise
    except StageError as exc:
        raise StageError(stage, exc.reason) from None
    except BaseException:
        raise StageError(stage) from None


def agent_snapshot(readonly, namespace, node, image, *, expected_ds_uid=None):
    """One Ready, owner-bound agent Pod on the selected workload's exact node.

    ReadOnlyAPI is restricted to the already-preflighted release namespace;
    the selector comes only from the controller-owned DaemonSet, never the Pod.
    """
    if (not isinstance(namespace, str) or not ha.ha_live.NAME.fullmatch(namespace) or
            not isinstance(node, str) or node not in node_images.NODES or
            not isinstance(image, str) or not run.ID_PATTERN.fullmatch(image)):
        raise StageError("agent-baseline", "agent-node")
    daemon = readonly.get("daemonset", "ratatoskr-agent", namespace)
    meta, spec = daemon["metadata"], daemon["spec"]
    selector = spec["selector"]["matchLabels"]
    uid = meta.get("uid")
    if (meta.get("name") != "ratatoskr-agent" or meta.get("namespace") != namespace or
            not isinstance(uid, str) or not lifecycle.UID.fullmatch(uid) or
            meta.get("deletionTimestamp") or
            expected_ds_uid is not None and uid != expected_ds_uid or
            not isinstance(selector, dict) or not selector or
            any(not isinstance(k, str) or not isinstance(v, str) or
                not re.fullmatch(r"[a-z0-9./-]{1,63}", k) or
                not re.fullmatch(r"[a-z0-9-]{1,63}", v) for k, v in selector.items()) or
            selector.get("app.kubernetes.io/name") != "ratatoskr" or
            selector.get("app.kubernetes.io/component") != "agent"):
        raise StageError("agent-baseline", "agent-owner")
    # Only these chart-owned labels can enter a kubectl selector; the release
    # instance must match the already preflighted DaemonSet template exactly.
    template_labels = spec["template"]["metadata"]["labels"]
    if any(template_labels.get(k) != v for k, v in selector.items()):
        raise StageError("agent-baseline", "agent-owner")
    selector_text = ",".join(k + "=" + v for k, v in sorted(selector.items()))
    pods = readonly.get("pods", namespace=namespace, selector=selector_text)
    if pods.get("kind") != "List" or not isinstance(pods.get("items"), list) or len(pods["items"]) > 8:
        raise StageError("agent-baseline", "agent-owner")
    # A terminating old Pod overlapping its replacement is allowed; never
    # accept two live Pods on the same node, even if only one is Ready.
    live = [p for p in pods["items"] if p.get("spec", {}).get("nodeName") == node and
            not p.get("metadata", {}).get("deletionTimestamp")]
    if len(live) != 1:
        raise StageError("agent-baseline", "agent-node")
    pod = live[0]
    pmeta = pod["metadata"]
    containers = [c for c in pod.get("spec", {}).get("containers", []) if c.get("name") == "agent"]
    template = [c for c in spec["template"]["spec"].get("containers", []) if c.get("name") == "agent"]
    statuses = [s for s in pod.get("status", {}).get("containerStatuses", []) if s.get("name") == "agent"]
    if (pod.get("kind") != "Pod" or pmeta.get("namespace") != namespace or
            not isinstance(pmeta.get("uid"), str) or not lifecycle.UID.fullmatch(pmeta["uid"]) or
            not run.owner_is(pod, "DaemonSet", uid) or
            any(pmeta.get("labels", {}).get(k) != v for k, v in selector.items()) or
            pod.get("status", {}).get("phase") != "Running" or not run.ready(pod) or
            len(containers) != 1 or len(template) != 1 or len(statuses) != 1 or
            containers[0].get("image") != template[0].get("image") or
            containers[0].get("imagePullPolicy") != "Never" or
            template[0].get("imagePullPolicy") != "Never" or
            statuses[0].get("ready") is not True or statuses[0].get("imageID") != image):
        raise StageError("agent-baseline", "agent-runtime")
    return {"daemonUID": uid, "agentUID": pmeta["uid"], "node": node}


def external_agent_restart(api, owner, ids, gateway, selected_uid, api_ip, *,
                           readonly, release_namespace, ready_callback,
                           expected_daemon_uid=None, clock=time.monotonic, sleep=time.sleep):
    """Pure observer: parent alone may restart an exact agent Pod externally."""
    if ready_callback is None or not callable(ready_callback):
        raise StageError("agent-baseline")
    if not isinstance(release_namespace, str) or not ha.ha_live.NAME.fullmatch(release_namespace):
        raise StageError("agent-baseline", "agent-node")
    def baseline():
        selected = selected_state(api, owner, ids, gateway, selected_uid)
        node = selected.get("spec", {}).get("nodeName")
        if node not in node_images.NODES:
            raise StageError("agent-baseline", "agent-node")
        return agent_snapshot(readonly, release_namespace, node, ids["agent"],
                              expected_ds_uid=expected_daemon_uid)
    before = checkpoint("agent-baseline", baseline)
    node = before["node"]
    if owner.deadline - clock() < 165:
        raise StageError("agent-baseline")
    # No mutation here. A parent-owned callback can signal a separate, exact
    # UID-preconditioned agent Pod restart while this owned selected Pod lives.
    checkpoint("agent-baseline", lambda: ready_callback(node, before["agentUID"], before["daemonUID"]))
    def replacement():
        if api.get("pod", "synthetic-client", owner.names[1])["metadata"].get("uid") != selected_uid:
            raise SelectedUIDChanged()
        observed = agent_snapshot(readonly, release_namespace, node, ids["agent"],
                                  expected_ds_uid=before["daemonUID"])
        current = gateway_state(api, owner, ids, gateway["gatewayUID"])
        if current != gateway:
            return None
        selected_state(api, owner, ids, current, selected_uid)
        if observed["agentUID"] == before["agentUID"]:
            return None
        return observed
    # The 150-second window is part of the existing 700-second owner budget;
    # separate Lifecycle cleanup_budget is retained for failure and success.
    after = await_stage(owner, "agent-restart-ready", replacement, seconds=150,
                        clock=clock, sleep=sleep)
    def verify():
        if replacement() != after:
            raise StageError("agent-restart-probe")
        if api.probe_running("synthetic-client", selected_uid, ids["selected"],
                             "healthy", api_ip) is not True:
            raise StageError("agent-restart-probe")
        if replacement() != after:
            raise StageError("agent-restart-probe")
    checkpoint("agent-restart-probe", verify)
    return True


def replace(api, owner, ids, created, api_ip, *, clock=time.monotonic, sleep=time.sleep,
            restart_reader=None, release_namespace=None, ready_callback=None,
            expected_daemon_uid=None):
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
    identity = checkpoint("selected-create", lambda: api.create(
        prepare.running_probe_pod(apps, ns, api_ip)))
    if ((identity.get("kind"), identity.get("namespace"), identity.get("name")) !=
            ("Pod", apps, "synthetic-client") or
            not isinstance(identity.get("uid"), str) or not lifecycle.UID.fullmatch(identity["uid"])):
        raise StageError("selected-create")
    uid = identity["uid"]
    def initial():
        current = gateway_state(api, owner, ids, gw_uid)
        if any(current[key] != before[key] for key in ("gatewayUID", "gatewayID", "podUID", "endpoint")):
            raise Blocked("Initial Gateway Pod changed before controlled deletion.")
        selected_state(api, owner, ids, current, uid)
        return current
    before = await_stage(owner, "selected-ready", initial, seconds=160, clock=clock, sleep=sleep)
    def baseline_probe():
        if api.probe_running("synthetic-client", uid, ids["selected"], "healthy", api_ip) is not True:
            raise StageError("baseline-probe")
        selected_state(api, owner, ids, before, uid)
        if gateway_state(api, owner, ids, gw_uid) != before:
            raise StageError("baseline-probe")
    checkpoint("baseline-probe", baseline_probe)
    # delete_chosen_gateway_pod GETs the generated Pod's current status and
    # rechecks Deployment→ReplicaSet→Pod ownership before sending exactly one
    # UID-preconditioned, five-second-grace DELETE.
    checkpoint("gateway-delete", lambda: api.delete_chosen_gateway_pod(
        ns, before["podName"], before["podUID"]))
    def replacement():
        # Check exact old selected UID BEFORE any retryable gateway transition.
        if api.get("pod", "synthetic-client", apps)["metadata"].get("uid") != uid:
            raise SelectedUIDChanged()
        current = gateway_state(api, owner, ids, gw_uid)
        if (current["gatewayID"] != before["gatewayID"] or
                current["podUID"] == before["podUID"] or
                current["endpoint"] == before["endpoint"]):
            return None
        selected_state(api, owner, ids, current, uid)
        return current
    after = await_stage(owner, "replacement-ready", replacement, seconds=135, clock=clock, sleep=sleep)
    def replacement_probe():
        sleep(2)
        if replacement() != after:
            raise StageError("replacement-probe")
        if api.probe_running("synthetic-client", uid, ids["selected"], "healthy", api_ip) is not True:
            raise StageError("replacement-probe")
        if replacement() != after:
            raise StageError("replacement-probe")
        if partial_gateway.source_ready(api.get("pod", "synthetic-vpn", ns),
                                        api.get("service", "synthetic-vpn", ns), ids["server"])["metadata"]["uid"] != source_uid:
            raise StageError("replacement-probe")
    checkpoint("replacement-probe", replacement_probe)
    result = {"sameSelectedPodUID": True, "newGatewayPodUIDAndIP": True,
              "newConnectionMarker": True, "establishedFlowContinuity": "not-asserted",
              "agentRestart": "not-tested"}
    if restart_reader is not None:
        external_agent_restart(api, owner, ids, after, uid, api_ip,
                               readonly=restart_reader, release_namespace=release_namespace,
                               ready_callback=ready_callback, expected_daemon_uid=expected_daemon_uid,
                               clock=clock, sleep=sleep)
        result["agentRestart"] = "observed"
        result["agentRestartObserved"] = True
    return result


def execute(ids, api_ip, *, lifecycle_factory=lifecycle.Lifecycle, adapter_factory=LifecycleAPI,
            clock=time.monotonic, sleep=time.sleep, restart_reader=None,
            release_namespace=None, ready_callback=None, expected_daemon_uid=None):
    if (not isinstance(ids, dict) or set(ids) != set(run.COMPONENTS) or
            any(not isinstance(v, str) or not run.ID_PATTERN.fullmatch(v) for v in ids.values())):
        raise Blocked("Immutable approved image IDs missing.")
    ha.ha_live.ip4(api_ip)
    if restart_reader is not None and (ready_callback is None or not callable(ready_callback) or
                                      not isinstance(release_namespace, str) or
                                      not ha.ha_live.NAME.fullmatch(release_namespace)):
        raise StageError("agent-baseline")
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
            return replace(api, owner, ids, created, api_ip, clock=clock, sleep=sleep,
                           restart_reader=restart_reader, release_namespace=release_namespace,
                           ready_callback=ready_callback, expected_daemon_uid=expected_daemon_uid)
        except (StageError, KeyboardInterrupt, SystemExit):
            raise
        except BaseException:
            raise StageError(stage) from None


def main(argv=None, environ=None, *, readonly_factory=run.ReadOnlyAPI,
         restart_reader_factory=run.ReadOnlyAPI, executor=execute):
    parser = argparse.ArgumentParser(description="Gated existing-client singleton gateway replacement")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--execute-agent-gateway-replacement", action="store_true")
    parser.add_argument("--wait-external-agent-restart", action="store_true")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    if (not args.execute or not args.execute_agent_gateway_replacement or
            env.get("RATATOSKR_E2E_FINAL_GATE") != "1" or
            env.get("RATATOSKR_E2E_AGENT_GATEWAY_REPLACEMENT") != "1" or
            args.wait_external_agent_restart and env.get("RATATOSKR_E2E_AGENT_RESTART") != "1"):
        print("SKIPPED: explicit gateway-replacement final gate absent; no cluster accessed.")
        return 2
    try:
        ids = run.expected_ids(env)
        readonly = readonly_factory()
        release_namespace = run.preflight(readonly, ids)
        expected_daemon_uid = None
        if args.wait_external_agent_restart:
            daemon = readonly.get("daemonset", "ratatoskr-agent", release_namespace)
            expected_daemon_uid = daemon.get("metadata", {}).get("uid")
            if (not isinstance(expected_daemon_uid, str) or
                    not lifecycle.UID.fullmatch(expected_daemon_uid)):
                raise StageError("agent-baseline", "agent-owner")
        node_images.verify({component: ids[component] for component in node_images.TAGS})
        ip = partial_gateway.api_service_ip(readonly)
        if args.wait_external_agent_restart:
            # stdout is a fixed protocol; never disclose Pod/DaemonSet UID or
            # node identity. Parent reads them from its own authenticated API.
            def ready_callback(_node, _pod_uid, _daemon_uid):
                print("READY: externally restart the UID-owned agent Pod on the selected node.", flush=True)
            result = executor(ids, ip, restart_reader=restart_reader_factory(budget=900),
                              release_namespace=release_namespace, ready_callback=ready_callback,
                              expected_daemon_uid=expected_daemon_uid)
        else:
            result = executor(ids, ip)
        expected = {"sameSelectedPodUID": True, "newGatewayPodUIDAndIP": True,
                    "newConnectionMarker": True, "establishedFlowContinuity": "not-asserted",
                    "agentRestart": "not-tested"}
        if args.wait_external_agent_restart:
            expected["agentRestart"] = "observed"
            expected["agentRestartObserved"] = True
        if result != expected:
            raise Blocked("Existing-client replacement marker incomplete.")
        if args.wait_external_agent_restart:
            print("PARTIAL: existing selected Pod healthy after external agent Pod restart; established flows NOT TESTED.")
        else:
            print("PARTIAL: existing selected Pod healthy on replacement Gateway Pod; established flows and agent restart NOT TESTED.")
        return 4
    except (KeyboardInterrupt, SystemExit):
        print("FAILED: gateway replacement interrupted; inspect UID-owned namespace cleanup.")
        return 1
    except StageError as failure:
        # StageError has a fixed allowlist, never interpolates API/adapter text.
        print("FAILED: " + str(failure) + " Inspect UID-owned cleanup privately.")
        return 1
    except BaseException:
        print("FAILED: gateway replacement blocked; inspect UID-owned cleanup privately.")
        return 1


if __name__ == "__main__":
    sys.exit(main())
