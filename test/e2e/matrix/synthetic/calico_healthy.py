#!/usr/bin/env python3
"""Separate opt-in Calico/no-mesh agent/iproute healthy synthetic subset.

No cluster creation, CNI installation, release rollout or variant switch.
No outage, init, WireGuard, full-matrix PASS or destructive cluster action.
The owner/operator must approve the existing Calico context before executing.
"""
import argparse
import os
import sys

try:
    from . import environment, node_images, partial_gateway, run
except ImportError:
    import environment
    import node_images
    import partial_gateway
    import run


class Blocked(Exception):
    """Only fixed, non-secret checkpoints may escape the final-gate runner."""


def preflight(environ, *, api_factory=run.ReadOnlyAPI, verifier=node_images.verify):
    """Shared read-only existing-Calico agent preflight; no fixture mutation."""
    try:
        ids = run.expected_ids(environ)
        api = api_factory(environment=environment.CALICO)
        if (not isinstance(api, run.ReadOnlyAPI) or
                api.environment != environment.CALICO):
            raise Blocked("context")
        namespace = run.preflight(api, ids, environment=environment.CALICO)
        if not namespace:
            raise Blocked("release")
        images = {component: ids[component] for component in node_images.TAGS}
        if verifier(images, environment=environment.CALICO,
                    observed_nodes=environment.CALICO.nodes) is not True:
            raise Blocked("images")
        controller = api.get("deployment", "ratatoskr-controller", namespace)
        containers = [c for c in controller["spec"]["template"]["spec"]["containers"]
                      if c.get("name") == "controller"]
        if len(containers) != 1:
            raise Blocked("release")
        values = {item.get("name"): item.get("value") for item in containers[0].get("env", [])}
        if (values.get("GATEWAY_IMAGE") != "ghcr.io/skaldhall/ratatoskr-gateway:dev" or
                values.get("OPENVPN_IMAGE") != "ghcr.io/skaldhall/ratatoskr-upstream-openvpn:dev" or
                values.get("GATEWAY_UPSTREAM_PROBE_URL") != run.PROBE or
                values.get("IMAGE_PULL_POLICY") != "Never"):
            raise Blocked("release")
        ip = partial_gateway.api_service_ip(api)
    except (Blocked, run.Blocked, node_images.Blocked, KeyError, IndexError, StopIteration,
            TypeError, ValueError, AttributeError):
        raise Blocked("preflight") from None
    return ids, ip


def execute(environ, *, api_factory=run.ReadOnlyAPI, verifier=node_images.verify,
            smoke=partial_gateway.execute):
    """Authorize exactly one existing Calico context before any owned writes."""
    if (environ.get("RATATOSKR_E2E_FINAL_GATE") != "1" or
            environ.get("RATATOSKR_E2E_CALICO_HEALTHY") != "1"):
        raise Blocked("authorization")
    ids, ip = preflight(environ, api_factory=api_factory, verifier=verifier)
    try:
        result = smoke(ids, api_ip=ip, environment=environment.CALICO)
        if result is not False:
            raise Blocked("fixture")
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        # Lifecycle owns UID-precondition cleanup; never serialize its raw
        # exception, private fixture inputs or untrusted API response.
        raise Blocked("fixture-or-cleanup") from None
    return {"environment": "calico/none", "subset": "agent/iproute/healthy",
            "result": "INCOMPLETE", "fullMatrix": False}


def main(argv=None, environ=None):
    parser = argparse.ArgumentParser(description="Gated existing-Calico healthy synthetic subset")
    parser.add_argument("--execute-calico-healthy", action="store_true")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    if not (args.execute_calico_healthy and env.get("RATATOSKR_E2E_FINAL_GATE") == "1" and
            env.get("RATATOSKR_E2E_CALICO_HEALTHY") == "1"):
        print("SKIPPED: explicit existing-Calico healthy fixture authorization required; no cluster accessed.")
        return 2
    try:
        execute(env)
    except (KeyboardInterrupt, SystemExit):
        print("FAILED: Calico healthy synthetic interrupted; inspect UID-owned cleanup privately; no M8 PASS.")
        return 1
    except BaseException:
        # No untrusted API, PKI, subprocess or provider error may reach stdout.
        print("FAILED: existing Calico healthy synthetic preflight or UID-owned fixture cleanup blocked; no M8 PASS.")
        return 1
    print("INCOMPLETE: scoped existing-Calico healthy agent/iproute synthetic traffic and UID-owned cleanup verified; no outage, other CNI/mesh or full M8 PASS.")
    return 4


if __name__ == "__main__":
    sys.exit(main())
