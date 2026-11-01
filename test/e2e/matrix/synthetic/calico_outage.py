#!/usr/bin/env python3
"""Separate opt-in existing-Calico witnessed outage/recovery synthetic subset.

Only an already approved Calico/no-mesh agent/iproute cluster and immutable
images; never provisions, installs, switches a release or claims full M8 PASS.
"""
import argparse
import os
import sys

try:
    from . import calico_healthy, environment, outage
except ImportError:
    import calico_healthy
    import environment
    import outage


class Blocked(Exception):
    """Only authored, non-secret final-gate failure category."""


def execute(environ, *, api_factory=calico_healthy.run.ReadOnlyAPI,
            verifier=calico_healthy.node_images.verify, smoke=outage.execute):
    """Reuse the healthy runner's exact context/release/CRI preflight first."""
    if (environ.get("RATATOSKR_E2E_FINAL_GATE") != "1" or
            environ.get("RATATOSKR_E2E_CALICO_OUTAGE") != "1"):
        raise Blocked("authorization")
    try:
        ids, api_ip = calico_healthy.preflight(environ, api_factory=api_factory,
                                                verifier=verifier)
    except BaseException:
        raise Blocked("preflight") from None
    try:
        result = smoke(ids, api_ip=api_ip, environment=environment.CALICO)
        if result is not False:
            raise Blocked("fixture")
    except (KeyboardInterrupt, SystemExit):
        raise
    except BaseException:
        raise Blocked("fixture-or-cleanup") from None
    return {"environment": "calico/none", "subset": "agent/iproute/witnessed-outage-recovery",
            "result": "INCOMPLETE", "fullMatrix": False}


def main(argv=None, environ=None):
    parser = argparse.ArgumentParser(description="Existing-Calico witnessed outage/recovery subset")
    parser.add_argument("--execute-calico-outage", action="store_true")
    args = parser.parse_args(argv)
    env = os.environ if environ is None else environ
    if not (args.execute_calico_outage and env.get("RATATOSKR_E2E_FINAL_GATE") == "1" and
            env.get("RATATOSKR_E2E_CALICO_OUTAGE") == "1"):
        print("SKIPPED: explicit existing-Calico outage authorization required; no cluster accessed.")
        return 2
    try:
        execute(env)
    except (KeyboardInterrupt, SystemExit):
        print("FAILED: Calico outage interrupted; inspect UID-owned cleanup privately; no M8 PASS.")
        return 1
    except BaseException:
        print("FAILED: existing-Calico outage preflight or UID-owned fixture cleanup blocked; no M8 PASS.")
        return 1
    print("INCOMPLETE: scoped existing-Calico witnessed outage/recovery and UID-owned cleanup verified; other CNI/mesh and full M8 remain unverified.")
    return 4


if __name__ == "__main__":
    sys.exit(main())
