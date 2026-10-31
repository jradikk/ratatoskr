#!/usr/bin/env python3
"""Independent Kubernetes Pod-bound TokenReview diagnostic; NOT gateway evidence.

No cluster access by default. The caller owns the disposable WireGuard selected
Pod and must pass its server-returned CREATE UID. Tokens and API responses stay
in memory, never in argv, files, logs, diagnostics, or reported evidence.
"""
import argparse
import json
import os
import re
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parents[1] / "matrix" / "synthetic"
if str(HERE) not in sys.path:
    sys.path.insert(0, str(HERE))
import adapter  # noqa: E402 - bounded, stderr-suppressed stdin transport
import lifecycle  # noqa: E402

AUDIENCE = "ratatoskr.skaldhall.io/gateway"
WRONG_AUDIENCE = "ratatoskr.skaldhall.io/gateway-negative"
POD = "synthetic-client"
LABEL = lifecycle.LABEL
TOKEN = re.compile(r"[0-9a-f]{32}\Z")


class Blocked(Exception):
    """Fixed, token-free diagnostic; do not print underlying exceptions."""


# These are authored checkpoint names, never untrusted Kubernetes/API text.
STAGES = frozenset({"namespace-pre", "pod-pre", "token-request", "positive-review",
                    "negative-review", "namespace-post", "pod-post"})


class StageBlocked(Blocked):
    """Sanitized operation checkpoint without raw API, token, or CLI output."""
    def __init__(self, stage):
        if stage not in STAGES:
            raise Blocked("Independent TokenReview checkpoint invalid.")
        self.stage = stage
        super().__init__("Independent TokenReview blocked at " + stage + ".")


def require(condition):
    if not condition:
        raise Blocked("Independent TokenReview identity or audience check failed.")


def identity(namespace, uid, service_account, token, gateway):
    """Reject nonfixture Pods, arbitrary gateways, and unowned identity inputs."""
    require(type(token) is str and TOKEN.fullmatch(token) is not None and
            namespace == "rtk-syn-" + token[:16] + "-apps" and
            type(uid) is str and lifecycle.UID.fullmatch(uid) is not None and
            service_account == "default" and
            gateway == "rtk-wg-" + token[:16])


def validate_namespace(obj, namespace, token):
    require(type(obj) is dict and obj.get("kind") == "Namespace" and
            obj.get("metadata", {}).get("name") == namespace and
            obj["metadata"].get("labels", {}).get(LABEL) == token and
            isinstance(obj["metadata"].get("uid"), str) and
            lifecycle.UID.fullmatch(obj["metadata"]["uid"]) is not None and
            not obj["metadata"].get("deletionTimestamp"))
    return obj["metadata"]["uid"]


def validate_pod(obj, namespace, uid, service_account, token, gateway):
    require(type(obj) is dict and obj.get("kind") == "Pod" and
            obj.get("metadata", {}).get("namespace") == namespace and
            obj["metadata"].get("name") == POD and obj["metadata"].get("uid") == uid and
            obj["metadata"].get("labels", {}).get(LABEL) == token and
            obj["metadata"]["labels"].get("ratatoskr.skaldhall.io/gateway") == gateway and
            obj["metadata"]["labels"].get("ratatoskr.skaldhall.io/gateway-namespace") == "ratatoskr-system" and
            not obj["metadata"].get("deletionTimestamp") and
            obj.get("spec", {}).get("serviceAccountName", "default") == service_account)


def validate_request(obj, namespace, uid, service_account):
    """TokenRequest response is not required to echo boundObjectRef."""
    require(type(obj) is dict and obj.get("kind") == "TokenRequest" and
            type(obj.get("status", {}).get("token")) is str and
            bool(obj["status"]["token"]) and
            type(obj["status"].get("expirationTimestamp")) is str and
            bool(obj["status"]["expirationTimestamp"]))
    spec = obj.get("spec")
    if spec is not None:
        require(type(spec) is dict and spec.get("audiences") == [AUDIENCE] and
                spec.get("boundObjectRef") == {"kind": "Pod", "apiVersion": "v1",
                                               "name": POD, "uid": uid})
    return obj["status"]["token"]


def validate_review(obj, namespace, uid, service_account, *, positive):
    require(type(obj) is dict and obj.get("kind") == "TokenReview" and
            type(obj.get("status")) is dict)
    status = obj["status"]
    if not positive:
        # Kubernetes omits the false zero value (authenticated,omitempty).
        # Accept only absence or an exact boolean false, never null/0/strings.
        require("authenticated" not in status or status["authenticated"] is False)
        return
    user = status.get("user")
    require(status.get("authenticated") is True and
            isinstance(status.get("audiences"), list) and AUDIENCE in status["audiences"] and
            type(user) is dict and
            user.get("username") == "system:serviceaccount:" + namespace + ":" + service_account and
            type(user.get("extra")) is dict and
            user["extra"].get("authentication.kubernetes.io/pod-name") == [POD] and
            user["extra"].get("authentication.kubernetes.io/pod-uid") == [uid])


def _call(args, *, payload=None, max_output=8192, timeout=12, transport=adapter._bounded):
    require(0 < timeout <= 12)
    raw = transport(["kubectl", "--context", lifecycle.CONTEXT,
                     "--request-timeout=10s", *args], payload=payload,
                    timeout=timeout, max_output=max_output)
    require(type(raw) is bytes and len(raw) <= max_output)
    try:
        result = json.loads(raw)
        require(type(result) is dict)
        return result
    except (ValueError, UnicodeError, TypeError):
        raise Blocked("Independent TokenReview API response malformed.") from None


def execute(namespace, uid, service_account, token, gateway, *, transport=adapter._bounded,
            remaining=None):
    """One bounded, separately opted-in diagnostic against the current owned Pod.

    This does NOT observe whether the gateway submitted its own TokenReview.
    The Pod may only be named synthetic-client in the Lifecycle-owned apps NS.
    Direct in-process callers must also hold all three explicit environment gates.
    """
    require(os.environ.get("RATATOSKR_E2E_FINAL_GATE") == "1" and
            os.environ.get("RATATOSKR_E2E_WG_SYNTHETIC") == "1" and
            os.environ.get("RATATOSKR_E2E_TOKENREVIEW") == "1")
    identity(namespace, uid, service_account, token, gateway)
    def checkpoint(stage, args, *, validator, payload=None, max_output=8192):
        # Never expose the raw response, bearer, subprocess diagnostics or
        # parser exception even when called directly by the owned fixture.
        try:
            timeout = 12 if remaining is None else min(12, remaining())
            result = _call(args, payload=payload, max_output=max_output,
                           timeout=timeout, transport=transport)
            return validator(result)
        except (KeyboardInterrupt, SystemExit, lifecycle.Interrupted):
            raise
        except BaseException:
            raise StageBlocked(stage) from None

    ns_args = ["get", "namespace", namespace, "-o", "json"]
    pod_args = ["get", "pod", POD, "--namespace", namespace, "-o", "json"]
    ns_uid = checkpoint("namespace-pre", ns_args,
                        validator=lambda obj: validate_namespace(obj, namespace, token))
    checkpoint("pod-pre", pod_args, max_output=65536,
               validator=lambda obj: validate_pod(obj, namespace, uid, service_account,
                                                  token, gateway))
    body = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenRequest",
            "spec": {"audiences": [AUDIENCE], "expirationSeconds": 600,
                     "boundObjectRef": {"apiVersion": "v1", "kind": "Pod", "name": POD, "uid": uid}}}
    request_path = "/api/v1/namespaces/" + namespace + "/serviceaccounts/" + service_account + "/token"
    bearer = checkpoint("token-request", ["create", "--raw", request_path, "-f", "-"],
                        validator=lambda obj: validate_request(obj, namespace, uid, service_account),
                        payload=json.dumps(body, separators=(",", ":")).encode(), max_output=16384)
    # A single Pod-bound token is reviewed under both audiences; never put it
    # into process argv. The second review MUST be unauthenticated outright.
    for audience, positive, stage in ((AUDIENCE, True, "positive-review"),
                                      (WRONG_AUDIENCE, False, "negative-review")):
        review = {"apiVersion": "authentication.k8s.io/v1", "kind": "TokenReview",
                  "spec": {"token": bearer, "audiences": [audience]}}
        checkpoint(stage, ["create", "--raw", "/apis/authentication.k8s.io/v1/tokenreviews", "-f", "-"],
                   payload=json.dumps(review, separators=(",", ":")).encode(), max_output=8192,
                   validator=lambda obj: validate_review(obj, namespace, uid, service_account,
                                                         positive=positive))
    checkpoint("namespace-post", ns_args,
               validator=lambda obj: require(validate_namespace(obj, namespace, token) == ns_uid))
    checkpoint("pod-post", pod_args, max_output=65536,
               validator=lambda obj: validate_pod(obj, namespace, uid, service_account,
                                                  token, gateway))
    return {"independentKubernetesTokenReview": "exact-pod-uid-sa-audience-and-negative-audience-verified",
            "gatewayTokenReviewObserved": False}


def main(argv=None):
    parser = argparse.ArgumentParser(description="Independent owned-Pod Kubernetes TokenReview diagnostic")
    parser.add_argument("--execute", action="store_true")
    parser.add_argument("--namespace")
    parser.add_argument("--pod-uid")
    parser.add_argument("--service-account")
    parser.add_argument("--lifecycle-token")
    parser.add_argument("--gateway")
    args = parser.parse_args(argv)
    if not (args.execute and os.environ.get("RATATOSKR_E2E_FINAL_GATE") == "1" and
            os.environ.get("RATATOSKR_E2E_WG_SYNTHETIC") == "1" and
            os.environ.get("RATATOSKR_E2E_TOKENREVIEW") == "1"):
        print("SKIPPED: independent TokenReview authorization required; no cluster accessed.")
        return 2
    try:
        execute(args.namespace, args.pod_uid, args.service_account,
                args.lifecycle_token, args.gateway)
    except StageBlocked as err:
        print("FAILED: " + str(err) + " Gateway behavior unverified.")
        return 1
    except (Blocked, adapter.AdapterError, KeyError, ValueError, TypeError, AttributeError):
        print("FAILED: independent Kubernetes TokenReview check blocked; gateway behavior unverified.")
        return 1
    print("INDEPENDENT KUBERNETES TOKENREVIEW VERIFIED: owned Pod UID, SA and audiences; gateway behavior unverified; no M8 PASS.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
