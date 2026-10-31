"""Pure acceptance predicate over independently collected M4/M5 WireGuard evidence.

This module never collects cluster evidence or handles bearer tokens/private keys.
Caller must establish the provenance of each observation in its final-gate report.
"""
import ipaddress


class EvidenceError(ValueError):
    pass


def require(condition, message):
    if not condition:
        raise EvidenceError(message)


def integer(value):
    return type(value) is int and value >= 0


def counter(before, after, label, increase=True):
    require(integer(before) and integer(after) and after >= before,
            label + " counter invalid or reset")
    if increase:
        require(after > before, label + " did not increase")
    else:
        require(after == before, label + " changed")


def ipv4(value):
    try:
        ip = ipaddress.ip_address(value)
    except (ValueError, TypeError):
        raise EvidenceError("invalid PodIP") from None
    require(ip.version == 4 and not (ip.is_unspecified or ip.is_multicast or ip.is_loopback),
            "invalid PodIP")
    return str(ip)


def validate(evidence):
    """Require registration, authenticated delivery, plaintext rejection, revocation.

    The parent collector must supply sequential, fresh measurements for the SAME
    flow/Pod/gateway; counters alone are insufficient without packet identity.
    No positive evidence is inferred from API configuration or readiness alone.
    """
    require(type(evidence) is dict and evidence.get("schemaVersion") == 1,
            "unsupported evidence schema")
    identity = evidence.get("identity")
    require(type(identity) is dict and identity.get("driver") == "agent" and
            identity.get("datapath") == "iproute" and
            identity.get("encryption") == "wireguard", "wrong mode")
    client, gateway = ipv4(identity.get("clientPodIP")), ipv4(identity.get("gatewayPodIP"))
    require(client != gateway and type(identity.get("clientPodUID")) is str and
            bool(identity["clientPodUID"]) and type(identity.get("gatewayPodUID")) is str and
            bool(identity["gatewayPodUID"]) and type(identity.get("gatewayID")) is int and
            identity["gatewayID"] > 0, "invalid identities")
    require(set(evidence) == {"schemaVersion", "identity", "registered", "plain", "authenticated", "revoked"},
            "missing or unexpected evidence sections")
    reg, plain, auth, revoked = (evidence[k] for k in
                                  ("registered", "plain", "authenticated", "revoked"))
    require(all(type(s) is dict for s in (reg, plain, auth, revoked)), "invalid stage")
    require(reg.get("tokenReviewAuthenticated") is True and
            reg.get("podUIDMatched") is True and reg.get("audienceMatched") is True and
            reg.get("pinnedTLS") is True and reg.get("gatewayPeerAllowedIP") == client + "/32" and
            reg.get("clientPeerAllowedIP") == gateway + "/32" and
            reg.get("gatewayReturnRoute") == client + "/32" and
            reg.get("clientMarkerUp") is True, "registration/identity/route unverified")
    require(plain.get("outerSrc") == client and plain.get("outerDst") == gateway and
            plain.get("udpDstPort") == 6081 and plain.get("gatewayEth0Capture") is True and
            plain.get("gatewayGnv0Capture") is False and
            plain.get("markerDelivered") is False, "plaintext GENEVE rejection unverified")
    counter(plain.get("dropBefore"), plain.get("dropAfter"), "plaintext nft drop")
    require(auth.get("markerOverWG") is True and auth.get("gatewayGnv0Capture") is True and
            auth.get("markerDelivered") is True and auth.get("clientWgPeer") == gateway and
            auth.get("gatewayWgPeer") == client and
            auth.get("underlayWgTransportObserved") is True and
            auth.get("underlayPlainGeneveObserved") is False,
            "authenticated packet delivery or encrypted underlay unverified")
    counter(auth.get("clientWgTxBefore"), auth.get("clientWgTxAfter"), "client WG TX")
    counter(auth.get("gatewayWgRxBefore"), auth.get("gatewayWgRxAfter"), "gateway WG RX")
    require(revoked.get("reason") in ("pod-deleted", "opt-out", "ttl") and
            revoked.get("gatewayPeerAbsent") is True and
            revoked.get("gatewayRouteAbsent") is True and
            revoked.get("gatewayFallbackUnreachable") is True and
            revoked.get("newMarkerDelivered") is False and
            revoked.get("directFallback") is False, "post-revoke fail-close unverified")
    counter(revoked.get("attemptBefore"), revoked.get("attemptAfter"), "post-revoke selected attempt")
    return True
