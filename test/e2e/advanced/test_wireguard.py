"""Cluster-free synthetic evidence, never live traffic or credentials."""
import copy
import unittest

from wireguard import EvidenceError, validate


def sample():
    return {
        "schemaVersion": 1,
        "identity": {"driver": "agent", "datapath": "iproute", "encryption": "wireguard",
                     "clientPodUID": "uid-client", "gatewayPodUID": "uid-gateway", "gatewayID": 7,
                     "clientPodIP": "10.42.1.8", "gatewayPodIP": "10.42.2.4"},
        "registered": {"tokenReviewAuthenticated": True, "podUIDMatched": True,
                       "audienceMatched": True, "pinnedTLS": True,
                       "gatewayPeerAllowedIP": "10.42.1.8/32",
                       "clientPeerAllowedIP": "10.42.2.4/32",
                       "gatewayReturnRoute": "10.42.1.8/32", "clientMarkerUp": True},
        "plain": {"outerSrc": "10.42.1.8", "outerDst": "10.42.2.4",
                  "udpDstPort": 6081, "gatewayEth0Capture": True,
                  "gatewayGnv0Capture": False, "markerDelivered": False,
                  "dropBefore": 2, "dropAfter": 3},
        "authenticated": {"markerOverWG": True, "gatewayGnv0Capture": True,
                          "markerDelivered": True, "clientWgPeer": "10.42.2.4",
                          "gatewayWgPeer": "10.42.1.8", "underlayWgTransportObserved": True,
                          "underlayPlainGeneveObserved": False, "clientWgTxBefore": 5,
                          "clientWgTxAfter": 6, "gatewayWgRxBefore": 8, "gatewayWgRxAfter": 9},
        "revoked": {"reason": "pod-deleted", "gatewayPeerAbsent": True,
                    "gatewayRouteAbsent": True, "gatewayFallbackUnreachable": True,
                    "newMarkerDelivered": False, "directFallback": False,
                    "attemptBefore": 4, "attemptAfter": 5},
    }


class WireGuardAcceptanceTest(unittest.TestCase):
    def test_complete_evidence(self):
        self.assertTrue(validate(sample()))

    def test_rejects_missing_stage(self):
        for stage in ("registered", "plain", "authenticated", "revoked"):
            with self.subTest(stage=stage):
                evidence = sample()
                del evidence[stage]
                with self.assertRaises(EvidenceError):
                    validate(evidence)

    def test_rejects_false_positive_observations(self):
        cases = (
            ("identity", "driver", "init"),
            ("identity", "encryption", "none"),
            ("registered", "tokenReviewAuthenticated", False),
            ("registered", "pinnedTLS", False),
            ("registered", "gatewayPeerAllowedIP", "10.42.1.0/24"),
            ("plain", "gatewayGnv0Capture", True),
            ("plain", "dropAfter", 2),
            ("authenticated", "markerDelivered", False),
            ("authenticated", "underlayPlainGeneveObserved", True),
            ("authenticated", "underlayWgTransportObserved", False),
            ("authenticated", "clientWgTxAfter", 5),
            ("authenticated", "gatewayWgRxAfter", 8),
            ("revoked", "gatewayPeerAbsent", False),
            ("revoked", "gatewayRouteAbsent", False),
            ("revoked", "directFallback", True),
            ("revoked", "attemptAfter", 4),
        )
        for stage, field, value in cases:
            with self.subTest(stage=stage, field=field):
                evidence = copy.deepcopy(sample())
                evidence[stage][field] = value
                with self.assertRaises(EvidenceError):
                    validate(evidence)

    def test_rejects_boolean_counters_and_wrong_peer(self):
        for stage, field, value in (("plain", "dropAfter", True),
                                    ("authenticated", "gatewayWgPeer", "10.42.1.9"),
                                    ("revoked", "gatewayFallbackUnreachable", False)):
            with self.subTest(stage=stage, field=field):
                evidence = sample()
                evidence[stage][field] = value
                with self.assertRaises(EvidenceError):
                    validate(evidence)


if __name__ == "__main__":
    unittest.main()
