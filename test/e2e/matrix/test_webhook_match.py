"""Pure exact CEL registration contract: annotation, labels and old UPDATE state."""
import importlib.util
from pathlib import Path
import sys
import unittest

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("synthetic_webhook_match_test", HERE / "webhook_match.py")
contract = importlib.util.module_from_spec(spec)
spec.loader.exec_module(contract)


class WebhookMatchTest(unittest.TestCase):
    def test_create_and_update_exact_expression_no_object_selector(self):
        for validate, expression in ((False, contract.CREATE), (True, contract.UPDATE)):
            hook = {"matchConditions": [{"name": "gateway-opt-in", "expression": expression}]}
            self.assertTrue(contract.matches(hook, validate=validate))
            for broken in ({**hook, "objectSelector": {"matchLabels": {"ratatoskr.skaldhall.io/gateway": ""}}},
                           {"matchConditions": []},
                           {"matchConditions": [hook["matchConditions"][0], hook["matchConditions"][0]]},
                           {"matchConditions": [{"name": "other", "expression": expression}]},
                           {"matchConditions": [{"name": "gateway-opt-in", "expression": expression.replace("annotations", "labels")}]},
                           {"matchConditions": [{"name": "gateway-opt-in", "expression": "true"}]},
                           {"matchConditions": [{"name": "gateway-opt-in", "expression": contract.UPDATE if not validate else contract.CREATE}]}):
                with self.subTest(broken=broken):
                    self.assertFalse(contract.matches(broken, validate=validate))


if __name__ == "__main__":
    unittest.main()
