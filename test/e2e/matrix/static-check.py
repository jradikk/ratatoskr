#!/usr/bin/env python3
"""Pure static inventory/config checks. Never calls runner main or cluster commands."""
import importlib.util
import ipaddress
import json
from pathlib import Path
import sys
from unittest.mock import patch

sys.dont_write_bytecode = True
HERE = Path(__file__).resolve().parent


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def main():
    runner = load("matrix_static", HERE / "run.py")
    config = load("config_static", HERE / "client-config.py")
    for mode in ("fake", "live"):
        with patch.object(runner.subprocess, "Popen", side_effect=AssertionError("commands forbidden in static inventory")):
            spec, cells = runner.inventory(mode)
        require(len(cells) == 96, "expected 96 declared compatibility cells")
        require(len({cell["id"] for cell in cells}) == 96, "duplicate matrix cell")
        require(sum(cell["runnerImplemented"] for cell in cells) == 2, "only two flannel/no-mesh/init/none scaffolds exist")
        require(all(cell["status"] in {"SKIPPED", "DEFERRED"} for cell in cells), "static matrix must never mark a cell passed")
        require(all(not scenario["covered"] for cell in cells for scenario in cell["scenarios"]), "no traffic evidence exists")
        require(len({s["id"] for s in spec["scenarios"]}) == len(spec["scenarios"]), "duplicate scenario")
        for cell in cells:
            if cell["datapath"] == "ebpf" and cell["encryption"] == "wireguard":
                require(not cell["runnerImplemented"] and cell["status"] == "SKIPPED", "unsupported mode cannot downgrade")
            if cell["cni"] != "flannel" or cell["mesh"] != "none" or cell["driver"] == "agent":
                require(all(s["status"] == "SKIPPED" for s in cell["scenarios"]), "missing fixture cannot inherit M1 pass")
        # Empty inner report cannot accidentally count as successful evidence.
        chosen = next(cell for cell in cells if cell["runnerImplemented"])
        runner.apply_result(chosen, {"mode": mode, "status": "passed", "checks": []})
        require(not any(s["covered"] for s in chosen["scenarios"]), "missing checkpoints cannot pass")
        require(chosen["status"] == "INCOMPLETE", "partial inner run must never pass matrix")
        print(f"PASS static {mode} inventory: 96 cells, 2 implemented subsets, no coverage claimed")
    original = {"podIP": "10.42.2.10", "gatewayID": 7, "endpoint": "10.42.1.10", "mtu": 1400,
                "encryption": "none", "exclusions": ["10.42.0.0/16", "10.43.0.0/16", "10.42.1.10/32"]}
    remote = ipaddress.IPv4Address("10.42.0.10")
    for mode in config.MODES:
        rendered = config.build(original, str(remote), "10.42.0.0/16", mode)
        exclusions = [ipaddress.IPv4Network(p) for p in rendered["exclusions"]]
        require(not any(remote in p for p in exclusions), "controlled remote /32 must allow both routing choices")
        require(any(ipaddress.IPv4Address("10.42.2.10") in p for p in exclusions), "other pod paths must stay excluded")
        rule = rendered["policy"]["rules"][0]
        require(rule["cidrs"] == (["198.19.0.1/32"] if mode == "wrong-cidr" else [str(remote) + "/32"]), "selector must target controlled remote except mismatched CIDR")
        require(rule["ports"][0]["port"] == (8081 if mode == "wrong-port" else 8080), "port selector mismatch")
        require(any(ipaddress.IPv4Address("10.43.0.1") in p for p in exclusions), "service exclusion preserved")
        require(("endpoint" not in rendered) == (mode == "no-endpoint"), "endpoint revocation config contract")
        require(original["exclusions"][0] == "10.42.0.0/16", "render must not mutate original")
        json.dumps(rendered)
        print(f"PASS static non-secret selector JSON: {mode}")
    # Static fixture/source agreement, not a transfer: ratatoskr is nine bytes.
    fake_source = (runner.ROOT / "test/e2e/ci/fakeupstream/main.go").read_text()
    extended_source = (runner.ROOT / "test/e2e/m1/extended.sh").read_text()
    require('bytes.Repeat([]byte("ratatoskr"), 512*1024)' in fake_source, "payload fixture changed; re-audit expected size/hash")
    require(str(len(b"ratatoskr") * 512 * 1024) in extended_source, "scaffold length must match actual 4.5 MiB payload")
    print("PASS static payload fixture agreement: 4718592 bytes (4.5 MiB), not a transfer")
    # Parse every authored Python file without generating pycache or executing main.
    for path in (HERE / "run.py", HERE / "client-config.py", HERE / "static-check.py"):
        compile(path.read_text(), str(path), "exec")
    print("Static checks only; no fake/live e2e, runner main, API request or credential access.")


if __name__ == "__main__":
    main()
