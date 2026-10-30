#!/usr/bin/env python3
"""Render non-secret selector configs for static checks and final-gate scenarios."""
import argparse
import ipaddress
import json
import sys

MODES = ("include", "wrong-port", "wrong-cidr", "exclude", "no-endpoint")


def build(config, remote_ip, pod_cidr, mode):
    if mode not in MODES:
        raise ValueError("unknown static selector scenario")
    cfg = json.loads(json.dumps(config))
    remote = ipaddress.IPv4Address(remote_ip)
    pods = ipaddress.IPv4Network(pod_cidr)
    if remote not in pods or str(pods) not in cfg["exclusions"]:
        raise ValueError("remote must be inside an explicitly excluded pod CIDR")
    # Remove ONLY the fake remote's /32 from the pod CIDR exclusions. The
    # remote HTTP listener is reachable through both the CNI and the fake
    # upstream. Its selected reply requires the owned, numbered GENEVE link
    # so loose reverse-path validation can check the tunneled source.
    cfg["exclusions"] = [p for p in cfg["exclusions"] if p != str(pods)]
    selected = ipaddress.IPv4Network(str(remote) + "/32")
    cfg["exclusions"] += [str(p) for p in pods.address_exclude(selected)]
    target = "198.19.0.1/32" if mode == "wrong-cidr" else str(selected)
    port = 8081 if mode == "wrong-port" else 8080
    cfg["policy"] = {"mode": "exclude" if mode == "exclude" else "include",
                     "rules": [{"cidrs": [target], "ports": [{"protocol": "TCP", "port": port}]}]}
    if mode == "no-endpoint":
        cfg.pop("endpoint", None)
    return cfg


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("input", help="non-secret original client JSON file")
    parser.add_argument("remote_ip")
    parser.add_argument("pod_cidr")
    parser.add_argument("mode", choices=MODES)
    args = parser.parse_args()
    try:
        with open(args.input, encoding="utf-8") as file:
            cfg = build(json.load(file), args.remote_ip, args.pod_cidr, args.mode)
    except (OSError, ValueError, KeyError, TypeError):
        parser.error("invalid non-secret selector configuration")
    json.dump(cfg, sys.stdout)
    print()


if __name__ == "__main__":
    main()
