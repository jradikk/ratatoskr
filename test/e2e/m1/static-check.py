#!/usr/bin/env python3
"""Only render/parse static manifests; never invoke e2e or cluster commands."""
import json
from pathlib import Path
import subprocess
import sys

import yaml

HERE = Path(__file__).resolve().parent
VALUES = {
    "NAMESPACE": "ratatoskr-m1-static",
    "REMOTE_NODE": "k3d-ratatoskr-flannel-server-0",
    "GATEWAY_NODE": "k3d-ratatoskr-flannel-agent-0",
    "CLIENT_NODE": "k3d-ratatoskr-flannel-agent-1",
    "REMOTE_IP": "10.42.0.10",
    "CLIENT_IP": "10.42.2.10",
    "GATEWAY_IMAGE": "ghcr.io/skaldhall/ratatoskr-gateway:dev",
    "TOOLS_IMAGE": "ratatoskr-tools:m1-local",
    "FAKE_IMAGE": "ratatoskr-fakeupstream:m1-local",
    "OPENVPN_IMAGE": "ratatoskr-openvpn:m1-local",
}


def require(condition, message):
    if not condition:
        raise AssertionError(message)


def render(path, values):
    args = [sys.executable, str(HERE / "render.py"), str(path)]
    for key, value in values.items():
        args.extend(["--set", f"{key}={value}"])
    return subprocess.run(args, capture_output=True, text=True, check=True).stdout


def main():
    documents = 0
    templates = sorted((HERE / "templates").glob("*.yaml.tmpl"))
    require(len(templates) == 9, "expected nine complete YAML templates including both eBPF modes")
    for path in templates:
        text = render(path, VALUES)
        require("@NAMESPACE@" not in text, "unsubstituted template")
        docs = list(yaml.safe_load_all(text))
        require(all(isinstance(doc, dict) for doc in docs), "empty/partial YAML document")
        for doc in docs:
            documents += 1
            require(doc.get("apiVersion") == "v1", "missing or unexpected apiVersion")
            require(doc.get("kind") in {"Namespace", "ConfigMap", "Service", "Pod"}, "unexpected kind")
            require(doc.get("metadata", {}).get("name"), "missing object name")
            if doc["kind"] != "Namespace":
                require(doc["metadata"].get("namespace") == VALUES["NAMESPACE"], "missing namespace")
            if doc["kind"] == "ConfigMap":
                config = json.loads(doc["data"]["gateway.json"])
                require(config == {"gatewayID": 7, "clients": [VALUES["CLIENT_IP"]],
                                   "mtu": 1400, "encryption": "none"}, "gateway JSON contract drift")
                continue
            if doc["kind"] != "Pod":
                continue
            spec = doc["spec"]
            require(spec.get("automountServiceAccountToken") is False, "unneeded API token mount forbidden")
            require(not spec.get("hostNetwork"), "host networking forbidden")
            require(not spec.get("hostPID"), "host PID forbidden")
            require("initContainers" not in spec, "client init must use existing pod netns")
            require(spec.get("nodeName") in {VALUES[x] for x in ("REMOTE_NODE", "GATEWAY_NODE", "CLIENT_NODE")}, "missing deterministic node")
            for volume in spec.get("volumes", []):
                require("hostPath" not in volume, "host mounts forbidden")
            for container in spec["containers"]:
                require(container["imagePullPolicy"] == "Never", "must not pull from registry")
                security = container["securityContext"]
                require(security["runAsUser"] == 0, "root override missing")
                require(not security.get("privileged"), "privilege escalation forbidden")
                require(security["capabilities"]["drop"] == ["ALL"], "capability drop missing")
                added = security["capabilities"].get("add", [])
                allowed = {"NET_ADMIN", "MKNOD"}
                programming = container["name"] in {"gateway", "tools"} and "ebpf" in path.name
                if programming:
                    allowed |= {"BPF", "PERFMON"}
                    require(container["env"][0] == {"name": "DATAPATH", "value": "ebpf"}, "explicit eBPF selector missing")
                require(set(added) <= allowed, "extra capabilities forbidden")
                if container["name"] == "observer":
                    require(not added, "observer must be capability-free")
                elif container["name"] == "gateway":
                    require(added == (["NET_ADMIN", "BPF", "PERFMON"] if programming else ["NET_ADMIN"]), "gateway capability contract")
                    env = {entry["name"]: entry for entry in container["env"]}
                    require(env["POD_UID"] == {"name": "POD_UID", "valueFrom": {"fieldRef": {"fieldPath": "metadata.uid"}}}, "gateway applied acknowledgment needs Downward API pod UID")
                    require(container["command"] == ["/ratatoskr"], "gateway command contract")
                    require(container["args"] == ["-config", "/config/gateway.json"], "gateway config flag contract")
                    require(container["readinessProbe"]["httpGet"] == {"port": 9900, "path": "/healthz"}, "cached readiness contract")
                elif container["name"] == "upstream" and "live" in path.name:
                    require(added == ["NET_ADMIN", "MKNOD"], "OpenVPN capability contract")
                    require(container["args"] == ["--secret-dir", "/etc/ratatoskr/upstream", "--runtime-dir", "/run/ratatoskr"], "safe plugin defaults changed")
                    mounts = {v["name"]: v for v in container["volumeMounts"]}
                    require(mounts["upstream"]["readOnly"], "upstream Secret must be read-only")
                    require(mounts["devnet"]["mountPath"] == "/dev/net", "TUN device path contract")
                    volumes = {v["name"]: v for v in spec["volumes"]}
                    require("emptyDir" in volumes["devnet"], "TUN device must be pod-local")
                    require(volumes["runtime"]["emptyDir"] == {"medium": "Memory"}, "runtime must be ephemeral")
                    require(volumes["upstream"]["secret"]["defaultMode"] == 0o400, "Secret mode contract")
                else:
                    require(added == (["NET_ADMIN", "BPF", "PERFMON"] if programming else ["NET_ADMIN"]), "fake/client capability contract")
            if doc["metadata"]["name"] == "client":
                require(spec["nodeName"] == VALUES["CLIENT_NODE"], "selected client placement")
                if "live" in path.name:
                    require(spec["volumes"][0]["secret"]["secretName"] == "m1-ipinfo", "client token Secret contract")
                    require(spec["volumes"][0]["secret"]["optional"], "token must be optional")
        print(f"PASS static complete-YAML rendering: {path.name} ({len(docs)} documents)")
    print(f"Validated {documents} static YAML documents; no runner or traffic test executed.")


if __name__ == "__main__":
    main()
