#!/usr/bin/env python3
"""Pure contract checks. No PKI generation, Docker, kubectl or cluster traffic."""
import ast
import importlib.util
from pathlib import Path
import subprocess
import sys

HERE = Path(__file__).resolve().parent
sys.dont_write_bytecode = True
spec = importlib.util.spec_from_file_location("synthetic_prepare", HERE / "prepare.py")
module = importlib.util.module_from_spec(spec)
# Guard against accidental subprocess calls even if the generator changes.
original = subprocess.run
subprocess.run = lambda *_a, **_kw: (_ for _ in ()).throw(AssertionError("no subprocess in static test"))
try:
    spec.loader.exec_module(module)
    sample = ("CA_PUBLIC", "SERVER_PUBLIC", "SERVER_PRIVATE", "CLIENT_PUBLIC", "CLIENT_PRIVATE")
    namespace = "ratatoskr-syn-static"
    objects = module.manifests(namespace, "ratatoskr-synthetic-openvpn:local", sample)
    assert len(objects) == 9
    assert [(o["kind"], o["metadata"]["namespace"]) for o in objects if "namespace" in o["metadata"]] == [
        ("Secret", namespace), ("Secret", namespace), ("Pod", namespace), ("Service", namespace),
        ("EgressGateway", namespace), ("EgressPolicy", namespace + "-apps"),
        ("Pod", namespace + "-apps")]
    server, client = objects[2:4]
    import base64
    decode = lambda value: base64.b64decode(value).decode()
    assert "SERVER_PRIVATE" in decode(server["data"]["server.key"])
    profile = decode(client["data"]["client.ovpn"])
    assert "CLIENT_PRIVATE" in profile and "SERVER_PRIVATE" not in profile
    assert "remote synthetic-vpn.ratatoskr-syn-static.svc.cluster.local 1194" in profile
    for malformed in ("synthetic-vpn.ratatoskr-syn-static.svc.cluster.local.evil",
                      "synthetic-vpn.ratatoskr-syn-static.svc.cluster.local/arg",
                      "synthetic-vpn.ratatoskr-syn-static.svc.cluster.local:1194"):
        try:
            module.client_config(malformed, *sample[:1], sample[3], sample[4])
        except ValueError:
            pass
        else:
            raise AssertionError("invalid service hostname admitted")
    assert "remote-cert-tls server" in profile and "verify-x509-name synthetic-server name" in profile
    assert "remote-cert-tls client" in decode(server["data"]["server.conf"])
    assert "redirect-gateway" not in profile and "auth-user-pass" not in profile
    workload = objects[-1]
    assert objects[1]["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "restricted"
    assert workload["spec"]["automountServiceAccountToken"] is False
    assert workload["spec"]["volumes"] == [{"name": "api-public-ca", "configMap": {
        "name": "kube-root-ca.crt", "items": [{"key": "ca.crt", "path": "ca.crt"}], "defaultMode": 292}}]
    assert workload["spec"]["containers"][0]["volumeMounts"] == [{"name": "api-public-ca",
        "mountPath": "/var/run/ratatoskr/api-ca", "readOnly": True}]
    assert not any("secret" in v or "projected" in v or "serviceAccountToken" in str(v)
                   for v in workload["spec"]["volumes"])
    assert workload["spec"]["containers"][0]["securityContext"]["capabilities"] == {"drop": ["ALL"]}
    assert not workload["spec"].get("initContainers")  # Production webhook must inject the wait-init.
    assert objects[7]["spec"]["gatewayRef"]["namespace"] == namespace
    assert objects[6]["spec"]["upstream"]["secretRef"]["name"] == client["metadata"]["name"]
    server_pod = objects[4]
    assert server_pod["spec"]["containers"][0]["imagePullPolicy"] == "Never"
    assert server_pod["spec"]["containers"][0]["securityContext"]["capabilities"] == {"drop": ["ALL"], "add": ["NET_ADMIN", "MKNOD"]}
    assert server_pod["spec"]["volumes"][1] == {"name": "dev-net", "emptyDir": {}}
    assert server_pod["spec"]["volumes"][2] == {"name": "status", "emptyDir": {"medium": "Memory"}}
    assert server_pod["spec"]["containers"][0]["volumeMounts"][2] == {"name": "status", "mountPath": "/run/synthetic"}
    assert "status /run/synthetic/openvpn.status 1" in decode(server["data"]["server.conf"])
    assert "status-version 3" in decode(server["data"]["server.conf"])
    assert not any("hostPath" in volume for volume in server_pod["spec"]["volumes"])
    assert objects[0]["metadata"]["labels"]["pod-security.kubernetes.io/enforce"] == "privileged"
    for malicious in ("example.net", "synthetic-vpn.bad/shell.svc.cluster.local", "vpn.UPPER.svc.cluster.local"):
        try:
            module.client_config(malicious, *sample[:1], sample[3], sample[4])
        except ValueError:
            pass
        else:
            raise AssertionError("invalid remote admitted")
    source = ast.parse((HERE / "prepare.py").read_text())
    assert not any(isinstance(node, (ast.Import, ast.ImportFrom)) and
                   any(alias.name in ("kubernetes", "docker") for alias in node.names)
                   for node in ast.walk(source))
    assert "kubectl" not in (HERE / "prepare.py").read_text()
    assert "HTTPServer((\"10.88.0.1\", 8080)" in (HERE / "server/serve.py").read_text()
    assert '>/dev/null 2>&1' in (HERE / "server/start.sh").read_text()
finally:
    subprocess.run = original
print("Synthetic fixture static contracts passed; NO PKI, image, cluster or traffic executed.")
