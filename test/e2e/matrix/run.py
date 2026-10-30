#!/usr/bin/env python3
"""M8 inventory and serial final-gate orchestration. Defaults to STATIC ONLY."""
import argparse
import fcntl
import itertools
import json
import os
from pathlib import Path
import platform
import shutil
import signal
import subprocess
import tempfile

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
AXES = ("cni", "mesh", "driver", "datapath", "encryption")


def inventory(mode):
    spec = json.loads((HERE / "coverage.json").read_text())
    cells = []
    for values in itertools.product(*(spec["axes"][axis] for axis in AXES)):
        cell = dict(zip(AXES, values))
        cell["id"] = "/".join(values)
        unsupported = cell["datapath"] == "ebpf" and cell["encryption"] == "wireguard"
        runnable = (cell["cni"], cell["mesh"], cell["driver"], cell["encryption"]) == ("flannel", "none", "init", "none")
        cell["runnerImplemented"] = runnable and not unsupported
        cell["status"] = "DEFERRED" if cell["runnerImplemented"] else "SKIPPED"
        cell["reason"] = ("unsupported ebpf+wireguard; refusal needs its own negative test" if unsupported else
                          "direct-config subset implemented but not executed" if runnable else
                          "CNI/mesh/agent/WireGuard fixture not implemented; not covered")
        cell["scenarios"] = []
        for scenario in spec["scenarios"]:
            if scenario["mode"] not in (mode, "both"):
                continue
            applicable = not (scenario["id"].startswith("ebpf-") and cell["datapath"] != "ebpf")
            implemented = applicable and runnable and scenario["implementation"] != "unimplemented"
            if mode == "live" and scenario["id"] == "private-health-metric":
                implemented = False  # 1/0/1 transition requires unimplemented live disruption.
            cell["scenarios"].append({**scenario, "applicable": applicable,
                "status": "DEFERRED" if implemented else "SKIPPED",
                "covered": False,
                "reason": "implemented scaffold; execution deferred" if implemented else
                          "not applicable to iproute" if not applicable else "not implemented/not covered"})
        cells.append(cell)
    return spec, cells


def static_preflight(mode):
    # No commands, cluster/API contacts, module loads or credential reads.
    tools = ("bash", "python3", "jq", "timeout", "kubectl", "k3d", "docker")
    files = ["hack/k3d-up.sh", "hack/k3d-down.sh", "hack/versions.env", "hack/m1-proof.sh",
             "test/e2e/m1/run.sh", "test/e2e/m1/extended.sh", "test/e2e/matrix/client-config.py"]
    files += [f"hack/k3d/{variant}.yaml" for variant in ("flannel", "cilium", "cilium-wg", "calico")]
    return {"kind": "STATIC_ONLY", "toolsAvailable": {tool: bool(shutil.which(tool)) for tool in tools},
            "requiredFilesPresent": {file: (ROOT / file).is_file() for file in files},
            "linux": platform.system() == "Linux",
            "liveProfilePresent": bool(os.environ.get("RATATOSKR_E2E_OVPN")) if mode == "live" else None,
            "resourcePreflight": "NOT_RUN; mandatory hack/k3d-up.sh preflight on creation at final gate",
            "images": "NOT_CHECKED; local builds/imports required; no registry fallback",
            "runtimeCapabilities": "NOT_CHECKED; NET_ADMIN/BPF/PERFMON/TUN/seccomp are runtime gates"}


def write_report(directory, report):
    directory.mkdir(parents=True, exist_ok=True)
    (directory / "report.json").write_text(json.dumps(report, indent=2) + "\n")
    lines = ["# M8 coverage inventory", "", f"Status: **{report['status']}**", "",
             "This is not a passed compatibility matrix. SKIPPED means not covered, not success.", "",
             "| Cell | Status | Reason |", "|---|---|---|"]
    for cell in report["cells"]:
        lines.append(f"| {cell['id']} | {cell['status']} | {cell['reason']} |")
    lines += ["", "## Missing requirements", ""]
    lines += [f"- {item}" for item in report["limitations"]]
    lines += ["", "## Scenario coverage (first implemented cell; JSON lists every cell)", ""]
    sample = next((cell for cell in report["cells"] if cell["runnerImplemented"]), report["cells"][0])
    lines += [f"- {s['milestone']} / {s['id']}: **{s['status']}** — {s['reason']}" for s in sample["scenarios"]]
    (directory / "report.md").write_text("\n".join(lines) + "\n")


# Map inventory claims only to actual checkpoint names emitted by the inner run.
CHECKPOINTS = {
    "direct-cluster-baseline": ["direct-baseline", "cluster-preservation"],
    "selective-cidr-port": ["m8-selective-policy"],
    "payload-integrity": ["m8-payload-integrity"],
    "measured-mtu-mss": ["m8-measured-mtu"],
    "ebpf-tunnel": ["client-steering", "fake-tunnel-echo"],
    "private-health-metric": ["m8-private-metric-ready", "m8-private-metric-down", "m8-private-metric-recovered"],
    "upstream-fail-close-recovery": ["fake-fail-close", "fake-recovery"],
    "public-exit-country": ["live-exit-check"],
}


def apply_result(cell, inner):
    checks = {check["name"]: check["status"] for check in inner.get("checks", [])}
    for scenario in cell["scenarios"]:
        if scenario["status"] != "DEFERRED":
            continue
        names = CHECKPOINTS.get(scenario["id"], [])
        # A live eBPF tunnel is evidenced by public exit rather than fake echo.
        if scenario["id"] == "ebpf-tunnel" and inner.get("mode") == "live":
            names = ["client-steering", "live-exit-check"]
        # Live disruption is not automated; a healthy private gauge is partial.
        if scenario["id"] == "private-health-metric" and inner.get("mode") == "live":
            scenario.update(status="SKIPPED", covered=False, reason="healthy private metric checked; live down/up not implemented")
            continue
        statuses = [checks.get(name) for name in names]
        if names and all(status == "passed" for status in statuses):
            scenario.update(status="PASSED", covered=True, reason="listed checkpoints passed in selected direct-config fixture only")
        elif "failed" in statuses:
            scenario.update(status="FAILED", reason="listed checkpoint failed")
        elif "inconclusive" in statuses:
            scenario.update(status="INCONCLUSIVE", reason="external check inconclusive")
        else:
            scenario.update(status="SKIPPED", reason="required checkpoint missing or not executed; not covered")
    cell["status"] = "FAILED" if inner.get("status") == "failed" else "INCOMPLETE"
    cell["reason"] = "selected scaffold executed; remaining requirements skipped/not covered"


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=("fake", "live"), default="fake")
    parser.add_argument("--execute", action="store_true", help="final gate only; requires explicit environment authorization")
    parser.add_argument("--cell", action="append", default=[], help="exact inventory ID; executions remain serial")
    parser.add_argument("--report-dir", type=Path)
    parser.add_argument("--no-build", action="store_true", help="all images are operator-built; accepted for compatibility")
    parser.add_argument("--no-import", action="store_true")
    parser.add_argument("--skip", action="store_true", help="explicitly skipped execution, still non-green matrix")
    args = parser.parse_args()
    os.umask(0o077)
    directory = (args.report_dir or Path(tempfile.mkdtemp(prefix=f"ratatoskr-m8-{args.mode}-", dir="/tmp"))).resolve()
    if directory == ROOT or ROOT in directory.parents:
        parser.error("report directory must be outside repository")
    if (directory / "report.json").exists() or any(directory.glob("cell-*")):
        parser.error("report directory already contains evidence; use a fresh directory")
    _, cells = inventory(args.mode)
    unknown = set(args.cell) - {cell["id"] for cell in cells}
    if unknown:
        parser.error("unknown cell ID; consult static inventory")
    report = {"schemaVersion": 1, "scope": "M8-incomplete-M2-M8-matrix", "mode": args.mode,
              "status": "INCOMPLETE", "execution": "NOT_RUN", "preflight": static_preflight(args.mode),
              "cells": cells, "limitations": [
                  "All e2e execution was deferred during authoring; static reports are not traffic evidence.",
                  "Alternative CNI/mesh, CRD/admission, agent, WireGuard, HA and full observability fixtures unimplemented.",
                  "M6 policy-only failure revocation and late IPv6 runtime safety remain final-gate blockers.",
                  "Kernel 5.10 actual runtime and full packet capture/PMTU scenarios are unverified.",
                  "Live exact steps 1–13 unavailable locally; no replacement checklist is invented.",
                  "Final-gate matrix returns nonzero when required coverage is missing, skipped or inconclusive."]}
    write_report(directory, report)
    if args.execute and not args.skip:
        if os.environ.get("RATATOSKR_E2E_FINAL_GATE") != "1":
            parser.error("execution deferred; final gate requires RATATOSKR_E2E_FINAL_GATE=1")
        preflight = report["preflight"]
        # Missing credentials is a skip before requiring cluster tools or contacting the API.
        if args.mode == "live" and not preflight["liveProfilePresent"]:
            report["execution"] = "SKIPPED_MISSING_LIVE_PROFILE"
            write_report(directory, report)
            return 4
        if not preflight["linux"] or not all(preflight["toolsAvailable"].values()) or not all(preflight["requiredFilesPresent"].values()):
            report["status"] = "FAILED"
            report["execution"] = "PREFLIGHT_FAILED"
            write_report(directory, report)
            return 1
        with open("/tmp/ratatoskr-e2e-matrix.lock", "a", encoding="utf-8") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                parser.error("another matrix runner is active; one cluster at a time")
            report["execution"] = "SELECTED_SCAFFOLDS_ONLY"
            for index, cell in enumerate(cells):
                if not cell["runnerImplemented"]:
                    continue
                if args.cell and cell["id"] not in args.cell:
                    cell.update(status="SKIPPED", reason="not selected for execution; not covered")
                    for scenario in cell["scenarios"]:
                        if scenario["status"] == "DEFERRED":
                            scenario.update(status="SKIPPED", reason="cell not selected; not covered")
                    continue
                inner_dir = directory / f"cell-{index}"
                command = ["bash", str(ROOT / "hack/m1-proof.sh"), f"--mode={args.mode}", "--extended",
                           f"--datapath={cell['datapath']}", "--no-build", f"--report-dir={inner_dir}"]
                if args.no_import:
                    command.append("--no-import")
                # Never retain raw runner stderr/stdout or provider logs.
                process = subprocess.Popen(command, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
                interrupted = []

                def stop_child(signum, _frame):
                    interrupted.append(signum)
                    process.send_signal(signal.SIGTERM)

                old_handlers = {sig: signal.signal(sig, stop_child) for sig in (signal.SIGINT, signal.SIGTERM)}
                try:
                    code = process.wait()
                finally:
                    for sig, handler in old_handlers.items():
                        signal.signal(sig, handler)
                path = inner_dir / "report.json"
                if path.is_file():
                    apply_result(cell, json.loads(path.read_text()))
                else:
                    cell.update(status="FAILED", reason="inner runner did not produce a report")
                if code not in (0, 3) or interrupted:
                    cell["status"] = "FAILED"
                write_report(directory, report)
                # Never proceed after failed/timeout/cleanup or signal: cluster
                # state may be dirty and must be reconciled by the operator.
                if cell["status"] == "FAILED":
                    break
    elif args.skip:
        report["execution"] = "EXPLICITLY_SKIPPED"
        write_report(directory, report)
    if any(cell["status"] == "FAILED" for cell in cells):
        report["status"] = "FAILED"
    write_report(directory, report)
    print(f"M8 {report['status']}; JSON/Markdown inventory: {directory}")
    # Static/incomplete matrix must not silently return green, even if two subset runs pass.
    return 1 if report["status"] == "FAILED" else 4


if __name__ == "__main__":
    raise SystemExit(main())
