"""Small CI acquisition tool. These records are CI observations, not attestation.

Never run its network/process subcommands on a workstation or production host.
The workflow enters a private no-egress namespace before isolation/units.
"""
from __future__ import annotations

import argparse
import ast
import hashlib
import importlib
import importlib.util
import json
import os
import pathlib
import re
import stat
import subprocess
import sys
import unittest

sys.dont_write_bytecode = True
BASE = pathlib.Path(__file__).resolve().parent
spec = importlib.util.spec_from_file_location("subscription_ci_contract", BASE / "lab_contract.py")
C = importlib.util.module_from_spec(spec)
spec.loader.exec_module(C)
WORKFLOW = ".github/workflows/chengwang-subscription-readback.yml"
PINNED_UNITS = {
    "test_wire_fixture": (24, "c22d31e8501e9975760ef1d59dfbd4c7de1074107bb3ac42bcd27fbcd458f565"),
    "test_run_subscription_lab": (24, "23574c38480dc9936345cc9de9950365b1b1be88298b5e8c76ef6cc13c8aa5bc"),
    "test_check_subscription_lab": (32, "7f42b31818aafb4c0b77e7a47a16c0ae407547619aacdc070ca911e4608c477e"),
}


def require(ok):
    if not ok:
        raise ValueError("ci-input-rejected")


def emit(path, value):
    data = (json.dumps(value, sort_keys=True, separators=(",", ":")) + "\n").encode()
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | getattr(os, "O_NOFOLLOW", 0), 0o600)
    with os.fdopen(fd, "wb") as stream:
        stream.write(data)


def run(*args):
    command = list(args)
    if command[0] == "git":
        # Source acquisition also runs as the namespace orchestrator. Bind this
        # single checkout explicitly; never set a global safe.directory wildcard.
        command[1:1] = ["-c", "safe.directory=" + str(pathlib.Path.cwd().resolve()), "-c", "core.fsmonitor=false"]
    return subprocess.check_output(command, stderr=subprocess.DEVNULL, timeout=30)


def source(commit):
    require(re.fullmatch(r"[a-f0-9]{40}", commit) is not None)
    require(run("git", "rev-parse", "HEAD").decode().strip() == commit)
    names = run("git", "ls-files", "-z", "--", "chengwang", WORKFLOW).split(b"\0")
    records = []
    for raw in sorted(n for n in names if n):
        name = raw.decode("utf-8", "strict")
        path = pathlib.Path(name)
        meta = path.lstat()
        require(stat.S_ISREG(meta.st_mode) and meta.st_nlink == 1)
        data = path.read_bytes()
        require(data == run("git", "cat-file", "blob", commit + ":" + name))
        records.append({"path": name, "bytes": len(data), "sha256": hashlib.sha256(data).hexdigest()})
    require(any(r["path"] == WORKFLOW for r in records))
    require(not run("git", "status", "--porcelain", "--untracked-files=all"))
    return records


def build(binary, commit):
    path = pathlib.Path(binary)
    require(path.is_file() and not path.is_symlink())
    data = path.read_bytes()
    require(data[:4] == b"\x7fELF" and len(data) > 1024)
    require(run("go", "env", "GOVERSION").decode().strip() == "go1.23.12")
    require(re.fullmatch(r"[0-9a-f]{40}", commit) is not None)
    return {"schema": C.BUILD_SCHEMA, "sourceCommit": commit, "goVersion": "go1.23.12",
        "moduleMode": "vendor", "dependencyDownloads": False, "authorization": "BLOCKED",
        "production": False, "server": {"name": "server", "bytes": len(data),
        "sha256": hashlib.sha256(data).hexdigest()}}


def host():
    return {"netNamespace": os.readlink("/proc/self/ns/net"),
        "mountNamespace": os.readlink("/proc/self/ns/mnt"),
        "portStart": int(pathlib.Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text()),
        "systemCASHA256": hashlib.sha256(pathlib.Path("/etc/ssl/certs/ca-certificates.crt").read_bytes()).hexdigest()}


def isolation(outer):
    require(sys.platform == "linux" and os.getuid() == C.UID and os.getgid() == C.GID)
    status = dict(line.split(":", 1) for line in pathlib.Path("/proc/self/status").read_text().splitlines() if ":" in line)
    links = json.loads(run("/usr/sbin/ip", "-json", "link", "show"))
    addresses = json.loads(run("/usr/sbin/ip", "-json", "-4", "address", "show"))
    value = {"schema": C.ISOLATION_SCHEMA, "outerNetNamespace": outer,
        "netNamespace": os.readlink("/proc/self/ns/net"),
        "mountNamespace": os.readlink("/proc/self/ns/mnt"),
        "pidNamespace": os.readlink("/proc/self/ns/pid"), "uid": os.getuid(), "gid": os.getgid(),
        "capabilities": status["CapEff"].strip(), "noNewPrivileges": int(status["NoNewPrivs"]),
        "interfaces": sorted(link["ifname"] for link in links),
        "ipv4Addresses": sorted(info["local"] + "/" + str(info["prefixlen"])
            for address in addresses for info in address["addr_info"]),
        "ipv4DefaultRoutes": json.loads(run("/usr/sbin/ip", "-json", "-4", "route", "show", "default")),
        "ipv6DefaultRoutes": json.loads(run("/usr/sbin/ip", "-json", "-6", "route", "show", "default")),
        "unprivilegedPortStart": int(pathlib.Path("/proc/sys/net/ipv4/ip_unprivileged_port_start").read_text())}
    require(value["outerNetNamespace"] != value["netNamespace"])
    require(value["interfaces"] == ["lo"] and value["ipv4Addresses"] == ["127.0.0.1/8", "8.8.4.4/32"])
    require(not value["ipv4DefaultRoutes"] and not value["ipv6DefaultRoutes"])
    require(value["capabilities"] == "0000000000000000" and value["noNewPrivileges"] == 1)
    require(value["unprivilegedPortStart"] == 0)
    return value


def units(modules):
    # Assertions use the frozen task-card list, not the suite's eventual result.
    sys.path.insert(0, str(BASE))
    reports = []

    class Recorded(unittest.TextTestResult):
        def __init__(self, *args):
            super().__init__(*args)
            self.runs, self.passes = [], []

        def startTest(self, test):
            self.runs.append(test.id())
            super().startTest(test)

        def addSuccess(self, test):
            self.passes.append(test.id())
            super().addSuccess(test)

    for module in modules:
        expected = sorted(module + "." + cls + ".test_" + name
            for cls, names in C.UNIT_NAMES[module].items() for name in names)
        fingerprint = hashlib.sha256(("\n".join(expected) + "\n").encode()).hexdigest()
        require((len(expected), fingerprint) == PINNED_UNITS[module])
        tree = ast.parse((BASE / (module + ".py")).read_bytes())
        actual = sorted(module + "." + cls.name + "." + method.name
            for cls in tree.body if isinstance(cls, ast.ClassDef)
            for method in cls.body if isinstance(method, ast.FunctionDef) and method.name.startswith("test_"))
        require(actual == expected and len(expected) == len(set(expected)))
        suite = unittest.defaultTestLoader.loadTestsFromModule(importlib.import_module(module))
        result = unittest.TextTestRunner(verbosity=2, resultclass=Recorded).run(suite)
        require(result.wasSuccessful() and not result.skipped and not result.expectedFailures and not result.unexpectedSuccesses)
        require(sorted(result.runs) == sorted(result.passes) == expected)
        reports.append({"module": module, "testsRun": result.testsRun, "skipped": 0, "names": expected,
            "namesSHA256": fingerprint,
            "syntheticOnly": module != "test_wire_fixture", "productAcceptanceProven": False})
    return reports


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("action", choices=("source", "build", "isolation", "host", "units"))
    parser.add_argument("--output", required=True)
    parser.add_argument("--source-commit")
    parser.add_argument("--server-binary")
    parser.add_argument("--outer-net-namespace")
    parser.add_argument("--unit-profile", choices=("wire", "contracts"))
    args = parser.parse_args()
    if args.action == "source":
        value = source(args.source_commit)
    elif args.action == "build":
        value = build(args.server_binary, args.source_commit)
    elif args.action == "isolation":
        value = isolation(args.outer_net_namespace)
    elif args.action == "host":
        value = host()
    else:
        require(args.unit_profile is not None)
        names = ["test_wire_fixture"] if args.unit_profile == "wire" else ["test_run_subscription_lab", "test_check_subscription_lab"]
        value = units(names)
    emit(args.output, value)


if __name__ == "__main__":
    try:
        main()
    except Exception:
        print("SUBSCRIPTION_CI_ACQUISITION=REJECTED", file=sys.stderr)
        raise SystemExit(1) from None
