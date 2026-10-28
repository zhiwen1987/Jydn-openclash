#!/usr/bin/env python3
"""Build, boot and verify a network-isolated Clash Center rehearsal.

The script never reads production directly.  An operator must first create the
private input tree described by ``layout``.  Generated configuration is mode
0600, Docker has no published ports, and reports contain hashes/counts only.
"""
from __future__ import annotations

import argparse
import hashlib
import ipaddress
import json
import os
from pathlib import Path
import re
import shutil
import stat
import subprocess
import sys
import time
from typing import Any

try:
    import yaml
except ImportError:  # pragma: no cover - exercised by the host preflight
    yaml = None


class LabFailure(RuntimeError):
    pass


SAFE_NAME = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")
SHA256 = re.compile(r"^[0-9a-f]{64}$")
SCOPE_LABEL = "io.jydn.acceptance.scope"
SCOPE_VALUE = "clash-center-isolated-rehearsal"
REQUIRED_PRIVATE_ENV = {
    "OPENCLASH_SECRET", "SUBSCRIPTION_PUBLISH_TOKEN", "SUBSCRIPTION_HMAC_KEY",
}
ISOLATED_ENV = {
    "LAN_CENTER_PASSIVE": "1",
    "CENTER_ENVIRONMENT": "isolated",
    "CENTER_UI_ENABLED": "1",
    "CENTER_WRITES_ENABLED": "1",
    "OPENCLASH_API": "http://127.0.0.1:19090",
    "PROXY": "http://127.0.0.1:19999",
    "CAPABILITY_PROXY": "http://127.0.0.1:19999",
    "ADMISSION_NATIVE_SSH": "0",
    "CENTER_KUMA_URL": "http://127.0.0.1:3001",
    "CENTER_KUMA_DB": "/app/data/kuma.db",
    "CENTER_KUMA_TOKEN_FILE": "/data/unified/kuma-bridge.jwt",
    "CENTER_COREFILE": "/etc/coredns/Corefile",
    "CENTER_DNS_FRAGMENT": "/etc/coredns/Corefile.managed",
    "CENTER_DNS_HOSTS": "/etc/coredns/hosts",
    "CENTER_COREDNS_BIN": "/usr/local/bin/coredns",
    "LOCAL_SOURCE_HOSTS": "127.0.0.1:8082,localhost:8082,clash-center-lab:8082,127.0.0.1:23993,localhost:23993",
    "SUBSCRIPTION_ALLOWED_PROVIDER_CLIENTS": "127.0.0.1",
    "SUBSCRIPTION_CONTROLLER_MODE": "shadow",
}


def _sha(path: Path) -> str:
    digest = hashlib.sha256()
    with open(path, "rb") as stream:
        for chunk in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _run(command: list[str], timeout: float = 60, capture: bool = True) -> str:
    completed = subprocess.run(
        command, check=False, timeout=timeout,
        stdout=subprocess.PIPE if capture else None,
        stderr=subprocess.PIPE if capture else None,
        text=True,
    )
    if completed.returncode:
        raise LabFailure("command_failed:" + command[0] + ":" + str(completed.returncode))
    return (completed.stdout or "").strip()


def _private_regular(path: Path, *, directory: bool = False) -> None:
    if path.is_symlink() or (not path.is_dir() if directory else not path.is_file()):
        raise LabFailure("private_input_invalid:" + path.name)
    if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
        raise LabFailure("private_input_permissions:" + path.name)


def _repository_source(path: Path) -> None:
    """Accept a normal checked-out source file without weakening private inputs.

    Git does not preserve a 0600 mode for tracked source files, so a Linux
    checkout is normally 0644.  Repository source must still be a direct,
    regular file; only operator-supplied private inputs require 0600.
    """
    if path.is_symlink() or not path.is_file():
        raise LabFailure("repository_source_invalid:" + path.name)


def _tree_safe(root: Path) -> None:
    _private_regular(root, directory=True)
    for path in root.rglob("*"):
        if path.is_symlink():
            raise LabFailure("symlink_input_refused:" + path.name)
        if os.name == "posix" and stat.S_IMODE(path.stat().st_mode) & 0o077:
            raise LabFailure("private_input_permissions:" + path.name)


def _read_env(path: Path) -> dict[str, str]:
    _private_regular(path)
    values: dict[str, str] = {}
    for line in path.read_text(encoding="utf-8").splitlines():
        if not line or line.lstrip().startswith("#"):
            continue
        if "=" not in line:
            raise LabFailure("private_env_invalid")
        key, value = line.split("=", 1)
        key = key.strip()
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{1,79}", key) or "\x00" in value or "\n" in value:
            raise LabFailure("private_env_invalid")
        values[key] = value
    if set(values) != REQUIRED_PRIVATE_ENV:
        raise LabFailure("private_env_unknown_or_missing_key")
    if any(len(values[key]) < 24 for key in REQUIRED_PRIVATE_ENV):
        raise LabFailure("private_env_required_value_missing")
    return values


def _atomic_private(path: Path, payload: bytes) -> None:
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name("." + path.name + ".tmp")
    with open(temporary, "xb") as stream:
        os.chmod(temporary, 0o600)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def _copy_tree(source: Path, target: Path) -> None:
    _tree_safe(source)
    shutil.copytree(source, target, copy_function=shutil.copy2)
    if os.name == "posix":
        for path in [target, *target.rglob("*")]:
            os.chmod(path, 0o700 if path.is_dir() else 0o600)


def _ensure_no_candidate(value: Any) -> None:
    if "Managed_Candidate" in json.dumps(value, ensure_ascii=False):
        raise LabFailure("candidate_exposed_in_lab_runtime")


def _provider_payload(path: Path) -> None:
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict) or not isinstance(value.get("proxies"), list) or not value["proxies"]:
        raise LabFailure("provider_payload_invalid:" + path.name)


def _validate_coredns(root: Path) -> None:
    _tree_safe(root)
    files = (root / "Corefile", root / "Corefile.managed", root / "hosts")
    for path in files:
        _private_regular(path)
    forwards = []
    for path in files[:2]:
        forwards.extend(line.split("#", 1)[0].strip() for line in path.read_text(encoding="utf-8").splitlines()
                        if line.split("#", 1)[0].strip().startswith("forward "))
    if not forwards or any(not re.match(r"^forward\s+\.\s+127\.0\.0\.1:1153(?:\s|$)", line) for line in forwards):
        raise LabFailure("coredns_not_isolated_to_fixture")


def _load_yaml(path: Path) -> dict[str, Any]:
    if yaml is None:
        raise LabFailure("pyyaml_required")
    _private_regular(path)
    value = yaml.safe_load(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise LabFailure("router_runtime_invalid")
    return value


def _generate_mihomo(input_root: Path, output_root: Path, private: dict[str, str]) -> dict[str, Any]:
    router = input_root / "router"
    runtime = _load_yaml(router / "runtime.yaml")
    _ensure_no_candidate(runtime)
    provider_map_path = router / "provider-map.json"
    _private_regular(provider_map_path)
    provider_map = json.loads(provider_map_path.read_text(encoding="utf-8"))
    if not isinstance(provider_map, dict) or not provider_map:
        raise LabFailure("provider_map_invalid")
    original = runtime.get("proxy-providers", {})
    if not isinstance(original, dict):
        raise LabFailure("runtime_provider_map_invalid")
    expected = {str(name) for name in original if str(name) not in {"Managed_Auto", "Managed_Candidate"}}
    if set(provider_map) != expected:
        raise LabFailure("provider_map_identity_mismatch")
    provider_out = output_root / "lab" / "providers"
    provider_out.mkdir(mode=0o700, parents=True)
    providers: dict[str, Any] = {}
    evidence: list[dict[str, Any]] = []
    for index, name in enumerate(sorted(provider_map)):
        if not isinstance(name, str) or not name or name == "Managed_Candidate":
            raise LabFailure("provider_name_invalid")
        relative = provider_map[name]
        if not isinstance(relative, str) or Path(relative).is_absolute() or ".." in Path(relative).parts:
            raise LabFailure("provider_path_invalid")
        source = (router / "providers" / relative).resolve()
        if not source.is_relative_to((router / "providers").resolve()):
            raise LabFailure("provider_path_escape")
        _private_regular(source)
        _provider_payload(source)
        target_name = f"provider-{index:03d}.yaml"
        target = provider_out / target_name
        shutil.copyfile(source, target)
        os.chmod(target, 0o600)
        providers[name] = {
            "type": "file", "path": "/lab/providers/" + target_name,
            "health-check": {"enable": False},
        }
        evidence.append({"name_sha256": hashlib.sha256(name.encode()).hexdigest(), "payload_sha256": _sha(target)})

    managed_cache = output_root / "control" / "lab-providers" / "Managed_Auto.yaml"
    _atomic_private(managed_cache, yaml.safe_dump({"proxies": [{
        "name": "__STACK_EMPTY_MANAGED_AUTO__", "type": "socks5",
        "server": "127.0.0.1", "port": 9, "udp": False,
    }]}, allow_unicode=True, sort_keys=False).encode())
    token = private["SUBSCRIPTION_PUBLISH_TOKEN"]
    providers["Managed_Auto"] = {
        "type": "http",
        "url": "http://127.0.0.1:8082/providers/Managed_Auto.yaml?token=" + token,
        "path": "/data/lab-providers/Managed_Auto.yaml",
        "interval": 3600,
        "health-check": {"enable": False},
    }
    config: dict[str, Any] = {
        "mixed-port": 19999,
        "external-controller": "127.0.0.1:19090",
        "secret": private["OPENCLASH_SECRET"],
        "allow-lan": False,
        "bind-address": "127.0.0.1",
        "mode": "rule",
        "ipv6": False,
        "log-level": "warning",
        "proxies": runtime.get("proxies", []),
        "proxy-providers": providers,
        "proxy-groups": runtime.get("proxy-groups", []),
        "profile": runtime.get("profile", {"store-selected": False, "store-fake-ip": False}),
        "rules": ["MATCH,DIRECT"],
    }
    if not isinstance(config["proxies"], list) or not isinstance(config["proxy-groups"], list):
        raise LabFailure("runtime_topology_invalid")
    _ensure_no_candidate(config)
    config_path = output_root / "lab" / "mihomo.yaml"
    _atomic_private(config_path, yaml.safe_dump(config, allow_unicode=True, sort_keys=False).encode())
    # Do not return or report config bytes: the file contains a private API secret.
    return {"provider_count": len(providers), "provider_evidence": evidence, "config_sha256": _sha(config_path)}


def prepare(args: argparse.Namespace) -> dict[str, Any]:
    input_root, output_root = args.input.resolve(), args.output.resolve()
    if output_root == input_root or output_root.is_relative_to(input_root) or input_root.is_relative_to(output_root):
        raise LabFailure("input_output_overlap")
    if output_root.exists():
        raise LabFailure("output_must_not_exist")
    _tree_safe(input_root)
    private = _read_env(input_root / "private.env")
    output_root.mkdir(mode=0o700, parents=True)
    try:
        # Preserve the production permission/storage boundary: control state is
        # /data while Kuma owns a distinct /app/data volume.
        _copy_tree(input_root / "control", output_root / "control")
        _copy_tree(input_root / "kuma", output_root / "kuma")
        current_path = output_root / "control" / "subscription-controller" / "current.json"
        _private_regular(current_path)
        try:
            current_release = json.loads(current_path.read_text(encoding="utf-8")).get("release_id")
        except (OSError, ValueError, TypeError, AttributeError):
            current_release = None
        if not isinstance(current_release, str) or not SAFE_NAME.fullmatch(current_release):
            raise LabFailure("current_release_invalid")
        hold_until = int(time.time()) + 48 * 3600
        _atomic_private(output_root / "control" / "node-health" / "acceptance-hold.json", json.dumps({
            "until": hold_until,
            "health": {"status": "degraded", "mode": "shadow", "current_release": current_release},
        }, separators=(",", ":")).encode())
        _copy_tree(input_root / "coredns", output_root / "coredns")
        _validate_coredns(output_root / "coredns")
        for required in (
            output_root / "kuma" / "kuma.db",
            output_root / "control" / "unified" / "kuma-bridge.jwt",
            output_root / "control" / "local-source" / "admin-token",
            output_root / "control" / "subscription-controller" / "current.json",
        ):
            _private_regular(required)
        topology = _generate_mihomo(input_root, output_root, private)
        (output_root / "control" / "lab-mihomo").mkdir(mode=0o700, parents=True, exist_ok=True)
        acceptance_source = Path(__file__).with_name("acceptance.py")
        _repository_source(acceptance_source)
        shutil.copyfile(acceptance_source, output_root / "lab" / "acceptance.py")
        os.chmod(output_root / "lab" / "acceptance.py", 0o600)
        shutil.copyfile(input_root / "private.env", output_root / "private.env")
        os.chmod(output_root / "private.env", 0o600)
        selectors = input_root / "router" / "selector-state.json"
        if selectors.exists():
            _private_regular(selectors)
            value = json.loads(selectors.read_text(encoding="utf-8"))
            if not isinstance(value, dict) or not all(isinstance(k, str) and isinstance(v, str) for k, v in value.items()):
                raise LabFailure("selector_state_invalid")
            _ensure_no_candidate(value)
            _atomic_private(output_root / "lab" / "selector-state.json", json.dumps(value, ensure_ascii=False).encode())
        manifest = {
            "schema": 1,
            "scope": "isolated_rehearsal_not_production_acceptance",
            "image": args.image,
            "container": args.container,
            "network": args.network,
            "input_control_sha256": tree_digest(output_root / "control"),
            "input_kuma_sha256": tree_digest(output_root / "kuma"),
            "coredns_sha256": tree_digest(output_root / "coredns"),
            "topology": topology,
            "limitations": [
                "rules_fixture_is_MATCH_DIRECT_not_production_rule_equivalence",
                "subscription_third_source_502_is_a_separate_gate",
                "business_health_is_not_claimed_on_internal_network",
                "reserved_dns_fixture_is_not_real_dns_resolution_evidence",
            ],
            "acceptance_hold_until": hold_until,
        }
        _atomic_private(output_root / "manifest.json", (json.dumps(manifest, ensure_ascii=False, indent=2) + "\n").encode())
        return manifest
    except Exception:
        # A failed new bundle has no reusable authority. Keep it for forensics
        # only when explicitly requested; default is fail closed and remove it.
        if not args.keep_failed:
            shutil.rmtree(output_root, ignore_errors=True)
        raise


def tree_digest(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(root.rglob("*")):
        if path.is_symlink():
            raise LabFailure("symlink_input_refused:" + path.name)
        if path.is_file():
            relative = path.relative_to(root).as_posix().encode()
            digest.update(len(relative).to_bytes(4, "big")); digest.update(relative)
            digest.update(bytes.fromhex(_sha(path)))
    return digest.hexdigest()


def _docker_env(bundle: Path) -> list[str]:
    values = _read_env(bundle / "private.env")
    merged = {**values, **ISOLATED_ENV}
    generated = bundle / "lab" / "container.env"
    payload = "".join(f"{key}={value}\n" for key, value in sorted(merged.items())).encode()
    _atomic_private(generated, payload)
    return sorted(ISOLATED_ENV)


def boot(args: argparse.Namespace) -> dict[str, Any]:
    bundle = args.bundle.resolve()
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    if manifest.get("scope") != "isolated_rehearsal_not_production_acceptance":
        raise LabFailure("bundle_scope_invalid")
    if not isinstance(manifest.get("acceptance_hold_until"), int) or time.time() >= manifest["acceptance_hold_until"]:
        raise LabFailure("isolated_acceptance_hold_expired")
    _docker_env(bundle)
    name, network, image = manifest["container"], manifest["network"], manifest["image"]
    pinned = re.fullmatch(r"(?:sha256:)?[0-9a-f]{64}", image) or re.fullmatch(r"[^\s@]+@sha256:[0-9a-f]{64}", image)
    if not SAFE_NAME.fullmatch(name) or not SAFE_NAME.fullmatch(network) or not pinned:
        raise LabFailure("docker_identity_invalid")
    networks = _run(["docker", "network", "ls", "--format", "{{.Name}}"])
    if network in networks.splitlines():
        raise LabFailure("lab_network_already_exists")
    _run(["docker", "network", "create", "--internal", "--label", SCOPE_LABEL + "=" + SCOPE_VALUE, network])
    internal = json.loads(_run(["docker", "network", "inspect", network]))[0].get("Internal")
    if internal is not True:
        raise LabFailure("docker_network_not_internal")
    existing = _run(["docker", "ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.Names}}"])
    if existing:
        raise LabFailure("lab_container_already_exists")
    command = [
        "docker", "run", "-d", "--name", name, "--hostname", name,
        "--label", SCOPE_LABEL + "=" + SCOPE_VALUE,
        "--network", network, "--restart", "no", "--read-only",
        "--cpus", "0.7", "--memory", "768m", "--pids-limit", "192",
        "--tmpfs", "/tmp:rw,noexec,nosuid,size=128m",
        "--tmpfs", "/run:rw,noexec,nosuid,size=32m",
        "--env-file", str(bundle / "lab" / "container.env"),
        "-v", str(bundle / "control") + ":/data:rw",
        "-v", str(bundle / "kuma") + ":/app/data:rw",
        "-v", str(bundle / "coredns") + ":/etc/coredns:rw",
        "-v", str(bundle / "lab") + ":/lab:ro",
        image,
    ]
    try:
        container_id = _run(command, timeout=120)
    except Exception:
        subprocess.run(["docker", "network", "rm", network], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise
    if not SHA256.fullmatch(container_id.lower()):
        raise LabFailure("container_id_invalid")
    try:
        # passive_control.py in the immutable image is the only owner of the
        # loopback fixture. Verify its exact reserved-address response over UDP
        # and TCP, not merely a bound port, so another stub cannot pass.
        fake_dns_wait = r'''import sys,time
sys.path.insert(0,'/unified-center')
from dns_diagnostics import query_wire
def signature(value):
 return value.get('rcode'),sorted((row.get('section'),row.get('type'),row.get('value')) for row in value.get('records',[]))
expected=('NOERROR',[('answer','A','192.0.2.1')])
d=time.monotonic()+15
while time.monotonic()<d:
 try:
  u=query_wire('example.com','A','127.0.0.1:1153','udp',.8)
  t=query_wire('example.com','A','127.0.0.1:1153','tcp',.8)
  if signature(u)==expected and signature(t)==expected:break
 except Exception:pass
 time.sleep(.1)
else:raise SystemExit(2)
'''
        _run(["docker", "exec", name, "python3", "-c", fake_dns_wait], timeout=20)
        publisher_wait = r'''import time,urllib.request
o=urllib.request.build_opener(urllib.request.ProxyHandler({}));d=time.monotonic()+30
while time.monotonic()<d:
 try:
  with o.open('http://127.0.0.1:8082/health',timeout=1) as r:
   if r.status==200:break
 except Exception:time.sleep(.2)
else:raise SystemExit(2)
'''
        _run(["docker", "exec", name, "python3", "-c", publisher_wait], timeout=40)
        _run(["docker", "exec", "-d", name, "/local-subscription/core", "-d", "/data/lab-mihomo", "-f", "/lab/mihomo.yaml"], timeout=20)
        wait_script = """import json,os,time,urllib.request
o=urllib.request.build_opener(urllib.request.ProxyHandler({}))
d=time.monotonic()+30
while time.monotonic()<d:
 try:
  r=urllib.request.Request('http://127.0.0.1:19090/version',headers={'Authorization':'Bearer '+os.environ['OPENCLASH_SECRET']})
  with o.open(r,timeout=1) as x:
   if x.status==200:break
 except Exception:time.sleep(.2)
else:raise SystemExit(2)
"""
        _run(["docker", "exec", name, "python3", "-c", wait_script], timeout=40)
        restore_script = r'''import json,os,pathlib,urllib.parse,urllib.request
p=pathlib.Path('/lab/selector-state.json')
if p.is_file():
 o=urllib.request.build_opener(urllib.request.ProxyHandler({}));h={'Authorization':'Bearer '+os.environ['OPENCLASH_SECRET'],'Content-Type':'application/json'}
 def req(path,method='GET',body=None):
  q=urllib.request.Request('http://127.0.0.1:19090'+path,data=None if body is None else json.dumps(body).encode(),method=method,headers=h)
  with o.open(q,timeout=3) as r:return json.loads(r.read())
 state=json.loads(p.read_text());proxies=req('/proxies').get('proxies',{})
 for group,choice in state.items():
  row=proxies.get(group);assert isinstance(row,dict) and choice in row.get('all',[])
  req('/proxies/'+urllib.parse.quote(group,safe=''),'PUT',{'name':choice})
 after=req('/proxies').get('proxies',{});assert all(after[g].get('now')==v for g,v in state.items())
 print(json.dumps({'restored':len(state)}))
else:print(json.dumps({'restored':0}))
'''
        restore = json.loads(_run(["docker", "exec", name, "python3", "-c", restore_script], timeout=30))
    except Exception:
        subprocess.run(["docker", "rm", "-f", name], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        subprocess.run(["docker", "network", "rm", network], check=False,
                       stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        raise
    return {"container_id_sha256": hashlib.sha256(container_id.encode()).hexdigest(), "container": name,
            "network": network, "host_ports": [], "resource_limits": {"cpus": 0.7, "memory_mib": 768, "pids": 192},
            "selectors_restored": restore["restored"]}


def verify(args: argparse.Namespace) -> dict[str, Any]:
    bundle = args.bundle.resolve()
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    if not isinstance(manifest.get("acceptance_hold_until"), int) or time.time() >= manifest["acceptance_hold_until"]:
        raise LabFailure("isolated_acceptance_hold_expired")
    name = manifest["container"]
    inspect = json.loads(_run(["docker", "inspect", name]))[0]
    if ((inspect.get("Config") or {}).get("Labels") or {}).get(SCOPE_LABEL) != SCOPE_VALUE:
        raise LabFailure("lab_container_scope_label_missing")
    ports = (inspect.get("HostConfig") or {}).get("PortBindings") or {}
    if any(value for value in ports.values()):
        raise LabFailure("lab_host_port_published")
    host_config = inspect.get("HostConfig") or {}
    if (host_config.get("NanoCpus") != 700_000_000 or host_config.get("Memory") != 768 * 1024 * 1024
            or host_config.get("PidsLimit") != 192):
        raise LabFailure("lab_resource_limits_changed")
    network = (inspect.get("HostConfig") or {}).get("NetworkMode")
    if network != manifest["network"]:
        raise LabFailure("lab_network_changed")
    env_keys = {str(value).split("=", 1)[0] for value in (inspect.get("Config") or {}).get("Env", [])}
    if not set(ISOLATED_ENV).issubset(env_keys):
        raise LabFailure("isolated_environment_missing")
    network_detail = json.loads(_run(["docker", "network", "inspect", manifest["network"]]))[0]
    if network_detail.get("Internal") is not True:
        raise LabFailure("docker_network_not_internal")
    if (network_detail.get("Labels") or {}).get(SCOPE_LABEL) != SCOPE_VALUE:
        raise LabFailure("lab_network_scope_label_missing")
    address = str(((inspect.get("NetworkSettings") or {}).get("Networks") or {}).get(manifest["network"], {}).get("IPAddress", ""))
    try:
        parsed_address = ipaddress.ip_address(address)
    except ValueError:
        raise LabFailure("lab_container_address_invalid") from None
    if not parsed_address.is_private:
        raise LabFailure("lab_container_address_not_private")
    # This script emits only bounded public evidence. It does not print config,
    # URLs, credentials, monitor targets or notification bodies.
    probe = r'''import hashlib,json,os,pathlib,re,urllib.request
opener=urllib.request.build_opener(urllib.request.ProxyHandler({}))
def get(url,auth=False):
 h={'Accept':'application/json'}
 if auth:h['Authorization']='Bearer '+os.environ['OPENCLASH_SECRET']
 with opener.open(urllib.request.Request(url,headers=h),timeout=5) as r:return r.status,json.loads(r.read(4*1024*1024))
version=get('http://127.0.0.1:19090/version',True)
configs=get('http://127.0.0.1:19090/configs',True)[1]
providers=get('http://127.0.0.1:19090/providers/proxies',True)[1].get('providers',{})
proxies=get('http://127.0.0.1:19090/proxies',True)[1].get('proxies',{})
assert configs.get('mixed-port')==19999 and configs.get('mode')=='rule' and configs.get('allow-lan') is False
encoded=json.dumps({'providers':list(providers),'proxies':list(proxies)},ensure_ascii=False)
assert 'Managed_Candidate' not in encoded and 'Managed_Auto' in providers
sys_path='/unified-center';import sys;sys.path.insert(0,sys_path)
from kuma_management import create_extension
k=create_extension({'data_root':'/data','center_root':'/data/center','remote_timeout':3}).snapshot()
assert k.get('state')=='ready' and (k.get('connection') or {}).get('state')=='ready' and k.get('version')=='2.5.6'
assert len(k.get('monitors') or [])==22 and len(k.get('notifications') or [])==1
from dns_validator import IsolatedCoreDnsValidator
from dns_diagnostics import query_wire
fixture_udp=query_wire('example.com','A','127.0.0.1:1153','udp',1.5)
fixture_tcp=query_wire('example.com','A','127.0.0.1:1153','tcp',1.5)
def fixture_signature(value):
 return value.get('rcode'),sorted((row.get('section'),row.get('type'),row.get('value')) for row in value.get('records',[]))
fixture_expected=('NOERROR',[('answer','A','192.0.2.1')])
assert fixture_signature(fixture_udp)==fixture_expected and fixture_signature(fixture_tcp)==fixture_expected
core=pathlib.Path('/etc/coredns/Corefile').read_text();fragment=pathlib.Path('/etc/coredns/Corefile.managed').read_text();hosts=pathlib.Path('/etc/coredns/hosts').read_text()
d=IsolatedCoreDnsValidator('/etc/coredns/Corefile.managed','/etc/coredns/hosts','/usr/local/bin/coredns',12)(core,fragment,hosts)
assert d.get('state')=='ok' and d.get('udp',{}).get('rcode')==d.get('tcp',{}).get('rcode')
print(json.dumps({'schema':1,'mihomo':{'state':'ok','provider_count':len(providers)},'kuma':{'state':'ready','version':'2.5.6','monitors':22,'notifications':1},'dns':{'state':'ok','fixture_udp_tcp':'NOERROR_A_RESERVED_FIXTURE','udp_tcp_match':True},'candidate_exposed':False},separators=(',',':')))
'''
    value = json.loads(_run(["docker", "exec", name, "python3", "-c", probe], timeout=45))
    http_probe = r'''import http.cookiejar,json,os,pathlib,subprocess,sys,urllib.request
base='http://127.0.0.1:8082';token=pathlib.Path('/data/local-source/admin-token').read_text().strip()
jar=http.cookiejar.CookieJar();opener=urllib.request.build_opener(urllib.request.ProxyHandler({}),urllib.request.HTTPCookieProcessor(jar))
payload=json.dumps({'token':token}).encode();request=urllib.request.Request(base+'/api/local/login',data=payload,method='POST',headers={'Content-Type':'application/json','Origin':base,'Host':'127.0.0.1:8082'})
with opener.open(request,timeout=5) as response:csrf=json.loads(response.read())['csrf']
cookie='; '.join(cookie.name+'='+cookie.value for cookie in jar);assert cookie and csrf
report='/data/lab-evidence/http.json';pathlib.Path(report).parent.mkdir(mode=0o700,parents=True,exist_ok=True)
environment=os.environ.copy();environment['CENTER_ACCEPTANCE_COOKIE']=cookie;environment['CENTER_ACCEPTANCE_CSRF']=csrf
command=[sys.executable,'/lab/acceptance.py','--base-url',base,'--report',report,'--allow-isolated-contract-writes','--expected-monitor-count','22','--expected-notification-count','1','--forbid-host-port','127.0.0.1:3101','--snapshot-ready-timeout','45','--required-action','monitors=kuma.monitor_detail','--required-action','monitors=kuma.monitor_history']
result=subprocess.run(command,env=environment,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL,timeout=90)
document=json.loads(pathlib.Path(report).read_text());assert result.returncode==0 and document.get('passed') is True
print(json.dumps({'passed':True,'snapshot':document['checks']['snapshot'],'performance':document['performance']},separators=(',',':')))
'''
    http = json.loads(_run(["docker", "exec", name, "python3", "-c", http_probe], timeout=110))
    return {
        "schema": 1, "scope": manifest["scope"], "container_running": inspect.get("State", {}).get("Running") is True,
        "host_ports": [], "network_internal": True,
        "resource_limits": {"cpus": 0.7, "memory_mib": 768, "pids": 192}, "runtime": value, "http": http,
        "browser_access": {"ssh_local_port": 23993, "container_address": address, "container_port": 8082,
                           "origin": "http://127.0.0.1:23993"},
        "limitations": manifest["limitations"],
    }


def destroy(args: argparse.Namespace) -> dict[str, Any]:
    bundle = args.bundle.resolve()
    manifest = json.loads((bundle / "manifest.json").read_text(encoding="utf-8"))
    name, network = manifest["container"], manifest["network"]
    if not SAFE_NAME.fullmatch(name) or not SAFE_NAME.fullmatch(network):
        raise LabFailure("docker_identity_invalid")
    inspect = json.loads(_run(["docker", "inspect", name]))[0]
    if ((inspect.get("Config") or {}).get("Labels") or {}).get(SCOPE_LABEL) != SCOPE_VALUE:
        raise LabFailure("refuse_destroy_unlabelled_container")
    _run(["docker", "rm", "-f", name], timeout=30)
    remaining = _run(["docker", "ps", "-a", "--filter", "name=^/" + name + "$", "--format", "{{.Names}}"])
    if remaining:
        raise LabFailure("lab_container_remove_failed")
    if args.remove_network:
        network_detail = json.loads(_run(["docker", "network", "inspect", network]))[0]
        if (network_detail.get("Labels") or {}).get(SCOPE_LABEL) != SCOPE_VALUE:
            raise LabFailure("refuse_destroy_unlabelled_network")
        _run(["docker", "network", "rm", network], timeout=30)
    return {"container_removed": True, "network_removed": bool(args.remove_network), "bundle_preserved": True}


def layout() -> dict[str, Any]:
    return {
        "private_input_tree": {
            "private.env": sorted(REQUIRED_PRIVATE_ENV),
            "control/": ["unified/kuma-bridge.jwt", "local-source/admin-token", "subscription-controller/current.json", "the referenced release/state files"],
            "kuma/": ["kuma.db", "other files from the independent /app/data volume if present"],
            "coredns/": ["Corefile", "Corefile.managed", "hosts"],
            "router/": ["runtime.yaml", "provider-map.json", "providers/*", "selector-state.json (optional)"],
        },
        "rules_fixture": ["MATCH,DIRECT"],
        "network": "Docker --internal; no published ports",
        "secrets": "private.env and generated files must remain 0600 and never enter Git/logs",
    }


def main() -> int:
    os.umask(0o077)
    parser = argparse.ArgumentParser()
    sub = parser.add_subparsers(dest="command", required=True)
    sub.add_parser("layout")
    prepare_parser = sub.add_parser("prepare")
    prepare_parser.add_argument("--input", type=Path, required=True)
    prepare_parser.add_argument("--output", type=Path, required=True)
    prepare_parser.add_argument("--image", required=True)
    prepare_parser.add_argument("--container", default="clash-center-lab")
    prepare_parser.add_argument("--network", default="clash-center-lab-internal")
    prepare_parser.add_argument("--keep-failed", action="store_true")
    for command in ("boot", "verify", "destroy"):
        child = sub.add_parser(command)
        child.add_argument("--bundle", type=Path, required=True)
        if command == "destroy":
            child.add_argument("--remove-network", action="store_true")
    args = parser.parse_args()
    try:
        if args.command == "layout": result = layout()
        elif args.command == "prepare": result = prepare(args)
        elif args.command == "boot": result = boot(args)
        elif args.command == "verify": result = verify(args)
        else: result = destroy(args)
        print(json.dumps({"passed": True, "result": result}, ensure_ascii=False, separators=(",", ":")))
        return 0
    except Exception as error:
        print(json.dumps({"passed": False, "error": str(error)[:180]}, ensure_ascii=False, separators=(",", ":")))
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
