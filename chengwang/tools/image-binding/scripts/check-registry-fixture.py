#!/usr/bin/env python3
"""Project Docker inspect evidence only after verifying fixture isolation."""
import json
import pathlib
import sys

network_file, owner, network_name, network_id, image_id = sys.argv[1:]
networks = json.loads(pathlib.Path(network_file).read_text(encoding="utf-8"))
containers = json.load(sys.stdin)
if len(networks) != 1 or len(containers) != 1:
    raise SystemExit("expected exactly one Registry container/network")
n, c = networks[0], containers[0]
label = "org.chengwang.image-binding-fixture"
if n.get("Id") != network_id or n.get("Name") != network_name or not n.get("Internal") or n.get("Driver") != "bridge" or n.get("Labels", {}).get(label) != owner:
    raise SystemExit("Registry network is not the owned internal bridge")
cfg, host, state = c["Config"], c["HostConfig"], c["State"]
if cfg.get("Labels", {}).get(label) != owner or c.get("Image") != image_id or cfg.get("User") != "65532:65532" or not state.get("Running"):
    raise SystemExit("Registry container identity or user mismatch")
if host.get("Privileged") or not host.get("ReadonlyRootfs") or host.get("NetworkMode") != network_name or host.get("PortBindings") or host.get("PublishAllPorts") or host.get("Binds") or host.get("Devices") or host.get("VolumesFrom"):
    raise SystemExit("Registry container has unsafe host attachments")
if host.get("PidMode") == "host" or host.get("IpcMode") == "host" or host.get("CapAdd") or host.get("CapDrop") != ["ALL"] or "no-new-privileges:true" not in host.get("SecurityOpt", []):
    raise SystemExit("Registry namespace or capabilities mismatch")
if host.get("Memory") != 256 * 1024 * 1024 or host.get("PidsLimit") != 128 or host.get("NanoCpus") != 1_000_000_000:
    raise SystemExit("Registry resource limits mismatch")
if set(c.get("NetworkSettings", {}).get("Networks", {})) != {network_name}:
    raise SystemExit("Registry container has unexpected networks")
if any(value is not None for value in c.get("NetworkSettings", {}).get("Ports", {}).values()):
    raise SystemExit("Registry exposes a host port")
expected_binds = {"/etc/distribution/config.yml", "/certs/server.pem", "/certs/server-key.pem"}
binds = [m for m in c.get("Mounts", []) if m.get("Type") == "bind"]
if {m.get("Destination") for m in binds} != expected_binds or len(binds) != 3 or any(m.get("RW") for m in binds):
    raise SystemExit("Registry has unexpected or writable bind mounts")
if any(m.get("Type") not in {"bind", "tmpfs"} for m in c.get("Mounts", [])) or set(host.get("Tmpfs", {})) != {"/var/lib/registry", "/tmp"}:
    raise SystemExit("Registry fixture must not allocate persistent volumes")
print(json.dumps({"owner": owner, "containerID": c["Id"], "imageID": image_id,
                  "networkID": network_id, "internal": True, "tls": True,
                  "user": cfg["User"], "readonlyRootfs": True, "capabilities": "none",
                  "noNewPrivileges": True, "hostPorts": 0, "persistentVolumes": 0,
                  "authorization": "BLOCKED", "production": False}, sort_keys=True))
