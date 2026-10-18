#!/bin/sh
# Shared, fail-closed lifecycle helpers for the active probe candidate.
# Callers must set SCRIPT_DIR and ROOT_DIR before sourcing this file.

PROBE_COMPOSE_FILE=$ROOT_DIR/compose.probe-agent.yaml
PROBE_PROFILE=active-probe-candidate
PROBE_SERVICE=probe-agent
PROBE_COMPONENT=m2b-probe-agent-candidate
PROBE_BACKUP_SCHEMA=chengwang.m2b-probe-backup/v2
PROBE_EGRESS_EVIDENCE_SCHEMA=chengwang.m2b-probe-egress-evidence/v1
PROBE_BACKUP_MAX_AGE_SECONDS=3600
PROBE_ARCHIVE_MAX_ENTRIES=8192
PROBE_ARCHIVE_MAX_BYTES=268435456
PROBE_VALIDATOR_SPOOL_PATH=/var/lib/chengwang-probe/results
PROBE_VALIDATOR_LEDGER_PATH=/var/lib/chengwang-probe/ledger
PROBE_VALIDATOR_CATALOG_PATH=/run/chengwang-probe/catalog.json

probe_require() {
  command -v "$1" >/dev/null 2>&1 || candidate_fail "required command is missing: $1"
}

probe_load_contract() {
  candidate_load_existing_root
  M2B_PROBE_PROJECT_NAME=chengwang-m2b-probe-$M2B_INSTANCE_ID-candidate
  unset COMPOSE_PROJECT_NAME
  export M2B_PROBE_PROJECT_NAME

  PROBE_CONFIG_DIR=$CANDIDATE_ROOT/config
  PROBE_ENV_FILE=$PROBE_CONFIG_DIR/probe.env
  PROBE_CATALOG_FILE=$PROBE_CONFIG_DIR/catalog.json
  PROBE_DOT_CA_FILE=$PROBE_CONFIG_DIR/dot-ca.pem
  PROBE_EGRESS_POLICY_FILE=$PROBE_CONFIG_DIR/egress-policy.json
  PROBE_STATE_DIR=$CANDIDATE_ROOT/probe-state
  PROBE_SPOOL_DIR=$PROBE_STATE_DIR/probe-spool
  PROBE_LEDGER_DIR=$PROBE_STATE_DIR/probe-ledger
  PROBE_BACKUP_ROOT=$CANDIDATE_ROOT/probe-backups
  PROBE_EVIDENCE_DIR=$CANDIDATE_ROOT/evidence

  export PROBE_CONFIG_DIR PROBE_ENV_FILE PROBE_CATALOG_FILE PROBE_DOT_CA_FILE
  export PROBE_EGRESS_POLICY_FILE PROBE_STATE_DIR PROBE_SPOOL_DIR PROBE_LEDGER_DIR
  export PROBE_BACKUP_ROOT PROBE_EVIDENCE_DIR
}

probe_acquire_lifecycle_lock() {
  probe_require flock
  PROBE_GLOBAL_LIFECYCLE_LOCK=/run/chengwang-m2b-probe-lifecycle.lock
  python3 - "$PROBE_GLOBAL_LIFECYCLE_LOCK" <<'PY'
import os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
parent = path.parent.lstat()
if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 0 or parent.st_mode & 0o022:
    raise SystemExit("global probe lifecycle lock parent must be root-owned and not writable by group/other")
flags = os.O_RDWR | os.O_CREAT
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags, 0o600)
os.close(descriptor)
info = path.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
    raise SystemExit("global probe lifecycle lock must be root-owned, mode 0600, with one hard link")
PY
  exec 8<>"$PROBE_GLOBAL_LIFECYCLE_LOCK"
  flock -n 8 || candidate_fail "another probe lifecycle operation holds the global lock"

  PROBE_LIFECYCLE_LOCK=$CANDIDATE_ROOT/.probe-lifecycle.lock
  python3 - "$PROBE_LIFECYCLE_LOCK" <<'PY'
import os, pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
flags = os.O_RDWR | os.O_CREAT
if hasattr(os, "O_NOFOLLOW"):
    flags |= os.O_NOFOLLOW
descriptor = os.open(path, flags, 0o600)
os.close(descriptor)
info = path.lstat()
if not stat.S_ISREG(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1:
    raise SystemExit("probe lifecycle lock must be root-owned, mode 0600, with one hard link")
PY
  candidate_assert_same_mount "$CANDIDATE_ROOT" "$PROBE_LIFECYCLE_LOCK"
  exec 9<>"$PROBE_LIFECYCLE_LOCK"
  flock -n 9 || candidate_fail "another probe lifecycle operation holds the candidate lock"
}

probe_assert_no_uid10001_writers() {
  python3 - "$PROBE_CONFIG_DIR" "$PROBE_STATE_DIR" <<'PY'
import os, pathlib, sys
protected = [pathlib.Path(value).resolve(strict=True) for value in sys.argv[1:]]
found = set()
def overlaps(value):
    try:
        candidate = pathlib.Path(value.removesuffix(" (deleted)")).resolve(strict=False)
    except (OSError, RuntimeError):
        return False
    return any(candidate == item or candidate in item.parents or item in candidate.parents for item in protected)
for status in pathlib.Path("/proc").glob("[0-9]*/status"):
    try:
        uid_matches = False
        for line in status.read_text(encoding="ascii", errors="replace").splitlines():
            if line.startswith("Uid:") and int(line.split()[1]) == 10001:
                uid_matches = True
                break
        if not uid_matches:
            continue
        process = status.parent
        candidates = [process / "cwd"]
        candidates.extend((process / "fd").iterdir())
        for link in candidates:
            try:
                target = os.readlink(link)
            except (FileNotFoundError, PermissionError, ProcessLookupError, OSError):
                continue
            if overlaps(target):
                found.add(process.name)
                break
    except (FileNotFoundError, PermissionError, ProcessLookupError, ValueError):
        continue
if found:
    raise SystemExit("uid 10001 process holds a protected probe path; pids=" + ",".join(sorted(found)[:16]))
PY
}

probe_assert_unique_container_and_mounts() {
  probe_allowed_cid=${1:-}
  python3 - "$probe_allowed_cid" "$PROBE_COMPONENT" "$M2B_PROBE_PROJECT_NAME" "$PROBE_CONFIG_DIR" "$PROBE_STATE_DIR" "$PROBE_CATALOG_FILE" "$PROBE_DOT_CA_FILE" "$PROBE_EGRESS_POLICY_FILE" "$PROBE_SPOOL_DIR" "$PROBE_LEDGER_DIR" <<'PY'
import json, pathlib, subprocess, sys
allowed, component, project, *path_args = sys.argv[1:]
protected = {pathlib.Path(item).resolve(strict=True) for item in path_args}
listed = subprocess.run(["docker", "ps", "-aq"], check=True, capture_output=True, text=True, timeout=15).stdout.split()
same_project_containers = []
mount_conflicts = []
for cid in listed:
    raw = subprocess.run(["docker", "inspect", cid], check=True, capture_output=True, text=True, timeout=15)
    values = json.loads(raw.stdout)
    if not isinstance(values, list) or len(values) != 1:
        raise SystemExit("container inspect result is ambiguous")
    value = values[0]
    labels = value.get("Config", {}).get("Labels") or {}
    if labels.get("com.docker.compose.project") == project:
        same_project_containers.append(cid)
        if labels.get("com.jydn.chengwang.component") != component:
            raise SystemExit("unexpected component exists inside the derived probe project")
    for mount in value.get("Mounts") or []:
        source = mount.get("Source")
        try:
            resolved = pathlib.Path(source).resolve(strict=False) if source and pathlib.Path(source).is_absolute() else None
        except (OSError, RuntimeError):
            resolved = None
        if resolved is not None and cid != allowed:
            for protected_path in protected:
                if resolved == protected_path or protected_path in resolved.parents or resolved in protected_path.parents:
                    mount_conflicts.append(f"{cid}:{resolved}")
                    break
if same_project_containers != ([allowed] if allowed else []):
    raise SystemExit("active probe container is not unique inside the derived project")
if mount_conflicts:
    raise SystemExit("another container mounts protected probe paths: " + ",".join(mount_conflicts))
PY
}

probe_offline_verify() {
  sh "$SCRIPT_DIR/verify-probe-config.sh" \
    --env "$PROBE_ENV_FILE" \
    --compose "$PROBE_COMPOSE_FILE" \
    --catalog "$PROBE_CATALOG_FILE" \
    --dot-ca "$PROBE_DOT_CA_FILE" \
    --egress-policy "$PROBE_EGRESS_POLICY_FILE" \
    --candidate-root "$CANDIDATE_ROOT"
}

probe_env_value() {
  probe_key=$1
  awk -F= -v key="$probe_key" '$1 == key { print substr($0, index($0, "=") + 1); found++ } END { if (found != 1) exit 1 }' "$PROBE_ENV_FILE"
}

probe_image_reference() {
  probe_release_id=$(probe_env_value M2B_PROBE_RELEASE_ID) || candidate_fail "cannot read the verified probe release id"
  printf '%s\n' "chengwang-m2b-probe-agent:$probe_release_id"
}

probe_compose() {
  unset COMPOSE_PROJECT_NAME
  docker compose \
    --env-file "$PROBE_ENV_FILE" \
    --project-name "$M2B_PROBE_PROJECT_NAME" \
    --project-directory "$ROOT_DIR" \
    -f "$PROBE_COMPOSE_FILE" \
    --profile "$PROBE_PROFILE" \
    "$@"
}

probe_assert_private_admin_directory() {
  candidate_assert_no_symlink_components "$1"
  python3 - "$1" <<'PY'
import pathlib, stat, sys
path = pathlib.Path(sys.argv[1])
info = path.lstat()
if not stat.S_ISDIR(info.st_mode) or info.st_uid != 0 or stat.S_IMODE(info.st_mode) != 0o700:
    raise SystemExit(f"directory must be root-owned with mode 0700: {path}")
PY
  candidate_assert_same_mount "$CANDIDATE_ROOT" "$1"
}

probe_assert_backup_file() {
  [ -f "$1" ] && [ ! -L "$1" ] || candidate_fail "backup member is missing or unsafe: $1"
  candidate_assert_admin_file "$1"
  candidate_assert_same_mount "$CANDIDATE_ROOT" "$1"
}

probe_assert_container_identity() {
  probe_cid=$1
  [ -n "$probe_cid" ] || candidate_fail "probe candidate container id is empty"
  [ "$(docker inspect --format '{{index .Config.Labels "com.jydn.chengwang.component"}}' "$probe_cid")" = "$PROBE_COMPONENT" ] || \
    candidate_fail "probe candidate container identity mismatch"
  [ "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.project"}}' "$probe_cid")" = "$M2B_PROBE_PROJECT_NAME" ] || \
    candidate_fail "probe candidate Compose project mismatch"
  [ "$(docker inspect --format '{{index .Config.Labels "com.docker.compose.service"}}' "$probe_cid")" = "$PROBE_SERVICE" ] || \
    candidate_fail "probe candidate Compose service mismatch"
}

probe_assert_container_mounts() {
  probe_cid=$1
  python3 - "$probe_cid" "$PROBE_CATALOG_FILE" "$PROBE_DOT_CA_FILE" "$PROBE_EGRESS_POLICY_FILE" "$PROBE_SPOOL_DIR" "$PROBE_LEDGER_DIR" <<'PY'
import json, os, pathlib, subprocess, sys
cid, catalog, ca, policy, spool, ledger = sys.argv[1:]
raw = subprocess.run(["docker", "inspect", cid], check=True, capture_output=True, text=True, timeout=15)
value = json.loads(raw.stdout)
if not isinstance(value, list) or len(value) != 1:
    raise SystemExit("container inspect result is ambiguous")
mounts = value[0].get("Mounts")
if not isinstance(mounts, list):
    raise SystemExit("container mount list is absent")
expected = {
    "/run/chengwang-probe/catalog.json": (catalog, False),
    "/run/chengwang-probe/dot-ca.pem": (ca, False),
    "/run/chengwang-probe/egress-policy.json": (policy, False),
    "/var/lib/chengwang-probe/results": (spool, True),
    "/var/lib/chengwang-probe/ledger": (ledger, True),
}
seen = {}
for mount in mounts:
    target = mount.get("Destination")
    if target not in expected:
        raise SystemExit(f"unexpected persistent mount: {target}")
    if target in seen or mount.get("Type") != "bind":
        raise SystemExit(f"duplicate or non-bind mount: {target}")
    source = pathlib.Path(mount.get("Source", "")).resolve(strict=True)
    wanted, writable = expected[target]
    if source != pathlib.Path(wanted).resolve(strict=True):
        raise SystemExit(f"mount source mismatch: {target}")
    if bool(mount.get("RW")) is not writable:
        raise SystemExit(f"mount read/write mode mismatch: {target}")
    seen[target] = True
if set(seen) != set(expected):
    raise SystemExit("container mount set is incomplete")
PY
}

probe_validate_state_snapshot() (
  set -eu
  probe_validator_image=$1
  probe_validator_catalog=$2
  probe_validator_spool=$3
  probe_validator_ledger=$4
  probe_validator_report=$5

  printf '%s\n' "$probe_validator_image" | grep -Eq '^sha256:[0-9a-f]{64}$' || \
    candidate_fail "state validator image id is invalid"
  [ "$(docker image inspect --format '{{.Id}}' "$probe_validator_image")" = "$probe_validator_image" ] || \
    candidate_fail "state validator immutable image is not present locally"
  [ -f "$probe_validator_catalog" ] && [ ! -L "$probe_validator_catalog" ] || \
    candidate_fail "state validator catalog is missing or unsafe"
  for probe_validator_directory in "$probe_validator_spool" "$probe_validator_ledger"; do
    [ -d "$probe_validator_directory" ] && [ ! -L "$probe_validator_directory" ] || \
      candidate_fail "state validator directory is missing or unsafe: $probe_validator_directory"
  done
  [ ! -e "$probe_validator_report" ] || candidate_fail "state validator report destination already exists"
  candidate_assert_no_symlink_components "$probe_validator_catalog"
  candidate_assert_no_symlink_components "$probe_validator_spool"
  candidate_assert_no_symlink_components "$probe_validator_ledger"

  probe_validator_name=m2b-probe-validator-$M2B_INSTANCE_ID-$$
  probe_validator_cid=
  cleanup_validator() {
    if [ -n "${probe_validator_cid:-}" ]; then
      docker rm -f "$probe_validator_cid" >/dev/null 2>&1 || true
    fi
  }
  trap cleanup_validator EXIT HUP INT TERM

  probe_validator_cid=$(docker create \
    --pull never \
    --name "$probe_validator_name" \
    --label com.jydn.chengwang.component=m2b-probe-state-validator-candidate \
    --network none \
    --read-only \
    --user 10001:10001 \
    --cap-drop ALL \
    --security-opt no-new-privileges=true \
    --pids-limit 32 \
    --memory 64m \
    --cpus 0.25 \
    --restart no \
    --log-driver none \
    --mount "type=bind,src=$probe_validator_catalog,dst=$PROBE_VALIDATOR_CATALOG_PATH,readonly" \
    --mount "type=bind,src=$probe_validator_spool,dst=$PROBE_VALIDATOR_SPOOL_PATH,readonly" \
    --mount "type=bind,src=$probe_validator_ledger,dst=$PROBE_VALIDATOR_LEDGER_PATH,readonly" \
    --entrypoint /app/probe-agent \
    "$probe_validator_image" \
    validate-state \
    --catalog "$PROBE_VALIDATOR_CATALOG_PATH" \
    --spool-dir "$PROBE_VALIDATOR_SPOOL_PATH" \
    --ledger-dir "$PROBE_VALIDATOR_LEDGER_PATH" \
    --expected-ledger-writer-dir "$PROBE_VALIDATOR_LEDGER_PATH")
  printf '%s\n' "$probe_validator_cid" | grep -Eq '^[0-9a-f]{64}$' || \
    candidate_fail "state validator container id is invalid"

  python3 - "$probe_validator_cid" "$probe_validator_name" "$probe_validator_image" "$probe_validator_catalog" "$probe_validator_spool" "$probe_validator_ledger" "$PROBE_VALIDATOR_CATALOG_PATH" "$PROBE_VALIDATOR_SPOOL_PATH" "$PROBE_VALIDATOR_LEDGER_PATH" <<'PY'
import json, pathlib, subprocess, sys
(
    cid, name, image_id, catalog, spool, ledger,
    catalog_target, spool_target, ledger_target,
) = sys.argv[1:]
raw = subprocess.run(["docker", "inspect", cid], check=True, capture_output=True, text=True, timeout=15)
values = json.loads(raw.stdout)
if not isinstance(values, list) or len(values) != 1:
    raise SystemExit("state validator inspect result is ambiguous")
value = values[0]
config, host = value.get("Config"), value.get("HostConfig")
if not isinstance(config, dict) or not isinstance(host, dict):
    raise SystemExit("state validator inspect structure is incomplete")
if value.get("Id") != cid or value.get("Name") != "/" + name or value.get("Image") != image_id:
    raise SystemExit("state validator container identity mismatch")
if config.get("Image") != image_id or config.get("User") != "10001:10001":
    raise SystemExit("state validator image or user mismatch")
if config.get("Entrypoint") != ["/app/probe-agent"]:
    raise SystemExit("state validator entrypoint mismatch")
expected_command = [
    "validate-state", "--catalog", catalog_target, "--spool-dir", spool_target,
    "--ledger-dir", ledger_target, "--expected-ledger-writer-dir", ledger_target,
]
if config.get("Cmd") != expected_command:
    raise SystemExit("state validator command mismatch")
for item in config.get("Env") or []:
    key = item.split("=", 1)[0].upper()
    if key in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"}:
        raise SystemExit("proxy environment is forbidden in the state validator")
labels = config.get("Labels") or {}
if labels != {"com.jydn.chengwang.component": "m2b-probe-state-validator-candidate"}:
    raise SystemExit("state validator labels mismatch")
if host.get("NetworkMode") != "none" or host.get("ReadonlyRootfs") is not True or host.get("Privileged") is not False:
    raise SystemExit("state validator isolation mismatch")
if host.get("PidMode") or host.get("IpcMode") or host.get("UTSMode") or host.get("UsernsMode") or host.get("CgroupnsMode") == "host":
    raise SystemExit("state validator namespace sharing is forbidden")
if host.get("CapAdd") or host.get("CapDrop") != ["ALL"]:
    raise SystemExit("state validator capability contract mismatch")
if host.get("SecurityOpt") not in (["no-new-privileges"], ["no-new-privileges:true"]):
    raise SystemExit("state validator no-new-privileges contract mismatch")
if host.get("PidsLimit") != 32 or host.get("Memory") != 64 * 1024 * 1024 or host.get("NanoCpus") != 250_000_000:
    raise SystemExit("state validator resource limit mismatch")
if (host.get("RestartPolicy") or {}).get("Name") not in ("", "no") or host.get("AutoRemove") is not False:
    raise SystemExit("state validator lifecycle policy mismatch")
if (host.get("LogConfig") or {}).get("Type") != "none":
    raise SystemExit("state validator logging policy mismatch")
if (
    host.get("PortBindings") or config.get("ExposedPorts") or config.get("Volumes")
    or config.get("Healthcheck") or host.get("Devices") or host.get("DeviceRequests")
    or host.get("Binds") or host.get("Tmpfs") or host.get("Links")
    or host.get("VolumesFrom") or host.get("Dns") or host.get("DnsOptions")
    or host.get("DnsSearch") or host.get("ExtraHosts") or host.get("GroupAdd")
    or host.get("PublishAllPorts")
):
    raise SystemExit("state validator exposes an unexpected host resource")
expected_mounts = {
    catalog_target: pathlib.Path(catalog).resolve(strict=True),
    spool_target: pathlib.Path(spool).resolve(strict=True),
    ledger_target: pathlib.Path(ledger).resolve(strict=True),
}
seen = set()
for mount in value.get("Mounts") or []:
    target = mount.get("Destination")
    if target not in expected_mounts or target in seen or mount.get("Type") != "bind" or mount.get("RW") is not False:
        raise SystemExit("state validator mount set or mode is invalid")
    if pathlib.Path(mount.get("Source", "")).resolve(strict=True) != expected_mounts[target]:
        raise SystemExit("state validator mount source mismatch")
    if mount.get("Propagation") not in ("", "rprivate"):
        raise SystemExit("state validator mount propagation mismatch")
    seen.add(target)
if seen != set(expected_mounts):
    raise SystemExit("state validator mount set is incomplete")
PY

  probe_validator_diagnostics=$probe_validator_report.stderr
  [ ! -e "$probe_validator_diagnostics" ] || candidate_fail "state validator diagnostics destination already exists"
  docker start -a "$probe_validator_cid" >"$probe_validator_report" 2>"$probe_validator_diagnostics"
  chmod 600 "$probe_validator_report" "$probe_validator_diagnostics"
  [ "$(docker inspect --format '{{.State.Running}}' "$probe_validator_cid")" = false ] || \
    candidate_fail "state validator container did not stop"
  [ "$(docker inspect --format '{{.State.ExitCode}}' "$probe_validator_cid")" = 0 ] || \
    candidate_fail "state validator container returned a non-zero exit code"
  [ ! -s "$probe_validator_diagnostics" ] || candidate_fail "state validator emitted unexpected diagnostics"
  rm -f -- "$probe_validator_diagnostics"
  [ "$(stat -c %s "$probe_validator_report")" -le 65536 ] || \
    candidate_fail "state validator report exceeds its size limit"

  python3 - "$probe_validator_report" <<'PY'
import json, re, sys
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate state validation report key: {key}")
        result[key] = value
    return result
with open(sys.argv[1], encoding="utf-8") as stream:
    report = json.load(stream, object_pairs_hook=unique)
expected = {
    "schema", "catalogDigest", "snapshotDigest", "readPathDigest", "ledgerWriterPathDigest",
    "relationshipScope", "spoolResults", "ledgerSnapshots", "latestSequence", "latestStarts",
    "latestInFlight", "latestSettled", "latestRateLimits", "advisoryOnly", "readOnlyValidation",
    "securityMetadataVerified", "ownerUid", "ownerGid", "expectedOwnerUid", "expectedOwnerGid",
    "missingRetainedEvidence", "relationshipComplete",
}
if not isinstance(report, dict) or set(report) != expected:
    raise SystemExit("state validation report field set is invalid")
if report["schema"] != "chengwang.probe-state-validation/v1" or report["relationshipScope"] != "latest-ledger-vs-retained-spool":
    raise SystemExit("state validation report schema or relationship scope is invalid")
for key in ("catalogDigest", "snapshotDigest", "readPathDigest", "ledgerWriterPathDigest"):
    if not isinstance(report[key], str) or not re.fullmatch(r"sha256:[0-9a-f]{64}", report[key]):
        raise SystemExit(f"state validation report digest is invalid: {key}")
if report["advisoryOnly"] is not True or report["readOnlyValidation"] is not True or report["securityMetadataVerified"] is not True:
    raise SystemExit("state validation report does not prove read-only security metadata validation")
for key in (
    "spoolResults", "ledgerSnapshots", "latestSequence", "latestStarts", "latestInFlight",
    "latestSettled", "latestRateLimits", "missingRetainedEvidence",
):
    if not isinstance(report[key], int) or isinstance(report[key], bool) or report[key] < 0:
        raise SystemExit(f"state validation report count is invalid: {key}")
for key in ("ownerUid", "ownerGid", "expectedOwnerUid", "expectedOwnerGid"):
    if report[key] != 10001:
        raise SystemExit(f"state validation report ownership is invalid: {key}")
if not isinstance(report["relationshipComplete"], bool):
    raise SystemExit("state validation relationshipComplete must be boolean")
if report["relationshipComplete"] != (report["missingRetainedEvidence"] == 0):
    raise SystemExit("state validation relationship completeness is inconsistent")
PY

  docker rm "$probe_validator_cid" >/dev/null
  probe_validator_cid=
  trap - EXIT HUP INT TERM
)

probe_extract_state_archive() {
  probe_archive=$1
  probe_destination=$2
  [ -f "$probe_archive" ] && [ ! -L "$probe_archive" ] || candidate_fail "probe state archive is missing or unsafe"
  [ ! -e "$probe_destination" ] || candidate_fail "probe state extraction destination already exists"
  candidate_assert_no_symlink_components "$probe_archive"

  python3 - "$probe_archive" "$probe_destination" "$PROBE_ARCHIVE_MAX_ENTRIES" "$PROBE_ARCHIVE_MAX_BYTES" <<'PY'
import os, pathlib, shutil, sys, tarfile
archive, destination = pathlib.Path(sys.argv[1]), pathlib.Path(sys.argv[2])
maximum_entries, maximum_bytes = map(int, sys.argv[3:])
destination.mkdir(mode=0o700)
os.chown(destination, 10001, 10001)
count = 0
total = 0
seen = set()
seen_directories = set()
with tarfile.open(archive, "r|gz") as source:
    for member in source:
        path = pathlib.PurePosixPath(member.name)
        if (
            path.is_absolute() or ".." in path.parts or path.as_posix() != member.name
            or not path.parts or path.parts[0] not in {"probe-spool", "probe-ledger"}
            or not (member.isdir() or member.isfile()) or member.name in seen
        ):
            raise SystemExit("unsafe or duplicate probe state archive member")
        if len(path.parts) == 1 and not member.isdir():
            raise SystemExit("probe state archive roots must be directories")
        if len(path.parts) > 1 and path.parent.as_posix() not in seen_directories:
            raise SystemExit("probe state archive member appears before its declared parent directory")
        count += 1
        if count > maximum_entries + 2:
            raise SystemExit("probe state archive entry limit exceeded")
        seen.add(member.name)
        target = destination.joinpath(*path.parts)
        if member.isdir():
            target.mkdir(mode=0o700, parents=False, exist_ok=False)
            os.chown(target, 10001, 10001)
            seen_directories.add(path.as_posix())
            continue
        total += member.size
        if member.size < 0 or total > maximum_bytes:
            raise SystemExit("probe state archive byte limit exceeded")
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = os.open(target, flags, 0o600)
        try:
            with os.fdopen(descriptor, "wb", closefd=False) as output:
                extracted = source.extractfile(member)
                if extracted is None:
                    raise SystemExit("probe state archive member has no payload")
                shutil.copyfileobj(extracted, output, length=65536)
                output.flush()
                os.fsync(output.fileno())
            os.chown(target, 10001, 10001)
            if target.stat().st_size != member.size:
                raise SystemExit("probe state archive member was truncated during extraction")
        finally:
            os.close(descriptor)
if {"probe-spool", "probe-ledger"} - seen:
    raise SystemExit("probe state archive is missing a required state root")
PY
}

probe_compare_state_validation_reports() {
  python3 - "$1" "$2" <<'PY'
import json, sys
def unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise SystemExit(f"duplicate state validation report key: {key}")
        result[key] = value
    return result
with open(sys.argv[1], encoding="utf-8") as stream:
    expected = json.load(stream, object_pairs_hook=unique)
with open(sys.argv[2], encoding="utf-8") as stream:
    actual = json.load(stream, object_pairs_hook=unique)
if actual != expected:
    raise SystemExit("archive state semantic report differs from the validated live-state report")
value = actual.get("relationshipComplete")
if not isinstance(value, bool):
    raise SystemExit("state relationship completeness is invalid")
print(str(value).lower())
PY
}

probe_render_compose_json() {
  probe_output=$1
  probe_compose config --format json >"$probe_output"
  chmod 600 "$probe_output"
  [ -s "$probe_output" ] || candidate_fail "Compose JSON rendering is empty"
}

probe_verify_compose_json() {
  probe_expected_image=$(probe_image_reference)
  python3 - "$1" "$PROBE_COMPOSE_FILE" "$M2B_PROBE_PROJECT_NAME" "$PROBE_CATALOG_FILE" "$PROBE_DOT_CA_FILE" "$PROBE_EGRESS_POLICY_FILE" "$PROBE_SPOOL_DIR" "$PROBE_LEDGER_DIR" "$probe_expected_image" <<'PY'
import hashlib, json, pathlib, sys
path, compose_path, project, catalog, ca, policy, spool, ledger, expected_image = sys.argv[1:]
with open(path, encoding="utf-8") as stream:
    value = json.load(stream)
if not isinstance(value, dict) or value.get("name") != project:
    raise SystemExit("rendered Compose project identity mismatch")
services = value.get("services")
if not isinstance(services, dict) or set(services) != {"probe-agent"}:
    raise SystemExit("rendered Compose service set must contain only probe-agent")
service = services["probe-agent"]
if service.get("profiles") != ["active-probe-candidate"]:
    raise SystemExit("probe-agent profile mismatch")
if service.get("user") != "10001:10001" or service.get("read_only") is not True or service.get("privileged") is not False:
    raise SystemExit("probe-agent identity or root filesystem contract mismatch")
if service.get("image") != expected_image:
    raise SystemExit("probe-agent image reference mismatch")
build = service.get("build")
if not isinstance(build, dict) or set(build) != {"context", "dockerfile"}:
    raise SystemExit("probe-agent Dockerfile contract mismatch")
repository_root = pathlib.Path(compose_path).resolve(strict=True).parents[2]
if pathlib.Path(build["context"]).resolve(strict=True) != repository_root:
    raise SystemExit("probe-agent build context is not the repository root")
dockerfile = pathlib.Path(build["dockerfile"])
if not dockerfile.is_absolute():
    dockerfile = repository_root / dockerfile
if dockerfile.resolve(strict=True) != repository_root / "deploy/m2b-candidate/Dockerfile.probe-agent":
    raise SystemExit("probe-agent Dockerfile path mismatch")
if service.get("entrypoint") != ["/app/probe-agent-entrypoint.sh"]:
    raise SystemExit("probe-agent entrypoint mismatch")
environment = service.get("environment")
required_environment = {
    "TZ", "M2B_PROBE_ACTIVE_APPROVAL", "M2B_PROBE_DOT_UPSTREAM",
    "M2B_PROBE_DOT_SERVER_NAME", "M2B_PROBE_EXPECTED_CATALOG_SHA256",
    "M2B_PROBE_EXPECTED_DOT_CA_SHA256", "M2B_PROBE_EXPECTED_EGRESS_POLICY_SHA256",
}
if not isinstance(environment, dict) or set(environment) != required_environment:
    raise SystemExit("probe-agent environment field set mismatch")
if environment["TZ"] != "UTC" or environment["M2B_PROBE_ACTIVE_APPROVAL"] != "approved-candidate-only":
    raise SystemExit("probe-agent timezone or approval environment mismatch")
if any(key.upper() in {"HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY"} for key in environment):
    raise SystemExit("proxy environment variables are forbidden")
for key, source in (
    ("M2B_PROBE_EXPECTED_CATALOG_SHA256", catalog),
    ("M2B_PROBE_EXPECTED_DOT_CA_SHA256", ca),
    ("M2B_PROBE_EXPECTED_EGRESS_POLICY_SHA256", policy),
):
    if environment[key] != hashlib.sha256(pathlib.Path(source).read_bytes()).hexdigest():
        raise SystemExit(f"probe-agent rendered digest does not match its mount: {key}")
expected_command = [
    "/app/probe-agent", "--catalog", "/run/chengwang-probe/catalog.json",
    "--spool-dir", "/var/lib/chengwang-probe/results", "--ledger-dir",
    "/var/lib/chengwang-probe/ledger", "--dot-upstream", service.get("environment", {}).get("M2B_PROBE_DOT_UPSTREAM"),
    "--dot-server-name", service.get("environment", {}).get("M2B_PROBE_DOT_SERVER_NAME"),
    "--dot-ca", "/run/chengwang-probe/dot-ca.pem", "--health-file",
    "/run/m2b-probe-health/health.json", "--resolver-timeout", "5s",
    "--runner-timeout", "10s", "--concurrency", "2", "--queue-size", "256",
    "--starts-per-minute", "20",
]
if service.get("command") != expected_command:
    raise SystemExit("probe-agent command mismatch")
if service.get("init") is not True or service.get("stdin_open") is not False or service.get("tty") is not False:
    raise SystemExit("probe-agent process contract mismatch")
if service.get("restart") not in ("no", "none", None):
    raise SystemExit("probe-agent restart policy must be disabled")
if service.get("network_mode") or service.get("pid") or service.get("ipc") or service.get("uts") or service.get("userns"):
    raise SystemExit("host or shared namespaces are forbidden")
for forbidden_field in (
    "ports", "expose", "cap_add", "devices", "device_cgroup_rules", "volumes_from",
    "links", "external_links", "dns", "dns_opt", "dns_search", "extra_hosts",
    "group_add", "secrets", "configs", "sysctls",
):
    if service.get(forbidden_field):
        raise SystemExit(f"forbidden probe-agent field is populated: {forbidden_field}")
if service.get("cap_drop") != ["ALL"] or service.get("security_opt") != ["no-new-privileges:true"]:
    raise SystemExit("capability or no-new-privileges contract mismatch")
if service.get("stop_signal") != "SIGTERM" or service.get("stop_grace_period") not in ("20s", 20_000_000_000):
    raise SystemExit("probe-agent stop contract mismatch")
def numeric(value, expected):
    try:
        return float(value) == float(expected)
    except (TypeError, ValueError):
        return False
if not numeric(service.get("cpus"), 0.25) or not numeric(service.get("mem_limit"), 96 * 1024 * 1024):
    raise SystemExit("probe-agent CPU or memory limit mismatch")
if not numeric(service.get("mem_reservation"), 48 * 1024 * 1024) or not numeric(service.get("pids_limit"), 64):
    raise SystemExit("probe-agent reservation or PID limit mismatch")
nofile = service.get("ulimits", {}).get("nofile")
if not isinstance(nofile, dict) or not numeric(nofile.get("soft"), 256) or not numeric(nofile.get("hard"), 256):
    raise SystemExit("probe-agent nofile limit mismatch")
if service.get("networks") not in (["m2b_probe_quarantine"], {"m2b_probe_quarantine": None}, {"m2b_probe_quarantine": {}}):
    raise SystemExit("probe-agent network set mismatch")
networks = value.get("networks")
network = networks.get("m2b_probe_quarantine") if isinstance(networks, dict) else None
if not isinstance(network, dict) or network.get("internal") is not True or network.get("attachable") is not False:
    raise SystemExit("quarantine network contract mismatch")
if network.get("driver") != "bridge" or network.get("external") not in (None, False):
    raise SystemExit("quarantine network driver or ownership mismatch")
if network.get("driver_opts") != {"com.docker.network.bridge.enable_icc": "false"}:
    raise SystemExit("quarantine network driver options mismatch")
expected_mounts = {
    "/run/chengwang-probe/catalog.json": (catalog, True),
    "/run/chengwang-probe/dot-ca.pem": (ca, True),
    "/run/chengwang-probe/egress-policy.json": (policy, True),
    "/var/lib/chengwang-probe/results": (spool, False),
    "/var/lib/chengwang-probe/ledger": (ledger, False),
}
seen = {}
for mount in service.get("volumes", []):
    if not isinstance(mount, dict):
        raise SystemExit("rendered Compose volume must use long syntax")
    target = mount.get("target")
    if target not in expected_mounts or target in seen or mount.get("type") != "bind":
        raise SystemExit(f"unexpected or duplicate bind mount: {target}")
    expected_source, read_only = expected_mounts[target]
    if pathlib.Path(mount.get("source", "")).resolve() != pathlib.Path(expected_source).resolve():
        raise SystemExit(f"rendered bind source mismatch: {target}")
    if bool(mount.get("read_only")) is not read_only:
        raise SystemExit(f"rendered bind mode mismatch: {target}")
    if mount.get("bind", {}).get("create_host_path") is not False:
        raise SystemExit(f"create_host_path must remain false: {target}")
    seen[target] = True
if set(seen) != set(expected_mounts):
    raise SystemExit("rendered Compose bind mount set is incomplete")
tmpfs = service.get("tmpfs")
if not isinstance(tmpfs, list) or len(tmpfs) != 2:
    raise SystemExit("probe-agent tmpfs set mismatch")
tmpfs_by_target = {}
for entry in tmpfs:
    if not isinstance(entry, str) or ":" not in entry:
        raise SystemExit("probe-agent tmpfs representation is unsupported")
    target, options = entry.split(":", 1)
    if target in tmpfs_by_target:
        raise SystemExit("duplicate probe-agent tmpfs target")
    tmpfs_by_target[target] = set(options.split(","))
tmp_options = tmpfs_by_target.get("/tmp", set())
health_options = tmpfs_by_target.get("/run/m2b-probe-health", set())
if not {"mode=1777", "nosuid", "nodev", "noexec"}.issubset(tmp_options) or not ({"size=4m", "size=4194304"} & tmp_options):
    raise SystemExit("/tmp tmpfs contract mismatch")
if not {"mode=0700", "uid=10001", "gid=10001", "nosuid", "nodev", "noexec"}.issubset(health_options) or not ({"size=1m", "size=1048576"} & health_options):
    raise SystemExit("health tmpfs contract mismatch")
healthcheck = service.get("healthcheck")
if not isinstance(healthcheck, dict):
    raise SystemExit("probe-agent healthcheck is absent")
health = healthcheck.get("test")
expected_health = ["CMD", "/app/probe-agent", "health", "--health-file", "/run/m2b-probe-health/health.json", "--catalog", "/run/chengwang-probe/catalog.json", "--max-age", "20s"]
if health != expected_health:
    raise SystemExit("probe-agent health command mismatch")
def duration(value, text, nanoseconds):
    return value == text or value == nanoseconds
if (
    not duration(healthcheck.get("interval"), "10s", 10_000_000_000)
    or not duration(healthcheck.get("timeout"), "3s", 3_000_000_000)
    or not duration(healthcheck.get("start_period"), "5s", 5_000_000_000)
    or not numeric(healthcheck.get("retries"), 3)
):
    raise SystemExit("probe-agent health timing contract mismatch")
logging = service.get("logging")
if logging != {"driver": "json-file", "options": {"max-file": "2", "max-size": "1m"}}:
    raise SystemExit("probe-agent logging contract mismatch")
labels = service.get("labels")
expected_labels = {
    "com.jydn.chengwang.component": "m2b-probe-agent-candidate",
    "com.jydn.chengwang.active-probes": "true",
    "com.jydn.chengwang.advisory-only": "true",
    "com.jydn.chengwang.egress-approved": "false",
}
if not isinstance(labels, dict) or any(labels.get(key) != value for key, value in expected_labels.items()):
    raise SystemExit("probe-agent identity labels mismatch")
if "/var/run/docker.sock" in json.dumps(value, sort_keys=True):
    raise SystemExit("Docker socket is forbidden")
PY
}

probe_copy_validate_backup() {
  probe_backup_requested=$1
  probe_stage=$2
  probe_max_age=$3
  probe_expected_image=$4
  probe_require_current_match=$5

  case "$probe_backup_requested" in /*) ;; *) candidate_fail "probe backup path must be absolute" ;; esac
  [ -d "$probe_backup_requested" ] && [ ! -L "$probe_backup_requested" ] || candidate_fail "probe backup must be a real directory"
  candidate_assert_no_symlink_components "$probe_backup_requested"
  probe_backup=$(realpath "$probe_backup_requested")
  [ "$(dirname -- "$probe_backup")" = "$PROBE_BACKUP_ROOT" ] || candidate_fail "probe backup must be a direct child of the dedicated backup root"
  probe_assert_private_admin_directory "$probe_backup"

  python3 - "$probe_backup" <<'PY'
import pathlib, sys
root = pathlib.Path(sys.argv[1])
expected = {"SHA256SUMS", "backup-meta.json", "catalog.json", "dot-ca.pem", "egress-policy.json", "image-inspect.json", "probe-state.tar.gz", "probe.env", "state-validation.json"}
actual = {entry.name for entry in root.iterdir()}
if actual != expected:
    raise SystemExit("probe backup directory must contain exactly the required backup unit")
PY

  for probe_member in SHA256SUMS backup-meta.json catalog.json dot-ca.pem egress-policy.json image-inspect.json probe-state.tar.gz probe.env state-validation.json; do
    probe_assert_backup_file "$probe_backup/$probe_member"
  done
  [ "$(stat -c %s "$probe_backup/state-validation.json")" -le 65536 ] || candidate_fail "state validation report exceeds its size limit"
  [ "$(stat -c %s "$probe_backup/probe-state.tar.gz")" -le "$PROBE_ARCHIVE_MAX_BYTES" ] || candidate_fail "compressed probe state archive exceeds its limit"

  [ ! -e "$probe_stage" ] || candidate_fail "private backup stage already exists"
  mkdir -m 700 -- "$probe_stage"
  cp -- "$probe_backup/SHA256SUMS" "$probe_backup/backup-meta.json" \
    "$probe_backup/catalog.json" "$probe_backup/dot-ca.pem" \
    "$probe_backup/egress-policy.json" "$probe_backup/image-inspect.json" \
    "$probe_backup/probe-state.tar.gz" "$probe_backup/probe.env" \
    "$probe_backup/state-validation.json" "$probe_stage/"
  chmod 600 "$probe_stage"/*

  probe_expected_reference=$(probe_image_reference)
  python3 - "$probe_stage" "$PROBE_BACKUP_SCHEMA" "$CANDIDATE_ROOT" "$M2B_PROBE_PROJECT_NAME" "$probe_expected_image" "$probe_expected_reference" "$probe_max_age" "$probe_require_current_match" "$PROBE_COMPOSE_FILE" "$PROBE_ENV_FILE" "$PROBE_CATALOG_FILE" "$PROBE_DOT_CA_FILE" "$PROBE_EGRESS_POLICY_FILE" "$PROBE_ARCHIVE_MAX_ENTRIES" "$PROBE_ARCHIVE_MAX_BYTES" <<'PY'
import hashlib, json, os, pathlib, re, stat, sys, tarfile, time
(
    stage_arg, schema, root, project, expected_image, expected_reference, max_age_text, require_match_text,
    compose_arg, env_arg, catalog_arg, ca_arg, policy_arg, max_entries_text, max_bytes_text,
) = sys.argv[1:]
stage = pathlib.Path(stage_arg)
expected_names = {
    "backup-meta.json", "catalog.json", "dot-ca.pem", "egress-policy.json",
    "image-inspect.json", "probe-state.tar.gz", "probe.env", "state-validation.json",
}
actual_names = {entry.name for entry in stage.iterdir() if entry.name != "SHA256SUMS"}
if actual_names != expected_names:
    raise SystemExit("staged probe backup member set is invalid")

entries = {}
for line in (stage / "SHA256SUMS").read_text(encoding="ascii").splitlines():
    match = re.fullmatch(r"([0-9a-f]{64})  (backup-meta\.json|catalog\.json|dot-ca\.pem|egress-policy\.json|image-inspect\.json|probe-state\.tar\.gz|probe\.env|state-validation\.json)", line)
    if not match or match.group(2) in entries:
        raise SystemExit("probe backup checksum manifest is invalid")
    entries[match.group(2)] = match.group(1)
if set(entries) != expected_names:
    raise SystemExit("probe backup checksum manifest is incomplete")
for name, expected in entries.items():
    digest = hashlib.sha256((stage / name).read_bytes()).hexdigest()
    if digest != expected:
        raise SystemExit(f"probe backup checksum mismatch: {name}")

with (stage / "backup-meta.json").open(encoding="utf-8") as stream:
    metadata = json.load(stream)
required_meta = {"schema", "createdUnix", "candidateRoot", "projectName", "imageId", "imageReference", "composeSha256", "activeContainerPresent", "relationshipComplete"}
if not isinstance(metadata, dict) or set(metadata) != required_meta:
    raise SystemExit("probe backup metadata schema is invalid")
if metadata["schema"] != schema or metadata["candidateRoot"] != root or metadata["projectName"] != project:
    raise SystemExit("probe backup identity does not match this candidate")
if not isinstance(metadata["createdUnix"], int) or isinstance(metadata["createdUnix"], bool):
    raise SystemExit("probe backup creation time is invalid")
if not isinstance(metadata["activeContainerPresent"], bool):
    raise SystemExit("probe backup active-container flag is invalid")
if not isinstance(metadata["relationshipComplete"], bool):
    raise SystemExit("probe backup relationship completeness flag is invalid")
now = int(time.time())
maximum_age = int(max_age_text)
if metadata["createdUnix"] > now + 5:
    raise SystemExit("probe backup creation time is in the future")
if maximum_age >= 0 and now - metadata["createdUnix"] > maximum_age:
    raise SystemExit("probe backup is stale")
if not re.fullmatch(r"sha256:[0-9a-f]{64}", metadata["imageId"]):
    raise SystemExit("probe backup image id is invalid")
if expected_image and metadata["imageId"] != expected_image:
    raise SystemExit("probe backup image differs from the current immutable image")
if metadata["imageReference"] != expected_reference:
    raise SystemExit("probe backup image reference differs from the verified candidate release")
if metadata["composeSha256"] != hashlib.sha256(pathlib.Path(compose_arg).read_bytes()).hexdigest():
    raise SystemExit("probe backup Compose digest differs from the repository Compose")

with (stage / "image-inspect.json").open(encoding="utf-8") as stream:
    image = json.load(stream)
if not isinstance(image, list) or len(image) != 1 or image[0].get("Id") != metadata["imageId"]:
    raise SystemExit("probe backup image inspect evidence is invalid")
if metadata["imageReference"] not in (image[0].get("RepoTags") or []):
    raise SystemExit("probe backup image inspect does not bind the release tag")

with (stage / "state-validation.json").open(encoding="utf-8") as stream:
    validation = json.load(stream)
if not isinstance(validation, dict) or validation.get("schema") != "chengwang.probe-state-validation/v1":
    raise SystemExit("probe backup state validation report is invalid")
if validation.get("relationshipComplete") is not metadata["relationshipComplete"]:
    raise SystemExit("probe backup relationship completeness metadata mismatch")
if validation.get("readOnlyValidation") is not True or validation.get("securityMetadataVerified") is not True:
    raise SystemExit("probe backup lacks read-only state security validation")

if require_match_text == "yes":
    for staged_name, current_name in (
        ("probe.env", env_arg), ("catalog.json", catalog_arg),
        ("dot-ca.pem", ca_arg), ("egress-policy.json", policy_arg),
    ):
        current = hashlib.sha256(pathlib.Path(current_name).read_bytes()).hexdigest()
        staged = hashlib.sha256((stage / staged_name).read_bytes()).hexdigest()
        if current != staged:
            raise SystemExit(f"fresh backup differs from current configuration: {staged_name}")
elif require_match_text != "no":
    raise SystemExit("internal current-config match mode is invalid")

maximum_entries = int(max_entries_text)
maximum_bytes = int(max_bytes_text)
seen = set()
count = 0
total = 0
with tarfile.open(stage / "probe-state.tar.gz", "r|gz") as source:
    for member in source:
        path = pathlib.PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or path.as_posix() != member.name or not (member.isfile() or member.isdir()):
            raise SystemExit("probe backup archive contains an unsafe entry")
        if not path.parts or path.parts[0] not in {"probe-spool", "probe-ledger"}:
            raise SystemExit("probe backup archive has an unexpected root")
        if member.name in seen:
            raise SystemExit("probe backup archive contains a duplicate entry")
        if len(path.parts) == 1 and (member.name not in {"probe-spool", "probe-ledger"} or not member.isdir()):
            raise SystemExit("probe backup archive state roots must be directories")
        seen.add(member.name)
        count += 1
        if member.isfile():
            total += member.size
        if count > maximum_entries + 2 or total > maximum_bytes:
            raise SystemExit("probe backup archive exceeds its bounds")
if not {"probe-spool", "probe-ledger"}.issubset(seen):
    raise SystemExit("probe backup archive is missing a state root")
PY
}
