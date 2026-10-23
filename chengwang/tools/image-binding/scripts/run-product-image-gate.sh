#!/usr/bin/env bash
# Actual default product-image entrypoint, local Docker only. Never publishes to
# external/formal Registries; D11 seeds only its isolated disposable fixture.
# Never binds a host binary over /app or uses production data or networks.
set -euo pipefail
umask 077
if (( $# != 3 )); then
  echo 'usage: run-product-image-gate.sh ABSOLUTE_RUN_DIRECTORY GO_BINARY MODULE_CACHE' >&2
  exit 2
fi
run_root=$(/usr/bin/realpath -e -- "$1")
go_binary=$(/usr/bin/realpath -e -- "$2")
module_cache=$(/usr/bin/realpath -e -- "$3")
script_root=$(/usr/bin/realpath -e -- "$(/usr/bin/dirname -- "${BASH_SOURCE[0]}")")
module_root=$(/usr/bin/realpath -e -- "$script_root/..")
source_root=$(/usr/bin/git -C "$module_root" rev-parse --show-toplevel)
source_commit=$(/usr/bin/git -C "$source_root" rev-parse HEAD)
checker="$source_root/chengwang/deploy/product-candidate/check_product_image.py"
node_binary=$(/usr/bin/realpath -e -- "$(command -v node)")
chrome_binary=$(/usr/bin/realpath -e -- "$(command -v google-chrome)")
certutil_binary=$(/usr/bin/realpath -e -- "$(command -v certutil)")
test "$(/usr/bin/id -u)" != 0
[[ "$source_commit" =~ ^[a-f0-9]{40}$ ]]
case "$run_root/" in "$source_root/"*) echo 'product-image run directory must be outside source' >&2; exit 2;; esac
test "$("$go_binary" env GOVERSION)" = go1.25.8
case "$(/usr/bin/findmnt -n -T /tmp -o FSTYPE)" in
  ext4|xfs) ;;
  *) echo 'product-image durable fixture requires native ext4/xfs at /tmp' >&2; exit 1;;
esac
test -f "$checker"
test -x "$run_root/bin/image-trust-api-static"
test -x "$run_root/bin/product-image.test"
test -f "$run_root/evidence/candidate-static-binary.sha256"
test -f "$run_root/evidence/candidate-static-binary-buildinfo.txt"
fixture_uuid=$(/usr/bin/python3 -c 'import uuid; print(uuid.uuid4().hex)')
[[ "$fixture_uuid" =~ ^[a-f0-9]{32}$ ]]
fixture_root="/tmp/chengwang-product-image-$fixture_uuid"
browser_source="$fixture_root/bin/browser-source"
browser_guard="$browser_source/chengwang/tools/image-binding/scripts/browser-process-guard.py"
image_tag="chengwang-product-candidate:ci-$fixture_uuid-${source_commit:0:12}"
label_key=org.chengwang.product-image-fixture
context="$run_root/product-image-context"
private="$run_root/product-image-private"
evidence="$run_root/evidence"
image_id=''
trusted_id=''
trusted_pid=''
acceptance_completed=false
phase=initialization
declare -a container_ids=()
declare -a endpoint_ids=()
declare -a kinds=(trusted untrusted wrong-san expired)
test ! -e "$fixture_root"
test ! -e "$context"
test ! -e "$private"
/usr/bin/install -d -m 0700 "$private" "$evidence"

as_fixture() {
  /usr/bin/sudo --non-interactive /usr/bin/setpriv \
    --reuid=10001 --regid=10001 --clear-groups --bounding-set=-all \
    --inh-caps=-all --ambient-caps=-all --no-new-privs "$@"
}

record_failure_diagnostic() {
  # Only a fixed classification is exported. No raw Node/CDP stderr, ready
  # object, credentials, private URL, configuration or remote body is printed.
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$phase" "$fixture_root" "$private" \
    > "$evidence/product-image-failure-diagnostic.json" <<'PY'
import json
import os
import pathlib
import re
import stat
import sys
phase, root, private = sys.argv[1], pathlib.Path(sys.argv[2]), pathlib.Path(sys.argv[3])
if not re.fullmatch(r"[a-z0-9-]{1,64}", phase):
    raise SystemExit("invalid fixed diagnostic phase")
def bounded(path, maximum):
    try:
        descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(descriptor, "rb") as handle:
            info = os.fstat(handle.fileno())
            if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 <= info.st_size <= maximum:
                return b""
            return handle.read(maximum + 1)
    except OSError:
        return b""
secrets = []
try:
    ready = json.loads(bounded(root / "ready.json", 16384))
    secrets = [ready[key].encode() for key in ("auditorToken", "viewerToken", "wrongToken") if isinstance(ready.get(key), str) and 32 <= len(ready[key]) <= 4096]
except (ValueError, TypeError, AttributeError):
    pass
admin = bounded(root / "admin-token.private", 4096).strip()
if admin:
    secrets.append(admin)
log = bounded(private / "browser-supervisor.log", 1 << 20)
report = bounded(root / "evidence" / "trust-https-browser-report.json", 256 << 10)
material = log + report
if any(secret in material for secret in secrets) or b"PRIVATE KEY" in material:
    reason = "PRIVATE_DIAGNOSTIC_WITHHELD"
elif b"Permission denied" in log or b"EACCES" in log:
    reason = "BROWSER_RUNTIME_PATH_ACCESS_DENIED"
elif b"Cannot find module" in log or b"MODULE_NOT_FOUND" in log:
    reason = "BROWSER_HARNESS_MODULE_UNAVAILABLE"
elif report:
    reason = "BROWSER_REPORT_AVAILABLE_AT_PHASE_FAILURE"
else:
    reason = "PHASE_FAILED_WITHOUT_SAFE_BROWSER_DETAILS"
print(json.dumps({"schema": "chengwang.product-image-failure/v1", "outcome": "FAIL", "phase": phase, "reason": reason, "rawPrivateLogPublished": False, "authorization": "BLOCKED", "production": False}, sort_keys=True))
PY
}

cleanup() {
  original_status=$?
  trap - EXIT HUP INT TERM
  cleanup_failed=0
  if test "$original_status" -ne 0; then
    echo "D10_PRODUCT_IMAGE_FAILURE_PHASE=$phase" >&2
    if ! record_failure_diagnostic; then
      /usr/bin/rm -f -- "$evidence/product-image-failure-diagnostic.json"
      echo 'D10_PRODUCT_IMAGE_FAILURE_DIAGNOSTIC=WITHHELD' >&2
    fi
  fi
  if test "$original_status" -eq 0 && test "$acceptance_completed" != true; then cleanup_failed=1; fi
  for owned_id in "${container_ids[@]}"; do
    if /usr/bin/docker container inspect "$owned_id" >/dev/null 2>&1; then
      if test "$(/usr/bin/docker container inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$owned_id")" != "$fixture_uuid"; then
        echo 'product-image cleanup refused a container with mismatched ownership' >&2
        cleanup_failed=1
        continue
      fi
      # A still-running container is a failed acceptance, even if emergency
      # cleanup can stop it. SIGKILL must never turn a graceful-stop failure green.
      if test "$(/usr/bin/docker container inspect --format '{{.State.Running}}' "$owned_id")" = true; then
        cleanup_failed=1
        /usr/bin/docker container rm --force "$owned_id" >/dev/null 2>&1 || cleanup_failed=1
      else
        /usr/bin/docker container rm "$owned_id" >/dev/null 2>&1 || cleanup_failed=1
      fi
      if /usr/bin/docker container inspect "$owned_id" >/dev/null 2>&1; then cleanup_failed=1; fi
    fi
  done
  if /usr/bin/sudo --non-interactive /usr/bin/test -d "$fixture_root"; then
    if ! as_fixture /usr/bin/python3 -B "$browser_guard" cleanup "$fixture_root" >/dev/null; then
      echo 'product-image browser cleanup unproven; private fixture retained' >&2
      cleanup_failed=1
    elif ! /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$fixture_uuid" <<'PY'
import os
import pathlib
import re
import stat
import sys

root, identity = pathlib.Path(sys.argv[1]), sys.argv[2]
if not re.fullmatch(r"[a-f0-9]{32}", identity) or str(root) != "/tmp/chengwang-product-image-" + identity:
    raise SystemExit("unsafe product-image cleanup target")
before = root.lstat()
if not stat.S_ISDIR(before.st_mode) or before.st_uid != 10001 or before.st_gid != 10001 or stat.S_IMODE(before.st_mode) != 0o700 or root.resolve(strict=True) != root:
    raise SystemExit("unsafe product-image cleanup directory")
owner = root / ".fixture-owner"
owner_stat = owner.lstat()
if not stat.S_ISREG(owner_stat.st_mode) or owner_stat.st_nlink != 1 or owner.read_text(encoding="ascii") != identity + "\n":
    raise SystemExit("unbound product-image cleanup ownership")
device = before.st_dev
def remove_contents(directory):
    for entry in os.scandir(directory):
        info = entry.stat(follow_symlinks=False)
        if info.st_dev != device or info.st_uid not in (0, 10001):
            raise SystemExit("unexpected device or owner in private fixture")
        if stat.S_ISDIR(info.st_mode):
            remove_contents(entry.path)
            os.rmdir(entry.path)
        else:
            # Unlink links themselves; never follow Chrome profile links.
            os.unlink(entry.path)
remove_contents(root)
os.rmdir(root)
if root.exists() or root.is_symlink():
    raise SystemExit("private product-image fixture remained")
PY
    then
      cleanup_failed=1
    fi
  fi
  if /usr/bin/docker image inspect "$image_tag" >/dev/null 2>&1; then
    if test "$(/usr/bin/docker image inspect --format "{{ index .Config.Labels \"$label_key\" }}" "$image_tag")" != "$fixture_uuid"; then
      echo 'product-image cleanup refused an image with mismatched ownership' >&2
      cleanup_failed=1
    else
      owned_image=$(/usr/bin/docker image inspect --format '{{.Id}}' "$image_tag")
      if test -n "$image_id" && test "$owned_image" != "$image_id"; then cleanup_failed=1
      else /usr/bin/docker image rm "$owned_image" >/dev/null 2>&1 || cleanup_failed=1
      fi
    fi
  fi
  if /usr/bin/docker image inspect "$image_tag" >/dev/null 2>&1; then cleanup_failed=1; fi
  if test -n "$image_id" && /usr/bin/docker image inspect "$image_id" >/dev/null 2>&1; then cleanup_failed=1; fi
  # Raw daemon inspections are private and never archived, even on failure.
  /usr/bin/find "$private" -maxdepth 1 -type f -delete
  if test "$cleanup_failed" -ne 0; then
    echo 'D10_PRODUCT_IMAGE_CLEANUP=FAIL production=false' >&2
    exit 1
  fi
  echo 'D10_PRODUCT_IMAGE_CLEANUP=PASS exact_owned_containers=true exact_owned_image=true private_fixture_removed=true browser_processes_stopped=true production=false'
  exit "$original_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM

# This is a packaging-only scratch image: no mutable FROM, remote frontend,
# RUN, package install, credential, build-time network or source copy.
phase=staging
/usr/bin/python3 -B "$checker" stage \
  --binary "$run_root/bin/image-trust-api-static" \
  --binary-sha256 "$evidence/candidate-static-binary.sha256" \
  --buildinfo "$evidence/candidate-static-binary-buildinfo.txt" \
  --web-dist "$run_root/web-dist" --web-sha256 "$evidence/web-dist.sha256" \
  --source-commit "$source_commit" --context "$context" \
  --report "$evidence/product-image-staging.json"
/usr/bin/docker version --format '{{json .}}' > "$private/docker-version.json"
phase=image-build
/usr/bin/timeout --signal=TERM --kill-after=10s 180s /usr/bin/docker build \
  --platform linux/amd64 --network none --pull=false --no-cache \
  --build-arg "SOURCE_COMMIT=$source_commit" \
  --label "$label_key=$fixture_uuid" \
  --iidfile "$private/image-id" --tag "$image_tag" "$context" \
  > "$evidence/product-image-build.log" 2>&1
image_id=$(/usr/bin/cat "$private/image-id")
[[ "$image_id" =~ ^sha256:[a-f0-9]{64}$ ]]
/usr/bin/docker image inspect "$image_id" > "$private/image-inspect.json"
phase=image-archive-verification
/usr/bin/timeout --signal=TERM --kill-after=10s 120s /usr/bin/docker image save "$image_id" \
  > "$private/product-image.private.tar"
/usr/bin/python3 -B - "$private/product-image.private.tar" "$evidence/product-image-staging.json" \
  "$private/docker-version.json" "$image_id" "$source_commit" \
  > "$evidence/product-image-packaged-contents.json" <<'PY'
import hashlib
import gzip
import io
import json
import pathlib
import re
import tarfile
import sys

archive, staging_path, version_path, image_id, commit = sys.argv[1:]
def require(condition):
    if not condition:
        raise SystemExit("actual product image archive or packaged content rejected")
def decode(raw):
    def unique(pairs):
        result = {}
        for key, value in pairs:
            require(key not in result)
            result[key] = value
        return result
    return json.loads(raw, object_pairs_hook=unique)
def name(raw):
    require(isinstance(raw, str) and len(raw) <= 512 and not raw.startswith("/") and "\\" not in raw and "\0" not in raw)
    while raw.startswith("./"):
        raw = raw[2:]
    raw = raw.rstrip("/")
    require(raw not in ("", ".") and str(pathlib.PurePosixPath(raw)) == raw and ".." not in pathlib.PurePosixPath(raw).parts)
    return raw
staging = decode(pathlib.Path(staging_path).read_bytes())
require(staging.get("sourceCommit") == commit and staging.get("imageBuilt") is False)
require(all(key == "Dockerfile" or key.startswith("rootfs/app/") for key in staging["contextFiles"]))
expected = {key.removeprefix("rootfs/"): value for key, value in staging["contextFiles"].items() if key != "Dockerfile"}
require(expected and "app/image-trust-api" in expected and all(re.fullmatch(r"[a-f0-9]{64}", value) for value in expected.values()))
path = pathlib.Path(archive)
require(path.is_file() and not path.is_symlink() and 0 < path.stat().st_size <= 512 * 1024 * 1024)
files = {}
with tarfile.open(path, "r:") as outer:
    outer_members = {}
    for index, member in enumerate(outer):
        require(index < 4096 and (member.isdir() or member.isreg()) and not member.sparse and 0 <= member.size <= 256 * 1024 * 1024)
        key = name(member.name)
        require(key not in outer_members)
        outer_members[key] = member
    def read(key, maximum):
        member = outer_members.get(name(key))
        require(member is not None and member.isreg() and member.size <= maximum)
        stream = outer.extractfile(member)
        require(stream is not None)
        data = stream.read(maximum + 1)
        require(len(data) == member.size)
        return data
    manifests = decode(read("manifest.json", 1 << 20))
    require(isinstance(manifests, list) and len(manifests) == 1 and isinstance(manifests[0], dict))
    manifest = manifests[0]
    config_raw = read(manifest["Config"], 1 << 20)
    require("sha256:" + hashlib.sha256(config_raw).hexdigest() == image_id)
    config = decode(config_raw)
    require(config.get("os") == "linux" and config.get("architecture") == "amd64" and config.get("config", {}).get("Labels", {}).get("org.opencontainers.image.revision") == commit)
    layers = manifest.get("Layers")
    diff_ids = config.get("rootfs", {}).get("diff_ids")
    require(isinstance(layers, list) and isinstance(diff_ids, list) and 1 <= len(layers) <= 8 and len(layers) == len(diff_ids) and len(set(layers)) == len(layers))
    for key, expected_diff_id in zip(layers, diff_ids):
        layer = read(key, 256 << 20)
        if layer.startswith(b"\x1f\x8b"):
            with gzip.GzipFile(fileobj=io.BytesIO(layer), mode="rb") as compressed:
                layer = compressed.read((256 << 20) + 1)
            require(len(layer) <= 256 << 20)
        require("sha256:" + hashlib.sha256(layer).hexdigest() == expected_diff_id)
        seen = set()
        with tarfile.open(fileobj=io.BytesIO(layer), mode="r:") as entries:
            for index, member in enumerate(entries):
                require(index < 4096 and (member.isdir() or member.isreg()) and not member.sparse and member.uid == 0 and member.gid == 0)
                key = name(member.name)
                require(key not in seen and not any(part.startswith(".wh.") for part in pathlib.PurePosixPath(key).parts))
                seen.add(key)
                if member.isdir():
                    require(any(path.startswith(key + "/") for path in expected))
                    require(member.mode == 0o555)
                    continue
                require(key in expected and 0 < member.size <= 128 * 1024 * 1024 and member.mode == (0o555 if key == "app/image-trust-api" else 0o444))
                stream = entries.extractfile(member)
                require(stream is not None)
                contents = stream.read((128 << 20) + 1)
                require(len(contents) == member.size and hashlib.sha256(contents).hexdigest() == expected[key])
                files[key] = {"sha256": expected[key], "bytes": len(contents), "mode": format(member.mode, "04o"), "uid": 0, "gid": 0}
require(set(files) == set(expected))
version = decode(pathlib.Path(version_path).read_bytes())
toolchain = {}
for role in ("Client", "Server"):
    item = version.get(role, {})
    for field in ("Version", "ApiVersion", "GitCommit", "Os", "Arch"):
        value = item.get(field)
        if value is not None:
            require(isinstance(value, str) and re.fullmatch(r"[A-Za-z0-9._+:/() -]{1,128}", value))
            toolchain[role.lower() + field] = value
print(json.dumps({"schema": "chengwang.product-image-packaged-content/v1", "authorization": "BLOCKED", "production": False,
    "sourceCommit": commit, "localImageID": image_id, "identityKind": "LOCAL_DOCKER_CONFIG_ID_NOT_REGISTRY_MANIFEST",
    "registryManifestDigestVerified": False, "configDigestMatched": True, "layerDiffIDs": diff_ids,
    "packagedFileCount": len(files), "files": dict(sorted(files.items())), "dockerToolchain": toolchain,
    "secretsPackaged": False, "rawArchivePublished": False}, sort_keys=True))
PY

# Only this exact, new CI-owned directory may be provisioned or removed.
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$fixture_uuid" <<'PY'
import os
import pathlib
import re
import sys
root, identity = pathlib.Path(sys.argv[1]), sys.argv[2]
if not re.fullmatch(r"[a-f0-9]{32}", identity) or str(root) != "/tmp/chengwang-product-image-" + identity or root.parent.resolve() != pathlib.Path("/tmp"):
    raise SystemExit("unsafe product-image fixture target")
os.mkdir(root, 0o700)
os.chown(root, 10001, 10001)
for name in ("bin", "tmp"):
    os.mkdir(root / name, 0o700)
    os.chown(root / name, 10001, 10001)
owner = root / ".fixture-owner"
fd = os.open(owner, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
with os.fdopen(fd, "w", encoding="ascii") as handle:
    handle.write(identity + "\n")
os.chown(owner, 10001, 10001)
PY
/usr/bin/sudo --non-interactive /usr/bin/install -d -m 0700 -o 10001 -g 10001 "$fixture_root/bin" "$fixture_root/tmp"
/usr/bin/sudo --non-interactive /usr/bin/install -m 0555 -o 10001 -g 10001 \
  "$run_root/bin/product-image.test" "$fixture_root/bin/product-image.test"

# The hosted runner's workspace ancestors need not be traversable by UID10001.
# Do not chmod them or elevate Chrome. Copy only the three required, exact Git
# blobs into a root-owned, permission-read-only mirror with the original layout.
phase=browser-harness-binding
/usr/bin/python3 -B - "$source_root" "$source_commit" > "$private/browser-harness-input.json" <<'PY'
import hashlib
import json
import pathlib
import subprocess
import sys
source, commit = pathlib.Path(sys.argv[1]), sys.argv[2]
names = ("chengwang/web/scripts/verify-trust-browser.mjs", "chengwang/web/scripts/trust-browser-tls.mjs", "chengwang/tools/image-binding/scripts/browser-process-guard.py")
files = {}
for name in names:
    path = source / name
    if path.is_symlink() or not path.is_file():
        raise SystemExit("browser harness source is not a regular checkout file")
    raw = path.read_bytes()
    committed = subprocess.check_output(["/usr/bin/git", "-C", str(source), "show", commit + ":" + name])
    if raw != committed or not 0 < len(raw) <= 128 * 1024:
        raise SystemExit("browser harness checkout differs from the accepted source commit")
    files[name] = hashlib.sha256(raw).hexdigest()
print(json.dumps({"sourceCommit": commit, "files": files}, sort_keys=True))
PY
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$source_root" "$source_commit" \
  "$browser_source" "$private/browser-harness-input.json" \
  > "$evidence/product-image-browser-harness.json" <<'PY'
import hashlib
import json
import os
import pathlib
import re
import stat
import sys
source, commit, destination, manifest = sys.argv[1:]
source, destination = pathlib.Path(source), pathlib.Path(destination)
expected = json.loads(pathlib.Path(manifest).read_text(encoding="utf-8"))
names = {"chengwang/web/scripts/verify-trust-browser.mjs", "chengwang/web/scripts/trust-browser-tls.mjs", "chengwang/tools/image-binding/scripts/browser-process-guard.py"}
if not re.fullmatch(r"[a-f0-9]{40}", commit) or expected.get("sourceCommit") != commit or set(expected.get("files", {})) != names or not re.fullmatch(r"/tmp/chengwang-product-image-[a-f0-9]{32}/bin/browser-source", str(destination)):
    raise SystemExit("browser harness binding inputs rejected")
parent = destination.parent.lstat()
if not stat.S_ISDIR(parent.st_mode) or parent.st_uid != 10001 or parent.st_gid != 10001 or stat.S_IMODE(parent.st_mode) != 0o700 or destination.exists() or destination.is_symlink():
    raise SystemExit("browser harness private parent rejected")
os.mkdir(destination, 0o555)
os.chmod(destination, 0o555)
for name in sorted(names):
    original = source / name
    descriptor = os.open(original, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1 or not 0 < info.st_size <= 128 * 1024:
            raise SystemExit("browser harness source metadata rejected")
        raw = handle.read(128 * 1024 + 1)
    if hashlib.sha256(raw).hexdigest() != expected["files"][name]:
        raise SystemExit("browser harness source changed before copy")
    target = destination / name
    relative = pathlib.PurePosixPath(name).parts[:-1]
    parent_path = destination
    for part in relative:
        parent_path = parent_path / part
        if not parent_path.exists():
            os.mkdir(parent_path, 0o555)
            os.chmod(parent_path, 0o555)
        parent_info = parent_path.lstat()
        if not stat.S_ISDIR(parent_info.st_mode) or parent_info.st_uid != 0 or parent_info.st_gid != 0 or stat.S_IMODE(parent_info.st_mode) != 0o555:
            raise SystemExit("browser harness copied directory rejected")
    output = os.open(target, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o444)
    with os.fdopen(output, "wb") as handle:
        handle.write(raw)
        os.fchmod(handle.fileno(), 0o444)
    if target.read_bytes() != raw:
        raise SystemExit("browser harness copied bytes differ")
print(json.dumps({"schema": "chengwang.product-image-browser-harness/v1", "authorization": "BLOCKED", "production": False, "sourceCommit": commit, "files": expected["files"], "fileCount": 3, "checkoutMatchesGitBlobs": True, "copiedBytesMatchCheckout": True, "copiedFilesRootOwned": True, "fileMode": "0444", "directoryMode": "0555", "kernelReadOnlyMountRequired": True}, sort_keys=True))
PY
phase=browser-harness-accessibility
for harness in "$browser_source/chengwang/web/scripts/verify-trust-browser.mjs" \
  "$browser_source/chengwang/web/scripts/trust-browser-tls.mjs" "$browser_guard"; do
  as_fixture /usr/bin/test -r "$harness"
done
for executable in "$node_binary" "$chrome_binary" "$certutil_binary"; do
  as_fixture /usr/bin/test -x "$executable"
done
echo 'D10_PRODUCT_IMAGE_BROWSER_HARNESS=PASS files=3 source_bound=true uid10001_readable=true toolchain_executable=true root_owned_readonly_copy=true'

validate_fixture_log() {
  /usr/bin/python3 -B - "$1" "$2" <<'PY'
import pathlib
import re
import sys
path, action = pathlib.Path(sys.argv[1]), sys.argv[2]
markers = {
    "prepare": "D10_PRODUCT_IMAGE_PREPARE=PASS endpoints=4 journal=22 audit=44 ledger=0 server_started=false authorization=BLOCKED",
    "verify": "D10_PRODUCT_IMAGE_VERIFY=PASS endpoints=4 journal=22 audit=44 ledger=0 state_unchanged=true locks_released=true authorization=BLOCKED",
    "read": "D10_PRODUCT_IMAGE_READ=PASS normal_tls=true generation=3 journal=22 ledger=0 parent_api=true viewer403=true wrong401=true writes423=true authorization=BLOCKED",
    "negative-prepare": "D10_PRODUCT_IMAGE_NEGATIVE_PREPARE=PASS owned_input_only=true authorization=BLOCKED",
    "negative-restore": "D10_PRODUCT_IMAGE_NEGATIVE_RESTORE=PASS original_input_restored=true authorization=BLOCKED",
}
if action not in markers or path.stat().st_size > 65536:
    raise SystemExit("product-image fixture result missing or oversized")
raw = path.read_text(encoding="utf-8")
if raw.count(markers[action]) != 1 or len(re.findall(r"^=== RUN   TestCandidateD10ProductImageFixture$", raw, re.MULTILINE)) != 1 or len(re.findall(r"^--- PASS: TestCandidateD10ProductImageFixture \(", raw, re.MULTILINE)) != 1 or not raw.endswith("PASS\n"):
    raise SystemExit("product-image fixture action lacks actual passing evidence")
print(markers[action])
PY
}

fixture_action() {
  action=$1
  negative=${2:-}
  action_log="$private/$action-${negative:-normal}.private.log"
  as_fixture /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC \
    HOME="$fixture_root" TMPDIR="$fixture_root/tmp" \
    CHENGWANG_D10_ROOT="$fixture_root" CHENGWANG_D10_ACTION="$action" CHENGWANG_D10_NEGATIVE="$negative" \
    /usr/bin/timeout --signal=TERM --kill-after=5s 40s "$fixture_root/bin/product-image.test" \
      -test.run='^TestCandidateD10ProductImageFixture$' -test.v -test.timeout=35s \
    2>&1 | /usr/bin/tee "$action_log" >/dev/null
  validate_fixture_log "$action_log" "$action"
}
phase=fixture-prepare
fixture_action prepare

create_container() {
  endpoint=$1
  network_mode=$2
  name=$3
  created=$(/usr/bin/docker container create --pull never --platform linux/amd64 \
    --name "$name" --label "$label_key=$fixture_uuid" \
    --network "$network_mode" --read-only \
    --cap-drop ALL --security-opt no-new-privileges:true \
    --pids-limit 128 --memory 256m --memory-swap 256m --cpus 1 \
    --ulimit nofile=1024:1024 --restart no --stop-timeout 15 \
    --mount "type=bind,src=$endpoint,dst=$endpoint,readonly,bind-propagation=rprivate" \
    --mount "type=bind,src=$endpoint/trust,dst=$endpoint/trust,bind-propagation=rprivate" \
    --mount "type=bind,src=$endpoint/data,dst=$endpoint/data,bind-propagation=rprivate" \
    "$image_id" --config "$endpoint/trust-config.json" --product-config "$endpoint/product-config.json")
  [[ "$created" =~ ^[a-f0-9]{64}$ ]]
  container_ids+=("$created")
}

inspect_container() {
  container_id=$1
  endpoint=$2
  network_mode=$3
  state=$4
  label=$5
  /usr/bin/docker container inspect "$container_id" > "$private/container-inspect.json"
  /usr/bin/python3 -B "$checker" inspect \
    --image-inspect "$private/image-inspect.json" --container-inspect "$private/container-inspect.json" \
    --image-id "$image_id" --source-commit "$source_commit" \
    --expected-private-source "$endpoint" --expected-state-source "$endpoint/trust" \
    --expected-network-mode "$network_mode" --container-status "$state" \
    --report "$evidence/product-image-$label-inspect.json"
}

# Record actual /proc identity without dumping arbitrary cmdline or environment.
# This function body is kept separate from docker inspect's local declarations.
record_pid1() {
  container_id=$1; endpoint=$2; label=$3
  pid=$(/usr/bin/docker container inspect --format '{{.State.Pid}}' "$container_id")
  [[ "$pid" =~ ^[1-9][0-9]*$ ]] && test "$pid" -gt 1
  /usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$pid" "$endpoint" \
    "$run_root/bin/image-trust-api-static" "$source_commit" "$image_id" "$container_id" <<'PY' \
    | /usr/bin/tee "$evidence/product-image-$label-pid1.json" >/dev/null
import hashlib
import json
import pathlib
import sys
pid, endpoint, binary, commit, image, container = sys.argv[1:]
proc = pathlib.Path("/proc") / pid
expected = ["/app/image-trust-api", "--config", endpoint + "/trust-config.json", "--product-config", endpoint + "/product-config.json"]
actual = (proc / "cmdline").read_bytes().rstrip(b"\0").decode("utf-8").split("\0")
status = dict(line.split(":", 1) for line in (proc / "status").read_text(encoding="ascii").splitlines())
if actual != expected or any(status[name].split() != ["10001"] * 4 for name in ("Uid", "Gid")) or status["NSpid"].split()[-1] != "1" or status["NoNewPrivs"].strip() != "1" or any(int(status[name].strip(), 16) != 0 for name in ("CapInh", "CapPrm", "CapEff", "CapBnd", "CapAmb")):
    raise SystemExit("actual product image PID1 identity or sandbox mismatch")
expected_hash = hashlib.sha256(pathlib.Path(binary).read_bytes()).hexdigest()
if hashlib.sha256((proc / "exe").read_bytes()).hexdigest() != expected_hash:
    raise SystemExit("actual product image executable differs from accepted static binary")
print(json.dumps({"schema": "chengwang.product-image-pid1/v1", "authorization": "BLOCKED", "production": False,
    "sourceCommit": commit, "localImageID": image, "containerID": container, "hostPID": int(pid),
    "namespacePID": 1, "uid": 10001, "gid": 10001, "capabilities": "none", "noNewPrivileges": True,
    "defaultProductEntrypoint": True, "expectedConfigurationArguments": True, "actualExecutableSHA256": expected_hash}, sort_keys=True))
PY
  test "$(/usr/bin/docker container inspect --format '{{.State.Pid}}' "$container_id")" = "$pid"
}

for kind in "${kinds[@]}"; do
  phase="container-start-$kind"
  if test "$kind" = trusted; then network_mode=none
  else network_mode="container:$trusted_id"
  fi
  create_container "$fixture_root/$kind" "$network_mode" "cw-product-$fixture_uuid-$kind"
  endpoint_ids+=("$created")
  /usr/bin/docker container start "$created" >/dev/null
  inspect_container "$created" "$fixture_root/$kind" "$network_mode" running "$kind-running"
  record_pid1 "$created" "$fixture_root/$kind" "$kind-running"
  if test "$kind" = trusted; then
    trusted_id=$created
    trusted_pid=$(/usr/bin/docker container inspect --format '{{.State.Pid}}' "$trusted_id")
  fi
done

wait_normal_tls() {
  /usr/bin/sudo --non-interactive /usr/bin/nsenter --net="/proc/$trusted_pid/ns/net" -- \
    /usr/bin/setpriv --reuid=10001 --regid=10001 --clear-groups --bounding-set=-all \
      --inh-caps=-all --ambient-caps=-all --no-new-privs \
    /usr/bin/python3 -B - "$fixture_root/ca.pem" <<'PY'
import socket
import ssl
import sys
import time
context = ssl.create_default_context(cafile=sys.argv[1])
deadline = time.monotonic() + 10
while True:
    try:
        with socket.create_connection(("127.0.0.1", 17812), timeout=0.5) as stream:
            with context.wrap_socket(stream, server_hostname="127.0.0.1"):
                pass
        break
    except (OSError, ssl.SSLError):
        if time.monotonic() >= deadline:
            raise SystemExit("actual product-image normal TLS listener not ready")
        time.sleep(0.1)
print("D10_PRODUCT_IMAGE_TLS_READY=PASS normal_verification=true http_requests=0")
PY
}
wait_normal_tls

# Fixtures use already verified, fixed-commit OFL fonts. Keep every pathname
# accessible to UID10001, not behind RUN_ROOT's runner-owned 0700 directory.
/usr/bin/sudo --non-interactive /usr/bin/install -d -m 0700 -o 10001 -g 10001 \
  "$fixture_root/fonts" "$fixture_root/font-cache" "$fixture_root/evidence"
for font in NotoSansCJKsc-Regular.otf NotoSansCJKsc-Bold.otf LICENSE; do
  /usr/bin/sudo --non-interactive /usr/bin/install -m 0444 -o 10001 -g 10001 "$run_root/fonts/$font" "$fixture_root/fonts/$font"
done
as_fixture /usr/bin/python3 -B - "$fixture_root" <<'PY'
import hashlib
import pathlib
import sys
import xml.etree.ElementTree as ET
root = pathlib.Path(sys.argv[1])
pins = {"NotoSansCJKsc-Regular.otf": "2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b", "NotoSansCJKsc-Bold.otf": "b5f0d1a190a7f9b43c310a8850630af12553df32c4c050543f9059732d9b4c0a", "LICENSE": "6a73f9541c2de74158c0e7cf6b0a58ef774f5a780bf191f2d7ec9cc53efe2bf2"}
for name, expected in pins.items():
    if hashlib.sha256((root / "fonts" / name).read_bytes()).hexdigest() != expected:
        raise SystemExit("product-image browser font pin mismatch")
conf = ET.Element("fontconfig")
ET.SubElement(conf, "dir").text = str(root / "fonts")
ET.SubElement(conf, "cachedir").text = str(root / "font-cache")
for family in ("sans-serif", "system-ui"):
    alias = ET.SubElement(conf, "alias")
    ET.SubElement(alias, "family").text = family
    ET.SubElement(ET.SubElement(alias, "prefer"), "family").text = "Noto Sans CJK SC"
ET.ElementTree(conf).write(root / "fontconfig.conf", encoding="utf-8", xml_declaration=True)
PY

parent_netns=$(/usr/bin/readlink /proc/self/ns/net)
parent_mountns=$(/usr/bin/readlink /proc/self/ns/mnt)
phase=actual-image-browser
/usr/bin/sudo --non-interactive /usr/bin/nsenter --net="/proc/$trusted_pid/ns/net" -- \
  /usr/bin/unshare --mount -- /usr/bin/bash --noprofile --norc -c '
    set -euo pipefail
    /usr/bin/mount --make-rprivate /
    for readonly in "$1" "$2/fonts"; do
      /usr/bin/mount --bind "$readonly" "$readonly"
      /usr/bin/mount -o remount,bind,ro "$readonly"
    done
    test "$(/usr/bin/readlink /proc/self/ns/net)" != "$6"
    test "$(/usr/bin/readlink /proc/self/ns/mnt)" != "$7"
    test "$(/usr/sbin/ip -o link show | /usr/bin/wc -l)" -eq 1
    /usr/sbin/ip -o link show lo | /usr/bin/grep -q LOOPBACK
    exec /usr/bin/setpriv --reuid=10001 --regid=10001 --clear-groups \
      --bounding-set=-all --inh-caps=-all --ambient-caps=-all --no-new-privs \
      /usr/bin/env -i PATH="$(/usr/bin/dirname "$3"):/usr/bin:/bin" \
      HOME="$2" TMPDIR="$2/tmp" LANG=C.UTF-8 TZ=UTC PYTHONDONTWRITEBYTECODE=1 \
      CERTUTIL_BINARY="$5" FONTCONFIG_FILE="$2/fontconfig.conf" \
      /usr/bin/timeout --signal=TERM --kill-after=5s 160s "$3" \
        "$1/chengwang/web/scripts/verify-trust-browser.mjs" \
        --fixture-root "$2" --chrome "$4" --evidence-dir "$2/evidence" --transport https
  ' chengwang-product-image-browser "$browser_source" "$fixture_root" \
    "$node_binary" "$chrome_binary" "$certutil_binary" "$parent_netns" "$parent_mountns" \
  > "$private/browser-supervisor.log" 2>&1

stop_container() {
  container_id=$1; endpoint=$2; network_mode=$3; label=$4
  /usr/bin/timeout --signal=TERM --kill-after=5s 25s /usr/bin/docker container stop --time 15 "$container_id" >/dev/null
  inspect_container "$container_id" "$endpoint" "$network_mode" exited "$label"
}
for index in 3 2 1 0; do
  phase=initial-graceful-stop
  kind=${kinds[$index]}
  if test "$kind" = trusted; then network_mode=none; else network_mode="container:$trusted_id"; fi
  stop_container "${endpoint_ids[$index]}" "$fixture_root/$kind" "$network_mode" "$kind-stopped"
done
phase=initial-state-reopen
fixture_action verify

# Restart the exact same local image/container against the same bound state.
/usr/bin/docker container start "$trusted_id" >/dev/null
phase=same-image-restart
inspect_container "$trusted_id" "$fixture_root/trusted" none running trusted-restarted
record_pid1 "$trusted_id" "$fixture_root/trusted" trusted-restarted
trusted_pid=$(/usr/bin/docker container inspect --format '{{.State.Pid}}' "$trusted_id")
wait_normal_tls
/usr/bin/sudo --non-interactive /usr/bin/nsenter --net="/proc/$trusted_pid/ns/net" -- \
  /usr/bin/setpriv --reuid=10001 --regid=10001 --clear-groups --bounding-set=-all \
    --inh-caps=-all --ambient-caps=-all --no-new-privs \
  /usr/bin/env -i PATH=/usr/bin:/bin LANG=C.UTF-8 TZ=UTC HOME="$fixture_root" TMPDIR="$fixture_root/tmp" \
    CHENGWANG_D10_ROOT="$fixture_root" CHENGWANG_D10_ACTION=read \
  /usr/bin/timeout --signal=TERM --kill-after=5s 40s "$fixture_root/bin/product-image.test" \
    -test.run='^TestCandidateD10ProductImageFixture$' -test.v -test.timeout=35s \
  2>&1 | /usr/bin/tee "$private/read-normal.private.log" >/dev/null
validate_fixture_log "$private/read-normal.private.log" read
stop_container "$trusted_id" "$fixture_root/trusted" none trusted-restarted-stopped
fixture_action verify

for fault in missing-checkpoint missing-tls wrong-mode unknown-config; do
  phase="negative-startup-$fault"
  fixture_action negative-prepare "$fault"
  create_container "$fixture_root/trusted" none "cw-product-$fixture_uuid-negative-$fault"
  negative_id=$created
  /usr/bin/docker container start "$negative_id" >/dev/null
  code=$(/usr/bin/timeout --signal=TERM --kill-after=5s 25s /usr/bin/docker container wait "$negative_id")
  test "$code" = 1
  /usr/bin/docker container inspect "$negative_id" > "$private/negative-inspect.json"
  /usr/bin/python3 -B - "$private/negative-inspect.json" "$image_id" "$fixture_uuid" "$fault" \
    > "$evidence/product-image-negative-$fault.json" <<'PY'
import json
import pathlib
import sys
raw, image, fixture, fault = sys.argv[1:]
rows = json.loads(pathlib.Path(raw).read_text(encoding="utf-8"))
if not isinstance(rows, list) or len(rows) != 1:
    raise SystemExit("invalid negative container inspection")
row = rows[0]
if row.get("Image") != image or row.get("Config", {}).get("Labels", {}).get("org.chengwang.product-image-fixture") != fixture or row.get("State", {}).get("Running") is not False or row["State"].get("ExitCode") != 1 or row["State"].get("OOMKilled") is not False or row["State"].get("Pid") != 0:
    raise SystemExit("negative product image did not fail closed")
print(json.dumps({"schema": "chengwang.product-image-negative/v1", "authorization": "BLOCKED", "production": False, "case": fault, "localImageID": image, "exitCode": 1, "oomKilled": False, "running": False}, sort_keys=True))
PY
  fixture_action negative-restore "$fault"
done
fixture_action verify

# Only explicit bounded, credential-checked public evidence crosses out of the
# private fixture. The raw ready/configuration/keys/NSS/daemon JSON never do.
phase=public-evidence-validation
/usr/bin/sudo --non-interactive /usr/bin/python3 -B - "$fixture_root" "$private" <<'PY'
import hashlib
import json
import pathlib
import re
import sys
root, destination = map(pathlib.Path, sys.argv[1:])
ready = json.loads((root / "ready.json").read_text(encoding="utf-8"))
secrets = [ready[key] for key in ("auditorToken", "viewerToken", "wrongToken")]
secrets.append((root / "admin-token.private").read_text(encoding="utf-8").strip())
report_path = root / "evidence" / "trust-https-browser-report.json"
raw = report_path.read_bytes()
report = json.loads(raw)
expected = {"schema": "chengwang.trust-console-browser-https/v1", "outcome": "PASS", "failure": "", "boundary": "ISOLATED_REAL_BROWSER_REAL_CANDIDATE", "authorization": "BLOCKED", "deviceActionsExecuted": False, "transport": "HTTPS_127_PRIVATE_NSS_NORMAL_VERIFICATION", "chromeSandbox": "DISABLED_CI_ONLY_OUTER_ISOLATION_REQUIRED", "mockedResponses": False, "injectedFetch": False, "tlsBypass": False, "screenshotCount": 4, "browserGroupStopped": True, "cjkFontVerified": True}
if any(type(report.get(key)) is not type(value) or report[key] != value for key, value in expected.items()) or any(type(report.get(key)) is not int or report[key] != 0 for key in ("consoleErrors", "consoleWarnings", "runtimeErrors", "cspErrors", "assetErrors", "forbiddenRequests")):
    raise SystemExit("actual product-image browser report failed")
checks = report.get("checks")
if not isinstance(checks, list) or len(checks) != 45 or hashlib.sha256("\n".join(checks).encode()).hexdigest() != "35954742fa0f04665850ebe8072450a5ae808eecd19717b6137b2c8ebf9560c0":
    raise SystemExit("actual product-image browser lost accepted 45 checks")
canonical = lambda value: json.dumps(value, sort_keys=True, separators=(",", ":"))
if type(report.get("requestCount")) is not int or report["requestCount"] != 16 or canonical(report.get("httpStatusCounts")) != canonical({"200": 13, "401": 2, "403": 1}) or canonical(report.get("parentAPI")) != canonical({"operationsStatus": 200, "capabilitiesStatus": 200}):
    raise SystemExit("actual product-image browser API observations incomplete")
trust, tls = report.get("normalTrust", {}), report.get("tls", {})
if trust.get("method") != "PRIVATE_NSS_SQL_LOCAL_CA" or trust.get("legacyDatabaseAbsent") is not True or trust.get("trustFlags") != "C,," or trust.get("tool") != "preinstalled-certutil" or tls.get("securityState") != "secure" or tls.get("protocol") not in ("TLS 1.2", "TLS 1.3") or tls.get("leafSignatureVerified") is not True or tls.get("ipSANVerified") is not True or type(tls.get("serverChainLength")) is not int or not 1 <= tls["serverChainLength"] <= 8 or any(not re.fullmatch(r"[a-f0-9]{64}", str(trust.get(name))) or trust[name] != tls.get(name) for name in ("caSHA256", "leafSHA256")):
    raise SystemExit("actual product-image normal TLS proof incomplete")
expected_negatives = [{"kind": kind, "error": error, "businessMounted": False, "httpResponses": 0, "apiRequests": 0, "authorizationHeaders": 0} for kind, error in (("untrusted", "net::ERR_CERT_AUTHORITY_INVALID"), ("wrong-san", "net::ERR_CERT_COMMON_NAME_INVALID"), ("expired", "net::ERR_CERT_DATE_INVALID"))]
if canonical(report.get("negativeTLS")) != canonical(expected_negatives):
    raise SystemExit("actual product-image browser certificate negatives incomplete")
names = ["trust-https-browser-report.json", "trust-https-console-desktop-disconnected.png", "trust-https-console-desktop-auditor.png", "trust-https-console-desktop-viewer-forbidden.png", "trust-https-console-mobile-auditor.png"]
if {path.name for path in (root / "evidence").iterdir()} != set(names):
    raise SystemExit("unexpected private browser evidence file")
for name in names:
    path = root / "evidence" / name
    data = path.read_bytes()
    if path.is_symlink() or not path.is_file() or len(data) > 5 * 1024 * 1024 or any(secret.encode() in data for secret in secrets) or b"PRIVATE KEY" in data or (name.endswith(".png") and data[:8] != b"\x89PNG\r\n\x1a\n"):
        raise SystemExit("product-image browser evidence containment failed")
    output = destination / ("product-image-" + name)
    with output.open("xb") as handle:
        handle.write(data)
    output.chmod(0o644)
print("D10_PRODUCT_IMAGE_BROWSER=PASS checks=45 requests=16 normal_tls=true negative_certificates=3 client_http_and_bearer=0 mocked_responses=false product_image_executed=true production=false")
PY
for name in product-image-trust-https-browser-report.json \
  product-image-trust-https-console-desktop-disconnected.png \
  product-image-trust-https-console-desktop-auditor.png \
  product-image-trust-https-console-desktop-viewer-forbidden.png \
  product-image-trust-https-console-mobile-auditor.png; do
  /usr/bin/cp -- "$private/$name" "$evidence/$name"
done
/usr/bin/python3 -B - "$source_commit" "$image_id" > "$evidence/product-image-outcome.json" <<'PY'
import json
import sys
print(json.dumps({"schema": "chengwang.product-image-gate/v1", "outcome": "PASS", "authorization": "BLOCKED", "production": False, "sourceCommit": sys.argv[1], "localImageID": sys.argv[2], "registryManifestDigestVerified": False, "imagePublished": False, "productImageExecuted": True, "defaultEntrypoint": True, "gracefulStops": 5, "stateReopenedAfterStops": True, "sameImageRestartReadback": True, "negativeStartupCases": 4, "browserChecks": 45, "browserHTTPSNormalVerification": True, "serverNegativeHTTPCountObserved": False}, sort_keys=True))
PY
phase=isolated-product-registry
/usr/bin/bash "$script_root/run-product-registry-gate.sh" "$run_root" "$go_binary" "$module_cache" \
  "$image_id" "$private/product-image.private.tar"
phase=isolated-product-lifecycle
/usr/bin/timeout --signal=TERM --kill-after=15s 480s \
  /usr/bin/bash "$script_root/run-product-lifecycle-gate.sh" "$run_root" "$go_binary" "$module_cache" \
  "$image_id" "$private/product-image.private.tar"
phase=isolated-product-crash
/usr/bin/timeout --signal=TERM --kill-after=15s 720s \
  /usr/bin/bash "$script_root/run-product-crash-gate.sh" "$run_root" "$go_binary" "$module_cache" \
  "$image_id" "$private/product-image.private.tar"
phase=isolated-product-state
/usr/bin/timeout --signal=TERM --kill-after=15s 1800s \
  /usr/bin/bash "$script_root/run-product-state-gate.sh" "$run_root" "$go_binary" "$module_cache" \
  "$image_id" "$private/product-image.private.tar"
phase=isolated-product-source-wave1
/usr/bin/timeout --signal=TERM --kill-after=15s 900s \
  /usr/bin/bash "$script_root/run-product-source-gate.sh" "$run_root" "$go_binary" "$module_cache" \
  "$image_id" "$private/product-image.private.tar"
phase=isolated-product-source-tls
/usr/bin/timeout --signal=TERM --kill-after=15s 900s \
  /usr/bin/bash "$script_root/run-product-source-tls-gate.sh" "$run_root" "$go_binary" "$module_cache" \
  "$image_id" "$private/product-image.private.tar"
acceptance_completed=true
echo 'D10_PRODUCT_IMAGE_GATE=PASS actual_default_entrypoint=true actual_pid1_binary_hash=true graceful_stops=5 restart_readback=true fail_closed_startups=4 product_image_executed=true image_published=false authorization=BLOCKED production=false'
