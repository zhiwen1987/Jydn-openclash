#!/usr/bin/env bash
set -euo pipefail
umask 077
ulimit -c 0
ulimit -t 1800
ulimit -n 1024
ulimit -f 131072
ulimit -u 1024
test "$(/usr/bin/id -u)" != 0
test "$GOWORK" = off
test "$("$GO_BINARY" env GOVERSION)" = go1.25.8
# Durable state tests need native Linux filesystems, not tmpfs/overlay/NFS.
# No additional source/cache write permission is granted: TMPDIR is already
# the run-owned, private temporary directory established by run-linux-ci.sh.
test "$TMPDIR" = "$RUN_ROOT/tmp"
test "$(/usr/bin/stat -c '%u:%g:%a' -- "$TMPDIR")" = "$(/usr/bin/id -u):$(/usr/bin/id -g):700"
case "$(/usr/bin/findmnt -n -T "$TMPDIR" -o FSTYPE)" in
  ext4|xfs) ;;
  *) echo 'durable trust-state tests require native ext4 or XFS' >&2; exit 1;;
esac
echo 'IMAGE_BINDING_TRUSTSTATE_FILESYSTEM=PASS private_run_tmp=true native_ext4_or_xfs=true'
test "$(/usr/bin/readlink /proc/self/ns/net)" != "$PARENT_NETNS"
test "$(/usr/bin/readlink /proc/self/ns/mnt)" != "$PARENT_MOUNTNS"
/usr/bin/grep -qE '^NoNewPrivs:[[:space:]]+1$' /proc/self/status
for field in CapInh CapPrm CapEff CapBnd CapAmb; do
  /usr/bin/grep -qE "^${field}:[[:space:]]+0000000000000000$" /proc/self/status
done
test "$(/usr/sbin/ip -o link show | /usr/bin/wc -l)" -eq 1
test -z "$(/usr/sbin/ip -o route show default)"
test -z "$(/usr/sbin/ip -6 -o route show default)"
source_root=$(/usr/bin/git -C "$MODULE_ROOT" rev-parse --show-toplevel)
for mount_path in "$source_root" "$MODULE_ROOT" "$GOMODCACHE" "$RUN_ROOT/remote-verification" "$source_root/chengwang/web/node_modules" "$RUN_ROOT/fonts"; do
  /usr/bin/findmnt -n -T "$mount_path" -o OPTIONS | /usr/bin/grep -qE '(^|,)ro(,|$)'
done
/usr/bin/python3 -B - <<'PY'
import socket
with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as server:
    server.bind(("127.0.0.1", 0))
    server.listen(1)
    with socket.create_connection(server.getsockname(), timeout=1) as client:
        connection, _ = server.accept()
        connection.close()
for family, address in ((socket.AF_INET, ("1.1.1.1", 443)),
                        (socket.AF_INET6, ("2606:4700:4700::1111", 443, 0, 0))):
    try:
        with socket.socket(family, socket.SOCK_STREAM) as stream:
            stream.settimeout(1)
            stream.connect(address)
    except OSError:
        continue
    raise SystemExit("external connectivity unexpectedly available")
print("IMAGE_BINDING_NETWORK_NAMESPACE=PASS loopback=usable external_interfaces=0 ipv4_external=blocked ipv6_external=blocked")
PY
/usr/bin/id
/usr/bin/grep -E '^(NoNewPrivs|Cap(Inh|Prm|Eff|Bnd|Amb)):' /proc/self/status
/usr/sbin/ip -o link show
/usr/sbin/ip -o route show table all
cd "$MODULE_ROOT"
/usr/bin/find . -type f -print0 | /usr/bin/sort -z | /usr/bin/xargs -0 /usr/bin/sha256sum > "$RUN_ROOT/evidence/source-before.sha256"
# The backend now composes the parent API, authn/authz, evidence and DTO
# packages as well as the sibling signature verifier. Bind their actual
# checkout bytes too, not only the nested module's source directory.
(
  cd "$source_root"
  /usr/bin/git ls-files -z -- 'chengwang/**' '.github/workflows/chengwang-image-binding.yml' \
    | /usr/bin/xargs -0 /usr/bin/sha256sum --
) > "$RUN_ROOT/evidence/checkout-before.sha256"
/usr/bin/python3 -B scripts/check-go-json.py --self-test
/usr/bin/python3 -B scripts/test-check-go-json.py
/usr/bin/python3 -B scripts/test-check-go-json-probe.py
/usr/bin/python3 -B "$source_root/chengwang/deploy/product-candidate/test_check_product_image.py" \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/product-image-checker-tests.log"
/usr/bin/grep -qx 'PRODUCT_IMAGE_CHECKER_TESTS=PASS tests=18 skips=0 simulated_elf=true actual_image_not_proven=true' \
  "$RUN_ROOT/evidence/product-image-checker-tests.log"
/usr/bin/python3 -B "$source_root/chengwang/deploy/product-candidate/test_check_product_registry.py" \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/product-registry-checker-tests.log"
/usr/bin/grep -qx 'PRODUCT_REGISTRY_CHECK_TESTS=PASS tests=33 passed=33 skipped=0 synthetic_only=true' \
  "$RUN_ROOT/evidence/product-registry-checker-tests.log"
/usr/bin/python3 -B "$source_root/chengwang/deploy/product-candidate/test_lifecycle_image_profile.py" \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/product-lifecycle-profile-tests.log"
/usr/bin/grep -qx 'D12_IMAGE_PROFILE_TESTS=PASS tests=5 skipped=0 synthetic_only=true' \
  "$RUN_ROOT/evidence/product-lifecycle-profile-tests.log"
/usr/bin/python3 -B "$source_root/chengwang/deploy/product-candidate/test_check_product_lifecycle.py" \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/product-lifecycle-verifier-tests.log"
/usr/bin/grep -qx 'PRODUCT_LIFECYCLE_VERIFIER_TESTS=PASS synthetic_only=true tests=27 skipped=0' \
  "$RUN_ROOT/evidence/product-lifecycle-verifier-tests.log"
/usr/bin/python3 -B "$source_root/chengwang/deploy/product-candidate/test_crash_image_profile.py" \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/product-crash-profile-tests.log"
/usr/bin/grep -qx 'D12_CRASH_IMAGE_PROFILE_TESTS=PASS tests=6 skipped=0 synthetic_only=true' \
  "$RUN_ROOT/evidence/product-crash-profile-tests.log"
/usr/bin/python3 -B "$source_root/chengwang/deploy/product-candidate/test_check_product_crash.py" \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/product-crash-verifier-tests.log"
/usr/bin/grep -qx 'PRODUCT_CRASH_VERIFIER_TESTS=PASS synthetic_only=true tests=27 skipped=0' \
  "$RUN_ROOT/evidence/product-crash-verifier-tests.log"
/usr/bin/python3 -B "$source_root/chengwang/deploy/product-candidate/test_state_image_profile.py" \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/product-state-profile-tests.log"
/usr/bin/grep -qx 'D12_STATE_IMAGE_PROFILE_TESTS=PASS tests=8 skipped=0 synthetic_only=true' \
  "$RUN_ROOT/evidence/product-state-profile-tests.log"
/usr/bin/python3 -B "$source_root/chengwang/deploy/product-candidate/test_check_product_state.py" \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/product-state-verifier-tests.log"
/usr/bin/grep -qx 'PRODUCT_STATE_VERIFIER_TESTS=PASS synthetic_only=true tests=32 skipped=0' \
  "$RUN_ROOT/evidence/product-state-verifier-tests.log"
/usr/bin/python3 -B scripts/test-browser-process-guard.py \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/browser-process-guard-tests.log"
/usr/bin/grep -qx 'D8_BROWSER_PROCESS_GUARD_TESTS=PASS real_linux_processes=true simulated_chrome=true' \
  "$RUN_ROOT/evidence/browser-process-guard-tests.log"
(
  cd "$RUN_ROOT/remote-verification"
  test "$("$GO_BINARY" env GOWORK)" = off
  /usr/bin/timeout --signal=TERM --kill-after=10s 180s "$GO_BINARY" list -m -json all \
    > "$RUN_ROOT/evidence/remote-modules-offline.json"
  /usr/bin/python3 -B "$MODULE_ROOT/scripts/module-verification.py" check \
    "$RUN_ROOT" "$GOMODCACHE" "$RUN_ROOT/evidence/remote-modules-offline.json"
  /usr/bin/timeout --signal=TERM --kill-after=10s 180s "$GO_BINARY" mod verify \
    | /usr/bin/tee "$RUN_ROOT/evidence/module-verification-offline.txt"
  /usr/bin/python3 -B "$MODULE_ROOT/scripts/module-verification.py" check \
    "$RUN_ROOT" "$GOMODCACHE" "$RUN_ROOT/evidence/remote-modules-offline.json"
)
test "$("$GO_BINARY" env GOWORK)" = off
echo 'IMAGE_BINDING_BUILD_WORKSPACE=off'
# Existing locked packages were downloaded with --ignore-scripts. All
# repository frontend code, native optional dependencies, test workers and
# compilers execute only here: no external network, no capabilities, and
# read-only source/node_modules. Generated output remains in the private run.
test -x "$NODE_BINARY"
test -x "$CHROME_BINARY"
"$NODE_BINARY" -e 'if(Number(process.versions.node.split(".")[0])<22||typeof WebSocket!=="function")process.exit(1)'
"$CHROME_BINARY" --version
# A DOM containing Chinese is not evidence that a Linux browser can render
# Chinese. Verify pinned input data, use an exclusively private fontconfig
# and cache, then prove both regular/bold SC faces are actually selected.
/usr/bin/python3 -B - "$RUN_ROOT" <<'PY'
import hashlib
import json
import pathlib
import sys
import xml.etree.ElementTree as ET
root = pathlib.Path(sys.argv[1])
pins = {
    "NotoSansCJKsc-Regular.otf": (16437364, "2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b"),
    "NotoSansCJKsc-Bold.otf": (17002248, "b5f0d1a190a7f9b43c310a8850630af12553df32c4c050543f9059732d9b4c0a"),
    "LICENSE": (4301, "6a73f9541c2de74158c0e7cf6b0a58ef774f5a780bf191f2d7ec9cc53efe2bf2"),
}
files = []
for name, (size, digest) in pins.items():
    path = root / "fonts" / name
    raw = path.read_bytes()
    if path.is_symlink() or len(raw) != size or hashlib.sha256(raw).hexdigest() != digest:
        raise SystemExit("test CJK font pin mismatch")
    files.append({"name": name, "bytes": size, "sha256": digest})
if {p.name for p in (root / "fonts").iterdir()} != set(pins):
    raise SystemExit("unexpected test font input")
conf = ET.Element("fontconfig")
ET.SubElement(conf, "dir").text = str(root / "fonts")
ET.SubElement(conf, "cachedir").text = str(root / "font-cache")
for family in ("sans-serif", "system-ui"):
    alias = ET.SubElement(conf, "alias")
    ET.SubElement(alias, "family").text = family
    ET.SubElement(ET.SubElement(alias, "prefer"), "family").text = "Noto Sans CJK SC"
ET.ElementTree(conf).write(root / "fontconfig.conf", encoding="utf-8", xml_declaration=True)
(root / "font-cache").mkdir(mode=0o700)
(root / "evidence" / "browser-font-manifest.json").write_text(json.dumps({
    "schema": "chengwang.ci-browser-fonts/v1", "testOnly": True,
    "upstream": "https://github.com/notofonts/noto-cjk", "commit": "f8d157532fbfaeda587e826d4cd5b21a49186f7c",
    "license": "SIL Open Font License 1.1", "readonlyMount": True, "files": files,
}, sort_keys=True) + "\n", encoding="utf-8")
PY
/usr/bin/cp -- "$RUN_ROOT/fonts/LICENSE" "$RUN_ROOT/evidence/browser-font-LICENSE.txt"
/usr/bin/fc-cache --force "$RUN_ROOT/fonts"
/usr/bin/fc-match -f '%{family}\n%{file}\n' ':lang=zh-cn' > "$RUN_ROOT/evidence/browser-font-regular.txt"
/usr/bin/fc-match -f '%{family}\n%{file}\n' ':lang=zh-cn:weight=bold' > "$RUN_ROOT/evidence/browser-font-bold.txt"
/usr/bin/python3 -B - "$RUN_ROOT" <<'PY'
import pathlib
import sys
root = pathlib.Path(sys.argv[1])
for kind, name in (("regular", "NotoSansCJKsc-Regular.otf"), ("bold", "NotoSansCJKsc-Bold.otf")):
    observed = (root / "evidence" / ("browser-font-" + kind + ".txt")).read_text(encoding="utf-8").splitlines()
    if observed != ["Noto Sans CJK SC", str(root / "fonts" / name)]:
        raise SystemExit("actual Chinese font selection failed")
print("D8_CJK_FONT_INPUTS=PASS pinned_commit=true sha256=true readonly_fonts=true private_fontconfig_cache=true regular_and_bold=true")
PY
web_root="$source_root/chengwang/web"
(
  cd "$web_root"
  /usr/bin/timeout --signal=TERM --kill-after=10s 180s "$NODE_BINARY" node_modules/typescript/bin/tsc \
    -p tsconfig.app.json --noEmit --incremental --tsBuildInfoFile "$RUN_ROOT/app.tsbuildinfo"
  /usr/bin/timeout --signal=TERM --kill-after=10s 180s "$NODE_BINARY" node_modules/typescript/bin/tsc \
    -p tsconfig.node.json --noEmit --incremental --tsBuildInfoFile "$RUN_ROOT/node.tsbuildinfo"
  /usr/bin/timeout --signal=TERM --kill-after=10s 180s "$NODE_BINARY" node_modules/vitest/vitest.mjs run --configLoader runner \
    --fsModuleCachePath "$RUN_ROOT/vitest-module-cache" \
    --reporter=default --reporter=json --outputFile "$RUN_ROOT/evidence/frontend-vitest.json" \
    2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/frontend-vitest.log"
  /usr/bin/timeout --signal=TERM --kill-after=10s 180s "$NODE_BINARY" node_modules/eslint/bin/eslint.js . \
    2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/frontend-eslint.log"
  /usr/bin/timeout --signal=TERM --kill-after=10s 180s "$NODE_BINARY" node_modules/vite/bin/vite.js build --configLoader runner \
    --outDir "$RUN_ROOT/web-dist" --emptyOutDir \
    2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/frontend-build.log"
)
/usr/bin/python3 -B - "$RUN_ROOT/evidence/frontend-vitest.json" <<'PY'
import hashlib
import json
import pathlib
import sys
report = json.loads(pathlib.Path(sys.argv[1]).read_text(encoding="utf-8"))
# Retain all 77 prior cases and the 33 exact P1 unit scenarios. The seven
# single-flight cases are a separate increment, never a replacement baseline.
# Subscription increment: 40 transport + 32 component + one App integration.
# Three decision-eligibility cases extend, never replace, that baseline.
# Four opt-in request-binding checks extend the accepted 193-case baseline.
# Twenty-five feedback cases extend, never replace, that accepted 197-case set.
# Eighteen EOF-cleanup cases extend the 222-case set. One existing named
# cancellation-settlement case explicitly migrates to rejected JSON after EOF;
# its non-await, settlement, ordering and redaction assertions remain enforced.
# Existing App capability-state/offline cases now reject unsupported claims;
# twenty truthfulness/error/ownership/deadline cases extend the accepted 240 names.
# Forty-four bounded snapshot wire/display cases extend the accepted 260 names.
# Two overview-mode cases extend that 304-case requirement without substituting
# demo origin or a read-only page for the actual control mode/authorization.
# These are mocked checks, not real agent/subscription/browser evidence.
if report.get("success") is not True or report.get("numFailedTests") != 0 or report.get("numPendingTests") != 0 or report.get("numTodoTests", 0) != 0 or report.get("numPassedTests") != 197 + 25 + 18 + 20 + 44 + 2 or report.get("numPassedTests") != report.get("numTotalTests"):
    raise SystemExit("frontend unit transcript failed, skipped or incomplete")
required = {"App.test.tsx", "OperationCenter.test.tsx", "api.test.ts", "ImageTrustConsole.test.tsx", "image-trust-api.test.ts", "probe-api.test.ts", "ProbeReadback.test.tsx", "subscription-api.test.ts", "Subscriptions.test.tsx", "SubscriptionsFeedback.test.tsx", "ProbeEofCleanup.test.ts", "CapabilityTruth.test.tsx", "SnapshotTruth.test.tsx", "DemoModeTruth.test.tsx"}
results = report.get("testResults", [])
if len(results) != len(required) or {pathlib.Path(result["name"]).name for result in results} != required:
    raise SystemExit("frontend required test file set changed")
if any(result.get("status") != "passed" or not result.get("assertionResults") or any(case.get("status") != "passed" for case in result["assertionResults"]) for result in results):
    raise SystemExit("frontend test file has missing or non-passing cases")
# Retain all 69 actually accepted names from db1f018 run 39776115304.
baseline = {
    "App.test.tsx": (9, "ede9f83603b68390c1c61bfcdd8c2de171cc69e805cf318437dafdfcd4d3b94a"),
    "OperationCenter.test.tsx": (8, "8e0a8700ad2d1d3d58b87c7f215798e12a1f4658e65a41b0557aea5d37b0992f"),
    "api.test.ts": (3, "af87cc03df0bb1d89d064461dd8ad45e7accbb7811ca06d12ee37b5de3f9c670"),
    "ImageTrustConsole.test.tsx": (21, "39d7c98703a268fc2e6810e36720df7738970a914d9e2a27170ae507859b4986"),
    "image-trust-api.test.ts": (28, "0327632bcee80de191a3695700a2b65d39e6787f48b9bf2608b79ae1ccfecf69"),
}
new_prefixes = ("image trust read-only transport cancels the real unread response stream when rejecting ",
                "image trust read-only transport does not wait for or expose a ",
                "image trust read-only transport cancels only a forbidden history response ")
probe_increment = {
    "probe-api.test.ts": (21, "81955cb0b7996f5659a4d70a5d6cd56531f79a33f24e6066b06ab2117c64764a"),
    "ProbeReadback.test.tsx": (12, "727a3ac9da8d4910b0f6ddad8bb6b78fbd44e77f07007d768b1b10e327465c05"),
}
request_binding_increment = frozenset((
    "P1 probe read-only transport adds a binding header only for an opted-in bound anonymous loopback status request",
    "P1 probe read-only transport keeps diagnostic headers absent on ordinary and protected requests",
    "P1 probe read-only transport observes cancel fulfillment and rejection without awaiting or changing the read result",
    "P1 probe read-only transport preserves synchronous and absent cancellation outcomes without exposing errors",
))
summary_singleflight_increment = frozenset((
    "P1 ProbeReadback lifecycle does not abort a manual summary when the automatic poll overlaps it",
    "P1 ProbeReadback lifecycle shares an active automatic summary instead of cancelling it on a click",
    "P1 ProbeReadback lifecycle releases the single-flight latch after a real abort rejection at the deadline",
    "P1 ProbeReadback lifecycle does not let an obsolete StrictMode completion unlock a newer summary",
    "P1 ProbeReadback lifecycle clears protected reads immediately even when a summary refresh is joined",
    "P1 ProbeReadback lifecycle rejects a timed-out late success without unlocking or overwriting its retry",
    "P1 ProbeReadback lifecycle stops polling and deadlines on unmount and ignores late summary completion",
))
summary_singleflight_sha256 = "1ac0f0ac2b63cf57b4a8e5f26e1ddf1101842407b9d6097d0c9afc7fcdead76a"
subscription_increment = {
    "subscription-api.test.ts": (40, "de4c10feb1681a8cc53b4678b094831943404ee59ceb8fbf6be3680a3a3569b6"),
    "Subscriptions.test.tsx": (32, "8a38de66374776ecfd5b6d11bbdb7b990a6bfa99fa1c9723a5c3cad85d142ad4"),
}
subscription_decision_increment = frozenset((
    "Subscriptions disables decisions for an already admitted candidate without preparing or writing",
    "Subscriptions disables decisions for an already rejected candidate without preparing or writing",
    "Subscriptions disables decisions for a quarantined candidate from an older source revision",
))
subscription_app_increment = "App opens real subscription resources and retains session across navigation"
if len(summary_singleflight_increment) != 7 or hashlib.sha256("\n".join(sorted(summary_singleflight_increment)).encode()).hexdigest() != summary_singleflight_sha256:
    raise SystemExit("single-flight frontend increment definition changed")
for result in results:
    filename = pathlib.Path(result["name"]).name
    names = [case["fullName"] for case in result["assertionResults"]]
    if len(set(names)) != len(names):
        raise SystemExit("frontend duplicate test name")
    if filename == "DemoModeTruth.test.tsx":
        if len(names) != 2 or hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest() != "b3438ab865c53ffdf53d9d104f8fb31860d471c613f479d8f7ff88d46ae43df1":
            raise SystemExit("overview mode truthfulness scenarios missing, renamed or substituted")
        continue
    if filename == "SnapshotTruth.test.tsx":
        if len(names) != 44 or hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest() != "f5d8cf23ab45fb50cde16918352285d85fb020a1b68639ca57fe015268f20c4f":
            raise SystemExit("snapshot wire/display scenarios missing, renamed or substituted")
        continue
    if filename == "CapabilityTruth.test.tsx":
        if len(names) != 20 or hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest() != "3ac9c257aa0e795d80d25a45462c86ace708f693e4fb0d2dbd5bc6431a0e9dfc":
            raise SystemExit("capability truthfulness scenarios missing, renamed or substituted")
        continue
    if filename == "ProbeEofCleanup.test.ts":
        if len(names) != 18 or hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest() != "de7d15a53dbddd3d52558f12b6de317b13ed297cc269f9a171ff706ebdec798f":
            raise SystemExit("EOF cleanup frontend scenarios missing, renamed or substituted")
        continue
    if filename == "SubscriptionsFeedback.test.tsx":
        if len(names) != 25 or hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest() != "9320b1e792e6e1b9c5a6d4c7b45a070f4b187b76e5e51fd5381d2373dd898860":
            raise SystemExit("feedback frontend scenarios missing, renamed or substituted")
        continue
    if filename in subscription_increment:
        count, digest = subscription_increment[filename]
        if filename == "Subscriptions.test.tsx":
            increment = frozenset(name for name in names if name in subscription_decision_increment)
            if len(names) != count + 3 or increment != subscription_decision_increment:
                raise SystemExit("subscription decision eligibility scenarios missing, renamed or substituted")
            names = [name for name in names if name not in subscription_decision_increment]
        if len(names) != count or hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest() != digest:
            raise SystemExit("pre-CI subscription frontend scenarios missing, renamed or substituted")
        continue
    if filename == "App.test.tsx":
        if names.count(subscription_app_increment) != 1:
            raise SystemExit("subscription App integration scenario missing or duplicated")
        names = [name for name in names if name != subscription_app_increment]
    # Also pin all 36 actual names here. The original 28-name baseline below
    # remains unchanged; the former eight prefix exclusions cannot be renamed
    # or substituted while preserving only their count.
    if filename == "image-trust-api.test.ts" and (len(names) != 36 or hashlib.sha256("\n".join(sorted(names)).encode()).hexdigest() != "a2febdcfd345b9464200ab7c4a1255ec4a8b0550364ed129b364639d61c111bb"):
        raise SystemExit("accepted complete 36 transport scenarios changed")
    if filename in probe_increment:
        count, digest = probe_increment[filename]
        retained = names
        if filename == "probe-api.test.ts":
            increment = frozenset(name for name in names if name in request_binding_increment)
            if len(names) != count + 4 or increment != request_binding_increment:
                raise SystemExit("request-binding frontend scenarios missing, renamed or substituted")
            retained = [name for name in names if name not in request_binding_increment]
        if filename == "ProbeReadback.test.tsx":
            increment = frozenset(name for name in names if name in summary_singleflight_increment)
            if len(names) != count + 7 or increment != summary_singleflight_increment or hashlib.sha256("\n".join(sorted(increment)).encode()).hexdigest() != summary_singleflight_sha256:
                raise SystemExit("single-flight frontend scenarios missing, renamed or substituted")
            retained = [name for name in names if name not in summary_singleflight_increment]
        if len(retained) != count or hashlib.sha256("\n".join(sorted(retained)).encode()).hexdigest() != digest:
            raise SystemExit("reviewed 33 P1 frontend scenarios changed")
        continue
    old = sorted(name for name in names if filename != "image-trust-api.test.ts" or not name.startswith(new_prefixes))
    count, digest = baseline[filename]
    if len(old) != count or hashlib.sha256("\n".join(old).encode()).hexdigest() != digest:
        raise SystemExit("accepted 69 frontend scenario baseline changed")
print("D8_FRONTEND_UNIT_GATE=PASS files=14 tests=" + str(report["numPassedTests"]) + " retained=117 request_binding=4 subscription_transport=40 subscription_component=32 subscription_decision_eligibility=3 subscription_app=1 subscription_feedback=25 eof_cleanup=18 capability_truth=20 snapshot_truth=44 overview_mode_truth=2 retained_names=304 prior_eof_case_migrated=true existing_app_state_copy_corrected=true existing_snapshot_fixtures_wire_corrected=3 skips=0 mocks=unit_tests_only")
PY
test -f "$RUN_ROOT/web-dist/trust.html"
test -f "$RUN_ROOT/web-dist/.vite/manifest.json"
(
  cd "$RUN_ROOT/web-dist"
  /usr/bin/find . -type f -print0 | /usr/bin/sort -z | /usr/bin/xargs -0 /usr/bin/sha256sum
) > "$RUN_ROOT/evidence/web-dist.sha256"
# This generated bundle is permission-read-only and loaded once into memory;
# source/module caches retain their independent read-only mount protection.
/usr/bin/find "$RUN_ROOT/web-dist" -type f -exec /usr/bin/chmod 0444 {} +
/usr/bin/find "$RUN_ROOT/web-dist" -type d -exec /usr/bin/chmod 0555 {} +
/usr/bin/timeout --signal=TERM --kill-after=10s 600s "$GO_BINARY" test -json -timeout=4m -count=1 ./... \
  | /usr/bin/tee "$RUN_ROOT/evidence/go-test.json"
/usr/bin/timeout --signal=TERM --kill-after=10s 600s "$GO_BINARY" test -json -race -timeout=4m -count=1 ./... \
  | /usr/bin/tee "$RUN_ROOT/evidence/go-race.json"
/usr/bin/timeout --signal=TERM --kill-after=10s 180s "$GO_BINARY" vet ./... \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/go-vet.log"
/usr/bin/python3 -B scripts/check-go-json.py --mode ordinary "$RUN_ROOT/evidence/go-test.json" "$RUN_ROOT/evidence/go-race.json"
# Build and exercise the actual opt-in candidate command, rather than calling
# a test binary a release artifact. --help exits before opening any stores or
# starting a listener. Only its digest/build metadata/help become evidence.
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" build -trimpath \
  -o "$RUN_ROOT/bin/image-trust-api" ./cmd/image-trust-api
/usr/bin/sha256sum -- "$RUN_ROOT/bin/image-trust-api" > "$RUN_ROOT/evidence/candidate-binary.sha256"
"$GO_BINARY" version -m "$RUN_ROOT/bin/image-trust-api" > "$RUN_ROOT/evidence/candidate-binary-buildinfo.txt"
/usr/bin/timeout --signal=TERM --kill-after=1s 10s "$RUN_ROOT/bin/image-trust-api" --help \
  > "$RUN_ROOT/evidence/candidate-binary-help.txt" 2>&1
echo 'IMAGE_TRUST_CANDIDATE_COMMAND=PASS trimpath=true help_only=true listener_started=false store_opened=false release_signed=false product_image_executed=false'
# Separate, actually static release-entry binary for the opt-in product image.
# Keep the previously accepted CGO=1 command and all ordinary/race scenarios.
# The later packaging gate checks real ELF program/dynamic headers; CGO=0 by
# itself is not accepted as proof of a runnable scratch image.
/usr/bin/timeout --signal=TERM --kill-after=10s 300s /usr/bin/env CGO_ENABLED=0 \
  "$GO_BINARY" build -trimpath -buildvcs=true \
  -o "$RUN_ROOT/bin/image-trust-api-static" ./cmd/image-trust-api
/usr/bin/sha256sum -- "$RUN_ROOT/bin/image-trust-api-static" \
  > "$RUN_ROOT/evidence/candidate-static-binary.sha256"
"$GO_BINARY" version -m "$RUN_ROOT/bin/image-trust-api-static" \
  > "$RUN_ROOT/evidence/candidate-static-binary-buildinfo.txt"
/usr/bin/timeout --signal=TERM --kill-after=1s 10s "$RUN_ROOT/bin/image-trust-api-static" --help \
  > "$RUN_ROOT/evidence/candidate-static-binary-help.txt" 2>&1
# This tagged executable only provisions/verifies inert CI-owned material.
# The image entrypoint remains the non-test binary above. The tagged fixture
# does not enter, replace or inflate the accepted ordinary 700-test baseline.
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c \
  -tags productimage -o "$RUN_ROOT/bin/product-image.test" ./cmd/image-trust-api
# D11 drives the same actual image via the product API and a private TLS
# Registry. Its fixture is opt-in and never enters the ordinary 700-test set.
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c \
  -tags productregistry -o "$RUN_ROOT/bin/product-registry.test" .
# Separate actual lifecycle driver; neither ordinary/race700 nor D11's
# original tagged test contract includes the opt-in D12 test.
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c \
  -tags productregistry,productlifecycle -o "$RUN_ROOT/bin/product-lifecycle.test" .
# The source-failure/catch-up driver is a separate opt-in executable; the
# ordinary/race test set and the accepted lifecycle driver remain unchanged.
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c \
  -tags productregistry,productlifecycle,productsource -o "$RUN_ROOT/bin/product-source.test" .
# A distinct executable keeps source TLS fault/recovery actions out of the
# ordinary/race suite and out of the accepted wave-1 driver's entry point.
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c \
  -tags productregistry,productlifecycle,productsource,productsourcetls -o "$RUN_ROOT/bin/product-source-tls.test" .
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c \
  -tags productregistry,productcrash -o "$RUN_ROOT/bin/product-crash.test" .
# Preseeded-state startup matrix is a separate opt-in driver, not an addition
# to the ordinary/race baseline or a replacement for actual crash evidence.
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c \
  -tags productregistry,productstate -o "$RUN_ROOT/bin/product-state.test" .
# Only the Docker-save envelope parser's synthetic metadata cases run here.
# This does not replace the actual image/Registry API lifecycle or enlarge the
# ordinary/race 700-test contract. Both the unique marker and actual named PASS
# are required, so an absent or renamed test cannot silently exit green.
/usr/bin/timeout --signal=TERM --kill-after=5s 60s "$RUN_ROOT/bin/product-registry.test" \
  -test.run='^TestProductRegistryD11DockerSaveMetadata$' -test.v -test.timeout=50s \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/product-registry-metadata-tests.log"
test "$(/usr/bin/grep -Fxc 'D11_DOCKER_SAVE_METADATA=PASS cases=17 synthetic=true actual_registry_not_proven=true authorization=BLOCKED production=false' \
  "$RUN_ROOT/evidence/product-registry-metadata-tests.log")" -eq 1
test "$(/usr/bin/grep -Ec -- '^--- PASS: TestProductRegistryD11DockerSaveMetadata \(' \
  "$RUN_ROOT/evidence/product-registry-metadata-tests.log")" -eq 1
# HTTP content negotiation is tested separately from any real Registry claim.
/usr/bin/timeout --signal=TERM --kill-after=5s 60s "$RUN_ROOT/bin/product-registry.test" \
  -test.run='^TestProductRegistryD11ManifestAcceptHeader$' -test.v -test.timeout=50s \
  2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/product-registry-manifest-accept-tests.log"
test "$(/usr/bin/grep -Fxc 'D11_MANIFEST_ACCEPT_HEADER=PASS cases=4 synthetic=true actual_registry_not_proven=true authorization=BLOCKED production=false' \
  "$RUN_ROOT/evidence/product-registry-manifest-accept-tests.log")" -eq 1
test "$(/usr/bin/grep -Ec -- '^--- PASS: TestProductRegistryD11ManifestAcceptHeader \(' \
  "$RUN_ROOT/evidence/product-registry-manifest-accept-tests.log")" -eq 1
# Independently retain the parent OCI verifier scenarios. This transcript is
# not merged into the child-module test contract.
/usr/bin/timeout --signal=TERM --kill-after=10s 600s "$GO_BINARY" test -json -timeout=4m -count=1 chengwang/internal/restoreimage \
  | /usr/bin/tee "$RUN_ROOT/evidence/parent-restoreimage.json"
# Compile genuine Registry integration test executables while still offline.
# Their only later network access is inside the private Registry's own netns.
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c -tags registrycli -o "$RUN_ROOT/bin/registrycli.test" .
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c -race -tags registrycli -o "$RUN_ROOT/bin/registrycli-race.test" .
/usr/bin/timeout --signal=TERM --kill-after=10s 240s "$GO_BINARY" test -c \
  -o "$RUN_ROOT/bin/candidate-ui.test" ./cmd/image-trust-api
/usr/bin/bash "$MODULE_ROOT/scripts/run-browser-gate.sh"
(
  cd "$source_root/chengwang"
  "$NODE_BINARY" --test web/scripts/check-trust-browser-tls.mjs \
    2>&1 | /usr/bin/tee "$RUN_ROOT/evidence/browser-tls-helper-tests.log"
)
/usr/bin/bash "$MODULE_ROOT/scripts/run-browser-gate.sh" --d9-https
/usr/bin/python3 -B scripts/module-verification.py check \
  "$RUN_ROOT" "$GOMODCACHE" "$RUN_ROOT/evidence/remote-modules-offline.json"
/usr/bin/find . -type f -print0 | /usr/bin/sort -z | /usr/bin/xargs -0 /usr/bin/sha256sum > "$RUN_ROOT/evidence/source-after.sha256"
/usr/bin/cmp "$RUN_ROOT/evidence/source-before.sha256" "$RUN_ROOT/evidence/source-after.sha256"
(
  cd "$source_root"
  /usr/bin/git ls-files -z -- 'chengwang/**' '.github/workflows/chengwang-image-binding.yml' \
    | /usr/bin/xargs -0 /usr/bin/sha256sum --
) > "$RUN_ROOT/evidence/checkout-after.sha256"
/usr/bin/cmp "$RUN_ROOT/evidence/checkout-before.sha256" "$RUN_ROOT/evidence/checkout-after.sha256"
echo 'IMAGE_BINDING_OFFLINE_GATE=PASS toolchain=go1.25.8 readonly_source=true readonly_module_cache=true capabilities=none no_new_privileges=true authorization=BLOCKED production=false'
