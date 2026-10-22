#!/usr/bin/env bash
set -euo pipefail
umask 077
test "$(/usr/bin/id -u)" != 0
test -x "$NODE_BINARY"
test -x "$CHROME_BINARY"
run_root=$(/usr/bin/realpath -e -- "$RUN_ROOT")
fixture_root="$run_root/browser-fixture"
evidence_root="$run_root/evidence"
source_root=$(/usr/bin/git -C "$MODULE_ROOT" rev-parse --show-toplevel)
case "$run_root/" in "$source_root/"*) echo 'browser run root must be outside source' >&2; exit 1;; esac
test ! -e "$fixture_root"
/usr/bin/install -d -m 0700 "$fixture_root"
fixture_pid=''
private_ready="$run_root/browser-ready.private.json"
private_log="$run_root/browser-fixture.private.log"
cleanup() {
  cleanup_status=$?
  trap - EXIT HUP INT TERM
  if test -n "$fixture_pid" && /usr/bin/kill -0 "$fixture_pid" 2>/dev/null; then
    /usr/bin/printf 'stop\n' > "$fixture_root/stop"
    for attempt in {1..100}; do
      if ! /usr/bin/kill -0 "$fixture_pid" 2>/dev/null; then break; fi
      /usr/bin/sleep 0.1
    done
    if /usr/bin/kill -0 "$fixture_pid" 2>/dev/null; then
      /usr/bin/kill -TERM "$fixture_pid" 2>/dev/null || true
    fi
    wait "$fixture_pid" 2>/dev/null || true
  fi
  # Chrome is detached from Node's timeout group. A private process record
  # and /proc identity verification are required even on Node crash/signal.
  # The guard fails closed rather than signalling an unrelated PID/group.
  if ! /usr/bin/python3 -B "$MODULE_ROOT/scripts/browser-process-guard.py" "$fixture_root"; then
    cleanup_status=1
    echo 'browser process cleanup could not be verified; private profile retained' >&2
  else
    if test -d "$fixture_root/chrome-profile"; then
      profile=$(/usr/bin/realpath -e -- "$fixture_root/chrome-profile")
      if test "$profile" != "$fixture_root/chrome-profile"; then exit 1; fi
      /usr/bin/find "$profile" -depth -delete
    fi
    /usr/bin/rm -f -- "$fixture_root/chrome-process.private.json" "$fixture_root/.chrome-process.tmp"
  fi
  # Only exact files and the validated test-owned Chrome profile are removed.
  # No production directory, source tree or broad run-root deletion occurs.
  /usr/bin/rm -f -- "$fixture_root/ready.json" "$fixture_root/.ready.tmp" \
    "$fixture_root/identities.json" "$fixture_root/candidate.json" "$private_ready" "$private_log"
  test ! -e "$fixture_root/ready.json"
  test ! -e "$fixture_root/identities.json"
  test ! -e "$fixture_root/chrome-profile"
  test ! -e "$private_ready"
  echo 'D8_BROWSER_FIXTURE_CLEANUP=PASS only_owned_objects=true credentials_removed=true profile_removed=true'
  exit "$cleanup_status"
}
trap cleanup EXIT
trap 'exit 129' HUP
trap 'exit 130' INT
trap 'exit 143' TERM
CHENGWANG_D8_UI_FIXTURE_ROOT="$fixture_root" CHENGWANG_D8_UI_WEB_DIR="$run_root/web-dist" \
  /usr/bin/timeout --signal=TERM --kill-after=5s 200s "$run_root/bin/candidate-ui.test" \
    -test.run='^TestCandidateD8LiveUIFixture$' -test.v -test.timeout=190s \
    > "$private_log" 2>&1 &
fixture_pid=$!
ready=false
for attempt in {1..200}; do
  if test -f "$fixture_root/ready.json"; then ready=true; break; fi
  if ! /usr/bin/kill -0 "$fixture_pid" 2>/dev/null; then break; fi
  /usr/bin/sleep 0.1
done
if test "$ready" != true; then
  echo 'actual candidate browser fixture did not become ready' >&2
  exit 1
fi
/usr/bin/cp -- "$fixture_root/ready.json" "$private_ready"
node_status=0
/usr/bin/timeout --signal=TERM --kill-after=5s 160s "$NODE_BINARY" \
  "$source_root/chengwang/web/scripts/verify-trust-browser.mjs" \
  --fixture-root "$fixture_root" --chrome "$CHROME_BINARY" --evidence-dir "$evidence_root" \
  || node_status=$?
/usr/bin/printf 'stop\n' > "$fixture_root/stop"
fixture_status=0
wait "$fixture_pid" || fixture_status=$?
fixture_pid=''
/usr/bin/python3 -B - "$private_ready" "$private_log" "$evidence_root" "$node_status" "$fixture_status" <<'PY'
import json
import pathlib
import re
import sys
ready_path, log_path, evidence_path, node_status, fixture_status = sys.argv[1:]
ready = json.loads(pathlib.Path(ready_path).read_text(encoding="utf-8"))
secrets = [ready[name] for name in ("auditorToken", "viewerToken", "wrongToken")]
log = pathlib.Path(log_path).read_text(encoding="utf-8")
if any(secret in log for secret in secrets):
    raise SystemExit("private fixture log contained a credential; artifact withheld")
evidence = pathlib.Path(evidence_path)
# The helper emits only test metadata and fixed diagnostic labels, never the
# ready object, credentials, HTTP bodies or private bootstrap material.
(evidence / "browser-fixture.log").write_text(log, encoding="utf-8")
if node_status != "0" or fixture_status != "0":
    raise SystemExit("real browser or actual candidate fixture failed")
marker = "CANDIDATE_D8_UI_FIXTURE=PASS actual_candidate=true journal=22 audit=44 readonly=true authorization=BLOCKED"
if len(re.findall(re.escape(marker), log)) != 1:
    raise SystemExit("missing or repeated actual candidate browser fixture completion")
report = json.loads((evidence / "trust-browser-report.json").read_text(encoding="utf-8"))
if report.get("outcome") != "PASS" or report.get("mockedResponses") is not False or report.get("injectedFetch") is not False or report.get("tlsBypass") is not False or report.get("screenshotCount") != 4:
    raise SystemExit("invalid real browser acceptance report")
expected_fields = {
    "schema": "chengwang.trust-console-browser/v1",
    "boundary": "ISOLATED_REAL_BROWSER_REAL_CANDIDATE",
    "authorization": "BLOCKED",
    "deviceActionsExecuted": False,
    "transport": "HTTP_127_LOOPBACK_ONLY_NOT_BROWSER_TLS_ACCEPTANCE",
    "chromeSandbox": "DISABLED_CI_ONLY_OUTER_ISOLATION_REQUIRED",
    "browserGroupStopped": True,
}
if any(report.get(name) != value for name, value in expected_fields.items()):
    raise SystemExit("real browser evidence boundary or cleanup mismatch")
required_checks = {
    "actual browser document carries restrictive CSP no-store nosniff DENY and no-referrer",
    "unknown initial state and explicit candidate boundary",
    "no automatic authenticated requests before connection",
    "actual candidate generation and 22 persisted operation records",
    "actual signed policy catalogue first page has 20 of 25 definitions",
    "actual signed policy catalogue next page has remaining 5 definitions",
    "actual policy search spans fetched catalogue and resets page",
    "browser received real status and history HTTP 200",
    "connected idle page makes no automatic network requests in observed window",
    "actual prefixed catalogue digest expands in full",
    "actual operation detail opens with audit acknowledgement",
    "real second page pagination label",
    "375px real authenticated page has no horizontal overflow",
    "all visible console buttons meet 44px target height",
    "real reduced motion presentation",
    "real keyboard navigation and visible focus",
    "viewer keeps authorized status but cannot see history",
    "real browser history HTTP 403",
    "HTTP 401 clears all successful observations and credential",
    "real browser HTTP 401",
    "disconnected observations remain cleared",
    "credentials absent from URL visible text storage and cookies",
    "all observed API calls same origin read-only GET",
}
checks = report.get("checks")
if not isinstance(checks, list) or any(not isinstance(name, str) for name in checks) or required_checks - set(checks):
    raise SystemExit("real browser flow checks missing")
status_counts = report.get("httpStatusCounts", {})
if any(not isinstance(status_counts.get(str(code)), int) or status_counts[str(code)] < 1 for code in (200, 401, 403)):
    raise SystemExit("real browser missing authenticated and rejection HTTP evidence")
if any(report.get(name) != 0 for name in ("runtimeErrors", "cspErrors", "assetErrors", "forbiddenRequests")):
    raise SystemExit("real browser reported runtime, CSP, resource or scope errors")
screenshots = list(evidence.glob("trust-console-*.png"))
if len(screenshots) != 4 or any(p.stat().st_size > 5 * 1024 * 1024 or p.read_bytes()[:8] != b"\x89PNG\r\n\x1a\n" for p in screenshots):
    raise SystemExit("missing, oversized or invalid real browser screenshots")
for artifact in (evidence / "trust-browser-report.json", evidence / "browser-fixture.log"):
    if any(secret in artifact.read_text(encoding="utf-8") for secret in secrets):
        raise SystemExit("browser credential containment failed")
print("D8_REAL_BROWSER_GATE=PASS actual_candidate=true journal=22 audit=44 readonly=true mocked_responses=false production=false")
PY
