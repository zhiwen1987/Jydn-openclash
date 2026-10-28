#!/usr/bin/env python3
"""Read-only HTTP acceptance probe with an opt-in isolated mutation gate.

Secrets are read from the environment and are never included in the report.
The default mode performs no writes and is safe against a production endpoint.
"""
from __future__ import annotations

import argparse
import concurrent.futures
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import statistics
import time
import urllib.error
import urllib.parse
import urllib.request


STATES = {"ok", "running", "pending", "warning", "error", "stale", "unknown", "unsupported"}
MODULES = {"subscriptions", "nodes", "dns", "monitors"}
SECRET_KEYS = {"password", "secret", "token", "private_key", "authorization", "cookie", "csrf"}
REDACTED_VALUES = {"[已隐藏]", "[REDACTED]", "***"}
PRIVATE_REQUEST_KEYS = {
    "params", "url", "source_url", "node_url", "provider_url", "subscription_url",
    "request_url", "raw_url",
}
URL_VALUE = re.compile(r"https?://", re.I)
URL_SECRET_VALUE = re.compile(r"(?i)(?:[?&](?:token|secret|password|key)=|https?://[^/\s]*@)")


class GateFailure(AssertionError):
    pass


def percentile(values: list[float], fraction: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    index = min(len(ordered) - 1, max(0, math.ceil(len(ordered) * fraction) - 1))
    return ordered[index]


def public_shape(value):
    """Reject common secret fields recursively; return counts for evidence."""
    objects = 0
    strings = 0
    stack = [value]
    while stack:
        item = stack.pop()
        if isinstance(item, dict):
            objects += 1
            for key, child in item.items():
                normalized = str(key).casefold().replace("-", "_")
                if normalized in SECRET_KEYS or any(normalized.endswith("_" + key) for key in SECRET_KEYS):
                    if not isinstance(child, str) or child not in REDACTED_VALUES:
                        raise GateFailure("secret_field_exposed:" + str(key))
                stack.append(child)
        elif isinstance(item, list):
            stack.extend(item)
        elif isinstance(item, str):
            strings += 1
    return {"objects_checked": objects, "strings_checked": strings}


def assert_subscription_public_shape(value) -> dict:
    """Fail closed if a subscription URL or submitted request body is public.

    Subscription display names are deliberately unrestricted text and may look
    like URLs, so this checks schema keys rather than guessing from values.  The
    renderer must escape those names separately.
    """
    checked = 0
    stack = [("", value)]
    while stack:
        parent_key, item = stack.pop()
        if isinstance(item, dict):
            checked += 1
            for raw_key, child in item.items():
                key = str(raw_key).casefold().replace("-", "_")
                if key in PRIVATE_REQUEST_KEYS or key.endswith("_url"):
                    raise GateFailure("subscription_private_request_exposed:" + str(raw_key))
                stack.append((key, child))
        elif isinstance(item, list):
            stack.extend((parent_key, child) for child in item)
        elif isinstance(item, str) and parent_key not in {"name", "display_name", "label"}:
            if URL_VALUE.search(item) or URL_SECRET_VALUE.search(item):
                raise GateFailure("subscription_private_url_value_exposed:" + parent_key)
    return {"objects_checked": checked}


def assert_public_job_shape(value: dict) -> dict:
    """Jobs may expose bounded results, never the submitted parameter object."""
    if "params" in value:
        raise GateFailure("operation_params_exposed")
    public_shape(value)
    if value.get("module") == "subscriptions":
        return assert_subscription_public_shape(value)
    return {"objects_checked": 1}


class Client:
    def __init__(self, base: str, authenticated: bool = True):
        self.base = base.rstrip("/")
        self.cookie = os.getenv("CENTER_ACCEPTANCE_COOKIE", "") if authenticated else ""
        self.csrf = os.getenv("CENTER_ACCEPTANCE_CSRF", "") if authenticated else ""

    def request(self, path: str, method: str = "GET", body=None, headers=None, timeout: float = 8):
        request_headers = {"Accept": "application/json", **(headers or {})}
        if self.cookie:
            request_headers["Cookie"] = self.cookie
        if method != "GET":
            request_headers["Content-Type"] = "application/json"
            if self.csrf:
                request_headers["X-CSRF-Token"] = self.csrf
        raw = None if body is None else json.dumps(body, separators=(",", ":")).encode()
        request = urllib.request.Request(self.base + path, data=raw, method=method, headers=request_headers)
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(request, timeout=timeout) as response:
                payload = response.read(4 * 1024 * 1024 + 1)
                if len(payload) > 4 * 1024 * 1024:
                    raise GateFailure("response_too_large")
                return response.status, json.loads(payload), (time.perf_counter() - started) * 1000, len(payload)
        except urllib.error.HTTPError as error:
            payload = error.read(1024 * 1024)
            try:
                value = json.loads(payload)
            except ValueError:
                value = {"error": "non_json_error"}
            return error.code, value, (time.perf_counter() - started) * 1000, len(payload)


def validate_snapshot(value: dict) -> dict:
    if value.get("schema") != 2 or not isinstance(value.get("revision"), str) or not value["revision"]:
        raise GateFailure("snapshot_identity_invalid")
    if type(value.get("updated_at")) not in (int, float):
        raise GateFailure("snapshot_time_missing")
    modules = value.get("modules")
    if not isinstance(modules, dict) or not MODULES.issubset(modules):
        raise GateFailure("snapshot_modules_missing")
    actions = {}
    for name in sorted(MODULES):
        module = modules[name]
        if not isinstance(module, dict) or module.get("state") not in STATES:
            raise GateFailure("module_state_invalid:" + name)
        if not isinstance(module.get("revision"), str) or not module["revision"]:
            raise GateFailure("module_revision_invalid:" + name)
        capabilities = module.get("capabilities")
        if not isinstance(capabilities, dict) or not isinstance(capabilities.get("actions"), list):
            raise GateFailure("module_capabilities_invalid:" + name)
        if not all(isinstance(action, str) and action for action in capabilities["actions"]):
            raise GateFailure("module_action_invalid:" + name)
        action_meta = capabilities.get("action_meta")
        if not isinstance(action_meta, dict):
            raise GateFailure("module_action_meta_missing:" + name)
        for action in capabilities["actions"]:
            meta = action_meta.get(action)
            if (not isinstance(meta, dict) or type(meta.get("write")) is not bool
                    or type(meta.get("timeout_seconds")) not in (int, float)):
                raise GateFailure("module_action_meta_invalid:" + name + ":" + action)
        actions[name] = capabilities["actions"]
    public_shape(value)
    subscription_public = assert_subscription_public_shape(modules["subscriptions"])
    return {
        "revision_sha256": hashlib.sha256(value["revision"].encode()).hexdigest(),
        "actions": actions,
        "subscription_public_shape": subscription_public,
    }


def wait_for_snapshot(client: Client, timeout: float = 30) -> tuple[dict, dict]:
    deadline = time.monotonic() + max(1, timeout)
    attempts = 0
    last = "snapshot_not_requested"
    while time.monotonic() < deadline:
        attempts += 1
        status, snapshot, _, _ = client.request("/api/center/manage/snapshot")
        if status != 200:
            raise GateFailure("snapshot_http_" + str(status))
        try:
            evidence = validate_snapshot(snapshot)
            evidence["ready_attempts"] = attempts
            return snapshot, evidence
        except GateFailure as error:
            last = str(error)
            if not last.startswith("module_revision_invalid:"):
                raise
        time.sleep(.2)
    raise GateFailure("snapshot_ready_timeout:" + last)


def benchmark(client: Client, path: str, sequential: int = 20, concurrent: int = 12, warmup: int = 5) -> dict:
    for _ in range(warmup):
        status, _, _, _ = client.request(path)
        if status != 200:
            raise GateFailure("benchmark_warmup_http_" + str(status))
    sequential_samples = []
    sizes = []
    for _ in range(sequential):
        status, _, elapsed, size = client.request(path)
        if status != 200:
            raise GateFailure("benchmark_http_" + str(status))
        sequential_samples.append(elapsed)
        sizes.append(size)
    def once(_):
        return client.request(path)
    with concurrent.futures.ThreadPoolExecutor(max_workers=4) as executor:
        results = list(executor.map(once, range(concurrent)))
    if any(status != 200 for status, _, _, _ in results):
        raise GateFailure("concurrent_request_failed")
    concurrent_samples = [elapsed for _, _, elapsed, _ in results]
    return {
        "sequential_requests": sequential,
        "concurrent_requests": concurrent,
        "warmup_requests": warmup,
        "median_ms": round(statistics.median(sequential_samples), 3),
        "p95_ms": round(percentile(sequential_samples, .95), 3),
        "concurrent_p95_ms": round(percentile(concurrent_samples, .95), 3),
        "max_bytes": max(sizes + [size for _, _, _, size in results]),
        "errors": 0,
    }


def compare_performance(current: dict, baseline: dict) -> dict:
    checks = {}
    for key in ("p95_ms", "concurrent_p95_ms"):
        old = float(baseline[key])
        limit = max(old * 1.30, old + 25.0)
        checks[key] = {"value": current[key], "baseline": old, "limit": round(limit, 3), "passed": current[key] <= limit}
    size_limit = max(int(baseline.get("max_bytes", 0) * 1.25), int(baseline.get("max_bytes", 0)) + 16384)
    checks["max_bytes"] = {"value": current["max_bytes"], "baseline": baseline.get("max_bytes"), "limit": size_limit, "passed": current["max_bytes"] <= size_limit}
    if not all(check["passed"] for check in checks.values()):
        raise GateFailure("performance_regression")
    return checks


def unauthorized_gate(base: str) -> dict:
    client = Client(base, authenticated=False)
    status, body, _, _ = client.request("/api/center/manage/snapshot")
    if status != 401 or body.get("error") != "login_required":
        raise GateFailure("snapshot_auth_boundary_failed")
    status, body, _, _ = client.request("/api/center/operations", "POST", {
        "module": "dns", "action": "invalid", "expected_revision": "invalid", "params": {}
    }, {"Origin": "https://invalid.example"})
    if status not in {401, 403}:
        raise GateFailure("operation_auth_boundary_failed")
    return {"snapshot": 401, "operation": status}


def isolated_conflict_gate(client: Client, snapshot: dict) -> dict:
    # This deliberately cannot succeed and must never reach a module mutation.
    status, body, _, _ = client.request("/api/center/operations", "POST", {
        "module": "dns", "action": "__acceptance_invalid_action__",
        "expected_revision": "0" * 64, "params": {},
    }, {"Origin": urllib.parse.urlsplit(client.base).scheme + "://" + urllib.parse.urlsplit(client.base).netloc})
    if status not in {400, 404}:
        raise GateFailure("action_allowlist_failed")
    # A stale revision must be rejected before an otherwise advertised action executes.
    advertised = None
    for module, value in snapshot["modules"].items():
        capabilities = value.get("capabilities", {})
        metadata = capabilities.get("action_meta", {}) if isinstance(capabilities, dict) else {}
        for action in capabilities.get("actions", []) if isinstance(capabilities, dict) else []:
            meta = metadata.get(action, {}) if isinstance(metadata, dict) else {}
            if not isinstance(meta, dict) or meta.get("sensitive_input") is not True:
                advertised = (module, action)
                break
        if advertised:
            break
    if not advertised:
        return {"allowlist": status, "revision_conflict": "not_applicable_no_actions"}
    module, action = advertised
    stale = "0" * 64
    if snapshot["modules"][module].get("revision") == stale:
        stale = "f" * 64
    status, body, _, _ = client.request("/api/center/operations", "POST", {
        "module": module, "action": action, "expected_revision": stale, "params": {},
    }, {"Origin": urllib.parse.urlsplit(client.base).scheme + "://" + urllib.parse.urlsplit(client.base).netloc})
    if status != 409 or body.get("error") != "operation_revision_conflict":
        raise GateFailure("revision_conflict_gate_failed")
    return {"allowlist": status, "revision_conflict": 409}


def assert_required_actions(snapshot: dict, requirements: list[str]) -> dict:
    checked = []
    for requirement in requirements:
        if "=" not in requirement:
            raise GateFailure("required_action_format_invalid")
        module, action = requirement.split("=", 1)
        if module not in MODULES or not action:
            raise GateFailure("required_action_format_invalid")
        actions = snapshot["modules"][module].get("capabilities", {}).get("actions", [])
        if action not in actions:
            raise GateFailure("required_action_missing:" + module + ":" + action)
        checked.append(requirement)
    return {"checked": checked}


def _count(module: dict, plural: str, singular: str) -> int | None:
    value = module.get(plural)
    if isinstance(value, list):
        return len(value)
    for key in (plural + "_count", singular + "_count", "count"):
        if type(module.get(key)) is int:
            return module[key]
    return None


def assert_kuma_inventory(snapshot: dict, monitors: int | None, notifications: int | None) -> dict:
    module = snapshot["modules"]["monitors"]
    result = {}
    if monitors is not None:
        observed = _count(module, "monitors", "monitor")
        if observed != monitors:
            raise GateFailure(f"kuma_monitor_count_mismatch:{observed}:{monitors}")
        result["monitors"] = observed
    if notifications is not None:
        observed = _count(module, "notifications", "notification")
        if observed != notifications:
            raise GateFailure(f"kuma_notification_count_mismatch:{observed}:{notifications}")
        result["notifications"] = observed
    return result


def assert_candidate_isolation(snapshot: dict) -> dict:
    reconcile = snapshot["modules"]["subscriptions"].get("reconcile")
    if not isinstance(reconcile, dict):
        raise GateFailure("subscription_reconcile_missing")
    expected = {
        "candidate_provider": None,
        "candidate_scope": "isolated_admission_queue",
        "active_provider": "Managed_Auto",
        "candidate_exposed": False,
    }
    for key, value in expected.items():
        if reconcile.get(key) != value:
            raise GateFailure("candidate_isolation_invalid:" + key)
    return expected


def run_read_validation(client: Client, snapshot: dict, module: str, action: str, timeout: float = 40) -> dict:
    actions = snapshot["modules"][module].get("capabilities", {}).get("actions", [])
    if action not in actions:
        raise GateFailure("read_validation_action_missing:" + module + ":" + action)
    origin = urllib.parse.urlsplit(client.base).scheme + "://" + urllib.parse.urlsplit(client.base).netloc
    status, body, _, _ = client.request("/api/center/operations", "POST", {
        "module": module, "action": action,
        "expected_revision": snapshot["modules"][module]["revision"], "params": {},
    }, {"Origin": origin})
    if status != 202 or not isinstance(body.get("job_id"), str):
        raise GateFailure("read_validation_start_failed:" + str(status))
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        job_status, job, _, _ = client.request("/api/center/jobs/" + urllib.parse.quote(body["job_id"], safe=""))
        if job_status != 200:
            raise GateFailure("read_validation_job_http_" + str(job_status))
        if job.get("state") in {"ok", "error", "conflict"}:
            assert_public_job_shape(job)
            result = job.get("result") if isinstance(job.get("result"), dict) else {}
            if job.get("state") != "ok" or result.get("state") != "ok":
                raise GateFailure("read_validation_failed:" + str(job.get("error") or result.get("error_code") or "unknown"))
            return {"job_state": "ok", "result_state": "ok", "result": result}
        time.sleep(.15)
    raise GateFailure("read_validation_timeout")


def assert_ports_closed(values: list[str]) -> dict:
    checked = []
    for value in values:
        try:
            host, raw_port = value.rsplit(":", 1)
            port = int(raw_port)
        except (ValueError, TypeError):
            raise GateFailure("forbidden_port_format_invalid") from None
        try:
            with socket.create_connection((host, port), timeout=1.5):
                raise GateFailure("forbidden_port_reachable:" + value)
        except (ConnectionRefusedError, TimeoutError, OSError):
            checked.append(value)
    return {"unreachable": checked}


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", required=True)
    parser.add_argument("--report", type=Path, required=True)
    parser.add_argument("--baseline", type=Path)
    parser.add_argument("--allow-isolated-contract-writes", action="store_true")
    parser.add_argument("--require-complete", action="store_true")
    parser.add_argument("--required-action", action="append", default=[])
    parser.add_argument("--expected-monitor-count", type=int)
    parser.add_argument("--expected-notification-count", type=int)
    parser.add_argument("--forbid-host-port", action="append", default=[])
    parser.add_argument("--snapshot-p95-budget-ms", type=float)
    parser.add_argument("--require-candidate-isolation", action="store_true")
    parser.add_argument("--run-subscription-validation", action="store_true")
    parser.add_argument("--snapshot-ready-timeout", type=float, default=30)
    args = parser.parse_args()
    client = Client(args.base_url)
    report = {"schema": 1, "base_url": args.base_url, "started_at": time.time(), "checks": {}}
    try:
        report["checks"]["auth_boundary"] = unauthorized_gate(args.base_url)
        status, overview, _, _ = client.request("/api/center/overview")
        if status != 200 or overview.get("schema") != 1:
            raise GateFailure("overview_invalid")
        public_shape(overview)
        report["environment"] = overview.get("environment", "unknown")
        if not client.cookie:
            raise GateFailure("authenticated_cookie_not_supplied")
        snapshot, snapshot_evidence = wait_for_snapshot(client, args.snapshot_ready_timeout)
        report["checks"]["snapshot"] = snapshot_evidence
        if args.require_complete:
            incomplete = [name for name, value in snapshot["modules"].items()
                          if value.get("state") in {"error", "unsupported"}]
            if incomplete:
                raise GateFailure("incomplete_modules:" + ",".join(sorted(incomplete)))
        report["checks"]["required_actions"] = assert_required_actions(snapshot, args.required_action)
        report["checks"]["kuma_inventory"] = assert_kuma_inventory(
            snapshot, args.expected_monitor_count, args.expected_notification_count,
        )
        if args.require_candidate_isolation:
            report["checks"]["candidate_isolation"] = assert_candidate_isolation(snapshot)
        if args.run_subscription_validation:
            report["checks"]["subscription_validation"] = run_read_validation(
                client, snapshot, "subscriptions", "subscriptions.validate",
            )
        report["checks"]["forbidden_ports"] = assert_ports_closed(args.forbid_host_port)
        report["performance"] = {
            "overview": benchmark(client, "/api/center/overview"),
            "snapshot": benchmark(client, "/api/center/manage/snapshot"),
        }
        if args.snapshot_p95_budget_ms is not None:
            observed = report["performance"]["snapshot"]["p95_ms"]
            if observed > args.snapshot_p95_budget_ms:
                raise GateFailure("snapshot_latency_budget_exceeded")
            report["checks"]["snapshot_budget"] = {
                "p95_ms": observed, "limit_ms": args.snapshot_p95_budget_ms, "passed": True,
            }
        if args.baseline:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))["performance"]
            baseline_overview = baseline.get("overview", baseline)
            report["checks"]["performance_comparison"] = compare_performance(
                report["performance"]["overview"], baseline_overview,
            )
        if args.allow_isolated_contract_writes:
            if report["environment"] == "production":
                raise GateFailure("isolated_writes_refused_on_production")
            report["checks"]["isolated_contract"] = isolated_conflict_gate(client, snapshot)
        report["passed"] = True
    except Exception as error:
        report["passed"] = False
        report["failure"] = str(error)[:240]
    report["completed_at"] = time.time()
    args.report.parent.mkdir(parents=True, exist_ok=True)
    args.report.write_text(json.dumps(report, ensure_ascii=False, indent=2) + "\n", encoding="utf-8")
    print(json.dumps({"passed": report["passed"], "report": str(args.report), "failure": report.get("failure")}))
    return 0 if report["passed"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
