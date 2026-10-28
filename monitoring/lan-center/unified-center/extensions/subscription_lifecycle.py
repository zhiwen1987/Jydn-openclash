"""Subscription lifecycle evidence and private source-registry overrides.

Publication remains owned by ``subscription-controller.py``. Source writes are
local, bounded, coordinator-locked file transactions; they never fetch a URL or
publish a provider inside the management request.
"""
from __future__ import annotations

import hashlib
import json
import os
import re
import time
import urllib.parse
from collections import Counter
from pathlib import Path
from typing import Any

try:
    import yaml
except ImportError:  # Local control-plane tests do not require PyYAML.
    yaml = None

PARSE_ERRORS = (OSError, ValueError, TypeError, UnicodeError, json.JSONDecodeError) + (
    (yaml.YAMLError,) if yaml is not None else ()
)


MAX_DOCUMENT = 20 * 1024 * 1024
SAFE_ID = re.compile(r"^[A-Za-z0-9_.-]{1,96}$")
EMPTY_PREFIX = "__STACK_EMPTY_MANAGED_"
STAGES = ("information", "parse", "admission", "publish", "load")


class SubscriptionActionError(RuntimeError):
    def __init__(self, code: str, status: int = 400):
        super().__init__(code)
        self.code = code
        self.status = status


def _json(path: Path) -> dict[str, Any]:
    if not path.is_file() or path.stat().st_size > MAX_DOCUMENT:
        return {}
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except (OSError, UnicodeError, ValueError, TypeError):
        return {}


def _digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in paths:
        digest.update(str(path.name).encode())
        try:
            payload = path.read_bytes()
            if len(payload) <= MAX_DOCUMENT:
                digest.update(payload)
        except OSError:
            digest.update(b"missing")
    return digest.hexdigest()


def _atomic_private(path: Path, value: dict[str, Any]) -> None:
    if path.is_symlink():
        raise SubscriptionActionError("private_state_symlink_refused", 503)
    payload = (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode()
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}")
    try:
        with open(temporary, "wb") as stream:
            os.chmod(temporary, 0o600)
            stream.write(payload)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(temporary, path)
        os.chmod(path, 0o600)
    finally:
        try:
            temporary.unlink()
        except FileNotFoundError:
            pass


def _code(value: Any, default: str = "") -> str:
    text = str(value or "").split(":", 1)[0].strip().lower()
    text = re.sub(r"[^a-z0-9_.-]+", "_", text)[:96].strip("_")
    return text if text and SAFE_ID.fullmatch(text) else default


def _names(path: Path, expected_hash: str = "") -> list[str] | None:
    try:
        payload = path.read_bytes()
        if len(payload) > MAX_DOCUMENT:
            return None
        if expected_hash and hashlib.sha256(payload).hexdigest() != expected_hash:
            return None
        document = yaml.safe_load(payload) if yaml is not None else json.loads(payload)
        proxies = document.get("proxies") if isinstance(document, dict) else None
        if not isinstance(proxies, list):
            return None
        return [str(item.get("name")) for item in proxies if isinstance(item, dict)
                and item.get("name") and not str(item.get("name")).startswith(EMPTY_PREFIX)]
    except PARSE_ERRORS:
        return None


def _stage(stage_id: str, state: str, detail: str = "", at: Any = None) -> dict[str, Any]:
    row: dict[str, Any] = {"id": stage_id, "state": state}
    if detail:
        row["detail"] = detail
    if type(at) is int and at > 0:
        row["at"] = at
    return row


class SubscriptionLifecycleExtension:
    def __init__(self, context: dict[str, Any]):
        self.context = context
        self.data_root = Path(context.get("data_root", "/data"))
        self.controller = self.data_root / "subscription-controller"
        self.usage = self.data_root / "subscription-usage"
        self.health_path = self.controller / "health.json"
        self.current_path = self.controller / "current.json"
        self.pending_path = self.controller / "publish-pending.json"
        self.recovery_path = self.controller / "recovery-refresh.json"
        self.probation_path = self.controller / "release-probation.json"
        self.registry_path = self.usage / "information-sources.json"
        self.overrides_path = self.usage / "source-overrides.json"
        self.admission_progress_path = self.data_root / "node-health" / "admission-progress.json"
        self.clash = context.get("clash")
        self.write_lock_managed = context.get("write_lock_managed") is True

    def actions(self) -> dict[str, dict[str, Any]]:
        actions = {
            "subscriptions.preview": {"write": False, "supported": True, "timeout_seconds": 10},
            "subscriptions.validate": {"write": False, "supported": callable(self.clash), "timeout_seconds": 30},
        }
        for action in ("subscriptions.source.add", "subscriptions.source.update",
                       "subscriptions.source.disable", "subscriptions.source.enable",
                       "subscriptions.source.delete"):
            actions[action] = {
                "write": True, "supported": self.write_lock_managed, "timeout_seconds": 10,
                "deadline_enforced": True, "sensitive_fields": ["url"],
                "reason": None if self.write_lock_managed else "coordinator_lock_unavailable",
            }
        return actions

    def _manifest(self) -> tuple[dict[str, Any], Path | None]:
        pointer = _json(self.current_path)
        release_id = str(pointer.get("release_id", ""))
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,120}", release_id):
            return {}, None
        directory = self.controller / "releases" / release_id
        manifest = _json(directory / "manifest.json")
        if manifest.get("release_id") != release_id:
            return {}, None
        for row in list(manifest.get("sources", [])) + list(manifest.get("source_breakdown", [])):
            if not isinstance(row, dict):
                return {}, None
            for file_key, hash_key in (("file", "sha256"), ("approved_file", "approved_sha256")):
                if file_key not in row:
                    continue
                name = str(row.get(file_key, ""))
                if Path(name).name != name or not re.fullmatch(r"[A-Za-z0-9_.-]{1,160}", name):
                    return {}, None
                try:
                    payload = (directory / name).read_bytes()
                except OSError:
                    return {}, None
                if len(payload) > MAX_DOCUMENT or hashlib.sha256(payload).hexdigest() != row.get(hash_key):
                    return {}, None
        return manifest, directory

    def _base_registry(self) -> tuple[dict[str, dict[str, Any]], str]:
        document = _json(self.registry_path)
        if document.get("purpose") != "subscription_information_only":
            return {}, "unavailable"
        rows = document.get("sources")
        if not isinstance(rows, list):
            return {}, "invalid"
        result: dict[str, dict[str, Any]] = {}
        for row in rows:
            if not isinstance(row, dict) or row.get("enabled", True) is False:
                continue
            source_id = str(row.get("id", ""))
            if SAFE_ID.fullmatch(source_id):
                result[source_id] = dict(row)
        return result, "ok"

    def _overrides(self) -> dict[str, Any]:
        if not self.overrides_path.exists():
            return {"schema": 1, "sources": [], "tombstones": [], "updated_at": 0}
        if self.overrides_path.is_symlink():
            raise SubscriptionActionError("private_state_symlink_refused", 503)
        document = _json(self.overrides_path)
        if (document.get("schema") != 1 or not isinstance(document.get("sources"), list)
                or not isinstance(document.get("tombstones"), list)):
            raise SubscriptionActionError("source_overrides_invalid", 503)
        return document

    def _registry(self) -> tuple[dict[str, dict[str, Any]], str]:
        result, state = self._base_registry()
        if state != "ok":
            return {}, state
        try:
            overrides = self._overrides()
        except SubscriptionActionError:
            return {}, "override_invalid"
        for row in overrides["sources"]:
            if isinstance(row, dict) and SAFE_ID.fullmatch(str(row.get("id", ""))):
                result[str(row["id"])] = dict(row)
        for source_id in overrides["tombstones"]:
            source_id = str(source_id)
            row = dict(result.get(source_id, {"id": source_id, "name": source_id}))
            row["_disabled"] = True
            result[source_id] = row
        # URLs and tokens deliberately never enter the public model.
        return {
            source_id: {"id": source_id, "name": str(row.get("name", source_id))[:80],
                        "_disabled": row.get("_disabled") is True}
            for source_id, row in result.items()
        }, "ok"

    def _rows(self, health: dict[str, Any], manifest: dict[str, Any], registry: dict[str, dict[str, Any]],
              registry_state: str, admission_progress: dict[str, Any]) -> list[dict[str, Any]]:
        runtime_rows = health.get("source_inventory")
        runtime = {str(row.get("id")): row for row in (runtime_rows if isinstance(runtime_rows, list) else [])
                   if isinstance(row, dict) and row.get("id")}
        breakdown_rows = manifest.get("source_breakdown")
        breakdown = {str(row.get("id")): row for row in (breakdown_rows if isinstance(breakdown_rows, list) else [])
                     if isinstance(row, dict) and row.get("id")}
        explicit_rows = manifest.get("sources")
        explicit: dict[str, dict[str, Any]] = {}
        if isinstance(explicit_rows, list):
            for row in explicit_rows:
                if isinstance(row, dict) and row.get("id") and row.get("role", "explicit") == "explicit":
                    explicit[str(row["id"])] = row
        source_errors = {str(row.get("source_id")): row for row in health.get("sources", [])
                         if isinstance(row, dict) and row.get("source_id")}
        ids = sorted(set(registry) | set(runtime) | set(breakdown) | set(explicit))
        managed = manifest.get("managed") if isinstance(manifest.get("managed"), dict) else {}
        admission_rows = admission_progress.get("sources") if isinstance(admission_progress.get("sources"), list) else []
        admission = {str(row.get("source_id")): row for row in admission_rows
                     if isinstance(row, dict) and row.get("source_id")}
        admission_epoch = admission_progress.get("epoch")
        admission_fresh = isinstance(admission_epoch, (int, float)) and 0 <= time.time() - admission_epoch <= 180
        rows: list[dict[str, Any]] = []
        for source_id in ids:
            evidence = runtime.get(source_id, {})
            stored = breakdown.get(source_id, {})
            provider = explicit.get(source_id, {})
            origin = "managed" if source_id in registry or source_id in breakdown else "explicit"
            registry_present = source_id in registry and registry[source_id].get("_disabled") is not True
            dependencies = evidence.get("dependencies", stored.get("dependencies", []))
            dependencies = [str(item)[:160] for item in dependencies] if isinstance(dependencies, list) else []
            desired = str(evidence.get("desired", "present" if registry_present or origin == "explicit" else "absent"))
            candidate_count = int(evidence.get("candidate_count", stored.get("candidate_count", provider.get("node_count", 0))) or 0)
            approved_count = int(evidence.get("approved_count", stored.get("approved_count", provider.get("node_count", 0))) or 0)
            admission_row = admission.get(source_id, {})
            error = source_errors.get(source_id, {})
            reason = _code(evidence.get("reason") or error.get("last_error"))
            lifecycle = str(evidence.get("lifecycle", ""))
            if origin == "managed" and not registry_present and registry_state != "ok":
                # A missing/corrupt registry is not a deletion request.  Keep
                # the last release and make that uncertainty explicit.
                desired, actual, lifecycle = "unknown", "retained", "retained_by_selection"
                if "information_registry_unavailable" not in dependencies:
                    dependencies.append("information_registry_unavailable")
                reason = "information_registry_unavailable"
            elif origin == "managed" and not registry_present:
                # A valid registry is authoritative for desired membership.
                # Runtime health may still describe the previous reconciliation.
                desired = "absent"
                actual = "retained" if dependencies else "published"
                lifecycle = "retained_by_selection" if dependencies else "pending_retirement"
            else:
                actual = str(evidence.get("actual", "retained" if dependencies else lifecycle))
                if origin == "managed" and source_id not in registry and registry_state == "ok":
                    desired = "absent"
                    lifecycle = "retained_by_selection" if dependencies else "pending_retirement"
            if not lifecycle:
                if dependencies and desired == "absent":
                    lifecycle = "retained_by_selection"
                elif desired == "absent":
                    lifecycle = "pending_retirement"
                elif reason:
                    lifecycle = "error"
                elif source_id in breakdown or source_id in explicit:
                    lifecycle = "published" if approved_count else "checking"
                else:
                    lifecycle = "discovered"
            if not actual:
                actual = "retained" if dependencies else lifecycle
            parsed = candidate_count >= 0 and (source_id in breakdown or source_id in explicit)
            published = source_id in breakdown or source_id in explicit
            admission_stage = _stage(
                "admission", "ok" if approved_count else "warning" if candidate_count else "pending",
                "真实独立检测，不以虚构百分比表示进度",
            )
            if isinstance(admission_row.get("next_due"), (int, float)):
                admission_stage["next_due"] = admission_row["next_due"]
            stages = [
                _stage("information", "ok" if (origin == "explicit" or registry_present) else
                       "warning" if registry_state != "ok" else "stale", registry_state),
                _stage("parse", "ok" if parsed else "error" if reason else "pending"),
                admission_stage,
                _stage("publish", "ok" if published else "pending"),
                _stage("load", "ok" if evidence.get("loaded") is True else
                       "error" if evidence.get("loaded") is False else "pending"),
            ]
            provider_model: dict[str, Any]
            if origin == "managed":
                provider_model = {"candidate_scope": str(managed.get("candidate_channel", "isolated_admission_queue")),
                                  "active": str(managed.get("active_provider", "Managed_Auto"))}
            else:
                provider_model = {"active": str(provider.get("provider_name", source_id))}
            rows.append({
                "id": source_id, "name": str(evidence.get("name", stored.get("name", registry.get(source_id, {}).get("name", provider.get("name", source_id)))))[:80],
                "origin": origin, "stage": lifecycle, "lifecycle": lifecycle,
                "desired": desired, "actual": actual, "reason": reason or None,
                "dependencies": dependencies, "providers": provider_model,
                "candidate_count": candidate_count, "approved_count": approved_count,
                "admission": {
                    "parsed_count": int(admission_row.get("parsed_count", candidate_count) or 0),
                    "candidate_count": int(admission_row.get("candidate_count", candidate_count) or 0),
                    "tested_count": int(admission_row.get("tested_count", 0) or 0),
                    "approved_count": int(admission_row.get("approved_count", approved_count) or 0),
                    "published_count": int(admission_row.get("published_count", approved_count) or 0),
                    "queued_count": int(admission_row.get("queued_count", 0) or 0),
                    "cooling_count": int(admission_row.get("cooling_count", 0) or 0),
                    "due_count": int(admission_row.get("due_count", 0) or 0),
                    "next_due": admission_row.get("next_due") if isinstance(admission_row.get("next_due"), (int, float)) else None,
                    "evidence_at": admission_epoch if isinstance(admission_epoch, (int, float)) else None,
                    "fresh": admission_fresh,
                },
                "stages": stages,
            })
        return rows

    def _model(self) -> dict[str, Any]:
        health = _json(self.health_path)
        admission_progress = _json(self.admission_progress_path)
        publish_pending = _json(self.pending_path)
        recovery = _json(self.recovery_path)
        probation = _json(self.probation_path)
        manifest, directory = self._manifest()
        registry, registry_state = self._registry()
        sources = self._rows(health, manifest, registry, registry_state, admission_progress)
        managed = manifest.get("managed") if isinstance(manifest.get("managed"), dict) else {}
        retiring_pending = sum(row["desired"] == "absent" and row["actual"] != "retired" for row in sources)
        failed = sum(row["stage"] in {"error", "quarantined"} for row in sources)
        journal_state = ("publishing" if publish_pending else "recovering" if recovery else
                         "probation" if probation else "idle")
        state = "error" if not manifest else "warning" if registry_state != "ok" or failed or retiring_pending or publish_pending or recovery else "ok"
        # CRUD CAS tracks configuration and the serving pointer only. Heartbeat,
        # admission progress and journal freshness must not invalidate a user's
        # in-progress source form every few seconds.
        revision = _digest([self.current_path, self.registry_path, self.overrides_path,
                            directory / "manifest.json" if directory else self.controller / "missing-manifest"])
        return {
            "state": state, "revision": revision,
            "capabilities": {"actions": [name for name, meta in self.actions().items() if meta.get("supported")]},
            "sources": sources,
            "reconcile": {
                "revision": revision, "release_id": str(manifest.get("release_id", "")) or None,
                "last_attempt": health.get("epoch"),
                "last_success": health.get("epoch") if health.get("release_status") in {"published", "unchanged", "shadow_current_initialized"} else None,
                "managed_count": sum(row["origin"] == "managed" for row in sources),
                "retiring_count": retiring_pending, "failed_count": failed,
                "candidate_provider": managed.get("candidate_provider"),
                "candidate_scope": str(managed.get("candidate_channel", "isolated_admission_queue")),
                "detector_scope": str(admission_progress.get("detector_scope", "loopback_isolated_core")),
                "active_provider": str(managed.get("active_provider", "Managed_Auto")),
                "candidate_count": int(managed.get("candidate_count", 0) or 0),
                "approved_count": int(managed.get("approved_count", 0) or 0),
                "candidate_exposed": False if admission_progress.get("candidate_exposed") is False else managed.get("candidate_exposed"),
                "provider_ready": bool(manifest), "registry_state": registry_state,
                "cycle_budget_seconds": health.get("cycle_budget_seconds"),
                "cycle_elapsed_seconds": health.get("cycle_elapsed_seconds"),
                "reason": _code(health.get("reason")) or None,
                "journal": {
                    "state": journal_state,
                    "release_id": str((publish_pending or probation).get("release_id", "")) or None,
                    "started_at": (publish_pending or probation).get("started_at"),
                },
                "selection_consistency": {
                    "coordinated_writes": "routing_owner_locked",
                    "direct_openclash_change_during_publish": "detected_and_rolled_back",
                },
            },
        }

    def snapshot(self) -> dict[str, Any]:
        return self._model()

    def _expected_providers(self) -> tuple[dict[str, dict[str, Any]], list[dict[str, Any]]]:
        manifest, directory = self._manifest()
        failures: list[dict[str, Any]] = []
        expected: dict[str, dict[str, Any]] = {}
        if not manifest or not directory:
            return expected, [{"code": "current_release_unavailable"}]
        for row in manifest.get("sources", []):
            if not isinstance(row, dict):
                continue
            provider = str(row.get("provider_name", row.get("id", "")))
            file_name = str(row.get("file", ""))
            if not SAFE_ID.fullmatch(provider) or not re.fullmatch(r"[A-Za-z0-9_.-]{1,128}\.yaml", file_name):
                failures.append({"provider": provider[:96], "code": "manifest_provider_invalid"})
                continue
            names = _names(directory / file_name, str(row.get("sha256", "")))
            if names is None:
                failures.append({"provider": provider, "code": "provider_artifact_invalid"})
                continue
            expected[provider] = {"names": names, "role": str(row.get("role", "explicit"))}
        return expected, failures

    def _validate(self) -> dict[str, Any]:
        expected, failures = self._expected_providers()
        if not callable(self.clash):
            return {"state": "unsupported", "error_code": "clash_reader_unavailable", "providers": []}
        try:
            payload = self.clash("/providers/proxies")
        except Exception:
            return {"state": "error", "error_code": "clash_provider_read_failed", "providers": [],
                    "failures": failures}
        actual_root = payload.get("providers", {}) if isinstance(payload, dict) else {}
        actual_root = actual_root if isinstance(actual_root, dict) else {}
        if "Managed_Candidate" in actual_root:
            failures.append({"provider": "Managed_Candidate", "code": "candidate_provider_exposed_in_production"})
        evidence = []
        for provider, expected_row in expected.items():
            actual_row = actual_root.get(provider)
            proxies = actual_row.get("proxies", []) if isinstance(actual_row, dict) else []
            actual_names = [str(row.get("name")) for row in proxies if isinstance(row, dict) and row.get("name")
                            and not str(row.get("name")).startswith(EMPTY_PREFIX)]
            exact = Counter(expected_row["names"]) == Counter(actual_names)
            evidence.append({"provider": provider, "role": expected_row["role"],
                             "expected_count": len(expected_row["names"]), "actual_count": len(actual_names),
                             "identity_match": exact})
            if expected_row["role"] in {"managed_candidate", "managed_active"} and not exact:
                failures.append({"provider": provider, "code": "managed_provider_identity_mismatch"})
        manifest, directory = self._manifest()
        candidate_only: set[str] = set()
        if directory:
            for row in manifest.get("source_breakdown", []):
                if not isinstance(row, dict):
                    continue
                names = _names(directory / str(row.get("file", "")), str(row.get("sha256", ""))) or []
                approved = {str(name) for name in row.get("approved_names", [])}
                candidate_only.update(set(names) - approved)
        try:
            proxies_payload = self.clash("/proxies")
            proxies = proxies_payload.get("proxies", {}) if isinstance(proxies_payload, dict) else {}
            exposed = sorted(candidate_only.intersection(proxies if isinstance(proxies, dict) else {}))
            if exposed:
                failures.append({"code": "unadmitted_candidate_exposed", "count": len(exposed)})
            global_row = proxies.get("GLOBAL", {}) if isinstance(proxies, dict) else {}
            global_names = set(global_row.get("all", [])) if isinstance(global_row, dict) and isinstance(global_row.get("all", []), list) else set()
            if isinstance(global_row, dict) and global_row.get("now"):
                global_names.add(str(global_row["now"]))
            global_exposed = sorted(candidate_only.intersection(str(name) for name in global_names))
            if global_exposed:
                failures.append({"code": "unadmitted_candidate_in_global", "count": len(global_exposed)})
        except Exception:
            failures.append({"code": "production_proxy_visibility_failed"})
        return {"state": "ok" if not failures else "error", "providers": evidence, "failures": failures}

    @staticmethod
    def _source_id(params: dict[str, Any]) -> str:
        source_id = str(params.get("source_id", "")).strip()
        if not SAFE_ID.fullmatch(source_id):
            raise SubscriptionActionError("source_id_invalid")
        return source_id

    @staticmethod
    def _source_name(value: Any, fallback: str) -> str:
        name = str(value if value is not None else fallback).strip()
        if not 1 <= len(name) <= 80 or any(ord(character) < 32 for character in name):
            raise SubscriptionActionError("source_name_invalid")
        return name

    @staticmethod
    def _source_url(value: Any) -> str:
        url = str(value or "").strip()
        if not 1 <= len(url) <= 4096:
            raise SubscriptionActionError("source_url_invalid")
        parsed = urllib.parse.urlsplit(url)
        if parsed.scheme.lower() not in {"http", "https"} or not parsed.hostname or parsed.username or parsed.password:
            raise SubscriptionActionError("source_url_invalid")
        return urllib.parse.urlunsplit((parsed.scheme.lower(), parsed.netloc.lower(), parsed.path, parsed.query, ""))

    def _protected_ids(self) -> set[str]:
        manifest, _directory = self._manifest()
        return {
            str(row.get("id")) for row in manifest.get("sources", [])
            if isinstance(row, dict) and row.get("role", "explicit") == "explicit" and row.get("id")
        }

    def _write_source(self, action: str, params: dict[str, Any], progress: Any) -> dict[str, Any]:
        if not self.write_lock_managed:
            raise SubscriptionActionError("coordinator_lock_unavailable", 503)
        started = time.monotonic()
        progress("validating")
        base, registry_state = self._base_registry()
        if registry_state != "ok":
            raise SubscriptionActionError("information_registry_unavailable", 503)
        old_exists = self.overrides_path.exists()
        document = self._overrides()
        local = {
            str(row.get("id")): dict(row) for row in document["sources"]
            if isinstance(row, dict) and SAFE_ID.fullmatch(str(row.get("id", "")))
        }
        tombstones = {str(source_id) for source_id in document["tombstones"] if SAFE_ID.fullmatch(str(source_id))}
        protected = self._protected_ids()

        if action == "subscriptions.source.add":
            url = self._source_url(params.get("url"))
            name = self._source_name(params.get("name"), "自定义订阅")
            for row in list(base.values()) + list(local.values()):
                try:
                    if self._source_url(row.get("url")) == url:
                        raise SubscriptionActionError("source_url_already_exists", 409)
                except SubscriptionActionError as error:
                    if error.code == "source_url_already_exists":
                        raise
            source_id = "Local_" + hashlib.sha256(url.encode()).hexdigest()[:20]
            if source_id in protected or source_id in base or source_id in local:
                raise SubscriptionActionError("source_identity_collision", 409)
            local[source_id] = {"id": source_id, "name": name, "url": url, "owner": "clash-center", "enabled": True}
            tombstones.discard(source_id)
        else:
            source_id = self._source_id(params)
            if source_id in protected:
                raise SubscriptionActionError("protected_legacy_source", 409)
            current = local.get(source_id) or base.get(source_id)
            if action in {"subscriptions.source.update", "subscriptions.source.disable"} and current is None:
                raise SubscriptionActionError("source_not_found", 404)
            if action == "subscriptions.source.update":
                url = self._source_url(params.get("url", current.get("url")))
                name = self._source_name(params.get("name"), str(current.get("name", source_id)))
                for other_id, row in {**base, **local}.items():
                    if other_id == source_id:
                        continue
                    try:
                        if self._source_url(row.get("url")) == url:
                            raise SubscriptionActionError("source_url_already_exists", 409)
                    except SubscriptionActionError as error:
                        if error.code == "source_url_already_exists":
                            raise
                local[source_id] = {"id": source_id, "name": name, "url": url, "owner": "clash-center", "enabled": True}
            elif action == "subscriptions.source.disable":
                tombstones.add(source_id)
            elif action == "subscriptions.source.enable":
                if source_id not in tombstones:
                    raise SubscriptionActionError("source_not_disabled", 409)
                tombstones.discard(source_id)
            elif action == "subscriptions.source.delete":
                if source_id in base:
                    # Keep a tombstone so OpenClash source_sync cannot revive it.
                    tombstones.add(source_id)
                    local.pop(source_id, None)
                elif source_id in local:
                    local.pop(source_id, None)
                    tombstones.discard(source_id)
                elif source_id not in tombstones:
                    raise SubscriptionActionError("source_not_found", 404)
            else:
                raise SubscriptionActionError("subscription_action_unsupported", 404)

        if time.monotonic() - started >= 9:
            raise SubscriptionActionError("source_write_deadline_exceeded", 503)
        value = {
            "schema": 1, "sources": sorted(local.values(), key=lambda row: row["id"]),
            "tombstones": sorted(tombstones), "updated_at": int(time.time()),
        }
        progress("applying")
        _atomic_private(self.overrides_path, value)
        try:
            if self._overrides() != value:
                raise SubscriptionActionError("source_write_readback_failed", 503)
        except Exception as error:
            try:
                if old_exists:
                    _atomic_private(self.overrides_path, document)
                    if self._overrides() != document:
                        raise SubscriptionActionError("source_write_rollback_failed", 503)
                else:
                    self.overrides_path.unlink(missing_ok=True)
                    if self.overrides_path.exists():
                        raise SubscriptionActionError("source_write_rollback_failed", 503)
            except Exception as rollback_error:
                raise SubscriptionActionError("source_write_state_uncertain", 503) from rollback_error
            raise SubscriptionActionError("source_write_readback_failed", 503) from error
        # No URL is copied into the trigger. The controller consumes it under
        # the same routing-owner lock and performs the network work itself.
        reconcile = "scheduled_by_subscription_controller"
        try:
            _atomic_private(self.controller / "reconcile-request.json", {
                "schema": 1, "owner": "unified-center", "requested_at": int(time.time()), "source_id": source_id,
            })
        except Exception:
            # The source transaction already committed. A missing acceleration
            # hint must not turn success into a false failure; the periodic
            # controller cycle remains the durable fallback.
            reconcile = "scheduled_by_interval"
        progress("readback")
        return {
            "state": "ok", "source_id": source_id,
            "desired": "absent" if source_id in tombstones else "present",
            "reconcile": reconcile,
        }

    def execute(self, action: str, params: dict[str, Any], progress: Any) -> dict[str, Any]:
        if action == "subscriptions.preview":
            progress("reading")
            model = self._model()
            source_id = str(params.get("source_id", ""))
            if source_id:
                if not SAFE_ID.fullmatch(source_id):
                    return {"state": "error", "error_code": "source_id_invalid"}
                model["sources"] = [row for row in model["sources"] if row["id"] == source_id]
                if not model["sources"]:
                    return {"state": "error", "error_code": "source_not_found"}
            progress("readback")
            return model
        if action == "subscriptions.validate":
            progress("validating")
            result = self._validate()
            progress("readback")
            return result
        if action.startswith("subscriptions.source."):
            return self._write_source(action, params, progress)
        return {"state": "error", "error_code": "subscription_action_unsupported"}


def create_extension(context: dict[str, Any]) -> SubscriptionLifecycleExtension:
    return SubscriptionLifecycleExtension(context)
