#!/usr/bin/env python3
"""Fail-static subscription admission and release controller.

The controller never edits OpenClash configuration.  It publishes immutable,
validated proxy-provider releases and, in automatic mode, asks Mihomo to
refresh the existing providers.  A failed fetch, validation, smoke test or
controller crash leaves the last-known-good provider release in service.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import hmac
import html
import json
import math
import os
import re
import shutil
import sqlite3
import subprocess
import sys
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

import yaml
from autonomy_store import checkpoint, recover_document, exclusive, publication_verdict, valid_sample


DATA = Path(os.getenv("SUBSCRIPTION_DATA_DIR", "/data/subscription-controller"))
DB_PATH = Path(os.getenv("SUBSCRIPTION_DB", str(DATA / "controller.db")))
SOURCES_FILE = Path(os.getenv("SUBSCRIPTION_SOURCES_FILE", "/data/subscription-sources.json"))
CAPABILITY_URL = os.getenv("SUBSCRIPTION_CAPABILITY_URL", "http://127.0.0.1:8081/api/nodes")
OPENCLASH_API = os.getenv("OPENCLASH_API", "http://10.88.0.254:9090").rstrip("/")
OPENCLASH_SECRET = os.getenv("OPENCLASH_SECRET", "")
OPENCLASH_API_TIMEOUT = max(10, int(os.getenv("OPENCLASH_API_TIMEOUT", "30")))
MODE = os.getenv("SUBSCRIPTION_CONTROLLER_MODE", "shadow").lower()
PUBLISH_TOKEN = os.getenv("SUBSCRIPTION_PUBLISH_TOKEN", "")
HMAC_KEY = os.getenv("SUBSCRIPTION_HMAC_KEY", PUBLISH_TOKEN)
INTERVAL = max(300, int(os.getenv("SUBSCRIPTION_FETCH_INTERVAL", "3600")))
FETCH_TIMEOUT = max(5, int(os.getenv("SUBSCRIPTION_FETCH_TIMEOUT", "30")))
SUBSCRIPTION_USER_AGENT = os.getenv("SUBSCRIPTION_USER_AGENT", "clash.meta").strip() or "clash.meta"
MAX_BYTES = max(1024 * 1024, int(os.getenv("SUBSCRIPTION_MAX_BYTES", str(20 * 1024 * 1024))))
CACHE_TTL = max(3600, int(os.getenv("SUBSCRIPTION_CACHE_TTL", str(7 * 86400))))
MIN_APPROVED = max(1, int(os.getenv("SUBSCRIPTION_MIN_APPROVED", "3")))
MAX_DROP_PERCENT = max(5, min(95, int(os.getenv("SUBSCRIPTION_MAX_DROP_PERCENT", "30"))))
MAX_RUNTIME_REJECT_PERCENT = max(
    0, min(50, int(os.getenv("SUBSCRIPTION_MAX_RUNTIME_REJECT_PERCENT", "10")))
)
MAX_RELEASES = max(20, int(os.getenv("SUBSCRIPTION_MAX_RELEASES", "100")))
ANOMALY_CONFIRMATIONS = max(2, int(os.getenv("SUBSCRIPTION_ANOMALY_CONFIRMATIONS", "3")))
POST_PUBLISH_WAIT = max(5, int(os.getenv("SUBSCRIPTION_POST_PUBLISH_WAIT", "20")))
HTTP_PORT = int(os.getenv("SUBSCRIPTION_HTTP_PORT", "8082"))
ALLOWED_PROVIDER_CLIENTS = {
    item.strip() for item in os.getenv(
        "SUBSCRIPTION_ALLOWED_PROVIDER_CLIENTS",
        "10.88.0.254,127.0.0.1,172.17.0.1,172.18.0.1",
    ).split(",") if item.strip()
}
PROXY = os.getenv("PROXY", "http://10.88.0.254:7893")
PROXY_AUTH = os.getenv("PROXY_AUTH", "")
LOG_PATH = DATA / "controller.log"
HEALTH_PATH = DATA / "health.json"
CURRENT_PATH = DATA / "current.json"
PENDING_PATH = DATA / "publish-pending.json"
RELEASES = DATA / "releases"
CACHE = DATA / "cache"
STATUS_PATTERN = re.compile(
    r"(?:剩余流量|重置剩余|下次重置|套餐到期|官网|邮箱|节点异常|"
    r"刷新订阅|刷新失败|更新失败|取消订阅时限|Expire|Traffic|"
    r"Reset|Remaining|Official|Website)", re.I,
)
from upgrade_policy import usable_name
RETAINED_SOURCES = set()
LOCK = threading.RLock()

def retained_provider(source, manifest):
    if not manifest:
        return []
    item = next((x for x in manifest.get("sources",[]) if x["id"]==source.source_id),None)
    if not item:
        return []
    raw = (RELEASES/manifest["release_id"]/item["file"]).read_bytes()
    if hashlib.sha256(raw).hexdigest()!=item["sha256"]:
        raise ControllerError("retained_provider_checksum_failed:"+source.source_id)
    nodes = normalized_nodes(parse_nodes(raw))
    previous = previous_fingerprints(manifest)
    if any(fingerprint(node) not in previous for node in nodes):
        raise ControllerError("retained_provider_fingerprint_failed:"+source.source_id)
    if nodes:
        RETAINED_SOURCES.add(source.source_id)
    return nodes



SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=FULL;
CREATE TABLE IF NOT EXISTS source_state(
  source_id TEXT PRIMARY KEY,
  last_hash TEXT NOT NULL DEFAULT '',
  last_count INTEGER NOT NULL DEFAULT 0,
  last_success INTEGER NOT NULL DEFAULT 0,
  last_error TEXT NOT NULL DEFAULT '',
  consecutive_success INTEGER NOT NULL DEFAULT 0,
  consecutive_failure INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS releases(
  id TEXT PRIMARY KEY,
  created_at INTEGER NOT NULL,
  status TEXT NOT NULL,
  mode TEXT NOT NULL,
  node_count INTEGER NOT NULL,
  risk_score INTEGER NOT NULL,
  previous_id TEXT NOT NULL DEFAULT '',
  candidate_hash TEXT NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  manifest_json TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events(
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  created_at INTEGER NOT NULL,
  level TEXT NOT NULL,
  event TEXT NOT NULL,
  detail TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS metadata(
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);
"""


@dataclass(frozen=True)
class Source:
    source_id: str
    name: str
    url: str
    provider_name: str


class ControllerError(RuntimeError):
    pass


def now() -> int:
    return int(time.time())


def atomic_bytes(path: Path, payload: bytes, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f".{path.name}.tmp-{os.getpid()}-{threading.get_ident()}")
    with open(temporary, "wb") as stream:
        os.chmod(temporary, mode)
        stream.write(payload)
        stream.flush()
        os.fsync(stream.fileno())
    os.replace(temporary, path)


def atomic_json(path: Path, value: Any, mode: int = 0o600) -> None:
    atomic_bytes(path, (json.dumps(value, ensure_ascii=False, sort_keys=True, indent=2) + "\n").encode(), mode)
    if path == CURRENT_PATH:
        checkpoint(path,value)


def safe_detail(value: str) -> str:
    value = re.sub(r"https?://\S+", "URL_REDACTED", value)
    value = re.sub(r"(?i)(token|secret|password|authorization)=?[^\s,;]+", r"\1=REDACTED", value)
    return value[:600]


def log(event: str, detail: str = "", level: str = "info") -> None:
    DATA.mkdir(parents=True, exist_ok=True)
    line = f"{time.strftime('%F %T')} level={level} event={event} detail={safe_detail(detail)}\n"
    with LOCK:
        with open(LOG_PATH, "a", encoding="utf-8") as stream:
            os.chmod(LOG_PATH, 0o600)
            stream.write(line)
        with db() as conn:
            conn.execute(
                "INSERT INTO events(created_at,level,event,detail) VALUES(?,?,?,?)",
                (now(), level, event, safe_detail(detail)),
            )
            conn.execute("DELETE FROM events WHERE id NOT IN (SELECT id FROM events ORDER BY id DESC LIMIT 1000)")


@contextlib.contextmanager
def db():
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH, timeout=20)
    conn.row_factory = sqlite3.Row
    conn.executescript(SCHEMA)
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


def meta_get(key: str, default: str = "") -> str:
    with db() as conn:
        row = conn.execute("SELECT value FROM metadata WHERE key=?", (key,)).fetchone()
        return row[0] if row else default


def meta_set(key: str, value: str) -> None:
    with db() as conn:
        conn.execute(
            "INSERT INTO metadata(key,value) VALUES(?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (key, value),
        )


def load_sources() -> list[Source]:
    if not SOURCES_FILE.is_file():
        raise ControllerError("sources_file_missing")
    if SOURCES_FILE.stat().st_mode & 0o077:
        raise ControllerError("sources_file_permissions_must_be_600")
    raw = yaml.safe_load(SOURCES_FILE.read_text(encoding="utf-8"))
    if not isinstance(raw, (dict, list)):
        raise ControllerError("invalid_sources_document")
    entries = raw.get("sources", raw if isinstance(raw, list) else [])
    result: list[Source] = []
    seen: set[str] = set()
    for item in entries:
        if not item.get("enabled", True):
            continue
        source_id = str(item.get("id", "")).strip()
        url = str(item.get("url", "")).strip()
        provider_name = str(item.get("provider_name", source_id)).strip()
        parsed = urllib.parse.urlparse(url)
        if not re.fullmatch(r"[A-Za-z0-9_.-]{1,80}", source_id):
            raise ControllerError("invalid_source_id")
        if parsed.scheme not in {"http", "https"} or not parsed.hostname:
            raise ControllerError(f"invalid_source_url:{source_id}")
        if source_id in seen:
            raise ControllerError(f"duplicate_source_id:{source_id}")
        seen.add(source_id)
        result.append(Source(source_id, str(item.get("name", source_id))[:80], url, provider_name))
    if not result:
        raise ControllerError("no_enabled_sources")
    return result


def fetch(source: Source) -> bytes:
    last_error: Exception | None = None
    for attempt, delay in enumerate((0, 2, 5), start=1):
        if delay:
            time.sleep(delay)
        request = urllib.request.Request(
            source.url,
            headers={"User-Agent": SUBSCRIPTION_USER_AGENT, "Accept": "*/*"},
        )
        try:
            with urllib.request.urlopen(request, timeout=FETCH_TIMEOUT) as response:
                length = int(response.headers.get("Content-Length", "0") or 0)
                if length > MAX_BYTES:
                    raise ControllerError("source_too_large")
                payload = response.read(MAX_BYTES + 1)
                if len(payload) > MAX_BYTES:
                    raise ControllerError("source_too_large")
                if not payload.strip():
                    raise ControllerError("source_empty")
                return payload
        except Exception as exc:
            last_error = exc
            log("source_fetch_retry", f"source={source.source_id} attempt={attempt}", "warning")
    raise ControllerError(f"source_fetch_failed:{type(last_error).__name__}") from last_error


def maybe_decode_base64(payload: bytes) -> bytes:
    stripped = b"".join(payload.split())
    if not stripped:
        return payload
    try:
        decoded = base64.b64decode(stripped + b"=" * (-len(stripped) % 4), validate=False)
    except Exception:
        return payload
    return decoded if b"://" in decoded or b"proxies:" in decoded else payload


def parse_nodes(payload: bytes) -> list[dict[str, Any]]:
    candidates = [payload]
    decoded = maybe_decode_base64(payload)
    if decoded != payload:
        candidates.append(decoded)
    for candidate in candidates:
        try:
            document = yaml.safe_load(candidate.decode("utf-8-sig"))
        except Exception:
            continue
        if isinstance(document, dict) and isinstance(document.get("proxies"), list):
            nodes = [node for node in document["proxies"] if isinstance(node, dict)]
            if nodes:
                return nodes
        if isinstance(document, list) and all(isinstance(node, dict) for node in document):
            return list(document)
    text = decoded.decode("utf-8", errors="ignore")
    if re.search(r"(?m)^(ss|ssr|vmess|vless|trojan|hysteria2|tuic)://", text):
        raise ControllerError("uri_subscription_requires_local_converter")
    raise ControllerError("unsupported_subscription_format")


def canonical_node(node: dict[str, Any]) -> bytes:
    content = {key: value for key, value in node.items() if key != "name"}
    return json.dumps(content, ensure_ascii=False, sort_keys=True, separators=(",", ":")).encode()


def fingerprint(node: dict[str, Any]) -> str:
    return hmac.new(HMAC_KEY.encode(), canonical_node(node), hashlib.sha256).hexdigest()


def normalized_nodes(nodes: list[dict[str, Any]]) -> list[dict[str, Any]]:
    result = []
    for node in nodes:
        name = str(node.get("name", "")).strip()
        if not usable_name(name) or STATUS_PATTERN.search(name):
            continue
        if not node.get("type") or not node.get("server") or not node.get("port"):
            continue
        clean = dict(node)
        clean["name"] = name[:240]
        result.append(clean)
    return result


def capability_nodes() -> dict[str, dict[str, Any]]:
    try:
        with urllib.request.urlopen(CAPABILITY_URL, timeout=10) as response:
            payload = json.load(response)
        return {str(item.get("name")): item for item in payload.get("nodes", []) if item.get("name")}
    except Exception as exc:
        log("capability_unavailable", str(exc), "warning")
        return {}


def current_manifest() -> dict[str, Any] | None:
    try:
        pointer,_ = recover_document(CURRENT_PATH,valid_pointer)
        if pointer is None:return None
        manifest=json.loads((RELEASES / pointer["release_id"] / "manifest.json").read_text(encoding="utf-8"))
        for item in manifest.get("sources",[]):
            name=item["file"]
            if Path(name).name!=name:return None
            if hashlib.sha256((RELEASES/pointer["release_id"]/name).read_bytes()).hexdigest()!=item["sha256"]:return None
        return manifest
    except Exception:
        return None


def valid_pointer(value):
    try:
        if not (isinstance(value,dict) and isinstance(value.get("release_id"),str)
                and Path(value["release_id"]).name==value["release_id"]):return False
        directory=RELEASES/value["release_id"]
        manifest=json.loads((directory/"manifest.json").read_text())
        for item in manifest.get("sources",[]):
            if Path(item["file"]).name!=item["file"]:return False
            if hashlib.sha256((directory/item["file"]).read_bytes()).hexdigest()!=item["sha256"]:return False
        return True
    except (OSError,ValueError,TypeError,KeyError):return False


def repair_pointer() -> bool:
    if current_manifest() is not None:return False
    accepted,_=recover_document(DATA/"verified-current.json",valid_pointer)
    if accepted is None:return False
    atomic_json(CURRENT_PATH,accepted)
    atomic_json(DATA/"recovery-refresh.json",{"required":True,"at":now()})
    return True


def previous_fingerprints(manifest: dict[str, Any] | None) -> set[str]:
    if not manifest:
        return set()
    return set(manifest.get("fingerprints", []))


def admitted(node: dict[str, Any], capability: dict[str, Any] | None, previous: set[str], bootstrap: bool) -> tuple[bool, str]:
    fp = fingerprint(node)
    if bootstrap:
        return True, "bootstrap"
    general = (capability or {}).get("capabilities", {}).get("general", {})
    status = general.get("status", "unknown")
    successes = int(general.get("consecutive_success", 0) or 0)
    failures = int(general.get("consecutive_failure", 0) or 0)
    confidence = int(general.get("confidence", 0) or 0)
    fresh = bool((capability or {}).get("fresh", False))
    if fp in previous:
        if status == "unavailable" and failures >= 3 and fresh:
            return False, "confirmed_unavailable"
        return True, "sticky_previous"
    if status == "available" and successes >= 2 and confidence >= 60 and fresh:
        return True, "new_verified"
    return False, "quarantine"


def provider_yaml(nodes: list[dict[str, Any]]) -> bytes:
    return yaml.safe_dump(
        {"proxies": nodes}, allow_unicode=True, sort_keys=False, default_flow_style=False, width=1000,
    ).encode("utf-8")


def state_row(source_id: str) -> sqlite3.Row | None:
    with db() as conn:
        return conn.execute("SELECT * FROM source_state WHERE source_id=?", (source_id,)).fetchone()


def source_success(source: Source, payload_hash: str, count: int) -> None:
    with db() as conn:
        conn.execute(
            """INSERT INTO source_state(source_id,last_hash,last_count,last_success,last_error,consecutive_success,consecutive_failure)
               VALUES(?,?,?,?,?,1,0)
               ON CONFLICT(source_id) DO UPDATE SET last_hash=excluded.last_hash,last_count=excluded.last_count,
                 last_success=excluded.last_success,last_error='',consecutive_success=source_state.consecutive_success+1,
                 consecutive_failure=0""",
            (source.source_id, payload_hash, count, now(), ""),
        )


def source_failure(source: Source, reason: str) -> None:
    with db() as conn:
        conn.execute(
            """INSERT INTO source_state(source_id,last_error,consecutive_failure)
               VALUES(?,?,1)
               ON CONFLICT(source_id) DO UPDATE SET last_error=excluded.last_error,
                 consecutive_success=0,consecutive_failure=source_state.consecutive_failure+1""",
            (source.source_id, safe_detail(reason)),
        )


def source_cached(source: Source, count: int) -> None:
    with db() as conn:
        conn.execute("UPDATE source_state SET last_count=? WHERE source_id=?", (count, source.source_id))


def load_or_fetch(source: Source) -> tuple[list[dict[str, Any]], bool, str]:
    cache_file = CACHE / f"{source.source_id}.yaml"
    try:
        payload = fetch(source)
        nodes = normalized_nodes(parse_nodes(payload))
        if not nodes:
            raise ControllerError("no_valid_nodes")
        digest = hashlib.sha256(payload).hexdigest()
        atomic_bytes(cache_file, payload)
        source_success(source, digest, len(nodes))
        return nodes, False, digest
    except Exception as exc:
        source_failure(source, str(exc))
        # Preserve this source's exact last-published content; never contaminate it
        # with an error response or publish a newly guessed cached endpoint set.
        nodes = retained_provider(source, current_manifest())
        if nodes:
            return nodes, True, hashlib.sha256(provider_yaml(nodes)).hexdigest()
        raise ControllerError(f"source_unavailable:{source.source_id}:{safe_detail(str(exc))}") from exc


def evaluate_risk(total: int, previous_total: int, source_drops: list[float], cached_sources: int) -> tuple[int, list[str], bool]:
    risk = 0
    reasons: list[str] = []
    hard_hold = total < MIN_APPROVED
    if hard_hold:
        reasons.append("below_minimum_approved")
    if previous_total:
        drop = max(0.0, (previous_total - total) * 100.0 / previous_total)
        if drop > MAX_DROP_PERCENT:
            risk += 50
            reasons.append(f"approved_drop_{drop:.1f}_percent")
    if source_drops and max(source_drops) > 50:
        risk += 35
        reasons.append(f"source_drop_{max(source_drops):.1f}_percent")
    if cached_sources:
        risk += 20
        reasons.append(f"cached_sources_{cached_sources}")
    return risk, reasons, hard_hold


def anomaly_confirmed(candidate_hash: str, risky: bool) -> bool:
    if not risky:
        meta_set("pending_hash", "")
        meta_set("pending_count", "0")
        return True
    if meta_get("pending_hash") == candidate_hash:
        count = int(meta_get("pending_count", "0")) + 1
    else:
        count = 1
    meta_set("pending_hash", candidate_hash)
    meta_set("pending_count", str(count))
    return count >= ANOMALY_CONFIRMATIONS


def api_request(method: str, path: str, body: bytes | None = None, timeout: int | None = None) -> Any:
    request = urllib.request.Request(
        f"{OPENCLASH_API}{path}", data=body, method=method,
        headers={"Authorization": f"Bearer {OPENCLASH_SECRET}", "Content-Type": "application/json"},
    )
    with urllib.request.urlopen(request, timeout=timeout or OPENCLASH_API_TIMEOUT) as response:
        payload = response.read()
        return json.loads(payload) if payload else {}


def refresh_providers(sources: list[Source]) -> None:
    if not OPENCLASH_SECRET:
        raise ControllerError("openclash_secret_missing")
    for source in sources:
        encoded = urllib.parse.quote(source.provider_name, safe="")
        try:
            api_request("PUT", f"/providers/proxies/{encoded}", b"", timeout=max(60, OPENCLASH_API_TIMEOUT))
        except urllib.error.HTTPError as exc:
            body = safe_detail(exc.read().decode("utf-8", errors="replace"))
            raise ControllerError(
                f"provider_refresh_http:{source.source_id}:{exc.code}:{body}"
            ) from exc


def runtime_provider_counts(sources: list[Source]) -> dict[str, int]:
    payload = api_request("GET", "/providers/proxies")
    providers = payload.get("providers", {}) if isinstance(payload, dict) else {}
    counts: dict[str, int] = {}
    for source in sources:
        provider = providers.get(source.provider_name)
        if not isinstance(provider, dict) or not isinstance(provider.get("proxies"), list):
            raise ControllerError(f"runtime_provider_missing:{source.source_id}")
        counts[source.source_id] = len(provider["proxies"])
    return counts


def production_smoke() -> tuple[bool, str]:
    checks = [
        ("amd_cn", "https://developer.amd.com.cn/radeon/tokenfactory", {200, 301, 302}, None, "GET"),
        ("tuya_cn", "https://www.tuya.com/cn/", {200, 301, 302}, None, "GET"),
        ("google", "https://www.gstatic.com/generate_204", {204}, None, "GET"),
        ("chatgpt", "https://chatgpt.com/backend-api/codex/responses", {400, 401}, "json", "POST"),
        ("gemini", "https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta", {200}, "json", "GET"),
        ("github", "https://github.com/", {200, 301, 302}, None, "GET"),
    ]
    failures = []
    for name, url, accepted, content_required, method in checks:
        passed = False
        last_code = 0
        for attempt in range(2):
            command = ["curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}|%{content_type}", "--max-time", "15", "-x", PROXY]
            if PROXY_AUTH:
                command.extend(["-U", PROXY_AUTH])
            if method == "POST":
                command.extend([
                    "-X", "POST", "-H", "Content-Type: application/json",
                    "-H", "User-Agent: Mozilla/5.0", "-d", "{}",
                ])
            command.append(url)
            try:
                completed = subprocess.run(command, capture_output=True, text=True, timeout=20, check=False)
                code_text, _, content_type = completed.stdout.strip().partition("|")
                last_code = int(code_text or 0)
                passed = last_code in accepted and (content_required is None or content_required in content_type.lower())
            except Exception:
                last_code = 0
                passed = False
            if passed:
                break
            if attempt == 0:
                time.sleep(2)
        if not passed:
            failures.append(f"{name}:{last_code}")
    return not failures, ",".join(failures) if failures else "ok"


def release_record(release_id: str, status: str, mode: str, count: int, risk: int,
                   previous_id: str, candidate_hash: str, reason: str, manifest: dict[str, Any]) -> None:
    with db() as conn:
        conn.execute(
            """INSERT OR REPLACE INTO releases
               (id,created_at,status,mode,node_count,risk_score,previous_id,candidate_hash,reason,manifest_json)
               VALUES(?,?,?,?,?,?,?,?,?,?)""",
            (release_id, now(), status, mode, count, risk, previous_id, candidate_hash,
             safe_detail(reason), json.dumps(manifest, ensure_ascii=False, sort_keys=True)),
        )


def set_release_status(release_id: str, status: str, reason: str = "") -> None:
    with db() as conn:
        conn.execute("UPDATE releases SET status=?,reason=? WHERE id=?", (status, safe_detail(reason), release_id))


def recover_interrupted_publish() -> bool:
    if not PENDING_PATH.is_file():
        return False
    try:
        pending = json.loads(PENDING_PATH.read_text(encoding="utf-8"))
        previous_pointer = pending.get("previous_pointer")
        if not isinstance(previous_pointer, dict):
            raise ControllerError("interrupted_publish_previous_pointer_missing")
        previous_id = str(previous_pointer.get("release_id", ""))
        if not previous_id or not (RELEASES / previous_id / "manifest.json").is_file():
            raise ControllerError("interrupted_publish_previous_release_missing")
        atomic_json(CURRENT_PATH, previous_pointer)
        atomic_json(DATA/"recovery-refresh.json",{"required":True,"at":now()})
        PENDING_PATH.unlink()
        log("interrupted_publish_recovered", f"release={previous_id}", "warning")
        return True
    except Exception as exc:
        raise ControllerError(f"interrupted_publish_recovery_failed:{safe_detail(str(exc))}") from exc


def prune_releases() -> None:
    protected: set[str] = set()
    for path in (CURRENT_PATH, PENDING_PATH, DATA/"release-probation.json", DATA/"verified-current.json"):
        try:
            document = json.loads(path.read_text(encoding="utf-8"))
            for key in ("release_id",):
                if document.get(key):
                    protected.add(str(document[key]))
            previous = document.get("previous_pointer")
            if isinstance(previous, dict) and previous.get("release_id"):
                protected.add(str(previous["release_id"]))
        except Exception:
            pass
    with db() as conn:
        rows = conn.execute("SELECT id FROM releases ORDER BY created_at DESC,id DESC").fetchall()
        keep = {str(row[0]) for row in rows[:MAX_RELEASES]} | protected
        remove = [str(row[0]) for row in rows if str(row[0]) not in keep]
        for release_id in remove:
            if re.fullmatch(r"\d{8}-\d{6}-[0-9a-f]{12}", release_id):
                release_path = RELEASES / release_id
                if release_path.parent == RELEASES and release_path.is_dir():
                    shutil.rmtree(release_path)
            conn.execute("DELETE FROM releases WHERE id=?", (release_id,))


def create_release(source_nodes: dict[str, list[dict[str, Any]]], sources: list[Source],
                   capability: dict[str, dict[str, Any]], cached_sources: int,
                   previous_source_counts: dict[str, int]) -> tuple[str, dict[str, Any], int, list[str], bool]:
    previous_manifest = current_manifest()
    previous = previous_fingerprints(previous_manifest)
    bootstrap = previous_manifest is None
    approved: dict[str, list[dict[str, Any]]] = {}
    quarantined = 0
    seen_fingerprints: set[str] = set()
    name_counts: dict[str, int] = {}
    admission_budget=max(1,min(4,int(os.getenv("SUBSCRIPTION_ADMISSION_BUDGET","2"))))
    admission_cache_path=DATA/"admission-cache.json"
    try:
        admission_cache=json.loads(admission_cache_path.read_text())
        if not isinstance(admission_cache,dict):admission_cache={}
    except (OSError,ValueError):admission_cache={}
    admission_cache={k:v for k,v in admission_cache.items() if isinstance(v,dict) and type(v.get("ok")) is bool
                     and type(v.get("at")) in (int,float) and math.isfinite(v["at"])}
    if not bootstrap and os.getenv("SUBSCRIPTION_ISOLATED_ADMISSION","0")=="1":
        from node_admission import validate
        unseen={fingerprint(n):n for batch in source_nodes.values() for n in batch if fingerprint(n) not in previous}
        pending=[]
        for fp,node in unseen.items():
            record=admission_cache.get(fp,{})
            if not isinstance(record,dict):record={}
            age=now()-record.get("at",0)
            if not 0<=age<(3600 if record.get("ok") else 21600):pending.append((record.get("at",0),fp,node))
        for _,fp,node in sorted(pending,key=lambda item:item[:2])[:admission_budget]:
            ok,detail=validate(node)
            admission_cache[fp]={"ok":ok,"at":now(),"reason":detail}
    for nodes in source_nodes.values():
        for node in nodes:
            name_counts[str(node.get("name"))] = name_counts.get(str(node.get("name")), 0) + 1
    for source in sources:
        accepted_nodes = []
        provider_fingerprints = set()
        for original in source_nodes[source.source_id]:
            node = dict(original)
            fp = fingerprint(node)
            if fp in provider_fingerprints:
                continue
            ok, _reason = admitted(node, capability.get(str(node.get("name"))), previous, bootstrap)
            if not bootstrap and fp not in previous and os.getenv("SUBSCRIPTION_ISOLATED_ADMISSION","0")=="1":
                # Never inherit another endpoint's capability merely because names match.
                record=admission_cache.get(fp,{})
                if not isinstance(record,dict):record={}
                ok=record.get("ok") is True and 0<=now()-record.get("at",0)<3600
            if source.source_id in RETAINED_SOURCES:
                ok = fp in previous
            if not ok:
                quarantined += 1
                continue
            seen_fingerprints.add(fp)
            provider_fingerprints.add(fp)
            if name_counts.get(str(node.get("name")), 0) > 1:
                node["name"] = f"[{source.source_id}] {node['name']}"[:240]
            accepted_nodes.append(node)
        if not accepted_nodes:
            # A healthy subscription can advance while a source with no qualified
            # replacements remains on its own verified, last-published endpoints.
            accepted_nodes = retained_provider(source, previous_manifest)
            if accepted_nodes:
                seen_fingerprints.update(fingerprint(node) for node in accepted_nodes)
                source_failure(source, "admission_empty_retaining_published")
        if not accepted_nodes:
            raise ControllerError("source_empty_after_admission:"+source.source_id)
        approved[source.source_id] = accepted_nodes
    # Only bounded fingerprint/status records are kept; no endpoints or credentials.
    admission_cache={k:v for k,v in admission_cache.items() if isinstance(v,dict) and 0<=now()-v.get("at",0)<86400}
    atomic_json(admission_cache_path,admission_cache)
    total = sum(map(len, approved.values()))
    previous_total = int((previous_manifest or {}).get("node_count", 0))
    source_drops = []
    for source in sources:
        old = previous_source_counts.get(source.source_id, 0)
        new = len(source_nodes[source.source_id])
        if old > new:
            source_drops.append((old - new) * 100.0 / old)
    risk, reasons, hard_hold = evaluate_risk(total, previous_total, source_drops, cached_sources)
    digest_input = b"".join(
        provider_yaml(approved[source.source_id]) for source in sorted(sources, key=lambda x: x.source_id)
    )
    candidate_hash = hashlib.sha256(digest_input).hexdigest()
    release_id = time.strftime("%Y%m%d-%H%M%S") + "-" + candidate_hash[:12]
    release_dir = RELEASES / release_id
    release_dir.mkdir(parents=True, exist_ok=False)
    os.chmod(release_dir, 0o700)
    source_manifest = []
    for source in sources:
        payload = provider_yaml(approved[source.source_id])
        file_name = f"{source.source_id}.yaml"
        atomic_bytes(release_dir / file_name, payload)
        source_manifest.append({
            "id": source.source_id,
            "name": source.name,
            "provider_name": source.provider_name,
            "node_count": len(approved[source.source_id]),
            "sha256": hashlib.sha256(payload).hexdigest(),
            "file": file_name,
        })
    manifest = {
        "release_id": release_id,
        "created_at": now(),
        "mode": MODE,
        "bootstrap": bootstrap,
        "node_count": total,
        "quarantined": quarantined,
        "risk_score": risk,
        "reasons": reasons,
        "candidate_hash": candidate_hash,
        "previous_id": (previous_manifest or {}).get("release_id", ""),
        "fingerprints": sorted(seen_fingerprints),
        "sources": source_manifest,
        "retained_sources": sorted(RETAINED_SOURCES),
    }
    atomic_json(release_dir / "manifest.json", manifest)
    return release_id, manifest, risk, reasons, hard_hold


def publish(release_id: str, manifest: dict[str, Any], sources: list[Source]) -> tuple[bool, str]:
    with exclusive(DATA.parent/"routing-owner.lock") as acquired:
        if not acquired:return False,"deferred_routing_owner_busy"
        return _publish(release_id,manifest,sources)


def _publish(release_id: str, manifest: dict[str, Any], sources: list[Source]) -> tuple[bool, str]:
    if (DATA.parent/"automation-freeze").exists():return False,"deferred_operator_freeze"
    if (DATA/"release-probation.json").exists():return False,"deferred_previous_release_probation"
    previous_pointer = None
    if CURRENT_PATH.is_file():
        previous_pointer = json.loads(CURRENT_PATH.read_text(encoding="utf-8"))
    if MODE != "automatic":
        atomic_json(CURRENT_PATH, {"release_id": release_id, "published_at": now()})
        return True, "shadow_current_initialized"
    if not previous_pointer:
        return False, "automatic_publish_requires_shadow_bootstrap"
    try:
        autonomy=json.loads((DATA.parent/"autonomy-status.json").read_text())
        baseline=autonomy.get("recent_business_metrics",{}) if 0<=now()-autonomy.get("epoch",0)<360 else {}
    except (OSError,ValueError,TypeError):baseline={}
    atomic_json(PENDING_PATH, {
        "release_id": release_id,
        "previous_pointer": previous_pointer,
        "started_at": now(),
    })
    atomic_json(CURRENT_PATH, {"release_id": release_id, "published_at": now()})
    try:
        log("publish_stage", f"release={release_id} stage=refresh_providers")
        try:
            refresh_providers(sources)
        except Exception as exc:
            # 保留 refresh_providers 已构造的 provider_refresh_http:{id}:{code}:{body}
            # （body 已经过 safe_detail）。旧写法只用 type(exc).__name__，
            # 会把内层 ControllerError 吞成 "provider_refresh_failed:ControllerError"。
            inner = str(exc).strip() or type(exc).__name__
            log("provider_refresh_failed", inner, "error")
            raise ControllerError(f"provider_refresh_failed:{inner}") from exc
        time.sleep(POST_PUBLISH_WAIT)
        log("publish_stage", f"release={release_id} stage=runtime_counts")
        try:
            runtime_counts = runtime_provider_counts(sources)
        except Exception as exc:
            # 同类：避免只剩 runtime_count_failed:ControllerError
            inner = str(exc).strip() or type(exc).__name__
            log("runtime_count_failed", inner, "error")
            raise ControllerError(f"runtime_count_failed:{inner}") from exc
        expected_counts = {item["id"]: int(item["node_count"]) for item in manifest.get("sources", [])}
        expected_total = sum(expected_counts.values())
        effective_total = sum(runtime_counts.values())
        if effective_total < MIN_APPROVED:
            raise ControllerError("runtime_below_minimum_approved")
        for source in sources:
            expected = expected_counts.get(source.source_id, 0)
            effective = runtime_counts[source.source_id]
            rejected_percent = max(0.0, (expected - effective) * 100.0 / expected) if expected else 0.0
            if rejected_percent > MAX_RUNTIME_REJECT_PERCENT:
                raise ControllerError(
                    f"runtime_provider_rejected_too_many:{source.source_id}:{rejected_percent:.1f}"
                )
        meta_set("last_effective_count", str(effective_total))
        if effective_total != expected_total:
            log(
                "runtime_provider_filtered",
                f"expected={expected_total} effective={effective_total}",
                "warning",
            )
        log("publish_stage", f"release={release_id} stage=production_smoke")
        ok, detail = production_smoke()
        if not ok:
            raise ControllerError(f"production_smoke_failed:{detail}")
        atomic_json(DATA/"release-probation.json",{"release_id":release_id,"previous_pointer":previous_pointer,
                    "started_at":now(),"baseline":baseline,"records":{},"candidate_hash":manifest.get("candidate_hash","")})
        checkpoint(DATA/"release-probation.json",json.loads((DATA/"release-probation.json").read_text()))
        PENDING_PATH.unlink(missing_ok=True)
        return True, f"automatic_publish_ok:effective={effective_total}"
    except Exception as exc:
        if previous_pointer:
            atomic_json(CURRENT_PATH, previous_pointer)
            with contextlib.suppress(Exception):
                refresh_providers(sources)
        PENDING_PATH.unlink(missing_ok=True)
        return False, safe_detail(str(exc))


def cycle() -> None:
    RETAINED_SOURCES.clear()
    sources = load_sources()
    repair_pointer()
    if CURRENT_PATH.exists() and current_manifest() is None:
        raise ControllerError("current_release_invalid_frozen")
    recovery=DATA/"recovery-refresh.json"
    if recovery.exists() and MODE=="automatic":
        with exclusive(DATA.parent/"routing-owner.lock") as acquired:
            if not acquired:raise ControllerError("recovery_routing_owner_busy")
            refresh_providers(sources)
            recovery.unlink()
    capabilities = capability_nodes()
    source_nodes: dict[str, list[dict[str, Any]]] = {}
    previous_source_counts = {
        source.source_id: int((state_row(source.source_id) or {"last_count": 0})["last_count"])
        for source in sources
    }
    cached_sources = 0
    for source in sources:
        nodes, cached, _digest = load_or_fetch(source)
        source_nodes[source.source_id] = nodes
        cached_sources += int(cached)
    release_id, manifest, risk, reasons, hard_hold = create_release(
        source_nodes, sources, capabilities, cached_sources, previous_source_counts
    )
    previous_id = str(manifest.get("previous_id", ""))
    candidate_hash = str(manifest["candidate_hash"])
    risky = risk >= 50
    confirmed = anomaly_confirmed(candidate_hash, risky)
    if candidate_hash==meta_get("rejected_candidate_hash","") and now()<int(meta_get("rejected_until","0")):
        status,reason="held","candidate_in_regression_cooldown"
    elif hard_hold:
        status, reason = "rejected", ",".join(reasons)
    elif risky and not confirmed:
        status, reason = "held", f"anomaly_confirmation_pending:{meta_get('pending_count','0')}/{ANOMALY_CONFIRMATIONS}"
    elif cached_sources and cached_sources != len(RETAINED_SOURCES) and CURRENT_PATH.is_file() and candidate_hash != (current_manifest() or {}).get("candidate_hash"):
        status, reason = "held", "cached_source_cannot_change_production"
    elif CURRENT_PATH.is_file() and candidate_hash == (current_manifest() or {}).get("candidate_hash"):
        status, reason = "unchanged", "same_as_current"
    elif MODE == "shadow" and CURRENT_PATH.is_file():
        status, reason = "shadow", "shadow_mode_no_publish"
    else:
        ok, detail = publish(release_id, manifest, sources)
        status, reason = ("published", detail) if ok else ("held" if detail.startswith("deferred_") else "rolled_back", detail)
    release_record(release_id, status, MODE, int(manifest["node_count"]), risk,
                   previous_id, candidate_hash, reason, manifest)
    prune_releases()
    effective_node_count = int(meta_get("last_effective_count", str(manifest["node_count"])))
    if CURRENT_PATH.is_file() and OPENCLASH_SECRET:
        try:
            effective_node_count = sum(runtime_provider_counts(sources).values())
            meta_set("last_effective_count", str(effective_node_count))
        except Exception as exc:
            log("runtime_provider_count_failed", str(exc), "warning")
    atomic_json(HEALTH_PATH, {
        "status": "degraded" if RETAINED_SOURCES or status in {"rolled_back","rejected"} else "ok", "mode": MODE, "epoch": now(), "release_id": release_id,
        "retained_sources": sorted(RETAINED_SOURCES), "serving_previous_release": bool(RETAINED_SOURCES),
        "release_status": status, "node_count": manifest["node_count"], "risk_score": risk,
        "effective_node_count": effective_node_count,
        "cached_sources": cached_sources, "reason": reason,
    }, 0o644)
    log("cycle_complete", f"release={release_id} status={status} nodes={manifest['node_count']} risk={risk}")


def latest_status() -> dict[str, Any]:
    try:
        health = json.loads(HEALTH_PATH.read_text(encoding="utf-8"))
    except Exception:
        health = {"status": "starting", "mode": MODE, "epoch": now()}
    with db() as conn:
        sources = [dict(row) for row in conn.execute(
            "SELECT source_id,last_count,last_success,last_error,consecutive_success,consecutive_failure FROM source_state ORDER BY source_id"
        )]
        releases = [dict(row) for row in conn.execute(
            "SELECT id,created_at,status,node_count,risk_score,previous_id,reason FROM releases ORDER BY created_at DESC LIMIT 20"
        )]
    health["sources"] = sources
    health["releases"] = releases
    return health


def health_http_code(health: dict[str, Any]) -> int:
    age = now() - int(health.get("epoch", 0))
    status = health.get("status")
    has_release = bool(
        health.get("release_id")
        or health.get("current_release")
        or current_manifest()
    )
    serviceable = status in {"ok", "starting"} or (status == "degraded" and has_release)
    return 200 if serviceable and age <= INTERVAL * 2 + 300 else 503


def dashboard() -> bytes:
    status = latest_status()
    rows = "".join(
        f"<tr><td>{html.escape(item['source_id'])}</td><td>{item['last_count']}</td>"
        f"<td>{time.strftime('%F %T', time.localtime(item['last_success'])) if item['last_success'] else '-'}</td>"
        f"<td>{html.escape(item['last_error'] or 'OK')}</td></tr>" for item in status.get("sources", [])
    )
    release_rows = "".join(
        f"<tr><td>{html.escape(item['id'])}</td><td>{html.escape(item['status'])}</td>"
        f"<td>{item['node_count']}</td><td>{item['risk_score']}</td><td>{html.escape(item['reason'])}</td></tr>"
        for item in status.get("releases", [])
    )
    page = f"""<!doctype html><html lang=zh-CN><meta charset=utf-8><meta name=viewport content='width=device-width,initial-scale=1'>
<title>订阅发布控制器</title><style>body{{font-family:system-ui;margin:0;background:#f5f7fb;color:#182033}}main{{max-width:1100px;margin:auto;padding:24px}}.cards{{display:flex;gap:12px;flex-wrap:wrap}}.card{{background:#fff;padding:14px 18px;border-radius:12px;box-shadow:0 2px 12px #15234a12}}table{{width:100%;background:#fff;border-collapse:collapse;margin-top:12px}}td,th{{padding:10px;border-bottom:1px solid #edf0f5;text-align:left}}th{{background:#eef3fb}}.ok{{color:#166534}}.warn{{color:#92400e}}</style>
<main><h1>订阅发布控制器</h1><p>控制器失效时只停止更新，OpenClash继续使用最后一个正常版本。</p>
<div class=cards><div class=card>模式<br><b>{html.escape(str(status.get('mode')))}</b></div><div class=card>状态<br><b class=ok>{html.escape(str(status.get('status')))}</b></div><div class=card>最新节点<br><b>{status.get('node_count',0)}</b></div><div class=card>风险分<br><b>{status.get('risk_score',0)}</b></div></div>
<h2>订阅源</h2><table><tr><th>来源</th><th>节点</th><th>最近成功</th><th>最近错误</th></tr>{rows}</table>
<h2>发布历史</h2><table><tr><th>版本</th><th>状态</th><th>节点</th><th>风险</th><th>原因</th></tr>{release_rows}</table></main></html>"""
    return page.encode("utf-8")


class Handler(BaseHTTPRequestHandler):
    server_version = "lan-center-subscription-controller/1"

    def log_message(self, _format: str, *_args: Any) -> None:
        return

    def send(self, code: int, content_type: str, payload: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.end_headers()
        self.wfile.write(payload)

    def do_POST(self) -> None:  # noqa: N802
        self.send(405, "application/json", b'{"status":"read_only"}')

    def do_GET(self) -> None:  # noqa: N802
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path == "/":
            self.send(200, "text/html; charset=utf-8", dashboard())
            return
        if parsed.path == "/health":
            health = latest_status()
            self.send(health_http_code(health), "application/json", json.dumps(health, ensure_ascii=False).encode())
            return
        if parsed.path == "/api/status":
            self.send(200, "application/json", json.dumps(latest_status(), ensure_ascii=False).encode())
            return
        match = re.fullmatch(r"/providers/([A-Za-z0-9_.-]{1,80})\.yaml", parsed.path)
        if match:
            query = urllib.parse.parse_qs(parsed.query)
            client = self.client_address[0]
            if not hmac.compare_digest(query.get("token", [""])[0], PUBLISH_TOKEN):
                self.send(403, "application/json", b'{"status":"forbidden"}')
                return
            if ALLOWED_PROVIDER_CLIENTS and client not in ALLOWED_PROVIDER_CLIENTS:
                self.send(403, "application/json", b'{"status":"client_forbidden"}')
                return
            manifest = current_manifest()
            if not manifest:
                self.send(503, "application/json", b'{"status":"no_release"}')
                return
            source = next((item for item in manifest.get("sources", []) if item["id"] == match.group(1)), None)
            if not source:
                self.send(404, "application/json", b'{"status":"unknown_provider"}')
                return
            path = RELEASES / manifest["release_id"] / source["file"]
            self.send(200, "text/yaml; charset=utf-8", path.read_bytes())
            return
        self.send(404, "application/json", b'{"status":"not_found"}')


def maintain_probation():
    path=DATA/"release-probation.json"
    if not path.exists() or (DATA.parent/"automation-freeze").exists():return
    def valid_job(d):
        if not (isinstance(d,dict) and isinstance(d.get("records"),dict) and valid_pointer(d.get("previous_pointer"))
                and type(d.get("started_at")) in (int,float) and math.isfinite(d["started_at"])
                and isinstance(d.get("baseline",{}),dict)):return False
        for rows in d["records"].values():
            if not isinstance(rows,list) or not all(valid_sample(row) for row in rows):return False
        for row in d.get("baseline",{}).values():
            if not isinstance(row,dict) or any(type(row.get(k,0)) not in (int,float) or not math.isfinite(row.get(k,0)) for k in ("samples","success_ratio","slow_ratio")):return False
        return True
    job,_=recover_document(path,valid_job)
    if job is None:raise ControllerError("probation_journal_invalid_frozen")
    pointer=json.loads(CURRENT_PATH.read_text())
    if pointer.get("release_id")!=job["release_id"] and not job.get("rollback_started"):
        atomic_json(DATA/"last-probation.json",dict(job,status="superseded",records={}))
        path.unlink();return
    try:
        observation=json.loads((DATA.parent/"autonomy-status.json").read_text()).get("observation",{})
        for business,row in observation.get("businesses",{}).items():
            if business not in {"gemini","chatgpt","default"}:continue
            records=job["records"].setdefault(business,[])
            if (job["started_at"]<=row.get("at",0)<=now() and now()-row["at"]<360
                and (not records or row["at"]>records[-1]["at"])):
                records.append(row);del records[:-30]
    except (OSError,ValueError,TypeError):pass
    verdict="rollback_regression" if job.get("rollback_started") else publication_verdict(job.get("baseline",{}),job["records"],job["started_at"],now())
    atomic_json(path,job);checkpoint(path,job)
    if verdict=="running":return
    if verdict=="rollback_regression":
        with exclusive(DATA.parent/"routing-owner.lock") as acquired:
            if not acquired:return
            try:
                quality=json.loads((DATA.parent/"route-quality.json").read_text())
                if quality.get("trial"):return
            except (OSError,ValueError,TypeError):return
            job["rollback_started"]=True;atomic_json(path,job);checkpoint(path,job)
            atomic_json(CURRENT_PATH,job["previous_pointer"])
            refresh_providers(load_sources())
            set_release_status(job["release_id"],"rolled_back","independent_probe_regression")
            meta_set("rejected_candidate_hash",job.get("candidate_hash",""));meta_set("rejected_until",str(now()+21600))
    elif verdict=="passed":
        if not valid_pointer(pointer):raise ControllerError("probation_candidate_checksum_failed")
        atomic_json(DATA/"verified-current.json",pointer);checkpoint(DATA/"verified-current.json",pointer)
        set_release_status(job["release_id"],"accepted","independent_probation_passed")
    else:set_release_status(job["release_id"],"unverified","insufficient_quality_or_coverage")
    summary={k:v for k,v in job.items() if k!="records"};summary.update(status=verdict,finished_at=now())
    atomic_json(DATA/"last-probation.json",summary)
    path.unlink();log("release_probation_complete",verdict)


def scheduler() -> None:
    while True:
        started = now()
        try:
            with LOCK:
                cycle()
        except Exception as exc:
            log("cycle_failed", str(exc), "error")
            atomic_json(HEALTH_PATH, {
                "status": "degraded", "mode": MODE, "epoch": now(), "reason": safe_detail(str(exc)),
                "current_release": (current_manifest() or {}).get("release_id", ""),
            }, 0o644)
        deadline=started+INTERVAL
        while now()<deadline:
            time.sleep(min(30,max(1,deadline-now())))
            try:
                maintain_probation()
                if repair_pointer():
                    with exclusive(DATA.parent/"routing-owner.lock") as acquired:
                        if acquired:
                            refresh_providers(load_sources())
                            (DATA/"recovery-refresh.json").unlink(missing_ok=True)
            except Exception as error:log("pointer_repair_deferred",type(error).__name__,"warning")


def self_test() -> None:
    global DATA, DB_PATH, SOURCES_FILE, RELEASES, CACHE, LOG_PATH, HEALTH_PATH, CURRENT_PATH, PENDING_PATH, HMAC_KEY, MODE, POST_PUBLISH_WAIT
    global refresh_providers, runtime_provider_counts, production_smoke
    with tempfile.TemporaryDirectory() as temporary:
        DATA = Path(temporary)
        DB_PATH = DATA / "controller.db"
        SOURCES_FILE = DATA / "sources.json"
        RELEASES = DATA / "releases"
        CACHE = DATA / "cache"
        LOG_PATH = DATA / "controller.log"
        HEALTH_PATH = DATA / "health.json"
        CURRENT_PATH = DATA / "current.json"
        PENDING_PATH = DATA / "publish-pending.json"
        HMAC_KEY = "self-test-key"
        SOURCES_FILE.write_text(json.dumps({"sources": [{
            "id": "a", "name": "A", "url": "https://example.invalid/sub", "provider_name": "A",
        }]}), encoding="utf-8")
        os.chmod(SOURCES_FILE, 0o600)
        assert load_sources()[0].source_id == "a"
        sample = {"name": "node", "type": "ss", "server": "example.com", "port": 443, "cipher": "aes-128-gcm", "password": "x"}
        parsed = normalized_nodes(parse_nodes(provider_yaml([sample])))
        assert len(parsed) == 1 and fingerprint(parsed[0]) == fingerprint(sample)
        encoded = base64.b64encode(provider_yaml([sample])).rstrip(b"=")
        assert len(normalized_nodes(parse_nodes(encoded))) == 1
        assert normalized_nodes([{"name": "剩余流量 10GB", "type": "ss", "server": "x", "port": 1}]) == []
        risk, reasons, hold = evaluate_risk(2, 10, [80.0], 1)
        assert hold and risk >= 100 and reasons
        candidate = "candidate-hash"
        assert not anomaly_confirmed(candidate, True)
        assert not anomaly_confirmed(candidate, True)
        assert anomaly_confirmed(candidate, True)
        assert health_http_code({"status": "degraded", "epoch": now(), "current_release": "known-good"}) == 200
        assert health_http_code({"status": "degraded", "epoch": now()}) == 503
        assert health_http_code({"status": "ok", "epoch": now() - INTERVAL * 3}) == 503
        atomic_json(CURRENT_PATH, {"release_id": "known-good", "published_at": now()})
        old_refresh = refresh_providers
        old_runtime_counts = runtime_provider_counts
        old_smoke = production_smoke
        old_mode = MODE
        old_wait = POST_PUBLISH_WAIT
        try:
            MODE = "automatic"
            POST_PUBLISH_WAIT = 0
            refresh_providers = lambda _sources: None
            runtime_provider_counts = lambda _sources: {"a": 1}
            production_smoke = lambda: (False, "forced_failure")
            ok, _detail = publish("bad-release", {}, load_sources())
            assert not ok
            assert json.loads(CURRENT_PATH.read_text())["release_id"] == "known-good"
            runtime_provider_counts = lambda _sources: {"a": 5}
            production_smoke = lambda: (True, "ok")
            bad_manifest = {"sources": [{"id": "a", "node_count": 10}]}
            ok, _detail = publish("runtime-filtered-release", bad_manifest, load_sources())
            assert not ok
            assert json.loads(CURRENT_PATH.read_text())["release_id"] == "known-good"
            atomic_json(PENDING_PATH, {
                "release_id": "interrupted",
                "previous_pointer": {"release_id": "known-good", "published_at": now()},
                "started_at": now(),
            })
            atomic_json(CURRENT_PATH, {"release_id": "interrupted", "published_at": now()})
            release_dir = RELEASES / "known-good"
            release_dir.mkdir(parents=True, exist_ok=True)
            atomic_json(release_dir / "manifest.json", {"release_id": "known-good"})
            assert recover_interrupted_publish()
            assert json.loads(CURRENT_PATH.read_text())["release_id"] == "known-good"
            assert not PENDING_PATH.exists()
        finally:
            MODE = old_mode
            POST_PUBLISH_WAIT = old_wait
            refresh_providers = old_refresh
            runtime_provider_counts = old_runtime_counts
            production_smoke = old_smoke
        with db() as conn:
            assert conn.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    print("subscription_controller_self_test=OK")


def _main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--self-test", action="store_true")
    parser.add_argument("--once", action="store_true")
    parser.add_argument("--serve-only", action="store_true")
    args = parser.parse_args()
    if args.self_test:
        self_test()
        return
    if MODE not in {"shadow", "automatic"}:
        raise SystemExit("SUBSCRIPTION_CONTROLLER_MODE must be shadow or automatic")
    if not PUBLISH_TOKEN or len(PUBLISH_TOKEN) < 24 or not HMAC_KEY or len(HMAC_KEY) < 24:
        raise SystemExit("subscription controller secrets must be at least 24 characters")
    DATA.mkdir(parents=True, exist_ok=True)
    RELEASES.mkdir(parents=True, exist_ok=True)
    CACHE.mkdir(parents=True, exist_ok=True)
    os.chmod(DATA, 0o700)
    with db() as conn:
        if conn.execute("PRAGMA integrity_check").fetchone()[0] != "ok":
            raise SystemExit("controller database integrity check failed")
    if args.serve_only:
        server=ThreadingHTTPServer(("0.0.0.0",HTTP_PORT),Handler)
        server.serve_forever();return
    if args.once:
        recover_interrupted_publish()
        cycle()
        return
    recover_interrupted_publish()
    repair_pointer()
    if current_manifest() is not None and not (DATA/"verified-current.json").exists():
        pointer=json.loads(CURRENT_PATH.read_text())
        atomic_json(DATA/"verified-current.json",pointer);checkpoint(DATA/"verified-current.json",pointer)
    __import__("sys").path.insert(0, "/local-subscription")
    from local_web import install
    install(globals())
    server = ThreadingHTTPServer(("0.0.0.0", HTTP_PORT), Handler)
    log("controller_started", f"mode={MODE} port={HTTP_PORT}")
    server_thread = threading.Thread(target=server.serve_forever, name="subscription-http", daemon=True)
    server_thread.start()
    scheduler()


def main():
    if "--self-test" in sys.argv:return _main()
    with exclusive(DATA/"controller-process.lock") as acquired:
        if not acquired:raise SystemExit("subscription_controller_already_running")
        _main()


if __name__ == "__main__":main()
