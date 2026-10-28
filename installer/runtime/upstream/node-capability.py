#!/usr/bin/env python3
"""Shadow-mode node capability and stability evaluator.

The evaluator selects only the isolated OpenClash probe group. It never changes
production business groups or iKuai rules. Results are stored in SQLite and
served by a read-only LAN dashboard.
"""

from __future__ import annotations

from collections import Counter
from contextlib import contextmanager
import hashlib
import json
import os
import re
import sqlite3
import statistics
import subprocess
import sys
from pathlib import Path
import tempfile
import threading
import time
import urllib.error
import urllib.parse
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any


os.umask(0o077)


API = os.getenv("OPENCLASH_API", "http://10.88.0.254:9090").rstrip("/")
API_SECRET = os.getenv("OPENCLASH_SECRET", "")
GROUP = os.getenv("CAPABILITY_GROUP", "🧪 节点能力检测")
PROXY = os.getenv("CAPABILITY_PROXY", "http://10.88.0.254:7895")
PROXY_AUTH = os.getenv("CAPABILITY_PROXY_AUTH", "")
PRODUCTION_PROXY = os.getenv("PROXY", "http://10.88.0.254:7893")
PRODUCTION_PROXY_AUTH = os.getenv("PROXY_AUTH", "")
DB_PATH = Path(os.getenv("CAPABILITY_DB", "/data/node-capability.db"))
HEALTH_PATH = Path(os.getenv("CAPABILITY_HEALTH", "/data/node-capability.health"))
LOG_PATH = Path(os.getenv("CAPABILITY_LOG", "/data/node-capability.log"))
MODE = os.getenv("CAPABILITY_MODE", "shadow")
PORT = int(os.getenv("CAPABILITY_PORT", "8081"))
NODE_INTERVAL = max(10, int(os.getenv("CAPABILITY_NODE_INTERVAL", "30")))
DISCOVERY_INTERVAL = max(60, int(os.getenv("CAPABILITY_DISCOVERY_INTERVAL", "600")))
BUSINESS_RECHECK = max(900, int(os.getenv("CAPABILITY_BUSINESS_RECHECK", "21600")))
HEALTHY_RECHECK = max(300, int(os.getenv("CAPABILITY_HEALTHY_RECHECK", "900")))
UNHEALTHY_RECHECK = max(120, int(os.getenv("CAPABILITY_UNHEALTHY_RECHECK", "300")))
SETTLE_SECONDS = max(1, int(os.getenv("CAPABILITY_SETTLE_SECONDS", "2")))
PROBE_TIMEOUT = max(5, int(os.getenv("CAPABILITY_PROBE_TIMEOUT", "12")))
GENERAL_ATTEMPTS = max(2, int(os.getenv("CAPABILITY_GENERAL_ATTEMPTS", "2")))
STALE_MULTIPLIER = max(2, int(os.getenv("CAPABILITY_STALE_MULTIPLIER", "2")))
ROUTE_AUDIT_INTERVAL = max(120, int(os.getenv("ROUTE_AUDIT_INTERVAL", "300")))

GROUP_TYPES = {
    "Selector", "URLTest", "Fallback", "LoadBalance", "Compatible", "Direct",
    "Reject", "RejectDrop", "Pass", "PassRule",
}

GENERAL_PROBES = (
    ("gstatic", "https://www.gstatic.com/generate_204", "GET", {204}, None),
    ("cloudflare", "https://cp.cloudflare.com/generate_204", "GET", {204}, None),
    ("apple", "https://www.apple.com/library/test/success.html", "GET", {200}, None),
)

BUSINESS_PROBES = (
    ("chatgpt", "https://chatgpt.com/backend-api/codex/responses", "POST", {400, 401}, "json"),
    ("gemini", "https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta", "GET", {200}, "json"),
    ("claude", "https://claude.ai/", "GET", {200, 301, 302}, None),
    ("netflix", "https://www.netflix.com/", "GET", {200, 301, 302}, None),
    ("youtube", "https://www.youtube.com/generate_204", "GET", {204}, None),
    ("disney", "https://www.disneyplus.com/", "GET", {200, 301, 302}, None),
    ("github", "https://github.com/robots.txt", "GET", {200}, "text/plain"),
    ("telegram", "https://api.telegram.org/", "GET", {200, 301, 302}, None),
)

BUSINESS_LABELS = {
    "chatgpt": "ChatGPT", "gemini": "Gemini", "claude": "Claude",
    "netflix": "Netflix", "youtube": "YouTube", "disney": "Disney+",
    "github": "GitHub", "telegram": "Telegram",
}

ROUTE_AUDITS = (
    ("amd_cn", "domestic", "https://developer.amd.com.cn/radeon/tokenfactory", "GET", {200, 301, 302}, None),
    ("tuya_cn", "domestic", "https://www.tuya.com/cn/", "GET", {200, 301, 302}, None),
    ("google", "overseas", "https://www.gstatic.com/generate_204", "GET", {204}, None),
    ("chatgpt", "business", "https://chatgpt.com/backend-api/codex/responses", "POST", {400, 401}, "json"),
    ("gemini", "business", "https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta", "GET", {200}, "json"),
    ("github", "developer", "https://github.com/robots.txt", "GET", {200}, "text/plain"),
)

ROUTE_LABELS = {
    "amd_cn": "AMD中国", "tuya_cn": "涂鸦中国", "google": "Google",
    "chatgpt": "ChatGPT", "gemini": "Gemini", "github": "GitHub",
}

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  node_type TEXT NOT NULL,
  fingerprint TEXT,
  provider TEXT NOT NULL DEFAULT '',
  first_seen INTEGER NOT NULL,
  last_seen INTEGER NOT NULL,
  active INTEGER NOT NULL DEFAULT 1
);
CREATE TABLE IF NOT EXISTS probe_results (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  node_id TEXT NOT NULL,
  probe TEXT NOT NULL,
  business TEXT NOT NULL,
  success INTEGER NOT NULL,
  http_code INTEGER NOT NULL,
  latency_ms INTEGER NOT NULL,
  content_type TEXT NOT NULL,
  error TEXT NOT NULL,
  error_category TEXT NOT NULL DEFAULT '',
  created_at INTEGER NOT NULL,
  FOREIGN KEY(node_id) REFERENCES nodes(id)
);
CREATE INDEX IF NOT EXISTS idx_probe_results_node_time
  ON probe_results(node_id, created_at DESC);
CREATE TABLE IF NOT EXISTS capabilities (
  node_id TEXT NOT NULL,
  business TEXT NOT NULL,
  status TEXT NOT NULL,
  score REAL NOT NULL,
  last_success INTEGER,
  last_failure INTEGER,
  last_checked INTEGER NOT NULL,
  consecutive_success INTEGER NOT NULL DEFAULT 0,
  consecutive_failure INTEGER NOT NULL DEFAULT 0,
  reason TEXT NOT NULL DEFAULT '',
  confidence REAL NOT NULL DEFAULT 0,
  PRIMARY KEY(node_id, business),
  FOREIGN KEY(node_id) REFERENCES nodes(id)
);
CREATE TABLE IF NOT EXISTS health_scores (
  node_id TEXT PRIMARY KEY,
  score REAL NOT NULL,
  state TEXT NOT NULL,
  general_success_ratio REAL NOT NULL,
  latency_ms REAL NOT NULL,
  jitter_ms REAL NOT NULL,
  confidence REAL NOT NULL DEFAULT 0,
  fresh_until INTEGER NOT NULL DEFAULT 0,
  updated_at INTEGER NOT NULL,
  FOREIGN KEY(node_id) REFERENCES nodes(id)
);
CREATE TABLE IF NOT EXISTS selection_state (
  business TEXT PRIMARY KEY,
  node_id TEXT,
  selected_at INTEGER,
  last_verified INTEGER,
  mode TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  level TEXT NOT NULL,
  event TEXT NOT NULL,
  node_id TEXT,
  detail TEXT NOT NULL,
  created_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS scheduler_state (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL,
  updated_at INTEGER NOT NULL
);
CREATE TABLE IF NOT EXISTS egress_observations (
  node_id TEXT PRIMARY KEY,
  country TEXT NOT NULL DEFAULT '',
  colo TEXT NOT NULL DEFAULT '',
  ip_hash TEXT NOT NULL DEFAULT '',
  changed_count INTEGER NOT NULL DEFAULT 0,
  last_checked INTEGER NOT NULL,
  FOREIGN KEY(node_id) REFERENCES nodes(id)
);
CREATE TABLE IF NOT EXISTS probe_schedule (
 node_id TEXT NOT NULL,business TEXT NOT NULL,record_json TEXT NOT NULL,
 PRIMARY KEY(node_id,business)
);
CREATE TABLE IF NOT EXISTS route_audits (
  probe TEXT PRIMARY KEY,
  category TEXT NOT NULL,
  status TEXT NOT NULL,
  http_code INTEGER NOT NULL,
  latency_ms INTEGER NOT NULL,
  reason TEXT NOT NULL DEFAULT '',
  consecutive_success INTEGER NOT NULL DEFAULT 0,
  consecutive_failure INTEGER NOT NULL DEFAULT 0,
  last_checked INTEGER NOT NULL
);
"""


def now() -> int:
    return int(time.time())


def node_id(identity: str) -> str:
    return hashlib.sha256(identity.encode("utf-8")).hexdigest()[:16]


def log(message: str) -> None:
    LOG_PATH.parent.mkdir(parents=True, exist_ok=True)
    stamp = time.strftime("%F %T")
    with LOG_PATH.open("a", encoding="utf-8") as stream:
        stream.write(f"{stamp} {message}\n")
    LOG_PATH.chmod(0o600)
    if LOG_PATH.stat().st_size > 5 * 1024 * 1024:
        rotated = LOG_PATH.with_suffix(LOG_PATH.suffix + ".1")
        rotated.unlink(missing_ok=True)
        LOG_PATH.replace(rotated)


def atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(path.name + f".tmp.{os.getpid()}")
    temporary.write_text(json.dumps(payload, ensure_ascii=False), encoding="utf-8")
    temporary.replace(path)
    path.chmod(0o600)


def db_connect() -> sqlite3.Connection:
    connection = sqlite3.connect(DB_PATH, timeout=15)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    return connection


@contextmanager
def db_session():
    connection = db_connect()
    try:
        yield connection
        connection.commit()
    finally:
        connection.close()


def init_db() -> None:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    with db_session() as connection:
        connection.executescript(SCHEMA)
        migrations = {
            "nodes": {
                "fingerprint": "TEXT",
                "provider": "TEXT NOT NULL DEFAULT ''",
            },
            "probe_results": {
                "error_category": "TEXT NOT NULL DEFAULT ''",
            },
            "capabilities": {
                "reason": "TEXT NOT NULL DEFAULT ''",
                "confidence": "REAL NOT NULL DEFAULT 0",
            },
            "health_scores": {
                "confidence": "REAL NOT NULL DEFAULT 0",
                "fresh_until": "INTEGER NOT NULL DEFAULT 0",
            },
        }
        for table, columns in migrations.items():
            existing = {
                row["name"] for row in connection.execute(f"PRAGMA table_info({table})")
            }
            for column, definition in columns.items():
                if column not in existing:
                    connection.execute(f"ALTER TABLE {table} ADD COLUMN {column} {definition}")
    DB_PATH.chmod(0o600)


def api_request(path: str, method: str = "GET", body: dict[str, Any] | None = None) -> Any:
    data = None if body is None else json.dumps(body).encode("utf-8")
    request = urllib.request.Request(
        f"{API}{path}",
        data=data,
        method=method,
        headers={
            "Authorization": f"Bearer {API_SECRET}",
            "Content-Type": "application/json",
        },
    )
    with urllib.request.urlopen(request, timeout=15) as response:
        payload = response.read()
    return json.loads(payload) if payload else None


def discover_nodes() -> list[dict[str, str]]:
    encoded = urllib.parse.quote(GROUP, safe="")
    group = api_request(f"/proxies/{encoded}")
    all_proxies = api_request("/proxies").get("proxies", {})
    # Mihomo /proxies often omits provider-name; derive provenance from providers.
    providers = api_request("/providers/proxies").get("providers", {})
    by_name = {}
    for provider_name, definition in providers.items():
        if definition.get("vehicleType") not in {"HTTP", "File"}:
            continue
        for entry in definition.get("proxies", []):
            by_name.setdefault(entry.get("name"), provider_name)
    discovered = []
    identities={}
    try:
        import subscription_impl as release
        manifest=release.current_manifest() or {}
        for item in manifest.get('sources',[]):
            raw=(release.RELEASES/manifest['release_id']/item['file']).read_bytes()
            for node in release.parse_nodes(raw):identities[(item.get('provider_name',item['id']),node['name'])]=release.fingerprint(node)
    except Exception:pass
    for name in group.get("all", []):
        proxy = all_proxies.get(name, {})
        proxy_type = str(proxy.get("type", "Unknown"))
        if name in {"DIRECT", "REJECT", "REJECT-DROP", "PASS", GROUP}:
            continue
        if proxy_type in GROUP_TYPES:
            continue
        provider = str(proxy.get("provider-name") or by_name.get(name) or "")
        fingerprint = identities.get((provider,name)) or str(proxy.get("id") or "")
        identity = f"mihomo:{fingerprint}" if fingerprint else f"name:{name}"
        discovered.append({
            "id": node_id(identity), "name": name, "type": proxy_type,
            "fingerprint": fingerprint, "provider": provider,
        })
    return discovered


def sync_nodes(nodes: list[dict[str, str]]) -> list[dict[str, str]]:
    epoch = now()
    with db_session() as connection:
        connection.execute("UPDATE nodes SET active=0")
        for entry in nodes:
            existing = None
            if entry["fingerprint"]:
                existing = connection.execute(
                    "SELECT id FROM nodes WHERE fingerprint=? ORDER BY last_seen DESC LIMIT 1",
                    (entry["fingerprint"],),
                ).fetchone()
            if existing is None:
                existing = connection.execute(
                    """SELECT id FROM nodes
                       WHERE name=? AND (fingerprint IS NULL OR fingerprint='')
                       ORDER BY last_seen DESC LIMIT 1""",
                    (entry["name"],),
                ).fetchone()
            if existing is not None:
                entry["id"] = existing["id"]
            connection.execute(
                """INSERT INTO nodes(id,name,node_type,fingerprint,provider,first_seen,last_seen,active)
                   VALUES(?,?,?,?,?,?,?,1)
                   ON CONFLICT(id) DO UPDATE SET
                     name=excluded.name,node_type=excluded.node_type,
                     fingerprint=excluded.fingerprint,provider=excluded.provider,
                     last_seen=excluded.last_seen,active=1""",
                (entry["id"], entry["name"], entry["type"], entry["fingerprint"],
                 entry["provider"], epoch, epoch),
            )
    return nodes


def select_probe_node(name: str) -> None:
    encoded = urllib.parse.quote(GROUP, safe="")
    api_request(f"/proxies/{encoded}", "PUT", {"name": name})
    selected = api_request(f"/proxies/{encoded}").get("now")
    if selected != name:
        raise RuntimeError("probe group selection readback failed")


def classify_failure(code: int, curl_code: int, content_type: str, hint_failed: bool = False) -> str:
    if hint_failed:
        return "unexpected_content"
    if code == 429:
        return "rate_limited"
    if code == 451:
        return "geo_restricted"
    if code == 403:
        return "access_denied"
    if code in {500, 502, 503, 504}:
        return "upstream_error"
    if curl_code in {5, 6}:
        return "dns_error"
    if curl_code in {7, 52, 56}:
        return "connect_error"
    if curl_code in {35, 51, 58, 59, 60, 77, 80, 82, 83, 90, 91}:
        return "tls_error"
    if curl_code == 28:
        return "timeout"
    if curl_code != 0:
        return "transport_error"
    if code == 0:
        return "no_response"
    if content_type.lower().startswith("text/html") and code in {403, 503}:
        return "challenge_page"
    return f"unexpected_http_{code}"


def curl_probe(url: str, method: str, expected: set[int], content_hint: str | None,
               proxy: str | None = None, proxy_auth: str | None = None) -> dict[str, Any]:
    proxy = PROXY if proxy is None else proxy
    proxy_auth = PROXY_AUTH if proxy_auth is None else proxy_auth
    command = [
        "curl", "-sS", "--max-time", str(PROBE_TIMEOUT), "--connect-timeout", "5",
        "-x", proxy, "-U", proxy_auth, "-o", "/dev/null",
        "-w", "%{http_code}\t%{time_total}\t%{content_type}",
        "-H", "User-Agent: Mozilla/5.0 node-capability-shadow",
    ]
    if method == "POST":
        command += ["-X", "POST", "-H", "Content-Type: application/json", "-d", "{}"]
    command.append(url)
    started = time.monotonic()
    try:
        completed = subprocess.run(command, capture_output=True, text=True, timeout=PROBE_TIMEOUT + 3, check=False)
        output = completed.stdout.strip().split("\t")
        code = int(output[0]) if output and output[0].isdigit() else 0
        elapsed = int(float(output[1]) * 1000) if len(output) > 1 else int((time.monotonic() - started) * 1000)
        content_type = output[2][:120] if len(output) > 2 else ""
        status_ok = completed.returncode == 0 and code in expected
        hint_failed = bool(status_ok and content_hint and content_hint.lower() not in content_type.lower())
        success = status_ok and not hint_failed
        if content_hint:
            success = success and content_hint.lower() in content_type.lower()
        category = "ok" if success else classify_failure(
            code, completed.returncode, content_type, hint_failed
        )
        error = "" if success else (completed.stderr.strip()[:240] or category)
        return {
            "success": success, "code": code, "latency": elapsed,
            "content_type": content_type, "error": error,
            "error_category": category, "curl_code": completed.returncode,
        }
    except subprocess.TimeoutExpired:
        return {
            "success": False, "code": 0, "latency": PROBE_TIMEOUT * 1000,
            "content_type": "", "error": "timeout", "error_category": "timeout",
            "curl_code": 28,
        }


def probe_egress() -> dict[str, str]:
    command = [
        "curl", "-sS", "--max-time", str(PROBE_TIMEOUT), "--connect-timeout", "5",
        "-x", PROXY, "-U", PROXY_AUTH,
        "-H", "User-Agent: Mozilla/5.0 node-capability-shadow",
        "https://www.cloudflare.com/cdn-cgi/trace",
    ]
    try:
        completed = subprocess.run(
            command, capture_output=True, text=True, timeout=PROBE_TIMEOUT + 3, check=False
        )
    except subprocess.TimeoutExpired:
        return {}
    if completed.returncode != 0:
        return {}
    values = {}
    for line in completed.stdout.splitlines():
        if "=" in line:
            key, value = line.split("=", 1)
            if key in {"ip", "loc", "colo"}:
                values[key] = value.strip()[:80]
    if not values.get("ip"):
        return {}
    return {
        "country": values.get("loc", ""),
        "colo": values.get("colo", ""),
        "ip_hash": hashlib.sha256(values["ip"].encode("utf-8")).hexdigest()[:16],
    }


def update_egress(connection: sqlite3.Connection, nid: str, epoch: int,
                  observation: dict[str, str]) -> None:
    previous = connection.execute(
        "SELECT * FROM egress_observations WHERE node_id=?", (nid,)
    ).fetchone()
    if previous is not None and epoch - previous["last_checked"] < BUSINESS_RECHECK:
        return
    if not observation:
        return
    changed = int(
        previous is not None
        and bool(previous["ip_hash"])
        and previous["ip_hash"] != observation["ip_hash"]
    )
    changed_count = (previous["changed_count"] if previous else 0) + changed
    connection.execute(
        """INSERT INTO egress_observations(node_id,country,colo,ip_hash,changed_count,last_checked)
           VALUES(?,?,?,?,?,?)
           ON CONFLICT(node_id) DO UPDATE SET
             country=excluded.country,colo=excluded.colo,ip_hash=excluded.ip_hash,
             changed_count=excluded.changed_count,last_checked=excluded.last_checked""",
        (nid, observation["country"], observation["colo"], observation["ip_hash"],
         changed_count, epoch),
    )


def record_result(connection: sqlite3.Connection, nid: str, probe: str, business: str,
                  result: dict[str, Any], epoch: int) -> None:
    connection.execute(
        """INSERT INTO probe_results
           (node_id,probe,business,success,http_code,latency_ms,content_type,error,error_category,created_at)
           VALUES(?,?,?,?,?,?,?,?,?,?)""",
        (nid, probe, business, int(result["success"]), result["code"], result["latency"],
         result["content_type"], result["error"], result.get("error_category", ""), epoch),
    )


def update_capability(connection: sqlite3.Connection, nid: str, business: str,
                      success: bool, score: float, epoch: int, reason: str = "", observed_at=None) -> None:
    previous = connection.execute(
        "SELECT * FROM capabilities WHERE node_id=? AND business=?", (nid, business)
    ).fetchone()
    consecutive_success = (previous["consecutive_success"] if previous and success else 0) + int(success)
    consecutive_failure = (previous["consecutive_failure"] if previous and not success else 0) + int(not success)
    last_success = epoch if success else (previous["last_success"] if previous else None)
    last_failure = epoch if not success else (previous["last_failure"] if previous else None)
    from health_policy import transition
    prior=connection.execute("SELECT record_json FROM probe_schedule WHERE node_id=? AND business=?",(nid,business)).fetchone()
    state=json.loads(prior[0]) if prior else {'status':previous['status'] if previous else 'unknown',
        'success_streak':previous['consecutive_success'] if previous else 0,
        'failure_streak':previous['consecutive_failure'] if previous and previous['consecutive_failure']>=3 else 0,
        'cooldown_until':(previous['last_failure'] or 0)+3600 if previous and previous['consecutive_failure']>=3 else 0,
        'last_observation':previous['last_checked'] if previous else 0}
    state=transition(state,success,epoch,reason,observed_at)
    if state.get('status')=='available' and not state.get('detector_error'):
        state['next_due']=epoch+(HEALTHY_RECHECK if business=='general' else BUSINESS_RECHECK)
    connection.execute("INSERT INTO probe_schedule VALUES(?,?,?) ON CONFLICT(node_id,business) DO UPDATE SET record_json=excluded.record_json",(nid,business,json.dumps(state)))
    status=state.get('status','checking')
    consecutive_success=state.get('success_streak',0);consecutive_failure=state.get('failure_streak',0)
    if state.get('detector_error'):
        return
    sample_count = connection.execute(
        "SELECT COUNT(*) AS total FROM probe_results WHERE node_id=? AND business=? AND created_at>=?",
        (nid, business, epoch - 7 * 86_400),
    ).fetchone()["total"]
    streak = consecutive_success if success else consecutive_failure
    confidence = min(100.0, 25.0 + min(sample_count, 10) * 5.0 + min(streak, 5) * 5.0)
    connection.execute(
        """INSERT INTO capabilities
           (node_id,business,status,score,last_success,last_failure,last_checked,
            consecutive_success,consecutive_failure,reason,confidence)
           VALUES(?,?,?,?,?,?,?,?,?,?,?)
           ON CONFLICT(node_id,business) DO UPDATE SET
             status=excluded.status,score=excluded.score,last_success=excluded.last_success,
             last_failure=excluded.last_failure,last_checked=excluded.last_checked,
             consecutive_success=excluded.consecutive_success,
             consecutive_failure=excluded.consecutive_failure,
             reason=excluded.reason,confidence=excluded.confidence""",
        (nid, business, status, score, last_success, last_failure, epoch,
         consecutive_success, consecutive_failure, reason, confidence),
    )


def due_businesses(connection: sqlite3.Connection, nid: str, epoch: int) -> list[tuple[Any, ...]]:
    due = []
    for definition in BUSINESS_PROBES:
        business = definition[0]
        row = connection.execute(
            "SELECT last_checked FROM capabilities WHERE node_id=? AND business=?", (nid, business)
        ).fetchone()
        policy=connection.execute('SELECT record_json FROM probe_schedule WHERE node_id=? AND business=?',(nid,business)).fetchone()
        scheduled=json.loads(policy[0]) if policy else None
        if row is None or (scheduled is not None and scheduled.get('next_due',0)<=epoch) or (scheduled is None and epoch - row["last_checked"] >= BUSINESS_RECHECK):
            due.append(definition)
    return due


def update_route_audit(connection: sqlite3.Connection, probe: str, category: str,
                       result: dict[str, Any], epoch: int) -> None:
    previous = connection.execute(
        "SELECT * FROM route_audits WHERE probe=?", (probe,)
    ).fetchone()
    success = bool(result["success"])
    consecutive_success = (previous["consecutive_success"] if previous and success else 0) + int(success)
    consecutive_failure = (previous["consecutive_failure"] if previous and not success else 0) + int(not success)
    status = "available" if success else ("checking" if consecutive_failure < 2 else "unavailable")
    connection.execute(
        """INSERT INTO route_audits
           (probe,category,status,http_code,latency_ms,reason,consecutive_success,
            consecutive_failure,last_checked)
           VALUES(?,?,?,?,?,?,?,?,?)
           ON CONFLICT(probe) DO UPDATE SET
             category=excluded.category,status=excluded.status,http_code=excluded.http_code,
             latency_ms=excluded.latency_ms,reason=excluded.reason,
             consecutive_success=excluded.consecutive_success,
             consecutive_failure=excluded.consecutive_failure,last_checked=excluded.last_checked""",
        (probe, category, status, result["code"], result["latency"],
         result.get("error_category", "ok"), consecutive_success, consecutive_failure, epoch),
    )


def route_audit_scheduler() -> None:
    if not PRODUCTION_PROXY_AUTH:
        log("status=warning child=route_audit reason=missing_proxy_auth")
        return
    while True:
        started = now()
        for probe, category, url, method, expected, content_hint in ROUTE_AUDITS:
            try:
                result = curl_probe(
                    url, method, expected, content_hint,
                    proxy=PRODUCTION_PROXY, proxy_auth=PRODUCTION_PROXY_AUTH,
                )
                with db_session() as connection:
                    update_route_audit(connection, probe, category, result, now())
            except Exception as error:
                log(f"status=error child=route_audit probe={probe} reason={type(error).__name__}")
            time.sleep(2)
        log(f"status=complete child=route_audit duration={now() - started}")
        time.sleep(max(10, ROUTE_AUDIT_INTERVAL - (now() - started)))


def calculate_score(connection: sqlite3.Connection, nid: str,
                    current_general: list[dict[str, Any]]) -> tuple[float, str, float, float, float, float]:
    recent = connection.execute(
        """SELECT success,latency_ms FROM probe_results
           WHERE node_id=? AND business='general' ORDER BY created_at DESC LIMIT 30""", (nid,)
    ).fetchall()
    recent_rate = sum(row["success"] for row in recent) / len(recent) if recent else 0.0
    day_ago = now() - 86_400
    uptime = connection.execute(
        """SELECT AVG(success) AS rate FROM probe_results
           WHERE node_id=? AND business='general' AND created_at>=?""", (nid, day_ago)
    ).fetchone()["rate"]
    uptime = float(uptime) if uptime is not None else recent_rate

    successful_latencies = [entry["latency"] for entry in current_general if entry["success"]]
    latency = statistics.mean(successful_latencies) if successful_latencies else 0.0
    jitter = statistics.pstdev(successful_latencies) if len(successful_latencies) > 1 else 0.0
    current_ratio = sum(entry["success"] for entry in current_general) / len(current_general)
    target_results: dict[str, list[bool]] = {}
    for entry in current_general:
        target_results.setdefault(entry["probe"], []).append(bool(entry["success"]))
    target_ratio = sum(all(attempts) for attempts in target_results.values()) / len(target_results)

    capabilities = connection.execute(
        """SELECT status,last_checked,confidence FROM capabilities
           WHERE node_id=? AND business!='general'""", (nid,)
    ).fetchall()
    fresh_capabilities = [
        row for row in capabilities if now() - row["last_checked"] <= BUSINESS_RECHECK * STALE_MULTIPLIER
    ]
    business_rate = (
        sum(row["status"] == "available" for row in fresh_capabilities) / len(fresh_capabilities)
        if fresh_capabilities else 0.5
    )

    quality = max(0.0, 1.0 - min(jitter, 1000.0) / 1000.0)
    latency_quality = max(0.0, min(1.0, (1500.0 - latency) / 1200.0)) if successful_latencies else 0.0
    score = round(
        business_rate * 50.0
        + recent_rate * 20.0
        + quality * current_ratio * 15.0
        + latency_quality * 10.0
        + uptime * 5.0,
        1,
    )

    general_capability = connection.execute(
        "SELECT consecutive_failure FROM capabilities WHERE node_id=? AND business='general'", (nid,)
    ).fetchone()
    consecutive_failure = general_capability["consecutive_failure"] if general_capability else 0
    general_confidence = min(1.0, len(recent) / 18.0)
    business_confidence = (
        sum(row["confidence"] for row in fresh_capabilities) / len(fresh_capabilities) / 100.0
        if fresh_capabilities else 0.0
    )
    confidence = round(100.0 * (general_confidence * 0.6 + business_confidence * 0.4), 1)
    policy=connection.execute("SELECT record_json FROM probe_schedule WHERE node_id=? AND business='general'",(nid,)).fetchone()
    policy=json.loads(policy[0]) if policy else {}
    if policy and policy.get('status')!='available':
        state='unavailable' if policy.get('status')=='unavailable' else 'cooling'
    elif fresh_capabilities and business_rate < 1.0:
        state = "business-limited"
    elif score >= 85:
        state = "healthy"
    else:
        state = "degraded"
    return score, state, current_ratio, float(latency), float(jitter), confidence


def probe_node(entry: dict[str, str]) -> dict[str, Any]:
    started = time.monotonic()
    nid = entry["id"]
    epoch = now()

    from clash_measurement import measure
    with db_session() as connection:
        previous=connection.execute("SELECT record_json FROM probe_schedule WHERE node_id=? AND business='general'",(nid,)).fetchone()
    force=previous is not None and json.loads(previous[0]).get('status')!='available'
    result=measure(api_request,entry,now(),force=force)
    epoch=now()
    from clash_measurement import suspect_batch,pause_batch
    if suspect_batch(entry,result,epoch):
        with db_session() as connection:
            reference=connection.execute("SELECT n.id,n.name,n.provider FROM nodes n JOIN capabilities c ON c.node_id=n.id WHERE n.active=1 AND c.business='general' AND c.status='available' AND n.id!=? ORDER BY c.last_success DESC LIMIT 1",(nid,)).fetchone()
        confirmation=measure(api_request,dict(reference),epoch,force=True) if reference else {'success':False}
        if not confirmation['success']:
            pause_batch(epoch);result.update(error_category='detector_batch_failure',success=False)
    result.setdefault('probe','clash_https');result.setdefault('code',0)
    result.setdefault('content_type','');result.setdefault('error',result.get('error_category','unknown'))
    if result.get('error_category','').startswith('detector_'):
        with db_session() as connection:
            update_capability(connection,nid,'general',False,0,epoch,result['error_category'])
        return {'state':'checking','score':0,'confidence':0,'duration':round(time.monotonic()-started,3),'phase':'detector_wait'}
    general_results=[result]
    general_result=result
    with db_session() as connection:
        for result in general_results:
            stamp=int(result.get('observed_at',epoch))
            if not connection.execute("SELECT 1 FROM probe_results WHERE node_id=? AND business='general' AND probe=? AND created_at=? LIMIT 1",(nid,result['probe'],stamp)).fetchone():
                record_result(connection, nid, result["probe"], "general", result, stamp)
        general_success=bool(general_results[0]['success'])
        target_successes=int(general_success)
        general_failures = [
            result.get("error_category", "unknown")
            for result in general_results if not result["success"]
        ]
        general_reason = "ok" if general_success else (
            Counter(general_failures).most_common(1)[0][0] if general_failures else "unknown"
        )
        update_capability(connection, nid, "general", general_success,
                          100.0 * target_successes, epoch,
                          general_reason, int(result.get('observed_at',epoch)))

        remaining_unknown = connection.execute(
            """SELECT COUNT(*) AS total FROM nodes n
               LEFT JOIN health_scores h ON h.node_id=n.id
               WHERE n.active=1 AND h.node_id IS NULL AND n.id!=?""",
            (nid,),
        ).fetchone()["total"]
        deep_allowed = remaining_unknown == 0
        definitions = due_businesses(connection, nid, epoch) if general_success and deep_allowed else []
        previous_egress = connection.execute(
            "SELECT last_checked FROM egress_observations WHERE node_id=?", (nid,)
        ).fetchone()
        egress_due = general_success and deep_allowed and (
            previous_egress is None or epoch-previous_egress["last_checked"] >= BUSINESS_RECHECK)

    # External requests must never run while holding a SQLite write transaction.
    # Only business/body/egress checks need the isolated selector. Basic delay
    # came from Clash's actual node object and never changed a selector.
    if definitions or egress_due:
        select_probe_node(entry['name']);time.sleep(min(SETTLE_SECONDS,.3))
    observation = probe_egress() if egress_due else {}
    business_results = [
        (business, curl_probe(url, method, expected, content_hint))
        for business, url, method, expected, content_hint in definitions
    ]
    with db_session() as connection:
        update_egress(connection, nid, epoch, observation)
        for business, result in business_results:
            record_result(connection, nid, business, business, result, epoch)
            update_capability(connection, nid, business, result["success"],
                              100.0 if result["success"] else 0.0, epoch,
                              result.get("error_category", "unknown"))

        score, state, ratio, latency, jitter, confidence = calculate_score(
            connection, nid, general_results
        )
        record=connection.execute("SELECT record_json FROM probe_schedule WHERE node_id=? AND business='general'",(nid,)).fetchone()
        schedule=json.loads(record[0]) if record else {}
        schedule.update(latency_source=general_result.get('origin','unknown'),latency_sample_at=general_result.get('observed_at',epoch))
        connection.execute("UPDATE probe_schedule SET record_json=? WHERE node_id=? AND business='general'",(json.dumps(schedule),nid))
        fresh_until = epoch + (
            HEALTHY_RECHECK if state in {"healthy", "degraded", "business-limited"}
            else UNHEALTHY_RECHECK
        )
        connection.execute(
            """INSERT INTO health_scores
               (node_id,score,state,general_success_ratio,latency_ms,jitter_ms,confidence,fresh_until,updated_at)
               VALUES(?,?,?,?,?,?,?,?,?)
               ON CONFLICT(node_id) DO UPDATE SET
                 score=excluded.score,state=excluded.state,
                 general_success_ratio=excluded.general_success_ratio,
                 latency_ms=excluded.latency_ms,jitter_ms=excluded.jitter_ms,
                 confidence=excluded.confidence,fresh_until=excluded.fresh_until,
                 updated_at=excluded.updated_at""",
            (nid, score, state, ratio, latency, jitter, confidence, fresh_until, epoch),
        )
        connection.execute(
            "INSERT INTO events(level,event,node_id,detail,created_at) VALUES(?,?,?,?,?)",
            ("info", "probe_complete", nid, f"state={state} score={score}", epoch),
        )
        connection.execute(
            "DELETE FROM probe_results WHERE created_at < ?", (epoch - 30 * 86_400,)
        )
        connection.execute(
            "DELETE FROM events WHERE created_at < ?", (epoch - 30 * 86_400,)
        )
    duration = round(time.monotonic() - started, 3)
    log(
        f"status=probed node_hash={nid[:12]} mode={MODE} state={state} "
        f"phase={'deep' if deep_allowed else 'quick'} score={score} "
        f"confidence={confidence} duration={duration}"
    )
    return {
        "state": state, "score": score, "confidence": confidence,
        "duration": duration, "phase": "deep" if deep_allowed else "quick",
    }


def scheduler_value(connection: sqlite3.Connection, key: str, default: str = "") -> str:
    row = connection.execute(
        "SELECT value FROM scheduler_state WHERE key=?", (key,)
    ).fetchone()
    return row["value"] if row else default


def set_scheduler_value(connection: sqlite3.Connection, key: str, value: Any) -> None:
    connection.execute(
        """INSERT INTO scheduler_state(key,value,updated_at) VALUES(?,?,?)
           ON CONFLICT(key) DO UPDATE SET value=excluded.value,updated_at=excluded.updated_at""",
        (key, str(value), now()),
    )


def choose_candidate(nodes: list[dict[str, str]], retry_after: dict[str, int]) -> dict[str, str] | None:
    epoch = now()
    from clash_measurement import batch_paused
    if batch_paused(epoch):return None
    node_map = {entry["id"]: entry for entry in nodes}
    with db_session() as connection:
        rows = connection.execute(
            """SELECT n.id,n.name,h.state,h.fresh_until,h.updated_at,COALESCE(c.consecutive_failure,0) AS failures
               FROM nodes n LEFT JOIN health_scores h ON h.node_id=n.id
               LEFT JOIN capabilities c ON c.node_id=n.id AND c.business='general'
               WHERE n.active=1"""
        ).fetchall()
    eligible = [row for row in rows if retry_after.get(row["id"], 0) <= epoch]
    unknown = sorted(
        (row for row in eligible if row["updated_at"] is None),
        key=lambda row: row["name"],
    )
    if unknown:
        return node_map.get(unknown[0]["id"])
    from health_policy import due
    with db_session() as connection:
        schedules={};business_due={}
        for r in connection.execute('SELECT node_id,business,record_json FROM probe_schedule'):
            value=json.loads(r[2])
            if r[1]=='general':schedules[r[0]]=value
            else:business_due[r[0]]=min(business_due.get(r[0],float('inf')),due(value,epoch))
    def deadline(row):
        if row['id'] in schedules:
            r=schedules[row['id']]
            if r.get('status')!='available' or r.get('detector_error'):return due(r,epoch)
        return min(int(row['fresh_until'] or 0),business_due.get(row['id'],float('inf')))
    due=sorted((row for row in eligible if deadline(row)<=epoch),key=lambda row:(deadline(row),int(row["updated_at"] or 0),row["name"]))
    return node_map.get(due[0]["id"]) if due else None


def progress_snapshot(active_nodes: int, ema_seconds: float, probed_boot: int,
                      last_probe_epoch: int, status: str = "ok", detail: str = "shadow_evaluation") -> dict[str, Any]:
    with db_session() as connection:
        evaluated = connection.execute(
            """SELECT COUNT(*) AS total FROM nodes n JOIN health_scores h ON h.node_id=n.id
               WHERE n.active=1"""
        ).fetchone()["total"]
        total_probes = int(scheduler_value(connection, "total_probes", "0") or 0)
    unknown = max(0, active_nodes - evaluated)
    with db_session() as connection:
        expired=connection.execute("SELECT count(*) FROM nodes n JOIN health_scores h ON h.node_id=n.id WHERE n.active=1 AND h.fresh_until<?",(now(),)).fetchone()[0]
    eta = int((unknown+expired) * max(ema_seconds + NODE_INTERVAL, 1.0))
    return {
        "status": status, "detail": detail, "mode": MODE,
        "active_nodes": active_nodes, "evaluated": evaluated, "unknown": unknown,
        "expired": expired, "fresh": max(0,evaluated-expired),
        "probed": probed_boot, "total_probes": total_probes,
        "ema_probe_seconds": round(ema_seconds, 2), "eta_seconds": eta,
        "last_probe_epoch": last_probe_epoch, "epoch": now(),
    }


def scheduler() -> None:
    from autonomy_store import exclusive
    with exclusive(DB_PATH.parent / "probe-scheduler.lock") as acquired:
        if not acquired:
            log("status=error reason=duplicate_probe_scheduler")
            return
        _scheduler()


def admission_scheduler() -> None:
    # A single separate lane tests unloaded nodes in its own native core. It
    # never owns the shared business probe selector, so slow onboarding cannot
    # stall current/backup business observations or create selector races.
    import admission_queue,subscription_impl
    while True:
        try:admission_queue.tick(subscription_impl)
        except Exception as error:log('status=admission_queue_error reason='+type(error).__name__)
        time.sleep(15)


def _scheduler() -> None:
    if MODE != "shadow":
        raise RuntimeError("only shadow mode is allowed in this release")
    if not API_SECRET or not PROXY_AUTH:
        raise RuntimeError("missing OpenClash or capability proxy credentials")

    nodes: list[dict[str, str]] = []
    last_discovery = 0
    last_local_generation = 0
    probed = 0
    quality = None
    if os.getenv("QUALITY_CONTROL_ENABLED", "0") == "1":
        from route_quality import Controller
        quality = Controller(api_request, status_payload)
    retry_after: dict[str, int] = {}
    quality_turns = 0
    with db_session() as connection:
        ema_seconds = float(scheduler_value(connection, "ema_probe_seconds", "15") or 15)
        last_probe_epoch = int(scheduler_value(connection, "last_probe_epoch", "0") or 0)
    while True:
        entry = None
        try:
            epoch = now()
            local_trigger = DB_PATH.parent / "local-discovery.json"
            local_generation = local_trigger.stat().st_mtime_ns if local_trigger.exists() else 0
            if not nodes or local_generation != last_local_generation or epoch - last_discovery >= DISCOVERY_INTERVAL:
                nodes = sync_nodes(discover_nodes())
                last_discovery = epoch
                last_local_generation = local_generation
                log(f"status=discovered active_nodes={len(nodes)} mode={MODE}")
            if not nodes:
                atomic_json(HEALTH_PATH, progress_snapshot(0, ema_seconds, probed, last_probe_epoch,
                            status="awaiting_sources", detail="等待订阅或自建节点；尚未具备代理业务能力"))
                # Idle sites don't poll the full router graph every ten seconds.
                # A local/public publication wakes discovery within one second.
                deadline = time.monotonic() + max(30, NODE_INTERVAL)
                while time.monotonic() < deadline:
                    time.sleep(1)
                    generation = local_trigger.stat().st_mtime_ns if local_trigger.exists() else 0
                    if generation != last_local_generation: break
                continue
            if quality is not None and quality_turns < 3:
                try:
                    quality_work = quality.tick()
                except Exception as error:
                    log(f"status=quality_error reason={type(error).__name__}")
                    quality.state["controller_error"] = type(error).__name__
                    quality.state["error_streak"] = quality.state.get("error_streak",0)+1
                    quality.save("quality_exception")
                    quality_work = False
                else:
                    quality.state.pop("controller_error",None)
                    quality.state["error_streak"]=0
                if quality_work:
                    quality_turns += 1
                    atomic_json(HEALTH_PATH, progress_snapshot(len(nodes), ema_seconds, probed, last_probe_epoch))
                    time.sleep(2)
                    continue
            quality_turns = 0
            entry = choose_candidate(nodes, retry_after)
            if entry is not None:
                result = probe_node(entry)
                probed += 1
                last_probe_epoch = now()
                ema_seconds = round(ema_seconds * 0.8 + float(result["duration"]) * 0.2, 3)
                retry_after.pop(entry["id"], None)
                with db_session() as connection:
                    total_probes = int(scheduler_value(connection, "total_probes", "0") or 0) + 1
                    set_scheduler_value(connection, "total_probes", total_probes)
                    set_scheduler_value(connection, "ema_probe_seconds", ema_seconds)
                    set_scheduler_value(connection, "last_node_id", entry["id"])
                    set_scheduler_value(connection, "last_probe_epoch", last_probe_epoch)
            atomic_json(
                HEALTH_PATH,
                progress_snapshot(len(nodes), ema_seconds, probed, last_probe_epoch),
            )
        except Exception as error:  # keep dashboard alive and retry without touching production
            detail = type(error).__name__
            log(f"status=error reason={detail}")
            if entry is not None:
                retry_after[entry["id"]] = now() + 60
            atomic_json(
                HEALTH_PATH,
                progress_snapshot(
                    len(nodes), ema_seconds, probed, last_probe_epoch,
                    status="error", detail=detail,
                ),
            )
        time.sleep(NODE_INTERVAL)


def status_payload() -> dict[str, Any]:
    epoch = now()
    with db_session() as connection:
        rows = connection.execute(
            """SELECT n.id,n.name,n.node_type,n.provider,n.last_seen,
                      COALESCE(h.score,0) AS score,COALESCE(h.state,'unknown') AS state,
                      COALESCE(h.general_success_ratio,0) AS general_success_ratio,
                      COALESCE(h.latency_ms,0) AS latency_ms,
                      COALESCE(h.jitter_ms,0) AS jitter_ms,
                      COALESCE(h.confidence,0) AS confidence,
                      COALESCE(h.fresh_until,0) AS fresh_until,
                      COALESCE(h.updated_at,0) AS updated_at
               FROM nodes n LEFT JOIN health_scores h ON h.node_id=n.id
               WHERE n.active=1 ORDER BY h.score DESC,n.name"""
        ).fetchall()
        capabilities = connection.execute(
            """SELECT c.node_id,c.business,c.status,c.last_checked,c.reason,c.confidence,
                      c.consecutive_success,c.consecutive_failure
               FROM capabilities c JOIN nodes n ON n.id=c.node_id WHERE n.active=1"""
        ).fetchall()
        egress = connection.execute(
            """SELECT e.* FROM egress_observations e JOIN nodes n ON n.id=e.node_id
               WHERE n.active=1"""
        ).fetchall()
        schedules={r[0]:json.loads(r[1]) for r in connection.execute("SELECT node_id,record_json FROM probe_schedule WHERE business='general'")}
        latency_values={r['id']:[v[0] for v in connection.execute("SELECT latency_ms FROM probe_results WHERE node_id=? AND probe='clash_https' AND success=1 ORDER BY created_at DESC LIMIT 30",(r['id'],))] for r in rows}
        route_audits = []
        for row in connection.execute(
            "SELECT * FROM route_audits ORDER BY category,probe"
        ).fetchall():
            item = dict(row)
            item["fresh"] = epoch - item["last_checked"] <= ROUTE_AUDIT_INTERVAL * 2
            if not item["fresh"]:
                item["status"] = "stale"
            route_audits.append(item)
    by_node: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = dict(row)
        item["capabilities"] = {}
        item["fresh"] = bool(item["fresh_until"] >= epoch)
        if item["updated_at"] and not item["fresh"]:
            item["state"] = "stale"
        item['health_schedule']=schedules.get(row['id'],{})
        item['latency_kind']='Clash HTTPS HEAD' if item['health_schedule'].get('latency_source') in ('clash_api','clash_history') else 'legacy_http'
        from health_policy import latency_summary
        item['latency_summary']=latency_summary(latency_values[row['id']])
        item["egress"] = {}
        by_node[row["id"]] = item
    for row in capabilities:
        if row["node_id"] in by_node:
            stale = epoch - row["last_checked"] > BUSINESS_RECHECK * STALE_MULTIPLIER
            by_node[row["node_id"]]["capabilities"][row["business"]] = {
                "status": "stale" if stale else row["status"],
                "last_checked": row["last_checked"], "reason": row["reason"],
                "confidence": row["confidence"],
                "consecutive_success": row["consecutive_success"],
                "consecutive_failure": row["consecutive_failure"],
            }
    for row in egress:
        if row["node_id"] in by_node:
            by_node[row["node_id"]]["egress"] = {
                "country": row["country"], "colo": row["colo"],
                "changed_count": row["changed_count"], "last_checked": row["last_checked"],
            }
    states: dict[str, int] = {}
    for item in by_node.values():
        states[item["state"]] = states.get(item["state"], 0) + 1
    business_summary = {}
    for business in BUSINESS_LABELS:
        counts = {"available": 0, "unavailable": 0, "stale": 0, "unknown": 0}
        for item in by_node.values():
            capability = item["capabilities"].get(business)
            key = capability["status"] if capability else "unknown"
            counts[key if key in counts else "unknown"] += 1
        business_summary[business] = counts
    try:
        progress = json.loads(HEALTH_PATH.read_text(encoding="utf-8"))
    except (OSError, ValueError, TypeError):
        progress = {"status": "starting"}
    return {
        "mode": MODE, "generated_at": epoch, "states": states,
        "business_labels": BUSINESS_LABELS, "business_summary": business_summary,
        "route_labels": ROUTE_LABELS, "route_audits": route_audits,
        "progress": progress, "nodes": list(by_node.values()),
    }


DASHBOARD = """<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>节点能力评估 V2</title>
<style>body{font-family:system-ui,sans-serif;margin:0;background:#f5f7fb;color:#182033}.wrap{max-width:1500px;margin:auto;padding:24px}h1{margin:0 0 8px}.hint,.muted{color:#64748b}.cards{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}.card{background:white;border-radius:12px;padding:12px 16px;box-shadow:0 2px 12px #15234a12;min-width:110px}.card b{font-size:22px;display:block}.toolbar{display:flex;gap:10px;flex-wrap:wrap;margin:14px 0}.toolbar input,.toolbar select{border:1px solid #cbd5e1;border-radius:8px;padding:9px;background:white}table{width:100%;border-collapse:collapse;background:white;margin-top:12px;border-radius:12px;overflow:hidden}th,td{padding:10px 9px;border-bottom:1px solid #edf0f5;text-align:left;vertical-align:top}th{background:#eef3fb;position:sticky;top:0}.pill{display:inline-block;border-radius:999px;padding:4px 8px;font-size:12px}.healthy,.available{background:#dcfce7;color:#166534}.degraded,.checking{background:#fef3c7;color:#92400e}.business-limited{background:#ffedd5;color:#9a3412}.cooling{background:#dbeafe;color:#1e40af}.unavailable{background:#fee2e2;color:#991b1b}.unknown,.stale{background:#e2e8f0;color:#475569}.caps{display:flex;gap:5px;flex-wrap:wrap}.section{margin-top:20px;font-size:17px;font-weight:650}@media(max-width:900px){.hide-sm{display:none}.wrap{padding:12px}th,td{padding:7px 5px;font-size:12px}}</style></head>
<body><div class=\"wrap\"><h1>节点能力与稳定性评估 V2</h1><div class=\"hint\">通用能力评估保持观察模式；Gemini、ChatGPT与默认境外出口由业务质量策略管理，是否启用及接管状态以下方卡片为准。页面每30秒刷新。</div>
<div class=\"cards\" id=\"progress\"></div><div class=\"section\">节点状态</div><div class=\"cards\" id=\"cards\"></div>
<div class=\"section\">业务能力概览</div><div class=\"cards\" id=\"business\"></div>
<div class=\"section\">当前生产分流验证</div><div class=\"cards\" id=\"routes\"></div>
<div class=\"toolbar\"><input id=\"query\" placeholder=\"搜索节点或提供商\"><select id=\"filter\"><option value=\"\">全部状态</option><option value=\"healthy\">健康</option><option value=\"business-limited\">业务受限</option><option value=\"unavailable\">不可用</option><option value=\"unknown\">未评估</option><option value=\"stale\">数据过期</option></select></div>
<table><thead><tr><th>节点</th><th>状态</th><th>评分/可信度</th><th>HTTPS耗时</th><th class=\"hide-sm\">出口</th><th>业务能力</th><th class=\"hide-sm\">最后检测</th></tr></thead><tbody id=\"rows\"></tbody></table></div>
<script>const labels={healthy:'健康',degraded:'降级','business-limited':'业务受限',cooling:'冷却观察',unavailable:'不可用',unknown:'未评估',stale:'数据过期'};let latest=null;
function pill(t,c,title=''){const s=document.createElement('span');s.className='pill '+c;s.textContent=t;s.title=title;return s}function td(tr){const x=document.createElement('td');tr.appendChild(x);return x}function card(root,value,label){const x=document.createElement('div');x.className='card';const b=document.createElement('b');b.textContent=value;x.append(b,document.createTextNode(label));root.appendChild(x)}
function render(d){latest=d;const p=document.querySelector('#progress');p.textContent='';const g=d.progress||{};card(p,(g.evaluated||0)+' / '+(g.active_nodes||d.nodes.length),'已评估');card(p,g.unknown||0,'未评估');card(p,g.eta_seconds?Math.ceil(g.eta_seconds/60)+' 分钟':'-','首轮预计剩余');card(p,g.ema_probe_seconds?g.ema_probe_seconds+' 秒':'-','单节点平均检测');
const cards=document.querySelector('#cards');cards.textContent='';Object.entries(d.states).forEach(([k,v])=>card(cards,v,labels[k]||k));
const business=document.querySelector('#business');business.textContent='';Object.entries(d.business_summary).forEach(([k,v])=>card(business,v.available+'/'+d.nodes.length,(d.business_labels[k]||k)+' 可用'));
const routes=document.querySelector('#routes');routes.textContent='';(d.route_audits||[]).forEach(a=>{const x=document.createElement('div');x.className='card';x.appendChild(pill(a.status==='available'?'正常':(a.status==='checking'?'复核中':'异常'),a.status,a.reason));x.appendChild(document.createElement('br'));x.appendChild(document.createTextNode((d.route_labels[a.probe]||a.probe)+' · '+a.latency_ms+' ms'));routes.appendChild(x)});
const q=document.querySelector('#query').value.toLowerCase();const f=document.querySelector('#filter').value;const rows=document.querySelector('#rows');rows.textContent='';d.nodes.filter(n=>(!f||n.state===f)&&(!q||(n.name+' '+n.provider).toLowerCase().includes(q))).forEach(n=>{const tr=document.createElement('tr');const name=td(tr);name.textContent=n.name;if(n.provider){const small=document.createElement('div');small.className='muted';small.textContent=n.provider;name.appendChild(small)}td(tr).appendChild(pill(labels[n.state]||n.state,n.state));td(tr).textContent=n.score.toFixed(1)+' / '+Math.round(n.confidence)+'%';td(tr).textContent=n.general_success_ratio>0?Math.round(n.latency_ms)+' ms':'未取得';const e=td(tr);e.className='hide-sm';e.textContent=n.egress.country?(n.egress.country+' / '+n.egress.colo):'-';const c=td(tr);c.className='caps';Object.entries(n.capabilities).filter(([k])=>k!=='general').forEach(([k,v])=>c.appendChild(pill(d.business_labels[k]||k,v.status,(v.reason||'')+' · 可信度 '+Math.round(v.confidence)+'%')));const u=td(tr);u.className='hide-sm';u.textContent=n.updated_at?new Date(n.updated_at*1000).toLocaleString():'-';rows.appendChild(tr)});}
async function load(){const d=await fetch('/api/nodes',{cache:'no-store'}).then(r=>r.json());render(d);try{const q=await fetch('/api/quality',{cache:'no-store'}).then(r=>r.json());const r=document.querySelector('#routes');Object.entries(q.businesses||{}).forEach(([k,v])=>{const m=v.metrics||{};const name={gemini:'Gemini',chatgpt:'ChatGPT',default:'默认境外出口'}[k]||k;const state=!q.fresh?'数据过期':v.manual_override?'手动接管':({normal:'正常',slow:'缓慢',down:'故障'}[v.status]||'评估中');card(r,state,name+' · 首次成功 '+Math.round((m.success_ratio||0)*100)+'% · 慢请求 '+Math.round((m.slow_ratio||0)*100)+'% · 中位 '+(m.median_ms||0)+'ms · '+(q.enabled?'自动优化':'观察中'))})}catch(e){}}document.querySelector('#query').addEventListener('input',()=>latest&&render(latest));document.querySelector('#filter').addEventListener('change',()=>latest&&render(latest));load().catch(()=>{});setInterval(()=>load().catch(()=>{}),30000);</script></body></html>"""


class Handler(BaseHTTPRequestHandler):
    def send_payload(self, code: int, content_type: str, payload: bytes) -> None:
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(payload)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Content-Security-Policy", "default-src 'self'; style-src 'unsafe-inline'; script-src 'unsafe-inline'")
        self.end_headers()
        self.wfile.write(payload)

    def do_GET(self) -> None:  # noqa: N802
        path = urllib.parse.urlparse(self.path).path
        if path == "/":
            self.send_payload(200, "text/html; charset=utf-8", DASHBOARD.encode("utf-8"))
        elif path == "/favicon.ico":
            self.send_payload(204, "image/x-icon", b"")
        elif path == "/api/nodes":
            payload = json.dumps(status_payload(), ensure_ascii=False).encode("utf-8")
            self.send_payload(200, "application/json; charset=utf-8", payload)
        elif path == "/health":
            try:
                health = json.loads(HEALTH_PATH.read_text(encoding="utf-8"))
                fresh = 0 <= now() - int(health.get("epoch", 0)) <= max(NODE_INTERVAL * 4, 300)
                code = 200 if health.get("status") in {"ok", "awaiting_sources"} and fresh else 503
            except (OSError, ValueError, TypeError):
                health, code = {"status": "starting"}, 503
            self.send_payload(code, "application/json", json.dumps(health).encode("utf-8"))
        elif path == "/api/quality":
            try:
                from route_quality import STATE
                value = json.loads(STATE.read_text(encoding="utf-8"))
                if not isinstance(value,dict):raise ValueError("state_document")
                # Detailed samples stay local; the LAN view exposes only aggregates.
                value.pop("samples", None)
                value.get("acceptance",{}).pop("records",None)
                value["fresh"] = 0 <= now() - value.get("epoch", 0) < 300
            except (OSError, ValueError, TypeError, AttributeError, ImportError):
                value = {"enabled": False, "status": "starting"}
            self.send_payload(200, "application/json; charset=utf-8", json.dumps(value, ensure_ascii=False).encode())
        elif path == "/api/autonomy":
            try:
                value=json.loads((DB_PATH.parent/"autonomy-status.json").read_text(encoding="utf-8"))
                if not isinstance(value,dict):raise ValueError("state_document")
                value["fresh"]=0<=now()-value.get("epoch",0)<360
            except (OSError,ValueError,TypeError):value={"fresh":False,"status":"starting"}
            self.send_payload(200,"application/json; charset=utf-8",json.dumps(value,ensure_ascii=False).encode())
        else:
            self.send_payload(404, "application/json", b'{"status":"not_found"}')

    def do_POST(self) -> None:  # noqa: N802
        self.send_payload(405, "application/json", b'{"status":"read_only"}')

    def log_message(self, _format: str, *_args: Any) -> None:
        return


def self_test() -> int:
    global DB_PATH
    with tempfile.TemporaryDirectory() as directory:
        DB_PATH = Path(directory) / "test.db"
        init_db()
        with db_session() as connection:
            connection.execute(
                """INSERT INTO nodes
                   (id,name,node_type,fingerprint,provider,first_seen,last_seen,active)
                   VALUES(?,?,?,?,?,?,?,1)""",
                ("abc", "test", "Vless", "stable-id", "provider-a", now(), now()),
            )
            for index in range(30):
                connection.execute(
                    """INSERT INTO probe_results
                       (node_id,probe,business,success,http_code,latency_ms,content_type,error,error_category,created_at)
                       VALUES(?,?,?,?,?,?,?,?,?,?)""",
                    ("abc", f"p{index % 3}", "general", 1, 204, 100 + index,
                     "", "", "ok", now()),
                )
            for business in ("chatgpt", "gemini", "claude", "netflix"):
                update_capability(connection, "abc", business, True, 100.0, now()-11)
                update_capability(connection, "abc", business, True, 100.0, now())
            metrics = [
                {"probe": probe, "success": True, "latency": latency + attempt * 5}
                for probe, latency in (("gstatic", 100), ("cloudflare", 110), ("apple", 120))
                for attempt in range(2)
            ]
            score, state, *_ = calculate_score(connection, "abc", metrics)
            assert score >= 85 and state == "healthy", (score, state)
            assert classify_failure(429, 0, "application/json") == "rate_limited"
            assert classify_failure(0, 28, "") == "timeout"
            assert classify_failure(0, 35, "") == "tls_error"
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
        synced = sync_nodes([{
            "id": "new-id", "name": "renamed", "type": "Vless",
            "fingerprint": "stable-id", "provider": "provider-b",
        }])
        assert synced[0]["id"] == "abc"
        with db_session() as connection:
            renamed = connection.execute(
                "SELECT name,provider FROM nodes WHERE id='abc'"
            ).fetchone()
            assert tuple(renamed) == ("renamed", "provider-b")
            columns = {
                row["name"] for row in connection.execute("PRAGMA table_info(capabilities)")
            }
            assert {"reason", "confidence"}.issubset(columns)
    print("node-capability self-test: OK")
    return 0


def route_audit_once() -> int:
    init_db()
    results = []
    for probe, category, url, method, expected, content_hint in ROUTE_AUDITS:
        result = curl_probe(
            url, method, expected, content_hint,
            proxy=PRODUCTION_PROXY, proxy_auth=PRODUCTION_PROXY_AUTH,
        )
        with db_session() as connection:
            update_route_audit(connection, probe, category, result, now())
        results.append({
            "probe": probe, "success": result["success"], "code": result["code"],
            "latency_ms": result["latency"], "reason": result["error_category"],
        })
    print(json.dumps(results, ensure_ascii=False))
    return 0 if all(item["success"] for item in results) else 1


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    if len(sys.argv) > 1 and sys.argv[1] == "--route-audit-once":
        return route_audit_once()
    init_db()
    if "--serve-only" in sys.argv:
        ThreadingHTTPServer(("0.0.0.0",PORT),Handler).serve_forever();return 0
    thread = threading.Thread(target=scheduler, name="capability-scheduler", daemon=True)
    thread.start()
    if os.getenv('SUBSCRIPTION_ISOLATED_ADMISSION','0')=='1':
        threading.Thread(target=admission_scheduler,name='admission-queue',daemon=True).start()
    route_thread = threading.Thread(
        target=route_audit_scheduler, name="route-audit-scheduler", daemon=True
    )
    route_thread.start()
    log(f"status=started mode={MODE} port={PORT}")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
