#!/usr/bin/env python3
"""Shadow-mode node capability and stability evaluator.

The evaluator selects only the isolated OpenClash probe group. It never changes
production business groups or iKuai rules. Results are stored in SQLite and
served by a read-only LAN dashboard.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import json
import os
import sqlite3
import statistics
import subprocess
import sys
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
DB_PATH = Path(os.getenv("CAPABILITY_DB", "/data/node-capability.db"))
HEALTH_PATH = Path(os.getenv("CAPABILITY_HEALTH", "/data/node-capability.health"))
LOG_PATH = Path(os.getenv("CAPABILITY_LOG", "/data/node-capability.log"))
MODE = os.getenv("CAPABILITY_MODE", "shadow")
PORT = int(os.getenv("CAPABILITY_PORT", "8081"))
NODE_INTERVAL = max(10, int(os.getenv("CAPABILITY_NODE_INTERVAL", "30")))
DISCOVERY_INTERVAL = max(60, int(os.getenv("CAPABILITY_DISCOVERY_INTERVAL", "600")))
BUSINESS_RECHECK = max(900, int(os.getenv("CAPABILITY_BUSINESS_RECHECK", "21600")))
SETTLE_SECONDS = max(1, int(os.getenv("CAPABILITY_SETTLE_SECONDS", "2")))
PROBE_TIMEOUT = max(5, int(os.getenv("CAPABILITY_PROBE_TIMEOUT", "12")))
GENERAL_ATTEMPTS = max(2, int(os.getenv("CAPABILITY_GENERAL_ATTEMPTS", "2")))

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
)

SCHEMA = """
PRAGMA journal_mode=WAL;
PRAGMA synchronous=NORMAL;
CREATE TABLE IF NOT EXISTS nodes (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  node_type TEXT NOT NULL,
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
"""


def now() -> int:
    return int(time.time())


def node_id(name: str) -> str:
    return hashlib.sha256(name.encode("utf-8")).hexdigest()[:16]


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
    discovered = []
    for name in group.get("all", []):
        proxy = all_proxies.get(name, {})
        proxy_type = str(proxy.get("type", "Unknown"))
        if name in {"DIRECT", "REJECT", "REJECT-DROP", "PASS", GROUP}:
            continue
        if proxy_type in GROUP_TYPES:
            continue
        discovered.append({"id": node_id(name), "name": name, "type": proxy_type})
    return discovered


def sync_nodes(nodes: list[dict[str, str]]) -> None:
    epoch = now()
    with db_session() as connection:
        connection.execute("UPDATE nodes SET active=0")
        for entry in nodes:
            connection.execute(
                """INSERT INTO nodes(id,name,node_type,first_seen,last_seen,active)
                   VALUES(?,?,?,?,?,1)
                   ON CONFLICT(id) DO UPDATE SET
                     name=excluded.name,node_type=excluded.node_type,
                     last_seen=excluded.last_seen,active=1""",
                (entry["id"], entry["name"], entry["type"], epoch, epoch),
            )


def select_probe_node(name: str) -> None:
    encoded = urllib.parse.quote(GROUP, safe="")
    api_request(f"/proxies/{encoded}", "PUT", {"name": name})
    selected = api_request(f"/proxies/{encoded}").get("now")
    if selected != name:
        raise RuntimeError("probe group selection readback failed")


def curl_probe(url: str, method: str, expected: set[int], content_hint: str | None) -> dict[str, Any]:
    command = [
        "curl", "-sS", "--max-time", str(PROBE_TIMEOUT), "--connect-timeout", "5",
        "-x", PROXY, "-U", PROXY_AUTH, "-o", "/dev/null",
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
        success = completed.returncode == 0 and code in expected
        if content_hint:
            success = success and content_hint.lower() in content_type.lower()
        error = "" if success else (completed.stderr.strip()[:240] or f"unexpected_http_{code}")
        return {"success": success, "code": code, "latency": elapsed, "content_type": content_type, "error": error}
    except subprocess.TimeoutExpired:
        return {"success": False, "code": 0, "latency": PROBE_TIMEOUT * 1000, "content_type": "", "error": "timeout"}


def record_result(connection: sqlite3.Connection, nid: str, probe: str, business: str,
                  result: dict[str, Any], epoch: int) -> None:
    connection.execute(
        """INSERT INTO probe_results
           (node_id,probe,business,success,http_code,latency_ms,content_type,error,created_at)
           VALUES(?,?,?,?,?,?,?,?,?)""",
        (nid, probe, business, int(result["success"]), result["code"], result["latency"],
         result["content_type"], result["error"], epoch),
    )


def update_capability(connection: sqlite3.Connection, nid: str, business: str,
                      success: bool, score: float, epoch: int) -> None:
    previous = connection.execute(
        "SELECT * FROM capabilities WHERE node_id=? AND business=?", (nid, business)
    ).fetchone()
    consecutive_success = (previous["consecutive_success"] if previous and success else 0) + int(success)
    consecutive_failure = (previous["consecutive_failure"] if previous and not success else 0) + int(not success)
    last_success = epoch if success else (previous["last_success"] if previous else None)
    last_failure = epoch if not success else (previous["last_failure"] if previous else None)
    status = "available" if success else "unavailable"
    connection.execute(
        """INSERT INTO capabilities
           (node_id,business,status,score,last_success,last_failure,last_checked,
            consecutive_success,consecutive_failure)
           VALUES(?,?,?,?,?,?,?,?,?)
           ON CONFLICT(node_id,business) DO UPDATE SET
             status=excluded.status,score=excluded.score,last_success=excluded.last_success,
             last_failure=excluded.last_failure,last_checked=excluded.last_checked,
             consecutive_success=excluded.consecutive_success,
             consecutive_failure=excluded.consecutive_failure""",
        (nid, business, status, score, last_success, last_failure, epoch,
         consecutive_success, consecutive_failure),
    )


def due_businesses(connection: sqlite3.Connection, nid: str, epoch: int) -> list[tuple[Any, ...]]:
    due = []
    for definition in BUSINESS_PROBES:
        business = definition[0]
        row = connection.execute(
            "SELECT last_checked FROM capabilities WHERE node_id=? AND business=?", (nid, business)
        ).fetchone()
        if row is None or epoch - row["last_checked"] >= BUSINESS_RECHECK:
            due.append(definition)
    return due


def calculate_score(connection: sqlite3.Connection, nid: str, current_general: list[dict[str, Any]]) -> tuple[float, str, float, float, float]:
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
    latency = statistics.mean(successful_latencies) if successful_latencies else PROBE_TIMEOUT * 1000.0
    jitter = statistics.pstdev(successful_latencies) if len(successful_latencies) > 1 else 0.0
    current_ratio = sum(entry["success"] for entry in current_general) / len(current_general)
    target_results: dict[str, list[bool]] = {}
    for entry in current_general:
        target_results.setdefault(entry["probe"], []).append(bool(entry["success"]))
    target_ratio = sum(all(attempts) for attempts in target_results.values()) / len(target_results)

    capabilities = connection.execute(
        "SELECT status FROM capabilities WHERE node_id=? AND business!='general'", (nid,)
    ).fetchall()
    business_rate = (
        sum(row["status"] == "available" for row in capabilities) / len(capabilities)
        if capabilities else 0.5
    )

    quality = max(0.0, 1.0 - min(jitter, 1000.0) / 1000.0)
    latency_quality = max(0.0, min(1.0, (1500.0 - latency) / 1200.0))
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
    if target_ratio < 2 / 3:
        state = "cooling" if consecutive_failure < 2 else "unavailable"
    elif capabilities and business_rate < 1.0:
        state = "business-limited"
    elif score >= 85:
        state = "healthy"
    else:
        state = "degraded"
    return score, state, current_ratio, float(latency), float(jitter)


def probe_node(entry: dict[str, str]) -> None:
    nid = entry["id"]
    epoch = now()
    select_probe_node(entry["name"])
    time.sleep(SETTLE_SECONDS)

    general_results = []
    for probe, url, method, expected, content_hint in GENERAL_PROBES:
        for _attempt in range(GENERAL_ATTEMPTS):
            result = curl_probe(url, method, expected, content_hint)
            result["probe"] = probe
            general_results.append(result)

    with db_session() as connection:
        for result in general_results:
            record_result(connection, nid, result["probe"], "general", result, epoch)
        target_successes = sum(
            all(result["success"] for result in general_results if result["probe"] == probe)
            for probe, *_rest in GENERAL_PROBES
        )
        general_success = target_successes >= 2
        update_capability(connection, nid, "general", general_success,
                          100.0 * target_successes / len(GENERAL_PROBES), epoch)

        if general_success:
            for business, url, method, expected, content_hint in due_businesses(connection, nid, epoch):
                result = curl_probe(url, method, expected, content_hint)
                record_result(connection, nid, business, business, result, epoch)
                update_capability(connection, nid, business, result["success"],
                                  100.0 if result["success"] else 0.0, epoch)

        score, state, ratio, latency, jitter = calculate_score(connection, nid, general_results)
        connection.execute(
            """INSERT INTO health_scores(node_id,score,state,general_success_ratio,latency_ms,jitter_ms,updated_at)
               VALUES(?,?,?,?,?,?,?)
               ON CONFLICT(node_id) DO UPDATE SET
                 score=excluded.score,state=excluded.state,
                 general_success_ratio=excluded.general_success_ratio,
                 latency_ms=excluded.latency_ms,jitter_ms=excluded.jitter_ms,
                 updated_at=excluded.updated_at""",
            (nid, score, state, ratio, latency, jitter, epoch),
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
    log(f"status=probed node_hash={nid[:12]} mode={MODE} state={state} score={score}")


def scheduler() -> None:
    if MODE != "shadow":
        raise RuntimeError("only shadow mode is allowed in this release")
    if not API_SECRET or not PROXY_AUTH:
        raise RuntimeError("missing OpenClash or capability proxy credentials")

    nodes: list[dict[str, str]] = []
    position = 0
    last_discovery = 0
    probed = 0
    while True:
        try:
            epoch = now()
            if not nodes or epoch - last_discovery >= DISCOVERY_INTERVAL:
                nodes = discover_nodes()
                sync_nodes(nodes)
                last_discovery = epoch
                position %= max(len(nodes), 1)
                log(f"status=discovered active_nodes={len(nodes)} mode={MODE}")
            if not nodes:
                raise RuntimeError("isolated probe group has no nodes")
            entry = nodes[position]
            position = (position + 1) % len(nodes)
            probe_node(entry)
            probed += 1
            atomic_json(HEALTH_PATH, {
                "status": "ok", "detail": "shadow_evaluation", "mode": MODE,
                "active_nodes": len(nodes), "probed": probed, "epoch": now(),
            })
        except Exception as error:  # keep dashboard alive and retry without touching production
            detail = type(error).__name__
            log(f"status=error reason={detail}")
            atomic_json(HEALTH_PATH, {
                "status": "error", "detail": detail, "mode": MODE,
                "active_nodes": len(nodes), "probed": probed, "epoch": now(),
            })
        time.sleep(NODE_INTERVAL)


def status_payload() -> dict[str, Any]:
    with db_session() as connection:
        rows = connection.execute(
            """SELECT n.id,n.name,n.node_type,n.last_seen,
                      COALESCE(h.score,0) AS score,COALESCE(h.state,'unknown') AS state,
                      COALESCE(h.general_success_ratio,0) AS general_success_ratio,
                      COALESCE(h.latency_ms,0) AS latency_ms,
                      COALESCE(h.jitter_ms,0) AS jitter_ms,COALESCE(h.updated_at,0) AS updated_at
               FROM nodes n LEFT JOIN health_scores h ON h.node_id=n.id
               WHERE n.active=1 ORDER BY h.score DESC,n.name"""
        ).fetchall()
        capabilities = connection.execute(
            "SELECT node_id,business,status,last_checked FROM capabilities"
        ).fetchall()
    by_node: dict[str, dict[str, Any]] = {}
    for row in rows:
        item = dict(row)
        item["capabilities"] = {}
        by_node[row["id"]] = item
    for row in capabilities:
        if row["node_id"] in by_node:
            by_node[row["node_id"]]["capabilities"][row["business"]] = {
                "status": row["status"], "last_checked": row["last_checked"],
            }
    states: dict[str, int] = {}
    for item in by_node.values():
        states[item["state"]] = states.get(item["state"], 0) + 1
    return {"mode": MODE, "generated_at": now(), "states": states, "nodes": list(by_node.values())}


DASHBOARD = """<!doctype html><html lang=\"zh-CN\"><head><meta charset=\"utf-8\">
<meta name=\"viewport\" content=\"width=device-width,initial-scale=1\"><title>节点能力评估</title>
<style>body{font-family:system-ui,sans-serif;margin:0;background:#f5f7fb;color:#182033}.wrap{max-width:1400px;margin:auto;padding:24px}h1{margin:0 0 8px}.hint{color:#64748b;margin-bottom:18px}.cards{display:flex;gap:12px;flex-wrap:wrap}.card{background:white;border-radius:12px;padding:14px 18px;box-shadow:0 2px 12px #15234a12}.card b{font-size:24px;display:block}table{width:100%;border-collapse:collapse;background:white;margin-top:18px;border-radius:12px;overflow:hidden}th,td{padding:11px 12px;border-bottom:1px solid #edf0f5;text-align:left}th{background:#eef3fb}.pill{border-radius:999px;padding:4px 9px;font-size:12px}.healthy,.available{background:#dcfce7;color:#166534}.degraded{background:#fef3c7;color:#92400e}.business-limited{background:#ffedd5;color:#9a3412}.cooling{background:#dbeafe;color:#1e40af}.unavailable{background:#fee2e2;color:#991b1b}.unknown{background:#e2e8f0;color:#475569}.caps{display:flex;gap:5px;flex-wrap:wrap}@media(max-width:800px){.hide-sm{display:none}.wrap{padding:12px}th,td{padding:8px 6px;font-size:13px}}</style></head>
<body><div class=\"wrap\"><h1>节点能力与稳定性评估</h1><div class=\"hint\">影子模式：只检测独立节点组，不修改生产分流。页面每 30 秒刷新。</div><div class=\"cards\" id=\"cards\"></div>
<table><thead><tr><th>节点</th><th>状态</th><th>评分</th><th>延迟</th><th class=\"hide-sm\">抖动</th><th>业务能力</th><th class=\"hide-sm\">最后检测</th></tr></thead><tbody id=\"rows\"></tbody></table></div>
<script>const labels={healthy:'健康',degraded:'降级','business-limited':'业务受限',cooling:'冷却观察',unavailable:'不可用',unknown:'未评估'};
function pill(t,c){const s=document.createElement('span');s.className='pill '+c;s.textContent=t;return s}function td(tr){const x=document.createElement('td');tr.appendChild(x);return x}
async function load(){const d=await fetch('/api/nodes',{cache:'no-store'}).then(r=>r.json());const cards=document.querySelector('#cards');cards.textContent='';
Object.entries(d.states).forEach(([k,v])=>{const x=document.createElement('div');x.className='card';const b=document.createElement('b');b.textContent=v;x.append(b,document.createTextNode(labels[k]||k));cards.appendChild(x)});
const rows=document.querySelector('#rows');rows.textContent='';d.nodes.forEach(n=>{const tr=document.createElement('tr');td(tr).textContent=n.name;td(tr).appendChild(pill(labels[n.state]||n.state,n.state));td(tr).textContent=n.score.toFixed(1);td(tr).textContent=Math.round(n.latency_ms)+' ms';const j=td(tr);j.className='hide-sm';j.textContent=Math.round(n.jitter_ms)+' ms';const c=td(tr);c.className='caps';Object.entries(n.capabilities).filter(([k])=>k!=='general').forEach(([k,v])=>c.appendChild(pill(k,v.status)));const u=td(tr);u.className='hide-sm';u.textContent=n.updated_at?new Date(n.updated_at*1000).toLocaleString():'-';rows.appendChild(tr)});}
load().catch(()=>{});setInterval(()=>load().catch(()=>{}),30000);</script></body></html>"""


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
        elif path == "/api/nodes":
            payload = json.dumps(status_payload(), ensure_ascii=False).encode("utf-8")
            self.send_payload(200, "application/json; charset=utf-8", payload)
        elif path == "/health":
            try:
                health = json.loads(HEALTH_PATH.read_text(encoding="utf-8"))
                fresh = now() - int(health.get("epoch", 0)) <= max(NODE_INTERVAL * 4, 180)
                code = 200 if health.get("status") == "ok" and fresh else 503
            except (OSError, ValueError, TypeError):
                health, code = {"status": "starting"}, 503
            self.send_payload(code, "application/json", json.dumps(health).encode("utf-8"))
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
                "INSERT INTO nodes VALUES(?,?,?,?,?,1)", ("abc", "test", "Vless", now(), now())
            )
            for index in range(30):
                connection.execute(
                    "INSERT INTO probe_results(node_id,probe,business,success,http_code,latency_ms,content_type,error,created_at) VALUES(?,?,?,?,?,?,?,?,?)",
                    ("abc", f"p{index % 3}", "general", 1, 204, 100 + index, "", "", now()),
                )
            for business in ("chatgpt", "gemini", "claude", "netflix"):
                update_capability(connection, "abc", business, True, 100.0, now())
            metrics = [
                {"probe": probe, "success": True, "latency": latency + attempt * 5}
                for probe, latency in (("gstatic", 100), ("cloudflare", 110), ("apple", 120))
                for attempt in range(2)
            ]
            score, state, *_ = calculate_score(connection, "abc", metrics)
            assert score >= 85 and state == "healthy", (score, state)
            assert connection.execute("PRAGMA integrity_check").fetchone()[0] == "ok"
    print("node-capability self-test: OK")
    return 0


def main() -> int:
    if len(sys.argv) > 1 and sys.argv[1] == "--self-test":
        return self_test()
    init_db()
    thread = threading.Thread(target=scheduler, name="capability-scheduler", daemon=True)
    thread.start()
    log(f"status=started mode={MODE} port={PORT}")
    server = ThreadingHTTPServer(("0.0.0.0", PORT), Handler)
    server.serve_forever()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
