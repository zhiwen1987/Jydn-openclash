"use strict";

/* Native, bounded Uptime Kuma 2.5.6 Socket.IO bridge. stdout is JSONL only. */
const crypto = require("crypto");
const fs = require("fs");
const path = require("path");
const readline = require("readline");

const MAX_MONITORS = 2000, MAX_NOTIFICATIONS = 512, MAX_HISTORY = 500;
const TYPES = new Set(["http", "ping", "port", "dns", "group"]);
const COMMON = new Set(["name", "description", "parent", "active", "interval", "retryInterval", "resendInterval", "maxretries", "timeout", "notificationIDList"]);
const TYPE_FIELDS = {
    http: new Set(["url", "method", "accepted_statuscodes", "ignoreTls", "upsideDown", "maxredirects", "expiryNotification", "domainExpiryNotification", "headers", "body", "basic_auth_user", "basic_auth_pass", "bearer_token"]),
    ping: new Set(["hostname", "packetSize", "ping_count", "ping_numeric", "ping_per_request_timeout"]),
    port: new Set(["hostname", "port"]),
    dns: new Set(["hostname", "port", "dns_resolve_type", "dns_resolve_server", "packetSize"]),
    group: new Set(),
};
const MON_SECRET = new Set(["headers", "body", "basic_auth_user", "basic_auth_pass", "bearer_token", "oauth_client_id", "oauth_client_secret", "tlsCa", "tlsCert", "tlsKey", "databaseConnectionString", "radiusUsername", "radiusPassword", "radiusSecret", "mqttUsername", "mqttPassword", "gamedigToken", "rabbitmqUsername", "rabbitmqPassword", "sshUser", "sshPassword", "sshPrivateKey", "sshKeyPassphrase", "kafkaProducerSaslOptions"]);
const NOTIFY_SECRET = /(?:url|token|secret|password|passwd|auth|authorization|cookie|key|headers|body)$/i;
const QUERY_SECRET = /(?:token|secret|password|passwd|auth|authorization|cookie|key|signature|sig|code)/i;
const VOLATILE = new Set(["status", "forceInactive", "maintenance", "path", "pathName", "screenshot", "dns_last_result", "includeSensitiveData", "humanReadableInterval", "responsecheck", "globalpingdnsresolvetypeoptions"]);

class BridgeError extends Error {
    constructor(code, status = 503) { super(code); this.code = code; this.status = status; }
}
function int(value, min, max) {
    const n = Number(value);
    if (!Number.isInteger(n) || n < min || n > max) throw new BridgeError("kuma_validation_failed", 400);
    return n;
}
function number(value, min, max) {
    const n = Number(value);
    if (!Number.isFinite(n) || n < min || n > max) throw new BridgeError("kuma_validation_failed", 400);
    return n;
}
function string(value, max, required = false) {
    if (value == null) value = "";
    if (typeof value !== "string" || value.length > max || value.includes("\0") || (required && !value.trim())) throw new BridgeError("kuma_validation_failed", 400);
    return value;
}
function copy(v) { return v == null ? v : JSON.parse(JSON.stringify(v)); }
function canonical(v) {
    if (Array.isArray(v)) return v.map(canonical);
    if (v && typeof v === "object") return Object.fromEntries(Object.keys(v).sort().map((k) => [k, canonical(v[k])]));
    return v;
}
function hash(v) { return crypto.createHash("sha256").update(JSON.stringify(canonical(v))).digest("hex"); }
function text(v, max = 512) { return v == null ? null : String(v).replace(/[\u0000-\u001f\u007f]/g, " ").slice(0, max); }
function safeUrl(value) {
    if (typeof value !== "string" || !value) return value || "";
    try {
        const u = new URL(value);
        if (u.username || u.password || Array.from(u.searchParams.keys()).some((key) => QUERY_SECRET.test(key))) return "[redacted-url-hidden]";
        return u.toString();
    } catch (_) { return "[invalid-url-hidden]"; }
}
function redactedUrl(value) {
    if (typeof value !== "string") return false;
    const lower = value.toLowerCase();
    return lower.startsWith("[redacted") || lower === "[invalid-url-hidden]" || lower.includes("[hidden]") || lower.includes("%5bhidden%5d");
}
function notificationConfig(row) {
    if (!row || typeof row !== "object") return null;
    let value = {};
    if (typeof row.config === "string") { try { value = JSON.parse(row.config); } catch (_) { value = {}; } }
    else if (row.config && typeof row.config === "object") value = copy(row.config);
    for (const [k, v] of Object.entries(row)) if (k !== "config" && !(k in value)) value[k] = v;
    if (row.id != null) value.id = Number(row.id);
    return value;
}
function notificationSummary(row) {
    const c = notificationConfig(row) || {};
    return { id: Number(c.id || row.id), name: text(c.name || "", 160), type: text(c.type || "", 64), active: Boolean(c.active), is_default: Boolean(c.isDefault), has_secret_fields: Object.keys(c).filter((k) => NOTIFY_SECRET.test(k) && c[k]).sort() };
}
function notificationDetailValue(row) {
    const config = notificationConfig(row) || {}, summary = notificationSummary(row);
    return {
        ...summary,
        http_method: text(config.httpMethod || "post", 8),
        webhook_content_type: text(config.webhookContentType || "json", 32),
        configured_fields: ["webhookURL", "webhookCustomBody", "webhookAdditionalHeaders"].filter((key) => config[key] != null && config[key] !== ""),
    };
}
function latest(heartbeats, id) {
    const rows = heartbeats[String(id)] || heartbeats[id];
    return Array.isArray(rows) && rows.length ? rows[rows.length - 1] : null;
}
function statusName(v) { return ({ 0: "down", 1: "up", 2: "pending", 3: "maintenance" })[Number(v)] || "unknown"; }
function monitorSummary(row, heartbeats = {}, avgPing = {}, uptime = {}) {
    const beat = latest(heartbeats, row.id);
    const average = avgPing[row.id] == null ? NaN : Number(avgPing[row.id]);
    return {
        id: Number(row.id), name: text(row.name || "", 160), description: text(row.description || "", 1000), type: text(row.type || "", 64), active: Boolean(row.active),
        parent: row.parent == null ? null : Number(row.parent), children_ids: Array.isArray(row.childrenIDs) ? row.childrenIDs.map(Number).filter(Number.isFinite) : [], interval: Number(row.interval || 0),
        status: beat ? statusName(beat.status) : (row.active ? "unknown" : "paused"), checked_at: beat ? text(beat.time, 64) : null,
        ping: beat && Number.isFinite(Number(beat.ping)) ? Number(beat.ping) : (Number.isFinite(average) ? average : null), uptime_24h: uptime[`${row.id}_24`] == null ? null : Number(uptime[`${row.id}_24`]),
        tags: Array.isArray(row.tags) ? row.tags.slice(0, 64).map((t) => ({ id: Number(t.tag_id || t.id), name: text(t.name || "", 80), value: text(t.value || "", 160), color: text(t.color || "", 16) })) : [],
        notification_ids: row.notificationIDList && typeof row.notificationIDList === "object" ? Object.keys(row.notificationIDList).filter((k) => row.notificationIDList[k]).map(Number) : [],
    };
}
function monitorDetail(row) {
    const type = String(row.type || ""), out = { id: Number(row.id), type }, secrets = [];
    for (const key of new Set([...COMMON, ...(TYPE_FIELDS[type] || [])])) {
        const value = row[key];
        if (MON_SECRET.has(key)) { if (value != null && value !== "" && value !== "{}") secrets.push(key); continue; }
        if (value !== undefined) {
            if (key === "url") {
                out[key] = safeUrl(value);
                if (out[key] === "[redacted-url-hidden]") secrets.push("url");
            } else out[key] = copy(value);
        }
    }
    out.has_secret_fields = secrets.sort(); return out;
}
function revisionValue(monitors, notifications) {
    const rows = Object.values(monitors || {}).slice(0, MAX_MONITORS).map((row) => Object.fromEntries(Object.keys(row).sort().filter((k) => !VOLATILE.has(k)).map((k) => [k, row[k]]))).sort((a, b) => Number(a.id) - Number(b.id));
    const notices = (notifications || []).slice(0, MAX_NOTIFICATIONS).map(notificationConfig).sort((a, b) => Number(a.id) - Number(b.id));
    return { monitors: rows, notifications: notices };
}

function applyMonitorPatch(current, patch, creating = false) {
    if (!patch || typeof patch !== "object" || Array.isArray(patch)) throw new BridgeError("kuma_validation_failed", 400);
    const type = creating ? String(patch.type || current.type) : String(current.type || "");
    if (!TYPES.has(type)) throw new BridgeError("kuma_monitor_type_unsupported", 400);
    if (!creating && patch.type != null && patch.type !== type) throw new BridgeError("kuma_monitor_type_change_unsupported", 400);
    const allowed = new Set([...COMMON, ...(TYPE_FIELDS[type] || [])]), out = copy(current), clear = new Set(Array.isArray(patch.clear_secret_fields) ? patch.clear_secret_fields : []);
    for (const [key, value] of Object.entries(patch)) {
        if (key === "type" || key === "clear_secret_fields") continue;
        if (!allowed.has(key)) throw new BridgeError("kuma_monitor_field_unsupported", 400);
        if (!creating && MON_SECRET.has(key) && value === "" && !clear.has(key)) continue;
        if (key === "url" && redactedUrl(value)) {
            if (creating) throw new BridgeError("kuma_validation_failed", 400);
            continue;
        }
        out[key] = copy(value);
    }
    out.type = type; out.name = string(out.name, 160, true); out.description = string(out.description || "", 2000); out.parent = out.parent == null ? null : int(out.parent, 1, 2147483647); out.active = out.active !== false;
    out.interval = int(out.interval, 5, 86400); out.retryInterval = int(out.retryInterval || out.interval, 5, 86400); out.resendInterval = int(out.resendInterval || 0, 0, 1000); out.maxretries = int(out.maxretries || 0, 0, 100); out.timeout = number(out.timeout || Math.max(1, out.interval * 0.8), 0.1, 86400);
    if (!out.notificationIDList || typeof out.notificationIDList !== "object" || Array.isArray(out.notificationIDList)) throw new BridgeError("kuma_validation_failed", 400);
    out.notificationIDList = Object.fromEntries(Object.entries(out.notificationIDList).slice(0, MAX_NOTIFICATIONS).map(([k, v]) => [String(int(k, 1, 2147483647)), Boolean(v)]));
    if (!Array.isArray(out.accepted_statuscodes)) out.accepted_statuscodes = ["200-299"];
    out.accepted_statuscodes = out.accepted_statuscodes.slice(0, 64).map((v) => string(v, 32, true));
    if (!Array.isArray(out.kafkaProducerBrokers)) out.kafkaProducerBrokers = [];
    if (!out.kafkaProducerSaslOptions || typeof out.kafkaProducerSaslOptions !== "object") out.kafkaProducerSaslOptions = { mechanism: "None" };
    if (!Array.isArray(out.conditions)) out.conditions = [];
    if (!Array.isArray(out.rabbitmqNodes)) out.rabbitmqNodes = [];
    if (type === "http") {
        out.url = string(out.url, 4096, true); if (!/^https?:\/\//i.test(out.url)) throw new BridgeError("kuma_validation_failed", 400);
        out.method = string(out.method || "GET", 16, true).toUpperCase(); if (!["GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"].includes(out.method)) throw new BridgeError("kuma_validation_failed", 400);
        out.maxredirects = int(out.maxredirects == null ? 10 : out.maxredirects, 0, 50);
        for (const key of ["headers", "body", "basic_auth_user", "basic_auth_pass", "bearer_token"]) out[key] = string(out[key] || "", key === "body" || key === "headers" ? 262144 : 8192);
        for (const key of ["ignoreTls", "upsideDown", "expiryNotification", "domainExpiryNotification"]) out[key] = Boolean(out[key]);
    } else if (type !== "group") out.hostname = string(out.hostname, 253, true).trim();
    if (type === "port") out.port = int(out.port, 1, 65535);
    if (type === "dns") { out.port = int(out.port == null ? 53 : out.port, 1, 65535); out.dns_resolve_type = string(out.dns_resolve_type || "A", 16, true).toUpperCase(); if (!["A", "AAAA", "CNAME", "MX", "NS", "PTR", "SOA", "SRV", "TXT", "CAA"].includes(out.dns_resolve_type)) throw new BridgeError("kuma_validation_failed", 400); out.dns_resolve_server = string(out.dns_resolve_server || "", 253); }
    if (type === "dns" || type === "ping") out.packetSize = int(out.packetSize == null ? 56 : out.packetSize, 1, 65535);
    if (type === "ping") { out.ping_count = int(out.ping_count == null ? 3 : out.ping_count, 1, 20); out.ping_numeric = Boolean(out.ping_numeric); out.ping_per_request_timeout = number(out.ping_per_request_timeout == null ? 2 : out.ping_per_request_timeout, 0.1, 60); }
    return out;
}

function defaultMonitor(input) {
    const type = string(input.type, 64, true); if (!TYPES.has(type)) throw new BridgeError("kuma_monitor_type_unsupported", 400);
    const base = { type, name: "", description: "", parent: null, active: true, url: type === "http" ? "https://" : "", wsSubprotocol: "", method: "GET", protocol: null, location: "world", ipFamily: null, interval: 60, retryInterval: 60, resendInterval: 0, maxretries: 0, retryOnlyOnStatusCodeFailure: false, notificationIDList: {}, ignoreTls: false, upsideDown: false, expiryNotification: false, domainExpiryNotification: true, maxredirects: 10, accepted_statuscodes: ["200-299"], saveResponse: false, saveErrorResponse: true, responseMaxLength: 1024, dns_resolve_type: "A", dns_resolve_server: "", docker_container: "", docker_host: null, proxyId: null, basic_auth_user: "", basic_auth_pass: "", bearer_token: "", mqttUsername: "", mqttPassword: "", mqttTopic: "", mqttWebsocketPath: "", mqttSuccessMessage: "", mqttCheckType: "keyword", authMethod: null, oauth_auth_method: "client_secret_basic", httpBodyEncoding: "json", kafkaProducerBrokers: [], kafkaProducerSaslOptions: { mechanism: "None" }, cacheBust: false, kafkaProducerSsl: false, kafkaProducerAllowAutoTopicCreation: false, gamedigGivenPortOnly: true, gamedigToken: "", remote_browser: null, screenshot_delay: 0, rabbitmqNodes: [], rabbitmqUsername: "", rabbitmqPassword: "", conditions: [], system_service_name: "", sshAuthMethod: "password", ntpStratumThreshold: 5, ntpTimeOffsetThreshold: 1000, ntpRootDispersionThreshold: 500, ping_count: 3, ping_numeric: true, packetSize: 56, ping_per_request_timeout: 2, hostname: "", port: null };
    return applyMonitorPatch(base, input, true);
}

function validateWebhook(input, existing = null) {
    if (!input || typeof input !== "object" || Array.isArray(input)) throw new BridgeError("kuma_validation_failed", 400);
    const out = existing ? copy(existing) : { type: "webhook", active: true, isDefault: false, httpMethod: "post", webhookContentType: "json" };
    const allowed = new Set(["name", "type", "active", "isDefault", "httpMethod", "webhookContentType", "webhookURL", "webhookCustomBody", "webhookAdditionalHeaders"]), clear = new Set(Array.isArray(input.clear_secret_fields) ? input.clear_secret_fields : []);
    for (const [key, value] of Object.entries(input)) { if (key === "clear_secret_fields") continue; if (!allowed.has(key)) throw new BridgeError("kuma_notification_field_unsupported", 400); if (existing && NOTIFY_SECRET.test(key) && value === "" && !clear.has(key)) continue; out[key] = copy(value); }
    if (out.type !== "webhook") throw new BridgeError("kuma_notification_type_unsupported", 400);
    out.name = string(out.name, 160, true); out.active = out.active !== false; out.isDefault = Boolean(out.isDefault); out.httpMethod = string(out.httpMethod || "post", 8, true).toLowerCase(); if (!["get", "post"].includes(out.httpMethod)) throw new BridgeError("kuma_validation_failed", 400);
    out.webhookContentType = string(out.webhookContentType || "json", 32, true); if (!["json", "form-data", "custom"].includes(out.webhookContentType)) throw new BridgeError("kuma_validation_failed", 400);
    out.webhookURL = string(out.webhookURL, 4096, true); if (!/^https?:\/\//i.test(out.webhookURL)) throw new BridgeError("kuma_validation_failed", 400);
    out.webhookCustomBody = string(out.webhookCustomBody || "", 65536); out.webhookAdditionalHeaders = string(out.webhookAdditionalHeaders || "", 65536); return out;
}

function loadSocketClient() {
    for (const name of ["socket.io-client", "/app/node_modules/socket.io-client"]) {
        try { const mod = require(name); return mod.io || mod; } catch (_) { /* next */ }
    }
    throw new BridgeError("kuma_protocol_mismatch");
}
function localKumaUrl(value) {
    let parsed;
    try { parsed = new URL(value); } catch (_) { throw new BridgeError("kuma_bridge_url_invalid", 400); }
    const hosts = new Set(["127.0.0.1", "localhost", "[::1]"]);
    if (parsed.protocol !== "http:" || !hosts.has(parsed.hostname) || parsed.port !== "3001" || parsed.username || parsed.password || parsed.pathname !== "/" || parsed.search || parsed.hash) {
        throw new BridgeError("kuma_bridge_url_invalid", 400);
    }
    return parsed.origin;
}

class KumaBridge {
    constructor(options = {}) {
        this.ioFactory = options.ioFactory || loadSocketClient();
        this.url = localKumaUrl(options.url || "http://127.0.0.1:3001");
        this.tokenFile = options.tokenFile || "/data/unified/kuma-bridge.jwt";
        this.requestTimeout = Number(options.requestTimeout || 8000);
        this.socket = null; this.state = "starting"; this.errorCode = null; this.authenticated = false;
        this.monitors = {}; this.notifications = []; this.heartbeats = {}; this.avgPing = {}; this.uptime = {}; this.info = {}; this.checkedAt = null; this.connecting = null;
        this.monitorGeneration = 0; this.notificationGeneration = 0;
    }
    setState(state, code = null) { this.state = state; this.errorCode = code; this.checkedAt = new Date().toISOString(); }
    async start() {
        if (this.connecting) return this.connecting;
        this.connecting = this.connect().finally(() => { this.connecting = null; });
        return this.connecting;
    }
    async connect() {
        if (this.socket) { try { this.socket.removeAllListeners(); this.socket.disconnect(); } catch (_) {} }
        this.setState("connecting");
        const socket = this.ioFactory(this.url, { autoConnect: false, transports: ["websocket", "polling"], reconnection: true, reconnectionDelay: 500, reconnectionDelayMax: 5000, timeout: Math.min(this.requestTimeout, 5000) });
        this.socket = socket; this.installListeners(socket);
        await new Promise((resolve, reject) => {
            let settled = false;
            const finish = (error) => { if (settled) return; settled = true; clearTimeout(timer); socket.off("connect", connected); socket.off("connect_error", failed); error ? reject(error) : resolve(); };
            const connected = () => finish(), failed = () => finish(new BridgeError("kuma_bridge_unavailable"));
            const timer = setTimeout(() => finish(new BridgeError("kuma_bridge_unavailable")), Math.min(this.requestTimeout, 5000));
            socket.once("connect", connected); socket.once("connect_error", failed); socket.connect();
        });
        await this.authenticateFile();
    }
    installListeners(socket) {
        socket.on("info", (v) => { if (v && typeof v === "object") this.info = copy(v); });
        socket.on("monitorList", (v) => { if (v && typeof v === "object" && !Array.isArray(v)) this.monitors = copy(v); this.monitorGeneration++; this.checkedAt = new Date().toISOString(); });
        socket.on("updateMonitorIntoList", (v) => { if (v && typeof v === "object") Object.assign(this.monitors, copy(v)); this.monitorGeneration++; this.checkedAt = new Date().toISOString(); });
        socket.on("deleteMonitorFromList", (id) => { delete this.monitors[String(id)]; delete this.monitors[id]; this.monitorGeneration++; });
        socket.on("notificationList", (v) => { if (Array.isArray(v)) this.notifications = copy(v).slice(0, MAX_NOTIFICATIONS); this.notificationGeneration++; this.checkedAt = new Date().toISOString(); });
        socket.on("heartbeatList", (monitorID, rows, overwrite) => { const key = String(monitorID); if (Array.isArray(rows)) this.heartbeats[key] = overwrite ? copy(rows) : (this.heartbeats[key] || []).concat(copy(rows)).slice(-100); });
        socket.on("heartbeat", (v) => { if (!v || v.monitorID == null) return; const key = String(v.monitorID), rows = Array.isArray(this.heartbeats[key]) ? this.heartbeats[key] : []; rows.push(copy(v)); this.heartbeats[key] = rows.slice(-100); });
        socket.on("avgPing", (monitorID, value) => { this.avgPing[String(monitorID)] = value; });
        socket.on("uptime", (monitorID, period, value) => { this.uptime[`${monitorID}_${period}`] = value; });
        socket.on("disconnect", () => { this.authenticated = false; this.setState("disconnected", "kuma_bridge_unavailable"); });
        socket.on("connect", () => { if (this.state === "disconnected") this.authenticateFile().catch(() => {}); });
        socket.on("connect_error", () => this.setState("error", "kuma_bridge_unavailable"));
    }
    readToken() {
        try {
            const stat = fs.statSync(this.tokenFile);
            if (process.platform !== "win32" && (stat.mode & 0o077)) throw new BridgeError("kuma_token_permissions_invalid");
            const token = fs.readFileSync(this.tokenFile, "utf8").trim();
            if (!token || token.length > 8192) throw new BridgeError("kuma_binding_required", 409);
            return token;
        } catch (error) { if (error instanceof BridgeError) throw error; throw new BridgeError("kuma_binding_required", 409); }
    }
    async authenticateFile() {
        let token;
        try { token = this.readToken(); } catch (error) { this.authenticated = false; this.setState("unbound", error.code); return; }
        const monitorGeneration = this.monitorGeneration, notificationGeneration = this.notificationGeneration;
        const result = await this.emitAck("loginByToken", [token], false);
        if (!result || result.ok !== true) { this.authenticated = false; this.setState("auth_failed", "kuma_auth_failed"); return; }
        this.authenticated = true;
        await this.waitFor(() => this.monitorGeneration > monitorGeneration && this.notificationGeneration > notificationGeneration);
        if (this.info.version !== "2.5.6") { this.setState("protocol_mismatch", "kuma_protocol_mismatch"); return; }
        this.setState("ready");
    }
    writeToken(token) {
        const dir = path.dirname(this.tokenFile); fs.mkdirSync(dir, { recursive: true, mode: 0o700 });
        try { fs.chmodSync(dir, 0o700); } catch (_) {}
        const temporary = `${this.tokenFile}.${process.pid}.${crypto.randomBytes(6).toString("hex")}.tmp`;
        let fd;
        try {
            fd = fs.openSync(temporary, "wx", 0o600); fs.writeFileSync(fd, token, "utf8"); fs.fsyncSync(fd); fs.closeSync(fd); fd = null;
            try { fs.chmodSync(temporary, 0o600); } catch (_) {}
            fs.renameSync(temporary, this.tokenFile);
        } finally { if (fd != null) try { fs.closeSync(fd); } catch (_) {} try { fs.unlinkSync(temporary); } catch (_) {} }
    }
    async bind(params) {
        if (!params || typeof params !== "object") throw new BridgeError("kuma_validation_failed", 400);
        const username = string(params.username, 128, true), password = string(params.password, 1024, true), totp = params.totp == null ? "" : string(params.totp, 10);
        if (!this.socket || !this.socket.connected) await this.start();
        const monitorGeneration = this.monitorGeneration, notificationGeneration = this.notificationGeneration;
        const response = await this.emitAck("login", [{ username, password, token: totp }], true);
        if (response && response.tokenRequired && !totp) throw new BridgeError("kuma_totp_required", 401);
        if (!response || response.ok !== true || typeof response.token !== "string") throw new BridgeError("kuma_auth_failed", 401);
        this.writeToken(response.token); this.authenticated = true;
        await this.waitFor(() => this.monitorGeneration > monitorGeneration && this.notificationGeneration > notificationGeneration);
        if (this.info.version !== "2.5.6") { this.setState("protocol_mismatch", "kuma_protocol_mismatch"); throw new BridgeError("kuma_protocol_mismatch"); }
        this.setState("ready");
        return { state: "bound", revision: this.revision() };
    }
    async emitAck(event, args = [], write = false) {
        if (!this.socket || !this.socket.connected) throw new BridgeError("kuma_bridge_unavailable");
        return new Promise((resolve, reject) => {
            let settled = false;
            const timer = setTimeout(() => {
                if (settled) return; settled = true;
                if (write) { try { this.socket.disconnect(); } catch (_) {} this.setState("stale", "kuma_write_outcome_unknown"); }
                reject(new BridgeError(write ? "kuma_write_outcome_unknown" : "kuma_timeout"));
            }, this.requestTimeout);
            const callback = (response) => { if (settled) return; settled = true; clearTimeout(timer); resolve(response); };
            try { this.socket.emit(event, ...args, callback); } catch (_) { clearTimeout(timer); settled = true; reject(new BridgeError("kuma_upstream_failed")); }
        });
    }
    async checked(event, args = [], write = false) { const value = await this.emitAck(event, args, write); if (!value || value.ok !== true) throw new BridgeError("kuma_upstream_failed"); return value; }
    requireReady() {
        if (this.authenticated && this.state === "ready") return;
        if (this.state === "unbound") throw new BridgeError("kuma_binding_required", 409);
        if (this.state === "auth_failed") throw new BridgeError("kuma_auth_failed", 401);
        throw new BridgeError("kuma_bridge_unavailable");
    }
    async waitFor(predicate) {
        const end = Date.now() + this.requestTimeout;
        while (!predicate()) {
            if (Date.now() >= end) throw new BridgeError("kuma_readback_failed");
            await new Promise((resolve) => setTimeout(resolve, 10));
        }
    }
    async refreshLists() {
        const generation = this.monitorGeneration; await this.checked("getMonitorList");
        await this.waitFor(() => this.monitorGeneration > generation);
        if (Object.keys(this.monitors).length > MAX_MONITORS) throw new BridgeError("kuma_capacity_exceeded");
    }
    revision() { return hash(revisionValue(this.monitors, this.notifications)); }
    snapshot() {
        const rows = Object.values(this.monitors).slice(0, MAX_MONITORS).map((r) => monitorSummary(r, this.heartbeats, this.avgPing, this.uptime)).sort((a, b) => a.name.localeCompare(b.name, "zh-CN") || a.id - b.id);
        return { state: this.state, error_code: this.errorCode, revision: this.authenticated ? this.revision() : null, version: text(this.info.version || this.info.latestVersion, 32), connection: { state: this.state, checked_at: this.checkedAt, detail: this.errorCode }, monitors: this.authenticated ? rows : [], groups: this.authenticated ? rows.filter((r) => r.type === "group").map((r) => ({ id: r.id, name: r.name, active: r.active, children_ids: r.children_ids })) : [], notifications: this.authenticated ? this.notifications.map(notificationSummary) : [] };
    }
    async monitorDetail(params) {
        this.requireReady(); const id = int(params && params.id, 1, 2147483647), value = await this.checked("getMonitor", [id]);
        if (!value.monitor) throw new BridgeError("kuma_not_found", 404);
        return { state: "ok", revision: this.revision(), monitor: monitorDetail(value.monitor) };
    }
    async monitorHistory(params) {
        this.requireReady(); const id = int(params && params.id, 1, 2147483647), hours = int((params && params.hours) || 24, 1, 720), limit = int((params && params.limit) || 200, 1, MAX_HISTORY);
        if (!this.monitors[String(id)] && !this.monitors[id]) throw new BridgeError("kuma_not_found", 404);
        const [beatsValue, chartValue] = await Promise.all([this.checked("getMonitorBeats", [id, hours]), this.checked("getMonitorChartData", [id, hours])]);
        const beats = (Array.isArray(beatsValue.data) ? beatsValue.data : []).slice(-limit).map((r) => ({ time: text(r.time, 64), status: statusName(r.status), ping: Number.isFinite(Number(r.ping)) ? Number(r.ping) : null, duration: Number.isFinite(Number(r.duration)) ? Number(r.duration) : null, important: Boolean(r.important), msg: text(r.msg || "", 1000) }));
        const chart = (Array.isArray(chartValue.data) ? chartValue.data : []).slice(-limit).map((r) => Array.isArray(r) ? r.slice(0, 8).map((v) => typeof v === "string" ? text(v, 128) : v) : (r && typeof r === "object" ? Object.fromEntries(["timestamp", "time", "value", "uptime", "down", "maintenance"].filter((k) => r[k] !== undefined).map((k) => [k, r[k]])) : r));
        return { state: "ok", monitor_id: id, hours, beats, chart };
    }
    async monitorCreate(params) {
        this.requireReady(); const monitor = defaultMonitor(params && params.monitor || {}), result = await this.checked("add", [monitor], true), id = int(result.monitorID, 1, 2147483647), detail = await this.checked("getMonitor", [id]);
        if (!detail.monitor) throw new BridgeError("kuma_readback_failed"); this.monitors[String(id)] = copy(detail.monitor);
        return { state: "ok", revision: this.revision(), readback: monitorDetail(detail.monitor) };
    }
    async monitorUpdate(params) {
        this.requireReady(); const id = int(params && params.id, 1, 2147483647), current = await this.checked("getMonitor", [id]);
        if (!current.monitor) throw new BridgeError("kuma_not_found", 404);
        const monitor = applyMonitorPatch(current.monitor, params.patch || {}); monitor.id = id; await this.checked("editMonitor", [monitor], true);
        const detail = await this.checked("getMonitor", [id]); if (!detail.monitor) throw new BridgeError("kuma_readback_failed"); this.monitors[String(id)] = copy(detail.monitor);
        return { state: "ok", revision: this.revision(), readback: monitorDetail(detail.monitor) };
    }
    async monitorToggle(params, active) {
        this.requireReady(); const id = int(params && params.id, 1, 2147483647); await this.checked(active ? "resumeMonitor" : "pauseMonitor", [id], true);
        const detail = await this.checked("getMonitor", [id]); if (!detail.monitor || Boolean(detail.monitor.active) !== active) throw new BridgeError("kuma_readback_failed"); this.monitors[String(id)] = copy(detail.monitor);
        return { state: "ok", revision: this.revision(), readback: monitorDetail(detail.monitor) };
    }
    async monitorDelete(params) {
        this.requireReady(); const id = int(params && params.id, 1, 2147483647), deleteChildren = Boolean(params && params.delete_children); await this.checked("deleteMonitor", [id, deleteChildren], true); await this.refreshLists();
        if (this.monitors[String(id)] || this.monitors[id]) throw new BridgeError("kuma_readback_failed");
        return { state: "ok", revision: this.revision(), readback: { id, deleted: true, delete_children: deleteChildren } };
    }
    findNotification(id) { return this.notifications.find((r) => Number(r.id) === Number(id)) || null; }
    notificationDetail(params) {
        this.requireReady(); const id = int(params && params.id, 1, 2147483647), row = this.findNotification(id); if (!row) throw new BridgeError("kuma_not_found", 404);
        return { state: "ok", revision: this.revision(), notification: notificationDetailValue(row) };
    }
    async notificationSave(params, creating) {
        this.requireReady(); const id = creating ? null : int(params && params.id, 1, 2147483647), row = creating ? null : this.findNotification(id); if (!creating && !row) throw new BridgeError("kuma_not_found", 404);
        const config = validateWebhook(params && (params.notification || params.patch) || {}, row ? notificationConfig(row) : null), generation = this.notificationGeneration;
        const result = await this.checked("addNotification", [config, id], true), savedID = int(result.id || id, 1, 2147483647);
        await this.waitFor(() => this.notificationGeneration > generation && Boolean(this.findNotification(savedID)));
        const saved = this.findNotification(savedID); if (!saved) throw new BridgeError("kuma_readback_failed");
        return { state: "ok", revision: this.revision(), readback: notificationSummary(saved) };
    }
    async notificationDelete(params) {
        this.requireReady(); const id = int(params && params.id, 1, 2147483647), generation = this.notificationGeneration; await this.checked("deleteNotification", [id], true);
        await this.waitFor(() => this.notificationGeneration > generation && !this.findNotification(id));
        if (this.findNotification(id)) throw new BridgeError("kuma_readback_failed"); return { state: "ok", revision: this.revision(), readback: { id, deleted: true } };
    }
    async notificationTest(params) {
        this.requireReady(); const id = params && params.id == null ? null : int(params.id, 1, 2147483647), row = id == null ? null : this.findNotification(id); if (id != null && !row) throw new BridgeError("kuma_not_found", 404);
        const config = validateWebhook(params && (params.notification || params.patch) || {}, row ? notificationConfig(row) : null), result = await this.checked("testNotification", [config], true);
        return { state: "ok", tested: true, message: text(result.msg || "", 512) };
    }
    async handle(action, params = {}) {
        if (!this.socket) await this.start();
        const handlers = {
            "internal.bind": () => this.bind(params), "kuma.snapshot": () => this.snapshot(),
            "kuma.monitor_detail": () => this.monitorDetail(params), "kuma.monitor_history": () => this.monitorHistory(params),
            "kuma.monitor_create": () => this.monitorCreate(params), "kuma.monitor_update": () => this.monitorUpdate(params),
            "kuma.monitor_pause": () => this.monitorToggle(params, false), "kuma.monitor_resume": () => this.monitorToggle(params, true), "kuma.monitor_delete": () => this.monitorDelete(params),
            "kuma.notification_detail": () => this.notificationDetail(params), "kuma.notification_create": () => this.notificationSave(params, true), "kuma.notification_update": () => this.notificationSave(params, false),
            "kuma.notification_delete": () => this.notificationDelete(params), "kuma.notification_test": () => this.notificationTest(params),
        };
        if (!handlers[action]) throw new BridgeError("kuma_action_unsupported", 404); return handlers[action]();
    }
    close() { if (this.socket) try { this.socket.removeAllListeners(); this.socket.disconnect(); } catch (_) {} this.socket = null; this.authenticated = false; }
}

async function runCli() {
    const bridge = new KumaBridge({ url: process.env.CENTER_KUMA_URL || "http://127.0.0.1:3001", tokenFile: process.env.CENTER_KUMA_TOKEN_FILE || "/data/unified/kuma-bridge.jwt", requestTimeout: Number(process.env.CENTER_KUMA_REQUEST_TIMEOUT_MS || 8000) });
    try { await bridge.start(); } catch (_) {}
    const input = readline.createInterface({ input: process.stdin, crlfDelay: Infinity, terminal: false }); let chain = Promise.resolve();
    input.on("line", (line) => { chain = chain.then(async () => {
        let request;
        try {
            if (line.length > 1024 * 1024) throw new BridgeError("kuma_request_too_large", 413); request = JSON.parse(line);
            if (!request || typeof request.id !== "string" || request.id.length > 96) throw new BridgeError("kuma_validation_failed", 400);
            const result = await bridge.handle(request.action, request.params || {}); process.stdout.write(`${JSON.stringify({ id: request.id, ok: true, result })}\n`);
        } catch (error) { const id = request && typeof request.id === "string" ? request.id.slice(0, 96) : null, code = error instanceof BridgeError ? error.code : "kuma_upstream_failed"; process.stdout.write(`${JSON.stringify({ id, ok: false, error: { code } })}\n`); }
    }); });
    const stop = () => { bridge.close(); process.exit(0); }; process.on("SIGTERM", stop); process.on("SIGINT", stop);
}

module.exports = { KumaBridge, BridgeError, monitorSummary, monitorDetail, notificationSummary, applyMonitorPatch, defaultMonitor, validateWebhook, safeUrl, localKumaUrl };
if (require.main === module) runCli().catch(() => process.exit(1));
