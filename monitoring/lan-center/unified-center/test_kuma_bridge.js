"use strict";
const assert = require("assert");
const { EventEmitter } = require("events");
const fs = require("fs");
const os = require("os");
const path = require("path");
const { KumaBridge, defaultMonitor, validateWebhook, safeUrl, localKumaUrl } = require("./kuma_bridge");

class FakeSocket extends EventEmitter {
    constructor(state, delay = 0) { super(); this.state = state; this.connected = false; this.delay = delay; }
    server(event, ...args) { return EventEmitter.prototype.emit.call(this, event, ...args); }
    connect() { this.connected = true; setImmediate(() => { this.server("info", { version: this.state.version || "2.5.6" }); this.server("connect"); }); }
    disconnect() { const was = this.connected; this.connected = false; if (was) this.server("disconnect", "client"); }
    emit(event, ...args) {
        const callback = typeof args[args.length - 1] === "function" ? args.pop() : () => {};
        const reply = (value) => setTimeout(() => callback(value), this.delay);
        const s = this.state;
        if (event === "loginByToken") { this.server("monitorList", structuredClone(s.monitors)); this.server("notificationList", structuredClone(s.notifications)); return reply({ ok: args[0] === "valid-token" }); }
        if (event === "login") { this.server("monitorList", structuredClone(s.monitors)); this.server("notificationList", structuredClone(s.notifications)); return reply(args[0].password === "correct" ? { ok: true, token: "valid-token" } : { ok: false }); }
        if (event === "getMonitorList") { setTimeout(() => this.server("monitorList", structuredClone(s.monitors)), s.monitorListDelay || 0); return reply({ ok: true }); }
        if (event === "getMonitor") return reply(s.monitors[args[0]] ? { ok: true, monitor: structuredClone(s.monitors[args[0]]) } : { ok: false });
        if (event === "getMonitorBeats") return reply({ ok: true, data: [{ monitor_id: args[0], time: "2026-10-28 10:00:00", status: 1, ping: 12, msg: "200 OK" }] });
        if (event === "getMonitorChartData") return reply({ ok: true, data: [{ timestamp: 1, uptime: 1 }] });
        if (event === "add") { const id = ++s.last; s.monitors[id] = { ...structuredClone(args[0]), id, childrenIDs: [] }; this.server("updateMonitorIntoList", { [id]: structuredClone(s.monitors[id]) }); return reply({ ok: true, monitorID: id }); }
        if (event === "editMonitor") { s.monitors[args[0].id] = structuredClone(args[0]); this.server("updateMonitorIntoList", { [args[0].id]: structuredClone(args[0]) }); return reply({ ok: true }); }
        if (event === "pauseMonitor" || event === "resumeMonitor") { s.monitors[args[0]].active = event === "resumeMonitor"; this.server("updateMonitorIntoList", { [args[0]]: structuredClone(s.monitors[args[0]]) }); return reply({ ok: true }); }
        if (event === "deleteMonitor") { delete s.monitors[args[0]]; this.server("deleteMonitorFromList", args[0]); return reply({ ok: true }); }
        if (event === "addNotification") { const id = args[1] || ++s.lastNotice, c = structuredClone(args[0]); s.notifications = s.notifications.filter((n) => n.id !== id).concat({ id, name: c.name, active: c.active, isDefault: c.isDefault, config: JSON.stringify(c) }); setTimeout(() => this.server("notificationList", structuredClone(s.notifications)), s.notificationListDelay || 0); return reply({ ok: true, id }); }
        if (event === "deleteNotification") { s.notifications = s.notifications.filter((n) => n.id !== args[0]); setTimeout(() => this.server("notificationList", structuredClone(s.notifications)), s.notificationListDelay || 0); return reply({ ok: true }); }
        if (event === "testNotification") return reply({ ok: true, msg: "Sent Successfully." });
        return reply({ ok: false });
    }
}

function fixture() {
    const state = {
        last: 2, lastNotice: 1,
        monitors: {
            1: { id: 1, type: "http", name: "主页", description: "旧描述", active: true, parent: 2, childrenIDs: [], url: "https://user:pass@example.test/?token=abc&x=1", method: "GET", interval: 60, retryInterval: 60, resendInterval: 0, maxretries: 0, timeout: 48, notificationIDList: { 1: true }, accepted_statuscodes: ["200-299"], headers: "{\"Authorization\":\"Bearer secret\"}", body: "", kafkaProducerBrokers: [], kafkaProducerSaslOptions: { mechanism: "None" }, conditions: [], rabbitmqNodes: [] },
            2: { id: 2, type: "group", name: "业务", active: true, parent: null, childrenIDs: [1], interval: 60, retryInterval: 60, resendInterval: 0, maxretries: 0, timeout: 48, notificationIDList: {}, accepted_statuscodes: ["200-299"], kafkaProducerBrokers: [], kafkaProducerSaslOptions: { mechanism: "None" }, conditions: [], rabbitmqNodes: [] },
        },
        notifications: [{ id: 1, name: "企业微信", active: true, isDefault: false, config: JSON.stringify({ name: "企业微信", type: "webhook", active: true, isDefault: false, webhookURL: "https://notify.test/?token=secret", httpMethod: "post", webhookContentType: "json", webhookAdditionalHeaders: "{\"Authorization\":\"secret\"}" }) }],
    };
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kuma-bridge-")), token = path.join(dir, "token"); fs.writeFileSync(token, "valid-token", { mode: 0o600 });
    const socket = new FakeSocket(state); return { state, socket, token, bridge: new KumaBridge({ ioFactory: () => socket, tokenFile: token, requestTimeout: 200 }) };
}

async function testNativeLifecycle() {
    const f = fixture(); await f.bridge.start();
    const snap = f.bridge.snapshot(); assert.equal(snap.state, "ready"); assert.equal(snap.monitors.length, 2); assert.equal(snap.groups.length, 1); assert.equal(snap.notifications.length, 1); assert(!JSON.stringify(snap).includes("Bearer secret")); assert(!JSON.stringify(snap).includes("notify.test"));
    const detail = await f.bridge.monitorDetail({ id: 1 }); assert.deepEqual(detail.monitor.has_secret_fields, ["headers", "url"]); assert(!JSON.stringify(detail).includes("Bearer")); assert.equal(detail.monitor.url, "[redacted-url-hidden]");
    const before = f.bridge.revision(); f.socket.server("heartbeatList", 1, [{ time: "now", status: 0, ping: 99 }], true); f.socket.server("avgPing", 1, 55); f.socket.server("uptime", 1, 24, 0.99); assert.equal(f.bridge.revision(), before, "runtime beats must not churn config revision"); assert.equal(f.bridge.snapshot().monitors.find((m) => m.id === 1).uptime_24h, 0.99);
    const history = await f.bridge.monitorHistory({ id: 1, hours: 24, limit: 10 }); assert.equal(history.beats[0].status, "up"); assert.equal(history.chart.length, 1);
    const originalURL = f.state.monitors[1].url;
    await f.bridge.monitorUpdate({ id: 1, patch: { name: "新主页", headers: "", url: "https://example.test/?token=%5Bhidden%5D" } }); assert.equal(f.state.monitors[1].name, "新主页"); assert.equal(f.state.monitors[1].url, originalURL, "redacted URL must never overwrite the real tokenized target"); assert(f.state.monitors[1].headers.includes("Authorization"), "blank secret preserves existing value");
    await f.bridge.monitorUpdate({ id: 1, patch: { headers: "", clear_secret_fields: ["headers"] } }); assert.equal(f.state.monitors[1].headers, "");
    await f.bridge.monitorUpdate({ id: 1, patch: { description: "", parent: null, notificationIDList: {} } }); assert.equal(f.state.monitors[1].description, ""); assert.equal(f.state.monitors[1].parent, null); assert.deepEqual(f.state.monitors[1].notificationIDList, {});
    const created = await f.bridge.monitorCreate({ monitor: { type: "ping", name: "路由器", hostname: "10.88.0.1" } }); assert.equal(created.readback.type, "ping");
    await f.bridge.monitorToggle({ id: created.readback.id }, false); assert.equal(f.state.monitors[created.readback.id].active, false);
    await f.bridge.monitorToggle({ id: created.readback.id }, true); assert.equal(f.state.monitors[created.readback.id].active, true);
    f.state.monitorListDelay = 60; const deleteStarted = Date.now(); await f.bridge.monitorDelete({ id: created.readback.id }); assert(!f.state.monitors[created.readback.id]); assert(Date.now() - deleteStarted >= 45, "delete readback must wait for delayed monitorList event");
    const dns = await f.bridge.monitorCreate({ monitor: { type: "dns", name: "DNS", hostname: "example.test", dns_resolve_server: "1.1.1.1" } }); await f.bridge.monitorUpdate({ id: dns.readback.id, patch: { dns_resolve_server: "" } }); assert.equal(f.state.monitors[dns.readback.id].dns_resolve_server, ""); await f.bridge.monitorDelete({ id: dns.readback.id });
    f.state.notificationListDelay = 60;
    const noticeStarted = Date.now(), notice = await f.bridge.notificationSave({ notification: { name: "测试", type: "webhook", webhookURL: "https://notify.test/hook", httpMethod: "post", webhookContentType: "json" } }, true); assert.equal(notice.readback.type, "webhook"); assert(Date.now() - noticeStarted >= 45, "readback must wait for delayed notificationList event");
    await f.bridge.notificationSave({ id: notice.readback.id, patch: { name: "测试2", webhookURL: "" } }, false); assert.equal(JSON.parse(f.state.notifications.find((n) => n.id === notice.readback.id).config).webhookURL, "https://notify.test/hook");
    const notificationDetail = f.bridge.notificationDetail({ id: notice.readback.id }); assert.equal(notificationDetail.notification.http_method, "post"); assert(!JSON.stringify(notificationDetail).includes("notify.test/hook"));
    assert.equal((await f.bridge.notificationTest({ id: notice.readback.id, patch: {} })).tested, true);
    await f.bridge.notificationDelete({ id: notice.readback.id }); f.bridge.close();
}

async function testBindingAndTimeout() {
    const dir = fs.mkdtempSync(path.join(os.tmpdir(), "kuma-bind-")), token = path.join(dir, "token"), state = { monitors: {}, notifications: [], last: 0, lastNotice: 0 }, socket = new FakeSocket(state);
    const bridge = new KumaBridge({ ioFactory: () => socket, tokenFile: token, requestTimeout: 100 }); await bridge.start(); assert.equal(bridge.snapshot().state, "unbound");
    const result = await bridge.bind({ username: "admin", password: "correct" }); assert.equal(result.state, "bound"); assert.equal(fs.readFileSync(token, "utf8"), "valid-token"); if (process.platform !== "win32") assert.equal(fs.statSync(token).mode & 0o077, 0);
    bridge.close();
    const slow = new FakeSocket(state, 100), timeoutBridge = new KumaBridge({ ioFactory: () => slow, tokenFile: token, requestTimeout: 20 }); await timeoutBridge.start().catch(() => {});
    assert.notEqual(timeoutBridge.snapshot().state, "ready", "auth deadline is bounded"); timeoutBridge.close();
    const mismatchState = { monitors: {}, notifications: [], last: 0, lastNotice: 0, version: "2.6.0" }, mismatchSocket = new FakeSocket(mismatchState), mismatchBridge = new KumaBridge({ ioFactory: () => mismatchSocket, tokenFile: token, requestTimeout: 100 });
    await mismatchBridge.start(); assert.equal(mismatchBridge.snapshot().state, "protocol_mismatch"); assert.equal(mismatchBridge.snapshot().error_code, "kuma_protocol_mismatch"); mismatchBridge.close();
}

function testValidation() {
    assert.equal(defaultMonitor({ type: "dns", name: "DNS", hostname: "example.com" }).port, 53);
    assert.throws(() => defaultMonitor({ type: "shell", name: "bad" }), /kuma_monitor_type_unsupported/);
    assert.equal(validateWebhook({ name: "w", type: "webhook", webhookURL: "https://example.test" }).httpMethod, "post");
    assert.equal(safeUrl("not a url?token=actual-secret"), "[invalid-url-hidden]");
    assert.equal(safeUrl("https://user:pass@example.test/path"), "[redacted-url-hidden]");
    assert.equal(safeUrl("https://example.test/path?token=actual-secret"), "[redacted-url-hidden]");
    assert.equal(safeUrl("https://example.test/path?lang=zh"), "https://example.test/path?lang=zh");
    assert.equal(localKumaUrl("http://127.0.0.1:3001"), "http://127.0.0.1:3001");
    assert.throws(() => localKumaUrl("http://example.com:3001"), /kuma_bridge_url_invalid/);
}

(async () => { testValidation(); await testNativeLifecycle(); await testBindingAndTimeout(); process.stdout.write("kuma_bridge: 3 suites passed\n"); })().catch((error) => { process.stderr.write(`${error.stack}\n`); process.exit(1); });
