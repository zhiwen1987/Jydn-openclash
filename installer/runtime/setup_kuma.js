// Use Kuma's own socket API; never write its database or reset an existing user.
const fs = require('fs');
const { io } = require('/app/node_modules/socket.io-client');
const file = '/data/setup-kuma.private.json';
const status = '/data/setup-kuma.status.json';
const socket = io('http://127.0.0.1:3001', { reconnection: true, timeout: 5000 });
let running = false;
let monitors;
socket.on('monitorList', value => { monitors = value; });
const deadline = setTimeout(() => finish(false, 'setup_timeout'), 180000);
function write(value) {
  fs.writeFileSync(status + '.tmp', JSON.stringify(value), { mode: 0o600 });
  fs.renameSync(status + '.tmp', status);
}
function finish(ok, reason) {
  write({ ok, reason, epoch: Math.floor(Date.now() / 1000) });
  if (ok && fs.existsSync(file)) fs.unlinkSync(file);
  clearTimeout(deadline); socket.disconnect(); process.exit(ok ? 0 : 1);
}
async function call(event, ...args) {
  return await socket.timeout(30000).emitWithAck(event, ...args);
}
socket.on('connect', async () => {
  if (running) return;
  running = true;
  try {
    const credentials = JSON.parse(fs.readFileSync(file, 'utf8'));
    if (!credentials.username || !credentials.password) return finish(false, 'credentials_missing');
    // An already initialized instance rejects setup; authenticate normally then.
    await call('setup', credentials.username, credentials.password);
    const login = await call('login', { username: credentials.username, password: credentials.password, token: '' });
    if (!login?.ok) return finish(false, 'authentication_failed');
    for (let i = 0; i < 20 && monitors === undefined; i++) await new Promise(resolve => setTimeout(resolve, 100));
    if (monitors === undefined) return finish(false, 'monitor_inventory_unavailable');
    const definitions = [
      ['中心控制服务', 'http://127.0.0.1:8080/health'],
      ['节点能力检测服务', 'http://127.0.0.1:8081/health'],
      ['订阅与自建节点服务', 'http://127.0.0.1:8082/health'],
    ];
    for (const [name, url] of definitions) {
      if (Object.values(monitors).some(monitor => monitor.name === name && monitor.url === url)) continue;
      const result = await call('add', { name, url, type: 'http', method: 'GET', interval: 60, retryInterval: 30,
        resendInterval: 0, maxretries: 2, timeout: 15, active: 1, weight: 2000, maxredirects: 3,
        accepted_statuscodes: ['200-299'], notificationIDList: {}, ignoreTls: false, upsideDown: false,
        kafkaProducerBrokers: [], kafkaProducerSaslOptions: {}, conditions: [], rabbitmqNodes: [] });
      if (!result?.ok) return finish(false, 'monitor_creation_failed');
    }
    finish(true, 'initialized');
  } catch { finish(false, 'socket_api_failed'); }
});
