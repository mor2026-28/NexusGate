'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawnSync } = require('node:child_process');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-test-v26-'));
process.env.NG_DATA_FILE = path.join(tmpDir, 'nexusgate.json');
process.env.NG_SINGBOX_CONFIG = path.join(tmpDir, 'sing-box-config.json');
process.env.NG_ADMIN_USERNAME = 'ng_adminTest01';
process.env.NG_ADMIN_PASSWORD = 'StrongPassword123456';
process.env.NG_BASE_PATH = '/SecPath16Chars99/';

const { store, singbox, handleRequest } = require('../server');
const { REALITY_PRESETS, parseShareUriToOutbound } = require('../lib/protocols');
const { computeResetCycleKey } = require('../lib/singbox');

let server;
let baseUrl;
let cookie = '';
let csrf = '';

async function req(urlPath, options = {}) {
  const fullUrl = `${baseUrl}${urlPath}`;
  const headers = {
    ...(options.body && typeof options.body === 'string' ? { 'content-type': 'application/json' } : {}),
    ...(cookie ? { cookie } : {}),
    ...(csrf ? { 'x-csrf-token': csrf } : {}),
    ...(options.headers || {})
  };
  const res = await fetch(fullUrl, { ...options, headers, redirect: 'manual' });
  const setCookie = res.headers.get('set-cookie');
  if (setCookie) {
    cookie = setCookie.split(';')[0];
  }
  const text = await res.text();
  let json = null;
  try { json = JSON.parse(text); } catch { /* raw */ }
  return { status: res.status, headers: res.headers, text, json };
}

test.before(async () => {
  server = http.createServer(handleRequest);
  await new Promise((resolve) => server.listen(0, '127.0.0.1', resolve));
  const addr = server.address();
  baseUrl = `http://127.0.0.1:${addr.port}`;
});

test.after(async () => {
  if (server) await new Promise((resolve) => server.close(resolve));
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('1. Strict webBasePath security: bare IP:Port returns 404, only /SecPath16Chars99/ allows login', async () => {
  const bareRes = await req('/');
  assert.equal(bareRes.status, 404);

  const loginRes = await req('/SecPath16Chars99/api/auth/login', {
    method: 'POST',
    body: JSON.stringify({ username: 'ng_adminTest01', password: 'StrongPassword123456' })
  });
  assert.equal(loginRes.status, 200);
  assert.equal(loginRes.json.authenticated, true);
  csrf = loginRes.json.csrf;
});

test('2. Reality SNI excludes Cloudflare/Microsoft & Reality never gets certificate_path, TLS gets valid cert', async () => {
  for (const preset of REALITY_PRESETS) {
    assert.ok(!/cloudflare|microsoft|bing/i.test(preset.serverName), `Forbidden SNI in presets: ${preset.serverName}`);
  }

  const presets = ['vless-reality', 'anytls', 'hysteria2', 'ss2022-128', 'ss2022-256', 'ss-128', 'socks'];
  let portBase = 31000;

  for (const p of presets) {
    portBase += 1;
    const payload = {
      remark: `Node-${p}`,
      port: portBase,
      protocol: p.startsWith('ss') ? 'shadowsocks' : (p === 'vless-reality' ? 'vless' : p),
      security: p === 'vless-reality' ? 'reality' : (['anytls', 'hysteria2'].includes(p) ? 'tls' : 'none'),
      method: p === 'ss2022-256' ? '2022-blake3-aes-256-gcm' : (p === 'ss-128' ? 'aes-128-gcm' : '2022-blake3-aes-128-gcm'),
      ...(p === 'vless-reality' ? { reality: { serverName: 'www.cloudflare.com', target: 'www.cloudflare.com:443' } } : {}),
      limitIp: 2,
      limitDevice: 5,
      totalGB: 100,
      resetDay: 15,
      expiryTime: Date.now() + 30 * 86400000
    };
    const createRes = await req('/SecPath16Chars99/api/inbounds', {
      method: 'POST',
      body: JSON.stringify(payload)
    });
    assert.equal(createRes.status, 201);
    const inb = createRes.json.inbound;
    assert.equal(inb.limitIp, 2);
    assert.equal(inb.limitDevice, 5);
    assert.equal(inb.resetDay, 15);
    assert.ok(inb.expiryTime > Date.now());
    assert.ok(inb.links.length > 0);

    if (p === 'vless-reality') {
      assert.equal(inb.reality.serverName, 'www.apple.com', 'Cloudflare SNI should automatically normalize to www.apple.com');
      assert.equal(inb.reality.target, 'www.apple.com:443');
    }

    for (const link of inb.links) {
      assert.ok(!link.uri.includes('www.bing.com'));
      assert.ok(!link.uri.includes('www.cloudflare.com'));
      const parsedOut = parseShareUriToOutbound(link.uri);
      assert.equal(parsedOut.port, portBase);
    }
  }

  const { config } = singbox.writeConfig();
  assert.equal(config.dns, undefined, 'Server config should omit deprecated legacy DNS block');
  assert.equal(config.log.level, 'warn', 'Default log level should be warn');

  const realityInb = config.inbounds.find((i) => i.type === 'vless' && i.tls?.reality?.enabled);
  assert.ok(realityInb, 'Reality inbound should exist in Sing-box config');
  assert.equal(realityInb.tls.certificate_path, undefined, 'Reality inbound MUST NEVER have certificate_path');
  assert.equal(realityInb.tls.key_path, undefined, 'Reality inbound MUST NEVER have key_path');
  assert.equal(realityInb.tls.server_name, 'www.apple.com');

  const anytlsInb = config.inbounds.find((i) => i.type === 'anytls');
  assert.ok(anytlsInb, 'AnyTLS inbound should exist');
  assert.ok(anytlsInb.tls.certificate_path && fs.existsSync(anytlsInb.tls.certificate_path), 'AnyTLS inbound must have existing certificate_path');
});

test('3. Monthly automatic traffic reset (resetDay 1..31), batch operations, and system memory/log cleanup', async () => {
  const targetInb = store.state.inbounds[0];
  targetInb.resetDay = 15;
  targetInb.lastResetCycle = computeResetCycleKey(15, new Date('2026-11-16T10:00:00Z'));
  targetInb.up = 50 * (1024 ** 3);
  targetInb.down = 60 * (1024 ** 3);
  targetInb.enable = false;
  targetInb.disabledReason = 'quota';
  targetInb.expiryTime = 0;

  const res = singbox.checkAndResetMonthlyTraffic(new Date('2026-12-15T00:05:00Z'));
  assert.ok(res.resetCount >= 1);
  assert.equal(targetInb.up, 0);
  assert.equal(targetInb.down, 0);
  assert.equal(targetInb.enable, true);
  assert.equal(targetInb.lastResetCycle, '2026-12');

  targetInb.up = 123456;
  const batchRes = await req('/SecPath16Chars99/api/inbounds/batch', {
    method: 'POST',
    body: JSON.stringify({ action: 'reset-all-traffic' })
  });
  assert.equal(batchRes.status, 200);
  assert.ok(batchRes.json.count >= 1);
  assert.equal(targetInb.up, 0);

  const cleanRes = await req('/SecPath16Chars99/api/system/cleanup', { method: 'POST' });
  assert.equal(cleanRes.status, 200);
  assert.ok(Array.isArray(cleanRes.json.result.actions));
});

test('4. High-entropy subToken security (/sub/all returns 404) & clean CLI --show-info without username/subscription', async () => {
  const subAllRes = await req('/sub/all?format=clash');
  assert.equal(subAllRes.status, 404, '/sub/all must be rejected with 404 to prevent scanning/leaks');

  const subToken = store.state.settings.subToken;
  assert.ok(subToken && subToken.length >= 16 && subToken !== 'all', 'settings.subToken must be a high-entropy token');

  const subRes = await req(`/sub/${subToken}?format=clash`);
  assert.equal(subRes.status, 200);
  assert.ok(subRes.headers.get('subscription-userinfo').includes('total='));
  assert.ok(subRes.text.includes('port: 7890'));
  assert.ok(subRes.text.includes('socks-port: 7891'));
  assert.ok(subRes.text.includes('🔰 节点选择'));
  assert.ok(subRes.text.includes('♻️ 自动选择'));
  assert.ok(subRes.text.includes('🤖 AI 专线'));
  assert.ok(subRes.text.includes('DOMAIN-SUFFIX,openai.com,🤖 AI 专线'));
  assert.ok(subRes.text.includes('DOMAIN-SUFFIX,google.com,🔰 节点选择'));
  assert.ok(subRes.text.includes('GEOIP,CN,🎯 全球直连,no-resolve'));

  // Test default CLI --show-info (must omit 登录账号 and 聚合订阅)
  const cliInfo = spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js'), '--show-info'], {
    env: { ...process.env, NG_DATA_FILE: path.join(tmpDir, 'nexusgate.json') },
    encoding: 'utf8'
  });
  assert.equal(cliInfo.status, 0);
  assert.ok(cliInfo.stdout.includes('访问地址'));
  assert.ok(cliInfo.stdout.includes('面板端口'));
  assert.ok(cliInfo.stdout.includes('安全路径'));
  assert.ok(!cliInfo.stdout.includes('登录账号'), '--show-info should NOT display 登录账号');
  assert.ok(!cliInfo.stdout.includes('聚合订阅'), '--show-info should NOT display 聚合订阅');
});

test('5. E2E Lossless Migration of Universal 3x-ui / X-Panel .tar.gz Archive (with sublink.db, x-ui.db, /root/cert, WS+TLS & Reality)', async () => {
  const archiveBuildDir = path.join(tmpDir, 'archive_src');
  fs.mkdirSync(path.join(archiveBuildDir, 'etc', 'x-ui'), { recursive: true });
  fs.mkdirSync(path.join(archiveBuildDir, 'usr', 'local', 'bin', 'sublink', 'db'), { recursive: true });

  const sublinkDbPath = path.join(archiveBuildDir, 'usr', 'local', 'bin', 'sublink', 'db', 'sublink.db');
  const xuiDbPath = path.join(archiveBuildDir, 'etc', 'x-ui', 'x-ui.db');
  const tarGzPath = path.join(tmpDir, '3xui_universal_backup.tar.gz');

  const pyGen = `
import sqlite3, json, sys

# Create dummy sublink.db (no inbounds table) to ensure findXuiDbInDir ignores it
c1 = sqlite3.connect(sys.argv[1])
c1.execute("CREATE TABLE sub_logs (id INTEGER PRIMARY KEY, name TEXT)")
c1.commit()
c1.close()

conn = sqlite3.connect(sys.argv[2])
cur = conn.cursor()
cur.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, user_id INT, up INT, down INT, total INT, remark TEXT, enable INT, expiry_time INT, traffic_reset TEXT, listen TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT, sniffing TEXT)")
cur.execute("CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INT, enable INT, email TEXT, up INT, down INT, expiry_time INT, total INT)")
cur.execute("CREATE TABLE outbound_traffics (id INTEGER PRIMARY KEY, tag TEXT, up INT, down INT, total INT)")
cur.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")

for i in range(1, 41):
    port = 40000 + i
    tag = f"inbound-{port}"
    if i % 4 == 0:
        proto = "vless"
        settings = {"clients": [{"id": f"11111111-2222-4333-8444-{i:012d}", "flow": "xtls-rprx-vision", "email": f"vless_user_{i}", "limitIp": 3, "totalGB": 100 * (1024**3), "expiryTime": 1893456000000, "enable": True, "subId": f"sub_{i}"}], "decryption": "none"}
        stream = {"network": "tcp", "security": "reality", "realitySettings": {"dest": "www.tesla.com:443", "serverNames": ["tesla.com", "www.tesla.com"], "privateKey": "cHJpdmF0ZWtleXplaceholder", "shortIds": ["1a2b3c4d"], "settings": {"publicKey": "cHVibGlja2V5placeholder", "fingerprint": "chrome"}}}
    elif i % 4 == 1:
        proto = "vless"
        settings = {"clients": [{"id": f"22222222-3333-4444-8555-{i:012d}", "flow": "", "email": f"vless_ws_{i}", "enable": True}], "decryption": "none"}
        stream = {"network": "ws", "security": "tls", "tlsSettings": {"serverName": "", "alpn": ["h2", "http/1.1"], "certificates": [{"certificateFile": "/root/cert/node.example.com/fullchain.pem", "keyFile": "/root/cert/node.example.com/privkey.pem"}]}, "wsSettings": {"path": "/ws-test", "headers": {}}}
    elif i % 4 == 2:
        proto = "shadowsocks"
        settings = {"method": "2022-blake3-aes-128-gcm", "password": "MTIzNDU2Nzg5MDEyMzQ1Ng==", "network": "tcp,udp", "clients": [{"password": "YWJjZGVmZ2hpamtsbW5vcA==", "email": f"ss2022_{i}", "enable": True}]}
        stream = {"network": "tcp", "security": "none"}
    else:
        proto = "mixed"
        settings = {"auth": "password", "accounts": [{"user": f"socks_u_{i}", "pass": f"socks_p_{i}"}], "udp": True}
        stream = {"network": "tcp", "security": "none"}

    cur.execute(
        "INSERT INTO inbounds VALUES (?, 1, ?, ?, ?, ?, 1, 1893456000000, 'monthly', '', ?, ?, ?, ?, ?, '{}')",
        (i, i * 1024, i * 2048, 100 * (1024**3), f"Node-{i}", port, proto, json.dumps(settings), json.dumps(stream), tag)
    )

outbounds = [
    {"tag": "direct", "protocol": "freedom", "settings": {}},
    {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    {"tag": "api", "protocol": "blackhole", "settings": {}},
    {"tag": "relay-node-1", "protocol": "shadowsocks", "settings": {"servers": [{"address": "198.51.100.10", "port": 15001, "method": "aes-256-gcm", "password": "pass1", "uot": True}]}},
    {"tag": "relay-node-2", "protocol": "shadowsocks", "settings": {"servers": [{"address": "198.51.100.11", "port": 15002, "method": "2022-blake3-aes-128-gcm", "password": "pass2"}]}},
    {"tag": "relay-vless-flat", "protocol": "vless", "settings": {"address": "198.51.100.88", "port": 443, "id": "99999999-8888-4777-8666-555555555555", "flow": "xtls-rprx-vision", "encryption": "none"}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "www.apple.com", "publicKey": "pbk123", "shortId": "1a2b"}, "sockopt": {"dialerProxy": "relay-node-1"}}}
]

rules = [
    {"type": "field", "inboundTag": ["inbound-40001"], "outboundTag": "relay-node-1"},
    {"type": "field", "inboundTag": ["inbound-40002"], "outboundTag": "relay-node-2"},
    {"type": "field", "inboundTag": ["inbound-40004"], "outboundTag": "relay-vless-flat"}
]

cur.execute("INSERT INTO outbound_traffics VALUES (1, 'relay-node-1', 10485760, 20971520, 31457280)")
cur.execute("INSERT INTO settings VALUES (1, 'xrayTemplateConfig', ?)", (json.dumps({"outbounds": outbounds, "routing": {"rules": rules}}),))
conn.commit()
conn.close()
`;
  const pyRun = spawnSync('python3', ['-c', pyGen, sublinkDbPath, xuiDbPath], { encoding: 'utf8' });
  assert.equal(pyRun.status, 0, pyRun.stderr);

  const tarRun = spawnSync('tar', ['-czf', tarGzPath, '-C', archiveBuildDir, 'usr/local/bin/sublink/db/sublink.db', 'etc/x-ui/x-ui.db']);
  assert.equal(tarRun.status, 0);

  const tarBuf = fs.readFileSync(tarGzPath);
  const migRes = await req('/SecPath16Chars99/api/migrate/3xui?mode=replace', {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: tarBuf
  });
  assert.equal(migRes.status, 200);
  assert.equal(migRes.json.summary.inboundsCount, 40, 'Must locate x-ui.db inside .tar.gz even when sublink.db is present');
  assert.equal(migRes.json.summary.outboundsCount, 3);

  const inbRes = await req('/SecPath16Chars99/api/inbounds');
  assert.equal(inbRes.status, 200);
  const wsInbound = inbRes.json.inbounds.find((i) => i.port === 40001);
  assert.equal(wsInbound.tlsDomain, 'node.example.com', 'Empty serverName in 3x-ui WS+TLS should infer domain from /root/cert/<domain>/fullchain.pem');
  assert.ok(wsInbound.links[0].uri.includes('sni=node.example.com'));
  assert.ok(wsInbound.links[0].uri.includes('type=ws'));

  const realityInbound = inbRes.json.inbounds.find((i) => i.port === 40004);
  assert.equal(realityInbound.reality.serverName, 'tesla.com', 'Migrated Reality node must preserve its existing SNI so existing clients are not broken');

  const { config } = singbox.writeConfig();
  const sbWsInb = config.inbounds.find((i) => i.listen_port === 40001);
  assert.deepEqual(sbWsInb.tls.alpn, ['http/1.1'], 'WS+TLS inbound in Sing-box must force alpn: ["http/1.1"] so WebSocket Upgrade works');

  const heapUsedMB = Math.round(process.memoryUsage().heapUsed / (1024 * 1024));
  assert.ok(heapUsedMB < 90, `Heap used (${heapUsedMB} MB) should stay well below 90MB`);
});
