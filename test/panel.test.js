'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawnSync } = require('node:child_process');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-test-v23-'));
process.env.NG_DATA_FILE = path.join(tmpDir, 'nexusgate.json');
process.env.NG_SINGBOX_CONFIG = path.join(tmpDir, 'sing-box-config.json');
process.env.NG_ADMIN_USERNAME = 'ng_adminTest01';
process.env.NG_ADMIN_PASSWORD = 'StrongPassword123456';
process.env.NG_BASE_PATH = '/SecPath16Chars99/';

const { store, singbox, handleRequest } = require('../server');
const { isValidUuid, parseShareUriToOutbound, toSingboxInbound } = require('../lib/protocols');
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

test('2. Reality vs TLS isolation: Reality NEVER gets certificate_path, TLS gets valid cert, 0 deprecated DNS warnings', async () => {
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

    for (const link of inb.links) {
      assert.ok(!link.uri.includes('www.bing.com'));
      const parsedOut = parseShareUriToOutbound(link.uri);
      assert.equal(parsedOut.port, portBase);
    }
  }

  // Also test legacy full-Base64 ss:// URI parsing (ss://BASE64(method:pass@host:port)#tag)
  const legacySsB64 = Buffer.from('aes-256-gcm:MySecretPass123@198.247.0.52:44092').toString('base64');
  const parsedLegacySs = parseShareUriToOutbound(`ss://${legacySsB64}#SS-198.247.0.52`);
  assert.equal(parsedLegacySs.type, 'shadowsocks');
  assert.equal(parsedLegacySs.method, 'aes-256-gcm');
  assert.equal(parsedLegacySs.password, 'MySecretPass123');
  assert.equal(parsedLegacySs.server, '198.247.0.52');
  assert.equal(parsedLegacySs.port, 44092);

  // Verify generated sing-box config.json on disk!
  const { config } = singbox.writeConfig();
  assert.equal(config.dns, undefined, 'Server config should omit deprecated legacy DNS block');

  const realityInb = config.inbounds.find((i) => i.type === 'vless' && i.tls?.reality?.enabled);
  assert.ok(realityInb, 'Reality inbound should exist in Sing-box config');
  assert.equal(realityInb.tls.certificate_path, undefined, 'Reality inbound MUST NEVER have certificate_path');
  assert.equal(realityInb.tls.key_path, undefined, 'Reality inbound MUST NEVER have key_path');

  const anytlsInb = config.inbounds.find((i) => i.type === 'anytls');
  assert.ok(anytlsInb, 'AnyTLS inbound should exist');
  assert.ok(anytlsInb.tls.certificate_path && fs.existsSync(anytlsInb.tls.certificate_path), 'AnyTLS inbound must have existing certificate_path');
});

test('3. Monthly automatic traffic reset (resetDay 1..31) & quota auto-reenable', async () => {
  const targetInb = store.state.inbounds[0];
  targetInb.resetDay = 15;
  targetInb.lastResetCycle = computeResetCycleKey(15, new Date('2026-11-16T10:00:00Z'));
  targetInb.up = 50 * (1024 ** 3);
  targetInb.down = 60 * (1024 ** 3);
  targetInb.enable = false;
  targetInb.disabledReason = 'quota';
  targetInb.expiryTime = 0;

  // Simulate date reaching Dec 15, 2026
  const res = singbox.checkAndResetMonthlyTraffic(new Date('2026-12-15T00:05:00Z'));
  assert.ok(res.resetCount >= 1);
  assert.equal(targetInb.up, 0);
  assert.equal(targetInb.down, 0);
  assert.equal(targetInb.enable, true);
  assert.equal(targetInb.lastResetCycle, '2026-12');
});

test('4. Clash smart subscription template (AI + Foreign Trade + User Rules) & subscription-userinfo header', async () => {
  const subRes = await req('/sub/all?format=clash');
  assert.equal(subRes.status, 200);
  assert.ok(subRes.headers.get('subscription-userinfo').includes('total='));
  assert.ok(subRes.text.includes('port: 7890'));
  assert.ok(subRes.text.includes('socks-port: 7891'));
  assert.ok(subRes.text.includes('🔰 节点选择'));
  assert.ok(subRes.text.includes('♻️ 自动选择'));
  assert.ok(subRes.text.includes('🤖 AI 专线'));
  assert.ok(subRes.text.includes('🎥 NETFLIX'));
  assert.ok(subRes.text.includes('🌍 国外媒体'));
  assert.ok(subRes.text.includes('🐟 漏网之鱼'));
  assert.ok(subRes.text.includes('DOMAIN-SUFFIX,openai.com,🤖 AI 专线'));
  assert.ok(subRes.text.includes('DOMAIN-SUFFIX,google.com,🔰 节点选择'));
  assert.ok(subRes.text.includes('GEOIP,CN,🎯 全球直连,no-resolve'));
});

test('5. E2E Lossless Migration of 3x-ui SQLite Database (30 Inbounds + 10 Relay Outbounds + Routing Rules)', async () => {
  const dbPath = path.join(tmpDir, 'x-ui-production.db');
  const pyGen = `
import sqlite3, json, sys

conn = sqlite3.connect(sys.argv[1])
cur = conn.cursor()
cur.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, user_id INT, up INT, down INT, total INT, remark TEXT, enable INT, expiry_time INT, traffic_reset TEXT, listen TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT, sniffing TEXT)")
cur.execute("CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INT, enable INT, email TEXT, up INT, down INT, expiry_time INT, total INT)")
cur.execute("CREATE TABLE outbound_traffics (id INTEGER PRIMARY KEY, tag TEXT, up INT, down INT, total INT)")
cur.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")

# Generate 30 diverse 3x-ui inbounds
for i in range(1, 31):
    port = 40000 + i
    tag = f"inbound-{port}"
    if i % 4 == 0:
        proto = "vless"
        settings = {"clients": [{"id": f"11111111-2222-4333-8444-{i:012d}", "flow": "xtls-rprx-vision", "email": f"vless_user_{i}", "limitIp": 3, "totalGB": 100 * (1024**3), "expiryTime": 1893456000000, "enable": True, "subId": f"sub_{i}"}], "decryption": "none"}
        stream = {"network": "raw", "security": "reality", "realitySettings": {"target": "www.apple.com:443", "serverNames": ["www.apple.com"], "privateKey": "cHJpdmF0ZWtleXplaceholder", "shortIds": ["1a2b3c4d"], "settings": {"publicKey": "cHVibGlja2V5placeholder", "fingerprint": "chrome"}}}
    elif i % 4 == 1:
        proto = "shadowsocks"
        # Classic SS in 3x-ui: client.password differs from settings.password
        settings = {"method": "aes-256-gcm", "password": f"srv_pass_{i}", "network": "tcp,udp", "clients": [{"password": f"real_client_pass_{i}", "email": f"ss_classic_{i}", "enable": True}]}
        stream = {"network": "tcp", "security": "none"}
    elif i % 4 == 2:
        proto = "shadowsocks"
        # SS-2022 EIH in 3x-ui: both server key and client key
        settings = {"method": "2022-blake3-aes-128-gcm", "password": "MTIzNDU2Nzg5MDEyMzQ1Ng==", "network": "tcp,udp", "clients": [{"password": "YWJjZGVmZ2hpamtsbW5vcA==", "email": f"ss2022_{i}", "enable": True}]}
        stream = {"network": "tcp", "security": "none"}
    else:
        proto = "mixed"
        settings = {"auth": "password", "accounts": [{"user": f"socks_u_{i}", "pass": f"socks_p_{i}"}], "udp": True}
        stream = {"network": "tcp", "security": "none"}

    cur.execute(
        "INSERT INTO inbounds VALUES (?, 1, ?, ?, ?, ?, 1, 1893456000000, 'monthly', '', ?, ?, ?, ?, ?, '{}')",
        (i, i * 1024, i * 2048, 100 * (1024**3), f"3xUI-Node-{i}", port, proto, json.dumps(settings), json.dumps(stream), tag)
    )

# Outbounds matching user screenshot image_2d8de4.png + flat VLESS outbound
outbounds = [
    {"tag": "direct", "protocol": "freedom", "settings": {}},
    {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    {"tag": "api", "protocol": "blackhole", "settings": {}},
    {"tag": "ace荷包蛋", "protocol": "shadowsocks", "settings": {"servers": [{"address": "216.167.79.10", "port": 15001, "method": "aes-256-gcm", "password": "pass1", "uot": True}]}},
    {"tag": "US-tsnzqn15", "protocol": "shadowsocks", "settings": {"servers": [{"address": "yun.362353.xyz", "port": 15002, "method": "2022-blake3-aes-128-gcm", "password": "pass2"}]}},
    {"tag": "ace us季度", "protocol": "shadowsocks", "settings": {"servers": [{"address": "216.167.88.20", "port": 15003, "method": "aes-128-gcm", "password": "pass3"}]}},
    {"tag": "NTT 193", "protocol": "shadowsocks", "settings": {"servers": [{"address": "192.220.32.193", "port": 15004, "method": "aes-256-gcm", "password": "pass4"}]}},
    {"tag": "NTT 24", "protocol": "shadowsocks", "settings": {"servers": [{"address": "192.220.32.24", "port": 15005, "method": "aes-256-gcm", "password": "pass5"}]}},
    {"tag": "ntt 141", "protocol": "shadowsocks", "settings": {"servers": [{"address": "192.204.38.141", "port": 15006, "method": "aes-256-gcm", "password": "pass6"}]}},
    {"tag": "NTT三刀年付", "protocol": "shadowsocks", "settings": {"servers": [{"address": "192.220.32.99", "port": 15007, "method": "aes-256-gcm", "password": "pass7"}]}},
    {"tag": "yunyoo US原生", "protocol": "shadowsocks", "settings": {"servers": [{"address": "38.76.150.11", "port": 15008, "method": "aes-256-gcm", "password": "pass8"}]}},
    # Flat VLESSSettings format from 3x-ui outbound.js
    {"tag": "US-Flat-VLESS", "protocol": "vless", "settings": {"address": "198.51.100.88", "port": 443, "id": "99999999-8888-4777-8666-555555555555", "flow": "xtls-rprx-vision", "encryption": "none"}, "streamSettings": {"network": "tcp", "security": "reality", "realitySettings": {"serverName": "www.apple.com", "publicKey": "pbk123", "shortId": "1a2b"}, "sockopt": {"dialerProxy": "ace荷包蛋"}}}
]

rules = [
    {"type": "field", "inboundTag": ["inbound-40001"], "outboundTag": "ace荷包蛋"},
    {"type": "field", "inboundTag": ["inbound-40002"], "outboundTag": "US-tsnzqn15"},
    {"type": "field", "inboundTag": ["inbound-40004"], "outboundTag": "US-Flat-VLESS"}
]

cur.execute("INSERT INTO outbound_traffics VALUES (1, 'ace荷包蛋', 10485760, 20971520, 31457280)")
cur.execute("INSERT INTO settings VALUES (1, 'xrayTemplateConfig', ?)", (json.dumps({"outbounds": outbounds, "routing": {"rules": rules}}),))
conn.commit()
conn.close()
`;
  const pyRun = spawnSync('python3', ['-c', pyGen, dbPath], { encoding: 'utf8' });
  assert.equal(pyRun.status, 0, pyRun.stderr);

  const dbBuf = fs.readFileSync(dbPath);
  const migRes = await req('/SecPath16Chars99/api/migrate/3xui?mode=replace', {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: dbBuf
  });
  assert.equal(migRes.status, 200);
  assert.equal(migRes.json.summary.inboundsCount, 30);
  assert.equal(migRes.json.summary.outboundsCount, 9);

  // Verify Classic SS inbound #1 uses clients[0].password ('real_client_pass_1')
  const ssClassicInb = store.state.inbounds.find((i) => i.port === 40001);
  assert.equal(ssClassicInb.password, 'real_client_pass_1');
  assert.equal(ssClassicInb.outboundTag, 'ace荷包蛋');
  assert.equal(ssClassicInb.resetDay, 1);

  // Verify SS-2022 EIH inbound #2 preserves both server key and user key in Sing-box config
  const ss2022Inb = store.state.inbounds.find((i) => i.port === 40002);
  const sbSs2022 = toSingboxInbound(ss2022Inb);
  assert.equal(sbSs2022.password, 'MTIzNDU2Nzg5MDEyMzQ1Ng==');
  assert.equal(sbSs2022.users[0].password, 'YWJjZGVmZ2hpamtsbW5vcA==');

  // Verify flat 3x-ui VLESS outbound migration + sockopt.dialerProxy detour
  const flatVlessOut = store.state.outbounds.find((o) => o.tag === 'US-Flat-VLESS');
  assert.ok(flatVlessOut);
  assert.equal(flatVlessOut.server, '198.51.100.88');
  assert.equal(flatVlessOut.uuid, '99999999-8888-4777-8666-555555555555');
  assert.equal(flatVlessOut.detour, 'ace荷包蛋');

  // Verify outbound_traffics migration
  const aceOut = store.state.outbounds.find((o) => o.tag === 'ace荷包蛋');
  assert.equal(aceOut.up, 10485760);
  assert.equal(aceOut.down, 20971520);
  assert.equal(aceOut.uot, true);
});
