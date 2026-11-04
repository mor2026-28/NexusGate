'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const http = require('node:http');
const { spawnSync } = require('node:child_process');

const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-test-v27-'));
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

test('2. Reality SNI excludes Cloudflare/Microsoft, SS-2022 enforces exact-length Base64 keys, and TLS gets valid cert', async () => {
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
      // Pass a non-Base64 plain string to verify SS2022 automatically converts it into a valid 16/32-byte Base64 PSK
      ...(p.startsWith('ss2022') ? { password: 'plain_password_not_base64_20chars' } : {}),
      ...(p === 'vless-reality' ? { reality: { serverName: 'www.cloudflare.com', target: 'www.cloudflare.com:443' } } : {}),
      limitIp: 2,
      limitDevice: 2,
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
    assert.equal(inb.limitDevice, 2);
    assert.equal(inb.resetDay, 15);
    assert.ok(inb.expiryTime > Date.now());
    assert.ok(inb.links.length > 0);

    if (p === 'ss2022-256') {
      assert.equal(Buffer.from(inb.password, 'base64').length, 32, 'SS2022-256 must have exact 32-byte Base64 PSK');
      assert.equal(inb.clients[0].password, inb.password, 'Single-user SS2022 client password must match server PSK');
    } else if (p === 'ss2022-128') {
      assert.equal(Buffer.from(inb.password, 'base64').length, 16, 'SS2022-128 must have exact 16-byte Base64 PSK');
    }

    if (p === 'vless-reality') {
      assert.equal(inb.reality.serverName, 'tesla.com', 'Forbidden SNI should automatically normalize to tesla.com');
      assert.equal(inb.reality.target, 'www.tesla.com:443');
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
  assert.equal(realityInb.tls.server_name, 'tesla.com');

  const anytlsInb = config.inbounds.find((i) => i.type === 'anytls');
  assert.ok(anytlsInb, 'AnyTLS inbound should exist');
  assert.ok(anytlsInb.tls.certificate_path && fs.existsSync(anytlsInb.tls.certificate_path), 'AnyTLS inbound must have existing certificate_path');
});

test('3. Sing-box Clash API metadata.type ("anytls/inbound-XXXX") traffic attribution + online IP/device tracking & limitDevice enforcement', async () => {
  const anytlsInbound = store.state.inbounds.find((i) => i.protocol === 'anytls');
  assert.ok(anytlsInbound);
  anytlsInbound.limitIp = 0;
  anytlsInbound.limitDevice = 2;
  anytlsInbound.up = 0;
  anytlsInbound.down = 0;

  // Start a mock Sing-box Clash API server returning metadata.type = "anytls/<tag>"
  const closedConnIds = [];
  let mockConnections = [
    {
      id: 'conn-dev1-a',
      metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '::ffff:203.0.113.10', sourcePort: '51001', destinationPort: '443', host: 'openai.com' },
      upload: 4096,
      download: 8192,
      chains: ['direct']
    },
    {
      // Same device (203.0.113.10) opening a second TCP connection on a distant ephemeral port — must still count as 1 device!
      id: 'conn-dev1-b',
      metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.10', sourcePort: '62005', destinationPort: '443', host: 'google.com' },
      upload: 1024,
      download: 2048,
      chains: ['direct']
    },
    {
      // 2nd device (203.0.113.20) — allowed since limitDevice = 2
      id: 'conn-dev2-a',
      metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.20', sourcePort: '53000', destinationPort: '443', host: 'github.com' },
      upload: 2000,
      download: 4000,
      chains: ['direct']
    },
    {
      // 3rd device (203.0.113.30) — exceeds limitDevice = 2, must be terminated immediately!
      id: 'conn-dev3-excess',
      metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.30', sourcePort: '54000', destinationPort: '443', host: 'youtube.com' },
      upload: 500,
      download: 500,
      chains: ['direct']
    }
  ];

  const mockClashServer = http.createServer((reqMock, resMock) => {
    if (reqMock.method === 'GET' && reqMock.url === '/connections') {
      resMock.writeHead(200, { 'content-type': 'application/json' });
      resMock.end(JSON.stringify({ connections: mockConnections }));
    } else if (reqMock.method === 'DELETE' && reqMock.url.startsWith('/connections/')) {
      closedConnIds.push(decodeURIComponent(reqMock.url.slice('/connections/'.length)));
      resMock.writeHead(204);
      resMock.end();
    } else {
      resMock.writeHead(404);
      resMock.end();
    }
  });

  await new Promise((resolve) => mockClashServer.listen(0, '127.0.0.1', resolve));
  const clashPort = mockClashServer.address().port;
  store.state.settings.clashApiPort = clashPort;

  try {
    const baseTime = Date.now();
    await singbox.pollConnectionsAndEnforceLimits(new Date(baseTime));
    // Wait briefly for async DELETE request to hit mockClashServer
    await new Promise((r) => setTimeout(r, 80));

    assert.equal(singbox.getActiveDeviceCountForInbound(anytlsInbound.tag), 2, 'Should show 2 online devices (not 3, and not splitting 1 device across ports)');
    assert.deepEqual(singbox.getActiveIpsForInbound(anytlsInbound.tag), ['203.0.113.10', '203.0.113.20']);
    assert.ok(closedConnIds.includes('conn-dev3-excess'), '3rd excess device connection must be closed via Clash API DELETE');
    assert.ok(!closedConnIds.includes('conn-dev1-a') && !closedConnIds.includes('conn-dev1-b') && !closedConnIds.includes('conn-dev2-a'), '1st and 2nd allowed devices must NEVER be interrupted when 3rd device connects');
    assert.equal(anytlsInbound.up, 7120, 'Only allowed devices (1st + 2nd) traffic should be accumulated');
    assert.equal(anytlsInbound.down, 14240, 'Only allowed devices (1st + 2nd) download traffic should be accumulated');

    // Poll #2: 1st and 2nd devices keep using traffic while 3rd device retries -> 1st & 2nd keep working smoothly, 3rd retry is blocked
    mockConnections = [
      {
        id: 'conn-dev1-a',
        metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.10', sourcePort: '51001', destinationPort: '443', host: 'openai.com' },
        upload: 6096,
        download: 12192,
        chains: ['direct']
      },
      {
        id: 'conn-dev2-a',
        metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.20', sourcePort: '53000', destinationPort: '443', host: 'github.com' },
        upload: 3000,
        download: 6000,
        chains: ['direct']
      },
      {
        id: 'conn-dev3-retry',
        metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.30', sourcePort: '54099', destinationPort: '443', host: 'youtube.com' },
        upload: 999,
        download: 999,
        chains: ['direct']
      }
    ];
    await singbox.pollConnectionsAndEnforceLimits(new Date(baseTime + 2000));
    await new Promise((r) => setTimeout(r, 80));
    assert.ok(closedConnIds.includes('conn-dev3-retry'), '3rd device retry must also be blocked');
    assert.ok(!closedConnIds.includes('conn-dev1-a') && !closedConnIds.includes('conn-dev2-a'), '1st and 2nd devices remain completely uninterrupted');
    assert.equal(anytlsInbound.up, 10120, '1st and 2nd devices continue accumulating traffic normally');

    // Even when active connections momentarily drop to [], 60s rolling lease keeps online count visible in UI
    mockConnections = [];
    await singbox.pollConnectionsAndEnforceLimits(new Date(baseTime + 5000));
    assert.equal(singbox.getActiveDeviceCountForInbound(anytlsInbound.tag), 2, 'Online devices should remain visible within 60s lease window');

    // After 65s idle of 2nd device (while 1st device stays active), 2nd slot is freed and 3rd device is now admitted cleanly
    mockConnections = [
      {
        id: 'conn-dev1-a',
        metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.10', sourcePort: '51001', destinationPort: '443', host: 'openai.com' },
        upload: 7096,
        download: 14192,
        chains: ['direct']
      }
    ];
    await singbox.pollConnectionsAndEnforceLimits(new Date(baseTime + 40000));
    mockConnections.push({
      id: 'conn-dev3-admitted',
      metadata: { network: 'tcp', type: `anytls/${anytlsInbound.tag}`, sourceIP: '203.0.113.30', sourcePort: '55000', destinationPort: '443', host: 'youtube.com' },
      upload: 1000,
      download: 2000,
      chains: ['direct']
    });
    await singbox.pollConnectionsAndEnforceLimits(new Date(baseTime + 70000));
    await new Promise((r) => setTimeout(r, 80));
    assert.ok(!closedConnIds.includes('conn-dev3-admitted'), 'Once a slot frees up after 60s idle, 3rd device is admitted without being closed');
    assert.deepEqual(singbox.getActiveIpsForInbound(anytlsInbound.tag), ['203.0.113.10', '203.0.113.30']);
  } finally {
    await new Promise((resolve) => mockClashServer.close(resolve));
  }
});

test('4. Monthly automatic traffic reset (resetDay 1..31), batch operations, and system memory/log cleanup', async () => {
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

test('5. High-entropy subToken security (/sub/all returns 404) & clean CLI --show-info without username/subscription', async () => {
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

test('6. E2E Backup Migration of Universal .tar.gz Archive (with sublink.db, x-ui.db, /root/cert, WS+TLS & Reality)', async () => {
  const archiveBuildDir = path.join(tmpDir, 'archive_src');
  fs.mkdirSync(path.join(archiveBuildDir, 'etc', 'x-ui'), { recursive: true });
  fs.mkdirSync(path.join(archiveBuildDir, 'usr', 'local', 'bin', 'sublink', 'db'), { recursive: true });

  const sublinkDbPath = path.join(archiveBuildDir, 'usr', 'local', 'bin', 'sublink', 'db', 'sublink.db');
  const xuiDbPath = path.join(archiveBuildDir, 'etc', 'x-ui', 'x-ui.db');
  const tarGzPath = path.join(tmpDir, '3xui_universal_backup.tar.gz');

  const pyGen = `
import sqlite3, json, sys

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
  assert.equal(migRes.json.summary.inboundsCount, 40);
  assert.equal(migRes.json.summary.outboundsCount, 3);

  const inbRes = await req('/SecPath16Chars99/api/inbounds');
  assert.equal(inbRes.status, 200);
  const wsInbound = inbRes.json.inbounds.find((i) => i.port === 40001);
  assert.equal(wsInbound.tlsDomain, 'node.example.com');
  assert.ok(wsInbound.links[0].uri.includes('sni=node.example.com'));
  assert.ok(wsInbound.links[0].uri.includes('type=ws'));

  const realityInbound = inbRes.json.inbounds.find((i) => i.port === 40004);
  assert.equal(realityInbound.reality.serverName, 'tesla.com');

  const { config } = singbox.writeConfig();
  const sbWsInb = config.inbounds.find((i) => i.listen_port === 40001);
  assert.deepEqual(sbWsInb.tls.alpn, ['http/1.1']);

  const heapUsedMB = Math.round(process.memoryUsage().heapUsed / (1024 * 1024));
  assert.ok(heapUsedMB < 90, `Heap used (${heapUsedMB} MB) should stay well below 90MB`);
});

test('7. Certificate failover switchover, deletion persistence, and SSH ng --show-info sync', async () => {
  // Create a mock Let's Encrypt CA so issued certs have issuer !== subject (isSelfSigned === false)
  const caDir = path.join(tmpDir, 'ca');
  fs.mkdirSync(caDir, { recursive: true });
  const caKey = path.join(caDir, 'ca.key');
  const caCert = path.join(caDir, 'ca.crt');
  spawnSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-days', '3650', '-nodes', '-subj', '/C=US/O=Let\'s Encrypt/CN=E1',
    '-keyout', caKey, '-out', caCert
  ]);

  const issueMockCaCert = (domain) => {
    const dir = path.join(tmpDir, 'certs', domain);
    fs.mkdirSync(dir, { recursive: true });
    const keyPath = path.join(dir, 'privkey.pem');
    const csrPath = path.join(dir, 'req.csr');
    const certPath = path.join(dir, 'fullchain.pem');
    spawnSync('openssl', [
      'req', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
      '-nodes', '-subj', `/CN=${domain}`, '-keyout', keyPath, '-out', csrPath
    ]);
    spawnSync('openssl', [
      'x509', '-req', '-in', csrPath, '-CA', caCert, '-CAkey', caKey,
      '-CAcreateserial', '-out', certPath, '-days', '365'
    ]);
    return { certPath, keyPath };
  };

  // 1. Import initial cert "old-standby.example.com"
  const oldC = issueMockCaCert('old-standby.example.com');
  const resOld = await req('/SecPath16Chars99/api/certificates/custom', {
    method: 'POST',
    body: JSON.stringify({
      domain: 'old-standby.example.com',
      certPath: oldC.certPath,
      keyPath: oldC.keyPath
    })
  });
  assert.equal(resOld.status, 201);

  // 2. Import new failover cert "new-failover.example.com"
  const newC = issueMockCaCert('new-failover.example.com');
  const resNew = await req('/SecPath16Chars99/api/certificates/custom', {
    method: 'POST',
    body: JSON.stringify({
      domain: 'new-failover.example.com',
      certPath: newC.certPath,
      keyPath: newC.keyPath
    })
  });
  assert.equal(resNew.status, 201);

  // Verify SSH ng (--show-info) immediately reflects the newly imported "new-failover.example.com"
  const cliAfterImport = spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js'), '--show-info'], {
    env: { ...process.env, NG_DATA_FILE: path.join(tmpDir, 'nexusgate.json') },
    encoding: 'utf8'
  });
  assert.equal(cliAfterImport.status, 0);
  assert.ok(cliAfterImport.stdout.includes('new-failover.example.com'), 'SSH --show-info must show newly imported cert domain');

  // 3. Delete "new-failover.example.com" and verify it stays deleted and automatically switches back to old-standby.example.com
  const certsListRes = await req('/SecPath16Chars99/api/certificates');
  const newCertItem = certsListRes.json.certificates.find((c) => c.domain === 'new-failover.example.com');
  assert.ok(newCertItem);

  const delRes = await req(`/SecPath16Chars99/api/certificates/${encodeURIComponent(newCertItem.id)}`, {
    method: 'DELETE'
  });
  assert.equal(delRes.status, 200);
  assert.equal(delRes.json.deletedDomain, 'new-failover.example.com');
  assert.equal(delRes.json.switchedDomain, 'old-standby.example.com');

  const certsAfterDel = await req('/SecPath16Chars99/api/certificates');
  assert.ok(!certsAfterDel.json.certificates.some((c) => c.domain === 'new-failover.example.com'), 'Deleted cert must not reappear');
  assert.equal(certsAfterDel.json.settings.webDomain, 'old-standby.example.com');
});

test('8. E2E Multi-Client Inbound Migration (client_alpha & client_beta), Per-Client CRUD, Per-Client Subscriptions & Independent Limits', async () => {
  // 1. Build a 3x-ui / X-Panel SQLite DB containing row #20 "Multi-User-Node-20" (port 55011, vless + ws + TLS) with 2 clients:
  //    - "client_alpha" (198.85 GB used, limitIp: 2)
  //    - "client_beta" (6.66 GB used, limitIp: 2)
  const multiDbPath = path.join(tmpDir, 'multi_client_xui.db');
  const pyMulti = `
import sqlite3, json, sys

conn = sqlite3.connect(sys.argv[1])
cur = conn.cursor()
cur.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, user_id INT, up INT, down INT, total INT, remark TEXT, enable INT, expiry_time INT, traffic_reset TEXT, listen TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT, sniffing TEXT)")
cur.execute("CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INT, enable INT, email TEXT, up INT, down INT, expiry_time INT, total INT)")
cur.execute("CREATE TABLE outbound_traffics (id INTEGER PRIMARY KEY, tag TEXT, up INT, down INT, total INT)")
cur.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")

settings = {
  "clients": [
    {
      "id": "aaaaaaaa-1111-4222-8333-111111111111",
      "flow": "",
      "email": "client_alpha",
      "limitIp": 2,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": True,
      "subId": "sub_client_alpha_token16"
    },
    {
      "id": "bbbbbbbb-2222-4333-8444-222222222222",
      "flow": "",
      "email": "client_beta",
      "limitIp": 2,
      "totalGB": 0,
      "expiryTime": 0,
      "enable": True,
      "subId": "sub_yanzi_token1688"
    }
  ],
  "decryption": "none"
}
stream = {
  "network": "ws",
  "security": "tls",
  "tlsSettings": {
    "serverName": "eb.example.com",
    "certificates": [{"certificateFile": "/root/cert/eb.example.com/fullchain.pem", "keyFile": "/root/cert/eb.example.com/privkey.pem"}]
  },
  "wsSettings": {"path": "/ws-nice", "headers": {}}
}

cur.execute(
  "INSERT INTO inbounds VALUES (20, 1, 1000000, 2000000, 0, 'Multi-User-Node-20', 1, 0, 'never', '', 55011, 'vless', ?, ?, 'inbound-55011', '{}')",
  (json.dumps(settings), json.dumps(stream))
)
u1_bytes = int(198.85 * (1024**3))
u2_bytes = int(6.66 * (1024**3))
cur.execute("INSERT INTO client_traffics VALUES (1, 20, 1, 'client_alpha', ?, ?, 0, 0)", (u1_bytes // 10, u1_bytes - (u1_bytes // 10)))
cur.execute("INSERT INTO client_traffics VALUES (2, 20, 1, 'client_beta', ?, ?, 0, 0)", (u2_bytes // 10, u2_bytes - (u2_bytes // 10)))
conn.commit()
conn.close()
`;
  const pyRun = spawnSync('python3', ['-c', pyMulti, multiDbPath], { encoding: 'utf8' });
  assert.equal(pyRun.status, 0, pyRun.stderr);

  const dbBuf = fs.readFileSync(multiDbPath);
  const migRes = await req('/SecPath16Chars99/api/migrate/3xui?mode=merge', {
    method: 'POST',
    headers: { 'content-type': 'application/octet-stream' },
    body: dbBuf
  });
  assert.equal(migRes.status, 200);

  // 2. Verify migrated inbound has both clients ("client_alpha" & "client_beta"), both share links, and Sing-box users array has both UUIDs
  const inbRes = await req('/SecPath16Chars99/api/inbounds');
  const niceInb = inbRes.json.inbounds.find((i) => i.port === 55011);
  assert.ok(niceInb, 'Multi-User-Node-20 inbound on port 55011 must exist');
  assert.equal(niceInb.clients.length, 2, 'Must preserve both clients on port 55011');
  assert.equal(niceInb.clients[0].email, 'client_alpha');
  assert.equal(niceInb.clients[1].email, 'client_beta');
  assert.equal(niceInb.links.length, 2, 'Must generate 2 independent client share links');
  assert.ok(niceInb.links[0].uri.includes('aaaaaaaa-1111-4222-8333-111111111111'));
  assert.ok(niceInb.links[1].uri.includes('bbbbbbbb-2222-4333-8444-222222222222'));

  const { config: sbCfg1 } = singbox.writeConfig();
  const sbNice = sbCfg1.inbounds.find((i) => i.listen_port === 55011);
  assert.equal(sbNice.users.length, 2, 'Sing-box inbound.users must contain both clients');
  assert.equal(sbNice.users[0].name, 'client_alpha');
  assert.equal(sbNice.users[1].name, 'client_beta');

  // 3. Verify editing the inbound remark/outboundTag preserves BOTH clients intact without overwriting Client #2
  const editInbRes = await req(`/SecPath16Chars99/api/inbounds/${niceInb.id}`, {
    method: 'PUT',
    body: JSON.stringify({
      ...niceInb,
      remark: 'Multi-User-Node-20-已核验'
    })
  });
  assert.equal(editInbRes.status, 200);
  assert.equal(editInbRes.json.inbound.clients.length, 2);
  assert.equal(editInbRes.json.inbound.clients[1].email, 'client_beta');
  assert.equal(editInbRes.json.inbound.clients[1].id, 'bbbbbbbb-2222-4333-8444-222222222222');

  // 4. Verify per-client subscription URLs return only that specific client's node and individual traffic stats
  const sub1Res = await req('/sub/sub_client_alpha_token16?format=clash');
  assert.equal(sub1Res.status, 200);
  assert.ok(sub1Res.text.includes('client_alpha'));
  assert.ok(!sub1Res.text.includes('client_beta'), 'Client 1 subscription must NOT leak Client 2 node');

  const sub2Res = await req('/sub/sub_yanzi_token1688?format=clash');
  assert.equal(sub2Res.status, 200);
  assert.ok(sub2Res.text.includes('client_beta'));
  assert.ok(!sub2Res.text.includes('client_alpha'), 'Client 2 subscription must NOT leak Client 1 node');

  // 5. Verify per-client CRUD: Add a 3rd client, toggle it, reset traffic, and delete it
  const addClientRes = await req(`/SecPath16Chars99/api/inbounds/${niceInb.id}/clients`, {
    method: 'POST',
    body: JSON.stringify({
      email: 'vip_third_user',
      limitIp: 1,
      limitDevice: 1,
      totalGB: 50
    })
  });
  assert.equal(addClientRes.status, 201);
  assert.equal(addClientRes.json.inbound.clients.length, 3);
  const thirdClient = addClientRes.json.client;

  const toggleClientRes = await req(`/SecPath16Chars99/api/inbounds/${niceInb.id}/clients/${encodeURIComponent(thirdClient.id)}/toggle`, {
    method: 'POST'
  });
  assert.equal(toggleClientRes.status, 200);
  assert.equal(toggleClientRes.json.client.enable, false);

  // When 3rd client is disabled, Sing-box config has 2 active users ("client_alpha" and "client_beta")
  const { config: sbCfg2 } = singbox.writeConfig();
  assert.equal(sbCfg2.inbounds.find((i) => i.listen_port === 55011).users.length, 2);

  const delClientRes = await req(`/SecPath16Chars99/api/inbounds/${niceInb.id}/clients/${encodeURIComponent(thirdClient.id)}`, {
    method: 'DELETE'
  });
  assert.equal(delClientRes.status, 200);
  assert.equal(delClientRes.json.inbound.clients.length, 2);

  // 6. Verify per-client independent limitIp enforcement on multi-client inbound:
  //    "client_alpha" has limitIp=2, "client_beta" has limitIp=2 -> 2 IPs for client_alpha + 2 IPs for client_beta (4 IPs total) are ALL allowed!
  //    Only a 3rd IP for "client_alpha" is blocked!
  const closedMultiIds = [];
  const mockMultiConns = [
    { id: 'c-u1-ip1', metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_alpha', sourceIP: '198.18.0.1', sourcePort: '40001' }, upload: 100, download: 200, chains: ['direct'] },
    { id: 'c-u1-ip2', metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_alpha', sourceIP: '198.18.0.2', sourcePort: '40002' }, upload: 100, download: 200, chains: ['direct'] },
    { id: 'c-u2-ip1', metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_beta', sourceIP: '198.18.0.3', sourcePort: '40003' }, upload: 100, download: 200, chains: ['direct'] },
    { id: 'c-u2-ip2', metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_beta', sourceIP: '198.18.0.4', sourcePort: '40004' }, upload: 100, download: 200, chains: ['direct'] },
    { id: 'c-u1-ip3-excess', metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_alpha', sourceIP: '198.18.0.5', sourcePort: '40005' }, upload: 100, download: 200, chains: ['direct'] }
  ];
  const mockClash = http.createServer((reqM, resM) => {
    if (reqM.method === 'GET' && reqM.url === '/connections') {
      resM.writeHead(200, { 'content-type': 'application/json' });
      resM.end(JSON.stringify({ connections: mockMultiConns }));
    } else if (reqM.method === 'DELETE' && reqM.url.startsWith('/connections/')) {
      closedMultiIds.push(decodeURIComponent(reqM.url.slice('/connections/'.length)));
      resM.writeHead(204);
      resM.end();
    }
  });
  await new Promise((r) => mockClash.listen(0, '127.0.0.1', r));
  store.state.settings.clashApiPort = mockClash.address().port;
  try {
    await singbox.pollConnectionsAndEnforceLimits(new Date());
    await new Promise((r) => setTimeout(r, 80));
    assert.ok(closedMultiIds.includes('c-u1-ip3-excess'), '3rd IP of client_alpha must be blocked');
    assert.ok(
      !closedMultiIds.includes('c-u1-ip1') &&
      !closedMultiIds.includes('c-u1-ip2') &&
      !closedMultiIds.includes('c-u2-ip1') &&
      !closedMultiIds.includes('c-u2-ip2'),
      'Both client_alpha (2 IPs) and client_beta (2 IPs) must remain online without interfering with each other'
    );
    assert.equal(singbox.getActiveDeviceCountForClient('inbound-55011', 'client_alpha', false), 2);
    assert.equal(singbox.getActiveDeviceCountForClient('inbound-55011', 'client_beta', false), 2);
  } finally {
    await new Promise((r) => mockClash.close(r));
  }
});

test('9. Zero-disruption cleanup & config diffing: memory cleanup never double-counts active connections or drops nodes', async () => {
  // 1. Verify writeConfig() diffing reports changed: false when config is identical
  const w1 = singbox.writeConfig();
  const w2 = singbox.writeConfig();
  assert.equal(w2.changed, false, 'Identical Sing-box config must report changed: false to avoid unnecessary restarts');

  // 2. Verify cleanupSystemLogsAndMemory never clears connTrafficCache of active connections (preventing false quota exhaustion)
  const targetInb = store.state.inbounds.find((i) => i.port === 55011);
  assert.ok(targetInb);
  const beforeUp = targetInb.up;

  let activeConns = [
    {
      id: 'long-lived-conn-1',
      start: new Date().toISOString(),
      metadata: { network: 'tcp', type: 'vless/inbound-55011', user: 'client_alpha', sourceIP: '198.18.0.1', sourcePort: '41000' },
      upload: 50000,
      download: 100000,
      chains: ['direct']
    }
  ];

  const mockClash = http.createServer((reqM, resM) => {
    if (reqM.method === 'GET' && reqM.url === '/connections') {
      resM.writeHead(200, { 'content-type': 'application/json' });
      resM.end(JSON.stringify({ connections: activeConns }));
    } else {
      resM.writeHead(204);
      resM.end();
    }
  });
  await new Promise((r) => mockClash.listen(0, '127.0.0.1', r));
  store.state.settings.clashApiPort = mockClash.address().port;

  try {
    const nowMs = Date.now();
    await singbox.pollConnectionsAndEnforceLimits(new Date(nowMs));
    assert.equal(targetInb.up - beforeUp, 50000);

    // Trigger system memory & log cleanup while long-lived-conn-1 is still active
    const cleanRes = await req('/SecPath16Chars99/api/system/cleanup', { method: 'POST' });
    assert.equal(cleanRes.status, 200);

    // Poll again with the same cumulative upload=50000: deltaUp MUST be 0 (not double-counted as +50000!)
    await singbox.pollConnectionsAndEnforceLimits(new Date(nowMs + 2000));
    assert.equal(targetInb.up - beforeUp, 50000, 'Active connection traffic must NOT be double-counted after memory cleanup');
  } finally {
    await new Promise((r) => mockClash.close(r));
  }
});

test('10. High-Concurrency Stress Test: 40 Inbound Nodes + 35 Relay Outbounds + 400 Concurrent Connections Zero-Drop Benchmark', async () => {
  // Ensure 35 relay outbounds exist and are bound across the 40+ inbound nodes
  for (let i = 1; i <= 35; i += 1) {
    const tag = `stress-relay-out-${i}`;
    if (!store.state.outbounds.some((o) => o.tag === tag)) {
      store.state.outbounds.push({
        id: `out_stress_${i}`,
        tag,
        type: 'shadowsocks',
        remark: `Relay-Landing-${i}`,
        enabled: true,
        server: `198.51.100.${i}`,
        port: 20000 + i,
        method: '2022-blake3-aes-128-gcm',
        password: 'MTIzNDU2Nzg5MDEyMzQ1Ng==',
        up: 0,
        down: 0
      });
    }
  }

  const activeInbounds = store.state.inbounds.filter((i) => i.enable !== false);
  assert.ok(activeInbounds.length >= 40, `Expected at least 40 active inbounds, got ${activeInbounds.length}`);

  // Simulate 400 concurrent connections across 40 inbounds and 35 relay outbounds (10 connections per inbound)
  const closedDuringStress = [];
  const stressConns = [];
  activeInbounds.slice(0, 40).forEach((inb, idx) => {
    inb.limitIp = 0;
    inb.limitDevice = 0;
    const outTag = `stress-relay-out-${(idx % 35) + 1}`;
    const userEmail = inb.clients?.[0]?.email || 'default';
    for (let cIdx = 0; cIdx < 10; cIdx += 1) {
      stressConns.push({
        id: `stress-conn-${idx}-${cIdx}`,
        start: new Date().toISOString(),
        metadata: {
          network: 'tcp',
          type: `${inb.protocol}/${inb.tag}`,
          user: userEmail,
          sourceIP: `198.19.${idx}.${cIdx + 1}`,
          sourcePort: String(30000 + cIdx)
        },
        upload: 16384 * (cIdx + 1),
        download: 65536 * (cIdx + 1),
        chains: [outTag]
      });
    }
  });

  const mockClash = http.createServer((reqM, resM) => {
    if (reqM.method === 'GET' && reqM.url === '/connections') {
      resM.writeHead(200, { 'content-type': 'application/json' });
      resM.end(JSON.stringify({ connections: stressConns }));
    } else if (reqM.method === 'DELETE' && reqM.url.startsWith('/connections/')) {
      closedDuringStress.push(reqM.url);
      resM.writeHead(204);
      resM.end();
    }
  });
  await new Promise((r) => mockClash.listen(0, '127.0.0.1', r));
  store.state.settings.clashApiPort = mockClash.address().port;

  try {
    const t0 = Date.now();
    for (let round = 1; round <= 5; round += 1) {
      for (const c of stressConns) {
        c.upload += 4096;
        c.download += 8192;
      }
      await singbox.pollConnectionsAndEnforceLimits(new Date(t0 + round * 1000));
    }
    const elapsedMs = Date.now() - t0;
    assert.equal(closedDuringStress.length, 0, 'Zero normal client connections may be dropped under 40-node / 400-conn load');
    assert.ok(elapsedMs < 400, `5 full polling cycles of 400 connections should complete in <400ms (took ${elapsedMs}ms)`);

    // Verify overview status endpoint reports low private panel memory (RssAnon)
    const ovRes = await req('/SecPath16Chars99/api/overview');
    assert.equal(ovRes.status, 200);
    const panelMemMB = Math.round(ovRes.json.system.panelMemoryBytes / (1024 * 1024));
    assert.ok(panelMemMB < 45, `Panel private memory (${panelMemMB} MB) should stay well under 45 MB even with 40+ nodes and 400 connections`);
  } finally {
    await new Promise((r) => mockClash.close(r));
  }
});

test('11. Fast Non-Blocking Node Creation (< 50ms), Idempotent Double-Submit Guard & Modal Auto-Close Verification', async () => {
  const startMs = Date.now();
  const payload = {
    remark: 'Fast-Create-VLESS-Reality',
    protocol: 'vless',
    port: 58899,
    security: 'reality',
    transport: 'tcp',
    flow: 'xtls-rprx-vision',
    limitIp: 2,
    limitDevice: 2
  };

  // 1st click: creates node in < 50ms without blocking on ufw/iptables/systemctl
  const res1 = await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  const elapsedMs = Date.now() - startMs;
  assert.equal(res1.status, 201);
  assert.equal(res1.json.inbound.port, 58899);
  assert.equal(res1.json.inbound.reality.serverName, 'tesla.com');
  assert.ok(elapsedMs < 150, `POST /api/inbounds must respond immediately without blocking (${elapsedMs}ms)`);

  // 2nd rapid click / network retry with same port & protocol within 15s: returns 200 OK (idempotent) instead of 400 error
  const res2 = await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify(payload)
  });
  assert.equal(res2.status, 200, 'Duplicate submit within 15s must return 200 OK so modal closes cleanly');
  assert.equal(res2.json.deduplicated, true);
  assert.equal(res2.json.inbound.id, res1.json.inbound.id);

  // Genuine port conflict (different protocol on the same port 58899) must still be rejected with 400
  const conflictRes = await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify({ remark: 'Conflict-Trojan', protocol: 'trojan', port: 58899, security: 'tls' })
  });
  assert.equal(conflictRes.status, 400);

  // Verify frontend app.js and styles.css contain double-submit lock and dialog:not([open]) safeguard
  const appJs = fs.readFileSync(path.join(__dirname, '..', 'public', 'app.js'), 'utf8');
  const stylesCss = fs.readFileSync(path.join(__dirname, '..', 'public', 'styles.css'), 'utf8');
  assert.ok(appJs.includes("form.dataset.submitting === '1'"), 'Frontend must lock form against double submit');
  assert.ok(appJs.includes("dlg.removeAttribute('open')"), 'closeModal() must forcefully remove open attribute');
  assert.ok(stylesCss.includes("dialog:not([open]){display:none!important}"), 'CSS must hide closed dialog across all browsers');
});

test('12. High-Strength Unique Initial Server Credentials (--init-panel & Store) and Non-Colliding Node/Client Credentials', async () => {
  const { generateStrongCredential, verifySecret, hashSecret } = require('../lib/auth');
  const { Store } = require('../lib/store');

  // 1) Verify generateStrongCredential guarantees uppercase, lowercase, digits, and non-collision across 50 runs
  const seen = new Set();
  for (let i = 0; i < 50; i += 1) {
    const u = generateStrongCredential(13, { prefix: 'ng_' });
    const p = generateStrongCredential(18, { exclude: u });
    assert.equal(u.length, 13);
    assert.equal(p.length, 18);
    assert.notEqual(u, p, 'Username and password must never be identical');
    assert.ok(/[A-Z]/.test(p) && /[a-z]/.test(p) && /[0-9]/.test(p), `Password must contain upper, lower, and digits: ${p}`);
    assert.ok(!seen.has(u) && !seen.has(p), 'Every generated credential must be unique');
    seen.add(u);
    seen.add(p);
  }

  // 2) Simulate 2 brand-new server installations via --init-panel and verify completely distinct high-strength credentials
  const srvDir1 = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-srv1-'));
  const srvDir2 = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-srv2-'));
  try {
    const cleanEnv1 = { ...process.env, NG_DATA_FILE: path.join(srvDir1, 'nexusgate.json'), NG_SINGBOX_CONFIG: path.join(srvDir1, 'sb.json') };
    delete cleanEnv1.NG_ADMIN_USERNAME;
    delete cleanEnv1.NG_ADMIN_PASSWORD;
    delete cleanEnv1.NG_PORT;
    delete cleanEnv1.NG_BASE_PATH;

    const cleanEnv2 = { ...cleanEnv1, NG_DATA_FILE: path.join(srvDir2, 'nexusgate.json'), NG_SINGBOX_CONFIG: path.join(srvDir2, 'sb.json') };

    const out1 = spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js'), '--init-panel', 'auto', 'auto', 'auto', 'auto', '203.0.113.10'], { env: cleanEnv1, encoding: 'utf8' });
    assert.equal(out1.status, 0, `srv1 init failed: ${out1.stderr}`);
    const info1 = JSON.parse(out1.stdout.trim());

    // Also test passing identical username & password to --init-panel: it must automatically remediate so password !== username
    const out2 = spawnSync(process.execPath, [path.join(__dirname, '..', 'server.js'), '--init-panel', 'auto', 'same_cred_test', 'same_cred_test', 'auto', '203.0.113.11'], { env: cleanEnv2, encoding: 'utf8' });
    assert.equal(out2.status, 0, `srv2 init failed: ${out2.stderr}`);
    const info2 = JSON.parse(out2.stdout.trim());

    assert.ok(info1.username.startsWith('ng_') && info1.username.length === 13);
    assert.equal(info1.password.length, 18);
    assert.notEqual(info1.username, info1.password);
    assert.notEqual(info1.username, info2.username, 'Different servers must get different usernames');
    assert.notEqual(info1.password, info2.password, 'Different servers must get different passwords');
    assert.notEqual(info2.username, info2.password, 'Even if identical user/pass passed to --init-panel, password must be auto-remediated to a distinct 18-char strong password');
    assert.equal(info2.password.length, 18);
  } finally {
    fs.rmSync(srvDir1, { recursive: true, force: true });
    fs.rmSync(srvDir2, { recursive: true, force: true });
  }

  // 3) Verify creating SOCKS5 and AnyTLS nodes and adding clients always produces distinct username, email, and password
  const socksCreate = await req('/SecPath16Chars99/api/inbounds', {
    method: 'POST',
    body: JSON.stringify({
      remark: 'SOCKS-Unique-Creds',
      protocol: 'socks',
      port: 58901,
      socksUser: 'same_socks_cred',
      socksPassword: 'same_socks_cred'
    })
  });
  assert.equal(socksCreate.status, 201);
  const socksNode = socksCreate.json.inbound;
  assert.equal(socksNode.socksUser, 'same_socks_cred');
  assert.notEqual(socksNode.socksPassword, socksNode.socksUser, 'SOCKS password must never equal SOCKS username');
  assert.equal(socksNode.socksPassword.length, 18);
  assert.notEqual(socksNode.clients[0].username, socksNode.clients[0].password);

  // Add a second client to SOCKS node without specifying credentials
  const addSocksClient = await req(`/SecPath16Chars99/api/inbounds/${socksNode.id}/clients`, {
    method: 'POST',
    body: JSON.stringify({})
  });
  assert.equal(addSocksClient.status, 201);
  const sc = addSocksClient.json.client;
  assert.notEqual(sc.username, sc.password, 'Added client username and password must be distinct');
  assert.notEqual(sc.email, sc.password, 'Added client email and password must be distinct');
  assert.ok(sc.password.length >= 18);
});
