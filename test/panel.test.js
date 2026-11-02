'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { normalizeBasePath } = require('../lib/http');
const {
  generateRealityKeypair,
  deriveRealityPublicKey,
  generateSsKey,
  toSingboxInbound,
  toSingboxOutbound,
  buildClientLinks,
  parseShareUriToOutbound
} = require('../lib/protocols');
const { buildSingboxConfig } = require('../lib/singbox');
const { parse3xuiPayload, apply3xuiMigration } = require('../lib/migrate3xui');
const { Store } = require('../lib/store');
const { issueSelfSignedCert, getAccelerationStatus } = require('../lib/system');
const { formatSubscription } = require('../lib/subscriptions');

test('normalizeBasePath strips accidental shell pipe newlines and control chars', () => {
  assert.equal(normalizeBasePath('/qErfNupP\ndf89b623856/'), '/qErfNupP');
  assert.equal(normalizeBasePath('  /my_secret_path/  '), '/my_secret_path');
  assert.equal(normalizeBasePath('/'), '/');
});

test('X25519 Reality keypair generation and public key derivation', () => {
  const pair = generateRealityKeypair();
  assert.ok(pair.privateKey.length >= 40);
  assert.ok(pair.publicKey.length >= 40);
  const derived = deriveRealityPublicKey(pair.privateKey);
  assert.equal(derived, pair.publicKey);
});

test('All protocols compile into valid Sing-box inbounds and generate 100% client-compatible URIs', () => {
  const kp = generateRealityKeypair();
  const serverPublicIp = '216.23.82.153';
  const protocolsToTest = [
    {
      id: 'in_vless',
      tag: 'vless-reality-in',
      remark: 'VLESS-Reality',
      protocol: 'vless',
      port: 24443,
      security: 'reality',
      transport: 'tcp',
      flow: 'xtls-rprx-vision',
      reality: {
        serverName: 'www.tesla.com',
        target: 'www.tesla.com:443',
        privateKey: kp.privateKey,
        publicKey: kp.publicKey,
        shortIds: ['1a2b3c4d']
      },
      clients: [{ id: '11111111-2222-4333-8444-555555555555', email: 'u1', flow: 'xtls-rprx-vision', enable: true }]
    },
    {
      id: 'in_anytls',
      tag: 'anytls-in',
      remark: 'AnyTLS-Node',
      protocol: 'anytls',
      port: 24444,
      security: 'tls',
      tlsDomain: 'www.bing.com',
      password: 'anytls_secret_pass',
      clients: [{ email: 'u_anytls', password: 'anytls_secret_pass', enable: true }]
    },
    {
      id: 'in_hy2',
      tag: 'hy2-in',
      remark: 'HY2-Node',
      protocol: 'hysteria2',
      port: 24445,
      security: 'tls',
      tlsDomain: 'www.bing.com',
      upMbps: 100,
      downMbps: 100,
      obfsPassword: 'salamander_pass',
      clients: [{ email: 'u_hy2', password: 'hy2_password', enable: true }]
    },
    {
      id: 'in_ss128',
      tag: 'ss128-in',
      remark: 'SS-AES128',
      protocol: 'shadowsocks',
      port: 24446,
      method: 'aes-128-gcm',
      password: generateSsKey('aes-128-gcm'),
      clients: [{ email: 'u_ss128', password: generateSsKey('aes-128-gcm'), enable: true }]
    },
    {
      id: 'in_ss2022_128',
      tag: 'ss2022-128-in',
      remark: 'SS2022-128',
      protocol: 'shadowsocks',
      port: 24447,
      method: '2022-blake3-aes-128-gcm',
      password: generateSsKey('2022-blake3-aes-128-gcm'),
      clients: [{ email: 'u_ss2022_128', password: generateSsKey('2022-blake3-aes-128-gcm'), enable: true }]
    },
    {
      id: 'in_ss2022_256',
      tag: 'ss2022-256-in',
      remark: 'SS2022-256',
      protocol: 'shadowsocks',
      port: 24448,
      method: '2022-blake3-aes-256-gcm',
      password: generateSsKey('2022-blake3-aes-256-gcm'),
      clients: [{ email: 'u_ss2022_256', password: generateSsKey('2022-blake3-aes-256-gcm'), enable: true }]
    },
    {
      id: 'in_socks',
      tag: 'socks-in',
      remark: 'SOCKS5-In',
      protocol: 'socks',
      port: 24449,
      socksUser: 'myuser',
      socksPassword: 'mypassword',
      clients: [{ username: 'myuser', password: 'mypassword', enable: true }]
    }
  ];

  for (const inb of protocolsToTest) {
    const sbInb = toSingboxInbound(inb);
    assert.equal(sbInb.type, inb.protocol);
    assert.equal(sbInb.listen_port, inb.port);

    // Ensure single-user SS2022 does not force multi-user EIH array
    if (inb.protocol === 'shadowsocks') {
      assert.equal(sbInb.users, undefined);
    }

    const links = buildClientLinks(inb, serverPublicIp);
    assert.equal(links.length, 1);

    // Ensure connect host is ALWAYS the real server IP (216.23.82.153), NOT fake SNI www.bing.com!
    assert.ok(links[0].uri.includes(`@${serverPublicIp}:${inb.port}`));

    // Ensure self-signed AnyTLS & HY2 automatically include insecure=1
    if (inb.protocol === 'anytls' || inb.protocol === 'hysteria2') {
      assert.ok(links[0].uri.includes('insecure=1'));
      assert.ok(links[0].uri.includes('sni=www.bing.com'));
    }

    const parsedOut = parseShareUriToOutbound(links[0].uri);
    assert.equal(parsedOut.type, inb.protocol);
    assert.equal(parsedOut.server, serverPublicIp);
    assert.equal(parsedOut.port, inb.port);
    const sbOut = toSingboxOutbound(parsedOut);
    assert.equal(sbOut.type, inb.protocol);
  }
});

test('Lossless 3x-ui migration from both SQLite x-ui.db and .tar.gz backup archive', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-test-'));
  const dbPath = path.join(tmpDir, 'x-ui.db');
  const tarPath = path.join(tmpDir, '3xui_backup.tar.gz');
  const storePath = path.join(tmpDir, 'nexusgate.json');

  const kp = generateRealityKeypair();

  const pyInit = `
import sqlite3, json, sys
conn = sqlite3.connect(sys.argv[1])
cur = conn.cursor()
cur.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, user_id INT, up INT, down INT, total INT, remark TEXT, enable INT, expiry_time INT, listen TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT, sniffing TEXT)")
cur.execute("CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INT, enable INT, email TEXT, up INT, down INT, expiry_time INT, total INT)")
cur.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")

vless_settings = json.dumps({
  "clients": [{"id": "a1b2c3d4-e5f6-4a5b-8c9d-0123456789ab", "email": "alice@3xui", "flow": "xtls-rprx-vision", "limitIp": 3, "subId": "sub_alice", "enable": True}],
  "decryption": "none"
})
vless_stream = json.dumps({
  "network": "tcp",
  "security": "reality",
  "realitySettings": {
    "target": "www.tesla.com:443",
    "serverNames": ["www.tesla.com"],
    "privateKey": "${kp.privateKey}",
    "shortIds": ["abcd1234"],
    "settings": {"publicKey": "${kp.publicKey}", "fingerprint": "chrome"}
  }
})
cur.execute("INSERT INTO inbounds VALUES (1, 1, 1024, 2048, 0, 'HK-Reality', 1, 0, '', 34567, 'vless', ?, ?, 'inbound-34567', '{}')", (vless_settings, vless_stream))
cur.execute("INSERT INTO client_traffics VALUES (1, 1, 1, 'alice@3xui', 1024, 2048, 0, 0)")

xray_template = json.dumps({
  "outbounds": [
    {"tag": "direct", "protocol": "freedom", "settings": {}},
    {"tag": "blocked", "protocol": "blackhole", "settings": {}},
    {
      "tag": "jp-relay-out",
      "protocol": "shadowsocks",
      "settings": {
        "servers": [{"address": "203.0.113.50", "port": 18388, "method": "2022-blake3-aes-256-gcm", "password": "${generateSsKey('2022-blake3-aes-256-gcm')}"}]
      }
    }
  ],
  "routing": {
    "rules": [
      {"type": "field", "inboundTag": ["inbound-34567"], "outboundTag": "jp-relay-out"}
    ]
  }
})
cur.execute("INSERT INTO settings VALUES (1, 'xrayTemplateConfig', ?)", (xray_template,))
conn.commit()
conn.close()
`;

  spawnSync('python3', ['-c', pyInit, dbPath], { encoding: 'utf8' });
  spawnSync('tar', ['-czf', tarPath, '-C', tmpDir, 'x-ui.db'], { encoding: 'utf8' });

  const tarBuffer = fs.readFileSync(tarPath);
  const parsed = parse3xuiPayload({ dbBuffer: tarBuffer });

  assert.equal(parsed.summary.inboundsCount, 1);
  assert.equal(parsed.summary.outboundsCount, 1);
  assert.equal(parsed.inbounds[0].limitIp, 3);
  assert.equal(parsed.inbounds[0].outboundTag, 'jp-relay-out');

  const store = new Store(storePath);
  apply3xuiMigration(store, parsed, 'replace');
  const sbConfig = buildSingboxConfig(store.state);
  assert.equal(sbConfig.inbounds.length, 1);

  const clashSub = formatSubscription(store.state, 'all', 'clash', '216.23.82.153:50084');
  assert.ok(clashSub.body.includes('216.23.82.153'));

  const cert = issueSelfSignedCert({ domain: 'www.bing.com', ip: '216.23.82.153', baseDir: path.join(tmpDir, 'certs') });
  assert.equal(cert.valid, true);
  assert.ok(getAccelerationStatus().congestion);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
