'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

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
const { issueSelfSignedCert } = require('../lib/system');
const { formatSubscription } = require('../lib/subscriptions');

test('X25519 Reality keypair generation and public key derivation', () => {
  const pair = generateRealityKeypair();
  assert.ok(pair.privateKey.length >= 40);
  assert.ok(pair.publicKey.length >= 40);
  const derived = deriveRealityPublicKey(pair.privateKey);
  assert.equal(derived, pair.publicKey);
});

test('All requested protocols compile into valid Sing-box inbounds and generate client URIs', () => {
  const kp = generateRealityKeypair();
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
      tlsDomain: 'node.example.com',
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
      tlsDomain: 'node.example.com',
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

    const links = buildClientLinks(inb, '203.0.113.88');
    assert.equal(links.length, 1, `Expected 1 client URI for ${inb.protocol}`);

    // Also test round-trip parsing URI into an Outbound!
    const parsedOut = parseShareUriToOutbound(links[0].uri);
    assert.equal(parsedOut.type, inb.protocol);
    assert.equal(parsedOut.port, inb.port);
    const sbOut = toSingboxOutbound(parsedOut);
    assert.equal(sbOut.type, inb.protocol);
  }
});

test('Lossless 3x-ui SQLite database (x-ui.db) migration for inbounds, outbounds, and routing rules', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-test-'));
  const dbPath = path.join(tmpDir, 'x-ui.db');
  const storePath = path.join(tmpDir, 'nexusgate.json');

  const kp = generateRealityKeypair();

  // Create a genuine 3x-ui SQLite database with inbounds, client_traffics, and settings (xrayTemplateConfig)
  const pyInit = `
import sqlite3, json, sys
conn = sqlite3.connect(sys.argv[1])
cur = conn.cursor()
cur.execute("CREATE TABLE inbounds (id INTEGER PRIMARY KEY, user_id INT, up INT, down INT, total INT, remark TEXT, enable INT, expiry_time INT, listen TEXT, port INT, protocol TEXT, settings TEXT, stream_settings TEXT, tag TEXT, sniffing TEXT)")
cur.execute("CREATE TABLE client_traffics (id INTEGER PRIMARY KEY, inbound_id INT, enable INT, email TEXT, up INT, down INT, expiry_time INT, total INT)")
cur.execute("CREATE TABLE settings (id INTEGER PRIMARY KEY, key TEXT, value TEXT)")

vless_settings = json.dumps({
  "clients": [{"id": "a1b2c3d4-e5f6-4a5b-8c9d-0123456789ab", "email": "alice@3xui", "flow": "xtls-rprx-vision", "subId": "sub_alice", "enable": True}],
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

ss_settings = json.dumps({
  "method": "2022-blake3-aes-128-gcm",
  "password": "${generateSsKey('2022-blake3-aes-128-gcm')}",
  "network": "tcp,udp",
  "clients": []
})
cur.execute("INSERT INTO inbounds VALUES (2, 1, 0, 0, 0, 'SG-SS2022', 1, 0, '', 34568, 'shadowsocks', ?, '{}', 'inbound-34568', '{}')", (ss_settings,))

tunnel_settings = json.dumps({
  "address": "198.51.100.99",
  "port": 5566,
  "network": "tcp,udp"
})
cur.execute("INSERT INTO inbounds VALUES (3, 1, 0, 0, 0, 'Relay-Tunnel', 1, 0, '', 34569, 'dokodemo-door', ?, '{}', 'inbound-34569', '{}')", (tunnel_settings,))

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
      {"type": "field", "inboundTag": ["inbound-34567"], "outboundTag": "jp-relay-out"},
      {"type": "field", "domain": ["geosite:cn"], "outboundTag": "direct"},
      {"type": "field", "domain": ["geosite:openai"], "outboundTag": "jp-relay-out"}
    ]
  }
})
cur.execute("INSERT INTO settings VALUES (1, 'xrayTemplateConfig', ?)", (xray_template,))
conn.commit()
conn.close()
`;

  const res = spawnSync('python3', ['-c', pyInit, dbPath], { encoding: 'utf8' });
  assert.equal(res.status, 0, res.stderr);

  const dbBuffer = fs.readFileSync(dbPath);
  const parsed = parse3xuiPayload({ dbBuffer });

  assert.equal(parsed.summary.inboundsCount, 3);
  assert.equal(parsed.summary.outboundsCount, 1);
  assert.equal(parsed.summary.rulesCount, 3);

  // Verify VLESS inbound was bound directly to jp-relay-out via routing rule detection
  const vlessInb = parsed.inbounds.find((i) => i.port === 34567);
  assert.ok(vlessInb);
  assert.equal(vlessInb.outboundTag, 'jp-relay-out');
  assert.equal(vlessInb.reality.publicKey, kp.publicKey);

  // Verify dokodemo-door became Sing-box direct port forwarding inbound
  const directInb = parsed.inbounds.find((i) => i.port === 34569);
  assert.ok(directInb);
  assert.equal(directInb.protocol, 'direct');
  assert.equal(directInb.overrideAddress, '198.51.100.99');
  assert.equal(directInb.overridePort, 5566);

  // Apply to store and compile Sing-box config + subscriptions
  const store = new Store(storePath);
  apply3xuiMigration(store, parsed, 'replace');
  const sbConfig = buildSingboxConfig(store.state);

  assert.equal(sbConfig.inbounds.length, 3);
  assert.ok(sbConfig.outbounds.some((o) => o.tag === 'jp-relay-out' && o.type === 'shadowsocks'));
  assert.ok(sbConfig.route.rules.some((r) => Array.isArray(r.inbound) && r.inbound.includes('inbound-34567') && r.outbound === 'jp-relay-out'));

  const clashSub = formatSubscription(store.state, 'all', 'clash');
  assert.ok(clashSub.body.includes('HK-Reality-alice@3xui'));
  assert.ok(clashSub.body.includes('SG-SS2022'));

  // Test self-signed SSL cert generation
  const cert = issueSelfSignedCert({ domain: 'test.nexusgate.local', baseDir: path.join(tmpDir, 'certs') });
  assert.equal(cert.valid, true);
  assert.ok(fs.existsSync(cert.certPath));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
