'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { spawnSync } = require('node:child_process');

const { normalizeBasePath } = require('../lib/http');
const {
  isValidUuid,
  ensureUuid,
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

test('normalizeBasePath strips accidental shell pipe newlines and Store defaults to strictBasePath=true', () => {
  assert.equal(normalizeBasePath('/qErfNupP\ndf89b623856/'), '/qErfNupP');
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-strict-'));
  const store = new Store(path.join(tmpDir, 'nexusgate.json'));
  assert.equal(store.state.settings.strictBasePath, true);
  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('UUID validation and auto-repair prevents base64 keys from corrupting VLESS links', () => {
  assert.equal(isValidUuid('Sr44m/SQ0MAsXxmR0o9GVQ=='), false);
  const repaired = ensureUuid('Sr44m/SQ0MAsXxmR0o9GVQ==');
  assert.equal(isValidUuid(repaired), true);

  // Verify VLESS inbound with bad client id produces a valid UUID in both Sing-box config and v2rayN share link
  const kp = generateRealityKeypair();
  const inb = {
    id: 'in_bad_uuid',
    tag: 'inbound-50488',
    remark: 'JP',
    protocol: 'vless',
    port: 50488,
    security: 'reality',
    transport: 'tcp',
    flow: 'xtls-rprx-vision',
    reality: {
      serverName: 'www.tesla.com',
      target: 'www.tesla.com:443',
      privateKey: kp.privateKey,
      publicKey: kp.publicKey,
      shortIds: ['e97ba46b']
    },
    clients: [{ id: 'Sr44m/SQ0MAsXxmR0o9GVQ==', email: 'user_1', flow: 'xtls-rprx-vision', enable: true }]
  };

  const sbInb = toSingboxInbound(inb);
  assert.equal(isValidUuid(sbInb.users[0].uuid), true);

  const links = buildClientLinks(inb, 'cs.vponlive.com');
  assert.equal(links.length, 1);
  // Must parse cleanly as a standard URL without '/' in username!
  const parsedUrl = new URL(links[0].uri);
  assert.equal(isValidUuid(parsedUrl.username), true);
  assert.equal(parsedUrl.hostname, 'cs.vponlive.com');
  assert.equal(parsedUrl.port, '50488');
});

test('CLI commands (--show-info, --issue-selfsigned, --set-cert) execute cleanly without ReferenceError', () => {
  const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-cli-'));
  const dataFile = path.join(tmpDir, 'nexusgate.json');
  const serverPath = path.join(__dirname, '..', 'server.js');

  const res1 = spawnSync('node', [serverPath, '--issue-selfsigned', 'cs.vponlive.com', '216.23.82.153'], {
    env: { ...process.env, NG_DATA_FILE: dataFile },
    encoding: 'utf8'
  });
  assert.equal(res1.status, 0, res1.stderr);

  const res2 = spawnSync('node', [serverPath, '--show-info'], {
    env: { ...process.env, NG_DATA_FILE: dataFile },
    encoding: 'utf8'
  });
  assert.equal(res2.status, 0, res2.stderr);
  const info = JSON.parse(res2.stdout);
  assert.equal(info.https, true);

  fs.rmSync(tmpDir, { recursive: true, force: true });
});

test('All protocols compile into valid Sing-box inbounds and generate v2rayN-compatible URIs without unescaped slashes before @', () => {
  const kp = generateRealityKeypair();
  const domain = 'cs.vponlive.com';
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
      tlsDomain: domain,
      password: 'anytlsCleanPassword123',
      clients: [{ email: 'u_anytls', password: 'anytlsCleanPassword123', enable: true }]
    },
    {
      id: 'in_hy2',
      tag: 'hy2-in',
      remark: 'HY2-Node',
      protocol: 'hysteria2',
      port: 24445,
      security: 'tls',
      tlsDomain: domain,
      upMbps: 100,
      downMbps: 100,
      obfsPassword: 'salamander_pass',
      clients: [{ email: 'u_hy2', password: 'hy2CleanPassword123', enable: true }]
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
      password: 'Sr44m/SQ0MAsXxmR0o9GVQ==', // Key containing '/' to test URL safety!
      clients: [{ email: 'u_ss2022_128', password: 'Sr44m/SQ0MAsXxmR0o9GVQ==', enable: true }]
    },
    {
      id: 'in_ss2022_256',
      tag: 'ss2022-256-in',
      remark: 'SS2022-256',
      protocol: 'shadowsocks',
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

    const links = buildClientLinks(inb, domain);
    assert.equal(links.length, 1);

    // Ensure no unescaped '/' appears before '@' in the URI authority section
    const authPart = links[0].uri.split('://')[1].split('@')[0];
    assert.equal(authPart.includes('/'), false, `URI authority contains '/' which breaks .NET Uri: ${links[0].uri}`);

    const parsedOut = parseShareUriToOutbound(links[0].uri);
    assert.equal(parsedOut.type, inb.protocol);
    assert.equal(parsedOut.server, domain);
    assert.equal(parsedOut.port, inb.port);
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
      "tag": "ace荷包蛋",
      "protocol": "shadowsocks",
      "settings": {
        "servers": [{"address": "216.167.79.95", "port": 46893, "method": "2022-blake3-aes-256-gcm", "password": "${generateSsKey('2022-blake3-aes-256-gcm')}"}]
      }
    }
  ],
  "routing": {
    "rules": [
      {"type": "field", "inboundTag": ["inbound-34567"], "outboundTag": "ace荷包蛋"}
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
  assert.equal(parsed.inbounds[0].outboundTag, 'ace荷包蛋');

  const store = new Store(storePath);
  apply3xuiMigration(store, parsed, 'replace');
  const sbConfig = buildSingboxConfig(store.state);
  assert.equal(sbConfig.inbounds.length, 1);

  const clashSub = formatSubscription(store.state, 'all', 'clash', 'cs.vponlive.com:15626');
  assert.ok(clashSub.body.includes('cs.vponlive.com'));

  fs.rmSync(tmpDir, { recursive: true, force: true });
});
