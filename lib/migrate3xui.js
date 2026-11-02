'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');
const { deriveRealityPublicKey } = require('./protocols');

function safeJson(str, fallback = {}) {
  if (!str) return fallback;
  if (typeof str === 'object') return str;
  try {
    return JSON.parse(String(str));
  } catch {
    return fallback;
  }
}

/**
 * Reads tables from a 3x-ui SQLite database file (x-ui.db) or a .tar.gz backup archive containing x-ui.db.
 */
function readSqliteDb(dbFilePath) {
  if (!fs.existsSync(dbFilePath)) {
    throw new Error(`未找到文件: ${dbFilePath}`);
  }

  // Check if file is a .tar.gz / .tgz archive (such as /root/3xui_backup.tar.gz)
  if (dbFilePath.endsWith('.tar.gz') || dbFilePath.endsWith('.tgz')) {
    const tmpExtract = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-xui-tar-'));
    try {
      spawnSync('tar', ['-xzf', dbFilePath, '-C', tmpExtract], { encoding: 'utf8', timeout: 20000 });
      const findRes = spawnSync('find', [tmpExtract, '-name', '*.db'], { encoding: 'utf8', timeout: 5000 });
      const dbFound = String(findRes.stdout || '').trim().split('\n').find(Boolean);
      if (!dbFound || !fs.existsSync(dbFound)) {
        throw new Error('压缩包内未找到 x-ui.db 数据库文件');
      }
      return readSqliteDb(dbFound);
    } finally {
      fs.rmSync(tmpExtract, { recursive: true, force: true });
    }
  }

  const pyScript = `
import sqlite3, json, sys
conn = sqlite3.connect(sys.argv[1])
conn.row_factory = sqlite3.Row
cur = conn.cursor()
def fetch_table(name):
    try:
        rows = cur.execute(f"SELECT * FROM {name}").fetchall()
        return [dict(r) for r in rows]
    except Exception:
        return []
out = {
    "inbounds": fetch_table("inbounds"),
    "client_traffics": fetch_table("client_traffics"),
    "settings": fetch_table("settings"),
    "outbound_traffics": fetch_table("outbound_traffics"),
    "users": fetch_table("users")
}
print(json.dumps(out))
`;

  const pyRes = spawnSync('python3', ['-c', pyScript, dbFilePath], {
    encoding: 'utf8',
    maxBuffer: 64 * 1024 * 1024,
    timeout: 15000
  });

  if (pyRes.status === 0 && pyRes.stdout.trim()) {
    return JSON.parse(pyRes.stdout.trim());
  }

  const queryTable = (table) => {
    const res = spawnSync('sqlite3', ['-json', dbFilePath, `SELECT * FROM ${table};`], {
      encoding: 'utf8',
      maxBuffer: 32 * 1024 * 1024,
      timeout: 10000
    });
    if (res.status === 0 && res.stdout.trim()) {
      return safeJson(res.stdout.trim(), []);
    }
    return [];
  };

  return {
    inbounds: queryTable('inbounds'),
    client_traffics: queryTable('client_traffics'),
    settings: queryTable('settings'),
    outbound_traffics: queryTable('outbound_traffics'),
    users: queryTable('users')
  };
}

/**
 * Converts a single 3x-ui Inbound record into a NexusGate Sing-box Inbound object.
 */
function convert3xuiInbound(row, clientTraffics = []) {
  const settings = safeJson(row.settings, {});
  const stream = safeJson(row.streamSettings || row.stream_settings, {});
  const rawProto = String(row.protocol || 'vless').toLowerCase();
  const protocol = rawProto === 'dokodemo-door' || rawProto === 'tunnel' ? 'direct' : (rawProto === 'hysteria' ? 'hysteria2' : rawProto);
  const port = Number(row.port || 443);
  const tag = row.tag || `inbound-${port}`;
  const remark = row.remark || tag;
  const listen = (!row.listen || row.listen === '0.0.0.0') ? '::' : String(row.listen).replace(/^"|"$/g, '');

  const security = String(stream.security || 'none').toLowerCase();
  const network = String(stream.network || 'tcp').toLowerCase();
  const transport = network === 'raw' || network === 'tcp' ? 'tcp' : network;

  const inbound = {
    id: `in_${crypto.randomBytes(5).toString('hex')}`,
    tag,
    remark,
    protocol,
    listen,
    port,
    enable: row.enable !== undefined ? Boolean(row.enable) : true,
    up: Number(row.up || 0),
    down: Number(row.down || 0),
    total: Number(row.total || 0),
    expiryTime: Number(row.expiryTime || row.expiry_time || 0),
    limitIp: 0,
    security,
    transport,
    outboundTag: 'default',
    clients: [],
    migratedFrom3xui: true
  };

  if (security === 'reality') {
    const r = stream.realitySettings || {};
    const rSub = r.settings || {};
    const serverNames = Array.isArray(r.serverNames)
      ? r.serverNames
      : String(r.serverNames || 'www.tesla.com').split(',').map((s) => s.trim()).filter(Boolean);
    const shortIds = Array.isArray(r.shortIds)
      ? r.shortIds
      : String(r.shortIds || '').split(',').map((s) => s.trim()).filter(Boolean);
    const privateKey = r.privateKey || '';
    const publicKey = rSub.publicKey || deriveRealityPublicKey(privateKey);
    const target = r.target || r.dest || `${serverNames[0] || 'www.tesla.com'}:443`;

    inbound.reality = {
      target: String(target),
      serverName: serverNames[0] || 'www.tesla.com',
      serverNames,
      privateKey,
      publicKey,
      shortIds: shortIds.length ? shortIds : [''],
      fingerprint: rSub.fingerprint || 'chrome'
    };
  }

  if (security === 'tls') {
    const t = stream.tlsSettings || {};
    const certs = Array.isArray(t.certificates) && t.certificates[0] ? t.certificates[0] : {};
    inbound.tlsDomain = t.serverName || (t.settings && t.settings.serverName) || '';
    inbound.certPath = certs.certificateFile || certs.certFile || '';
    inbound.keyPath = certs.keyFile || '';
    inbound.alpn = Array.isArray(t.alpn) ? t.alpn : [];
    inbound.allowInsecure = Boolean(t.settings && t.settings.allowInsecure);
  }

  if (transport === 'ws') {
    const ws = stream.wsSettings || {};
    inbound.wsPath = ws.path || '/';
    inbound.wsHost = ws.host || (ws.headers && (ws.headers.Host || ws.headers.host)) || '';
  } else if (transport === 'grpc') {
    const grpc = stream.grpcSettings || {};
    inbound.grpcServiceName = grpc.serviceName || 'grpc';
  } else if (transport === 'httpupgrade') {
    const hu = stream.httpupgradeSettings || {};
    inbound.wsPath = hu.path || '/';
    inbound.wsHost = hu.host || '';
  }

  const rawClients = Array.isArray(settings.clients) ? settings.clients : [];
  const statsByEmail = new Map();
  for (const st of clientTraffics) {
    if (st.email) statsByEmail.set(st.email, st);
  }

  if (protocol === 'vless' || protocol === 'vmess' || protocol === 'trojan') {
    inbound.clients = rawClients.map((c, idx) => {
      const stat = statsByEmail.get(c.email) || {};
      return {
        id: c.id || crypto.randomUUID(),
        password: c.password || c.id || '',
        email: c.email || `${tag}_user_${idx + 1}`,
        flow: c.flow || '',
        alterId: Number(c.alterId || 0),
        subId: c.subId || '',
        limitIp: Number(c.limitIp || 0),
        totalGB: Number(c.totalGB || stat.total || 0),
        up: Number(stat.up || 0),
        down: Number(stat.down || 0),
        expiryTime: Number(c.expiryTime || stat.expiry_time || 0),
        enable: c.enable !== undefined ? Boolean(c.enable) : (stat.enable !== undefined ? Boolean(stat.enable) : true)
      };
    });
    if (inbound.clients[0]?.flow) inbound.flow = inbound.clients[0].flow;
    if (inbound.clients[0]?.limitIp) inbound.limitIp = inbound.clients[0].limitIp;
  } else if (protocol === 'shadowsocks') {
    inbound.method = settings.method || 'aes-128-gcm';
    inbound.password = settings.password || '';
    inbound.network = settings.network || 'tcp,udp';
    inbound.clients = rawClients.map((c, idx) => {
      const stat = statsByEmail.get(c.email) || {};
      return {
        id: c.id || crypto.randomUUID(),
        email: c.email || `${tag}_ss_${idx + 1}`,
        password: c.password || settings.password || '',
        subId: c.subId || '',
        limitIp: Number(c.limitIp || 0),
        up: Number(stat.up || 0),
        down: Number(stat.down || 0),
        enable: c.enable !== undefined ? Boolean(c.enable) : true
      };
    });
    if (!inbound.clients.length && inbound.password) {
      inbound.clients.push({
        id: crypto.randomUUID(),
        email: remark,
        password: inbound.password,
        enable: true
      });
    }
  } else if (protocol === 'socks') {
    const accounts = Array.isArray(settings.accounts) ? settings.accounts : [];
    if (accounts[0]) {
      inbound.socksUser = accounts[0].user || '';
      inbound.socksPassword = accounts[0].pass || '';
    }
    inbound.clients = accounts.map((acc, idx) => ({
      id: crypto.randomUUID(),
      username: acc.user || `user${idx + 1}`,
      email: acc.user || `user${idx + 1}`,
      password: acc.pass || '',
      enable: true
    }));
  } else if (protocol === 'direct') {
    inbound.overrideAddress = settings.address || '';
    inbound.overridePort = Number(settings.port || 0);
    inbound.network = settings.network || 'tcp,udp';
  } else if (protocol === 'hysteria2') {
    const users = settings.clients || settings.users || [];
    inbound.clients = users.map((u, idx) => ({
      id: crypto.randomUUID(),
      email: u.email || `${tag}_hy2_${idx + 1}`,
      password: u.auth || u.password || '',
      enable: true
    }));
    if (inbound.clients[0]?.password) inbound.password = inbound.clients[0].password;
  }

  return inbound;
}

function convert3xuiOutbound(raw, index = 0) {
  const proto = String(raw.protocol || 'freedom').toLowerCase();
  const tag = raw.tag || `outbound-${index + 1}`;
  if (proto === 'freedom' || proto === 'direct') {
    return {
      id: tag === 'direct' ? 'out_direct' : `out_${crypto.randomBytes(4).toString('hex')}`,
      tag: tag === 'freedom' ? 'direct' : tag,
      type: 'direct',
      remark: raw.remark || '本地直连 (Freedom)',
      builtin: tag === 'direct' || tag === 'freedom',
      enabled: true
    };
  }
  if (proto === 'blackhole' || proto === 'block') {
    return {
      id: tag === 'block' || tag === 'blocked' ? 'out_block' : `out_${crypto.randomBytes(4).toString('hex')}`,
      tag: tag === 'blocked' ? 'block' : tag,
      type: 'block',
      remark: raw.remark || '黑洞拦截 (Blackhole)',
      builtin: tag === 'block' || tag === 'blocked',
      enabled: true
    };
  }

  const settings = raw.settings || {};
  const stream = raw.streamSettings || {};
  const security = String(stream.security || 'none').toLowerCase();
  const network = String(stream.network || 'tcp').toLowerCase();
  const transport = network === 'raw' || network === 'tcp' ? 'tcp' : network;
  const detour = raw.proxySettings?.tag || raw.detour || '';

  const out = {
    id: `out_${crypto.randomBytes(5).toString('hex')}`,
    tag,
    type: proto === 'hysteria' ? 'hysteria2' : proto,
    remark: raw.remark || `3x-ui 迁移出站 (${tag})`,
    enabled: true,
    security,
    transport,
    ...(detour ? { detour } : {}),
    migratedFrom3xui: true
  };

  if (security === 'reality') {
    const r = stream.realitySettings || {};
    out.sni = r.serverName || '';
    out.fingerprint = r.fingerprint || 'chrome';
    out.publicKey = r.publicKey || '';
    out.shortId = r.shortId || '';
  } else if (security === 'tls') {
    const t = stream.tlsSettings || {};
    out.sni = t.serverName || '';
    out.insecure = Boolean(t.allowInsecure);
    out.fingerprint = t.fingerprint || 'chrome';
  }

  if (transport === 'ws') {
    const ws = stream.wsSettings || {};
    out.wsPath = ws.path || '/';
    out.wsHost = ws.host || (ws.headers && (ws.headers.Host || ws.headers.host)) || '';
  } else if (transport === 'grpc') {
    out.grpcServiceName = stream.grpcSettings?.serviceName || 'grpc';
  }

  if (proto === 'vless' || proto === 'vmess') {
    const vnext = (Array.isArray(settings.vnext) && settings.vnext[0]) || {};
    const user = (Array.isArray(vnext.users) && vnext.users[0]) || {};
    out.server = vnext.address || raw.server || '';
    out.port = Number(vnext.port || raw.server_port || 443);
    out.uuid = user.id || raw.uuid || '';
    out.flow = user.flow || '';
    out.alterId = Number(user.alterId || 0);
    out.cipher = user.security || 'auto';
  } else if (proto === 'shadowsocks') {
    const srv = (Array.isArray(settings.servers) && settings.servers[0]) || settings;
    out.server = srv.address || raw.server || '';
    out.port = Number(srv.port || raw.server_port || 8388);
    out.method = srv.method || raw.method || 'aes-128-gcm';
    out.password = srv.password || raw.password || '';
  } else if (proto === 'trojan') {
    const srv = (Array.isArray(settings.servers) && settings.servers[0]) || settings;
    out.server = srv.address || raw.server || '';
    out.port = Number(srv.port || raw.server_port || 443);
    out.password = srv.password || raw.password || '';
  } else if (proto === 'socks' || proto === 'http') {
    const srv = (Array.isArray(settings.servers) && settings.servers[0]) || settings;
    const usr = (Array.isArray(srv.users) && srv.users[0]) || {};
    out.server = srv.address || raw.server || '';
    out.port = Number(srv.port || raw.server_port || 1080);
    out.username = usr.user || srv.user || raw.username || '';
    out.password = usr.pass || srv.pass || raw.password || '';
  }

  return out;
}

function convert3xuiRouteRule(raw, index = 0) {
  const inbound = Array.isArray(raw.inboundTag)
    ? raw.inboundTag
    : (Array.isArray(raw.inbound) ? raw.inbound : (raw.inboundTag ? [raw.inboundTag] : []));
  const outboundRaw = raw.outboundTag || raw.outbound || 'direct';
  const outbound = outboundRaw === 'blocked' ? 'block' : (outboundRaw === 'freedom' ? 'direct' : outboundRaw);

  return {
    id: `rule_3xui_${crypto.randomBytes(4).toString('hex')}_${index}`,
    remark: raw.remark || `3x-ui 分流规则 #${index + 1} (${outbound})`,
    enabled: true,
    action: 'route',
    inbound,
    domain: Array.isArray(raw.domain) ? raw.domain : (raw.domain ? [raw.domain] : []),
    domain_suffix: Array.isArray(raw.domain_suffix) ? raw.domain_suffix : [],
    domain_keyword: Array.isArray(raw.domain_keyword) ? raw.domain_keyword : [],
    ip_cidr: Array.isArray(raw.ip) ? raw.ip : (Array.isArray(raw.ip_cidr) ? raw.ip_cidr : []),
    source_ip_cidr: Array.isArray(raw.sourceIP) ? raw.sourceIP : (Array.isArray(raw.source_ip_cidr) ? raw.source_ip_cidr : []),
    port: raw.port ? String(raw.port).split(',').map((s) => s.trim()).filter(Boolean) : [],
    source_port: raw.sourcePort ? String(raw.sourcePort).split(',').map((s) => s.trim()).filter(Boolean) : [],
    network: raw.network ? String(raw.network).toLowerCase() : '',
    protocol: Array.isArray(raw.protocol) ? raw.protocol : (raw.protocol ? [raw.protocol] : []),
    rule_set: Array.isArray(raw.rule_set) ? raw.rule_set : [],
    ip_is_private: Array.isArray(raw.ip) && raw.ip.includes('geoip:private'),
    outbound,
    migratedFrom3xui: true
  };
}

function parse3xuiPayload({ dbPath = '', dbBuffer = null, jsonPayload = null }) {
  let rawInbounds = [];
  let clientTraffics = [];
  let rawSettings = [];
  let templateConfig = {};

  if (dbBuffer && Buffer.isBuffer(dbBuffer) && dbBuffer.length > 16) {
    const header = dbBuffer.subarray(0, 15).toString('utf8');
    const isGzip = dbBuffer[0] === 0x1f && dbBuffer[1] === 0x8b;
    if (header.startsWith('SQLite format 3') || isGzip) {
      const ext = isGzip ? '.tar.gz' : '.db';
      const tmpFile = path.join(os.tmpdir(), `x-ui-import-${Date.now()}-${crypto.randomBytes(4).toString('hex')}${ext}`);
      fs.writeFileSync(tmpFile, dbBuffer, { mode: 0o600 });
      try {
        const dump = readSqliteDb(tmpFile);
        rawInbounds = dump.inbounds || [];
        clientTraffics = dump.client_traffics || [];
        rawSettings = dump.settings || [];
      } finally {
        fs.rmSync(tmpFile, { force: true });
      }
    } else {
      jsonPayload = safeJson(dbBuffer.toString('utf8'), null);
    }
  } else if (dbPath) {
    const dump = readSqliteDb(dbPath);
    rawInbounds = dump.inbounds || [];
    clientTraffics = dump.client_traffics || [];
    rawSettings = dump.settings || [];
  }

  if (jsonPayload) {
    if (Array.isArray(jsonPayload)) {
      rawInbounds = jsonPayload;
    } else if (typeof jsonPayload === 'object') {
      if (Array.isArray(jsonPayload.inbounds)) rawInbounds = jsonPayload.inbounds;
      if (Array.isArray(jsonPayload.client_traffics)) clientTraffics = jsonPayload.client_traffics;
      if (Array.isArray(jsonPayload.settings)) rawSettings = jsonPayload.settings;
      if (jsonPayload.outbounds || jsonPayload.routing) {
        templateConfig = jsonPayload;
      }
    }
  }

  const settingsMap = {};
  for (const row of rawSettings) {
    if (row.key) settingsMap[row.key] = row.value;
  }

  if (settingsMap.xrayTemplateConfig) {
    templateConfig = safeJson(settingsMap.xrayTemplateConfig, templateConfig);
  }

  const convertedInbounds = [];
  for (const row of rawInbounds) {
    if (row.tag === 'api' || (row.protocol === 'dokodemo-door' && row.listen === '127.0.0.1' && Number(row.port) === 62789)) {
      continue;
    }
    convertedInbounds.push(convert3xuiInbound(row, clientTraffics));
  }

  const convertedOutbounds = [];
  const rawOutbounds = Array.isArray(templateConfig.outbounds) ? templateConfig.outbounds : [];
  for (let i = 0; i < rawOutbounds.length; i += 1) {
    const o = rawOutbounds[i];
    if (o.tag === 'api' || o.protocol === 'dns') continue;
    convertedOutbounds.push(convert3xuiOutbound(o, i));
  }

  const convertedRules = [];
  const rawRules = Array.isArray(templateConfig.routing?.rules)
    ? templateConfig.routing.rules
    : (Array.isArray(templateConfig.route?.rules) ? templateConfig.route.rules : []);

  for (let i = 0; i < rawRules.length; i += 1) {
    const r = rawRules[i];
    if (r.outboundTag === 'api' || (Array.isArray(r.inboundTag) && r.inboundTag.includes('api'))) {
      continue;
    }
    const rule = convert3xuiRouteRule(r, i);

    const isPureInboundRelay =
      rule.inbound.length > 0 &&
      !rule.domain.length &&
      !rule.domain_suffix.length &&
      !rule.ip_cidr.length &&
      !rule.port.length &&
      !rule.protocol.length &&
      !rule.ip_is_private;

    if (isPureInboundRelay) {
      for (const inb of convertedInbounds) {
        if (rule.inbound.includes(inb.tag)) {
          inb.outboundTag = rule.outbound;
        }
      }
    }
    convertedRules.push(rule);
  }

  const panelSettings = {};
  if (settingsMap.webPort) panelSettings.webPort = Number(settingsMap.webPort);
  if (settingsMap.webBasePath) panelSettings.webBasePath = settingsMap.webBasePath;
  if (settingsMap.webCertFile) panelSettings.webCertFile = settingsMap.webCertFile;
  if (settingsMap.webKeyFile) panelSettings.webKeyFile = settingsMap.webKeyFile;
  if (settingsMap.subPath) panelSettings.subPath = settingsMap.subPath;

  return {
    summary: {
      inboundsCount: convertedInbounds.length,
      clientsCount: convertedInbounds.reduce((acc, item) => acc + (item.clients?.length || 0), 0),
      outboundsCount: convertedOutbounds.filter((o) => !o.builtin).length,
      rulesCount: convertedRules.length,
      protocols: [...new Set(convertedInbounds.map((i) => i.protocol))]
    },
    inbounds: convertedInbounds,
    outbounds: convertedOutbounds,
    rules: convertedRules,
    panelSettings
  };
}

function apply3xuiMigration(store, parsed, mode = 'merge') {
  return store.transact((state) => {
    if (mode === 'replace') {
      state.inbounds = parsed.inbounds;
      const customOutbounds = parsed.outbounds.filter((o) => !['direct', 'block'].includes(o.tag));
      state.outbounds = [
        ...state.outbounds.filter((o) => o.builtin),
        ...customOutbounds
      ];
      state.routing.rules = [
        ...state.routing.rules.filter((r) => r.action === 'sniff'),
        ...parsed.rules
      ];
    } else {
      for (const inb of parsed.inbounds) {
        const existingIdx = state.inbounds.findIndex((x) => x.tag === inb.tag || Number(x.port) === Number(inb.port));
        if (existingIdx >= 0) {
          state.inbounds[existingIdx] = { ...state.inbounds[existingIdx], ...inb, id: state.inbounds[existingIdx].id };
        } else {
          state.inbounds.push(inb);
        }
      }
      for (const out of parsed.outbounds) {
        if (['direct', 'block'].includes(out.tag)) continue;
        const existingIdx = state.outbounds.findIndex((x) => x.tag === out.tag);
        if (existingIdx >= 0) {
          state.outbounds[existingIdx] = { ...state.outbounds[existingIdx], ...out, id: state.outbounds[existingIdx].id };
        } else {
          state.outbounds.push(out);
        }
      }
      for (const rule of parsed.rules) {
        state.routing.rules.push(rule);
      }
    }

    const record = {
      id: `mig_${crypto.randomBytes(4).toString('hex')}`,
      at: new Date().toISOString(),
      mode,
      ...parsed.summary
    };
    state.migrations.unshift(record);
    if (state.migrations.length > 30) state.migrations.length = 30;
    return record;
  });
}

module.exports = {
  readSqliteDb,
  convert3xuiInbound,
  convert3xuiOutbound,
  convert3xuiRouteRule,
  parse3xuiPayload,
  apply3xuiMigration
};
