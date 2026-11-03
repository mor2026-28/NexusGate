'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { hashSecret, randomToken } = require('./auth');
const { normalizeBasePath } = require('./http');
const { isValidUuid, ensureUuid } = require('./protocols');

function defaultState() {
  return {
    version: 2.6,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    admin: {
      id: 'admin_1',
      username: process.env.NG_ADMIN_USERNAME || 'admin',
      passwordHash: hashSecret(process.env.NG_ADMIN_PASSWORD || 'admin123456'),
      updatedAt: new Date().toISOString()
    },
    settings: {
      panelTitle: 'NexusGate · 枢门',
      webListen: process.env.NG_HOST || '0.0.0.0',
      webPort: Number(process.env.NG_PORT || 2053),
      webBasePath: normalizeBasePath(process.env.NG_BASE_PATH || '/'),
      strictBasePath: true,
      webDomain: process.env.NG_DOMAIN || '',
      webCertFile: process.env.NG_CERT_FILE || '',
      webKeyFile: process.env.NG_KEY_FILE || '',
      defaultTlsDomain: process.env.NG_DOMAIN || '',
      defaultCertFile: process.env.NG_CERT_FILE || '',
      defaultKeyFile: process.env.NG_KEY_FILE || '',
      sessionMaxAge: 720,
      subEnable: true,
      subPath: '/sub/',
      subToken: randomToken(20),
      subPublicUrl: '',
      publicIPv4: '',
      publicIPv6: '',
      singboxBin: process.env.NG_SINGBOX_BIN || '/usr/local/bin/sing-box',
      singboxConfigPath: process.env.NG_SINGBOX_CONFIG || '/etc/nexusgate/sing-box/config.json',
      singboxLogLevel: 'warn',
      singboxApiPort: 10085,
      clashApiPort: 10086,
      clashApiSecret: randomToken(16),
      autoApplyConfig: true,
      trafficResetDay: 0,
      remarkModel: '-ieo'
    },
    dns: {
      strategy: 'prefer_ipv4',
      independentCache: true
    },
    inbounds: [],
    outbounds: [
      {
        id: 'out_direct',
        tag: 'direct',
        type: 'direct',
        remark: 'direct (本地直连)',
        builtin: true,
        enabled: true,
        up: 0,
        down: 0,
        settings: {}
      },
      {
        id: 'out_block',
        tag: 'block',
        type: 'block',
        remark: 'block (黑洞拦截)',
        builtin: true,
        enabled: true,
        up: 0,
        down: 0,
        settings: {}
      }
    ],
    routing: {
      final: 'direct',
      autoDetectInterface: true,
      ruleSets: [],
      rules: [
        {
          id: 'rule_sniff',
          remark: '协议嗅探 (HTTP/TLS/QUIC)',
          enabled: true,
          action: 'sniff',
          inbound: [],
          domain: [],
          domain_suffix: [],
          domain_keyword: [],
          ip_cidr: [],
          source_ip_cidr: [],
          port: [],
          source_port: [],
          network: '',
          protocol: [],
          rule_set: [],
          ip_is_private: false,
          outbound: ''
        },
        {
          id: 'rule_private_block',
          remark: '阻止私有内网探测 (geoip:private)',
          enabled: true,
          action: 'route',
          inbound: [],
          domain: [],
          domain_suffix: [],
          domain_keyword: [],
          ip_cidr: [],
          source_ip_cidr: [],
          port: [],
          source_port: [],
          network: '',
          protocol: [],
          rule_set: [],
          ip_is_private: true,
          outbound: 'block'
        },
        {
          id: 'rule_bt_block',
          remark: '禁止 BitTorrent 协议下载',
          enabled: true,
          action: 'route',
          inbound: [],
          domain: [],
          domain_suffix: [],
          domain_keyword: [],
          ip_cidr: [],
          source_ip_cidr: [],
          port: [],
          source_port: [],
          network: '',
          protocol: ['bittorrent'],
          rule_set: [],
          ip_is_private: false,
          outbound: 'block'
        }
      ]
    },
    certificates: [],
    migrations: [],
    audit: []
  };
}

class Store {
  constructor(filePath) {
    this.filePath = path.resolve(filePath);
    this.state = null;
    this._dirtyTraffic = false;
    this._lastSaveAt = 0;
    this.load();
  }

  cleanStaleTmpFiles() {
    try {
      const dir = path.dirname(this.filePath);
      const base = path.basename(this.filePath);
      for (const f of fs.readdirSync(dir)) {
        if (f.startsWith(`${base}.tmp.`)) {
          fs.rmSync(path.join(dir, f), { force: true });
        }
      }
    } catch { /* ignore */ }
  }

  load() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
    this.cleanStaleTmpFiles();
    if (!fs.existsSync(this.filePath)) {
      this.state = defaultState();
      this.save();
      return this.state;
    }
    try {
      const raw = fs.readFileSync(this.filePath, 'utf8');
      const parsed = JSON.parse(raw);
      const defaults = defaultState();
      this.state = {
        ...defaults,
        ...parsed,
        version: 2.6,
        admin: { ...defaults.admin, ...(parsed.admin || {}) },
        settings: { ...defaults.settings, ...(parsed.settings || {}) },
        dns: { ...defaults.dns, ...(parsed.dns || {}) },
        routing: {
          ...defaults.routing,
          ...(parsed.routing || {}),
          ruleSets: Array.isArray(parsed.routing?.ruleSets) ? parsed.routing.ruleSets : defaults.routing.ruleSets,
          rules: Array.isArray(parsed.routing?.rules) ? parsed.routing.rules : defaults.routing.rules
        },
        inbounds: Array.isArray(parsed.inbounds) ? parsed.inbounds : [],
        outbounds: Array.isArray(parsed.outbounds) && parsed.outbounds.length ? parsed.outbounds : defaults.outbounds,
        certificates: Array.isArray(parsed.certificates) ? parsed.certificates : [],
        migrations: Array.isArray(parsed.migrations) ? parsed.migrations.slice(0, 20) : [],
        audit: Array.isArray(parsed.audit) ? parsed.audit.slice(0, 100) : []
      };

      this.state.settings.webBasePath = normalizeBasePath(this.state.settings.webBasePath || '/');
      if (this.state.settings.strictBasePath === undefined) {
        this.state.settings.strictBasePath = true;
      }
      if (!this.state.settings.subToken || this.state.settings.subToken === 'all' || String(this.state.settings.subToken).length < 12) {
        this.state.settings.subToken = randomToken(20);
      }

      if (this.state.settings.defaultTlsDomain === 'www.bing.com' || this.state.settings.defaultTlsDomain === 'www.cloudflare.com') {
        this.state.settings.defaultTlsDomain = this.state.settings.webDomain || '';
      }

      for (const r of this.state.routing.rules || []) {
        if (r.remark) {
          r.remark = r.remark.replace(/\s*·\s*(同\s*)?3x-ui\s*(默认|标准)/gi, '');
        }
      }

      for (const inb of this.state.inbounds) {
        if (['vless', 'vmess', 'tuic'].includes(inb.protocol)) {
          for (const c of inb.clients || []) {
            if (!isValidUuid(c.id)) {
              c.id = ensureUuid(c.id);
            }
          }
        }
        for (const c of inb.clients || []) {
          if (!c.id) c.id = crypto.randomUUID();
          if (!c.subId || c.subId === 'all' || String(c.subId).length < 8) {
            c.subId = randomToken(16);
          }
        }
        if ((inb.clients?.length || 0) > 1) {
          const sumUp = inb.clients.reduce((s, c) => s + Number(c.up || 0), 0);
          const sumDown = inb.clients.reduce((s, c) => s + Number(c.down || 0), 0);
          if (sumUp > Number(inb.up || 0)) inb.up = sumUp;
          if (sumDown > Number(inb.down || 0)) inb.down = sumDown;
        }
        if (inb.security === 'reality') {
          delete inb.certPath;
          delete inb.keyPath;
          // Only rewrite broken Cloudflare or Bing SNI; preserve existing migrated SNI (such as tesla.com) so existing clients aren't disrupted
          if (inb.reality && ['www.cloudflare.com', 'cloudflare.com', 'www.bing.com'].includes(String(inb.reality.serverName || '').toLowerCase())) {
            inb.reality.serverName = 'www.apple.com';
            inb.reality.target = 'www.apple.com:443';
          }
        }
        if (inb.tlsDomain === 'www.bing.com') {
          inb.tlsDomain = this.state.settings.webDomain || this.state.settings.defaultTlsDomain || 'www.apple.com';
        }
        if (inb.limitIp === undefined) inb.limitIp = 0;
        if (inb.limitDevice === undefined) inb.limitDevice = 0;
        if (inb.expiryTime === undefined) inb.expiryTime = 0;
        if (inb.resetDay === undefined) inb.resetDay = 0;
      }

      if (process.env.NG_ADMIN_USERNAME) {
        this.state.admin.username = process.env.NG_ADMIN_USERNAME;
      }
      if (process.env.NG_ADMIN_PASSWORD) {
        this.state.admin.passwordHash = hashSecret(process.env.NG_ADMIN_PASSWORD);
      }
      if (process.env.NG_PORT) {
        this.state.settings.webPort = Number(process.env.NG_PORT);
      }
      if (process.env.NG_BASE_PATH) {
        this.state.settings.webBasePath = normalizeBasePath(process.env.NG_BASE_PATH);
      }
      this.save();
    } catch {
      this.state = defaultState();
    }
    return this.state;
  }

  save() {
    this.state.updatedAt = new Date().toISOString();
    const tmp = `${this.filePath}.tmp.${process.pid}`;
    try {
      fs.writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
      fs.renameSync(tmp, this.filePath);
      this._dirtyTraffic = false;
      this._lastSaveAt = Date.now();
    } catch {
      try { fs.rmSync(tmp, { force: true }); } catch { /* ignore */ }
    }
  }

  saveTrafficThrottled() {
    this._dirtyTraffic = true;
    if (Date.now() - this._lastSaveAt >= 60000) {
      this.save();
    }
  }

  flushIfDirty() {
    if (this._dirtyTraffic) {
      this.save();
    }
  }

  transact(mutator) {
    const result = mutator(this.state);
    this.save();
    return result;
  }

  addAudit(actor, action, target = '') {
    this.state.audit.unshift({
      id: `aud_${crypto.randomBytes(6).toString('hex')}`,
      at: new Date().toISOString(),
      actor,
      action,
      target
    });
    if (this.state.audit.length > 100) {
      this.state.audit.length = 100;
    }
  }
}

module.exports = {
  Store,
  defaultState
};
