'use strict';

const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { hashSecret, randomToken } = require('./auth');
const { normalizeBasePath } = require('./http');

function defaultState() {
  return {
    version: 2.1,
    createdAt: new Date().toISOString(),
    updatedAt: new Date().toISOString(),
    admin: {
      id: 'admin_1',
      username: process.env.NG_ADMIN_USERNAME || 'admin',
      passwordHash: hashSecret(process.env.NG_ADMIN_PASSWORD || 'admin123456'),
      updatedAt: new Date().toISOString()
    },
    settings: {
      panelTitle: 'NexusGate · 枢门 Sing-box 面板',
      webListen: process.env.NG_HOST || '0.0.0.0',
      webPort: Number(process.env.NG_PORT || 2053),
      webBasePath: normalizeBasePath(process.env.NG_BASE_PATH || '/'),
      strictBasePath: false,
      webDomain: process.env.NG_DOMAIN || '',
      webCertFile: process.env.NG_CERT_FILE || '',
      webKeyFile: process.env.NG_KEY_FILE || '',
      defaultTlsDomain: process.env.NG_DOMAIN || '',
      defaultCertFile: process.env.NG_CERT_FILE || '',
      defaultKeyFile: process.env.NG_KEY_FILE || '',
      sessionMaxAge: 720,
      subEnable: true,
      subPath: '/sub/',
      subPublicUrl: '',
      publicIPv4: '',
      publicIPv6: '',
      singboxBin: process.env.NG_SINGBOX_BIN || '/usr/local/bin/sing-box',
      singboxConfigPath: process.env.NG_SINGBOX_CONFIG || '/etc/nexusgate/sing-box/config.json',
      singboxLogLevel: 'info',
      singboxApiPort: 10085,
      clashApiPort: 10086,
      clashApiSecret: randomToken(16),
      autoApplyConfig: true,
      trafficResetDay: 0,
      remarkModel: '-ieo'
    },
    dns: {
      strategy: 'prefer_ipv4',
      independentCache: true,
      servers: [
        { tag: 'dns-remote', address: 'tls://1.1.1.1', detour: 'direct' },
        { tag: 'dns-direct', address: '223.5.5.5', detour: 'direct' },
        { tag: 'dns-block', address: 'rcode://success' }
      ],
      rules: [
        { rule_set: ['geosite-category-ads-all'], server: 'dns-block', disable_cache: true },
        { rule_set: ['geosite-cn'], server: 'dns-direct' }
      ]
    },
    inbounds: [],
    outbounds: [
      {
        id: 'out_direct',
        tag: 'direct',
        type: 'direct',
        remark: '本地直连 (Freedom)',
        builtin: true,
        enabled: true,
        settings: {}
      },
      {
        id: 'out_block',
        tag: 'block',
        type: 'block',
        remark: '黑洞拦截 (Blackhole)',
        builtin: true,
        enabled: true,
        settings: {}
      }
    ],
    routing: {
      final: 'direct',
      autoDetectInterface: true,
      defaultDomainResolver: 'dns-direct',
      ruleSets: [
        {
          tag: 'geosite-cn',
          type: 'remote',
          format: 'binary',
          url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-cn.srs',
          download_detour: 'direct',
          enabled: false
        },
        {
          tag: 'geoip-cn',
          type: 'remote',
          format: 'binary',
          url: 'https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-cn.srs',
          download_detour: 'direct',
          enabled: false
        },
        {
          tag: 'geosite-category-ads-all',
          type: 'remote',
          format: 'binary',
          url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-category-ads-all.srs',
          download_detour: 'direct',
          enabled: false
        },
        {
          tag: 'geosite-openai',
          type: 'remote',
          format: 'binary',
          url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-openai.srs',
          download_detour: 'direct',
          enabled: false
        },
        {
          tag: 'geosite-netflix',
          type: 'remote',
          format: 'binary',
          url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-netflix.srs',
          download_detour: 'direct',
          enabled: false
        },
        {
          tag: 'geosite-geolocation-!cn',
          type: 'remote',
          format: 'binary',
          url: 'https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-geolocation-!cn.srs',
          download_detour: 'direct',
          enabled: false
        }
      ],
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
          remark: '阻止私有网络探测 (防内网扫描)',
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
    this.load();
  }

  load() {
    fs.mkdirSync(path.dirname(this.filePath), { recursive: true });
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
        migrations: Array.isArray(parsed.migrations) ? parsed.migrations : [],
        audit: Array.isArray(parsed.audit) ? parsed.audit : []
      };
      // Always sanitize webBasePath in case an earlier install script injected a newline
      this.state.settings.webBasePath = normalizeBasePath(this.state.settings.webBasePath || '/');
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
    fs.writeFileSync(tmp, JSON.stringify(this.state), { mode: 0o600 });
    fs.renameSync(tmp, this.filePath);
  }

  transact(mutator) {
    const result = mutator(this.state);
    this.save();
    return result;
  }

  addAudit(actor, action, target, detail = '') {
    this.state.audit.unshift({
      id: `aud_${crypto.randomBytes(6).toString('hex')}`,
      at: new Date().toISOString(),
      actor: actor || 'admin',
      action,
      target: String(target || ''),
      detail: String(detail || '')
    });
    if (this.state.audit.length > 250) {
      this.state.audit.length = 250;
    }
  }
}

module.exports = { Store, defaultState };
