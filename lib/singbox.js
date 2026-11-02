'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
const http = require('node:http');
const { spawn, spawnSync } = require('node:child_process');
const { toSingboxInbound, toSingboxOutbound } = require('./protocols');

const KNOWN_VERSIONS = [
  'v1.12.23',
  'v1.12.15',
  'v1.12.0',
  'v1.11.15',
  'v1.11.8',
  'v1.10.7'
];

// Built-in zero-dependency domain lists so Sing-box starts in <5ms without hanging on remote GitHub .srs downloads
const BUILTIN_GEOSITE_EXPANSIONS = {
  'category-ads-all': {
    domain_suffix: ['doubleclick.net', 'googlesyndication.com', 'googleadservices.com', 'adnxs.com', 'adsrvr.org', 'criteo.com', 'taboola.com', 'outbrain.com', 'scorecardresearch.com'],
    domain_keyword: ['adservice', 'pagead2', 'omtrdc']
  },
  openai: {
    domain_suffix: [
      'openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'auth0.com',
      'anthropic.com', 'claude.ai', 'claudeusercontent.com',
      'gemini.google.com', 'bard.google.com', 'generativelanguage.googleapis.com', 'aistudio.google.com',
      'perplexity.ai', 'x.ai', 'grok.com', 'cursor.sh', 'cursor.com', 'copilot.microsoft.com',
      'huggingface.co', 'midjourney.com', 'poe.com', 'coze.com', 'dify.ai'
    ]
  },
  google: {
    domain_suffix: ['google.com', 'googleapis.com', 'gstatic.com', 'googleusercontent.com', 'googlevideo.com', 'youtube.com', 'ytimg.com', 'ggpht.com', 'gmail.com', 'android.com', 'play.googleapis.com']
  },
  netflix: {
    domain_suffix: ['netflix.com', 'netflix.net', 'nflxvideo.net', 'nflximg.net', 'nflximg.com', 'nflxext.com', 'nflxso.net', 'fast.com']
  },
  cn: {
    domain_suffix: ['cn', 'baidu.com', 'qq.com', 'weixin.qq.com', 'taobao.com', 'tmall.com', 'alipay.com', 'aliyun.com', '163.com', '126.com', 'jd.com', 'bilibili.com', 'hdslb.com', 'douyin.com', 'bytedance.com', 'weibo.com', 'zhihu.com', 'xiaomi.com', 'huawei.com']
  },
  'geolocation-!cn': {
    domain_suffix: ['google.com', 'youtube.com', 'facebook.com', 'instagram.com', 'twitter.com', 'x.com', 'tiktok.com', 'whatsapp.com', 'telegram.org', 't.me', 'github.com', 'openai.com', 'chatgpt.com', 'claude.ai', 'netflix.com', 'amazon.com', 'shopify.com', 'paypal.com', 'stripe.com', 'linkedin.com']
  }
};

const BUILTIN_GEOIP_CIDRS = {
  cn: [
    '1.0.1.0/24', '1.0.2.0/23', '1.0.8.0/21', '1.1.0.0/24', '1.2.0.0/22', '1.4.1.0/24',
    '14.0.0.0/8', '27.0.0.0/8', '36.0.0.0/8', '39.0.0.0/8', '42.0.0.0/8', '49.0.0.0/8',
    '58.0.0.0/8', '59.0.0.0/8', '60.0.0.0/8', '61.0.0.0/8', '101.0.0.0/8', '103.0.0.0/8',
    '106.0.0.0/8', '110.0.0.0/7', '112.0.0.0/6', '116.0.0.0/6', '120.0.0.0/6', '124.0.0.0/7',
    '139.0.0.0/8', '140.205.0.0/16', '171.0.0.0/8', '175.0.0.0/8', '180.0.0.0/6', '182.0.0.0/8',
    '183.0.0.0/8', '202.0.0.0/8', '210.0.0.0/7', '218.0.0.0/7', '220.0.0.0/6'
  ]
};

function stripAnsi(str) {
  return String(str || '').replace(/\x1b\[[0-9;]*m/g, '');
}

function cleanArray(val) {
  if (!val) return [];
  if (Array.isArray(val)) return val.map((x) => String(x).trim()).filter(Boolean);
  return String(val)
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
}

/**
 * Parses 3x-ui / v2ray style domain/ip expressions into Sing-box native route rule fields.
 * Uses local built-in expansions for geosite/geoip when local .srs files are not present so Sing-box never hangs on startup.
 */
function compileRouteRule(rule, neededRuleSets) {
  const sbRule = {};

  const inbounds = cleanArray(rule.inbound || rule.inboundTag);
  if (inbounds.length) sbRule.inbound = inbounds;

  const protocols = cleanArray(rule.protocol);
  if (protocols.length) sbRule.protocol = protocols;

  if (rule.network && ['tcp', 'udp'].includes(String(rule.network).toLowerCase())) {
    sbRule.network = String(rule.network).toLowerCase();
  }

  const domains = cleanArray(rule.domain);
  const domainSuffix = cleanArray(rule.domain_suffix);
  const domainKeyword = cleanArray(rule.domain_keyword);
  const domainRegex = cleanArray(rule.domain_regex);
  const rawRuleSets = cleanArray(rule.rule_set);
  const localRuleSets = new Set();

  const applyGeositeName = (name) => {
    const cleanName = String(name || '').trim().toLowerCase();
    if (!cleanName) return;
    const localSrs = `/etc/nexusgate/sing-box/rulesets/geosite-${cleanName}.srs`;
    if (fs.existsSync(localSrs)) {
      const tag = `geosite-${cleanName}`;
      localRuleSets.add(tag);
      neededRuleSets.set(tag, localSrs);
      return;
    }
    const builtin = BUILTIN_GEOSITE_EXPANSIONS[cleanName];
    if (builtin) {
      if (builtin.domain_suffix) domainSuffix.push(...builtin.domain_suffix);
      if (builtin.domain_keyword) domainKeyword.push(...builtin.domain_keyword);
    } else {
      domainKeyword.push(cleanName);
    }
  };

  const applyGeoipName = (name, ipCidrsArr) => {
    const cleanName = String(name || '').trim().toLowerCase();
    if (!cleanName) return;
    const localSrs = `/etc/nexusgate/sing-box/rulesets/geoip-${cleanName}.srs`;
    if (fs.existsSync(localSrs)) {
      const tag = `geoip-${cleanName}`;
      localRuleSets.add(tag);
      neededRuleSets.set(tag, localSrs);
      return;
    }
    const builtinCidrs = BUILTIN_GEOIP_CIDRS[cleanName];
    if (builtinCidrs) {
      ipCidrsArr.push(...builtinCidrs);
    }
  };

  for (const rs of rawRuleSets) {
    if (rs.startsWith('geosite-')) {
      applyGeositeName(rs.slice(8));
    } else if (rs.startsWith('geoip-')) {
      // handled below with ipCidrs
    }
  }

  const exactDomains = [];
  for (const item of domains) {
    if (item.startsWith('geosite:')) {
      applyGeositeName(item.slice(8));
    } else if (item.startsWith('domain:')) {
      domainSuffix.push(item.slice(7).trim());
    } else if (item.startsWith('full:')) {
      exactDomains.push(item.slice(5).trim());
    } else if (item.startsWith('keyword:')) {
      domainKeyword.push(item.slice(8).trim());
    } else if (item.startsWith('regexp:') || item.startsWith('regex:')) {
      domainRegex.push(item.replace(/^regex(p)?:/, '').trim());
    } else if (!item.startsWith('ext:')) {
      domainSuffix.push(item);
    }
  }

  if (exactDomains.length) sbRule.domain = [...new Set(exactDomains)];
  if (domainSuffix.length) sbRule.domain_suffix = [...new Set(domainSuffix)];
  if (domainKeyword.length) sbRule.domain_keyword = [...new Set(domainKeyword)];
  if (domainRegex.length) sbRule.domain_regex = [...new Set(domainRegex)];

  const ipCidrs = [];
  let ipIsPrivate = Boolean(rule.ip_is_private);
  for (const rs of rawRuleSets) {
    if (rs.startsWith('geoip-')) {
      applyGeoipName(rs.slice(6), ipCidrs);
    }
  }
  for (const item of cleanArray(rule.ip || rule.ip_cidr)) {
    if (item === 'geoip:private') {
      ipIsPrivate = true;
    } else if (item.startsWith('geoip:')) {
      applyGeoipName(item.slice(6), ipCidrs);
    } else {
      ipCidrs.push(item);
    }
  }
  if (ipIsPrivate) sbRule.ip_is_private = true;
  if (ipCidrs.length) sbRule.ip_cidr = [...new Set(ipCidrs)];

  const sourceIpCidrs = cleanArray(rule.source_ip_cidr || rule.sourceIP).filter((x) => !x.startsWith('geoip:'));
  if (sourceIpCidrs.length) sbRule.source_ip_cidr = sourceIpCidrs;

  const parsePorts = (rawPorts) => {
    const ports = [];
    const ranges = [];
    for (const p of cleanArray(rawPorts)) {
      if (p.includes('-')) {
        const [a, b] = p.split('-').map((n) => Number(n.trim()));
        if (Number.isInteger(a) && Number.isInteger(b)) ranges.push(`${a}:${b}`);
      } else if (p.includes(':')) {
        ranges.push(p);
      } else {
        const num = Number(p);
        if (Number.isInteger(num) && num > 0) ports.push(num);
      }
    }
    return { ports, ranges };
  };

  const dstP = parsePorts(rule.port);
  if (dstP.ports.length) sbRule.port = dstP.ports;
  if (dstP.ranges.length) sbRule.port_range = dstP.ranges;

  const srcP = parsePorts(rule.source_port || rule.sourcePort);
  if (srcP.ports.length) sbRule.source_port = srcP.ports;
  if (srcP.ranges.length) sbRule.source_port_range = srcP.ranges;

  const authUsers = cleanArray(rule.auth_user || rule.user);
  if (authUsers.length) sbRule.auth_user = authUsers;

  if (localRuleSets.size) sbRule.rule_set = [...localRuleSets];

  const targetOutbound = rule.outbound || rule.outboundTag || 'direct';
  if (rule.action === 'sniff') {
    sbRule.action = 'sniff';
  } else if (rule.action === 'reject' || targetOutbound === 'block' || targetOutbound === 'blocked') {
    sbRule.outbound = 'block';
  } else {
    sbRule.outbound = targetOutbound;
  }

  return sbRule;
}

/**
 * Generates the complete Sing-box JSON configuration from current panel state.
 * Compatible with Sing-box 1.10, 1.11, 1.12, 1.13, and 1.14 without deprecated legacy DNS warnings.
 */
function buildSingboxConfig(state) {
  const settings = state.settings || {};
  const activeInbounds = (state.inbounds || []).filter((i) => i.enable !== false);
  const activeOutbounds = (state.outbounds || []).filter((o) => o.enabled !== false);

  const validInboundTags = new Set(activeInbounds.map((i) => i.tag || `in-${i.protocol}-${i.port}`));
  const sbInbounds = activeInbounds.map((item) => toSingboxInbound(item, state.certificates || [], settings));
  const sbOutbounds = activeOutbounds.map((item) => toSingboxOutbound(item));

  if (!sbOutbounds.some((o) => o.tag === 'direct')) {
    sbOutbounds.unshift({ type: 'direct', tag: 'direct' });
  }
  if (!sbOutbounds.some((o) => o.tag === 'block')) {
    sbOutbounds.push({ type: 'block', tag: 'block' });
  }

  const validOutboundTags = new Set(sbOutbounds.map((o) => o.tag));
  const neededRuleSets = new Map();
  const routeRules = [];

  // 1. Sniff rule first
  routeRules.push({ action: 'sniff' });

  // 2. Per-inbound bound outbound relay rules (unless already explicitly in routing.rules)
  const existingRuleInbounds = new Set();
  for (const r of (state.routing?.rules || [])) {
    if (r.enabled !== false && Array.isArray(r.inbound) && r.inbound.length === 1 && !r.domain?.length && !r.ip_cidr?.length && !r.port?.length) {
      existingRuleInbounds.add(r.inbound[0]);
    }
  }
  for (const inb of activeInbounds) {
    const tag = inb.tag || `in-${inb.protocol}-${inb.port}`;
    if (inb.outboundTag && inb.outboundTag !== 'default' && validOutboundTags.has(inb.outboundTag) && !existingRuleInbounds.has(tag)) {
      routeRules.push({
        inbound: [tag],
        outbound: inb.outboundTag
      });
    }
  }

  // 3. Custom & 3x-ui style routing rules
  for (const rule of (state.routing?.rules || [])) {
    if (rule.enabled === false) continue;
    if (rule.action === 'sniff') continue;
    const compiled = compileRouteRule(rule, neededRuleSets);

    // Filter out any non-existent inbound tags so Sing-box never fails if a rule references a disabled/deleted inbound
    if (Array.isArray(compiled.inbound)) {
      compiled.inbound = compiled.inbound.filter((t) => validInboundTags.has(t));
      if (compiled.inbound.length === 0) {
        continue;
      }
    }

    if (compiled.outbound && !validOutboundTags.has(compiled.outbound)) {
      compiled.outbound = 'direct';
    }
    const hasCondition = Object.keys(compiled).some((k) => !['action', 'outbound'].includes(k));
    if (hasCondition) {
      routeRules.push(compiled);
    }
  }

  const finalRuleSets = [];
  for (const [tag, localPath] of neededRuleSets.entries()) {
    finalRuleSets.push({
      tag,
      type: 'local',
      format: 'binary',
      path: localPath
    });
  }

  const finalOutbound = validOutboundTags.has(state.routing?.final) ? state.routing.final : 'direct';

  return {
    log: {
      level: settings.singboxLogLevel || 'info',
      timestamp: true
    },
    inbounds: sbInbounds,
    outbounds: sbOutbounds,
    route: {
      rules: routeRules,
      ...(finalRuleSets.length ? { rule_set: finalRuleSets } : {}),
      final: finalOutbound,
      auto_detect_interface: true
    },
    experimental: {
      clash_api: {
        external_controller: `127.0.0.1:${settings.clashApiPort || 10086}`,
        secret: settings.clashApiSecret || ''
      }
    }
  };
}

/**
 * Computes the current monthly reset cycle key (YYYY-MM) for a given resetDay (1..31) and reference date.
 */
function computeResetCycleKey(resetDay, nowDate = new Date()) {
  const rDay = Number(resetDay || 0);
  if (!Number.isInteger(rDay) || rDay < 1 || rDay > 31) return '';
  let year = nowDate.getFullYear();
  let month = nowDate.getMonth(); // 0..11
  const daysInThisMonth = new Date(year, month + 1, 0).getDate();
  const effectiveResetDay = Math.min(rDay, daysInThisMonth);
  if (nowDate.getDate() < effectiveResetDay) {
    month -= 1;
    if (month < 0) {
      month = 11;
      year -= 1;
    }
  }
  return `${year}-${String(month + 1).padStart(2, '0')}`;
}

class SingboxManager {
  constructor(store) {
    this.store = store;
    this.childProcess = null;
    this.lastError = '';
    this.logRing = [];
    this.startedAt = null;
    this.connTrafficCache = new Map();
    this.activeIpsByTag = new Map();
    this.activeDevicesByTag = new Map();
    this.activeConns = [];
  }

  appendLog(line) {
    const clean = stripAnsi(line).trim();
    if (!clean) return;
    this.logRing.push(`${new Date().toISOString()} ${clean}`);
    if (this.logRing.length > 300) {
      this.logRing.shift();
    }
  }

  getBinPath() {
    return this.store.state.settings.singboxBin || '/usr/local/bin/sing-box';
  }

  getConfigPath() {
    const cfg = this.store.state.settings.singboxConfigPath || '/etc/nexusgate/sing-box/config.json';
    try {
      fs.mkdirSync(path.dirname(cfg), { recursive: true });
      return cfg;
    } catch {
      const fallback = path.join(path.dirname(this.store.filePath), 'sing-box-config.json');
      fs.mkdirSync(path.dirname(fallback), { recursive: true });
      return fallback;
    }
  }

  ensureFallbackSelfSignedCert() {
    const certDir = '/etc/nexusgate/certs/selfsigned';
    let targetDir = certDir;
    try {
      fs.mkdirSync(certDir, { recursive: true });
    } catch {
      targetDir = path.join(path.dirname(this.store.filePath), 'certs', 'selfsigned');
      fs.mkdirSync(targetDir, { recursive: true });
    }
    const certFile = path.join(targetDir, 'fullchain.pem');
    const keyFile = path.join(targetDir, 'privkey.pem');
    const cn = this.store.state.settings.webDomain || 'www.apple.com';
    if (!fs.existsSync(certFile) || !fs.existsSync(keyFile)) {
      spawnSync('openssl', [
        'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
        '-days', '3650', '-nodes', '-subj', `/CN=${cn}`,
        '-keyout', keyFile, '-out', certFile
      ], { encoding: 'utf8', timeout: 10000 });
    }
    return { certFile, keyFile };
  }

  writeConfig() {
    const fallbackCert = this.ensureFallbackSelfSignedCert();
    const config = buildSingboxConfig(this.store.state);
    for (const inb of config.inbounds || []) {
      if (inb.tls && inb.tls.reality?.enabled) {
        // Reality MUST NEVER have certificate_path or key_path in Sing-box!
        delete inb.tls.certificate_path;
        delete inb.tls.key_path;
      } else if (inb.tls && (!inb.tls.certificate_path || !fs.existsSync(inb.tls.certificate_path))) {
        inb.tls.certificate_path = fallbackCert.certFile;
        inb.tls.key_path = fallbackCert.keyFile;
      }
    }
    const configPath = this.getConfigPath();
    const json = JSON.stringify(config, null, 2);
    fs.writeFileSync(configPath, json, { mode: 0o600 });
    return { configPath, config };
  }

  getVersion() {
    const bin = this.getBinPath();
    if (!fs.existsSync(bin)) return { installed: false, version: '未安装', binary: bin };
    try {
      const res = spawnSync(bin, ['version'], { encoding: 'utf8', timeout: 5000 });
      const out = stripAnsi(res.stdout || res.stderr || '');
      const match = out.match(/sing-box\s+version\s+([^\s\n]+)/i);
      return {
        installed: true,
        version: match ? match[1] : out.split('\n')[0].trim() || '已安装',
        detail: out.trim(),
        binary: bin
      };
    } catch (err) {
      return { installed: false, version: '检测失败', error: err.message, binary: bin };
    }
  }

  checkConfig() {
    const { configPath, config } = this.writeConfig();
    const bin = this.getBinPath();
    if (!fs.existsSync(bin)) {
      this.lastError = '';
      return { valid: true, warning: 'sing-box 二进制尚未安装，已生成合法配置文件', configPath, config };
    }
    const res = spawnSync(bin, ['check', '-c', configPath], { encoding: 'utf8', timeout: 10000 });
    if (res.status !== 0) {
      const msg = stripAnsi(res.stderr || res.stdout || '配置检查失败').trim();
      this.lastError = msg;
      return { valid: false, error: msg, configPath, config };
    }
    this.lastError = '';
    return { valid: true, configPath, config };
  }

  getStatus() {
    const ver = this.getVersion();
    const hasFatalError = Boolean(this.lastError);

    if (fs.existsSync('/run/systemd/system')) {
      const sys = spawnSync('systemctl', ['is-active', 'nexusgate-singbox.service'], { encoding: 'utf8', timeout: 3000 });
      if (String(sys.stdout || '').trim() === 'active') {
        return {
          state: hasFatalError ? 'error' : 'running',
          mode: 'systemd',
          version: ver.version,
          installed: ver.installed,
          binary: ver.binary,
          configPath: this.getConfigPath(),
          lastError: this.lastError
        };
      }
    }
    if (this.childProcess && this.childProcess.exitCode === null) {
      return {
        state: hasFatalError ? 'error' : 'running',
        mode: 'process',
        pid: this.childProcess.pid,
        version: ver.version,
        installed: ver.installed,
        binary: ver.binary,
        configPath: this.getConfigPath(),
        lastError: this.lastError
      };
    }
    const pgrep = spawnSync('pgrep', ['-f', 'sing-box run'], { encoding: 'utf8', timeout: 2000 });
    if (pgrep.status === 0 && String(pgrep.stdout || '').trim()) {
      return {
        state: hasFatalError ? 'error' : 'running',
        mode: 'daemon',
        pid: Number(String(pgrep.stdout).trim().split('\n')[0]),
        version: ver.version,
        installed: ver.installed,
        binary: ver.binary,
        configPath: this.getConfigPath(),
        lastError: this.lastError
      };
    }
    return {
      state: this.lastError ? 'error' : 'stop',
      mode: 'none',
      version: ver.version,
      installed: ver.installed,
      binary: ver.binary,
      configPath: this.getConfigPath(),
      lastError: this.lastError
    };
  }

  restart() {
    const check = this.checkConfig();
    if (!check.valid) {
      throw new Error(`Sing-box 配置校验未通过: ${check.error}`);
    }
    const bin = this.getBinPath();
    if (!fs.existsSync(bin)) {
      this.appendLog(`配置文件已更新并写入 ${check.configPath} (等待安装 sing-box 内核后启动)`);
      return { status: 'configured', message: '配置已保存（当前环境尚未安装 sing-box 二进制，可在内核版本管理中一键安装）', configPath: check.configPath };
    }

    if (fs.existsSync('/run/systemd/system') && fs.existsSync('/etc/systemd/system/nexusgate-singbox.service')) {
      const res = spawnSync('systemctl', ['restart', 'nexusgate-singbox.service'], { encoding: 'utf8', timeout: 15000 });
      if (res.status === 0) {
        this.lastError = '';
        this.appendLog('已通过 systemd 重启 nexusgate-singbox 服务');
        return { status: 'running', mode: 'systemd' };
      }
    }

    this.stop();
    const child = spawn(bin, ['run', '-c', check.configPath], {
      stdio: ['ignore', 'pipe', 'pipe'],
      detached: false
    });
    this.childProcess = child;
    this.startedAt = Date.now();
    this.lastError = '';
    child.stdout.on('data', (d) => this.appendLog(d.toString()));
    child.stderr.on('data', (d) => this.appendLog(d.toString()));
    child.on('exit', (code) => {
      if (code !== 0 && code !== null) {
        this.lastError = `Sing-box 进程退出 (code ${code})`;
        this.appendLog(this.lastError);
      }
    });
    this.appendLog(`已启动 Sing-box 进程 (PID: ${child.pid})`);
    return { status: 'running', pid: child.pid };
  }

  stop() {
    if (fs.existsSync('/run/systemd/system') && fs.existsSync('/etc/systemd/system/nexusgate-singbox.service')) {
      spawnSync('systemctl', ['stop', 'nexusgate-singbox.service'], { encoding: 'utf8', timeout: 10000 });
    }
    if (this.childProcess && this.childProcess.exitCode === null) {
      try {
        this.childProcess.kill('SIGTERM');
      } catch { /* ignore */ }
      this.childProcess = null;
    }
    spawnSync('pkill', ['-f', `sing-box run -c ${this.getConfigPath()}`], { encoding: 'utf8', timeout: 3000 });
    this.appendLog('已停止 Sing-box 服务');
    return { status: 'stopped' };
  }

  getLogs() {
    if (fs.existsSync('/run/systemd/system') && fs.existsSync('/etc/systemd/system/nexusgate-singbox.service')) {
      const j = spawnSync('journalctl', ['-u', 'nexusgate-singbox.service', '-n', '120', '--no-pager'], { encoding: 'utf8', timeout: 4000 });
      if (j.status === 0 && j.stdout.trim()) {
        return stripAnsi(j.stdout).trim().split('\n');
      }
    }
    return this.logRing.length ? this.logRing : ['暂无运行日志，启动或重载 Sing-box 后将在此显示实时输出。'];
  }

  /**
   * Checks and executes monthly scheduled traffic resets (e.g. resetDay = 1..31 of each month).
   * Returns { resetCount, needReload }.
   */
  checkAndResetMonthlyTraffic(nowDate = new Date()) {
    let resetCount = 0;
    let needReload = false;
    const globalResetDay = Number(this.store.state.settings?.trafficResetDay || 0);

    for (const inb of this.store.state.inbounds || []) {
      const rDay = Number(inb.resetDay !== undefined ? inb.resetDay : globalResetDay);
      if (!rDay || rDay < 1 || rDay > 31) continue;

      const cycleKey = computeResetCycleKey(rDay, nowDate);
      if (!cycleKey) continue;

      if (!inb.lastResetCycle) {
        inb.lastResetCycle = cycleKey;
        continue;
      }

      if (inb.lastResetCycle !== cycleKey) {
        inb.up = 0;
        inb.down = 0;
        for (const c of inb.clients || []) {
          c.up = 0;
          c.down = 0;
        }
        inb.lastResetCycle = cycleKey;
        inb.lastResetAt = nowDate.toISOString();
        resetCount += 1;

        const isExpired = inb.expiryTime && inb.expiryTime > 0 && nowDate.getTime() > inb.expiryTime;
        if (inb.enable === false && inb.disabledReason === 'quota' && !isExpired) {
          inb.enable = true;
          delete inb.disabledReason;
          needReload = true;
        }
        this.appendLog(`[月度流量自动重置] 入站 ${inb.remark} 已到达每月 ${rDay} 号重置周期 (${cycleKey})，已自动清零流量`);
      }
    }

    if (resetCount > 0) {
      this.store.save();
    }
    return { resetCount, needReload };
  }

  /**
   * Queries Sing-box Clash API /connections to track real-time traffic for BOTH inbounds and outbounds,
   * monitor online client IPs & device counts separately, and enforce limitIp, limitDevice, expiryTime, and monthly traffic reset.
   */
  async pollConnectionsAndEnforceLimits(nowDate = new Date()) {
    const port = this.store.state.settings.clashApiPort || 10086;
    const secret = this.store.state.settings.clashApiSecret || '';

    const fetchClashConnections = () => new Promise((resolve) => {
      const req = http.request({
        hostname: '127.0.0.1',
        port,
        path: '/connections',
        method: 'GET',
        headers: secret ? { Authorization: `Bearer ${secret}` } : {},
        timeout: 2000
      }, (res) => {
        const chunks = [];
        res.on('data', (c) => chunks.push(c));
        res.on('end', () => {
          try {
            resolve(JSON.parse(Buffer.concat(chunks).toString('utf8')));
          } catch {
            resolve(null);
          }
        });
      });
      req.on('error', () => resolve(null));
      req.on('timeout', () => { req.destroy(); resolve(null); });
      req.end();
    });

    const data = await fetchClashConnections();
    const conns = (data && Array.isArray(data.connections)) ? data.connections : [];
    this.activeConns = conns;

    const nextIpsByTag = new Map();
    const nextDevicesByTag = new Map();
    const currentConnIds = new Set();
    let trafficChanged = false;
    let needReload = false;

    for (const c of conns) {
      if (!c || !c.id) continue;
      currentConnIds.add(c.id);
      const inbTag = c.metadata?.inbound || '';
      const srcIp = c.metadata?.sourceIP || '';
      const srcPort = Number(c.metadata?.sourcePort || 0);
      const authUser = c.metadata?.user || 'default';
      const chains = Array.isArray(c.chains) ? c.chains : [];
      const up = Number(c.upload || 0);
      const down = Number(c.download || 0);

      const prev = this.connTrafficCache.get(c.id) || { up: 0, down: 0 };
      const deltaUp = Math.max(0, up - prev.up);
      const deltaDown = Math.max(0, down - prev.down);
      this.connTrafficCache.set(c.id, { up, down });

      if (deltaUp > 0 || deltaDown > 0) {
        for (const outTag of chains) {
          const outObj = this.store.state.outbounds.find((o) => o.tag === outTag);
          if (outObj) {
            outObj.up = Number(outObj.up || 0) + deltaUp;
            outObj.down = Number(outObj.down || 0) + deltaDown;
            trafficChanged = true;
          }
        }
      }

      if (inbTag) {
        const inb = this.store.state.inbounds.find((i) => i.tag === inbTag || `in-${i.protocol}-${i.port}` === inbTag);
        if (inb) {
          if (deltaUp > 0 || deltaDown > 0) {
            inb.up = Number(inb.up || 0) + deltaUp;
            inb.down = Number(inb.down || 0) + deltaDown;
            trafficChanged = true;
          }
          if (srcIp) {
            if (!nextIpsByTag.has(inb.tag)) nextIpsByTag.set(inb.tag, new Set());
            if (!nextDevicesByTag.has(inb.tag)) nextDevicesByTag.set(inb.tag, new Set());
            const ipSet = nextIpsByTag.get(inb.tag);
            const devSet = nextDevicesByTag.get(inb.tag);

            // Device fingerprint combines (srcIp, authUser, ephemeral port range bucket) to distinguish multiple devices behind NAT
            const portBucket = srcPort > 0 ? Math.floor(srcPort / 8192) : 0;
            const deviceFp = `${srcIp}#${authUser}#${portBucket}`;

            const limitIp = Number(inb.limitIp || (inb.clients && inb.clients[0]?.limitIp) || 0);
            const limitDevice = Number(inb.limitDevice || (inb.clients && inb.clients[0]?.limitDevice) || 0);

            if (limitIp > 0 && !ipSet.has(srcIp) && ipSet.size >= limitIp) {
              this.closeConnection(c.id);
              this.appendLog(`[IP限制触发] 入站 ${inb.remark} 已达最大同时在线公网 IP 数 (${limitIp})，已断开新 IP: ${srcIp}`);
            } else if (limitDevice > 0 && !devSet.has(deviceFp) && devSet.size >= limitDevice) {
              this.closeConnection(c.id);
              this.appendLog(`[设备限制触发] 入站 ${inb.remark} 已达最大同时在线设备数 (${limitDevice})，已断开新设备连接 (${srcIp})`);
            } else {
              ipSet.add(srcIp);
              devSet.add(deviceFp);
            }
          }
        }
      }
    }

    for (const id of this.connTrafficCache.keys()) {
      if (!currentConnIds.has(id)) this.connTrafficCache.delete(id);
    }

    this.activeIpsByTag = nextIpsByTag;
    this.activeDevicesByTag = nextDevicesByTag;

    // Monthly auto traffic reset check
    const monthlyReset = this.checkAndResetMonthlyTraffic(nowDate);
    if (monthlyReset.needReload) needReload = true;

    const nowMs = nowDate.getTime();
    for (const inb of this.store.state.inbounds) {
      if (inb.enable === false) continue;
      if (inb.expiryTime && inb.expiryTime > 0 && nowMs > inb.expiryTime) {
        inb.enable = false;
        inb.disabledReason = 'expired';
        trafficChanged = true;
        needReload = true;
        this.appendLog(`[到期自动停用] 入站 ${inb.remark} 已到期`);
      } else if (inb.total && inb.total > 0 && (Number(inb.up || 0) + Number(inb.down || 0)) >= inb.total) {
        inb.enable = false;
        inb.disabledReason = 'quota';
        trafficChanged = true;
        needReload = true;
        this.appendLog(`[流量达标停用] 入站 ${inb.remark} 已用尽配额`);
      }
    }

    if (trafficChanged) {
      this.store.save();
    }
    if (needReload) {
      try { this.restart(); } catch { /* ignore */ }
    }
  }

  closeConnection(connId) {
    const port = this.store.state.settings.clashApiPort || 10086;
    const secret = this.store.state.settings.clashApiSecret || '';
    const req = http.request({
      hostname: '127.0.0.1',
      port,
      path: `/connections/${encodeURIComponent(connId)}`,
      method: 'DELETE',
      headers: secret ? { Authorization: `Bearer ${secret}` } : {},
      timeout: 2000
    });
    req.on('error', () => {});
    req.end();
  }

  getActiveIpsForInbound(tag) {
    return [...(this.activeIpsByTag.get(tag) || [])];
  }

  getActiveDeviceCountForInbound(tag) {
    const devSet = this.activeDevicesByTag.get(tag);
    const ipSet = this.activeIpsByTag.get(tag);
    return Math.max(devSet ? devSet.size : 0, ipSet ? ipSet.size : 0);
  }

  async installVersion(versionTag = 'v1.12.23') {
    const cleanVer = String(versionTag || 'v1.12.23').trim().replace(/^v/, '');
    if (!/^[0-9]+\.[0-9]+\.[0-9]+(-[A-Za-z0-9.]+)?$/.test(cleanVer)) {
      throw new Error('版本号格式无效，例如 v1.12.23');
    }
    const archMap = { x64: 'amd64', arm64: 'arm64', arm: 'armv7' };
    const sbArch = archMap[os.arch()] || 'amd64';
    const tarball = `sing-box-${cleanVer}-linux-${sbArch}.tar.gz`;
    const url = `https://github.com/SagerNet/sing-box/releases/download/v${cleanVer}/${tarball}`;

    const tmpDir = fs.mkdtempSync(path.join(os.tmpdir(), 'ng-sb-'));
    try {
      this.appendLog(`开始下载 Sing-box v${cleanVer} (${sbArch}): ${url}`);
      const dl = spawnSync('curl', ['-fL', '--retry', '3', '--connect-timeout', '15', url, '-o', path.join(tmpDir, tarball)], {
        encoding: 'utf8',
        timeout: 120000
      });
      if (dl.status !== 0) {
        throw new Error(`下载 Sing-box v${cleanVer} 失败 (请检查服务器网络或 GitHub 连接): ${dl.stderr || dl.stdout}`);
      }
      const ex = spawnSync('tar', ['-xzf', path.join(tmpDir, tarball), '-C', tmpDir, '--strip-components=1'], {
        encoding: 'utf8',
        timeout: 30000
      });
      const extractedBin = path.join(tmpDir, 'sing-box');
      if (ex.status !== 0 || !fs.existsSync(extractedBin)) {
        throw new Error('解压 Sing-box 安装包失败');
      }

      const targetBin = this.getBinPath();
      fs.mkdirSync(path.dirname(targetBin), { recursive: true });
      fs.copyFileSync(extractedBin, `${targetBin}.next`);
      fs.chmodSync(`${targetBin}.next`, 0o755);
      fs.renameSync(`${targetBin}.next`, targetBin);

      this.appendLog(`成功切换 Sing-box 内核版本至 v${cleanVer}`);
      try {
        this.restart();
      } catch { /* ignore */ }
      return this.getVersion();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }
}

module.exports = {
  KNOWN_VERSIONS,
  BUILTIN_GEOSITE_EXPANSIONS,
  computeResetCycleKey,
  buildSingboxConfig,
  compileRouteRule,
  SingboxManager
};
