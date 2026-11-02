'use strict';

const fs = require('node:fs');
const path = require('node:path');
const os = require('node:os');
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

function cleanArray(val) {
  if (!val) return [];
  if (Array.isArray(val)) return val.map((x) => String(x).trim()).filter(Boolean);
  return String(val)
    .split(',')
    .map((x) => x.trim())
    .filter(Boolean);
}

/**
 * Parses 3x-ui / v2ray style domain/ip expressions (e.g. geosite:cn, domain:google.com, full:a.com, geoip:private)
 * into Sing-box native route rule fields and automatically enables required rule_sets.
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
  const ruleSets = new Set(cleanArray(rule.rule_set));

  const exactDomains = [];
  for (const item of domains) {
    if (item.startsWith('geosite:')) {
      const name = item.slice(8).trim();
      if (name) {
        const tag = `geosite-${name}`;
        ruleSets.add(tag);
        neededRuleSets.add(tag);
      }
    } else if (item.startsWith('domain:')) {
      domainSuffix.push(item.slice(7).trim());
    } else if (item.startsWith('full:')) {
      exactDomains.push(item.slice(5).trim());
    } else if (item.startsWith('keyword:')) {
      domainKeyword.push(item.slice(8).trim());
    } else if (item.startsWith('regexp:') || item.startsWith('regex:')) {
      domainRegex.push(item.replace(/^regex(p)?:/, '').trim());
    } else if (item.startsWith('ext:')) {
      // ignore legacy v2ray ext
    } else {
      domainSuffix.push(item);
    }
  }

  if (exactDomains.length) sbRule.domain = [...new Set(exactDomains)];
  if (domainSuffix.length) sbRule.domain_suffix = [...new Set(domainSuffix)];
  if (domainKeyword.length) sbRule.domain_keyword = [...new Set(domainKeyword)];
  if (domainRegex.length) sbRule.domain_regex = [...new Set(domainRegex)];

  const ipCidrs = [];
  let ipIsPrivate = Boolean(rule.ip_is_private);
  for (const item of cleanArray(rule.ip || rule.ip_cidr)) {
    if (item === 'geoip:private') {
      ipIsPrivate = true;
    } else if (item.startsWith('geoip:')) {
      const name = item.slice(6).trim();
      if (name) {
        const tag = `geoip-${name}`;
        ruleSets.add(tag);
        neededRuleSets.add(tag);
      }
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

  for (const rs of ruleSets) neededRuleSets.add(rs);
  if (ruleSets.size) sbRule.rule_set = [...ruleSets];

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
 */
function buildSingboxConfig(state) {
  const settings = state.settings || {};
  const activeInbounds = (state.inbounds || []).filter((i) => i.enable !== false);
  const activeOutbounds = (state.outbounds || []).filter((o) => o.enabled !== false);

  const sbInbounds = activeInbounds.map((item) => toSingboxInbound(item, state.certificates || []));
  const sbOutbounds = activeOutbounds.map((item) => toSingboxOutbound(item));

  if (!sbOutbounds.some((o) => o.tag === 'direct')) {
    sbOutbounds.unshift({ type: 'direct', tag: 'direct' });
  }
  if (!sbOutbounds.some((o) => o.tag === 'block')) {
    sbOutbounds.push({ type: 'block', tag: 'block' });
  }

  const validOutboundTags = new Set(sbOutbounds.map((o) => o.tag));
  const neededRuleSets = new Set();
  const routeRules = [];

  // 1. Sniff rule first
  routeRules.push({ action: 'sniff' });

  // 2. Per-inbound bound outbound relay rules (中转直接绑定: 入站 -> 指定出站)
  for (const inb of activeInbounds) {
    if (inb.outboundTag && inb.outboundTag !== 'default' && validOutboundTags.has(inb.outboundTag)) {
      const tag = inb.tag || `in-${inb.protocol}-${inb.port}`;
      routeRules.push({
        inbound: [tag],
        outbound: inb.outboundTag
      });
    }
  }

  // 3. Custom & 3x-ui style routing rules
  for (const rule of (state.routing?.rules || [])) {
    if (rule.enabled === false) continue;
    if (rule.action === 'sniff') continue; // already added at top
    const compiled = compileRouteRule(rule, neededRuleSets);
    if (compiled.outbound && !validOutboundTags.has(compiled.outbound)) {
      compiled.outbound = 'direct';
    }
    const hasCondition = Object.keys(compiled).some((k) => !['action', 'outbound'].includes(k));
    if (hasCondition) {
      routeRules.push(compiled);
    }
  }

  // Build rule_set definitions for any referenced geosite/geoip rule_set
  const configuredRuleSets = state.routing?.ruleSets || [];
  const finalRuleSets = [];
  for (const tag of neededRuleSets) {
    const existing = configuredRuleSets.find((r) => r.tag === tag);
    if (existing) {
      finalRuleSets.push({
        tag: existing.tag,
        type: existing.type || 'remote',
        format: existing.format || 'binary',
        url: existing.url,
        download_detour: validOutboundTags.has(existing.download_detour) ? existing.download_detour : 'direct'
      });
    } else if (tag.startsWith('geosite-')) {
      const name = tag.slice(8);
      finalRuleSets.push({
        tag,
        type: 'remote',
        format: 'binary',
        url: `https://raw.githubusercontent.com/SagerNet/sing-geosite/rule-set/geosite-${name}.srs`,
        download_detour: 'direct'
      });
    } else if (tag.startsWith('geoip-')) {
      const name = tag.slice(6);
      finalRuleSets.push({
        tag,
        type: 'remote',
        format: 'binary',
        url: `https://raw.githubusercontent.com/SagerNet/sing-geoip/rule-set/geoip-${name}.srs`,
        download_detour: 'direct'
      });
    }
  }

  const finalOutbound = validOutboundTags.has(state.routing?.final) ? state.routing.final : 'direct';

  const config = {
    log: {
      level: settings.singboxLogLevel || 'info',
      timestamp: true
    },
    dns: {
      servers: [
        { tag: 'dns-direct', address: '223.5.5.5', detour: 'direct' },
        { tag: 'dns-remote', address: '8.8.8.8', detour: finalOutbound }
      ],
      final: 'dns-direct',
      strategy: state.dns?.strategy || 'prefer_ipv4'
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

  return config;
}

class SingboxManager {
  constructor(store) {
    this.store = store;
    this.childProcess = null;
    this.lastError = '';
    this.logRing = [];
    this.startedAt = null;
  }

  appendLog(line) {
    const clean = String(line || '').trim();
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
    if (!fs.existsSync(certFile) || !fs.existsSync(keyFile)) {
      spawnSync('openssl', [
        'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
        '-days', '3650', '-nodes', '-subj', '/CN=www.bing.com',
        '-keyout', keyFile, '-out', certFile
      ], { encoding: 'utf8', timeout: 10000 });
    }
    return { certFile, keyFile };
  }

  writeConfig() {
    const fallbackCert = this.ensureFallbackSelfSignedCert();
    const config = buildSingboxConfig(this.store.state);
    // Replace default fallback path if running unprivileged
    for (const inb of config.inbounds || []) {
      if (inb.tls && inb.tls.certificate_path === '/etc/nexusgate/certs/selfsigned/fullchain.pem') {
        if (!fs.existsSync('/etc/nexusgate/certs/selfsigned/fullchain.pem')) {
          inb.tls.certificate_path = fallbackCert.certFile;
          inb.tls.key_path = fallbackCert.keyFile;
        }
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
      const out = String(res.stdout || res.stderr || '');
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
      return { valid: true, warning: 'sing-box 二进制尚未安装，已生成合法配置文件', configPath, config };
    }
    const res = spawnSync(bin, ['check', '-c', configPath], { encoding: 'utf8', timeout: 10000 });
    if (res.status !== 0) {
      const msg = String(res.stderr || res.stdout || '配置检查失败').trim();
      this.lastError = msg;
      return { valid: false, error: msg, configPath, config };
    }
    this.lastError = '';
    return { valid: true, configPath, config };
  }

  getStatus() {
    const ver = this.getVersion();
    // Check systemd service first
    if (fs.existsSync('/run/systemd/system')) {
      const sys = spawnSync('systemctl', ['is-active', 'nexusgate-singbox.service'], { encoding: 'utf8', timeout: 3000 });
      if (String(sys.stdout || '').trim() === 'active') {
        return {
          state: 'running',
          mode: 'systemd',
          version: ver.version,
          installed: ver.installed,
          binary: ver.binary,
          configPath: this.getConfigPath(),
          lastError: this.lastError
        };
      }
    }
    // Check child process or pgrep
    if (this.childProcess && this.childProcess.exitCode === null) {
      return {
        state: 'running',
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
        state: 'running',
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
        return j.stdout.trim().split('\n');
      }
    }
    return this.logRing.length ? this.logRing : ['暂无运行日志，启动或重载 Sing-box 后将在此显示实时输出。'];
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
      } catch { /* ignore if config needs adjustment */ }
      return this.getVersion();
    } finally {
      fs.rmSync(tmpDir, { recursive: true, force: true });
    }
  }
}

module.exports = {
  KNOWN_VERSIONS,
  buildSingboxConfig,
  compileRouteRule,
  SingboxManager
};
