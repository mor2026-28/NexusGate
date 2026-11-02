'use strict';

const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const crypto = require('node:crypto');
const { spawnSync } = require('node:child_process');

let lastCpuSample = null;
let lastNetSample = null;
let cachedPublicIp = { ipv4: '', ipv6: '', checkedAt: 0 };

function sampleCpuTimes() {
  const cpus = os.cpus();
  let idle = 0;
  let total = 0;
  for (const cpu of cpus) {
    for (const type of Object.keys(cpu.times)) {
      total += cpu.times[type];
    }
    idle += cpu.times.idle;
  }
  return { idle, total, cores: cpus.length, model: cpus[0]?.model || 'Generic CPU', speedMhz: cpus[0]?.speed || 0 };
}

function getCpuUsage() {
  const current = sampleCpuTimes();
  if (!lastCpuSample) {
    lastCpuSample = current;
    const loadPct = Math.min(100, Math.round(((os.loadavg()[0] || 0) / Math.max(1, current.cores)) * 100));
    return { percent: loadPct, cores: current.cores, model: current.model, speedMhz: current.speedMhz };
  }
  const idleDiff = current.idle - lastCpuSample.idle;
  const totalDiff = current.total - lastCpuSample.total;
  lastCpuSample = current;
  const percent = totalDiff > 0 ? Math.max(0, Math.min(100, Math.round((1 - idleDiff / totalDiff) * 1000) / 10)) : 0;
  return { percent, cores: current.cores, model: current.model, speedMhz: current.speedMhz };
}

function getMemoryAndSwap() {
  const total = os.totalmem();
  let available = os.freemem();
  let swapTotal = 0;
  let swapFree = 0;

  if (fs.existsSync('/proc/meminfo')) {
    try {
      const meminfo = fs.readFileSync('/proc/meminfo', 'utf8');
      const availMatch = meminfo.match(/^MemAvailable:\s+(\d+)\s+kB/m);
      if (availMatch) available = Number(availMatch[1]) * 1024;
      const stMatch = meminfo.match(/^SwapTotal:\s+(\d+)\s+kB/m);
      const sfMatch = meminfo.match(/^SwapFree:\s+(\d+)\s+kB/m);
      if (stMatch) swapTotal = Number(stMatch[1]) * 1024;
      if (sfMatch) swapFree = Number(sfMatch[1]) * 1024;
    } catch { /* fallback to os.freemem */ }
  }

  return {
    mem: { used: Math.max(0, total - available), total, available },
    swap: { used: Math.max(0, swapTotal - swapFree), total: swapTotal }
  };
}

function getDiskUsage() {
  try {
    const out = spawnSync('df', ['-B1', '/'], { encoding: 'utf8', timeout: 2000 }).stdout || '';
    const lines = out.trim().split('\n');
    if (lines.length >= 2) {
      const parts = lines[lines.length - 1].trim().split(/\s+/);
      if (parts.length >= 4) {
        const total = Number(parts[1]) || 0;
        const used = Number(parts[2]) || 0;
        const avail = Number(parts[3]) || 0;
        return { used, total, available: avail };
      }
    }
  } catch { /* ignore */ }
  return { used: 0, total: 0, available: 0 };
}

function getNetworkStats() {
  let rxBytes = 0;
  let txBytes = 0;
  if (fs.existsSync('/proc/net/dev')) {
    try {
      const lines = fs.readFileSync('/proc/net/dev', 'utf8').split('\n').slice(2);
      for (const line of lines) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith('lo:')) continue;
        const parts = trimmed.split(/[:\s]+/);
        if (parts.length >= 10) {
          rxBytes += Number(parts[1]) || 0;
          txBytes += Number(parts[9]) || 0;
        }
      }
    } catch { /* ignore */ }
  }

  const now = Date.now();
  let upSpeed = 0;
  let downSpeed = 0;
  if (lastNetSample && now > lastNetSample.at) {
    const dt = (now - lastNetSample.at) / 1000;
    downSpeed = Math.max(0, Math.round((rxBytes - lastNetSample.rxBytes) / dt));
    upSpeed = Math.max(0, Math.round((txBytes - lastNetSample.txBytes) / dt));
  }
  lastNetSample = { rxBytes, txBytes, at: now };

  return {
    sent: txBytes,
    recv: rxBytes,
    upSpeed,
    downSpeed
  };
}

function getSocketCounts() {
  const countLines = (file) => {
    try {
      if (!fs.existsSync(file)) return 0;
      return Math.max(0, fs.readFileSync(file, 'utf8').trim().split('\n').length - 1);
    } catch {
      return 0;
    }
  };
  return {
    tcp: countLines('/proc/net/tcp') + countLines('/proc/net/tcp6'),
    udp: countLines('/proc/net/udp') + countLines('/proc/net/udp6')
  };
}

function getLocalAddresses() {
  const nets = os.networkInterfaces();
  let ipv4 = '';
  let ipv6 = '';
  for (const name of Object.keys(nets)) {
    if (name === 'lo') continue;
    for (const netInfo of nets[name] || []) {
      if (netInfo.internal) continue;
      if (netInfo.family === 'IPv4' && !ipv4) ipv4 = netInfo.address;
      if (netInfo.family === 'IPv6' && !netInfo.address.startsWith('fe80') && !ipv6) ipv6 = netInfo.address;
    }
  }
  return { ipv4: ipv4 || '127.0.0.1', ipv6 };
}

function getSystemStatus(singboxManager, storeSettings = {}) {
  const cpu = getCpuUsage();
  const { mem, swap } = getMemoryAndSwap();
  const disk = getDiskUsage();
  const netStats = getNetworkStats();
  const sockets = getSocketCounts();
  const localIps = getLocalAddresses();
  const sbStatus = singboxManager ? singboxManager.getStatus() : { state: 'stop', version: '未知' };
  const processMem = process.memoryUsage();

  return {
    timestamp: new Date().toISOString(),
    hostname: os.hostname(),
    platform: `${os.type()} ${os.release()} (${os.arch()})`,
    uptime: Math.floor(os.uptime()),
    panelUptime: Math.floor(process.uptime()),
    panelMemoryBytes: processMem.rss,
    loads: os.loadavg().map((n) => Number(n.toFixed(2))),
    cpu,
    mem,
    swap,
    disk,
    netTraffic: { sent: netStats.sent, recv: netStats.recv },
    netIO: { up: netStats.upSpeed, down: netStats.downSpeed },
    tcpCount: sockets.tcp,
    udpCount: sockets.udp,
    publicIP: {
      ipv4: storeSettings.publicIPv4 || cachedPublicIp.ipv4 || localIps.ipv4,
      ipv6: storeSettings.publicIPv6 || cachedPublicIp.ipv6 || localIps.ipv6
    },
    singbox: sbStatus
  };
}

function inspectCertificate(certPath, keyPath) {
  try {
    if (!fs.existsSync(certPath)) return { valid: false, error: '证书文件不存在' };
    const pem = fs.readFileSync(certPath, 'utf8');
    const x509 = new crypto.X509Certificate(pem);
    return {
      valid: true,
      subject: x509.subject,
      issuer: x509.issuer,
      validFrom: x509.validFrom,
      validTo: x509.validTo,
      serialNumber: x509.serialNumber,
      fingerprint256: x509.fingerprint256,
      keyExists: keyPath ? fs.existsSync(keyPath) : false
    };
  } catch (err) {
    return { valid: false, error: err.message };
  }
}

function issueSelfSignedCert({ domain = 'www.bing.com', days = 3650, baseDir = '/etc/nexusgate/certs' }) {
  const cleanDomain = String(domain || 'www.bing.com').trim().replace(/[^a-zA-Z0-9._-]/g, '') || 'localhost';
  let targetDir = path.join(baseDir, cleanDomain);
  try {
    fs.mkdirSync(targetDir, { recursive: true });
  } catch {
    targetDir = path.join(os.tmpdir(), 'nexusgate-certs', cleanDomain);
    fs.mkdirSync(targetDir, { recursive: true });
  }

  const certPath = path.join(targetDir, 'fullchain.pem');
  const keyPath = path.join(targetDir, 'privkey.pem');

  const res = spawnSync('openssl', [
    'req', '-x509', '-newkey', 'ec', '-pkeyopt', 'ec_paramgen_curve:prime256v1',
    '-days', String(days), '-nodes',
    '-subj', `/CN=${cleanDomain}`,
    '-addext', `subjectAltName=DNS:${cleanDomain}`,
    '-keyout', keyPath,
    '-out', certPath
  ], { encoding: 'utf8', timeout: 15000 });

  if (res.status !== 0) {
    throw new Error(`生成自签证书失败: ${res.stderr || res.stdout}`);
  }
  try {
    fs.chmodSync(keyPath, 0o600);
    fs.chmodSync(certPath, 0o644);
  } catch { /* ignore */ }

  const meta = inspectCertificate(certPath, keyPath);
  return {
    id: `cert_${crypto.randomBytes(5).toString('hex')}`,
    domain: cleanDomain,
    type: 'self-signed',
    certPath,
    keyPath,
    createdAt: new Date().toISOString(),
    ...meta
  };
}

function saveCustomCert({ domain, certPem, keyPem, certPath, keyPath, baseDir = '/etc/nexusgate/certs' }) {
  const cleanDomain = String(domain || 'custom').trim().replace(/[^a-zA-Z0-9._-]/g, '') || 'custom';
  let finalCertPath = certPath;
  let finalKeyPath = keyPath;

  if (certPem && keyPem) {
    let targetDir = path.join(baseDir, cleanDomain);
    try {
      fs.mkdirSync(targetDir, { recursive: true });
    } catch {
      targetDir = path.join(os.tmpdir(), 'nexusgate-certs', cleanDomain);
      fs.mkdirSync(targetDir, { recursive: true });
    }
    finalCertPath = path.join(targetDir, 'fullchain.pem');
    finalKeyPath = path.join(targetDir, 'privkey.pem');
    fs.writeFileSync(finalCertPath, String(certPem).trim() + '\n', { mode: 0o644 });
    fs.writeFileSync(finalKeyPath, String(keyPem).trim() + '\n', { mode: 0o600 });
  }

  if (!finalCertPath || !finalKeyPath || !fs.existsSync(finalCertPath) || !fs.existsSync(finalKeyPath)) {
    throw new Error('证书或私钥文件不存在，请检查路径或直接粘贴 PEM 内容');
  }

  const meta = inspectCertificate(finalCertPath, finalKeyPath);
  if (!meta.valid) {
    throw new Error(`证书内容校验失败: ${meta.error}`);
  }

  return {
    id: `cert_${crypto.randomBytes(5).toString('hex')}`,
    domain: cleanDomain,
    type: 'custom',
    certPath: finalCertPath,
    keyPath: finalKeyPath,
    createdAt: new Date().toISOString(),
    ...meta
  };
}

function issueAcmeCert({ domain, email = '', mode = 'standalone', cfToken = '', webPort = 80, baseDir = '/etc/nexusgate/certs' }) {
  const cleanDomain = String(domain || '').trim();
  if (!cleanDomain) throw new Error('请输入要申请证书的域名或公网 IP');

  let targetDir = path.join(baseDir, cleanDomain);
  try {
    fs.mkdirSync(targetDir, { recursive: true });
  } catch {
    targetDir = path.join(os.tmpdir(), 'nexusgate-certs', cleanDomain);
    fs.mkdirSync(targetDir, { recursive: true });
  }

  const certPath = path.join(targetDir, 'fullchain.pem');
  const keyPath = path.join(targetDir, 'privkey.pem');
  const acmeBin = path.join(os.homedir(), '.acme.sh', 'acme.sh');

  if (!fs.existsSync(acmeBin)) {
    const installRes = spawnSync('bash', ['-c', 'curl -fsSL https://get.acme.sh | sh'], { encoding: 'utf8', timeout: 60000 });
    if (installRes.status !== 0 && !fs.existsSync(acmeBin)) {
      throw new Error('当前环境无法自动下载安装 acme.sh，请先确保服务器联网或使用“一键生成自签证书 / 粘贴自定义证书”');
    }
  }

  spawnSync(acmeBin, ['--set-default-ca', '--server', 'letsencrypt'], { encoding: 'utf8', timeout: 10000 });
  if (email) {
    spawnSync(acmeBin, ['--register-account', '-m', email], { encoding: 'utf8', timeout: 15000 });
  }

  let issueArgs = ['--issue', '-d', cleanDomain, '--force'];
  const env = { ...process.env };
  if (mode === 'cf' && cfToken) {
    env.CF_Token = cfToken;
    issueArgs.push('--dns', 'dns_cf');
  } else if (mode === 'ip') {
    issueArgs.push('--standalone', '--server', 'letsencrypt', '--certificate-profile', 'shortlived', '--days', '6', '--httpport', String(webPort || 80));
  } else {
    issueArgs.push('--standalone', '--httpport', String(webPort || 80));
  }

  const issueRes = spawnSync(acmeBin, issueArgs, { encoding: 'utf8', env, timeout: 120000 });
  if (issueRes.status !== 0) {
    throw new Error(`ACME 证书签发失败: ${(issueRes.stderr || issueRes.stdout || '').slice(0, 500)}`);
  }

  spawnSync(acmeBin, [
    '--installcert', '-d', cleanDomain,
    '--key-file', keyPath,
    '--fullchain-file', certPath
  ], { encoding: 'utf8', timeout: 20000 });

  const meta = inspectCertificate(certPath, keyPath);
  if (!meta.valid) {
    throw new Error('ACME 证书安装后未找到有效 PEM 文件');
  }

  return {
    id: `cert_${crypto.randomBytes(5).toString('hex')}`,
    domain: cleanDomain,
    type: mode === 'cf' ? 'acme-dns' : (mode === 'ip' ? 'acme-ip' : 'acme-http'),
    certPath,
    keyPath,
    createdAt: new Date().toISOString(),
    ...meta
  };
}

module.exports = {
  getSystemStatus,
  inspectCertificate,
  issueSelfSignedCert,
  saveCustomCert,
  issueAcmeCert
};
