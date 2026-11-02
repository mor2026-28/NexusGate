'use strict';

const fs = require('node:fs');
const crypto = require('node:crypto');
const net = require('node:net');

const REALITY_PRESETS = Object.freeze([
  { id: 'tesla', label: 'Tesla (www.tesla.com)', serverName: 'www.tesla.com', target: 'www.tesla.com:443' },
  { id: 'apple', label: 'Apple (www.apple.com)', serverName: 'www.apple.com', target: 'www.apple.com:443' },
  { id: 'cloudflare', label: 'Cloudflare (www.cloudflare.com)', serverName: 'www.cloudflare.com', target: 'www.cloudflare.com:443' },
  { id: 'amazon', label: 'Amazon (www.amazon.com)', serverName: 'www.amazon.com', target: 'www.amazon.com:443' },
  { id: 'amd', label: 'AMD (www.amd.com)', serverName: 'www.amd.com', target: 'www.amd.com:443' },
  { id: 'intel', label: 'Intel (www.intel.com)', serverName: 'www.intel.com', target: 'www.intel.com:443' }
]);

const SS_METHODS = Object.freeze([
  { id: '2022-blake3-aes-128-gcm', label: '2022-blake3-aes-128-gcm (SS2022 128位 · 推荐)', keyBytes: 16, is2022: true },
  { id: '2022-blake3-aes-256-gcm', label: '2022-blake3-aes-256-gcm (SS2022 256位)', keyBytes: 32, is2022: true },
  { id: '2022-blake3-chacha20-poly1305', label: '2022-blake3-chacha20-poly1305 (SS2022 ChaCha20)', keyBytes: 32, is2022: true },
  { id: 'aes-128-gcm', label: 'aes-128-gcm (经典 AEAD 128位)', keyBytes: 16, is2022: false },
  { id: 'aes-256-gcm', label: 'aes-256-gcm (经典 AEAD 256位)', keyBytes: 24, is2022: false },
  { id: 'chacha20-ietf-poly1305', label: 'chacha20-ietf-poly1305 (经典 ChaCha20)', keyBytes: 24, is2022: false }
]);

const INBOUND_PROTOCOLS = Object.freeze([
  { id: 'vless', name: 'VLESS (Reality / TLS / WS / gRPC)', badge: 'VLESS', desc: '支持 Reality Vision 免证书、WebSocket、gRPC 与标准 TLS' },
  { id: 'anytls', name: 'AnyTLS (Sing-box 原生伪装填充)', badge: 'AnyTLS', desc: 'Sing-box 1.12+ 强特征消除协议，支持 TLS 与自适应长度填充' },
  { id: 'hysteria2', name: 'Hysteria 2 (HY2 高速 QUIC UDP)', badge: 'HY2', desc: '基于 QUIC 的高速抗丢包 UDP 协议，支持 Salamander 混淆与带宽控制' },
  { id: 'shadowsocks', name: 'Shadowsocks (SS 128/256 & SS 2022)', badge: 'SS/SS2022', desc: '支持 AES-128-GCM、AES-256-GCM 及 2022-blake3-aes-128/256-gcm' },
  { id: 'socks', name: 'SOCKS5 (标准代理 / 中转入口)', badge: 'SOCKS5', desc: '支持账号密码认证与 UDP 转发，常用于内网或前置中转接入' },
  { id: 'mixed', name: 'Mixed (SOCKS5 + HTTP 混合代理)', badge: 'MIXED', desc: '同端口同时支持 SOCKS5 与 HTTP 代理 (完美兼容 3x-ui Mixed 节点)' },
  { id: 'trojan', name: 'Trojan (TLS / Reality / WS)', badge: 'Trojan', desc: '经典 TLS 伪装协议，支持证书 TLS、Reality 或 WebSocket 传输' },
  { id: 'vmess', name: 'VMess (TCP / WS / TLS / gRPC)', badge: 'VMess', desc: '广泛兼容主流客户端，支持 WebSocket + TLS 或中转隧道' },
  { id: 'tuic', name: 'TUIC v5 (QUIC 0-RTT UDP)', badge: 'TUIC', desc: '基于 QUIC 的低延迟 UDP 协议，支持 BBR 拥塞控制' },
  { id: 'direct', name: 'Direct 端口转发 (Dokodemo 隧道中转)', badge: '端口转发', desc: '将本机端口 TCP/UDP 流量直接转发至目标 IP:Port 或通过指定出站中转' }
]);

const OUTBOUND_PROTOCOLS = Object.freeze([
  { id: 'shadowsocks', name: 'Shadowsocks 出站 (SS 128/256 / SS 2022)' },
  { id: 'vless', name: 'VLESS 出站 (Reality / TLS / WS / TCP)' },
  { id: 'anytls', name: 'AnyTLS 出站 (TLS)' },
  { id: 'hysteria2', name: 'Hysteria 2 出站 (UDP QUIC)' },
  { id: 'socks', name: 'SOCKS5 出站' },
  { id: 'trojan', name: 'Trojan 出站' },
  { id: 'vmess', name: 'VMess 出站' },
  { id: 'tuic', name: 'TUIC v5 出站' },
  { id: 'http', name: 'HTTP/HTTPS 代理出站' },
  { id: 'urltest', name: 'URLTest 自动测速负载均衡组' },
  { id: 'selector', name: 'Selector 手动/故障切换出站组' },
  { id: 'direct', name: 'Direct 本地直连 (Freedom)' },
  { id: 'block', name: 'Block 黑洞拦截 (Blackhole)' }
]);

const UUID_REGEX = /^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/i;

function isValidUuid(str) {
  return UUID_REGEX.test(String(str || '').trim());
}

function ensureUuid(str) {
  const s = String(str || '').trim();
  return isValidUuid(s) ? s : crypto.randomUUID();
}

function normalizeSsMethod(method = '2022-blake3-aes-128-gcm') {
  const m = String(method || '2022-blake3-aes-128-gcm').trim().toLowerCase();
  if (m === 'chacha20-poly1305') return 'chacha20-ietf-poly1305';
  if (m === 'xchacha20-poly1305') return 'xchacha20-ietf-poly1305';
  return m;
}

function generateRealityKeypair() {
  const { publicKey, privateKey } = crypto.generateKeyPairSync('x25519');
  const privJwk = privateKey.export({ format: 'jwk' });
  const pubJwk = publicKey.export({ format: 'jwk' });
  return {
    privateKey: privJwk.d,
    publicKey: pubJwk.x
  };
}

function deriveRealityPublicKey(privateKeyStr) {
  if (!privateKeyStr) return '';
  try {
    const rawPriv = Buffer.from(String(privateKeyStr).trim(), 'base64url');
    if (rawPriv.length !== 32) return '';
    const pkcs8Header = Buffer.from('302e020100300506032b656e04220420', 'hex');
    const privObj = crypto.createPrivateKey({
      key: Buffer.concat([pkcs8Header, rawPriv]),
      format: 'der',
      type: 'pkcs8'
    });
    return crypto.createPublicKey(privObj).export({ format: 'jwk' }).x;
  } catch {
    return '';
  }
}

function generateSsKey(method = '2022-blake3-aes-128-gcm') {
  const normMethod = normalizeSsMethod(method);
  const spec = SS_METHODS.find((m) => m.id === normMethod);
  if (spec && spec.is2022) {
    return crypto.randomBytes(spec.keyBytes).toString('base64');
  }
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  const bytes = crypto.randomBytes(22);
  let out = '';
  for (let i = 0; i < 22; i += 1) out += chars[bytes[i] % chars.length];
  return out;
}

function generateShortId() {
  return crypto.randomBytes(4).toString('hex');
}

function uriHost(address) {
  const str = String(address || '127.0.0.1').trim();
  if (str.startsWith('[') && str.endsWith(']')) return str;
  return net.isIP(str) === 6 ? `[${str}]` : str;
}

function parseTargetHostPort(target = 'www.tesla.com:443', defaultServerName = 'www.tesla.com') {
  const str = String(target || '').trim();
  if (!str) return { server: defaultServerName, server_port: 443 };
  const idx = str.lastIndexOf(':');
  if (idx > 0 && !str.endsWith(']')) {
    const host = str.slice(0, idx).replace(/^\[|\]$/g, '');
    const port = Number(str.slice(idx + 1)) || 443;
    return { server: host || defaultServerName, server_port: port };
  }
  return { server: str, server_port: 443 };
}

function isCertFileSelfSigned(certPath) {
  if (!certPath || !fs.existsSync(certPath)) return true;
  if (certPath.includes('selfsigned')) return true;
  try {
    const x509 = new crypto.X509Certificate(fs.readFileSync(certPath, 'utf8'));
    return String(x509.issuer || '') === String(x509.subject || '');
  } catch {
    return true;
  }
}

/**
 * Resolves the active certificate and SNI domain for a standard TLS inbound.
 * Always prioritizes real ACME/custom certificates over self-signed fallback.
 */
function resolveInboundCertAndDomain(inbound, certificates = [], defaultSettings = {}) {
  const nonSelfCert = certificates.find((c) => c.type !== 'self-signed' && c.valid !== false);
  let certPath = inbound.certPath || '';
  let keyPath = inbound.keyPath || '';
  let domain = inbound.tlsDomain || '';

  const filesExist = Boolean(certPath && keyPath && fs.existsSync(certPath) && fs.existsSync(keyPath));
  const curIsSelf = !filesExist || isCertFileSelfSigned(certPath);

  // If a real ACME cert exists, and the inbound has no valid cert or is using a self-signed cert, auto-upgrade!
  if (nonSelfCert && (curIsSelf || domain === 'www.bing.com' || domain === 'www.apple.com')) {
    certPath = nonSelfCert.certPath;
    keyPath = nonSelfCert.keyPath;
    domain = nonSelfCert.domain;
  }

  if ((!certPath || !keyPath || !fs.existsSync(certPath)) && domain) {
    const matched = certificates.find((c) => c.domain === domain && c.certPath && fs.existsSync(c.certPath));
    if (matched) {
      certPath = matched.certPath;
      keyPath = matched.keyPath;
    }
  }

  if (!certPath || !keyPath || !fs.existsSync(certPath)) {
    if (nonSelfCert) {
      certPath = nonSelfCert.certPath;
      keyPath = nonSelfCert.keyPath;
      domain = domain || nonSelfCert.domain;
    } else if (defaultSettings.defaultCertFile && defaultSettings.defaultKeyFile && fs.existsSync(defaultSettings.defaultCertFile)) {
      certPath = defaultSettings.defaultCertFile;
      keyPath = defaultSettings.defaultKeyFile;
      domain = domain || defaultSettings.defaultTlsDomain || defaultSettings.webDomain || 'www.apple.com';
    } else if (certificates[0]?.certPath && certificates[0]?.keyPath) {
      certPath = certificates[0].certPath;
      keyPath = certificates[0].keyPath;
      domain = domain || certificates[0].domain || 'www.apple.com';
    } else {
      certPath = '/etc/nexusgate/certs/selfsigned/fullchain.pem';
      keyPath = '/etc/nexusgate/certs/selfsigned/privkey.pem';
      domain = domain || defaultSettings.webDomain || 'www.apple.com';
    }
  }

  const matchedCertObj = certificates.find((c) => c.certPath === certPath || (domain && c.domain === domain));
  const isSelfSigned = Boolean(
    inbound.allowInsecure === true ||
    (matchedCertObj ? matchedCertObj.type === 'self-signed' : isCertFileSelfSigned(certPath))
  );

  return { certPath, keyPath, domain: domain || 'www.apple.com', isSelfSigned };
}

/**
 * Converts a panel Inbound object into a native Sing-box inbound configuration object.
 */
function toSingboxInbound(inbound, certificates = [], defaultSettings = {}) {
  const listen = inbound.listen || '::';
  const port = Number(inbound.port);
  const tag = inbound.tag || `in-${inbound.protocol}-${port}`;
  const base = {
    type: inbound.protocol,
    tag,
    listen,
    listen_port: port
  };

  const activeClients = (inbound.clients || []).filter((c) => c.enable !== false);
  const tlsConfig = buildInboundTls(inbound, certificates, defaultSettings);
  const transportConfig = buildInboundTransport(inbound);

  switch (inbound.protocol) {
    case 'vless': {
      const isReality = inbound.security === 'reality';
      return {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || `user_${ensureUuid(c.id || c.uuid).slice(0, 6)}`,
          uuid: ensureUuid(c.id || c.uuid),
          flow: (isReality || inbound.security === 'tls') && (!inbound.transport || inbound.transport === 'tcp')
            ? (c.flow ?? inbound.flow ?? '')
            : ''
        })).map((u) => {
          if (!u.flow) delete u.flow;
          return u;
        }),
        ...(tlsConfig ? { tls: tlsConfig } : {}),
        ...(transportConfig ? { transport: transportConfig } : {})
      };
    }

    case 'anytls': {
      return {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || 'anytls_user',
          password: c.password || inbound.password || generateSsKey('aes-128-gcm')
        })),
        padding_scheme: Array.isArray(inbound.paddingScheme) && inbound.paddingScheme.length
          ? inbound.paddingScheme
          : undefined,
        tls: tlsConfig
      };
    }

    case 'hysteria2': {
      const hy2 = {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || 'hy2_user',
          password: c.password || inbound.password || generateSsKey('aes-128-gcm')
        })),
        tls: tlsConfig
      };
      if (Number(inbound.upMbps) > 0) hy2.up_mbps = Number(inbound.upMbps);
      if (Number(inbound.downMbps) > 0) hy2.down_mbps = Number(inbound.downMbps);
      if (inbound.obfsPassword) {
        hy2.obfs = { type: 'salamander', password: inbound.obfsPassword };
      }
      if (inbound.masquerade) {
        hy2.masquerade = inbound.masquerade;
      }
      return hy2;
    }

    case 'shadowsocks': {
      const method = normalizeSsMethod(inbound.method || '2022-blake3-aes-128-gcm');
      const is2022 = method.startsWith('2022-');
      const firstClientPass = activeClients[0]?.password || '';
      // For classic SS migrated from 3x-ui, clients[0].password is the actual client password
      const serverPassword = is2022
        ? (inbound.password || firstClientPass || generateSsKey(method))
        : (firstClientPass || inbound.password || generateSsKey(method));

      const ss = {
        ...base,
        network: inbound.network === 'tcp' || inbound.network === 'udp' ? inbound.network : undefined,
        method,
        password: serverPassword
      };

      // Include users array when there are multiple clients OR when a 3x-ui SS-2022 node uses EIH (serverPassword + clientPassword)
      const needsMultiUser = activeClients.length > 1 ||
        (is2022 && activeClients.length === 1 && firstClientPass && firstClientPass !== serverPassword);

      if (needsMultiUser) {
        ss.users = activeClients.map((c) => ({
          name: c.email || c.name || 'ss_user',
          password: c.password || serverPassword
        }));
      }
      return ss;
    }

    case 'socks':
    case 'mixed':
    case 'http': {
      const users = activeClients
        .filter((c) => (c.username || c.email) && c.password)
        .map((c) => ({
          username: c.username || c.email,
          password: c.password
        }));
      if (!users.length && inbound.socksUser && inbound.socksPassword) {
        users.push({ username: inbound.socksUser, password: inbound.socksPassword });
      }
      return {
        ...base,
        ...(users.length ? { users } : {})
      };
    }

    case 'trojan': {
      return {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || 'trojan_user',
          password: c.password || inbound.password || generateSsKey('aes-128-gcm')
        })),
        ...(tlsConfig ? { tls: tlsConfig } : {}),
        ...(transportConfig ? { transport: transportConfig } : {})
      };
    }

    case 'vmess': {
      return {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || 'vmess_user',
          uuid: ensureUuid(c.id || c.uuid),
          alterId: Number(c.alterId || 0)
        })),
        ...(tlsConfig ? { tls: tlsConfig } : {}),
        ...(transportConfig ? { transport: transportConfig } : {})
      };
    }

    case 'tuic': {
      return {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || 'tuic_user',
          uuid: ensureUuid(c.id || c.uuid),
          password: c.password || inbound.password || ''
        })),
        congestion_control: inbound.congestionControl || 'bbr',
        tls: tlsConfig
      };
    }

    case 'direct': {
      const d = {
        ...base,
        network: inbound.network === 'tcp' || inbound.network === 'udp' ? inbound.network : undefined
      };
      if (inbound.overrideAddress) d.override_address = inbound.overrideAddress;
      if (Number(inbound.overridePort) > 0) d.override_port = Number(inbound.overridePort);
      return d;
    }

    default:
      return base;
  }
}

function buildInboundTls(inbound, certificates = [], defaultSettings = {}) {
  const security = inbound.security || (['anytls', 'hysteria2', 'tuic'].includes(inbound.protocol) ? 'tls' : 'none');
  if (security === 'none') return null;

  if (security === 'reality') {
    const r = inbound.reality || {};
    const serverName = r.serverName || (Array.isArray(r.serverNames) && r.serverNames[0]) || 'www.tesla.com';
    const handshake = parseTargetHostPort(r.target || `${serverName}:443`, serverName);
    const shortIds = Array.isArray(r.shortIds)
      ? r.shortIds
      : String(r.shortIds || r.shortId || '')
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
    // CRITICAL: Reality inbounds in Sing-box MUST NOT have certificate_path or key_path!
    return {
      enabled: true,
      server_name: serverName,
      reality: {
        enabled: true,
        handshake,
        private_key: r.privateKey,
        short_id: shortIds.length ? shortIds : ['']
      }
    };
  }

  if (security === 'tls') {
    const resolved = resolveInboundCertAndDomain(inbound, certificates, defaultSettings);
    const tls = {
      enabled: true,
      server_name: resolved.domain,
      certificate_path: resolved.certPath,
      key_path: resolved.keyPath
    };
    if (inbound.alpn && inbound.alpn.length) {
      tls.alpn = Array.isArray(inbound.alpn) ? inbound.alpn : String(inbound.alpn).split(',').map((s) => s.trim()).filter(Boolean);
    } else if (['hysteria2', 'tuic'].includes(inbound.protocol)) {
      tls.alpn = ['h3'];
    }
    return tls;
  }

  return null;
}

function buildInboundTransport(inbound) {
  const netType = inbound.transport || inbound.streamNetwork || 'tcp';
  if (netType === 'ws') {
    const ws = {
      type: 'ws',
      path: inbound.wsPath || '/'
    };
    if (inbound.wsHost) {
      ws.headers = { Host: inbound.wsHost };
    }
    return ws;
  }
  if (netType === 'grpc') {
    return {
      type: 'grpc',
      service_name: inbound.grpcServiceName || 'grpc'
    };
  }
  if (netType === 'httpupgrade') {
    const hu = {
      type: 'httpupgrade',
      path: inbound.wsPath || '/'
    };
    if (inbound.wsHost) hu.host = inbound.wsHost;
    return hu;
  }
  if (netType === 'http' || netType === 'h2') {
    return {
      type: 'http',
      path: inbound.wsPath || '/',
      ...(inbound.wsHost ? { host: [inbound.wsHost] } : {})
    };
  }
  return null;
}

/**
 * Converts a panel Outbound object into a native Sing-box outbound configuration object.
 */
function toSingboxOutbound(outbound) {
  if (outbound.rawJson && typeof outbound.rawJson === 'object' && outbound.rawJson.type) {
    return { ...outbound.rawJson, tag: outbound.tag };
  }
  if (outbound.type === 'direct' || outbound.type === 'freedom') {
    return { type: 'direct', tag: outbound.tag };
  }
  if (outbound.type === 'block' || outbound.type === 'blackhole') {
    return { type: 'block', tag: outbound.tag };
  }
  if (outbound.type === 'urltest') {
    return {
      type: 'urltest',
      tag: outbound.tag,
      outbounds: Array.isArray(outbound.outbounds) && outbound.outbounds.length ? outbound.outbounds : ['direct'],
      url: outbound.url || 'https://www.gstatic.com/generate_204',
      interval: outbound.interval || '3m'
    };
  }
  if (outbound.type === 'selector') {
    return {
      type: 'selector',
      tag: outbound.tag,
      outbounds: Array.isArray(outbound.outbounds) && outbound.outbounds.length ? outbound.outbounds : ['direct'],
      default: outbound.defaultOutbound || (outbound.outbounds && outbound.outbounds[0]) || 'direct'
    };
  }

  const s = outbound.settings || outbound;
  const base = {
    type: outbound.type,
    tag: outbound.tag,
    server: s.server || outbound.server || '127.0.0.1',
    server_port: Number(s.server_port || s.port || outbound.port || 443)
  };
  if (outbound.detour) {
    base.detour = outbound.detour;
  }

  const tls = buildOutboundTls(outbound);
  const transport = buildOutboundTransport(outbound);

  switch (outbound.type) {
    case 'vless':
      return {
        ...base,
        uuid: ensureUuid(s.uuid || s.id || outbound.uuid),
        ...(s.flow || outbound.flow ? { flow: s.flow || outbound.flow } : {}),
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {})
      };

    case 'anytls':
      return {
        ...base,
        password: s.password || outbound.password || '',
        tls: tls || {
          enabled: true,
          server_name: s.sni || s.server_name || base.server,
          insecure: Boolean(s.insecure || outbound.insecure)
        }
      };

    case 'hysteria2': {
      const hy2 = {
        ...base,
        password: s.password || outbound.password || '',
        tls: tls || {
          enabled: true,
          alpn: ['h3'],
          server_name: s.sni || s.server_name || base.server,
          insecure: Boolean(s.insecure || outbound.insecure)
        }
      };
      if (Number(s.upMbps || outbound.upMbps) > 0) hy2.up_mbps = Number(s.upMbps || outbound.upMbps);
      if (Number(s.downMbps || outbound.downMbps) > 0) hy2.down_mbps = Number(s.downMbps || outbound.downMbps);
      if (s.obfsPassword || outbound.obfsPassword) {
        hy2.obfs = { type: 'salamander', password: s.obfsPassword || outbound.obfsPassword };
      }
      return hy2;
    }

    case 'shadowsocks': {
      const ssOut = {
        ...base,
        method: normalizeSsMethod(s.method || outbound.method || '2022-blake3-aes-128-gcm'),
        password: s.password || outbound.password || ''
      };
      if (s.uot || outbound.uot) {
        ssOut.udp_over_tcp = true;
      }
      return ssOut;
    }

    case 'socks': {
      const sk = {
        ...base,
        version: '5'
      };
      if (s.username || outbound.username) sk.username = s.username || outbound.username;
      if (s.password || outbound.password) sk.password = s.password || outbound.password;
      return sk;
    }

    case 'trojan':
      return {
        ...base,
        password: s.password || outbound.password || '',
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {})
      };

    case 'vmess':
      return {
        ...base,
        uuid: ensureUuid(s.uuid || s.id || outbound.uuid),
        security: s.security || outbound.cipher || 'auto',
        alter_id: Number(s.alterId || outbound.alterId || 0),
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {})
      };

    case 'tuic':
      return {
        ...base,
        uuid: ensureUuid(s.uuid || outbound.uuid),
        password: s.password || outbound.password || '',
        congestion_control: s.congestionControl || outbound.congestionControl || 'bbr',
        tls: tls || {
          enabled: true,
          alpn: ['h3'],
          server_name: s.sni || base.server,
          insecure: Boolean(s.insecure || outbound.insecure)
        }
      };

    case 'http': {
      const hp = { ...base };
      if (s.username || outbound.username) hp.username = s.username || outbound.username;
      if (s.password || outbound.password) hp.password = s.password || outbound.password;
      if (tls) hp.tls = tls;
      return hp;
    }

    default:
      return { ...base, ...(s.raw || {}) };
  }
}

function buildOutboundTls(outbound) {
  const s = outbound.settings || outbound;
  const security = s.securityMode || outbound.security || (['anytls', 'hysteria2', 'tuic'].includes(outbound.type) ? 'tls' : 'none');
  if (security === 'none') return null;

  if (security === 'reality') {
    return {
      enabled: true,
      server_name: s.sni || outbound.sni || s.server || outbound.server || 'www.tesla.com',
      utls: {
        enabled: true,
        fingerprint: s.fingerprint || outbound.fingerprint || 'chrome'
      },
      reality: {
        enabled: true,
        public_key: s.publicKey || outbound.publicKey || '',
        short_id: s.shortId || outbound.shortId || ''
      }
    };
  }

  if (security === 'tls') {
    const tls = {
      enabled: true,
      server_name: s.sni || outbound.sni || s.server || outbound.server || '',
      insecure: Boolean(s.insecure || outbound.insecure)
    };
    if (s.fingerprint || outbound.fingerprint) {
      tls.utls = { enabled: true, fingerprint: s.fingerprint || outbound.fingerprint };
    }
    if (['hysteria2', 'tuic'].includes(outbound.type)) {
      tls.alpn = ['h3'];
    }
    return tls;
  }
  return null;
}

function buildOutboundTransport(outbound) {
  const s = outbound.settings || outbound;
  const netType = s.transport || outbound.transport || 'tcp';
  if (netType === 'ws') {
    return {
      type: 'ws',
      path: s.wsPath || outbound.wsPath || '/',
      ...(s.wsHost || outbound.wsHost ? { headers: { Host: s.wsHost || outbound.wsHost } } : {})
    };
  }
  if (netType === 'grpc') {
    return {
      type: 'grpc',
      service_name: s.grpcServiceName || outbound.grpcServiceName || 'grpc'
    };
  }
  if (netType === 'httpupgrade') {
    return {
      type: 'httpupgrade',
      path: s.wsPath || outbound.wsPath || '/',
      ...(s.wsHost || outbound.wsHost ? { host: s.wsHost || outbound.wsHost } : {})
    };
  }
  return null;
}

/**
 * Generates client share links (URI), Clash/Mihomo YAML snippets, and Sing-box JSON snippets.
 */
function buildClientLinks(inbound, publicHost = '127.0.0.1', certificates = [], defaultSettings = {}) {
  const resolvedTls = resolveInboundCertAndDomain(inbound, certificates, defaultSettings);
  const nonSelfCert = certificates.find((c) => c.type !== 'self-signed' && c.valid !== false);
  const realDomain = defaultSettings.webDomain || (nonSelfCert ? nonSelfCert.domain : '');
  const connectAddr = inbound.publicHost || realDomain || publicHost || '127.0.0.1';
  const host = uriHost(connectAddr);
  const rawServer = connectAddr.replace(/^\[|\]$/g, '');
  const port = Number(inbound.port);
  const isSelfSigned = resolvedTls.isSelfSigned;
  const sniDomain = resolvedTls.domain;

  const clients = (inbound.clients && inbound.clients.length)
    ? inbound.clients
    : [{ email: inbound.remark || inbound.tag, id: ensureUuid(inbound.uuid), password: inbound.password }];

  const links = [];

  for (const client of clients) {
    if (client.enable === false) continue;
    const labelName = clients.length === 1
      ? (inbound.remark || inbound.tag)
      : `${inbound.remark || inbound.tag}-${client.email || client.name || 'client'}`;
    const label = encodeURIComponent(labelName);
    let uri = '';
    let altUri = '';
    let clashProxy = null;
    let singboxOut = null;

    if (inbound.protocol === 'vless') {
      const uuid = ensureUuid(client.id || client.uuid);
      const transport = inbound.transport || 'tcp';
      const params = new URLSearchParams({ encryption: 'none', type: transport });
      const flow = (inbound.security === 'reality' || inbound.security === 'tls') && transport === 'tcp'
        ? (client.flow ?? inbound.flow ?? '')
        : '';

      if (inbound.security === 'reality') {
        const r = inbound.reality || {};
        const pubKey = r.publicKey || deriveRealityPublicKey(r.privateKey);
        const sni = r.serverName || (Array.isArray(r.serverNames) && r.serverNames[0]) || 'www.tesla.com';
        const sid = Array.isArray(r.shortIds) ? (r.shortIds[0] || '') : String(r.shortIds || r.shortId || '').split(',')[0].trim();
        params.set('security', 'reality');
        params.set('sni', sni);
        params.set('fp', r.fingerprint || 'chrome');
        if (pubKey) params.set('pbk', pubKey);
        if (sid) params.set('sid', sid);
        if (flow) params.set('flow', flow);
        params.set('headerType', 'none');

        clashProxy = {
          name: labelName, type: 'vless', server: rawServer, port, uuid, udp: true, tls: true,
          network: transport, ...(flow ? { flow } : {}), servername: sni, 'client-fingerprint': r.fingerprint || 'chrome',
          'reality-opts': { 'public-key': pubKey, 'short-id': sid }
        };
        singboxOut = {
          type: 'vless', tag: labelName, server: rawServer, server_port: port, uuid, ...(flow ? { flow } : {}),
          tls: { enabled: true, server_name: sni, utls: { enabled: true, fingerprint: r.fingerprint || 'chrome' }, reality: { enabled: true, public_key: pubKey, short_id: sid } }
        };
      } else if (inbound.security === 'tls') {
        params.set('security', 'tls');
        params.set('sni', sniDomain);
        params.set('fp', 'chrome');
        if (flow) params.set('flow', flow);
        if (isSelfSigned) {
          params.set('allowInsecure', '1');
          params.set('insecure', '1');
        }
        clashProxy = {
          name: labelName, type: 'vless', server: rawServer, port, uuid, udp: true, tls: true,
          network: transport, ...(flow ? { flow } : {}), servername: sniDomain, 'skip-cert-verify': isSelfSigned
        };
        singboxOut = {
          type: 'vless', tag: labelName, server: rawServer, server_port: port, uuid, ...(flow ? { flow } : {}),
          tls: { enabled: true, server_name: sniDomain, insecure: isSelfSigned }
        };
      } else {
        params.set('security', 'none');
        clashProxy = { name: labelName, type: 'vless', server: rawServer, port, uuid, udp: true, tls: false, network: transport };
        singboxOut = { type: 'vless', tag: labelName, server: rawServer, server_port: port, uuid };
      }

      if (transport === 'ws' || transport === 'httpupgrade') {
        params.set('path', inbound.wsPath || '/');
        if (inbound.wsHost) params.set('host', inbound.wsHost);
      } else if (transport === 'grpc') {
        params.set('serviceName', inbound.grpcServiceName || 'grpc');
      }

      uri = `vless://${uuid}@${host}:${port}?${params.toString()}#${label}`;
    } else if (inbound.protocol === 'anytls') {
      const pass = client.password || inbound.password || '';
      const params = new URLSearchParams({ sni: sniDomain, fp: 'chrome' });
      if (isSelfSigned) {
        params.set('insecure', '1');
        params.set('allowInsecure', '1');
      }
      uri = `anytls://${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
      clashProxy = {
        name: labelName, type: 'anytls', server: rawServer, port, password: pass, udp: true,
        sni: sniDomain, 'client-fingerprint': 'chrome', 'skip-cert-verify': isSelfSigned
      };
      singboxOut = {
        type: 'anytls', tag: labelName, server: rawServer, server_port: port, password: pass,
        tls: { enabled: true, server_name: sniDomain, insecure: isSelfSigned }
      };
    } else if (inbound.protocol === 'hysteria2') {
      const pass = client.password || inbound.password || '';
      const params = new URLSearchParams({ sni: sniDomain, alpn: 'h3' });
      if (isSelfSigned) {
        params.set('insecure', '1');
        params.set('allowInsecure', '1');
      }
      if (inbound.obfsPassword) {
        params.set('obfs', 'salamander');
        params.set('obfs-password', inbound.obfsPassword);
      }
      uri = `hysteria2://${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
      altUri = `hy2://${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
      clashProxy = {
        name: labelName, type: 'hysteria2', server: rawServer, port, password: pass,
        sni: sniDomain, alpn: ['h3'], 'skip-cert-verify': isSelfSigned,
        ...(inbound.obfsPassword ? { obfs: 'salamander', 'obfs-password': inbound.obfsPassword } : {})
      };
      singboxOut = {
        type: 'hysteria2', tag: labelName, server: rawServer, server_port: port, password: pass,
        ...(inbound.obfsPassword ? { obfs: { type: 'salamander', password: inbound.obfsPassword } } : {}),
        tls: { enabled: true, alpn: ['h3'], server_name: sniDomain, insecure: isSelfSigned }
      };
    } else if (inbound.protocol === 'shadowsocks') {
      const method = normalizeSsMethod(inbound.method || '2022-blake3-aes-128-gcm');
      const is2022 = method.startsWith('2022-');
      const serverPass = inbound.password || '';
      let userPass = '';
      if (is2022) {
        userPass = (client.password && client.password !== serverPass && serverPass)
          ? `${serverPass}:${client.password}`
          : (serverPass || client.password);
      } else {
        userPass = client.password || serverPass;
      }
      const safeB64 = Buffer.from(`${method}:${userPass}`, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
      uri = `ss://${safeB64}@${host}:${port}#${label}`;
      altUri = `ss://${encodeURIComponent(method)}:${encodeURIComponent(userPass)}@${host}:${port}#${label}`;
      clashProxy = { name: labelName, type: 'ss', server: rawServer, port, cipher: method, password: userPass, udp: true };
      singboxOut = { type: 'shadowsocks', tag: labelName, server: rawServer, server_port: port, method, password: userPass };
    } else if (inbound.protocol === 'socks' || inbound.protocol === 'mixed' || inbound.protocol === 'http') {
      const user = client.username || client.email || inbound.socksUser || '';
      const pass = client.password || inbound.socksPassword || '';
      const scheme = inbound.protocol === 'http' ? 'http' : 'socks';
      if (user && pass) {
        if (scheme === 'http') {
          uri = `http://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}#${label}`;
        } else {
          const safeB64 = Buffer.from(`${user}:${pass}`, 'utf8').toString('base64').replace(/\+/g, '-').replace(/\//g, '_');
          uri = `socks://${safeB64}@${host}:${port}#${label}`;
          altUri = `socks5://${encodeURIComponent(user)}:${encodeURIComponent(pass)}@${host}:${port}#${label}`;
        }
      } else {
        uri = `${scheme === 'http' ? 'http' : 'socks5'}://${host}:${port}#${label}`;
      }
      clashProxy = {
        name: labelName,
        type: scheme === 'http' ? 'http' : 'socks5',
        server: rawServer,
        port,
        ...(user ? { username: user, password: pass } : {}),
        ...(scheme !== 'http' ? { udp: true } : {})
      };
      singboxOut = {
        type: scheme === 'http' ? 'http' : 'socks',
        tag: labelName,
        server: rawServer,
        server_port: port,
        ...(scheme !== 'http' ? { version: '5' } : {}),
        ...(user ? { username: user, password: pass } : {})
      };
    } else if (inbound.protocol === 'trojan') {
      const pass = client.password || inbound.password || '';
      const params = new URLSearchParams({ type: inbound.transport || 'tcp' });
      if (inbound.security === 'reality') {
        const r = inbound.reality || {};
        params.set('security', 'reality');
        params.set('sni', r.serverName || 'www.tesla.com');
        params.set('pbk', r.publicKey || deriveRealityPublicKey(r.privateKey));
        params.set('sid', Array.isArray(r.shortIds) ? (r.shortIds[0] || '') : String(r.shortIds || '').split(',')[0]);
      } else {
        params.set('security', 'tls');
        params.set('sni', sniDomain);
        if (isSelfSigned) {
          params.set('allowInsecure', '1');
          params.set('insecure', '1');
        }
      }
      if (inbound.transport === 'ws') {
        params.set('path', inbound.wsPath || '/');
        if (inbound.wsHost) params.set('host', inbound.wsHost);
      }
      uri = `trojan://${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
      clashProxy = { name: labelName, type: 'trojan', server: rawServer, port, password: pass, udp: true, sni: sniDomain, 'skip-cert-verify': isSelfSigned };
      singboxOut = { type: 'trojan', tag: labelName, server: rawServer, server_port: port, password: pass, tls: { enabled: true, server_name: sniDomain, insecure: isSelfSigned } };
    } else if (inbound.protocol === 'vmess') {
      const uuid = ensureUuid(client.id || client.uuid);
      const vmessJson = {
        v: '2',
        ps: labelName,
        add: rawServer,
        port: String(port),
        id: uuid,
        aid: String(client.alterId || 0),
        scy: 'auto',
        net: inbound.transport || 'tcp',
        type: 'none',
        host: inbound.wsHost || (inbound.security === 'tls' ? sniDomain : ''),
        path: inbound.wsPath || inbound.grpcServiceName || '',
        tls: inbound.security === 'tls' ? 'tls' : '',
        sni: inbound.security === 'tls' ? sniDomain : ''
      };
      uri = `vmess://${Buffer.from(JSON.stringify(vmessJson)).toString('base64')}`;
      clashProxy = { name: labelName, type: 'vmess', server: rawServer, port, uuid, alterId: Number(client.alterId || 0), cipher: 'auto', udp: true, tls: inbound.security === 'tls', 'skip-cert-verify': isSelfSigned, network: inbound.transport || 'tcp' };
      singboxOut = { type: 'vmess', tag: labelName, server: rawServer, server_port: port, uuid, security: 'auto', alter_id: Number(client.alterId || 0) };
    } else if (inbound.protocol === 'tuic') {
      const uuid = ensureUuid(client.id || client.uuid);
      const pass = client.password || inbound.password || '';
      const params = new URLSearchParams({ congestion_control: inbound.congestionControl || 'bbr', alpn: 'h3', sni: sniDomain });
      if (isSelfSigned) {
        params.set('allow_insecure', '1');
        params.set('insecure', '1');
      }
      uri = `tuic://${encodeURIComponent(uuid)}:${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
      clashProxy = { name: labelName, type: 'tuic', server: rawServer, port, uuid, password: pass, 'congestion-controller': inbound.congestionControl || 'bbr', alpn: ['h3'], sni: sniDomain, 'skip-cert-verify': isSelfSigned };
      singboxOut = { type: 'tuic', tag: labelName, server: rawServer, server_port: port, uuid, password: pass, congestion_control: inbound.congestionControl || 'bbr', tls: { enabled: true, alpn: ['h3'], server_name: sniDomain, insecure: isSelfSigned } };
    }

    if (uri) {
      links.push({
        clientName: client.email || client.name || 'default',
        subId: client.subId || 'all',
        protocol: inbound.protocol,
        name: labelName,
        uri,
        altUri,
        sniDomain,
        isSelfSigned,
        clashYaml: clashProxy ? `  - ${JSON.stringify(clashProxy)}` : '',
        singboxJson: singboxOut ? JSON.stringify(singboxOut, null, 2) : ''
      });
    }
  }

  return links;
}

/**
 * Parses a share URI into a panel Outbound object.
 * Supports vmess://, vless://, trojan://, ss:// (SIP002 & legacy full Base64), hysteria2://, hy2://, anytls://, tuic://, socks://, socks5://, http://.
 */
function parseShareUriToOutbound(rawUri, customTag = '', customRemark = '') {
  const uri = String(rawUri || '').trim();
  if (!uri) throw new Error('节点链接不能为空');

  if (uri.startsWith('vmess://')) {
    const b64 = uri.slice(8).trim().replace(/-/g, '+').replace(/_/g, '/');
    const json = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
    const remark = customRemark || json.ps || `VMess-${json.add}:${json.port}`;
    const tag = customTag || remark.replace(/\s+/g, '-') || `out-vmess-${crypto.randomBytes(3).toString('hex')}`;
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'vmess',
      remark,
      enabled: true,
      server: json.add,
      port: Number(json.port || 443),
      uuid: ensureUuid(json.id),
      alterId: Number(json.aid || 0),
      cipher: json.scy || 'auto',
      transport: json.net === 'ws' ? 'ws' : (json.net === 'grpc' ? 'grpc' : 'tcp'),
      wsPath: json.path || '/',
      wsHost: json.host || '',
      security: json.tls === 'tls' ? 'tls' : 'none',
      sni: json.sni || json.host || json.add,
      up: 0,
      down: 0
    };
  }

  // Handle legacy full-Base64 ss:// links where '@' is inside the Base64 string: ss://BASE64(method:pass@host:port)#remark
  if (uri.toLowerCase().startsWith('ss://')) {
    const withoutScheme = uri.slice(5);
    const hashIdx = withoutScheme.indexOf('#');
    const mainPart = hashIdx >= 0 ? withoutScheme.slice(0, hashIdx) : withoutScheme;
    const rawHash = hashIdx >= 0 ? withoutScheme.slice(hashIdx + 1) : '';
    if (!mainPart.includes('@')) {
      try {
        const cleanB64 = decodeURIComponent(mainPart).trim().replace(/-/g, '+').replace(/_/g, '/');
        const decoded = Buffer.from(cleanB64, 'base64').toString('utf8');
        if (decoded.includes('@')) {
          return parseShareUriToOutbound(`ss://${decoded}${rawHash ? `#${rawHash}` : ''}`, customTag, customRemark);
        }
      } catch { /* fall through */ }
    }
  }

  let parsed;
  try {
    parsed = new URL(uri);
  } catch {
    throw new Error('无法解析该节点 URI 格式');
  }

  const proto = parsed.protocol.replace(':', '').toLowerCase();
  const server = parsed.hostname.replace(/^\[|\]$/g, '');
  const port = Number(parsed.port || 443);
  const remark = customRemark || decodeURIComponent(parsed.hash ? parsed.hash.slice(1) : '') || `${proto.toUpperCase()}-${server}:${port}`;
  const tag = customTag || remark.replace(/\s+/g, '-') || `out-${proto}-${crypto.randomBytes(3).toString('hex')}`;
  const q = parsed.searchParams;

  if (proto === 'vless') {
    const security = q.get('security') || 'none';
    const rawNet = q.get('type') || 'tcp';
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'vless',
      remark,
      enabled: true,
      server,
      port,
      uuid: ensureUuid(decodeURIComponent(parsed.username)),
      flow: q.get('flow') || '',
      security,
      sni: q.get('sni') || q.get('host') || server,
      fingerprint: q.get('fp') || 'chrome',
      publicKey: q.get('pbk') || '',
      shortId: q.get('sid') || '',
      insecure: q.get('allowInsecure') === '1' || q.get('insecure') === '1',
      transport: rawNet === 'raw' ? 'tcp' : rawNet,
      wsPath: q.get('path') || '/',
      wsHost: q.get('host') || '',
      grpcServiceName: q.get('serviceName') || '',
      up: 0,
      down: 0
    };
  }

  if (proto === 'anytls') {
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'anytls',
      remark,
      enabled: true,
      server,
      port,
      password: decodeURIComponent(parsed.username || parsed.password),
      security: 'tls',
      sni: q.get('sni') || server,
      insecure: q.get('insecure') === '1' || q.get('allowInsecure') === '1',
      up: 0,
      down: 0
    };
  }

  if (proto === 'hysteria2' || proto === 'hy2') {
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'hysteria2',
      remark,
      enabled: true,
      server,
      port,
      password: decodeURIComponent(parsed.username || parsed.password),
      security: 'tls',
      sni: q.get('sni') || server,
      insecure: q.get('insecure') === '1' || q.get('allowInsecure') === '1',
      obfsPassword: q.get('obfs-password') || '',
      up: 0,
      down: 0
    };
  }

  if (proto === 'ss') {
    let method = 'aes-128-gcm';
    let password = '';
    if (parsed.password) {
      method = normalizeSsMethod(decodeURIComponent(parsed.username));
      password = decodeURIComponent(parsed.password);
    } else {
      const rawUser = decodeURIComponent(parsed.username).replace(/-/g, '+').replace(/_/g, '/');
      const decoded = Buffer.from(rawUser, 'base64').toString('utf8');
      const idx = decoded.indexOf(':');
      if (idx > 0) {
        method = normalizeSsMethod(decoded.slice(0, idx));
        password = decoded.slice(idx + 1);
      }
    }
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'shadowsocks',
      remark,
      enabled: true,
      server,
      port,
      method,
      password,
      up: 0,
      down: 0
    };
  }

  if (proto === 'socks' || proto === 'socks5' || proto === 'http' || proto === 'https') {
    let username = decodeURIComponent(parsed.username || '');
    let password = decodeURIComponent(parsed.password || '');
    if (username && !password) {
      try {
        const normB64 = username.replace(/-/g, '+').replace(/_/g, '/');
        const dec = Buffer.from(normB64, 'base64').toString('utf8');
        if (dec.includes(':')) {
          const idx = dec.indexOf(':');
          username = dec.slice(0, idx);
          password = dec.slice(idx + 1);
        }
      } catch { /* ignore */ }
    }
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: (proto === 'http' || proto === 'https') ? 'http' : 'socks',
      remark,
      enabled: true,
      server,
      port,
      username,
      password,
      ...(proto === 'https' ? { security: 'tls', sni: server } : {}),
      up: 0,
      down: 0
    };
  }

  if (proto === 'trojan') {
    const rawNet = q.get('type') || 'tcp';
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'trojan',
      remark,
      enabled: true,
      server,
      port,
      password: decodeURIComponent(parsed.username),
      security: q.get('security') || 'tls',
      sni: q.get('sni') || server,
      publicKey: q.get('pbk') || '',
      shortId: q.get('sid') || '',
      insecure: q.get('allowInsecure') === '1' || q.get('insecure') === '1',
      transport: rawNet === 'raw' ? 'tcp' : rawNet,
      wsPath: q.get('path') || '/',
      wsHost: q.get('host') || '',
      up: 0,
      down: 0
    };
  }

  if (proto === 'tuic') {
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'tuic',
      remark,
      enabled: true,
      server,
      port,
      uuid: ensureUuid(decodeURIComponent(parsed.username)),
      password: decodeURIComponent(parsed.password),
      congestionControl: q.get('congestion_control') || 'bbr',
      security: 'tls',
      sni: q.get('sni') || server,
      insecure: q.get('allow_insecure') === '1' || q.get('insecure') === '1',
      up: 0,
      down: 0
    };
  }

  throw new Error(`暂不支持自动解析协议: ${proto}`);
}

module.exports = {
  REALITY_PRESETS,
  SS_METHODS,
  INBOUND_PROTOCOLS,
  OUTBOUND_PROTOCOLS,
  isValidUuid,
  ensureUuid,
  normalizeSsMethod,
  isCertFileSelfSigned,
  generateRealityKeypair,
  deriveRealityPublicKey,
  generateSsKey,
  generateShortId,
  resolveInboundCertAndDomain,
  toSingboxInbound,
  toSingboxOutbound,
  buildClientLinks,
  parseShareUriToOutbound
};
