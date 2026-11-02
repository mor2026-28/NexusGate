'use strict';

const crypto = require('node:crypto');
const net = require('node:net');

const REALITY_PRESETS = Object.freeze([
  { id: 'tesla', label: 'Tesla (www.tesla.com)', serverName: 'www.tesla.com', target: 'www.tesla.com:443' },
  { id: 'apple', label: 'Apple (www.apple.com)', serverName: 'www.apple.com', target: 'www.apple.com:443' },
  { id: 'microsoft', label: 'Microsoft (www.microsoft.com)', serverName: 'www.microsoft.com', target: 'www.microsoft.com:443' },
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
  { id: 'trojan', name: 'Trojan (TLS / Reality / WS)', badge: 'Trojan', desc: '经典 TLS 伪装协议，支持证书 TLS、Reality 或 WebSocket 传输' },
  { id: 'vmess', name: 'VMess (TCP / WS / TLS / gRPC)', badge: 'VMess', desc: '广泛兼容主流客户端，支持 WebSocket + TLS 或中转隧道' },
  { id: 'tuic', name: 'TUIC v5 (QUIC 0-RTT UDP)', badge: 'TUIC', desc: '基于 QUIC 的低延迟 UDP 协议，支持 BBR 拥塞控制' },
  { id: 'direct', name: 'Direct 端口转发 (Dokodemo 隧道中转)', badge: '端口转发', desc: '将本机端口 TCP/UDP 流量直接转发至目标 IP:Port 或通过指定出站中转' }
]);

const OUTBOUND_PROTOCOLS = Object.freeze([
  { id: 'vless', name: 'VLESS 出站 (Reality / TLS / WS / TCP)' },
  { id: 'anytls', name: 'AnyTLS 出站 (TLS)' },
  { id: 'hysteria2', name: 'Hysteria 2 出站 (UDP QUIC)' },
  { id: 'shadowsocks', name: 'Shadowsocks 出站 (SS 128/256 / SS 2022)' },
  { id: 'socks', name: 'SOCKS5 出站' },
  { id: 'trojan', name: 'Trojan 出站' },
  { id: 'vmess', name: 'VMess 出站' },
  { id: 'tuic', name: 'TUIC v5 出站' },
  { id: 'http', name: 'HTTP/HTTPS 代理出站' },
  { id: 'urltest', name: 'URLTest 自动测速负载均衡组' },
  { id: 'selector', name: 'Selector 手动/故障切换出站组' },
  { id: 'direct', name: 'Direct 本地直连' },
  { id: 'block', name: 'Block 黑洞拦截' }
]);

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
  const spec = SS_METHODS.find((m) => m.id === method);
  const bytes = spec ? spec.keyBytes : 16;
  return crypto.randomBytes(bytes).toString('base64');
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

/**
 * Converts a panel Inbound object into a native Sing-box inbound configuration object.
 */
function toSingboxInbound(inbound, certificates = []) {
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
  const tlsConfig = buildInboundTls(inbound, certificates);
  const transportConfig = buildInboundTransport(inbound);

  switch (inbound.protocol) {
    case 'vless': {
      const isReality = inbound.security === 'reality';
      return {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || `user_${c.id?.slice(0, 6)}`,
          uuid: c.id || c.uuid || crypto.randomUUID(),
          flow: isReality || inbound.security === 'tls' ? (c.flow ?? inbound.flow ?? '') : ''
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
          password: c.password || c.id || inbound.password || generateSsKey('aes-128-gcm')
        })),
        padding_scheme: Array.isArray(inbound.paddingScheme) && inbound.paddingScheme.length
          ? inbound.paddingScheme
          : undefined,
        tls: tlsConfig || {
          enabled: true,
          server_name: inbound.tlsDomain || 'localhost',
          certificate_path: inbound.certPath || '/etc/nexusgate/certs/selfsigned/fullchain.pem',
          key_path: inbound.keyPath || '/etc/nexusgate/certs/selfsigned/privkey.pem'
        }
      };
    }

    case 'hysteria2': {
      const hy2 = {
        ...base,
        users: activeClients.map((c) => ({
          name: c.email || c.name || 'hy2_user',
          password: c.password || c.id || inbound.password || generateSsKey('aes-128-gcm')
        })),
        tls: tlsConfig || {
          enabled: true,
          alpn: ['h3'],
          server_name: inbound.tlsDomain || 'localhost',
          certificate_path: inbound.certPath || '/etc/nexusgate/certs/selfsigned/fullchain.pem',
          key_path: inbound.keyPath || '/etc/nexusgate/certs/selfsigned/privkey.pem'
        }
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
      const method = inbound.method || '2022-blake3-aes-128-gcm';
      const serverPassword = inbound.password || generateSsKey(method);
      const ss = {
        ...base,
        network: inbound.network === 'tcp' || inbound.network === 'udp' ? inbound.network : undefined,
        method,
        password: serverPassword
      };
      if (activeClients.length > 0) {
        ss.users = activeClients.map((c) => ({
          name: c.email || c.name || 'ss_user',
          password: c.password || serverPassword
        }));
      }
      return ss;
    }

    case 'socks': {
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
          password: c.password || c.id || inbound.password || generateSsKey('aes-128-gcm')
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
          uuid: c.id || c.uuid || crypto.randomUUID(),
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
          uuid: c.id || c.uuid || crypto.randomUUID(),
          password: c.password || inbound.password || ''
        })),
        congestion_control: inbound.congestionControl || 'bbr',
        tls: tlsConfig || {
          enabled: true,
          alpn: ['h3'],
          server_name: inbound.tlsDomain || 'localhost',
          certificate_path: inbound.certPath || '/etc/nexusgate/certs/selfsigned/fullchain.pem',
          key_path: inbound.keyPath || '/etc/nexusgate/certs/selfsigned/privkey.pem'
        }
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

function buildInboundTls(inbound, certificates = []) {
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
    let certPath = inbound.certPath || '';
    let keyPath = inbound.keyPath || '';
    const domain = inbound.tlsDomain || '';
    if ((!certPath || !keyPath) && domain) {
      const matched = certificates.find((c) => c.domain === domain);
      if (matched) {
        certPath = matched.certPath;
        keyPath = matched.keyPath;
      }
    }
    if (!certPath || !keyPath) {
      certPath = '/etc/nexusgate/certs/selfsigned/fullchain.pem';
      keyPath = '/etc/nexusgate/certs/selfsigned/privkey.pem';
    }
    const tls = {
      enabled: true,
      server_name: domain || 'localhost',
      certificate_path: certPath,
      key_path: keyPath
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
  if (outbound.type === 'direct') {
    return { type: 'direct', tag: outbound.tag };
  }
  if (outbound.type === 'block') {
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
        uuid: s.uuid || s.id || outbound.uuid || '',
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

    case 'shadowsocks':
      return {
        ...base,
        method: s.method || outbound.method || '2022-blake3-aes-128-gcm',
        password: s.password || outbound.password || ''
      };

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
        uuid: s.uuid || s.id || outbound.uuid || '',
        security: s.security || outbound.cipher || 'auto',
        alter_id: Number(s.alterId || outbound.alterId || 0),
        ...(tls ? { tls } : {}),
        ...(transport ? { transport } : {})
      };

    case 'tuic':
      return {
        ...base,
        uuid: s.uuid || outbound.uuid || '',
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
 * Generates client share links (URI) for an inbound and its clients.
 */
function buildClientLinks(inbound, publicHost = '127.0.0.1') {
  const hostAddr = inbound.publicHost || inbound.tlsDomain || publicHost || '127.0.0.1';
  const host = uriHost(hostAddr);
  const port = Number(inbound.port);
  const clients = (inbound.clients && inbound.clients.length)
    ? inbound.clients
    : [{ email: inbound.remark || inbound.tag, id: inbound.uuid || crypto.randomUUID(), password: inbound.password }];

  const links = [];

  for (const client of clients) {
    if (client.enable === false) continue;
    const labelName = `${inbound.remark || inbound.tag}-${client.email || client.name || 'client'}`;
    const label = encodeURIComponent(labelName);
    let uri = '';

    if (inbound.protocol === 'vless') {
      const uuid = client.id || client.uuid;
      const params = new URLSearchParams({ encryption: 'none' });
      const transport = inbound.transport || 'tcp';
      params.set('type', transport);

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
        const flow = client.flow ?? inbound.flow ?? '';
        if (flow) params.set('flow', flow);
      } else if (inbound.security === 'tls') {
        params.set('security', 'tls');
        if (inbound.tlsDomain) params.set('sni', inbound.tlsDomain);
        const flow = client.flow ?? inbound.flow ?? '';
        if (flow) params.set('flow', flow);
        if (inbound.allowInsecure) params.set('allowInsecure', '1');
      } else {
        params.set('security', 'none');
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
      const params = new URLSearchParams();
      if (inbound.tlsDomain) params.set('sni', inbound.tlsDomain);
      if (inbound.allowInsecure) params.set('insecure', '1');
      uri = `anytls://${encodeURIComponent(pass)}@${host}:${port}${params.toString() ? `?${params.toString()}` : ''}#${label}`;
    } else if (inbound.protocol === 'hysteria2') {
      const pass = client.password || inbound.password || '';
      const params = new URLSearchParams({ alpn: 'h3' });
      if (inbound.tlsDomain) params.set('sni', inbound.tlsDomain);
      if (inbound.allowInsecure) params.set('insecure', '1');
      if (inbound.obfsPassword) {
        params.set('obfs', 'salamander');
        params.set('obfs-password', inbound.obfsPassword);
      }
      uri = `hysteria2://${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
    } else if (inbound.protocol === 'shadowsocks') {
      const method = inbound.method || '2022-blake3-aes-128-gcm';
      const serverPass = inbound.password || '';
      const userPass = client.password && client.password !== serverPass && method.startsWith('2022-')
        ? `${serverPass}:${client.password}`
        : (client.password || serverPass);
      const userInfo = Buffer.from(`${method}:${userPass}`).toString('base64url');
      uri = `ss://${userInfo}@${host}:${port}#${label}`;
    } else if (inbound.protocol === 'socks') {
      const user = client.username || client.email || inbound.socksUser || '';
      const pass = client.password || inbound.socksPassword || '';
      const authPart = user && pass ? `${encodeURIComponent(user)}:${encodeURIComponent(pass)}@` : '';
      uri = `socks5://${authPart}${host}:${port}#${label}`;
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
        if (inbound.tlsDomain) params.set('sni', inbound.tlsDomain);
        if (inbound.allowInsecure) params.set('allowInsecure', '1');
      }
      if (inbound.transport === 'ws') {
        params.set('path', inbound.wsPath || '/');
        if (inbound.wsHost) params.set('host', inbound.wsHost);
      }
      uri = `trojan://${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
    } else if (inbound.protocol === 'vmess') {
      const vmessJson = {
        v: '2',
        ps: labelName,
        add: hostAddr.replace(/^\[|\]$/g, ''),
        port: String(port),
        id: client.id || client.uuid,
        aid: String(client.alterId || 0),
        scy: 'auto',
        net: inbound.transport || 'tcp',
        type: 'none',
        host: inbound.wsHost || inbound.tlsDomain || '',
        path: inbound.wsPath || inbound.grpcServiceName || '',
        tls: inbound.security === 'tls' ? 'tls' : '',
        sni: inbound.tlsDomain || ''
      };
      uri = `vmess://${Buffer.from(JSON.stringify(vmessJson)).toString('base64')}`;
    } else if (inbound.protocol === 'tuic') {
      const uuid = client.id || client.uuid;
      const pass = client.password || inbound.password || '';
      const params = new URLSearchParams({ congestion_control: inbound.congestionControl || 'bbr', alpn: 'h3' });
      if (inbound.tlsDomain) params.set('sni', inbound.tlsDomain);
      if (inbound.allowInsecure) params.set('allow_insecure', '1');
      uri = `tuic://${encodeURIComponent(uuid)}:${encodeURIComponent(pass)}@${host}:${port}?${params.toString()}#${label}`;
    }

    if (uri) {
      links.push({
        clientName: client.email || client.name || 'default',
        subId: client.subId || '',
        protocol: inbound.protocol,
        name: labelName,
        uri
      });
    }
  }

  return links;
}

/**
 * Parses a share URI (vless://, ss://, hy2://, anytls://, vmess://, trojan://, socks5://, tuic://)
 * into a panel Outbound object for quick relay setup.
 */
function parseShareUriToOutbound(rawUri, customTag = '', customRemark = '') {
  const uri = String(rawUri || '').trim();
  if (!uri) throw new Error('节点链接不能为空');

  if (uri.startsWith('vmess://')) {
    const b64 = uri.slice(8).trim();
    const json = JSON.parse(Buffer.from(b64, 'base64').toString('utf8'));
    const tag = customTag || `out-vmess-${crypto.randomBytes(3).toString('hex')}`;
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'vmess',
      remark: customRemark || json.ps || `VMess ${json.add}:${json.port}`,
      enabled: true,
      server: json.add,
      port: Number(json.port || 443),
      uuid: json.id,
      alterId: Number(json.aid || 0),
      cipher: json.scy || 'auto',
      transport: json.net === 'ws' ? 'ws' : (json.net === 'grpc' ? 'grpc' : 'tcp'),
      wsPath: json.path || '/',
      wsHost: json.host || '',
      security: json.tls === 'tls' ? 'tls' : 'none',
      sni: json.sni || json.host || json.add
    };
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
  const remark = customRemark || decodeURIComponent(parsed.hash ? parsed.hash.slice(1) : '') || `${proto.toUpperCase()} ${server}:${port}`;
  const tag = customTag || `out-${proto}-${crypto.randomBytes(3).toString('hex')}`;
  const q = parsed.searchParams;

  if (proto === 'vless') {
    const security = q.get('security') || 'none';
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'vless',
      remark,
      enabled: true,
      server,
      port,
      uuid: decodeURIComponent(parsed.username),
      flow: q.get('flow') || '',
      security,
      sni: q.get('sni') || q.get('host') || server,
      fingerprint: q.get('fp') || 'chrome',
      publicKey: q.get('pbk') || '',
      shortId: q.get('sid') || '',
      insecure: q.get('allowInsecure') === '1' || q.get('insecure') === '1',
      transport: q.get('type') || 'tcp',
      wsPath: q.get('path') || '/',
      wsHost: q.get('host') || '',
      grpcServiceName: q.get('serviceName') || ''
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
      insecure: q.get('insecure') === '1' || q.get('allowInsecure') === '1'
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
      obfsPassword: q.get('obfs-password') || ''
    };
  }

  if (proto === 'ss') {
    let method = 'aes-128-gcm';
    let password = '';
    if (parsed.password) {
      method = decodeURIComponent(parsed.username);
      password = decodeURIComponent(parsed.password);
    } else {
      const decoded = Buffer.from(decodeURIComponent(parsed.username), 'base64').toString('utf8');
      const idx = decoded.indexOf(':');
      if (idx > 0) {
        method = decoded.slice(0, idx);
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
      password
    };
  }

  if (proto === 'socks' || proto === 'socks5') {
    return {
      id: `out_${crypto.randomBytes(5).toString('hex')}`,
      tag,
      type: 'socks',
      remark,
      enabled: true,
      server,
      port,
      username: decodeURIComponent(parsed.username || ''),
      password: decodeURIComponent(parsed.password || '')
    };
  }

  if (proto === 'trojan') {
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
      transport: q.get('type') || 'tcp',
      wsPath: q.get('path') || '/',
      wsHost: q.get('host') || ''
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
      uuid: decodeURIComponent(parsed.username),
      password: decodeURIComponent(parsed.password),
      congestionControl: q.get('congestion_control') || 'bbr',
      security: 'tls',
      sni: q.get('sni') || server,
      insecure: q.get('allow_insecure') === '1' || q.get('insecure') === '1'
    };
  }

  throw new Error(`暂不支持自动解析协议: ${proto}`);
}

module.exports = {
  REALITY_PRESETS,
  SS_METHODS,
  INBOUND_PROTOCOLS,
  OUTBOUND_PROTOCOLS,
  generateRealityKeypair,
  deriveRealityPublicKey,
  generateSsKey,
  generateShortId,
  toSingboxInbound,
  toSingboxOutbound,
  buildClientLinks,
  parseShareUriToOutbound
};
