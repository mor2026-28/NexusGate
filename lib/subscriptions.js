'use strict';

const { buildClientLinks, deriveRealityPublicKey } = require('./protocols');

/**
 * Collects all enabled client links across all enabled inbounds (optionally filtered by subId or clientName).
 */
function collectSubscriptionItems(state, subToken = '') {
  const publicHost = state.settings?.publicIPv4 || state.settings?.webDomain || '127.0.0.1';
  const items = [];

  for (const inbound of state.inbounds || []) {
    if (inbound.enable === false || inbound.protocol === 'direct') continue;
    const links = buildClientLinks(inbound, publicHost);
    for (let idx = 0; idx < links.length; idx += 1) {
      const link = links[idx];
      const client = (inbound.clients || [])[idx] || {};
      if (subToken && subToken !== 'all') {
        const matchSub = client.subId === subToken || client.email === subToken || inbound.tag === subToken;
        if (!matchSub) continue;
      }
      items.push({
        inbound,
        client,
        link
      });
    }
  }
  return items;
}

function toClashProxy(inbound, client, defaultHost) {
  const server = (inbound.publicHost || inbound.tlsDomain || defaultHost || '127.0.0.1').replace(/^\[|\]$/g, '');
  const port = Number(inbound.port);
  const name = `${inbound.remark || inbound.tag}-${client.email || client.name || 'node'}`;

  if (inbound.protocol === 'vless') {
    const p = {
      name,
      type: 'vless',
      server,
      port,
      uuid: client.id || client.uuid,
      udp: true,
      tls: inbound.security === 'tls' || inbound.security === 'reality',
      network: inbound.transport || 'tcp'
    };
    const flow = client.flow ?? inbound.flow ?? '';
    if (flow) p.flow = flow;
    if (inbound.security === 'reality') {
      const r = inbound.reality || {};
      p.servername = r.serverName || 'www.tesla.com';
      p['client-fingerprint'] = r.fingerprint || 'chrome';
      p['reality-opts'] = {
        'public-key': r.publicKey || deriveRealityPublicKey(r.privateKey),
        'short-id': Array.isArray(r.shortIds) ? (r.shortIds[0] || '') : String(r.shortIds || '').split(',')[0]
      };
    } else if (inbound.security === 'tls') {
      if (inbound.tlsDomain) p.servername = inbound.tlsDomain;
      if (inbound.allowInsecure) p['skip-cert-verify'] = true;
    }
    if (inbound.transport === 'ws') {
      p['ws-opts'] = {
        path: inbound.wsPath || '/',
        ...(inbound.wsHost ? { headers: { Host: inbound.wsHost } } : {})
      };
    } else if (inbound.transport === 'grpc') {
      p['grpc-opts'] = { 'grpc-service-name': inbound.grpcServiceName || 'grpc' };
    }
    return p;
  }

  if (inbound.protocol === 'anytls') {
    return {
      name,
      type: 'anytls',
      server,
      port,
      password: client.password || inbound.password || '',
      udp: true,
      sni: inbound.tlsDomain || server,
      'skip-cert-verify': Boolean(inbound.allowInsecure)
    };
  }

  if (inbound.protocol === 'hysteria2') {
    const hy2 = {
      name,
      type: 'hysteria2',
      server,
      port,
      password: client.password || inbound.password || '',
      sni: inbound.tlsDomain || server,
      alpn: ['h3'],
      'skip-cert-verify': Boolean(inbound.allowInsecure)
    };
    if (inbound.obfsPassword) {
      hy2.obfs = 'salamander';
      hy2['obfs-password'] = inbound.obfsPassword;
    }
    return hy2;
  }

  if (inbound.protocol === 'shadowsocks') {
    const method = inbound.method || '2022-blake3-aes-128-gcm';
    const serverPass = inbound.password || '';
    const password = client.password && client.password !== serverPass && method.startsWith('2022-')
      ? `${serverPass}:${client.password}`
      : (client.password || serverPass);
    return {
      name,
      type: 'ss',
      server,
      port,
      cipher: method,
      password,
      udp: true
    };
  }

  if (inbound.protocol === 'socks') {
    return {
      name,
      type: 'socks5',
      server,
      port,
      username: client.username || client.email || inbound.socksUser || '',
      password: client.password || inbound.socksPassword || '',
      udp: true
    };
  }

  if (inbound.protocol === 'trojan') {
    return {
      name,
      type: 'trojan',
      server,
      port,
      password: client.password || inbound.password || '',
      udp: true,
      sni: inbound.tlsDomain || server,
      'skip-cert-verify': Boolean(inbound.allowInsecure)
    };
  }

  if (inbound.protocol === 'vmess') {
    return {
      name,
      type: 'vmess',
      server,
      port,
      uuid: client.id || client.uuid,
      alterId: Number(client.alterId || 0),
      cipher: 'auto',
      udp: true,
      tls: inbound.security === 'tls',
      network: inbound.transport || 'tcp'
    };
  }

  return null;
}

function formatSubscription(state, subToken = 'all', format = 'base64') {
  const defaultHost = state.settings?.publicIPv4 || state.settings?.webDomain || '127.0.0.1';
  const items = collectSubscriptionItems(state, subToken);
  const uris = items.map((x) => x.link.uri);

  if (format === 'raw' || format === 'uri') {
    return {
      contentType: 'text/plain; charset=utf-8',
      body: uris.join('\n')
    };
  }

  if (format === 'clash' || format === 'mihomo') {
    const proxies = items.map((x) => toClashProxy(x.inbound, x.client, defaultHost)).filter(Boolean);
    const names = proxies.map((p) => p.name);
    const yamlLines = [
      'mixed-port: 7890',
      'allow-lan: true',
      'mode: rule',
      'log-level: info',
      'proxies:'
    ];
    for (const p of proxies) {
      yamlLines.push(`  - ${JSON.stringify(p)}`);
    }
    yamlLines.push(
      'proxy-groups:',
      `  - name: "🚀 节点选择"`,
      '    type: select',
      `    proxies: ${JSON.stringify([...names, 'DIRECT'])}`,
      'rules:',
      '  - GEOIP,LAN,DIRECT,no-resolve',
      '  - GEOIP,CN,DIRECT',
      '  - MATCH,🚀 节点选择'
    );
    return {
      contentType: 'text/yaml; charset=utf-8',
      body: yamlLines.join('\n') + '\n'
    };
  }

  if (format === 'singbox' || format === 'json') {
    const outbounds = items.map((x) => {
      const p = toClashProxy(x.inbound, x.client, defaultHost);
      return {
        tag: x.link.name,
        type: x.inbound.protocol,
        server: p?.server || defaultHost,
        server_port: Number(x.inbound.port)
      };
    });
    return {
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify({
        log: { level: 'info' },
        inbounds: [{ type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }],
        outbounds: [
          { type: 'selector', tag: 'proxy', outbounds: [...outbounds.map((o) => o.tag), 'direct'] },
          ...outbounds,
          { type: 'direct', tag: 'direct' }
        ],
        route: { final: 'proxy' }
      }, null, 2)
    };
  }

  return {
    contentType: 'text/plain; charset=utf-8',
    body: Buffer.from(uris.join('\n'), 'utf8').toString('base64')
  };
}

module.exports = {
  collectSubscriptionItems,
  formatSubscription
};
