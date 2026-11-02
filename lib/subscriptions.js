'use strict';

const { buildClientLinks } = require('./protocols');

/**
 * Collects all enabled client links across all enabled inbounds (optionally filtered by subId or clientName).
 */
function collectSubscriptionItems(state, subToken = '', reqHost = '') {
  const cleanReqHost = String(reqHost || '').split(':')[0].replace(/^\[|\]$/g, '');
  const publicHost = state.settings?.publicIPv4 || state.settings?.webDomain || cleanReqHost || '127.0.0.1';
  const items = [];

  for (const inbound of state.inbounds || []) {
    if (inbound.enable === false || inbound.protocol === 'direct') continue;
    const links = buildClientLinks(inbound, publicHost, state.certificates || [], state.settings || {});
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

function formatSubscription(state, subToken = 'all', format = 'base64', reqHost = '') {
  const items = collectSubscriptionItems(state, subToken, reqHost);
  const uris = items.map((x) => x.link.uri);

  if (format === 'raw' || format === 'uri') {
    return {
      contentType: 'text/plain; charset=utf-8',
      body: uris.join('\n')
    };
  }

  if (format === 'clash' || format === 'mihomo') {
    const proxyLines = items.map((x) => x.link.clashYaml).filter(Boolean);
    const names = items.map((x) => x.link.name);
    const yamlLines = [
      'mixed-port: 7890',
      'allow-lan: true',
      'mode: rule',
      'log-level: info',
      'unified-delay: true',
      'tcp-concurrent: true',
      'proxies:',
      ...proxyLines,
      'proxy-groups:',
      '  - name: "🚀 节点选择"',
      '    type: select',
      `    proxies: ${JSON.stringify(['⚡ 自动测速', ...names, 'DIRECT'])}`,
      '  - name: "⚡ 自动测速"',
      '    type: url-test',
      `    proxies: ${JSON.stringify(names.length ? names : ['DIRECT'])}`,
      '    url: "https://www.gstatic.com/generate_204"',
      '    interval: 300',
      'rules:',
      '  - GEOIP,LAN,DIRECT,no-resolve',
      '  - GEOIP,CN,DIRECT',
      '  - MATCH,🚀 节点选择'
    ];
    return {
      contentType: 'text/yaml; charset=utf-8',
      body: yamlLines.join('\n') + '\n'
    };
  }

  if (format === 'singbox' || format === 'json') {
    const outbounds = items
      .map((x) => {
        try { return JSON.parse(x.link.singboxJson); } catch { return null; }
      })
      .filter(Boolean);
    const tags = outbounds.map((o) => o.tag);
    return {
      contentType: 'application/json; charset=utf-8',
      body: JSON.stringify({
        log: { level: 'info', timestamp: true },
        dns: {
          servers: [
            { tag: 'dns-remote', address: 'tls://1.1.1.1', detour: 'proxy' },
            { tag: 'dns-direct', address: '223.5.5.5', detour: 'direct' }
          ]
        },
        inbounds: [
          { type: 'mixed', tag: 'mixed-in', listen: '127.0.0.1', listen_port: 2080 }
        ],
        outbounds: [
          { type: 'selector', tag: 'proxy', outbounds: ['auto', ...tags, 'direct'] },
          { type: 'urltest', tag: 'auto', outbounds: tags.length ? tags : ['direct'] },
          ...outbounds,
          { type: 'direct', tag: 'direct' }
        ],
        route: {
          rules: [
            { action: 'sniff' },
            { ip_is_private: true, outbound: 'direct' }
          ],
          final: 'proxy',
          auto_detect_interface: true
        }
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
