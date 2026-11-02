'use strict';

const http = require('node:http');
const https = require('node:https');
const fs = require('node:fs');
const path = require('node:path');
const crypto = require('node:crypto');
const { Store } = require('./lib/store');
const { hashSecret, verifySecret, randomString, SessionManager } = require('./lib/auth');
const {
  sendJson,
  sendError,
  readBuffer,
  readJson,
  normalizeBasePath,
  stripBasePath,
  route,
  serveStatic
} = require('./lib/http');
const {
  REALITY_PRESETS,
  SS_METHODS,
  INBOUND_PROTOCOLS,
  OUTBOUND_PROTOCOLS,
  generateRealityKeypair,
  deriveRealityPublicKey,
  generateSsKey,
  generateShortId,
  buildClientLinks,
  parseShareUriToOutbound
} = require('./lib/protocols');
const { KNOWN_VERSIONS, buildSingboxConfig, SingboxManager } = require('./lib/singbox');
const {
  getSystemStatus,
  inspectCertificate,
  issueSelfSignedCert,
  saveCustomCert,
  issueAcmeCert
} = require('./lib/system');
const { parse3xuiPayload, apply3xuiMigration } = require('./lib/migrate3xui');
const { collectSubscriptionItems, formatSubscription } = require('./lib/subscriptions');

const VERSION = '2.0.0';
const APP_ROOT = __dirname;
const PUBLIC_DIR = path.join(APP_ROOT, 'public');
const DATA_FILE = process.env.NG_DATA_FILE || path.join(APP_ROOT, 'data', 'nexusgate.json');

const store = new Store(DATA_FILE);

// Handle CLI flags for `nexusgate` management script
if (process.argv.length > 2 && process.argv[2].startsWith('--')) {
  handleCliCommand(process.argv.slice(2));
  process.exit(0);
}

const sessions = new SessionManager(24);
sessions.setMaxAgeMinutes(store.state.settings.sessionMaxAge || 720);
const singbox = new SingboxManager(store);
const loginAttempts = new Map();

function handleCliCommand(args) {
  const cmd = args[0];
  if (cmd === '--show-info') {
    const s = store.state.settings;
    const proto = s.webCertFile && s.webKeyFile && fs.existsSync(s.webCertFile) ? 'https' : 'http';
    const host = s.webDomain || s.publicIPv4 || '您的服务器IP';
    const base = normalizeBasePath(s.webBasePath);
    console.log(JSON.stringify({
      version: VERSION,
      username: store.state.admin.username,
      listen: s.webListen,
      port: s.webPort,
      basePath: base,
      https: proto === 'https',
      url: `${proto}://${host}:${s.webPort}${base === '/' ? '/' : `${base}/`}`,
      inboundsCount: store.state.inbounds.length,
      outboundsCount: store.state.outbounds.length
    }, null, 2));
    return;
  }
  if (cmd === '--set-account') {
    const username = args[1];
    const password = args[2];
    if (!username || !password) {
      console.error('用法: node server.js --set-account <username> <password>');
      process.exit(1);
    }
    store.transact((st) => {
      st.admin.username = username.trim();
      st.admin.passwordHash = hashSecret(password);
      st.admin.updatedAt = new Date().toISOString();
    });
    console.log(`管理员账号已更新为: ${username}`);
    return;
  }
  if (cmd === '--set-port') {
    const port = Number(args[1]);
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      console.error('无效端口号 (1-65535)');
      process.exit(1);
    }
    store.transact((st) => {
      st.settings.webPort = port;
    });
    console.log(`面板端口已更改为: ${port}`);
    return;
  }
  if (cmd === '--set-path') {
    const base = normalizeBasePath(args[1] || '/');
    store.transact((st) => {
      st.settings.webBasePath = base;
    });
    console.log(`面板安全根路径已更改为: ${base}`);
    return;
  }
  if (cmd === '--set-cert') {
    const certFile = args[1] || '';
    const keyFile = args[2] || '';
    store.transact((st) => {
      st.settings.webCertFile = certFile;
      st.settings.webKeyFile = keyFile;
    });
    console.log(`面板 SSL 证书路径已更新`);
    return;
  }
  if (cmd === '--migrate-3xui') {
    const dbPath = args[1] || '/etc/x-ui/x-ui.db';
    const mode = args[2] || 'merge';
    const parsed = parse3xuiPayload({ dbPath });
    const rec = apply3xuiMigration(store, parsed, mode);
    singbox.writeConfig();
    console.log(`成功从 ${dbPath} 无损迁移: 入站 ${rec.inboundsCount} 个 (${rec.clientsCount} 客户端), 出站 ${rec.outboundsCount} 个, 分流规则 ${rec.rulesCount} 条`);
    return;
  }
}

function normalizeInboundPayload(body, existing = null) {
  const protocol = String(body.protocol || existing?.protocol || 'vless').toLowerCase();
  const port = Number(body.port || existing?.port || (Math.floor(Math.random() * 40000) + 15000));
  if (!Number.isInteger(port) || port < 1 || port > 65535) {
    const err = new Error('端口号必须是 1–65535 之间的整数');
    err.statusCode = 400;
    throw err;
  }

  const tag = String(body.tag || existing?.tag || `${protocol}-${port}`).trim();
  const remark = String(body.remark || existing?.remark || `${protocol.toUpperCase()}-${port}`).trim();
  const listen = String(body.listen || existing?.listen || '::').trim();
  const enable = body.enable !== undefined ? Boolean(body.enable) : (existing ? existing.enable !== false : true);
  const outboundTag = String(body.outboundTag ?? existing?.outboundTag ?? 'default').trim();

  let security = String(body.security ?? existing?.security ?? 'none').toLowerCase();
  if (['anytls', 'hysteria2', 'tuic'].includes(protocol)) {
    security = 'tls';
  }
  const transport = String(body.transport ?? existing?.transport ?? 'tcp').toLowerCase();

  const inbound = {
    id: existing?.id || `in_${crypto.randomBytes(5).toString('hex')}`,
    tag,
    remark,
    protocol,
    listen,
    port,
    enable,
    security,
    transport,
    outboundTag,
    up: Number(body.up ?? existing?.up ?? 0),
    down: Number(body.down ?? existing?.down ?? 0),
    total: Number(body.total ?? existing?.total ?? 0),
    expiryTime: Number(body.expiryTime ?? existing?.expiryTime ?? 0),
    createdAt: existing?.createdAt || new Date().toISOString(),
    updatedAt: new Date().toISOString()
  };

  if (security === 'reality') {
    const rIn = body.reality || existing?.reality || {};
    let priv = String(rIn.privateKey || '').trim();
    let pub = String(rIn.publicKey || '').trim();
    if (!priv) {
      const pair = generateRealityKeypair();
      priv = pair.privateKey;
      pub = pair.publicKey;
    } else if (!pub) {
      pub = deriveRealityPublicKey(priv);
    }
    const serverName = String(rIn.serverName || 'www.tesla.com').trim();
    const target = String(rIn.target || `${serverName}:443`).trim();
    const shortIds = Array.isArray(rIn.shortIds)
      ? rIn.shortIds
      : String(rIn.shortIds || rIn.shortId || generateShortId())
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);

    inbound.reality = {
      serverName,
      target,
      privateKey: priv,
      publicKey: pub,
      shortIds: shortIds.length ? shortIds : [generateShortId()],
      fingerprint: rIn.fingerprint || 'chrome'
    };
  }

  if (security === 'tls') {
    inbound.tlsDomain = String(body.tlsDomain ?? existing?.tlsDomain ?? '').trim();
    inbound.certPath = String(body.certPath ?? existing?.certPath ?? '').trim();
    inbound.keyPath = String(body.keyPath ?? existing?.keyPath ?? '').trim();
    inbound.allowInsecure = Boolean(body.allowInsecure ?? existing?.allowInsecure ?? false);
    inbound.alpn = Array.isArray(body.alpn)
      ? body.alpn
      : String(body.alpn ?? (['hysteria2', 'tuic'].includes(protocol) ? 'h3' : ''))
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean);
  }

  if (['ws', 'httpupgrade', 'http', 'h2'].includes(transport)) {
    inbound.wsPath = String(body.wsPath ?? existing?.wsPath ?? '/').trim();
    inbound.wsHost = String(body.wsHost ?? existing?.wsHost ?? '').trim();
  } else if (transport === 'grpc') {
    inbound.grpcServiceName = String(body.grpcServiceName ?? existing?.grpcServiceName ?? 'grpc').trim();
  }

  if (protocol === 'vless') {
    inbound.flow = String(body.flow ?? existing?.flow ?? (security === 'reality' && transport === 'tcp' ? 'xtls-rprx-vision' : '')).trim();
  } else if (protocol === 'shadowsocks') {
    inbound.method = String(body.method || existing?.method || '2022-blake3-aes-128-gcm').trim();
    inbound.password = String(body.password || existing?.password || generateSsKey(inbound.method)).trim();
    inbound.network = String(body.network || existing?.network || 'tcp,udp').trim();
  } else if (protocol === 'hysteria2') {
    inbound.password = String(body.password || existing?.password || randomString(18)).trim();
    inbound.upMbps = Number(body.upMbps ?? existing?.upMbps ?? 100);
    inbound.downMbps = Number(body.downMbps ?? existing?.downMbps ?? 100);
    inbound.obfsPassword = String(body.obfsPassword ?? existing?.obfsPassword ?? '').trim();
  } else if (protocol === 'anytls') {
    inbound.password = String(body.password || existing?.password || randomString(18)).trim();
  } else if (protocol === 'socks') {
    inbound.socksUser = String(body.socksUser ?? existing?.socksUser ?? `user_${randomString(4)}`).trim();
    inbound.socksPassword = String(body.socksPassword ?? existing?.socksPassword ?? randomString(12)).trim();
  } else if (protocol === 'trojan') {
    inbound.password = String(body.password || existing?.password || randomString(18)).trim();
  } else if (protocol === 'tuic') {
    inbound.password = String(body.password || existing?.password || randomString(16)).trim();
    inbound.congestionControl = String(body.congestionControl || existing?.congestionControl || 'bbr').trim();
  } else if (protocol === 'direct') {
    inbound.overrideAddress = String(body.overrideAddress ?? existing?.overrideAddress ?? '').trim();
    inbound.overridePort = Number(body.overridePort ?? existing?.overridePort ?? 0);
    inbound.network = String(body.network ?? existing?.network ?? 'tcp,udp').trim();
  }

  // Normalize clients list
  if (Array.isArray(body.clients) && body.clients.length > 0) {
    inbound.clients = body.clients.map((c, i) => ({
      id: c.id || c.uuid || crypto.randomUUID(),
      email: String(c.email || c.name || `${remark}_${i + 1}`).trim(),
      username: String(c.username || c.email || `user_${i + 1}`).trim(),
      password: String(c.password || inbound.password || inbound.socksPassword || generateSsKey(inbound.method || 'aes-128-gcm')).trim(),
      flow: c.flow !== undefined ? c.flow : (inbound.flow || ''),
      subId: String(c.subId || randomString(10)).trim(),
      totalGB: Number(c.totalGB || 0),
      up: Number(c.up || 0),
      down: Number(c.down || 0),
      expiryTime: Number(c.expiryTime || 0),
      enable: c.enable !== false
    }));
  } else if (existing?.clients?.length && !body.resetClients) {
    inbound.clients = existing.clients.map((c) => ({
      ...c,
      flow: inbound.protocol === 'vless' ? (inbound.flow ?? c.flow ?? '') : c.flow,
      password: ['anytls', 'hysteria2', 'trojan', 'shadowsocks'].includes(inbound.protocol) && body.password
        ? body.password
        : c.password
    }));
  } else if (protocol !== 'direct') {
    inbound.clients = [
      {
        id: body.uuid || crypto.randomUUID(),
        email: body.clientEmail || `${tag}_default`,
        username: inbound.socksUser || `user_${randomString(4)}`,
        password: inbound.password || inbound.socksPassword || generateSsKey(inbound.method || 'aes-128-gcm'),
        flow: inbound.flow || '',
        subId: randomString(10),
        totalGB: 0,
        up: 0,
        down: 0,
        expiryTime: 0,
        enable: true
      }
    ];
  } else {
    inbound.clients = [];
  }

  return inbound;
}

function normalizeOutboundPayload(body, existing = null) {
  const type = String(body.type || existing?.type || 'shadowsocks').toLowerCase();
  const tag = String(body.tag || existing?.tag || `out-${type}-${randomString(4).toLowerCase()}`).trim();
  const remark = String(body.remark || existing?.remark || tag).trim();

  const outbound = {
    id: existing?.id || `out_${crypto.randomBytes(5).toString('hex')}`,
    tag,
    type,
    remark,
    builtin: Boolean(existing?.builtin),
    enabled: body.enabled !== undefined ? Boolean(body.enabled) : (existing ? existing.enabled !== false : true),
    server: String(body.server ?? existing?.server ?? '').trim(),
    port: Number(body.port ?? existing?.port ?? 443),
    detour: String(body.detour ?? existing?.detour ?? '').trim(),
    security: String(body.security ?? existing?.security ?? (['anytls', 'hysteria2', 'tuic'].includes(type) ? 'tls' : 'none')).toLowerCase(),
    transport: String(body.transport ?? existing?.transport ?? 'tcp').toLowerCase(),
    uuid: String(body.uuid ?? existing?.uuid ?? '').trim(),
    password: String(body.password ?? existing?.password ?? '').trim(),
    method: String(body.method ?? existing?.method ?? '2022-blake3-aes-128-gcm').trim(),
    username: String(body.username ?? existing?.username ?? '').trim(),
    flow: String(body.flow ?? existing?.flow ?? '').trim(),
    sni: String(body.sni ?? existing?.sni ?? '').trim(),
    fingerprint: String(body.fingerprint ?? existing?.fingerprint ?? 'chrome').trim(),
    publicKey: String(body.publicKey ?? existing?.publicKey ?? '').trim(),
    shortId: String(body.shortId ?? existing?.shortId ?? '').trim(),
    insecure: Boolean(body.insecure ?? existing?.insecure ?? false),
    wsPath: String(body.wsPath ?? existing?.wsPath ?? '/').trim(),
    wsHost: String(body.wsHost ?? existing?.wsHost ?? '').trim(),
    grpcServiceName: String(body.grpcServiceName ?? existing?.grpcServiceName ?? '').trim(),
    upMbps: Number(body.upMbps ?? existing?.upMbps ?? 0),
    downMbps: Number(body.downMbps ?? existing?.downMbps ?? 0),
    obfsPassword: String(body.obfsPassword ?? existing?.obfsPassword ?? '').trim(),
    outbounds: Array.isArray(body.outbounds)
      ? body.outbounds
      : String(body.outbounds || (existing?.outbounds || []).join(','))
          .split(',')
          .map((s) => s.trim())
          .filter(Boolean)
  };
  return outbound;
}

function enrichInboundWithLinks(inbound) {
  const defaultHost = store.state.settings.publicIPv4 || store.state.settings.webDomain || '127.0.0.1';
  return {
    ...inbound,
    links: buildClientLinks(inbound, defaultHost)
  };
}

function autoApplyIfEnabled() {
  if (store.state.settings.autoApplyConfig !== false) {
    try {
      singbox.restart();
    } catch {
      singbox.writeConfig();
    }
  } else {
    singbox.writeConfig();
  }
}

async function handleRequest(req, res) {
  try {
    const url = new URL(req.url || '/', `http://${req.headers.host || 'localhost'}`);
    const rawPathname = url.pathname;
    const method = req.method || 'GET';

    // 1. Health check endpoint
    if (rawPathname === '/healthz' && method === 'GET') {
      return sendJson(res, 200, { status: 'ok', version: VERSION });
    }

    // 2. Public Subscription endpoint (/sub/:token or <basePath>/sub/:token)
    const configuredSubPath = normalizeBasePath(store.state.settings.subPath || '/sub/');
    const strippedForSub = stripBasePath(rawPathname, store.state.settings.webBasePath) || rawPathname;
    for (const candidatePath of [rawPathname, strippedForSub]) {
      const subMatch = route(`${configuredSubPath === '/' ? '/sub' : configuredSubPath}/:token`, candidatePath)
        || route('/sub/:token', candidatePath);
      if (subMatch && method === 'GET') {
        if (store.state.settings.subEnable === false) {
          return sendError(res, 403, '订阅功能已关闭', 'sub_disabled');
        }
        const ua = String(req.headers['user-agent'] || '').toLowerCase();
        const fmt = url.searchParams.get('format')
          || (ua.includes('clash') || ua.includes('mihomo') || ua.includes('stash') ? 'clash' : (ua.includes('sing-box') || ua.includes('sfi') ? 'singbox' : 'base64'));
        const output = formatSubscription(store.state, subMatch.token, fmt);
        res.writeHead(200, {
          'content-type': output.contentType,
          'profile-update-interval': '12',
          'subscription-userinfo': `upload=0; download=0; total=0; expire=0`,
          'cache-control': 'no-store'
        });
        res.end(output.body);
        return;
      }
    }

    // 3. Enforce webBasePath for Panel UI & API
    const basePath = normalizeBasePath(store.state.settings.webBasePath || '/');
    if (basePath !== '/' && rawPathname === basePath && !rawPathname.endsWith('/')) {
      res.writeHead(302, { location: `${basePath}/` });
      res.end();
      return;
    }
    const pathname = stripBasePath(rawPathname, basePath);
    if (pathname === null) {
      res.writeHead(404, { 'content-type': 'text/plain; charset=utf-8' });
      res.end('404 Not Found');
      return;
    }

    // 4. Static files
    if (method === 'GET' && !pathname.startsWith('/api/')) {
      const served = await serveStatic(PUBLIC_DIR, pathname, res, basePath);
      if (served) return;
    }

    // 5. Public Auth Endpoints
    if (pathname === '/api/auth/session' && method === 'GET') {
      const session = sessions.get(req);
      if (!session) return sendJson(res, 200, { authenticated: false, basePath });
      return sendJson(res, 200, {
        authenticated: true,
        csrf: session.csrf,
        basePath,
        user: { username: store.state.admin.username }
      });
    }

    if (pathname === '/api/auth/login' && method === 'POST') {
      const ip = req.socket.remoteAddress || 'unknown';
      const record = loginAttempts.get(ip) || { count: 0, resetAt: Date.now() + 600000 };
      if (Date.now() > record.resetAt) {
        record.count = 0;
        record.resetAt = Date.now() + 600000;
      }
      if (record.count >= 12) {
        return sendError(res, 429, '登录尝试次数过多，请稍后再试', 'rate_limited');
      }
      const body = await readJson(req);
      const username = String(body.username || '').trim();
      const password = String(body.password || '');
      if (username !== store.state.admin.username || !verifySecret(password, store.state.admin.passwordHash)) {
        record.count += 1;
        loginAttempts.set(ip, record);
        return sendError(res, 401, '账号或密码不正确', 'invalid_credentials');
      }
      loginAttempts.delete(ip);
      const session = sessions.create(store.state.admin.id, store.state.admin.username);
      store.transact(() => store.addAudit(username, 'login', '控制台登录'));
      const cookieParts = [`ng_session=${encodeURIComponent(session.id)}`, 'Path=/', 'HttpOnly', 'SameSite=Lax', `Max-Age=${Math.floor(sessions.ttlMs / 1000)}`];
      return sendJson(
        res,
        200,
        { authenticated: true, csrf: session.csrf, basePath, user: { username } },
        { 'set-cookie': cookieParts.join('; ') }
      );
    }

    if (pathname === '/api/auth/logout' && method === 'POST') {
      sessions.delete(req);
      return sendJson(res, 200, { ok: true }, { 'set-cookie': 'ng_session=; Path=/; HttpOnly; Max-Age=0' });
    }

    // 6. Protected API Middleware
    const session = sessions.get(req);
    if (!session) {
      return sendError(res, 401, '登录会话已过期，请重新登录', 'unauthorized');
    }
    if (!['GET', 'HEAD'].includes(method)) {
      const csrf = req.headers['x-csrf-token'];
      if (!csrf || csrf !== session.csrf) {
        return sendError(res, 403, '安全令牌校验失败，请刷新页面重试', 'csrf_error');
      }
    }

    // 7. Overview & System Status
    if (pathname === '/api/overview' && method === 'GET') {
      const system = getSystemStatus(singbox, store.state.settings);
      const inbounds = store.state.inbounds || [];
      const outbounds = store.state.outbounds || [];
      const rules = store.state.routing?.rules || [];
      const totalClients = inbounds.reduce((acc, i) => acc + (i.clients?.length || 0), 0);
      const relayInbounds = inbounds.filter((i) => (i.outboundTag && i.outboundTag !== 'default' && i.outboundTag !== 'direct') || i.protocol === 'direct').length;
      const local3xuiExists = fs.existsSync('/etc/x-ui/x-ui.db');

      return sendJson(res, 200, {
        version: VERSION,
        system,
        local3xuiExists,
        counts: {
          inbounds: inbounds.length,
          activeInbounds: inbounds.filter((i) => i.enable !== false).length,
          clients: totalClients,
          outbounds: outbounds.filter((o) => !o.builtin).length,
          relayBindings: relayInbounds,
          rules: rules.filter((r) => r.enabled !== false).length,
          certificates: (store.state.certificates || []).length
        },
        audit: (store.state.audit || []).slice(0, 15)
      });
    }

    if (pathname === '/api/catalog' && method === 'GET') {
      return sendJson(res, 200, {
        inboundProtocols: INBOUND_PROTOCOLS,
        outboundProtocols: OUTBOUND_PROTOCOLS,
        ssMethods: SS_METHODS,
        realityPresets: REALITY_PRESETS,
        knownVersions: KNOWN_VERSIONS
      });
    }

    if (pathname === '/api/tools/reality-keypair' && method === 'POST') {
      return sendJson(res, 200, {
        ...generateRealityKeypair(),
        shortId: generateShortId()
      });
    }

    if (pathname === '/api/tools/ss-key' && method === 'POST') {
      const body = await readJson(req);
      return sendJson(res, 200, {
        password: generateSsKey(body.method || '2022-blake3-aes-128-gcm')
      });
    }

    // 8. Inbounds CRUD
    if (pathname === '/api/inbounds' && method === 'GET') {
      return sendJson(res, 200, {
        inbounds: (store.state.inbounds || []).map(enrichInboundWithLinks),
        outbounds: store.state.outbounds || [],
        certificates: store.state.certificates || []
      });
    }

    if (pathname === '/api/inbounds' && method === 'POST') {
      const body = await readJson(req);
      const inbound = normalizeInboundPayload(body);
      const portConflict = store.state.inbounds.find((x) => Number(x.port) === Number(inbound.port));
      if (portConflict) {
        return sendError(res, 400, `端口 ${inbound.port} 已被入站 [${portConflict.remark}] 占用`);
      }
      store.transact((st) => {
        st.inbounds.unshift(inbound);
        store.addAudit(session.username, 'create_inbound', `${inbound.remark} (${inbound.protocol}:${inbound.port})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 201, { inbound: enrichInboundWithLinks(inbound) });
    }

    const inbMatch = route('/api/inbounds/:id', pathname);
    if (inbMatch && method === 'PUT') {
      const body = await readJson(req);
      const existing = store.state.inbounds.find((x) => x.id === inbMatch.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      const updated = normalizeInboundPayload(body, existing);
      const portConflict = store.state.inbounds.find((x) => x.id !== existing.id && Number(x.port) === Number(updated.port));
      if (portConflict) {
        return sendError(res, 400, `端口 ${updated.port} 已被入站 [${portConflict.remark}] 占用`);
      }
      store.transact((st) => {
        const idx = st.inbounds.findIndex((x) => x.id === existing.id);
        st.inbounds[idx] = updated;
        store.addAudit(session.username, 'update_inbound', `${updated.remark} (${updated.protocol}:${updated.port})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { inbound: enrichInboundWithLinks(updated) });
    }

    if (inbMatch && method === 'DELETE') {
      const existing = store.state.inbounds.find((x) => x.id === inbMatch.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      store.transact((st) => {
        st.inbounds = st.inbounds.filter((x) => x.id !== inbMatch.id);
        store.addAudit(session.username, 'delete_inbound', `${existing.remark} (:${existing.port})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { ok: true });
    }

    const inbToggle = route('/api/inbounds/:id/toggle', pathname);
    if (inbToggle && method === 'POST') {
      const existing = store.state.inbounds.find((x) => x.id === inbToggle.id);
      if (!existing) return sendError(res, 404, '未找到该入站节点');
      store.transact(() => {
        existing.enable = !existing.enable;
        store.addAudit(session.username, 'toggle_inbound', `${existing.remark} -> ${existing.enable ? '启用' : '停用'}`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { inbound: enrichInboundWithLinks(existing) });
    }

    // 9. Outbounds & Relay CRUD
    if (pathname === '/api/outbounds' && method === 'GET') {
      return sendJson(res, 200, {
        outbounds: store.state.outbounds || [],
        inbounds: store.state.inbounds || []
      });
    }

    if (pathname === '/api/outbounds' && method === 'POST') {
      const body = await readJson(req);
      const outbound = normalizeOutboundPayload(body);
      if (store.state.outbounds.some((o) => o.tag === outbound.tag)) {
        return sendError(res, 400, `出站标识 Tag [${outbound.tag}] 已存在`);
      }
      store.transact((st) => {
        st.outbounds.push(outbound);
        store.addAudit(session.username, 'create_outbound', `${outbound.remark} (${outbound.type})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 201, { outbound });
    }

    if (pathname === '/api/outbounds/import-uri' && method === 'POST') {
      const body = await readJson(req);
      const outbound = parseShareUriToOutbound(body.uri, body.tag, body.remark);
      if (store.state.outbounds.some((o) => o.tag === outbound.tag)) {
        outbound.tag = `${outbound.tag}-${randomString(3).toLowerCase()}`;
      }
      store.transact((st) => {
        st.outbounds.push(outbound);
        store.addAudit(session.username, 'import_outbound_uri', `${outbound.remark} (${outbound.type})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 201, { outbound });
    }

    const outMatch = route('/api/outbounds/:id', pathname);
    if (outMatch && method === 'PUT') {
      const body = await readJson(req);
      const existing = store.state.outbounds.find((x) => x.id === outMatch.id);
      if (!existing) return sendError(res, 404, '未找到该出站节点');
      const updated = normalizeOutboundPayload(body, existing);
      store.transact((st) => {
        const idx = st.outbounds.findIndex((x) => x.id === existing.id);
        st.outbounds[idx] = updated;
        store.addAudit(session.username, 'update_outbound', `${updated.remark} (${updated.tag})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { outbound: updated });
    }

    if (outMatch && method === 'DELETE') {
      const existing = store.state.outbounds.find((x) => x.id === outMatch.id);
      if (!existing) return sendError(res, 404, '未找到该出站节点');
      if (existing.builtin) return sendError(res, 400, '系统内置出站 (direct / block) 不可删除');
      store.transact((st) => {
        st.outbounds = st.outbounds.filter((x) => x.id !== outMatch.id);
        for (const inb of st.inbounds) {
          if (inb.outboundTag === existing.tag) inb.outboundTag = 'default';
        }
        store.addAudit(session.username, 'delete_outbound', `${existing.remark} (${existing.tag})`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { ok: true });
    }

    // 10. Routing & Diversion (分流规则管理)
    if (pathname === '/api/routing' && method === 'GET') {
      return sendJson(res, 200, {
        routing: store.state.routing,
        dns: store.state.dns,
        inbounds: store.state.inbounds.map((i) => ({ id: i.id, tag: i.tag, remark: i.remark, port: i.port, protocol: i.protocol, outboundTag: i.outboundTag })),
        outbounds: store.state.outbounds.map((o) => ({ id: o.id, tag: o.tag, remark: o.remark, type: o.type }))
      });
    }

    if (pathname === '/api/routing' && method === 'PUT') {
      const body = await readJson(req);
      store.transact((st) => {
        if (body.final) st.routing.final = body.final;
        if (body.dnsStrategy) st.dns.strategy = body.dnsStrategy;
        store.addAudit(session.username, 'update_routing_global', `默认出站 -> ${st.routing.final}`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { routing: store.state.routing, dns: store.state.dns });
    }

    if (pathname === '/api/routing/rules' && method === 'POST') {
      const body = await readJson(req);
      const splitList = (v) => (Array.isArray(v) ? v : String(v || '').split(',').map((s) => s.trim()).filter(Boolean));
      const newRule = {
        id: `rule_${crypto.randomBytes(5).toString('hex')}`,
        remark: String(body.remark || '自定义分流规则').trim(),
        enabled: body.enabled !== false,
        action: body.action || 'route',
        inbound: splitList(body.inbound),
        domain: splitList(body.domain),
        domain_suffix: splitList(body.domain_suffix),
        domain_keyword: splitList(body.domain_keyword),
        ip_cidr: splitList(body.ip_cidr),
        source_ip_cidr: splitList(body.source_ip_cidr),
        port: splitList(body.port),
        source_port: splitList(body.source_port),
        network: String(body.network || '').toLowerCase(),
        protocol: splitList(body.protocol),
        rule_set: splitList(body.rule_set),
        ip_is_private: Boolean(body.ip_is_private),
        outbound: String(body.outbound || 'direct').trim()
      };
      store.transact((st) => {
        st.routing.rules.push(newRule);
        store.addAudit(session.username, 'create_route_rule', `${newRule.remark} -> ${newRule.outbound}`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 201, { rule: newRule });
    }

    const ruleMatch = route('/api/routing/rules/:id', pathname);
    if (ruleMatch && method === 'PUT') {
      const body = await readJson(req);
      const splitList = (v) => (Array.isArray(v) ? v : String(v || '').split(',').map((s) => s.trim()).filter(Boolean));
      const existing = store.state.routing.rules.find((r) => r.id === ruleMatch.id);
      if (!existing) return sendError(res, 404, '未找到该分流规则');
      store.transact((st) => {
        const idx = st.routing.rules.findIndex((r) => r.id === ruleMatch.id);
        st.routing.rules[idx] = {
          ...existing,
          remark: body.remark !== undefined ? String(body.remark).trim() : existing.remark,
          enabled: body.enabled !== undefined ? Boolean(body.enabled) : existing.enabled,
          inbound: body.inbound !== undefined ? splitList(body.inbound) : existing.inbound,
          domain: body.domain !== undefined ? splitList(body.domain) : existing.domain,
          domain_suffix: body.domain_suffix !== undefined ? splitList(body.domain_suffix) : existing.domain_suffix,
          domain_keyword: body.domain_keyword !== undefined ? splitList(body.domain_keyword) : existing.domain_keyword,
          ip_cidr: body.ip_cidr !== undefined ? splitList(body.ip_cidr) : existing.ip_cidr,
          source_ip_cidr: body.source_ip_cidr !== undefined ? splitList(body.source_ip_cidr) : existing.source_ip_cidr,
          port: body.port !== undefined ? splitList(body.port) : existing.port,
          source_port: body.source_port !== undefined ? splitList(body.source_port) : existing.source_port,
          network: body.network !== undefined ? String(body.network).toLowerCase() : existing.network,
          protocol: body.protocol !== undefined ? splitList(body.protocol) : existing.protocol,
          rule_set: body.rule_set !== undefined ? splitList(body.rule_set) : existing.rule_set,
          ip_is_private: body.ip_is_private !== undefined ? Boolean(body.ip_is_private) : existing.ip_is_private,
          outbound: body.outbound !== undefined ? String(body.outbound).trim() : existing.outbound
        };
        store.addAudit(session.username, 'update_route_rule', st.routing.rules[idx].remark);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { rules: store.state.routing.rules });
    }

    if (ruleMatch && method === 'DELETE') {
      store.transact((st) => {
        st.routing.rules = st.routing.rules.filter((r) => r.id !== ruleMatch.id);
        store.addAudit(session.username, 'delete_route_rule', ruleMatch.id);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { ok: true });
    }

    const ruleMove = route('/api/routing/rules/:id/move', pathname);
    if (ruleMove && method === 'POST') {
      const body = await readJson(req);
      const dir = body.direction === 'up' ? -1 : 1;
      store.transact((st) => {
        const idx = st.routing.rules.findIndex((r) => r.id === ruleMove.id);
        const targetIdx = idx + dir;
        if (idx >= 0 && targetIdx >= 0 && targetIdx < st.routing.rules.length) {
          const tmp = st.routing.rules[idx];
          st.routing.rules[idx] = st.routing.rules[targetIdx];
          st.routing.rules[targetIdx] = tmp;
        }
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { rules: store.state.routing.rules });
    }

    if (pathname === '/api/routing/presets' && method === 'POST') {
      const body = await readJson(req);
      const preset = body.preset;
      const targetOutbound = body.outbound || 'direct';
      store.transact((st) => {
        if (preset === 'block-ads') {
          st.routing.rules.push({
            id: `rule_${crypto.randomBytes(4).toString('hex')}`,
            remark: '屏蔽广告与追踪域名 (geosite-category-ads-all)',
            enabled: true,
            action: 'route',
            inbound: [],
            domain: ['geosite:category-ads-all'],
            domain_suffix: [],
            domain_keyword: ['adservice', 'pagead2'],
            ip_cidr: [],
            source_ip_cidr: [],
            port: [],
            source_port: [],
            network: '',
            protocol: [],
            rule_set: ['geosite-category-ads-all'],
            ip_is_private: false,
            outbound: 'block'
          });
        } else if (preset === 'cn-direct') {
          st.routing.rules.push({
            id: `rule_${crypto.randomBytes(4).toString('hex')}`,
            remark: '中国大陆网站与 IP 直连 (geosite:cn / geoip:cn)',
            enabled: true,
            action: 'route',
            inbound: [],
            domain: ['geosite:cn'],
            domain_suffix: ['cn'],
            domain_keyword: [],
            ip_cidr: ['geoip:cn'],
            source_ip_cidr: [],
            port: [],
            source_port: [],
            network: '',
            protocol: [],
            rule_set: ['geosite-cn', 'geoip-cn'],
            ip_is_private: false,
            outbound: 'direct'
          });
        } else if (preset === 'ai-relay') {
          st.routing.rules.push({
            id: `rule_${crypto.randomBytes(4).toString('hex')}`,
            remark: `AI 平台分流 (OpenAI/Claude/Gemini -> ${targetOutbound})`,
            enabled: true,
            action: 'route',
            inbound: [],
            domain: ['geosite:openai'],
            domain_suffix: ['openai.com', 'chatgpt.com', 'oaistatic.com', 'oaiusercontent.com', 'anthropic.com', 'claude.ai', 'gemini.google.com'],
            domain_keyword: [],
            ip_cidr: [],
            source_ip_cidr: [],
            port: [],
            source_port: [],
            network: '',
            protocol: [],
            rule_set: ['geosite-openai'],
            ip_is_private: false,
            outbound: targetOutbound
          });
        } else if (preset === 'media-relay') {
          st.routing.rules.push({
            id: `rule_${crypto.randomBytes(4).toString('hex')}`,
            remark: `流媒体解锁分流 (Netflix/Disney+/YouTube -> ${targetOutbound})`,
            enabled: true,
            action: 'route',
            inbound: [],
            domain: ['geosite:netflix'],
            domain_suffix: ['netflix.com', 'nflxvideo.net', 'nflximg.net', 'disneyplus.com', 'bamgrid.com', 'youtube.com', 'googlevideo.com'],
            domain_keyword: [],
            ip_cidr: [],
            source_ip_cidr: [],
            port: [],
            source_port: [],
            network: '',
            protocol: [],
            rule_set: ['geosite-netflix'],
            ip_is_private: false,
            outbound: targetOutbound
          });
        }
        store.addAudit(session.username, 'apply_routing_preset', preset);
      });
      autoApplyIfEnabled();
      return sendJson(res, 201, { rules: store.state.routing.rules });
    }

    // 11. 3x-ui Lossless Migration Endpoints
    if (pathname === '/api/migrate/3xui' && method === 'POST') {
      const contentType = String(req.headers['content-type'] || '');
      let parsed;
      const mode = url.searchParams.get('mode') || 'merge';
      const dryRun = url.searchParams.get('dryRun') === 'true';

      if (contentType.includes('application/octet-stream')) {
        const dbBuffer = await readBuffer(req, 64 * 1024 * 1024);
        parsed = parse3xuiPayload({ dbBuffer });
      } else {
        const body = await readJson(req);
        if (body.source === 'local') {
          const localPath = body.dbPath || '/etc/x-ui/x-ui.db';
          parsed = parse3xuiPayload({ dbPath: localPath });
        } else if (body.dbBase64) {
          const dbBuffer = Buffer.from(body.dbBase64, 'base64');
          parsed = parse3xuiPayload({ dbBuffer });
        } else if (body.jsonPayload) {
          parsed = parse3xuiPayload({ jsonPayload: typeof body.jsonPayload === 'string' ? JSON.parse(body.jsonPayload) : body.jsonPayload });
        } else {
          throw new Error('请上传 x-ui.db 文件、选择本机 /etc/x-ui/x-ui.db 或粘贴 3x-ui JSON 配置');
        }
      }

      if (dryRun) {
        return sendJson(res, 200, { preview: true, ...parsed });
      }

      const record = apply3xuiMigration(store, parsed, mode);
      store.transact(() => store.addAudit(
        session.username,
        'migrate_3xui',
        `入站 ${record.inboundsCount} 个 / 出站 ${record.outboundsCount} 个 / 规则 ${record.rulesCount} 条`
      ));
      autoApplyIfEnabled();
      return sendJson(res, 200, {
        migrated: true,
        record,
        summary: parsed.summary
      });
    }

    // 12. Sing-box Core Management & Version Switching
    if (pathname === '/api/singbox/config' && method === 'GET') {
      const config = buildSingboxConfig(store.state);
      return sendJson(res, 200, {
        status: singbox.getStatus(),
        config,
        knownVersions: KNOWN_VERSIONS
      });
    }

    if (pathname === '/api/singbox/control' && method === 'POST') {
      const body = await readJson(req);
      const action = body.action || 'restart';
      let result;
      if (action === 'stop') {
        result = singbox.stop();
      } else if (action === 'check') {
        result = singbox.checkConfig();
      } else {
        result = singbox.restart();
      }
      store.transact(() => store.addAudit(session.username, `singbox_${action}`, 'Sing-box 核心操作'));
      return sendJson(res, 200, { result, status: singbox.getStatus() });
    }

    if (pathname === '/api/singbox/logs' && method === 'GET') {
      return sendJson(res, 200, { logs: singbox.getLogs(), status: singbox.getStatus() });
    }

    if (pathname === '/api/singbox/version' && method === 'POST') {
      const body = await readJson(req);
      const ver = await singbox.installVersion(body.version || 'v1.12.23');
      store.transact(() => store.addAudit(session.username, 'switch_singbox_version', body.version));
      return sendJson(res, 200, { version: ver, status: singbox.getStatus() });
    }

    // 13. SSL Certificates Management
    if (pathname === '/api/certificates' && method === 'GET') {
      const certs = (store.state.certificates || []).map((c) => ({
        ...c,
        ...inspectCertificate(c.certPath, c.keyPath)
      }));
      return sendJson(res, 200, { certificates: certs });
    }

    if (pathname === '/api/certificates/self-signed' && method === 'POST') {
      const body = await readJson(req);
      const cert = issueSelfSignedCert({
        domain: body.domain || store.state.settings.webDomain || 'www.bing.com',
        days: Number(body.days || 3650)
      });
      store.transact((st) => {
        st.certificates = st.certificates.filter((c) => c.domain !== cert.domain);
        st.certificates.unshift(cert);
        if (body.applyToPanel) {
          st.settings.webCertFile = cert.certPath;
          st.settings.webKeyFile = cert.keyPath;
        }
        store.addAudit(session.username, 'issue_selfsigned_cert', cert.domain);
      });
      return sendJson(res, 201, { certificate: cert });
    }

    if (pathname === '/api/certificates/custom' && method === 'POST') {
      const body = await readJson(req);
      const cert = saveCustomCert({
        domain: body.domain,
        certPem: body.certPem,
        keyPem: body.keyPem,
        certPath: body.certPath,
        keyPath: body.keyPath
      });
      store.transact((st) => {
        st.certificates = st.certificates.filter((c) => c.domain !== cert.domain);
        st.certificates.unshift(cert);
        if (body.applyToPanel) {
          st.settings.webCertFile = cert.certPath;
          st.settings.webKeyFile = cert.keyPath;
        }
        store.addAudit(session.username, 'save_custom_cert', cert.domain);
      });
      return sendJson(res, 201, { certificate: cert });
    }

    if (pathname === '/api/certificates/acme' && method === 'POST') {
      const body = await readJson(req);
      const cert = issueAcmeCert({
        domain: body.domain,
        email: body.email,
        mode: body.mode || 'standalone',
        cfToken: body.cfToken || '',
        webPort: Number(body.webPort || 80)
      });
      store.transact((st) => {
        st.certificates = st.certificates.filter((c) => c.domain !== cert.domain);
        st.certificates.unshift(cert);
        if (body.applyToPanel) {
          st.settings.webCertFile = cert.certPath;
          st.settings.webKeyFile = cert.keyPath;
        }
        store.addAudit(session.username, 'issue_acme_cert', `${cert.domain} (${cert.type})`);
      });
      return sendJson(res, 201, { certificate: cert });
    }

    const certMatch = route('/api/certificates/:id', pathname);
    if (certMatch && method === 'DELETE') {
      store.transact((st) => {
        st.certificates = st.certificates.filter((c) => c.id !== certMatch.id);
        store.addAudit(session.username, 'delete_cert', certMatch.id);
      });
      return sendJson(res, 200, { ok: true });
    }

    // 14. Panel Security & Settings
    if (pathname === '/api/settings' && method === 'GET') {
      const subItems = collectSubscriptionItems(store.state, 'all');
      return sendJson(res, 200, {
        settings: store.state.settings,
        admin: { username: store.state.admin.username, updatedAt: store.state.admin.updatedAt },
        certificates: store.state.certificates || [],
        migrations: store.state.migrations || [],
        subscriptionLinksCount: subItems.length
      });
    }

    if (pathname === '/api/settings' && method === 'PUT') {
      const body = await readJson(req);
      let needServerRestart = false;
      store.transact((st) => {
        const s = st.settings;
        if (body.webListen !== undefined && body.webListen !== s.webListen) {
          s.webListen = String(body.webListen).trim() || '0.0.0.0';
          needServerRestart = true;
        }
        if (body.webPort !== undefined) {
          const p = Number(body.webPort);
          if (!Number.isInteger(p) || p < 1 || p > 65535) {
            throw new Error('面板端口必须是 1–65535 之间的整数');
          }
          if (p !== s.webPort) needServerRestart = true;
          s.webPort = p;
        }
        if (body.webBasePath !== undefined) {
          s.webBasePath = normalizeBasePath(body.webBasePath);
        }
        if (body.webDomain !== undefined) s.webDomain = String(body.webDomain).trim();
        if (body.publicIPv4 !== undefined) s.publicIPv4 = String(body.publicIPv4).trim();
        if (body.publicIPv6 !== undefined) s.publicIPv6 = String(body.publicIPv6).trim();
        if (body.webCertFile !== undefined) {
          if (body.webCertFile !== s.webCertFile) needServerRestart = true;
          s.webCertFile = String(body.webCertFile).trim();
        }
        if (body.webKeyFile !== undefined) {
          if (body.webKeyFile !== s.webKeyFile) needServerRestart = true;
          s.webKeyFile = String(body.webKeyFile).trim();
        }
        if (body.subEnable !== undefined) s.subEnable = Boolean(body.subEnable);
        if (body.subPath !== undefined) s.subPath = normalizeBasePath(body.subPath);
        if (body.singboxBin !== undefined) s.singboxBin = String(body.singboxBin).trim();
        if (body.singboxLogLevel !== undefined) s.singboxLogLevel = String(body.singboxLogLevel).trim();
        if (body.autoApplyConfig !== undefined) s.autoApplyConfig = Boolean(body.autoApplyConfig);
        if (body.sessionMaxAge !== undefined) {
          s.sessionMaxAge = Math.max(5, Number(body.sessionMaxAge || 720));
          sessions.setMaxAgeMinutes(s.sessionMaxAge);
        }
        store.addAudit(session.username, 'update_settings', `端口:${s.webPort} 路径:${s.webBasePath}`);
      });

      if (needServerRestart) {
        setTimeout(() => restartPanelServer(), 300);
      }

      return sendJson(res, 200, {
        settings: store.state.settings,
        restarting: needServerRestart
      });
    }

    if (pathname === '/api/auth/account' && method === 'POST') {
      const body = await readJson(req);
      const currentPassword = String(body.currentPassword || '');
      if (!verifySecret(currentPassword, store.state.admin.passwordHash)) {
        return sendError(res, 400, '当前登录密码验证不正确');
      }
      const nextUser = String(body.username || store.state.admin.username).trim();
      const nextPass = String(body.newPassword || '');
      if (!nextUser) return sendError(res, 400, '管理员账号不能为空');
      if (nextPass && nextPass.length < 6) return sendError(res, 400, '新密码长度至少 6 位');

      store.transact((st) => {
        st.admin.username = nextUser;
        if (nextPass) st.admin.passwordHash = hashSecret(nextPass);
        st.admin.updatedAt = new Date().toISOString();
        store.addAudit(nextUser, 'update_account', '修改面板登录凭据');
      });
      sessions.clearAll();
      return sendJson(res, 200, { ok: true, message: '账号密码已更新，请重新登录' });
    }

    // 15. Backup & Restore
    if (pathname === '/api/backup' && method === 'GET') {
      const payload = JSON.stringify(store.state, null, 2);
      res.writeHead(200, {
        'content-type': 'application/json; charset=utf-8',
        'content-disposition': `attachment; filename="nexusgate-backup-${new Date().toISOString().slice(0, 10)}.json"`
      });
      res.end(payload);
      return;
    }

    if (pathname === '/api/restore' && method === 'POST') {
      const body = await readJson(req);
      const data = body.backup || body;
      if (!data || !Array.isArray(data.inbounds) || !Array.isArray(data.outbounds)) {
        return sendError(res, 400, '备份文件结构无效');
      }
      store.transact((st) => {
        st.inbounds = data.inbounds;
        st.outbounds = data.outbounds;
        if (data.routing) st.routing = data.routing;
        if (data.dns) st.dns = data.dns;
        if (data.certificates) st.certificates = data.certificates;
        store.addAudit(session.username, 'restore_backup', `恢复 ${data.inbounds.length} 个入站`);
      });
      autoApplyIfEnabled();
      return sendJson(res, 200, { ok: true });
    }

    return sendError(res, 404, `未找到接口: ${pathname}`, 'not_found');
  } catch (error) {
    return sendError(res, error.statusCode || 500, error.message || '服务器内部错误');
  }
}

let activeServer = null;

function createPanelServer() {
  const s = store.state.settings;
  const useTls = Boolean(s.webCertFile && s.webKeyFile && fs.existsSync(s.webCertFile) && fs.existsSync(s.webKeyFile));
  if (useTls) {
    try {
      const cert = fs.readFileSync(s.webCertFile);
      const key = fs.readFileSync(s.webKeyFile);
      return { server: https.createServer({ cert, key }, handleRequest), proto: 'https' };
    } catch (err) {
      console.error('加载面板 SSL 证书失败，回退至 HTTP 模式:', err.message);
    }
  }
  return { server: http.createServer(handleRequest), proto: 'http' };
}

function startPanelServer(callback) {
  const s = store.state.settings;
  const host = s.webListen || '0.0.0.0';
  const port = Number(s.webPort || 2053);
  const basePath = normalizeBasePath(s.webBasePath || '/');
  const { server, proto } = createPanelServer();
  activeServer = server;

  server.listen(port, host, () => {
    console.log(`[NexusGate Sing-box v${VERSION}] 面板已启动: ${proto}://${host}:${port}${basePath === '/' ? '/' : `${basePath}/`}`);
    try {
      singbox.writeConfig();
      if (fs.existsSync(singbox.getBinPath())) {
        singbox.restart();
      }
    } catch (err) {
      console.warn('[NexusGate] 初始化写入 Sing-box 配置提示:', err.message);
    }
    if (callback) callback(server, proto);
  });
  return server;
}

function restartPanelServer() {
  if (!activeServer) {
    startPanelServer();
    return;
  }
  activeServer.close(() => {
    startPanelServer();
  });
}

if (require.main === module) {
  startPanelServer();
  setInterval(() => sessions.prune(), 600000).unref();
}

module.exports = {
  store,
  singbox,
  startPanelServer,
  handleRequest
};
