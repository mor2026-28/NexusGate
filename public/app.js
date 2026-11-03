'use strict';

const BASE_PATH = (window.__NG_BASE_PATH__ && window.__NG_BASE_PATH__ !== '/')
  ? window.__NG_BASE_PATH__.replace(/\/+$/, '')
  : '';

const state = {
  session: null,
  page: 'overview',
  search: '',
  protoFilter: 'all',
  overview: null,
  catalog: { inboundProtocols: [], outboundProtocols: [], ssMethods: [], realityPresets: [], knownVersions: [] },
  inbounds: [],
  outbounds: [],
  outboundPings: {},
  routing: { final: 'direct', rules: [], ruleSets: [] },
  dns: { strategy: 'prefer_ipv4' },
  certificates: [],
  defaultSettings: { defaultTlsDomain: 'www.apple.com', defaultCertFile: '', defaultKeyFile: '' },
  settings: {},
  admin: {},
  migrations: [],
  migrationPreview: null
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (v) => String(v == null ? '' : v).replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c]);
const selected = (v, cur) => String(v) === String(cur) ? ' selected' : '';

function genUuidClient() {
  if (window.crypto && typeof window.crypto.randomUUID === 'function') {
    return window.crypto.randomUUID();
  }
  return 'xxxxxxxx-xxxx-4xxx-yxxx-xxxxxxxxxxxx'.replace(/[xy]/g, (c) => {
    const r = (Math.random() * 16) | 0;
    const v = c === 'x' ? r : (r & 0x3) | 0x8;
    return v.toString(16);
  });
}

function genRandomAlnum(len = 16) {
  const chars = 'abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789';
  let out = '';
  for (let i = 0; i < len; i += 1) {
    out += chars[Math.floor(Math.random() * chars.length)];
  }
  return out;
}

function makeQrSvg(text) {
  if (typeof window.qrcode !== 'function' || !text) return '';
  try {
    const qr = window.qrcode(0, 'M');
    qr.addData(String(text), 'Byte');
    qr.make();
    return qr.createSvgTag(4, 4);
  } catch {
    return '';
  }
}

function fmtBytes(bytes) {
  let n = Number(bytes || 0);
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
  return `${n >= 10 || i === 0 ? n.toFixed(0) : n.toFixed(2)} ${units[i]}`;
}

function fmtUptime(sec) {
  const s = Math.floor(Number(sec || 0));
  const d = Math.floor(s / 86400);
  const h = Math.floor((s % 86400) / 3600);
  const m = Math.floor((s % 3600) / 60);
  if (d > 0) return `${d}天 ${h}小时 ${m}分`;
  if (h > 0) return `${h}小时 ${m}分`;
  return `${m}分 ${s % 60}秒`;
}

function fmtDate(val) {
  if (!val) return '—';
  const d = new Date(val);
  if (!Number.isFinite(d.getTime()) || d.getTime() <= 0) return '—';
  return new Intl.DateTimeFormat('zh-CN', { dateStyle: 'short', timeStyle: 'short' }).format(d);
}

function toDatetimeLocalValue(ts) {
  const n = Number(ts || 0);
  if (!Number.isFinite(n) || n <= 0) return '';
  const d = new Date(n);
  const pad = (x) => String(x).padStart(2, '0');
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}T${pad(d.getHours())}:${pad(d.getMinutes())}`;
}

function setTheme(theme) {
  const next = theme === 'dark' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('nexusgate-theme', next); } catch { /* ignore */ }
  const metaTheme = $('meta[name="theme-color"]');
  if (metaTheme) metaTheme.content = next === 'dark' ? '#0c121d' : '#f3f6fb';
  $$('[data-theme-toggle]').forEach((btn) => {
    btn.textContent = next === 'dark' ? '☾ 深色' : '☀ 浅色';
  });
}

function toast(msg, isError = false) {
  const el = document.createElement('div');
  el.className = `toast${isError ? ' error' : ''}`;
  el.textContent = msg;
  $('#toasts').append(el);
  setTimeout(() => el.remove(), 4000);
}

async function api(path, options = {}) {
  const fullPath = path.startsWith('http') ? path : `${BASE_PATH}${path}`;
  const headers = {
    ...(options.body && !(options.body instanceof ArrayBuffer) && !ArrayBuffer.isView(options.body) ? { 'content-type': 'application/json' } : {}),
    ...(options.headers || {})
  };
  if (state.session && !['GET', 'HEAD'].includes(options.method || 'GET')) {
    headers['x-csrf-token'] = state.session.csrf;
  }
  const res = await fetch(fullPath, { ...options, headers });
  const ctype = res.headers.get('content-type') || '';
  const data = ctype.includes('json') ? await res.json() : await res.text();
  if (!res.ok) {
    if (res.status === 401 && path !== '/api/auth/login') showLogin();
    throw new Error((data && data.message) || `请求失败 (${res.status})`);
  }
  return data;
}

async function copyText(text, label = '内容') {
  try {
    await navigator.clipboard.writeText(String(text));
    toast(`${label}已复制到剪贴板`);
  } catch {
    const ta = document.createElement('textarea');
    ta.value = String(text);
    document.body.append(ta);
    ta.select();
    document.execCommand('copy');
    ta.remove();
    toast(`${label}已复制到剪贴板`);
  }
}

function openModal(kicker, title, html) {
  $('#modal-kicker').textContent = kicker;
  $('#modal-title').textContent = title;
  $('#modal-body').innerHTML = html;
  const dlg = $('#modal');
  if (!dlg.open) dlg.showModal();
}

function closeModal() {
  const dlg = $('#modal');
  if (dlg.open) dlg.close();
}

function showLogin() {
  state.session = null;
  $('#app').classList.add('hidden');
  $('#login').classList.remove('hidden');
}

function showApp() {
  $('#login').classList.add('hidden');
  $('#app').classList.remove('hidden');
  $('#user-chip').textContent = `${state.session.user.username} · 管理员`;
}

function updateSidebarIndicator() {
  const sb = state.overview?.system?.singbox;
  const dot = $('#sb-dot');
  const label = $('#connection-label');
  if (!sb || !dot || !label) return;
  dot.className = 'live-dot';
  if (sb.state === 'running') {
    label.textContent = 'Sing-box 运行中';
  } else if (sb.state === 'error') {
    dot.classList.add('error');
    label.textContent = 'Sing-box 异常';
  } else {
    dot.classList.add('stopped');
    label.textContent = sb.installed ? 'Sing-box 已停止' : 'Sing-box 待安装';
  }
}

async function loadCatalogOnce() {
  if (state.catalog.inboundProtocols.length) return;
  try {
    state.catalog = await api('/api/catalog');
  } catch { /* ignore */ }
}

async function load(page = state.page) {
  try {
    await loadCatalogOnce();
    if (page === 'overview') {
      state.overview = await api('/api/overview');
      updateSidebarIndicator();
    } else if (page === 'inbounds') {
      const data = await api('/api/inbounds');
      state.inbounds = data.inbounds || [];
      state.outbounds = data.outbounds || [];
      state.certificates = data.certificates || [];
      if (data.settings) state.settings = data.settings;
      if (data.defaultSettings) state.defaultSettings = data.defaultSettings;
    } else if (page === 'routing') {
      const data = await api('/api/routing');
      state.routing = data.routing || { final: 'direct', rules: [] };
      state.dns = data.dns || { strategy: 'prefer_ipv4' };
      state.inbounds = data.inbounds || [];
      state.outbounds = data.outbounds || [];
    } else if (page === 'outbounds') {
      const data = await api('/api/outbounds');
      state.outbounds = data.outbounds || [];
      state.inbounds = data.inbounds || [];
      if (data.routing) state.routing = data.routing;
    } else if (page === 'migrate') {
      const [ov, st] = await Promise.all([api('/api/overview'), api('/api/settings')]);
      state.overview = ov;
      state.settings = st.settings || state.settings;
      state.migrations = st.migrations || [];
    } else if (page === 'certificates') {
      const [certs, st, inbData] = await Promise.all([api('/api/certificates'), api('/api/settings'), api('/api/inbounds')]);
      state.certificates = certs.certificates || [];
      state.settings = st.settings || {};
      state.inbounds = inbData.inbounds || [];
    } else if (page === 'settings') {
      const [st, certs] = await Promise.all([api('/api/settings'), api('/api/certificates')]);
      state.settings = st.settings || {};
      state.admin = st.admin || {};
      state.certificates = certs.certificates || [];
    }
    render();
  } catch (err) {
    toast(err.message, true);
  }
}

function setPage(page) {
  state.page = page;
  state.search = '';
  $('#app').classList.remove('sidebar-open');
  $$('#nav button').forEach((b) => b.classList.toggle('active', b.dataset.page === page));
  const titles = {
    overview: '系统与内核总览',
    inbounds: '入站节点管理',
    routing: '路由规则 (转发)',
    outbounds: '出站规则 (中转)',
    migrate: '备份迁移',
    certificates: 'SSL 证书与订阅',
    settings: '面板设置与安全'
  };
  $('#page-title').textContent = titles[page] || '控制台';
  $('#breadcrumb').textContent = `NexusGate · 枢门 / ${titles[page] || ''}`;
  load(page);
}

function getBaseSubscriptionUrl(subToken = '') {
  const s = state.settings || {};
  const token = (subToken && subToken !== 'all') ? subToken : (s.subToken || '');
  const proto = window.location.protocol;
  const host = s.webDomain || window.location.hostname || s.publicIPv4 || '127.0.0.1';
  const portPart = window.location.port ? `:${window.location.port}` : (s.webPort ? `:${s.webPort}` : '');
  const subPath = (s.subPath || '/sub/').replace(/\/+$/, '');
  return `${proto}//${host}${portPart}${subPath}/${encodeURIComponent(token)}`;
}

/* ==================== RENDER PAGES ==================== */

function renderOverview() {
  const ov = state.overview || {};
  const counts = ov.counts || {};
  const sys = ov.system || {};
  const cpuPct = sys.cpu?.percent || 0;
  const memTotal = sys.mem?.total || 1;
  const memUsed = sys.mem?.used || 0;
  const memPct = Math.min(100, Math.round((memUsed / memTotal) * 100));
  const swapTotal = sys.swap?.total || 0;
  const swapUsed = sys.swap?.used || 0;
  const swapPct = swapTotal > 0 ? Math.min(100, Math.round((swapUsed / swapTotal) * 100)) : 0;
  const diskTotal = sys.disk?.total || 1;
  const diskUsed = sys.disk?.used || 0;
  const diskPct = sys.disk?.total ? Math.min(100, Math.round((diskUsed / diskTotal) * 100)) : 0;
  const sb = sys.singbox || { state: 'stop', version: '未安装' };
  const accel = sys.acceleration || {};

  const metrics = [
    ['入站节点总数', counts.inbounds || 0, `${counts.activeInbounds || 0} 个节点运行中`, '#2b6ee8'],
    ['活跃客户端', counts.clients || 0, '支持独立 IP 与设备数限制', '#129668'],
    ['路由转发规则', counts.rules || 0, `${counts.relayBindings || 0} 条入站直绑中转`, '#d97706'],
    ['中转出站节点', counts.outbounds || 0, '支持多协议落地与链式中转', '#7c3aed'],
    ['SSL 证书管理', counts.certificates || 0, '自动优先绑定已申请域名证书', '#d44458']
  ];

  const barClass = (pct) => (pct >= 88 ? 'crit' : pct >= 70 ? 'warn' : '');
  const versionOptions = (state.catalog.knownVersions || ['v1.12.23', 'v1.12.15', 'v1.12.0', 'v1.11.15'])
    .map((v) => `<option value="${esc(v)}">${esc(v)}</option>`)
    .join('');

  const auditHtml = (ov.audit || []).slice(0, 8).map((a) => `
    <div class="health-row">
      <div><b>${esc(a.action)}</b><span>${esc(a.actor)} · ${esc(a.target)}</span></div>
      <small>${fmtDate(a.at)}</small>
    </div>
  `).join('');

  return `
    ${ov.local3xuiExists ? `
      <div class="notice" style="margin-bottom:14px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
        <div><b>检测到本机存在可迁移备份数据 (/etc/x-ui/x-ui.db 或 /root/3xui_backup.tar.gz)</b> · 可一键备份迁移全部入站节点、客户端凭据、路由转发、中转出站与 SSL 证书，不影响现有客户连接。</div>
        <button class="primary" data-action="jump-migrate">前往备份迁移 →</button>
      </div>
    ` : ''}

    <section class="metrics">
      ${metrics.map(([label, val, note, color]) => `
        <article class="metric" style="--accent:${color}">
          <span>${esc(label)}</span>
          <strong>${esc(val)}</strong>
          <small>${esc(note)}</small>
        </article>
      `).join('')}
    </section>

    <section class="grid-2">
      <article class="panel">
        <div class="panel-head">
          <div>
            <h2>系统实时状态监控</h2>
            <p>${esc(sys.hostname || 'Server')} · ${esc(sys.platform || '')} · 面板内存占用 ${fmtBytes(sys.panelMemoryBytes || 0)}</p>
          </div>
          <span class="tag">运行 ${fmtUptime(sys.uptime)}</span>
        </div>
        <div class="panel-body">
          <div class="gauge-grid">
            <div class="gauge-card">
              <div class="gauge-head"><b>CPU 负载 (${sys.cpu?.cores || 1} 核)</b><strong>${cpuPct}%</strong></div>
              <div class="gauge-bar"><i class="${barClass(cpuPct)}" style="width:${cpuPct}%"></i></div>
              <div class="gauge-sub"><span>负载: ${(sys.loads || [0, 0, 0]).join(' / ')}</span><span>${esc((sys.cpu?.model || '').slice(0, 26))}</span></div>
            </div>
            <div class="gauge-card">
              <div class="gauge-head"><b>物理内存 (RAM)</b><strong>${memPct}%</strong></div>
              <div class="gauge-bar"><i class="${barClass(memPct)}" style="width:${memPct}%"></i></div>
              <div class="gauge-sub"><span>已用 ${fmtBytes(memUsed)}</span><span>总计 ${fmtBytes(memTotal)}</span></div>
            </div>
            <div class="gauge-card">
              <div class="gauge-head"><b>系统硬盘 (Disk)</b><strong>${diskPct}%</strong></div>
              <div class="gauge-bar"><i class="${barClass(diskPct)}" style="width:${diskPct}%"></i></div>
              <div class="gauge-sub"><span>已用 ${fmtBytes(diskUsed)}</span><span>总计 ${fmtBytes(diskTotal)}</span></div>
            </div>
            <div class="gauge-card">
              <div class="gauge-head"><b>交换分区 (Swap)</b><strong>${swapPct}%</strong></div>
              <div class="gauge-bar"><i class="${barClass(swapPct)}" style="width:${swapPct}%"></i></div>
              <div class="gauge-sub"><span>已用 ${fmtBytes(swapUsed)}</span><span>总计 ${fmtBytes(swapTotal)}</span></div>
            </div>
          </div>

          <div class="net-stat-grid">
            <div class="net-stat-box">
              <span>实时上下行速率</span>
              <strong>↑ ${fmtBytes(sys.netIO?.up || 0)}/s · ↓ ${fmtBytes(sys.netIO?.down || 0)}/s</strong>
            </div>
            <div class="net-stat-box">
              <span>网卡累计总流量</span>
              <strong>↑ ${fmtBytes(sys.netTraffic?.sent || 0)} · ↓ ${fmtBytes(sys.netTraffic?.recv || 0)}</strong>
            </div>
            <div class="net-stat-box">
              <span>活跃连接数 (实时)</span>
              <strong>TCP ${sys.tcpCount || 0} · UDP ${sys.udpCount || 0}</strong>
            </div>
          </div>

          <div style="margin-top:12px;padding-top:12px;border-top:1px solid var(--line);display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:8px">
            <div style="font-size:12px;display:flex;align-items:center;flex-wrap:wrap;gap:4px">
              <b>内核加速状态:</b>
              <span class="tag ${accel.bbrEnabled ? 'tls' : ''}">TCP: ${esc(accel.congestion || 'cubic')} + ${esc(accel.qdisc || 'fq')}</span>
              <span class="tag ${accel.hy2Tuned ? 'tls' : ''}">HY2 缓冲: ${fmtBytes(accel.rmemMax || 0)}</span>
            </div>
            <div style="display:flex;flex-wrap:wrap;gap:6px">
              <button class="primary" data-action="enable-bbr-hy2">🚀 开启 BBR+FQ+HY2</button>
              <button data-action="open-firewall-ports">🛡 放行所有端口</button>
              <button data-action="cleanup-system-memory">🧹 清理日志与释放内存</button>
            </div>
          </div>
        </div>
      </article>

      <article class="panel">
        <div class="panel-head">
          <div>
            <h2>Sing-box 核心管理与版本切换</h2>
            <p>二进制路径: ${esc(sb.binary || '/usr/local/bin/sing-box')}</p>
          </div>
          <span class="status ${sb.state === 'running' ? 'running' : (sb.state === 'error' ? 'error' : 'warning')}">
            ${sb.state === 'running' ? '运行中' : (sb.state === 'error' ? '配置或进程异常' : '已停止 / 待启动')}
          </span>
        </div>
        <div class="panel-body stack">
          <div class="health-row" style="padding-top:0">
            <div>
              <b>当前 Sing-box 内核版本</b>
              <span>配置文件: ${esc(sb.configPath || '/etc/nexusgate/sing-box/config.json')}</span>
            </div>
            <span class="tag">${esc(sb.version || '未安装')}</span>
          </div>

          ${sb.lastError
            ? `<div class="notice warning">内核诊断信息: ${esc(sb.lastError)}</div>`
            : `<div class="notice" style="background:var(--success-soft);border-color:color-mix(in srgb,var(--success) 28%,var(--line));color:var(--success)">✓ Sing-box 配置校验通过（0 警告 0 错误），入站、路由转发与中转出站均已正常加载</div>`}

          <div style="display:flex;flex-wrap:wrap;gap:7px">
            <button class="primary" data-action="sb-control" data-cmd="restart">↻ 启动 / 重启内核</button>
            <button data-action="sb-control" data-cmd="stop">■ 停止内核</button>
            <button data-action="sb-control" data-cmd="check">✓ 校验配置</button>
            <button data-action="sb-logs">📋 查看运行日志</button>
            <button data-action="sb-config-preview">｛｝ 预览配置</button>
          </div>

          <div style="padding-top:10px;border-top:1px solid var(--line)">
            <label>
              <span>更换 / 升级 Sing-box 内核版本 (官方 Release 自动匹配架构下载)</span>
              <div class="input-row" style="margin-top:4px">
                <select id="sb-version-select" style="max-width:155px">
                  ${versionOptions}
                </select>
                <input id="sb-version-custom" placeholder="或手动输入版本号，如 v1.12.23">
                <button class="primary" data-action="sb-switch-version">一键切换版本</button>
              </div>
              <small>支持随时升级或回退 Sing-box 内核版本，切换后自动校验配置并平滑重启服务。</small>
            </label>
          </div>
        </div>
      </article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><h2>最近操作审计日志</h2><p>记录面板登录、节点变更、内核加速、路由转发与备份迁移事件</p></div>
        <div style="display:flex;gap:8px">
          <button class="primary" data-action="quick-add-inbound">＋ 添加入站节点</button>
          <button class="ghost" data-action="Switch-to-routing">◇ 路由转发管理</button>
        </div>
      </div>
      <div class="panel-body">
        ${auditHtml || '<div class="empty"><b>暂无操作记录</b><span>创建节点或导入配置后将在此显示</span></div>'}
      </div>
    </section>
  `;
}

function renderInbounds() {
  const q = state.search.toLowerCase();
  const pf = state.protoFilter || 'all';

  const filtered = state.inbounds.filter((item) => {
    if (pf !== 'all') {
      if (pf === 'relay') {
        const hasRelay = (item.outboundTag && item.outboundTag !== 'default' && item.outboundTag !== 'direct') || item.protocol === 'direct';
        if (!hasRelay) return false;
      } else if (pf === 'socks') {
        if (!['socks', 'mixed', 'http'].includes(item.protocol)) return false;
      } else if (item.protocol !== pf) {
        return false;
      }
    }
    if (!q) return true;
    return [item.remark, item.tag, item.protocol, item.port, item.outboundTag].join(' ').toLowerCase().includes(q);
  });

  const subAllUrl = getBaseSubscriptionUrl();
  const totalUp = state.inbounds.reduce((acc, i) => acc + Number(i.up || 0), 0);
  const totalDown = state.inbounds.reduce((acc, i) => acc + Number(i.down || 0), 0);
  const activeCount = state.inbounds.filter((i) => i.enable !== false).length;
  const totalClients = state.inbounds.reduce((acc, i) => acc + (i.clients?.length || 0), 0);
  const defaultDomain = state.defaultSettings?.defaultTlsDomain || state.settings?.webDomain || 'www.apple.com';

  const filterDefs = [
    ['all', `全部 (${state.inbounds.length})`],
    ['vless', 'VLESS'],
    ['anytls', 'AnyTLS'],
    ['hysteria2', 'HY2'],
    ['shadowsocks', 'SS / SS2022'],
    ['socks', 'SOCKS / Mixed'],
    ['direct', 'Direct 转发'],
    ['relay', '已绑中转']
  ];

  const rows = filtered.map((item, idx) => {
    const protoBadge = item.protocol.toUpperCase();
    const secBadge = item.security && item.security !== 'none' ? `<span class="tag tls">${esc(item.security.toUpperCase())}</span>` : '';
    const netBadge = item.transport && item.transport !== 'tcp' ? `<span class="tag">${esc(item.transport.toUpperCase())}</span>` : '';
    const methodBadge = item.protocol === 'shadowsocks' ? `<small>${esc(item.method)}</small>` : '';
    const sniNote = item.security === 'reality' && item.reality?.serverName
      ? `<small>SNI: ${esc(item.reality.serverName)}</small>`
      : (item.security === 'tls' && item.tlsDomain ? `<small>TLS: ${esc(item.tlsDomain)}</small>` : '');
    const directNote = item.protocol === 'direct'
      ? `<small>转发目标: ${esc(item.overrideAddress || '未设')}:${esc(item.overridePort || 0)} (${esc(item.network || 'tcp,udp')})</small>`
      : '';

    let relayHtml = '<span class="tag">默认路由</span>';
    if (item.outboundTag && item.outboundTag !== 'default') {
      if (item.outboundTag === 'direct') {
        relayHtml = '<span class="tag tls">direct (直连)</span>';
      } else if (item.outboundTag === 'block') {
        relayHtml = '<span class="status disabled">block (拦截)</span>';
      } else {
        const targetOut = state.outbounds.find((o) => o.tag === item.outboundTag);
        relayHtml = `<span class="tag relay">⇄ ${esc(targetOut ? `${targetOut.tag} (${targetOut.server}:${targetOut.port})` : item.outboundTag)}</span>`;
      }
    }

    const limitIp = Number(item.limitIp || 0);
    const limitDevice = Number(item.limitDevice || 0);
    const activeIpCount = Number(item.activeIpCount || 0);
    const activeDevCount = Number(item.activeDeviceCount || 0);
    const totalQuota = item.total > 0 ? ` / ${fmtBytes(item.total)}` : '';
    const effResetDay = Number(item.resetDay || state.settings?.trafficResetDay || 0);
    const resetBadge = effResetDay > 0 ? `<span class="tag" style="margin-left:4px">↻ 每月${effResetDay}号清零</span>` : '';
    const onlineBadge = (activeDevCount > 0 || activeIpCount > 0)
      ? `<span class="tag tls" style="margin-left:4px" title="当前在线客户端 IP: ${esc((item.activeIps || []).join(', '))}">● 在线 ${activeDevCount} 设备</span>`
      : '';

    let expiryHtml = '<small class="muted">到期: 永久有效 · ';
    if (item.expiryTime && item.expiryTime > 0) {
      const diffMs = item.expiryTime - Date.now();
      if (diffMs <= 0) {
        expiryHtml = `<small style="color:var(--danger);font-weight:700">⚠ 已到期 (${fmtDate(item.expiryTime)}) · `;
      } else {
        const daysLeft = Math.ceil(diffMs / 86400000);
        expiryHtml = `<small style="color:var(--primary)">⏱ 到期: ${fmtDate(item.expiryTime)} (剩${daysLeft}天) · `;
      }
    }
    const ipStyle = activeIpCount > 0 ? 'color:var(--success);font-weight:800' : '';
    const devStyle = activeDevCount > 0 ? 'color:var(--success);font-weight:800' : '';
    const limitText = `${expiryHtml}IP: <b style="${ipStyle}">${activeIpCount}</b>/${limitIp > 0 ? limitIp : '∞'} · 设备: <b style="${devStyle}">${activeDevCount}</b>/${limitDevice > 0 ? limitDevice : '∞'}</small>`;

    return `
      <tr>
        <td><strong>${idx + 1}</strong></td>
        <td>
          <strong>${esc(item.remark)}</strong>
          <small>Tag: <code>${esc(item.tag)}</code> · 监听: ${esc(item.listen || '::')}</small>
          ${directNote}
        </td>
        <td>
          <div><span class="tag">${esc(protoBadge)}</span>${secBadge}${netBadge}</div>
          ${methodBadge}${sniNote}
        </td>
        <td><strong>:${esc(item.port)}</strong></td>
        <td>${relayHtml}</td>
        <td>
          <div><span class="status valid">↑ ${fmtBytes(item.up)} / ↓ ${fmtBytes(item.down)}${esc(totalQuota)}</span>${onlineBadge}${resetBadge}</div>
          ${limitText}
        </td>
        <td>
          <span class="status ${item.enable !== false ? 'active' : 'disabled'}">
            ${item.enable !== false ? '已启用' : (item.disabledReason === 'expired' ? '已到期停用' : (item.disabledReason === 'quota' ? '流量耗尽' : '已停用'))}
          </span>
        </td>
        <td>
          <div class="actions">
            ${item.protocol !== 'direct' ? `<button class="primary" data-action="inbound-links" data-id="${esc(item.id)}">链接 / 订阅</button>` : ''}
            <button data-action="edit-inbound" data-id="${esc(item.id)}">编辑</button>
            <button data-action="reset-inbound-traffic" data-id="${esc(item.id)}" title="重置该节点流量">清零</button>
            <button data-action="toggle-inbound" data-id="${esc(item.id)}">${item.enable !== false ? '停用' : '启用'}</button>
            <button class="danger" data-action="delete-inbound" data-id="${esc(item.id)}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="stat-strip">
      <div class="stat-strip-item">
        <span>总上传 / 下载</span>
        <strong>↑ ${fmtBytes(totalUp)} / ↓ ${fmtBytes(totalDown)}</strong>
      </div>
      <div class="stat-strip-item">
        <span>总流量累计</span>
        <strong>${fmtBytes(totalUp + totalDown)}</strong>
      </div>
      <div class="stat-strip-item">
        <span>入站节点数量</span>
        <strong>${activeCount} 启用 / 共 ${state.inbounds.length} 个</strong>
      </div>
      <div class="stat-strip-item">
        <span>客户端与默认证书域名</span>
        <strong>${totalClients} 个客户端 · ${esc(defaultDomain)}</strong>
      </div>
    </div>

    <div class="action-bar">
      <div class="action-bar-left">
        <button class="primary" data-action="add-inbound">＋ 添加入站</button>
        <button class="primary" data-action="open-aggregate-qr-modal">📱 全节点聚合订阅与二维码</button>
        <button data-copy="${esc(subAllUrl)}">🔗 复制通用订阅</button>
        <button data-copy="${esc(`${subAllUrl}?format=clash`)}">⚡ 复制 Clash 订阅</button>
        <button data-action="copy-all-links">📋 复制全部节点链接</button>
        <button data-action="batch-inbounds" data-batch="enable-all">✓ 批量启用</button>
        <button data-action="batch-inbounds" data-batch="reset-all-traffic">↻ 批量重置流量</button>
      </div>
    </div>

    <div class="quick-bar">
      <span>⚡ 快捷添加:</span>
      <button data-action="quick-inbound" data-preset="vless-reality">VLESS + Reality</button>
      <button data-action="quick-inbound" data-preset="anytls">AnyTLS</button>
      <button data-action="quick-inbound" data-preset="hysteria2">Hysteria 2 (HY2)</button>
      <button data-action="quick-inbound" data-preset="ss2022-128">SS 2022 · 128-GCM</button>
      <button data-action="quick-inbound" data-preset="ss2022-256">SS 2022 · 256-GCM</button>
      <button data-action="quick-inbound" data-preset="ss-128">SS · AES-128-GCM</button>
      <button data-action="quick-inbound" data-preset="socks">SOCKS5</button>
      <button data-action="quick-inbound" data-preset="direct">Direct 端口转发</button>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div class="toolbar">
          <div class="toolbar-left">
            <input class="search" data-search placeholder="搜索备注、Tag、协议、端口或目标出站..." value="${esc(state.search)}">
            <div class="filter-pills">
              ${filterDefs.map(([id, label]) => `<button type="button" class="filter-pill${pf === id ? ' active' : ''}" data-action="filter-proto" data-proto="${id}">${esc(label)}</button>`).join('')}
            </div>
          </div>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="width:48px">#</th>
              <th>备注 / 标签 (Tag)</th>
              <th>协议与传输</th>
              <th>端口</th>
              <th>转发目标出站</th>
              <th>流量 / 到期 / IP与设备限制</th>
              <th>状态</th>
              <th style="text-align:right">操作</th>
            </tr>
          </thead>
          <tbody>
            ${rows || '<tr><td colspan="8"><div class="empty"><b>还没有入站节点</b><span>点击左上方“＋ 添加入站”或“⚡ 快捷添加”即可快速创建节点</span></div></td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function renderRouting() {
  const rules = (state.routing.rules || []).filter((r) => r.action !== 'sniff');
  const outboundOpts = state.outbounds
    .map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, state.routing.final)}>${esc(o.tag)}${o.server ? ` (${o.server}:${o.port})` : ''}</option>`)
    .join('');

  const quickInboundOpts = state.inbounds
    .map((i) => `<option value="${esc(i.tag)}">${esc(i.tag)} (${esc(i.remark)} :${i.port})</option>`)
    .join('');
  const quickOutboundOpts = state.outbounds
    .filter((o) => o.tag !== 'block')
    .map((o) => `<option value="${esc(o.tag)}">${esc(o.tag)}${o.server ? ` (${o.server}:${o.port})` : ` (${o.remark})`}</option>`)
    .join('');

  const rows = rules.map((r, idx) => {
    const srcIp = (r.source_ip_cidr || []).join(', ');
    const srcPort = (r.source_port || []).join(', ');
    const l4 = r.network ? r.network.toUpperCase() : '';
    const proto = (r.protocol || []).join(', ');
    const dstIp = [
      ...(r.ip_is_private ? ['geoip:private'] : []),
      ...(r.ip_cidr || []),
      ...(r.rule_set || []).filter((x) => x.startsWith('geoip-'))
    ].join(', ');
    const dstDomain = [
      ...(r.domain || []),
      ...(r.domain_suffix || []),
      ...(r.domain_keyword || []).map((k) => `keyword:${k}`),
      ...(r.rule_set || []).filter((x) => x.startsWith('geosite-'))
    ].join(', ');
    const dstPort = (r.port || []).join(', ');
    const inbTags = (r.inbound || []).join(', ');
    const users = (r.user || r.auth_user || []).join(', ');
    const outTag = r.outbound || 'direct';

    const outBadgeClass = outTag === 'block' ? 'status disabled' : (outTag === 'direct' ? 'tag tls' : 'tag relay');

    return `
      <tr>
        <td><strong>⇅ ${idx + 1}</strong></td>
        <td><small>${esc(srcIp)}</small></td>
        <td><small>${esc(srcPort)}</small></td>
        <td><small>${esc(l4)}</small></td>
        <td><small>${esc(proto)}</small></td>
        <td><small>${esc(dstIp)}</small></td>
        <td>
          ${r.remark ? `<small style="font-weight:650;color:var(--text)">${esc(r.remark)}</small>` : ''}
          <small>${esc(dstDomain.length > 90 ? `${dstDomain.slice(0, 90)}...` : dstDomain)}</small>
        </td>
        <td><small>${esc(dstPort)}</small></td>
        <td><strong>${esc(inbTags)}</strong></td>
        <td><small>${esc(users)}</small></td>
        <td><span class="${outBadgeClass}">${esc(outTag)}</span></td>
        <td>
          <div class="actions">
            <button data-action="move-rule" data-id="${esc(r.id)}" data-dir="up" title="向上移动">↑</button>
            <button data-action="move-rule" data-id="${esc(r.id)}" data-dir="down" title="向下移动">↓</button>
            <button data-action="move-rule" data-id="${esc(r.id)}" data-dir="top" title="置顶">⤒</button>
            <button data-action="move-rule" data-id="${esc(r.id)}" data-dir="bottom" title="置底">⤓</button>
            <button data-action="edit-rule" data-id="${esc(r.id)}">编辑</button>
            <button class="danger" data-action="delete-rule" data-id="${esc(r.id)}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="action-bar">
      <div class="action-bar-left">
        <button class="primary" data-action="add-rule">＋ 添加路由规则</button>
        <button data-action="routing-preset" data-preset="3xui-default" title="仅保留入站中转 + 禁止私有IP + 禁止BT下载">🛡 恢复默认防探测/禁BT规则</button>
        <button data-action="routing-preset" data-preset="ai-relay">🤖 AI 专线分流</button>
        <button data-action="routing-preset" data-preset="foreign-trade">🌍 外贸跨境分流</button>
        <button data-action="routing-preset" data-preset="media-relay">🎬 流媒体分流</button>
        <button data-action="routing-preset" data-preset="block-ads">⛔ 屏蔽广告域名</button>
        <button data-action="Switch-to-outbounds">⇄ 管理出站规则 (${state.outbounds.filter((o) => !o.builtin).length})</button>
      </div>
      <div class="action-bar-right">
        <span class="muted" style="font-size:12px;font-weight:700">默认兜底出站:</span>
        <select id="routing-final-select" style="width:165px;min-height:34px;padding:4px 8px">${outboundOpts}</select>
        <button data-action="save-routing-global">保存兜底</button>
      </div>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div>
          <h2>快速添加入站 ➔ 出站一对一转发规则</h2>
          <p>选择本机入站节点标签并指定转发至目标出站节点，点击右侧按钮即可一键绑定生效</p>
        </div>
      </div>
      <div class="panel-body">
        <div class="form-grid" style="grid-template-columns:1fr 1fr auto;align-items:end">
          <label>
            选择入站标签 (Inbound Tag)
            <select id="quick-relay-inbound">
              ${quickInboundOpts || '<option value="">— 请先在【入站节点管理】创建入站 —</option>'}
            </select>
          </label>
          <label>
            转发至目标出站 (Outbound Tag)
            <select id="quick-relay-outbound">
              ${quickOutboundOpts}
            </select>
          </label>
          <button class="primary" data-action="quick-add-relay-rule" style="height:38px">＋ 立即绑定转发规则</button>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><h2>路由规则列表 (共 ${rules.length} 条)</h2><p>按从上往下顺序匹配，入站与出站绑定支持双向自动同步</p></div>
      </div>
      <div class="table-wrap">
        <table class="xui-routing-table">
          <thead>
            <tr>
              <th rowspan="2" style="width:65px">#</th>
              <th colspan="2" style="text-align:center;border-bottom:1px solid var(--line)">来源</th>
              <th colspan="2" style="text-align:center;border-bottom:1px solid var(--line)">网络</th>
              <th colspan="3" style="text-align:center;border-bottom:1px solid var(--line)">目标地址</th>
              <th colspan="2" style="text-align:center;border-bottom:1px solid var(--line)">入站</th>
              <th rowspan="2">出站</th>
              <th rowspan="2" style="text-align:right">操作</th>
            </tr>
            <tr>
              <th>IP</th>
              <th>端口</th>
              <th>L4</th>
              <th>协议</th>
              <th>IP</th>
              <th>域名 / 备注</th>
              <th>端口</th>
              <th>标签 (Tag)</th>
              <th>客户/用户</th>
            </tr>
          </thead>
          <tbody>
            ${rows || '<tr><td colspan="12"><div class="empty"><b>暂无路由规则</b><span>点击左上方“＋ 添加路由规则”或使用上方快速绑定功能</span></div></td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function renderOutbounds() {
  const q = state.search.toLowerCase();
  const filtered = state.outbounds.filter((item) =>
    [item.remark, item.tag, item.type, item.server, item.port].join(' ').toLowerCase().includes(q)
  );

  const rows = filtered.map((item, idx) => {
    const protoLabel = item.type === 'direct' ? 'freedom' : (item.type === 'block' ? 'blackhole' : item.type);
    const netPill = !item.builtin ? `<span class="tag tls">${esc(item.transport || 'tcp')}</span>` : '';
    const detourPill = item.detour ? `<span class="tag relay">前置: ${esc(item.detour)}</span>` : '';
    const addrText = item.builtin
      ? '系统内置出站'
      : (['urltest', 'selector'].includes(item.type)
          ? (item.outbounds || []).join(', ')
          : `${item.server || '—'}:${item.port || '—'}`);

    const boundInbounds = (state.inbounds || []).filter((i) => i.outboundTag === item.tag);
    const boundHtml = boundInbounds.length > 0
      ? boundInbounds.map((i) => `<span class="tag">${esc(i.tag)} (:${i.port})</span>`).join('')
      : '<small class="muted">—</small>';

    const pingInfo = state.outboundPings[item.id];
    const pingBadge = pingInfo
      ? (pingInfo.reachable
          ? `<span class="status valid" style="margin-left:6px">${pingInfo.latencyMs} ms</span>`
          : `<span class="status error" style="margin-left:6px" title="${esc(pingInfo.error)}">超时</span>`)
      : '';

    const upBytes = Number(item.up || 0);
    const downBytes = Number(item.down || 0);
    const trafficText = `↑ ${fmtBytes(upBytes)} / ↓ ${fmtBytes(downBytes)}`;

    return `
      <tr>
        <td><strong>${idx + 1}</strong></td>
        <td>
          <strong>${esc(item.tag)}</strong>
          ${item.remark && item.remark !== item.tag ? `<small>${esc(item.remark)}</small>` : ''}
        </td>
        <td>
          <span class="tag relay">${esc(protoLabel)}</span>
          ${netPill}${detourPill}
        </td>
        <td>
          <strong>${esc(addrText)}</strong>${pingBadge}
        </td>
        <td>${boundHtml}</td>
        <td>
          <span class="status valid">${esc(trafficText)}</span>
        </td>
        <td>
          <div class="actions">
            ${item.builtin ? `
              <button data-action="reset-outbound-traffic" data-id="${esc(item.id)}">重置流量</button>
            ` : `
              <button data-action="edit-outbound" data-id="${esc(item.id)}">编辑</button>
              <button data-action="reset-outbound-traffic" data-id="${esc(item.id)}">重置流量</button>
              ${item.server ? `<button data-action="ping-outbound" data-id="${esc(item.id)}">⚡ 测速</button>` : ''}
              <button class="danger" data-action="delete-outbound" data-id="${esc(item.id)}">删除</button>
            `}
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="action-bar">
      <div class="action-bar-left">
        <button class="primary" data-action="add-outbound">＋ 添加出站</button>
        <button data-action="import-outbound-uri">🔗 批量粘贴链接导入出站</button>
        <button data-action="ping-all-outbounds">⚡ 批量检测全部出站延迟</button>
        <button data-action="Switch-to-routing">◇ 前往路由规则绑定</button>
      </div>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div class="toolbar">
          <div class="toolbar-left">
            <input class="search" data-search placeholder="搜索出站标签、协议或服务器地址..." value="${esc(state.search)}">
            <span class="tag">共 ${state.outbounds.length} 个出站 (${state.outbounds.filter((o) => !o.builtin).length} 个自定义落地)</span>
          </div>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th style="width:52px">#</th>
              <th>标签 (Tag)</th>
              <th>协议 (Protocol)</th>
              <th>落地地址 (Address)</th>
              <th>已绑定入站</th>
              <th>流量 (上行 / 下行)</th>
              <th style="text-align:right">操作</th>
            </tr>
          </thead>
          <tbody>
            ${rows}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function renderMigrate() {
  const preview = state.migrationPreview;
  const previewHtml = preview ? `
    <article class="panel" style="border-color:var(--primary)">
      <div class="panel-head">
        <div>
          <h2>备份数据解析预览结果</h2>
          <p>解析成功！共识别到 ${preview.summary.inboundsCount} 个入站 (${preview.summary.clientsCount} 个客户端)、${preview.summary.outboundsCount} 个自定义中转出站、${preview.summary.rulesCount} 条分流规则${preview.summary.restoredCertsCount ? `、${preview.summary.restoredCertsCount} 张 SSL 域名证书 (${(preview.summary.restoredCertDomains || []).join(', ')})` : ''}${preview.summary.acmeRestored ? ' (含 .acme.sh 自动续签配置)' : ''}</p>
        </div>
        <span class="status valid">可完整迁移恢复</span>
      </div>
      <div class="panel-body stack">
        <div class="codebox" style="max-height:220px">${esc(JSON.stringify({
          summary: preview.summary,
          inboundsPreview: preview.inbounds.map((i) => ({ tag: i.tag, remark: i.remark, protocol: i.protocol, port: i.port, security: i.security, transport: i.transport, outboundTag: i.outboundTag, clientsCount: i.clients?.length || 0 })),
          outboundsPreview: preview.outbounds.map((o) => ({ tag: o.tag, type: o.type, server: o.server, port: o.port })),
          rulesCount: preview.rules.length
        }, null, 2))}</div>
      </div>
    </article>
  ` : '';

  const historyRows = (state.migrations || []).map((m) => `
    <tr>
      <td><strong>${fmtDate(m.at)}</strong></td>
      <td><span class="tag">${m.mode === 'replace' ? '覆盖替换' : '智能合并'}</span></td>
      <td>${m.inboundsCount || 0} 个入站 (${m.clientsCount || 0} 个客户端)</td>
      <td>${m.outboundsCount || 0} 个出站</td>
      <td>${m.rulesCount || 0} 条分流规则${m.restoredCertsCount ? ` · 证书: ${esc((m.restoredCertDomains || []).join(', '))}` : ''}</td>
    </tr>
  `).join('');

  return `
    ${previewHtml}

    <section class="grid-2">
      <article class="panel">
        <div class="panel-head">
          <div><h2>方式一：上传备份文件 (x-ui.db / .tar.gz) 或读取本机</h2><p>支持直接上传 x-ui.db 数据库、或包含 /etc/x-ui/x-ui.db + /root/cert + /root/.acme.sh 的 .tar.gz 备份包，完整还原全部节点、中转出站、路由规则与 SSL 自动续签证书</p></div>
        </div>
        <div class="panel-body stack">
          <label class="upload-dropzone" for="xui-db-file">
            <input type="file" id="xui-db-file" accept=".db,.sqlite,.sqlite3,.gz,.tgz,.json" class="hidden">
            <b style="display:block;font-size:15px;margin-bottom:6px">📁 点击选择或拖拽上传 <code>x-ui.db</code> 或 <code>3xui_backup.tar.gz</code></b>
            <span class="muted" style="font-size:12px" id="xui-file-label">支持 SQLite3 数据库 (x-ui.db)、通用 .tar.gz 备份包或 JSON 文件</span>
          </label>

          <label>
            <span>迁移合并策略</span>
            <select id="migrate-mode">
              <option value="merge">智能合并（保留当前面板已有节点，同端口/同Tag自动更新）</option>
              <option value="replace">完整替换（清空当前节点，完整还原导入的入站、出站与路由转发）</option>
            </select>
          </label>

          <div style="display:flex;flex-wrap:wrap;gap:8px">
            <button data-action="preview-xui-file">🔍 预览上传文件解析结果</button>
            <button class="primary" data-action="apply-xui-file">🚀 上传并立即执行备份迁移</button>
          </div>

          <div style="padding-top:12px;border-top:1px solid var(--line)">
            <label>
              <span>或者直接从服务器本机路径读取 (支持 <code>/etc/x-ui/x-ui.db</code> 或 <code>/root/3xui_backup.tar.gz</code>)</span>
              <div class="input-row" style="margin-top:4px">
                <input id="local-xui-path" value="/etc/x-ui/x-ui.db" placeholder="/etc/x-ui/x-ui.db 或 /root/3xui_backup.tar.gz">
                <button class="primary" data-action="migrate-local-xui">一键迁移本机数据</button>
              </div>
              <small>本机状态: ${state.overview?.local3xuiExists ? '✅ 已检测到本机备份数据库或压缩包' : '可填入服务器上的 .db 或 .tar.gz 路径一键读取'}</small>
            </label>
          </div>
        </div>
      </article>

      <article class="panel">
        <div class="panel-head">
          <div><h2>方式二：粘贴配置 JSON 导入</h2><p>支持粘贴 xrayTemplateConfig JSON 或入站数组 JSON</p></div>
        </div>
        <div class="panel-body stack">
          <label>
            <span>配置 JSON 内容</span>
            <textarea id="xui-json-input" style="min-height:190px" placeholder='{"inbounds": [...], "outbounds": [...], "routing": {"rules": [...]}}'></textarea>
          </label>
          <div style="display:flex;justify-content:flex-end;gap:8px">
            <button data-action="preview-xui-json">🔍 预览 JSON 解析</button>
            <button class="primary" data-action="apply-xui-json">🚀 从 JSON 执行备份迁移</button>
          </div>
        </div>
      </article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><h2>历史迁移记录</h2><p>历次数据与证书迁移导入审计</p></div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>迁移时间</th><th>模式</th><th>入站与客户端</th><th>迁移出站</th><th>迁移分流规则与证书</th></tr></thead>
          <tbody>
            ${historyRows || '<tr><td colspan="5"><div class="empty"><b>尚无迁移记录</b><span>上传 x-ui.db、备份包或粘贴 JSON 后将在此记录</span></div></td></tr>'}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function renderCertificates() {
  const s = state.settings || {};
  const baseSubUrl = getBaseSubscriptionUrl();
  const clashSubUrl = `${baseSubUrl}?format=clash`;
  const singboxSubUrl = `${baseSubUrl}?format=singbox`;

  const certRows = (state.certificates || []).map((c) => {
    const isPanelCert = s.webCertFile === c.certPath;
    const isNodeDefault = s.defaultCertFile === c.certPath;
    return `
      <tr>
        <td>
          <strong>${esc(c.domain)}</strong>
          <small>${esc(c.subject || '')}</small>
        </td>
        <td>
          <span class="tag">${esc(c.type || 'cert')}</span>
          ${isPanelCert ? '<span class="tag tls">当前面板 HTTPS</span>' : ''}
          ${isNodeDefault ? '<span class="tag relay">当前节点默认证书</span>' : ''}
        </td>
        <td>
          <small>公钥: <code>${esc(c.certPath)}</code></small>
          <small>私钥: <code>${esc(c.keyPath)}</code></small>
        </td>
        <td>
          <strong>${c.validTo ? fmtDate(c.validTo) : '长期有效'}</strong>
          <small>签发机构: ${esc((c.issuer || 'Self-Signed').slice(0, 40))}</small>
        </td>
        <td>
          <span class="status ${c.valid !== false ? 'valid' : 'error'}">${c.valid !== false ? '有效' : '文件异常'}</span>
        </td>
        <td>
          <div class="actions">
            <button class="primary" data-action="bind-cert-all" data-id="${esc(c.id)}">设为面板与节点默认证书</button>
            <button class="danger" data-action="delete-cert" data-id="${esc(c.id)}">移除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="action-bar">
      <div class="action-bar-left">
        <button class="primary" data-action="cert-acme">🌐 ACME 自动申请证书 (域名 / CF DNS / IP证书)</button>
        <button data-action="cert-selfsigned">⚡ 生成 10 年自签证书 (免域名)</button>
        <button data-action="cert-custom">📋 粘贴 / 导入已有证书</button>
        <button class="primary" data-action="open-aggregate-qr-modal">📱 打开全节点聚合订阅与二维码</button>
      </div>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div><h2>SSL 证书管理列表 (${state.certificates.length} 张)</h2><p>当前默认证书域名: <b>${esc(s.webDomain || s.defaultTlsDomain || '未绑定域名')}</b></p></div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>域名 / 标识</th><th>用途与类型</th><th>证书文件路径</th><th>到期时间 / 签发者</th><th>状态</th><th style="text-align:right">操作</th></tr></thead>
          <tbody>
            ${certRows || '<tr><td colspan="6"><div class="empty"><b>尚未添加自定义或 ACME 证书</b><span>点击左上方“🌐 ACME 自动申请证书”即可一键配置面板与节点证书</span></div></td></tr>'}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><h2>全节点聚合订阅中心 (高强度随机安全码防护)</h2><p>已启用 20 位随机安全码防扫描保护（拒绝简单 /sub/all 访问），支持 Shadowrocket、v2rayN、v2rayNG、NekoBox、Clash Verge / Mihomo、Sing-box、Stash、Surge、Hiddify 直接导入或按需展开二维码</p></div>
      </div>
      <div class="panel-body">
        <div class="qr-wall-grid">
          <div class="qr-wall-card">
            <div class="qr-wall-head">
              <strong>1. 通用 Base64 全节点聚合订阅</strong>
              <span class="tag">Base64</span>
            </div>
            <div class="qr-wall-sub">适用于 v2rayN / v2rayNG / Shadowrocket / NekoBox</div>
            <code style="font-size:11.5px;color:var(--primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(baseSubUrl)}</code>
            <div class="qr-wall-actions">
              <button class="primary" data-copy="${esc(baseSubUrl)}">📋 复制通用订阅</button>
              <button data-qr-inline="cert-qr-base64" data-qr-text="${esc(baseSubUrl)}">📱 展开/收起二维码</button>
            </div>
            <div id="cert-qr-base64" class="subscription-qr hidden"></div>
          </div>

          <div class="qr-wall-card">
            <div class="qr-wall-head">
              <strong>2. Clash / Mihomo 智能分流订阅</strong>
              <span class="tag tls">Clash YAML</span>
            </div>
            <div class="qr-wall-sub">内置 AI 专线 / 外贸 Google / Netflix / 自动测速策略组</div>
            <code style="font-size:11.5px;color:var(--primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(clashSubUrl)}</code>
            <div class="qr-wall-actions">
              <button class="primary" data-copy="${esc(clashSubUrl)}">📋 复制 Clash 订阅</button>
              <button data-qr-inline="cert-qr-clash" data-qr-text="${esc(clashSubUrl)}">📱 展开/收起二维码</button>
            </div>
            <div id="cert-qr-clash" class="subscription-qr hidden"></div>
          </div>

          <div class="qr-wall-card">
            <div class="qr-wall-head">
              <strong>3. Sing-box 客户端 JSON 订阅</strong>
              <span class="tag relay">Sing-box</span>
            </div>
            <div class="qr-wall-sub">适用于 Sing-box (SFI / SFA / SFM) 客户端</div>
            <code style="font-size:11.5px;color:var(--primary);overflow:hidden;text-overflow:ellipsis;white-space:nowrap">${esc(singboxSubUrl)}</code>
            <div class="qr-wall-actions">
              <button class="primary" data-copy="${esc(singboxSubUrl)}">📋 复制 Sing-box 订阅</button>
              <button data-qr-inline="cert-qr-sb" data-qr-text="${esc(singboxSubUrl)}">📱 展开/收起二维码</button>
            </div>
            <div id="cert-qr-sb" class="subscription-qr hidden"></div>
          </div>
        </div>
      </div>
    </section>
  `;
}

function renderSettings() {
  const s = state.settings || {};
  const certSelectOpts = [
    '<option value="">— 手动输入路径或不使用 HTTPS —</option>',
    ...(state.certificates || []).map((c) => `<option value="${esc(c.certPath)}|${esc(c.keyPath)}|${esc(c.domain)}"${s.webCertFile === c.certPath ? ' selected' : ''}>${esc(c.domain)} (${esc(c.type)})</option>`)
  ].join('');

  return `
    <div class="action-bar">
      <div class="action-bar-left">
        <a class="button primary" href="${BASE_PATH}/api/backup" target="_blank">⬇ 导出完整面板备份 (.json)</a>
        <button data-action="restore-backup-modal">⬆ 导入恢复备份</button>
      </div>
    </div>

    <section class="grid-2">
      <article class="panel">
        <div class="panel-head">
          <div><h2>面板网络、随机端口与安全路径</h2><p>修改端口或 SSL 证书后，面板服务将自动平滑重启生效</p></div>
        </div>
        <form id="settings-form" class="panel-body form-grid">
          <label>
            面板监听 IP (webListen)
            <input name="webListen" value="${esc(s.webListen || '0.0.0.0')}" placeholder="0.0.0.0 或 ::" required>
          </label>
          <label>
            面板监听端口 (webPort)
            <div class="input-row">
              <input name="webPort" id="setting-webport" type="number" min="1" max="65535" value="${esc(s.webPort || 2053)}" required>
              <button type="button" data-action="random-port">🎲 随机端口</button>
            </div>
          </label>

          <label class="wide">
            面板安全根路径 (webBasePath · 推荐 16 位随机字符)
            <div class="input-row">
              <input name="webBasePath" id="setting-webpath" value="${esc(s.webBasePath || '/')}" placeholder="/44A8m9DxlT7A7AbK/">
              <button type="button" data-action="random-path">🎲 生成 16 位随机安全路径</button>
              <button type="button" data-action="reset-path">设为 /</button>
            </div>
          </label>

          <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
            <input type="checkbox" name="strictBasePath" style="width:16px;min-height:16px" ${s.strictBasePath !== false ? 'checked' : ''}>
            <span><b>禁止单 IP+端口直接访问面板</b>（默认开启：访问无安全路径的 <code>IP:端口/</code> 直接返回 404，必须通过 <code>IP/域名:端口/安全路径/</code> 访问）</span>
          </label>

          <label>
            服务器公网 IPv4 (用于生成节点连接地址)
            <input name="publicIPv4" value="${esc(s.publicIPv4 || '')}" placeholder="自动检测本机公网 IPv4">
          </label>
          <label>
            面板 / 节点绑定域名 (webDomain)
            <input name="webDomain" id="setting-webdomain" value="${esc(s.webDomain || '')}" placeholder="填写已解析的域名">
          </label>

          <div class="section-title">面板 HTTPS (SSL 证书配置)</div>
          <label class="wide">
            快速选择已管理的 SSL 证书
            <select id="setting-cert-picker">${certSelectOpts}</select>
          </label>
          <label>
            面板公钥证书路径 (webCertFile)
            <input name="webCertFile" id="setting-cert-file" value="${esc(s.webCertFile || '')}" placeholder="留空则为 HTTP 模式">
          </label>
          <label>
            面板私钥文件路径 (webKeyFile)
            <input name="webKeyFile" id="setting-key-file" value="${esc(s.webKeyFile || '')}" placeholder="留空则为 HTTP 模式">
          </label>

          <div class="section-title">订阅安全码、流量重置与日志级别</div>
          <label class="wide">
            聚合订阅安全码 (subToken · 20 位高强度随机字符，防止订阅链接被扫描或猜测泄露)
            <div class="input-row">
              <input name="subToken" id="setting-subtoken" value="${esc(s.subToken || '')}" placeholder="20 位随机安全码" required>
              <button type="button" data-action="random-sub-token">🎲 重新生成 20 位安全码</button>
            </div>
            <small>更换安全码后，旧的聚合订阅链接将立即失效返回 404。</small>
          </label>
          <label>
            订阅路径前缀 (subPath)
            <input name="subPath" value="${esc(s.subPath || '/sub/')}" placeholder="/sub/">
          </label>
          <label>
            全局默认每月自动重置流量日 (1–31 号，0 = 不自动重置)
            <input name="trafficResetDay" type="number" min="0" max="31" value="${esc(s.trafficResetDay || 0)}" placeholder="0 表示按单节点设置">
          </label>
          <label class="wide">
            Sing-box 日志级别
            <select name="singboxLogLevel">
              <option value="warn"${selected('warn', s.singboxLogLevel || 'warn')}>warn (推荐 · 精简日志，省内存省硬盘)</option>
              <option value="info"${selected('info', s.singboxLogLevel)}>info (标准日志)</option>
              <option value="error"${selected('error', s.singboxLogLevel)}>error (仅记录错误)</option>
              <option value="debug"${selected('debug', s.singboxLogLevel)}>debug (调试模式)</option>
            </select>
          </label>

          <div class="form-actions">
            <button type="submit" class="primary">保存面板设置</button>
          </div>
        </form>
      </article>

      <div class="stack">
        <article class="panel">
          <div class="panel-head">
            <div><h2>修改管理员账号与密码</h2><p>当前登录账号: <b>${esc(state.admin.username || 'admin')}</b></p></div>
          </div>
          <form id="account-form" class="panel-body form-grid">
            <label class="wide">
              当前登录密码 (必填验证)
              <input name="currentPassword" type="password" required placeholder="请输入当前密码">
            </label>
            <label>
              新管理员账号
              <div class="input-row">
                <input name="username" id="account-user-input" value="${esc(state.admin.username || 'admin')}" required>
                <button type="button" data-action="random-account-user">🎲 随机</button>
              </div>
            </label>
            <label>
              新登录密码 (推荐 18 位高强度随机密码)
              <div class="input-row">
                <input name="newPassword" id="account-pass-input" type="text" required placeholder="输入或点击右侧随机生成">
                <button type="button" data-action="random-account-pass">🎲 随机 18 位</button>
              </div>
            </label>
            <div class="form-actions">
              <button type="submit" class="primary">修改账号与密码</button>
            </div>
          </form>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div><h2>SSH 命令行快捷管理菜单</h2><p>在服务器 SSH 终端输入 <code>ng</code> 或 <code>nexusgate</code> 即可呼出完整管理面板</p></div>
          </div>
          <div class="panel-body">
            <div class="command-item">
              <div>
                <b>呼出完整交互式管理菜单 (含 SSL / BBR+HY2 / 防火墙 / 内存清理)</b>
                <code>ng  或  nexusgate</code>
              </div>
              <button data-copy="ng">复制</button>
            </div>
            <div class="command-item">
              <div>
                <b>查看当前面板配置与访问地址 (简洁明了，方便直接复制)</b>
                <code>ng info</code>
              </div>
              <button data-copy="ng info">复制</button>
            </div>
            <div class="command-item">
              <div>
                <b>一键开启 BBR + FQ + HY2 UDP 高速内核加速</b>
                <code>ng bbr</code>
              </div>
              <button data-copy="ng bbr">复制</button>
            </div>
            <div class="command-item">
              <div>
                <b>SSL 证书管理 (ACME / CF DNS / IP证书 / 自签证书)</b>
                <code>ng cert</code>
              </div>
              <button data-copy="ng cert">复制</button>
            </div>
            <div class="command-item">
              <div>
                <b>一键备份迁移恢复本机数据库或通用备份包</b>
                <code>ng migrate</code>
              </div>
              <button data-copy="ng migrate">复制</button>
            </div>
          </div>
        </article>
      </div>
    </section>
  `;
}

function render() {
  const views = {
    overview: renderOverview,
    inbounds: renderInbounds,
    routing: renderRouting,
    outbounds: renderOutbounds,
    migrate: renderMigrate,
    certificates: renderCertificates,
    settings: renderSettings
  };
  $('#content').innerHTML = (views[state.page] || renderOverview)();
}

/* ==================== MODALS & ACTIONS ==================== */

async function openInboundModal(existing = null, preset = '') {
  const realCert = (state.certificates || []).find((c) => c.type !== 'self-signed' && !c.isSelfSigned && c.valid !== false);
  const defTlsDomain = realCert?.domain || state.settings?.webDomain || state.defaultSettings?.defaultTlsDomain || 'www.apple.com';
  const defCertFile = realCert?.certPath || state.defaultSettings?.defaultCertFile || state.settings?.webCertFile || '';
  const defKeyFile = realCert?.keyPath || state.defaultSettings?.defaultKeyFile || state.settings?.webKeyFile || '';

  const newUuid = genUuidClient();
  const newPass = genRandomAlnum(20);
  const portRand = Math.floor(Math.random() * 40000) + 15000;

  const item = existing ? JSON.parse(JSON.stringify(existing)) : {
    remark: '',
    tag: `inbound-${portRand}`,
    protocol: 'vless',
    listen: '::',
    port: portRand,
    security: 'reality',
    transport: 'tcp',
    flow: 'xtls-rprx-vision',
    method: '2022-blake3-aes-128-gcm',
    uuid: newUuid,
    password: newPass,
    outboundTag: 'default',
    limitIp: 0,
    limitDevice: 0,
    total: 0,
    expiryTime: 0,
    resetDay: state.settings?.trafficResetDay || 0,
    tlsDomain: defTlsDomain,
    certPath: defCertFile,
    keyPath: defKeyFile,
    reality: {
      serverName: 'www.apple.com',
      target: 'www.apple.com:443',
      privateKey: '',
      publicKey: '',
      shortIds: ['1a2b3c4d'],
      fingerprint: 'chrome'
    },
    clients: [{ email: 'user_1', id: newUuid, password: newPass, flow: 'xtls-rprx-vision', enable: true }]
  };

  if (item.reality && ['www.cloudflare.com', 'cloudflare.com', 'www.bing.com'].includes(String(item.reality.serverName || '').toLowerCase())) {
    item.reality.serverName = 'www.apple.com';
    item.reality.target = 'www.apple.com:443';
  }

  if (preset) {
    if (preset === 'vless-reality') {
      item.protocol = 'vless'; item.security = 'reality'; item.transport = 'tcp'; item.flow = 'xtls-rprx-vision'; item.remark = `VLESS-Reality-${item.port}`;
    } else if (preset === 'anytls') {
      item.protocol = 'anytls'; item.security = 'tls'; item.transport = 'tcp'; item.remark = `AnyTLS-${item.port}`;
    } else if (preset === 'hysteria2') {
      item.protocol = 'hysteria2'; item.security = 'tls'; item.upMbps = 100; item.downMbps = 100; item.remark = `HY2-${item.port}`;
    } else if (preset === 'ss2022-128') {
      item.protocol = 'shadowsocks'; item.method = '2022-blake3-aes-128-gcm'; item.security = 'none'; item.remark = `SS2022-128-${item.port}`;
    } else if (preset === 'ss2022-256') {
      item.protocol = 'shadowsocks'; item.method = '2022-blake3-aes-256-gcm'; item.security = 'none'; item.remark = `SS2022-256-${item.port}`;
    } else if (preset === 'ss-128') {
      item.protocol = 'shadowsocks'; item.method = 'aes-128-gcm'; item.security = 'none'; item.remark = `SS-128-${item.port}`;
    } else if (preset === 'socks') {
      item.protocol = 'socks'; item.security = 'none'; item.remark = `SOCKS5-${item.port}`;
    } else if (preset === 'direct') {
      item.protocol = 'direct'; item.security = 'none'; item.remark = `端口转发-${item.port}`;
    }
  }

  if (!existing && item.security === 'reality' && !item.reality.privateKey) {
    try {
      const kp = await api('/api/tools/reality-keypair', { method: 'POST' });
      item.reality.privateKey = kp.privateKey;
      item.reality.publicKey = kp.publicKey;
      item.reality.shortIds = [kp.shortId];
    } catch { /* fallback on submit */ }
  }
  if (!existing && item.protocol === 'shadowsocks') {
    try {
      const sk = await api('/api/tools/ss-key', { method: 'POST', body: JSON.stringify({ method: item.method }) });
      item.password = sk.password;
    } catch { /* ignore */ }
  }

  const outboundOpts = [
    `<option value="default"${selected('default', item.outboundTag)}>默认路由 (按分流规则表处理)</option>`,
    ...state.outbounds.map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, item.outboundTag)}>${o.builtin ? '' : '⇄ 绑定中转出站: '}${esc(o.tag)}${o.server ? ` (${o.server}:${o.port})` : ` (${o.remark})`}</option>`)
  ].join('');

  const certOpts = [
    `<option value="">默认绑定证书 (${esc(defTlsDomain)})</option>`,
    ...(state.certificates || []).map((c) => `<option value="${esc(c.domain)}" data-cert="${esc(c.certPath)}" data-key="${esc(c.keyPath)}"${selected(c.domain, item.tlsDomain)}>${esc(c.domain)} (${esc(c.type)})</option>`)
  ].join('');

  const c0 = (item.clients && item.clients[0]) || {};
  const clientUuidVal = /^[0-9a-f]{8}-[0-9a-f]{4}-/i.test(String(c0.id || '')) ? c0.id : (item.uuid || genUuidClient());
  const totalGB = item.total > 0 ? Math.round((item.total / (1024 ** 3)) * 100) / 100 : 0;
  const expiryStr = toDatetimeLocalValue(item.expiryTime);

  openModal(
    existing ? '编辑入站节点' : '新建入站节点',
    existing ? `${existing.remark} (:${existing.port})` : '配置入站协议、IP/设备限制、到期时间、流量重置与中转出站',
    `
    <form id="inbound-form" class="form-grid" data-id="${esc(existing?.id || '')}">
      <label>
        节点备注名称
        <input name="remark" value="${esc(item.remark)}" placeholder="如 VLESS-Reality" required>
      </label>
      <label>
        入站协议 (Protocol)
        <select name="protocol" id="inb-proto-select">
          ${state.catalog.inboundProtocols.map((p) => `<option value="${esc(p.id)}"${selected(p.id, item.protocol)}>${esc(p.name)}</option>`).join('')}
        </select>
      </label>

      <label>
        监听地址 (Listen)
        <input name="listen" value="${esc(item.listen || '::')}" placeholder=":: (双栈) 或 0.0.0.0">
      </label>
      <label>
        监听端口 (Port)
        <div class="input-row">
          <input name="port" id="inb-port-input" type="number" min="1" max="65535" value="${esc(item.port)}" required>
          <button type="button" data-action="inb-rand-port">🎲 随机</button>
        </div>
      </label>

      <div class="section-title">IP 限制、设备数限制、流量配额与到期自动管理</div>
      <label>
        限制同时在线公网 IP 数 (0 = 不限制)
        <input name="limitIp" type="number" min="0" max="1000" value="${esc(item.limitIp || 0)}" placeholder="0 表示不限制公网 IP 数">
        <small>超出设定数量时，仅拦截并断开第 N+1 个新接入的 IP，前 N 个已在线 IP/设备不受影响正常使用</small>
      </label>
      <label>
        限制同时在线设备数 (0 = 不限制)
        <input name="limitDevice" type="number" min="0" max="2000" value="${esc(item.limitDevice || 0)}" placeholder="0 表示不限制设备台数">
        <small>超出设定数量时，仅拦截并断开第 N+1 台新接入的设备，前 N 台已在线设备不受影响正常使用</small>
      </label>

      <label>
        总流量配额上限 (GB，0 = 不限制)
        <input name="totalGB" type="number" min="0" step="0.1" value="${esc(totalGB)}" placeholder="0 表示不限流量">
        <small>达到流量配额上限后自动停用该节点</small>
      </label>
      <label>
        每月自动重置流量日期 (1–31 号，0 = 不自动重置)
        <input name="resetDay" type="number" min="0" max="31" value="${esc(item.resetDay || 0)}" placeholder="如填 1 表示每月 1 号自动清零">
        <small>设为 1–31 后，每月到达该日期自动清零已用流量并恢复因超流停用的节点</small>
      </label>

      <label class="wide">
        节点到期时间 (留空表示永久有效，到期后自动停用)
        <div class="input-row" style="flex-wrap:wrap">
          <input name="expiryTime" id="inb-expiry-input" type="datetime-local" value="${esc(expiryStr)}" style="max-width:240px">
          <button type="button" data-action="set-expiry" data-days="0">永久有效</button>
          <button type="button" data-action="set-expiry" data-days="30">+30天 (月付)</button>
          <button type="button" data-action="set-expiry" data-days="90">+90天 (季付)</button>
          <button type="button" data-action="set-expiry" data-days="180">+180天 (半年)</button>
          <button type="button" data-action="set-expiry" data-days="365">+1年 (年付)</button>
        </div>
      </label>

      <label class="wide">
        ⇄ 一键绑定转发目标出站 (保存后将自动同步至【路由规则 (转发)】表)
        <select name="outboundTag">${outboundOpts}</select>
      </label>

      <div id="inb-dynamic-fields" class="form-grid wide" style="margin:0"></div>

      <div class="form-actions">
        <button type="button" data-close>取消</button>
        <button type="submit" class="primary">${existing ? '保存修改并应用' : '立即创建并启动'}</button>
      </div>
    </form>
    `
  );

  const renderDynamicFields = async () => {
    const proto = $('#inb-proto-select').value;
    const box = $('#inb-dynamic-fields');
    if (!box) return;

    if (proto === 'direct') {
      box.innerHTML = `
        <div class="section-title">Direct 端口转发 (隧道中转配置)</div>
        <label>
          转发目标地址 (Override Address)
          <input name="overrideAddress" value="${esc(item.overrideAddress || '')}" placeholder="目标落地机 IP 或域名" required>
        </label>
        <label>
          转发目标端口 (Override Port)
          <input name="overridePort" type="number" min="1" max="65535" value="${esc(item.overridePort || 443)}" required>
        </label>
        <label class="wide">
          转发网络协议
          <select name="network">
            <option value="tcp,udp"${selected('tcp,udp', item.network)}>TCP + UDP 双栈转发</option>
            <option value="tcp"${selected('tcp', item.network)}>仅 TCP</option>
            <option value="udp"${selected('udp', item.network)}>仅 UDP</option>
          </select>
        </label>
      `;
      return;
    }

    if (proto === 'shadowsocks') {
      box.innerHTML = `
        <div class="section-title">Shadowsocks / SS 2022 加密与密钥</div>
        <label>
          加密方式 (Method)
          <select name="method" id="inb-ss-method">
            ${state.catalog.ssMethods.map((m) => `<option value="${esc(m.id)}"${selected(m.id, item.method)}>${esc(m.label)}</option>`).join('')}
          </select>
        </label>
        <label>
          连接密钥 (Password / Base64 Key)
          <div class="input-row">
            <input name="password" id="inb-ss-pass" value="${esc(item.password || '')}" required>
            <button type="button" data-action="gen-ss-key">🔑 生成标准密钥</button>
          </div>
          <small>自动适配 v2rayN / Shadowrocket / Clash / Sing-box 全客户端。</small>
        </label>
        <label class="wide">
          客户端标识名称 (Email/Remark)
          <input name="clientEmail" value="${esc(c0.email || 'ss_client_1')}">
        </label>
      `;

      const refreshSsKeyForMethod = async () => {
        const curMethod = $('#inb-ss-method')?.value || '2022-blake3-aes-128-gcm';
        try {
          const sk = await api('/api/tools/ss-key', { method: 'POST', body: JSON.stringify({ method: curMethod }) });
          if ($('#inb-ss-pass')) {
            $('#inb-ss-pass').value = sk.password;
            item.password = sk.password;
            item.method = curMethod;
          }
        } catch { /* ignore */ }
      };

      if (!existing && (!item.password || !item.password.endsWith('='))) {
        refreshSsKeyForMethod();
      }
      $('#inb-ss-method')?.addEventListener('change', refreshSsKeyForMethod);
      return;
    }

    if (proto === 'socks' || proto === 'mixed' || proto === 'http') {
      box.innerHTML = `
        <div class="section-title">${proto.toUpperCase()} 认证凭据</div>
        <label>
          用户名 (Username)
          <input name="socksUser" value="${esc(item.socksUser || c0.username || `user_${genRandomAlnum(6)}`)}" required>
        </label>
        <label>
          密码 (Password)
          <input name="socksPassword" value="${esc(item.socksPassword || c0.password || genRandomAlnum(16))}" required>
        </label>
      `;
      return;
    }

    if (proto === 'anytls') {
      box.innerHTML = `
        <div class="section-title">AnyTLS 认证与 TLS 证书配置 (默认域名: ${esc(defTlsDomain)})</div>
        <label>
          AnyTLS 访问密码
          <div class="input-row">
            <input name="password" id="inb-anytls-pass" value="${esc(item.password || c0.password || genRandomAlnum(20))}" required>
            <button type="button" data-action="gen-clean-pass" data-target="inb-anytls-pass">🎲 随机</button>
          </div>
        </label>
        <label>
          客户端标识 (用户名)
          <input name="clientEmail" value="${esc(c0.email || 'anytls_user')}">
        </label>
        <label>
          选择已管理证书 / SNI 域名
          <select id="inb-cert-select">${certOpts}</select>
        </label>
        <label>
          TLS 域名 (SNI)
          <input name="tlsDomain" id="inb-tls-domain" value="${esc(item.tlsDomain || defTlsDomain)}">
        </label>
        <label>
          证书公钥路径
          <input name="certPath" id="inb-cert-path" value="${esc(item.certPath || defCertFile)}" placeholder="自动使用默认证书">
        </label>
        <label>
          证书私钥路径
          <input name="keyPath" id="inb-key-path" value="${esc(item.keyPath || defKeyFile)}" placeholder="自动使用默认私钥">
        </label>
      `;
      return;
    }

    if (proto === 'hysteria2') {
      box.innerHTML = `
        <div class="section-title">Hysteria 2 (HY2 UDP) 认证与证书配置 (默认域名: ${esc(defTlsDomain)})</div>
        <label>
          HY2 认证密码
          <div class="input-row">
            <input name="password" id="inb-hy2-pass" value="${esc(item.password || c0.password || genRandomAlnum(20))}" required>
            <button type="button" data-action="gen-clean-pass" data-target="inb-hy2-pass">🎲 随机</button>
          </div>
        </label>
        <label>
          Salamander 混淆密码 (可选)
          <input name="obfsPassword" value="${esc(item.obfsPassword || '')}" placeholder="留空则不开启 obfs">
        </label>
        <label>
          上行带宽限制 (Mbps)
          <input name="upMbps" type="number" value="${esc(item.upMbps ?? 100)}">
        </label>
        <label>
          下行带宽限制 (Mbps)
          <input name="downMbps" type="number" value="${esc(item.downMbps ?? 100)}">
        </label>
        <label>
          选择已管理证书
          <select id="inb-cert-select">${certOpts}</select>
        </label>
        <label>
          TLS SNI 域名
          <input name="tlsDomain" id="inb-tls-domain" value="${esc(item.tlsDomain || defTlsDomain)}">
        </label>
        <label>
          证书公钥路径
          <input name="certPath" id="inb-cert-path" value="${esc(item.certPath || defCertFile)}">
        </label>
        <label>
          证书私钥路径
          <input name="keyPath" id="inb-key-path" value="${esc(item.keyPath || defKeyFile)}">
        </label>
      `;
      return;
    }

    const sec = item.security || (proto === 'tuic' ? 'tls' : 'reality');
    const trans = item.transport || 'tcp';
    const isUuidProto = ['vless', 'vmess', 'tuic'].includes(proto);

    box.innerHTML = `
      <div class="section-title">${esc(proto.toUpperCase())} 客户端凭据与传输安全</div>
      ${isUuidProto ? `
        <label>
          客户端 UUID (标准 UUID v4 格式)
          <div class="input-row">
            <input name="uuid" id="inb-uuid-input" value="${esc(clientUuidVal)}" required>
            <button type="button" data-action="gen-uuid">🎲 随机 UUID</button>
          </div>
        </label>
      ` : `
        <label>
          Trojan 连接密码
          <div class="input-row">
            <input name="password" id="inb-trojan-pass" value="${esc(item.password || genRandomAlnum(20))}" required>
            <button type="button" data-action="gen-clean-pass" data-target="inb-trojan-pass">🎲 随机</button>
          </div>
        </label>
      `}
      <label>
        客户端备注标识 (Email)
        <input name="clientEmail" value="${esc(c0.email || `${proto}_user_1`)}">
      </label>

      <label>
        传输层协议 (Transport)
        <select name="transport" id="inb-trans-select">
          <option value="tcp"${selected('tcp', trans)}>TCP (Raw)</option>
          <option value="ws"${selected('ws', trans)}>WebSocket (WS)</option>
          <option value="grpc"${selected('grpc', trans)}>gRPC</option>
          <option value="httpupgrade"${selected('httpupgrade', trans)}>HTTPUpgrade</option>
        </select>
      </label>
      <label>
        安全层加密 (Security)
        <select name="security" id="inb-sec-select">
          <option value="reality"${selected('reality', sec)}>Reality (免证书高隐蔽 · 推荐)</option>
          <option value="tls"${selected('tls', sec)}>TLS (默认使用域名证书: ${esc(defTlsDomain)})</option>
          <option value="none"${selected('none', sec)}>无加密 (None · 适合内网中转或外层反代)</option>
        </select>
      </label>

      ${proto === 'vless' ? `
        <label class="wide">
          VLESS 流控 (Flow)
          <select name="flow">
            <option value="xtls-rprx-vision"${selected('xtls-rprx-vision', item.flow)}>xtls-rprx-vision (Reality/TLS TCP 推荐)</option>
            <option value=""${selected('', item.flow)}>无流控 (WS / gRPC / 普通模式)</option>
          </select>
        </label>
      ` : ''}

      <div id="inb-sec-box" class="form-grid wide" style="margin:0"></div>
      <div id="inb-trans-box" class="form-grid wide" style="margin:0"></div>
    `;

    const renderSecAndTrans = () => {
      const curSec = $('#inb-sec-select')?.value || 'none';
      const curTrans = $('#inb-trans-select')?.value || 'tcp';
      const secBox = $('#inb-sec-box');
      const transBox = $('#inb-trans-box');

      if (secBox) {
        if (curSec === 'reality') {
          const r = item.reality || {};
          secBox.innerHTML = `
            <div class="section-title">Reality 伪装与 X25519 密钥对 (默认 Apple 高可用伪装)</div>
            <label>
              伪装目标预设 (SNI)
              <select id="inb-reality-preset">
                <option value="">— 选择高可用 SNI 预设 —</option>
                ${state.catalog.realityPresets.map((p) => `<option value="${esc(p.serverName)}" data-target="${esc(p.target)}"${selected(p.serverName, r.serverName || 'www.apple.com')}>${esc(p.label)}</option>`).join('')}
              </select>
            </label>
            <label>
              伪装域名 (ServerName / SNI)
              <input name="realityServerName" id="inb-reality-sni" value="${esc(r.serverName || 'www.apple.com')}" required>
            </label>
            <label>
              握手目标地址 (Handshake Target)
              <input name="realityTarget" id="inb-reality-target" value="${esc(r.target || 'www.apple.com:443')}" required>
            </label>
            <label>
              ShortIds (十六进制，逗号分隔)
              <input name="realityShortIds" id="inb-reality-sid" value="${esc(Array.isArray(r.shortIds) ? r.shortIds.join(',') : (r.shortIds || '1a2b3c4d'))}">
            </label>
            <label>
              Reality 私钥 (Private Key)
              <div class="input-row">
                <input name="realityPrivateKey" id="inb-reality-priv" value="${esc(r.privateKey || '')}" required>
                <button type="button" data-action="gen-reality-keys">🔑 重新生成</button>
              </div>
            </label>
            <label>
              Reality 客户端公钥 (Public Key)
              <input name="realityPublicKey" id="inb-reality-pub" value="${esc(r.publicKey || '')}" readonly>
            </label>
          `;
        } else if (curSec === 'tls') {
          secBox.innerHTML = `
            <div class="section-title">TLS 证书配置 (已自动绑定域名证书: ${esc(defTlsDomain)})</div>
            <label>
              选择已管理证书
              <select id="inb-cert-select">${certOpts}</select>
            </label>
            <label>
              TLS SNI 域名
              <input name="tlsDomain" id="inb-tls-domain" value="${esc(item.tlsDomain || defTlsDomain)}">
            </label>
            <label>
              公钥证书路径
              <input name="certPath" id="inb-cert-path" value="${esc(item.certPath || defCertFile)}">
            </label>
            <label>
              私钥文件路径
              <input name="keyPath" id="inb-key-path" value="${esc(item.keyPath || defKeyFile)}">
            </label>
          `;
        } else {
          secBox.innerHTML = '';
        }
      }

      if (transBox) {
        if (curTrans === 'ws' || curTrans === 'httpupgrade') {
          transBox.innerHTML = `
            <div class="section-title">${curTrans.toUpperCase()} 路径与 Host</div>
            <label>路径 (Path)<input name="wsPath" value="${esc(item.wsPath || '/')}"></label>
            <label>伪装 Host (可选)<input name="wsHost" value="${esc(item.wsHost || '')}"></label>
          `;
        } else if (curTrans === 'grpc') {
          transBox.innerHTML = `
            <div class="section-title">gRPC 配置</div>
            <label class="wide">Service Name<input name="grpcServiceName" value="${esc(item.grpcServiceName || 'grpc')}"></label>
          `;
        } else {
          transBox.innerHTML = '';
        }
      }
    };

    renderSecAndTrans();
    $('#inb-sec-select')?.addEventListener('change', renderSecAndTrans);
    $('#inb-trans-select')?.addEventListener('change', renderSecAndTrans);
  };

  renderDynamicFields();
  $('#inb-proto-select')?.addEventListener('change', renderDynamicFields);
}

/**
 * Inbound Share Links & Subscription Modal — QR Codes Default to Collapsed (hidden)
 */
function openInboundLinksModal(inbound) {
  const links = inbound.links || [];
  const subToken = (links[0] && links[0].subId) || inbound.tag || state.settings?.subToken || '';
  const clientSubUrl = getBaseSubscriptionUrl(subToken);
  const allSubUrl = getBaseSubscriptionUrl();
  const allClashUrl = `${allSubUrl}?format=clash`;

  const rows = links.map((l, idx) => `
    <div class="subscription-row">
      <div>
        <b>${esc(l.name)} (${esc(l.protocol.toUpperCase())} · 端口 :${inbound.port})</b>
        <small style="color:var(--success)">✓ 支持 v2rayN / v2rayNG / Shadowrocket / NekoBox / Mihomo / Sing-box / Hiddify 直接导入或展开扫码</small>
        <code style="white-space:normal;word-break:break-all;display:block;margin-top:4px;padding:8px;background:var(--surface);border:1px solid var(--line);border-radius:8px">${esc(l.uri)}</code>
        ${l.altUri ? `<small style="margin-top:4px">备用兼容链接: <code>${esc(l.altUri)}</code></small>` : ''}
      </div>
      <div style="display:flex;flex-wrap:wrap;gap:6px;width:100%;justify-content:flex-end">
        <button class="primary" data-copy="${esc(l.uri)}">📋 复制节点链接</button>
        ${l.altUri ? `<button data-copy="${esc(l.altUri)}">复制备用链接</button>` : ''}
        ${l.clashYaml ? `<button data-copy="${esc(l.clashYaml)}">复制 Clash YAML</button>` : ''}
        ${l.singboxJson ? `<button data-copy="${esc(l.singboxJson)}">复制 Sing-box JSON</button>` : ''}
        <button data-qr-inline="qr-box-${idx}" data-qr-text="${esc(l.uri)}">📱 展开/收起二维码</button>
      </div>
      <div id="qr-box-${idx}" class="subscription-qr hidden"></div>
    </div>
  `).join('');

  openModal(
    `节点分享链接、二维码与客户端订阅 · 端口 :${inbound.port}`,
    `${inbound.remark} (${inbound.protocol.toUpperCase()})`,
    `
    <div class="stack">
      <div class="section-title" style="margin-top:0">一、单节点分享链接 (默认收起二维码，点击按钮展开)</div>
      ${rows || '<div class="empty"><b>该入站暂无可用客户端链接</b><span>请检查客户端是否已启用</span></div>'}

      <div class="section-title">二、当前节点专属订阅链接</div>
      <div class="subscription-row">
        <div>
          <b>当前节点专属订阅地址 (Base64 / Clash / Sing-box)</b>
          <code>${esc(clientSubUrl)}</code>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px">
          <button class="primary" data-copy="${esc(clientSubUrl)}">复制 Base64 订阅</button>
          <button data-copy="${esc(`${clientSubUrl}?format=clash`)}">复制 Clash 订阅</button>
          <button data-copy="${esc(`${clientSubUrl}?format=singbox`)}">复制 Sing-box 订阅</button>
          <button data-qr-inline="qr-sub-box" data-qr-text="${esc(clientSubUrl)}">📱 展开/收起订阅二维码</button>
        </div>
        <div id="qr-sub-box" class="subscription-qr hidden"></div>
      </div>

      <div class="section-title">三、全节点聚合订阅地址 (高强度随机安全码防护)</div>
      <div class="subscription-row">
        <div style="width:100%">
          <b>全节点聚合订阅地址 (通用 Base64 & Clash 智能分流)</b>
          <code>${esc(allSubUrl)}</code>
          <small style="margin-top:4px">Clash 智能分流订阅地址: <code>${esc(allClashUrl)}</code></small>
        </div>
        <div style="display:flex;flex-wrap:wrap;gap:6px;width:100%;justify-content:flex-end">
          <button class="primary" data-copy="${esc(allSubUrl)}">复制全节点通用订阅</button>
          <button class="primary" data-copy="${esc(allClashUrl)}">复制全节点 Clash 订阅</button>
          <button data-copy="${esc(`${allSubUrl}?format=singbox`)}">复制全节点 Sing-box 订阅</button>
          <button data-qr-inline="qr-all-sub-box" data-qr-text="${esc(allSubUrl)}">📱 展开/收起聚合二维码</button>
          <button data-action="open-aggregate-qr-modal">📱 打开全部节点二维码中心</button>
        </div>
        <div id="qr-all-sub-box" class="subscription-qr hidden">
          <div class="grid-2" style="width:100%;margin-top:4px">
            <div>
              <b style="display:block;font-size:12px;margin-bottom:6px">📱 全节点通用订阅二维码</b>
              ${makeQrSvg(allSubUrl)}
            </div>
            <div>
              <b style="display:block;font-size:12px;margin-bottom:6px">⚡ 全节点 Clash 分流二维码</b>
              ${makeQrSvg(allClashUrl)}
            </div>
          </div>
        </div>
      </div>
    </div>
    `
  );
}

/**
 * Compact All-Nodes Aggregate Subscription & QR Wall Modal
 */
function openAggregateQrModal() {
  const allSubUrl = getBaseSubscriptionUrl();
  const clashSubUrl = `${allSubUrl}?format=clash`;
  const singboxSubUrl = `${allSubUrl}?format=singbox`;

  const enabledNodes = state.inbounds.filter((i) => i.enable !== false && i.protocol !== 'direct');
  const allNodeCards = enabledNodes
    .flatMap((inb) => (inb.links || []).map((l) => ({ inb, l })))
    .map(({ inb, l }, idx) => `
      <div class="qr-wall-card">
        <div class="qr-wall-head">
          <strong title="${esc(l.name)}">${esc(l.name)}</strong>
          <span class="tag">${esc(inb.protocol.toUpperCase())} :${inb.port}</span>
        </div>
        <div class="qr-wall-actions">
          <button class="primary" data-copy="${esc(l.uri)}">📋 复制链接</button>
          <button data-qr-inline="wall-qr-${idx}" data-qr-text="${esc(l.uri)}">📱 展开二维码</button>
        </div>
        <div id="wall-qr-${idx}" class="subscription-qr hidden"></div>
      </div>
    `)
    .join('');

  openModal(
    '全节点聚合订阅与二维码中心',
    `聚合全部 ${enabledNodes.length} 个启用节点`,
    `
    <div class="stack">
      <div class="section-title" style="margin-top:0">一、全节点聚合订阅链接 (点击可展开二维码)</div>
      <div class="qr-wall-grid">
        <div class="qr-wall-card">
          <div class="qr-wall-head">
            <strong>通用 Base64 聚合订阅</strong>
            <span class="tag">Base64</span>
          </div>
          <div class="qr-wall-sub">v2rayN / Shadowrocket / v2rayNG / NekoBox</div>
          <div class="qr-wall-actions">
            <button class="primary" data-copy="${esc(allSubUrl)}">📋 复制通用订阅</button>
            <button data-qr-inline="agg-qr-b64" data-qr-text="${esc(allSubUrl)}">📱 展开二维码</button>
          </div>
          <div id="agg-qr-b64" class="subscription-qr hidden"></div>
        </div>

        <div class="qr-wall-card">
          <div class="qr-wall-head">
            <strong>Clash / Mihomo 智能分流</strong>
            <span class="tag tls">Clash</span>
          </div>
          <div class="qr-wall-sub">内置 AI 专线 / 外贸 Google / 自动测速策略组</div>
          <div class="qr-wall-actions">
            <button class="primary" data-copy="${esc(clashSubUrl)}">📋 复制 Clash 订阅</button>
            <button data-qr-inline="agg-qr-clash" data-qr-text="${esc(clashSubUrl)}">📱 展开二维码</button>
          </div>
          <div id="agg-qr-clash" class="subscription-qr hidden"></div>
        </div>

        <div class="qr-wall-card">
          <div class="qr-wall-head">
            <strong>Sing-box JSON 聚合订阅</strong>
            <span class="tag relay">Sing-box</span>
          </div>
          <div class="qr-wall-sub">SFI / SFA / SFM 客户端直接导入</div>
          <div class="qr-wall-actions">
            <button class="primary" data-copy="${esc(singboxSubUrl)}">📋 复制 Sing-box 订阅</button>
            <button data-qr-inline="agg-qr-sb" data-qr-text="${esc(singboxSubUrl)}">📱 展开二维码</button>
          </div>
          <div id="agg-qr-sb" class="subscription-qr hidden"></div>
        </div>
      </div>

      <div class="section-title">二、全部单节点快速复制与按需展开二维码 (${enabledNodes.length} 个节点)</div>
      <div class="qr-wall-grid">
        ${allNodeCards || '<div class="empty" style="grid-column:1/-1"><b>暂无已启用的入站节点</b></div>'}
      </div>
    </div>
    `
  );
}

function openOutboundModal(existing = null) {
  const item = existing || {
    remark: '',
    tag: '',
    type: 'shadowsocks',
    server: '',
    port: 8388,
    method: '2022-blake3-aes-128-gcm',
    password: '',
    uuid: '',
    username: '',
    security: 'none',
    transport: 'tcp',
    sni: '',
    publicKey: '',
    shortId: '',
    detour: ''
  };

  const detourOpts = [
    '<option value="">直连发出 (不经过前置链式代理)</option>',
    ...state.outbounds
      .filter((o) => !o.builtin && o.id !== existing?.id)
      .map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, item.detour)}>前置代理: ${esc(o.tag)} (${esc(o.remark)})</option>`)
  ].join('');

  const previewJson = JSON.stringify(item.singboxPreview || {
    type: item.type,
    tag: item.tag || 'outbound-1',
    server: item.server || '127.0.0.1',
    server_port: Number(item.port || 443)
  }, null, 2);

  openModal(
    existing ? `编辑出站 (${existing.tag})` : '添加出站规则',
    existing ? `${existing.tag} (${existing.server}:${existing.port})` : '支持直接粘贴节点链接一键解析或切换 Form / JSON 编辑',
    `
    <div class="stack">
      <div class="quick-bar" style="margin-bottom:0;justify-content:space-between">
        <div style="display:flex;gap:8px;align-items:center;flex:1">
          <span style="white-space:nowrap">🔗 链接解析:</span>
          <input id="out-modal-uri-input" placeholder="vmess:// vless:// trojan:// ss:// hysteria2:// anytls:// socks://" style="flex:1;min-height:34px">
          <button type="button" class="primary" data-action="parse-uri-into-outbound-modal">⚡ 解析填入</button>
        </div>
        <div style="display:flex;gap:4px">
          <button type="button" class="primary" id="out-tab-form-btn" data-action="switch-out-tab" data-tab="form">Form 表单</button>
          <button type="button" id="out-tab-json-btn" data-action="switch-out-tab" data-tab="json">JSON 视图</button>
        </div>
      </div>

      <form id="outbound-form" class="form-grid" data-id="${esc(existing?.id || '')}">
        <div id="out-form-pane" class="form-grid wide" style="margin:0">
          <label>
            出站标签 (Tag · 用于路由规则绑定)
            <input name="tag" id="out-f-tag" value="${esc(item.tag)}" placeholder="输入出站节点标签名称" required>
          </label>
          <label>
            出站协议 (Protocol)
            <select name="type" id="out-f-type">
              ${state.catalog.outboundProtocols.filter((p) => !['direct', 'block'].includes(p.id)).map((p) => `<option value="${esc(p.id)}"${selected(p.id, item.type)}>${esc(p.name)}</option>`).join('')}
            </select>
          </label>

          <label>
            落地服务器地址 (IP 或域名)
            <input name="server" id="out-f-server" value="${esc(item.server || '')}" placeholder="输入落地机 IP 或域名" required>
          </label>
          <label>
            落地服务器端口 (Port)
            <input name="port" id="out-f-port" type="number" min="1" max="65535" value="${esc(item.port || 443)}" required>
          </label>

          <label>
            备注说明 (可选)
            <input name="remark" id="out-f-remark" value="${esc(item.remark)}" placeholder="默认与标签 Tag 相同">
          </label>
          <label>
            前置链式代理 (Detour 多跳中转)
            <select name="detour" id="out-f-detour">${detourOpts}</select>
          </label>

          <div class="section-title">凭据与加密参数 (按所选协议填写对应项)</div>
          <label>
            密码 / 密钥 (SS / HY2 / AnyTLS / Trojan / SOCKS5)
            <input name="password" id="out-f-password" value="${esc(item.password || '')}" placeholder="连接密码或 Base64 密钥">
          </label>
          <label>
            Shadowsocks 加密方式
            <select name="method" id="out-f-method">
              ${state.catalog.ssMethods.map((m) => `<option value="${esc(m.id)}"${selected(m.id, item.method)}>${esc(m.label)}</option>`).join('')}
            </select>
          </label>

          <label>
            UUID (VLESS / VMess / TUIC)
            <input name="uuid" id="out-f-uuid" value="${esc(item.uuid || '')}" placeholder="标准 UUID">
          </label>
          <label>
            SOCKS5 / HTTP 用户名 (可选)
            <input name="username" id="out-f-username" value="${esc(item.username || '')}" placeholder="用户名">
          </label>

          <div class="section-title">TLS / Reality / 传输层参数 (可选)</div>
          <label>
            传输安全 (Security)
            <select name="security" id="out-f-security">
              <option value="none"${selected('none', item.security)}>无 (None · SS/SOCKS/明文)</option>
              <option value="tls"${selected('tls', item.security)}>TLS (AnyTLS / HY2 / Trojan / VLESS-TLS)</option>
              <option value="reality"${selected('reality', item.security)}>Reality (VLESS Reality 落地)</option>
            </select>
          </label>
          <label>
            传输协议 (Transport)
            <select name="transport" id="out-f-transport">
              <option value="tcp"${selected('tcp', item.transport)}>TCP / QUIC 原生</option>
              <option value="ws"${selected('ws', item.transport)}>WebSocket (WS)</option>
              <option value="grpc"${selected('grpc', item.transport)}>gRPC</option>
            </select>
          </label>
          <label>
            SNI 域名 (Server Name)
            <input name="sni" id="out-f-sni" value="${esc(item.sni || '')}" placeholder="TLS 或 Reality 的 SNI">
          </label>
          <label>
            Reality 公钥 (Public Key) / ShortId
            <div class="input-row">
              <input name="publicKey" id="out-f-pbk" value="${esc(item.publicKey || '')}" placeholder="pbk 公钥">
              <input name="shortId" id="out-f-sid" value="${esc(item.shortId || '')}" placeholder="sid" style="max-width:100px">
            </div>
          </label>

          <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
            <input type="checkbox" name="insecure" id="out-f-insecure" style="width:16px;min-height:16px" ${item.insecure ? 'checked' : ''}>
            <span>跳过落地节点 TLS 证书校验 (insecure=true，当落地节点使用自签证书时勾选)</span>
          </label>
        </div>

        <div id="out-json-pane" class="wide hidden">
          <label>
            Sing-box 出站 JSON 配置 (可直接查看或编辑)
            <textarea id="out-json-textarea" style="min-height:260px">${esc(previewJson)}</textarea>
          </label>
        </div>

        <div class="form-actions">
          <button type="button" data-close>取消</button>
          <button type="submit" class="primary">确定保存出站规则</button>
        </div>
      </form>
    </div>
    `
  );
}

function openRuleModal(existing = null) {
  const r = existing || {
    remark: '',
    inbound: [],
    user: [],
    domain: [],
    domain_suffix: [],
    domain_keyword: [],
    ip_cidr: [],
    source_ip_cidr: [],
    port: [],
    source_port: [],
    protocol: [],
    network: '',
    rule_set: [],
    ip_is_private: false,
    outbound: state.outbounds.find((o) => !o.builtin)?.tag || 'direct'
  };

  const outboundOpts = state.outbounds
    .map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, r.outbound)}>${esc(o.tag)}${o.server ? ` (${o.server}:${o.port})` : ` (${o.remark})`}</option>`)
    .join('');

  const inboundChecks = state.inbounds.map((i) => {
    const isChecked = (r.inbound || []).includes(i.tag) ? 'checked' : '';
    return `<label style="flex-direction:row;align-items:center;gap:6px;font-weight:500"><input type="checkbox" name="inbound_check" value="${esc(i.tag)}" style="width:15px;min-height:15px" ${isChecked}><span><code>${esc(i.tag)}</code> (${esc(i.remark)} :${i.port})</span></label>`;
  }).join('');

  openModal(
    existing ? '编辑路由规则' : '添加路由规则',
    existing ? (r.remark || `规则 -> ${r.outbound}`) : '配置入站转发映射或域名/IP分流规则',
    `
    <form id="rule-form" class="form-grid" data-id="${esc(existing?.id || '')}">
      <label class="wide">
        选择要转发的入站标签 (Inbound Tags · 可多选)
        <div style="display:grid;grid-template-columns:repeat(2,1fr);gap:8px;padding:10px;border:1px solid var(--line);border-radius:9px;background:var(--surface-soft);max-height:140px;overflow:auto">
          ${inboundChecks || '<span class="muted">当前尚无入站节点，也可以在下方手动输入入站 Tag</span>'}
        </div>
        <input name="inbound" value="${esc((r.inbound || []).join(', '))}" placeholder="或手动输入入站标签，逗号分隔" style="margin-top:4px">
      </label>

      <label>
        目标出站标签 (Outbound Tag)
        <select name="outbound">${outboundOpts}</select>
      </label>
      <label>
        规则备注 (可选)
        <input name="remark" value="${esc(r.remark)}" placeholder="留空自动按 入站 ➔ 出站 生成">
      </label>

      <div class="section-title">高级匹配条件 (一对一中转无需填写以下项，留空即转发该入站全部流量)</div>
      <label>
        来源 IP (Source IPs)
        <input name="source_ip_cidr" value="${esc((r.source_ip_cidr || []).join(', '))}" placeholder="e.g. 0.0.0.0/8, fc00::/7">
      </label>
      <label>
        来源端口 (Source Port)
        <input name="source_port" value="${esc((r.source_port || []).join(', '))}" placeholder="e.g. 53,443,1000-2000">
      </label>

      <label>
        网络 (Network L4)
        <select name="network">
          <option value=""${selected('', r.network)}>TCP + UDP (不限)</option>
          <option value="tcp"${selected('tcp', r.network)}>TCP</option>
          <option value="udp"${selected('udp', r.network)}>UDP</option>
        </select>
      </label>
      <label>
        嗅探协议 (Protocol，逗号分隔)
        <input name="protocol" value="${esc((r.protocol || []).join(', '))}" placeholder="http, tls, bittorrent, quic">
      </label>

      <label>
        目标 IP (IP / GeoIP)
        <input name="ip_cidr" value="${esc((r.ip_cidr || []).join(', '))}" placeholder="e.g. geoip:cn, 1.1.1.0/24">
      </label>
      <label>
        目标域名后缀 (Domain Suffix / Geosite)
        <input name="domain" value="${esc([...(r.domain || []), ...(r.domain_suffix || [])].join(', '))}" placeholder="e.g. openai.com, google.com, geosite:openai">
      </label>

      <label>
        目标端口 (Port)
        <input name="port" value="${esc((r.port || []).join(', '))}" placeholder="e.g. 53, 443, 1000-2000">
      </label>
      <label>
        客户/用户 (User Email)
        <input name="user" value="${esc((r.user || []).join(', '))}" placeholder="可选，按客户端标识匹配">
      </label>

      <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
        <input type="checkbox" name="ip_is_private" style="width:16px;min-height:16px" ${r.ip_is_private ? 'checked' : ''}>
        <span>匹配私有内网 IP 地址 (geoip:private / ip_is_private)</span>
      </label>

      <div class="form-actions">
        <button type="button" data-close>取消</button>
        <button type="submit" class="primary">保存路由规则</button>
      </div>
    </form>
    `
  );

  $$('input[name="inbound_check"]', $('#rule-form')).forEach((cb) => {
    cb.addEventListener('change', () => {
      const checkedVals = $$('input[name="inbound_check"]:checked', $('#rule-form')).map((x) => x.value);
      $('input[name="inbound"]', $('#rule-form')).value = checkedVals.join(', ');
    });
  });
}

/* ==================== EVENT DELEGATION ==================== */

document.addEventListener('click', async (e) => {
  const closeBtn = e.target.closest('[data-close]');
  if (closeBtn) { closeModal(); return; }

  const themeBtn = e.target.closest('[data-theme-toggle]');
  if (themeBtn) {
    setTheme(document.documentElement.dataset.theme === 'dark' ? 'light' : 'dark');
    return;
  }

  const navBtn = e.target.closest('#nav button[data-page]');
  if (navBtn) { setPage(navBtn.dataset.page); return; }

  const copyBtn = e.target.closest('[data-copy]');
  if (copyBtn) { copyText(copyBtn.dataset.copy, '链接/配置'); return; }

  const qrBtn = e.target.closest('[data-qr]');
  if (qrBtn) {
    const text = qrBtn.dataset.qr;
    const svg = makeQrSvg(text);
    openModal('客户端扫码导入', '使用 Shadowrocket / v2rayNG / NekoBox / Sing-box / Clash 扫码', `
      <div class="subscription-qr">${svg || '<p class="muted">二维码生成中</p>'}<p class="muted" style="margin-top:10px;font-size:11px;word-break:break-all">${esc(text)}</p></div>
    `);
    return;
  }

  const qrInlineBtn = e.target.closest('[data-qr-inline]');
  if (qrInlineBtn) {
    const box = $(`#${qrInlineBtn.dataset.qrInline}`);
    if (box) {
      box.classList.toggle('hidden');
      if (!box.classList.contains('hidden') && !box.innerHTML.trim() && qrInlineBtn.dataset.qrText) {
        box.innerHTML = makeQrSvg(qrInlineBtn.dataset.qrText);
      }
    }
    return;
  }

  const actEl = e.target.closest('[data-action]');
  if (!actEl) return;
  const action = actEl.dataset.action;

  try {
    if (action === 'jump-migrate') { setPage('migrate'); }
    else if (action === 'Switch-to-outbounds') { setPage('outbounds'); }
    else if (action === 'Switch-to-routing') { setPage('routing'); }
    else if (action === 'filter-proto') {
      state.protoFilter = actEl.dataset.proto || 'all';
      render();
    }
    else if (action === 'batch-inbounds') {
      const batchAct = actEl.dataset.batch;
      if (batchAct === 'reset-all-traffic' && !confirm('确定要一键清零全部入站节点的已用流量吗？')) return;
      const res = await api('/api/inbounds/batch', {
        method: 'POST',
        body: JSON.stringify({ action: batchAct })
      });
      toast(`批量操作已完成 (共处理 ${res.count || 0} 个节点)`);
      load('inbounds');
    }
    else if (action === 'cleanup-system-memory') {
      const res = await api('/api/system/cleanup', { method: 'POST' });
      if (state.overview && res.system) state.overview.system = res.system;
      toast(`🧹 已完成日志清理与内存释放 (${(res.result?.actions || []).join(', ')})`);
      render();
    }
    else if (action === 'open-aggregate-qr-modal') {
      if (!state.inbounds.length || !state.settings?.subToken) {
        const data = await api('/api/inbounds');
        state.inbounds = data.inbounds || [];
        if (data.settings) state.settings = data.settings;
      }
      openAggregateQrModal();
    }
    else if (action === 'set-expiry') {
      const days = Number(actEl.dataset.days || 0);
      const input = $('#inb-expiry-input');
      if (input) {
        if (days <= 0) {
          input.value = '';
        } else {
          input.value = toDatetimeLocalValue(Date.now() + days * 86400000);
        }
      }
    }
    else if (action === 'switch-out-tab') {
      const tab = actEl.dataset.tab;
      const formPane = $('#out-form-pane');
      const jsonPane = $('#out-json-pane');
      const formBtn = $('#out-tab-form-btn');
      const jsonBtn = $('#out-tab-json-btn');
      if (tab === 'json') {
        const curObj = {
          type: $('#out-f-type')?.value || 'shadowsocks',
          tag: $('#out-f-tag')?.value || 'outbound-1',
          server: $('#out-f-server')?.value || '127.0.0.1',
          server_port: Number($('#out-f-port')?.value || 443)
        };
        if ($('#out-f-password')?.value) curObj.password = $('#out-f-password').value;
        if (curObj.type === 'shadowsocks') curObj.method = $('#out-f-method')?.value || 'aes-128-gcm';
        if ($('#out-f-uuid')?.value) curObj.uuid = $('#out-f-uuid').value;
        if ($('#out-f-username')?.value) curObj.username = $('#out-f-username').value;
        if ($('#out-f-detour')?.value) curObj.detour = $('#out-f-detour').value;
        if ($('#out-json-textarea')) $('#out-json-textarea').value = JSON.stringify(curObj, null, 2);
        formPane?.classList.add('hidden');
        jsonPane?.classList.remove('hidden');
        formBtn?.classList.remove('primary');
        jsonBtn?.classList.add('primary');
      } else {
        try {
          const parsed = JSON.parse($('#out-json-textarea')?.value || '{}');
          if (parsed.tag && $('#out-f-tag')) $('#out-f-tag').value = parsed.tag;
          if ((parsed.type || parsed.protocol) && $('#out-f-type')) {
            const pType = (parsed.type || parsed.protocol).toLowerCase();
            $('#out-f-type').value = pType === 'freedom' ? 'direct' : (pType === 'blackhole' ? 'block' : pType);
          }
          if (parsed.server && $('#out-f-server')) $('#out-f-server').value = parsed.server;
          if (parsed.server_port && $('#out-f-port')) $('#out-f-port').value = parsed.server_port;
          if (parsed.password && $('#out-f-password')) $('#out-f-password').value = parsed.password;
          if (parsed.method && $('#out-f-method')) $('#out-f-method').value = parsed.method;
          if (parsed.uuid && $('#out-f-uuid')) $('#out-f-uuid').value = parsed.uuid;
        } catch { /* ignore */ }
        jsonPane?.classList.add('hidden');
        formPane?.classList.remove('hidden');
        jsonBtn?.classList.remove('primary');
        formBtn?.classList.add('primary');
      }
    }
    else if (action === 'parse-uri-into-outbound-modal') {
      const uri = $('#out-modal-uri-input')?.value.trim();
      if (!uri) { toast('请先粘贴节点链接 (ss://, vless://, vmess://, trojan://, hy2:// 等)', true); return; }
      const res = await api('/api/outbounds/parse-uri', { method: 'POST', body: JSON.stringify({ uri }) });
      const o = res.outbound;
      if ($('#out-f-tag')) $('#out-f-tag').value = o.tag || '';
      if ($('#out-f-type')) $('#out-f-type').value = o.type || 'shadowsocks';
      if ($('#out-f-server')) $('#out-f-server').value = o.server || '';
      if ($('#out-f-port')) $('#out-f-port').value = o.port || 443;
      if ($('#out-f-remark')) $('#out-f-remark').value = o.remark || '';
      if ($('#out-f-password')) $('#out-f-password').value = o.password || '';
      if (o.method && $('#out-f-method')) $('#out-f-method').value = o.method;
      if ($('#out-f-uuid')) $('#out-f-uuid').value = o.uuid || '';
      if ($('#out-f-username')) $('#out-f-username').value = o.username || '';
      if ($('#out-f-security')) $('#out-f-security').value = o.security || 'none';
      if ($('#out-f-transport')) $('#out-f-transport').value = o.transport || 'tcp';
      if ($('#out-f-sni')) $('#out-f-sni').value = o.sni || '';
      if ($('#out-f-pbk')) $('#out-f-pbk').value = o.publicKey || '';
      if ($('#out-f-sid')) $('#out-f-sid').value = o.shortId || '';
      if ($('#out-f-insecure')) $('#out-f-insecure').checked = Boolean(o.insecure);
      if ($('#out-json-textarea')) $('#out-json-textarea').value = JSON.stringify(res.singboxPreview, null, 2);
      toast(`已解析填入: ${o.tag} (${o.server}:${o.port})`);
    }
    else if (action === 'enable-bbr-hy2') {
      const res = await api('/api/system/acceleration', { method: 'POST', body: JSON.stringify({ mode: 'all' }) });
      toast(`🚀 已启用内核加速 (${res.acceleration?.congestion} + ${res.acceleration?.qdisc})`);
      load('overview');
    }
    else if (action === 'open-firewall-ports') {
      const res = await api('/api/system/firewall', { method: 'POST' });
      toast(`🛡 已自动放行端口: ${(res.openedPorts || []).join(', ')}`);
    }
    else if (action === 'quick-add-inbound' || action === 'add-inbound') { openInboundModal(); }
    else if (action === 'quick-inbound') { openInboundModal(null, actEl.dataset.preset); }
    else if (action === 'copy-all-links') {
      const allUris = state.inbounds.flatMap((i) => (i.links || []).map((l) => l.uri));
      if (!allUris.length) { toast('当前暂无可复制的节点链接', true); return; }
      copyText(allUris.join('\n'), `全部 ${allUris.length} 条节点链接`);
    }
    else if (action === 'edit-inbound') {
      const inb = state.inbounds.find((x) => x.id === actEl.dataset.id);
      if (inb) openInboundModal(inb);
    }
    else if (action === 'inbound-links') {
      const inb = state.inbounds.find((x) => x.id === actEl.dataset.id);
      if (inb) openInboundLinksModal(inb);
    }
    else if (action === 'reset-inbound-traffic') {
      await api(`/api/inbounds/${actEl.dataset.id}/reset-traffic`, { method: 'POST' });
      toast('入站节点流量已重置');
      load('inbounds');
    }
    else if (action === 'toggle-inbound') {
      await api(`/api/inbounds/${actEl.dataset.id}/toggle`, { method: 'POST' });
      toast('入站节点状态已切换');
      load('inbounds');
    }
    else if (action === 'delete-inbound') {
      if (!confirm('确认删除该入站节点？')) return;
      await api(`/api/inbounds/${actEl.dataset.id}`, { method: 'DELETE' });
      toast('入站节点已删除');
      load('inbounds');
    }
    else if (action === 'inb-rand-port') {
      const input = $('#inb-port-input');
      if (input) input.value = Math.floor(Math.random() * 40000) + 15000;
    }
    else if (action === 'gen-uuid') {
      const input = $('#inb-uuid-input');
      if (input) input.value = genUuidClient();
      toast('已生成新的标准 UUID');
    }
    else if (action === 'gen-clean-pass') {
      const target = $(`#${actEl.dataset.target}`);
      if (target) target.value = genRandomAlnum(20);
    }
    else if (action === 'gen-reality-keys') {
      const kp = await api('/api/tools/reality-keypair', { method: 'POST' });
      if ($('#inb-reality-priv')) $('#inb-reality-priv').value = kp.privateKey;
      if ($('#inb-reality-pub')) $('#inb-reality-pub').value = kp.publicKey;
      if ($('#inb-reality-sid')) $('#inb-reality-sid').value = kp.shortId;
      toast('已生成新的 Reality X25519 密钥对');
    }
    else if (action === 'gen-ss-key') {
      const method = $('#inb-ss-method')?.value || '2022-blake3-aes-128-gcm';
      const sk = await api('/api/tools/ss-key', { method: 'POST', body: JSON.stringify({ method }) });
      if ($('#inb-ss-pass')) $('#inb-ss-pass').value = sk.password;
      toast('已生成标准长度密钥');
    }
    else if (action === 'add-outbound') { openOutboundModal(); }
    else if (action === 'edit-outbound') {
      const out = state.outbounds.find((x) => x.id === actEl.dataset.id);
      if (out) openOutboundModal(out);
    }
    else if (action === 'reset-outbound-traffic') {
      await api(`/api/outbounds/${actEl.dataset.id}/reset-traffic`, { method: 'POST' });
      toast('出站流量统计已清零');
      load('outbounds');
    }
    else if (action === 'ping-outbound') {
      const id = actEl.dataset.id;
      const res = await api(`/api/outbounds/${id}/ping`, { method: 'POST' });
      state.outboundPings[id] = res;
      if (res.reachable) toast(`出站连通正常: ${res.latencyMs} ms`);
      else toast(`出站连接失败: ${res.error}`, true);
      render();
    }
    else if (action === 'ping-all-outbounds') {
      const targets = state.outbounds.filter((o) => !o.builtin && o.server);
      if (!targets.length) { toast('暂无可测速的远程出站节点', true); return; }
      toast('正在并发检测全部出站节点延迟...');
      await Promise.all(targets.map(async (o) => {
        try {
          state.outboundPings[o.id] = await api(`/api/outbounds/${o.id}/ping`, { method: 'POST' });
        } catch (err) {
          state.outboundPings[o.id] = { reachable: false, error: err.message };
        }
      }));
      toast('全部出站延迟检测完成');
      render();
    }
    else if (action === 'delete-outbound') {
      if (!confirm('确认删除该出站节点？')) return;
      await api(`/api/outbounds/${actEl.dataset.id}`, { method: 'DELETE' });
      toast('出站节点已删除');
      load('outbounds');
    }
    else if (action === 'import-outbound-uri') {
      openModal('批量导入外部节点作为中转出站', '支持一次粘贴单条或多条分享链接 (每行一条)', `
        <form id="import-uri-form" class="form-grid">
          <label class="wide">
            节点分享链接 (支持 ss://, socks://, socks5://, vless://, hysteria2://, hy2://, anytls://, trojan://, vmess://, tuic://)
            <textarea name="uri" style="min-height:160px" placeholder="可一次粘贴多条节点链接（每行一条），将自动提取节点名称作为出站标签 Tag" required></textarea>
          </label>
          <label>自定义标签前缀 (可选，单条时为完整 Tag)<input name="tag" placeholder="留空自动使用链接内节点名"></label>
          <label>自定义备注前缀 (可选)<input name="remark" placeholder="留空自动使用链接内节点名"></label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">解析并导入至出站列表</button>
          </div>
        </form>
      `);
    }
    else if (action === 'quick-add-relay-rule') {
      const inbTag = $('#quick-relay-inbound')?.value;
      const outTag = $('#quick-relay-outbound')?.value;
      if (!inbTag || !outTag) {
        toast('请先选择入站标签与目标出站', true);
        return;
      }
      await api('/api/routing/rules', {
        method: 'POST',
        body: JSON.stringify({
          remark: `入站转发: ${inbTag} ➔ ${outTag}`,
          inbound: [inbTag],
          outbound: outTag
        })
      });
      toast(`已绑定转发规则: ${inbTag} ➔ ${outTag}`);
      load('routing');
    }
    else if (action === 'save-routing-global') {
      const finalOut = $('#routing-final-select')?.value || 'direct';
      await api('/api/routing', { method: 'PUT', body: JSON.stringify({ final: finalOut }) });
      toast('默认兜底出站已保存');
      load('routing');
    }
    else if (action === 'add-rule') { openRuleModal(); }
    else if (action === 'edit-rule') {
      const r = (state.routing.rules || []).find((x) => x.id === actEl.dataset.id);
      if (r) openRuleModal(r);
    }
    else if (action === 'delete-rule') {
      const r = (state.routing.rules || []).find((x) => x.id === actEl.dataset.id);
      const label = r?.remark || (r?.inbound?.length ? `${r.inbound.join(', ')} ➔ ${r.outbound}` : actEl.dataset.id);
      if (!confirm(`确认删除路由转发规则「${label}」吗？`)) return;
      await api(`/api/routing/rules/${actEl.dataset.id}`, { method: 'DELETE' });
      toast('路由规则已删除');
      load('routing');
    }
    else if (action === 'move-rule') {
      await api(`/api/routing/rules/${actEl.dataset.id}/move`, {
        method: 'POST',
        body: JSON.stringify({ direction: actEl.dataset.dir })
      });
      load('routing');
    }
    else if (action === 'routing-preset') {
      const preset = actEl.dataset.preset;
      if (preset === '3xui-default' && !confirm('确认恢复默认防探测/禁BT规则吗？（将保留入站一对一中转规则，移除其他自定义分流规则）')) return;
      const selOut = $('#quick-relay-outbound')?.value;
      const customOut = (selOut && selOut !== 'direct')
        ? selOut
        : (state.outbounds.find((o) => !o.builtin)?.tag || 'direct');
      await api('/api/routing/presets', {
        method: 'POST',
        body: JSON.stringify({ preset, outbound: customOut })
      });
      toast(`已应用分流预设 (${preset})`);
      load('routing');
    }
    else if (action === 'sb-control') {
      const cmd = actEl.dataset.cmd;
      const res = await api('/api/singbox/control', { method: 'POST', body: JSON.stringify({ action: cmd }) });
      if (cmd === 'check') {
        if (res.result.valid) toast('✅ Sing-box 配置文件校验通过 (0 错误 0 警告)');
        else toast(`❌ 配置校验失败: ${res.result.error}`, true);
      } else {
        toast(`Sing-box 操作已执行 (${cmd})`);
      }
      load('overview');
    }
    else if (action === 'sb-logs') {
      const data = await api('/api/singbox/logs');
      openModal('Sing-box 实时运行日志', `当前状态: ${data.status?.state || '未知'}`, `<div class="codebox">${esc((data.logs || []).join('\n'))}</div>`);
    }
    else if (action === 'sb-config-preview') {
      const data = await api('/api/singbox/config');
      const jsonStr = JSON.stringify(data.config, null, 2);
      openModal('Sing-box 完整配置文件预览', data.status?.configPath || 'config.json', `
        <div class="stack">
          <div class="codebox">${esc(jsonStr)}</div>
          <div style="display:flex;justify-content:flex-end"><button class="primary" data-copy="${esc(jsonStr)}">复制完整 JSON 配置</button></div>
        </div>
      `);
    }
    else if (action === 'sb-switch-version') {
      const custom = $('#sb-version-custom')?.value.trim();
      const sel = $('#sb-version-select')?.value;
      const version = custom || sel || 'v1.12.23';
      toast(`正在下载并切换 Sing-box 内核至 ${version}...`);
      const res = await api('/api/singbox/version', { method: 'POST', body: JSON.stringify({ version }) });
      toast(`成功切换内核版本: ${res.version?.version || version}`);
      load('overview');
    }
    else if (action === 'preview-xui-file' || action === 'apply-xui-file') {
      const fileInput = $('#xui-db-file');
      const file = fileInput?.files?.[0];
      if (!file) { toast('请先选择要上传的 x-ui.db 或 .tar.gz 备份文件', true); return; }
      const mode = $('#migrate-mode')?.value || 'merge';
      const dryRun = action === 'preview-xui-file';
      const buf = await file.arrayBuffer();
      const res = await api(`/api/migrate/3xui?mode=${mode}&dryRun=${dryRun}`, {
        method: 'POST',
        headers: { 'content-type': 'application/octet-stream' },
        body: buf
      });
      if (dryRun) {
        state.migrationPreview = res;
        toast(`解析成功: 发现 ${res.summary.inboundsCount} 个入站与 ${res.summary.outboundsCount} 个出站`);
        render();
      } else {
        state.migrationPreview = null;
        const certMsg = res.summary?.restoredCertsCount ? `、${res.summary.restoredCertsCount} 张 SSL 证书` : '';
        toast(`🎉 备份迁移完成: 已导入 ${res.summary.inboundsCount} 个入站、${res.summary.outboundsCount} 个出站、${res.summary.rulesCount} 条规则${certMsg}！`);
        load('migrate');
      }
    }
    else if (action === 'migrate-local-xui') {
      const dbPath = $('#local-xui-path')?.value.trim() || '/etc/x-ui/x-ui.db';
      const mode = $('#migrate-mode')?.value || 'merge';
      const res = await api(`/api/migrate/3xui?mode=${mode}`, {
        method: 'POST',
        body: JSON.stringify({ source: 'local', dbPath })
      });
      const certMsg = res.summary?.restoredCertsCount ? `、${res.summary.restoredCertsCount} 张 SSL 证书` : '';
      toast(`🎉 本机备份数据迁移完成: 入站 ${res.summary.inboundsCount} 个，出站 ${res.summary.outboundsCount} 个${certMsg}`);
      load('migrate');
    }
    else if (action === 'preview-xui-json' || action === 'apply-xui-json') {
      const raw = $('#xui-json-input')?.value.trim();
      if (!raw) { toast('请粘贴配置 JSON 内容', true); return; }
      const mode = $('#migrate-mode')?.value || 'merge';
      const dryRun = action === 'preview-xui-json';
      const res = await api(`/api/migrate/3xui?mode=${mode}&dryRun=${dryRun}`, {
        method: 'POST',
        body: JSON.stringify({ jsonPayload: raw })
      });
      if (dryRun) {
        state.migrationPreview = res;
        toast(`JSON 解析成功: ${res.summary.inboundsCount} 个入站`);
        render();
      } else {
        state.migrationPreview = null;
        toast('🎉 从 JSON 备份迁移完成！');
        load('migrate');
      }
    }
    else if (action === 'cert-selfsigned') {
      openModal('一键生成 10 年自签 SSL 证书', '仅在无域名时使用；若已有真实域名建议使用 ACME 申请', `
        <form id="cert-selfsigned-form" class="form-grid">
          <label class="wide">
            自签域名标识 (Common Name / SAN)
            <input name="domain" value="${esc(state.settings.webDomain || 'www.apple.com')}" required>
            <small>自动包含本机公网 IPv4 作为 SAN 扩展</small>
          </label>
          <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
            <input type="checkbox" name="applyToPanel" style="width:16px;min-height:16px" checked>
            <span>同时绑定为面板 HTTPS 登录证书与节点默认证书</span>
          </label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">立即生成 10 年证书并绑定</button>
          </div>
        </form>
      `);
    }
    else if (action === 'cert-acme') {
      openModal('ACME 自动申请受信任证书', '签发后自动替换自签证书，并设为面板 HTTPS 与全部 TLS 节点默认证书', `
        <form id="cert-acme-form" class="form-grid">
          <label>
            申请域名或公网 IP
            <input name="domain" placeholder="填写已解析到本机的域名" required>
          </label>
          <label>
            通知邮箱 (可选)
            <input name="email" placeholder="admin@example.com">
          </label>
          <label class="wide">
            申请模式
            <select name="mode">
              <option value="standalone">1. 域名 HTTP-01 模式 (需本机 80 端口放行且域名已解析到本机)</option>
              <option value="cf">2. Cloudflare DNS API 模式 (无需 80 端口，支持泛域名)</option>
              <option value="ip">3. Let's Encrypt 短期 IP 证书模式 (无需域名，直接为公网 IP 签发受信任证书)</option>
            </select>
          </label>
          <label>
            Cloudflare API Token (仅 CF 模式选填)
            <input name="cfToken" type="password" placeholder="CF_Token (Edit zone DNS)">
          </label>
          <label>
            或 CF Global API Key + 邮箱 (仅 CF 模式选填)
            <div class="input-row">
              <input name="cfKey" type="password" placeholder="CF_Key">
              <input name="cfEmail" placeholder="CF 账号邮箱">
            </div>
          </label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">开始签发并一键绑定面板与节点</button>
          </div>
        </form>
      `);
    }
    else if (action === 'cert-custom') {
      openModal('导入或粘贴自定义 SSL 证书', '支持粘贴 PEM 内容或指定服务器已有证书路径', `
        <form id="cert-custom-form" class="form-grid">
          <label class="wide">
            域名标识名称
            <input name="domain" placeholder="填写证书对应的域名" required>
          </label>
          <label>
            方式 A: 服务器已有公钥路径 (可选)
            <input name="certPath" placeholder="/root/cert/example.com/fullchain.pem">
          </label>
          <label>
            方式 A: 服务器已有私钥路径 (可选)
            <input name="keyPath" placeholder="/root/cert/example.com/privkey.pem">
          </label>
          <label class="wide">
            方式 B: 直接粘贴证书公钥内容 (fullchain.pem)
            <textarea name="certPem" placeholder="-----BEGIN CERTIFICATE-----..."></textarea>
          </label>
          <label class="wide">
            方式 B: 直接粘贴证书私钥内容 (privkey.pem)
            <textarea name="keyPem" placeholder="-----BEGIN PRIVATE KEY-----..."></textarea>
          </label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">保存并一键绑定面板与节点</button>
          </div>
        </form>
      `);
    }
    else if (action === 'bind-cert-all') {
      await api('/api/certificates/bind-all', {
        method: 'POST',
        body: JSON.stringify({ id: actEl.dataset.id })
      });
      toast('已设为面板 HTTPS 与全部 TLS 节点的默认通用证书！');
      load('certificates');
    }
    else if (action === 'delete-cert') {
      if (!confirm('确认移除该证书记录吗？')) return;
      await api(`/api/certificates/${actEl.dataset.id}`, { method: 'DELETE' });
      toast('证书记录已移除');
      load('certificates');
    }
    else if (action === 'random-port') {
      const el = $('#setting-webport');
      if (el) el.value = Math.floor(Math.random() * 45000) + 15000;
    }
    else if (action === 'random-path') {
      const el = $('#setting-webpath');
      if (el) el.value = `/${genRandomAlnum(16)}/`;
    }
    else if (action === 'reset-path') {
      const el = $('#setting-webpath');
      if (el) el.value = '/';
    }
    else if (action === 'random-sub-token') {
      const el = $('#setting-subtoken');
      if (el) el.value = genRandomAlnum(20);
      toast('已生成新的 20 位聚合订阅安全码，点击下方【保存面板设置】生效');
    }
    else if (action === 'random-account-user') {
      const el = $('#account-user-input');
      if (el) el.value = `ng_${genRandomAlnum(10)}`;
    }
    else if (action === 'random-account-pass') {
      const el = $('#account-pass-input');
      if (el) el.value = genRandomAlnum(18);
    }
    else if (action === 'restore-backup-modal') {
      openModal('导入恢复面板备份', '粘贴备份 JSON 内容', `
        <form id="restore-backup-form" class="form-grid">
          <label class="wide">
            备份 JSON 内容
            <textarea name="backupJson" style="min-height:200px" required placeholder='粘贴导出的 nexusgate-backup.json 内容'></textarea>
          </label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">立即恢复备份</button>
          </div>
        </form>
      `);
    }
  } catch (err) {
    toast(err.message, true);
  }
});

document.addEventListener('change', (e) => {
  if (e.target.id === 'inb-reality-preset' && e.target.value) {
    const opt = e.target.selectedOptions[0];
    if ($('#inb-reality-sni')) $('#inb-reality-sni').value = e.target.value;
    if ($('#inb-reality-target')) $('#inb-reality-target').value = opt.dataset.target || `${e.target.value}:443`;
  }
  if (e.target.id === 'inb-cert-select' && e.target.value) {
    const opt = e.target.selectedOptions[0];
    if ($('#inb-tls-domain')) $('#inb-tls-domain').value = e.target.value;
    if ($('#inb-cert-path')) $('#inb-cert-path').value = opt.dataset.cert || '';
    if ($('#inb-key-path')) $('#inb-key-path').value = opt.dataset.key || '';
  }
  if (e.target.id === 'setting-cert-picker' && e.target.value) {
    const [cPath, kPath, cDomain] = e.target.value.split('|');
    if ($('#setting-cert-file')) $('#setting-cert-file').value = cPath || '';
    if ($('#setting-key-file')) $('#setting-key-file').value = kPath || '';
    if (cDomain && cDomain !== 'www.apple.com' && $('#setting-webdomain')) {
      $('#setting-webdomain').value = cDomain;
    }
  }
  if (e.target.id === 'xui-db-file' && e.target.files?.[0]) {
    const lbl = $('#xui-file-label');
    if (lbl) lbl.textContent = `已选择文件: ${e.target.files[0].name} (${fmtBytes(e.target.files[0].size)})`;
  }
});

document.addEventListener('input', (e) => {
  if (e.target.matches('[data-search]')) {
    state.search = e.target.value;
    const pos = e.target.selectionStart;
    render();
    const nextInput = $('[data-search]');
    if (nextInput) {
      nextInput.focus();
      nextInput.setSelectionRange(pos, pos);
    }
  }
});

document.addEventListener('submit', async (e) => {
  const form = e.target;
  e.preventDefault();
  const fd = new FormData(form);
  const data = Object.fromEntries(fd.entries());

  try {
    if (form.id === 'login-form') {
      $('#login-error').textContent = '';
      state.session = await api('/api/auth/login', { method: 'POST', body: JSON.stringify(data) });
      showApp();
      setPage('overview');
    }
    else if (form.id === 'inbound-form') {
      const id = form.dataset.id;
      const expiryMs = data.expiryTime ? Date.parse(data.expiryTime) : 0;
      const payload = {
        remark: data.remark,
        protocol: data.protocol,
        listen: data.listen,
        port: Number(data.port),
        limitIp: Number(data.limitIp || 0),
        limitDevice: Number(data.limitDevice || 0),
        totalGB: Number(data.totalGB || 0),
        resetDay: Number(data.resetDay || 0),
        expiryTime: Number.isFinite(expiryMs) && expiryMs > 0 ? expiryMs : 0,
        outboundTag: data.outboundTag,
        security: data.security || (['anytls', 'hysteria2', 'tuic'].includes(data.protocol) ? 'tls' : 'none'),
        transport: data.transport || 'tcp',
        flow: data.flow || '',
        method: data.method,
        password: data.password,
        socksUser: data.socksUser,
        socksPassword: data.socksPassword,
        upMbps: data.upMbps ? Number(data.upMbps) : undefined,
        downMbps: data.downMbps ? Number(data.downMbps) : undefined,
        obfsPassword: data.obfsPassword,
        tlsDomain: data.tlsDomain,
        certPath: data.certPath,
        keyPath: data.keyPath,
        wsPath: data.wsPath,
        wsHost: data.wsHost,
        grpcServiceName: data.grpcServiceName,
        overrideAddress: data.overrideAddress,
        overridePort: data.overridePort ? Number(data.overridePort) : undefined,
        network: data.network,
        uuid: data.uuid,
        clientEmail: data.clientEmail
      };
      if (payload.security === 'reality') {
        payload.reality = {
          serverName: data.realityServerName,
          target: data.realityTarget,
          privateKey: data.realityPrivateKey,
          publicKey: data.realityPublicKey,
          shortIds: data.realityShortIds
        };
      }
      if (id) {
        await api(`/api/inbounds/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
        toast('入站节点已更新并重载配置');
      } else {
        await api('/api/inbounds', { method: 'POST', body: JSON.stringify(payload) });
        toast('入站节点已创建并生效');
      }
      closeModal();
      load('inbounds');
    }
    else if (form.id === 'outbound-form') {
      const id = form.dataset.id;
      const isJsonTabActive = !$('#out-json-pane')?.classList.contains('hidden');
      const payload = {
        ...data,
        insecure: form.querySelector('[name="insecure"]')?.checked || false
      };
      if (isJsonTabActive && $('#out-json-textarea')?.value.trim()) {
        payload.rawJson = $('#out-json-textarea').value.trim();
      }
      if (id) {
        await api(`/api/outbounds/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
        toast('出站规则已更新');
      } else {
        await api('/api/outbounds', { method: 'POST', body: JSON.stringify(payload) });
        toast('出站规则已添加');
      }
      closeModal();
      load('outbounds');
    }
    else if (form.id === 'import-uri-form') {
      const res = await api('/api/outbounds/import-uri', { method: 'POST', body: JSON.stringify(data) });
      toast(`已成功解析并导入 ${res.count || 1} 个出站节点`);
      closeModal();
      load('outbounds');
    }
    else if (form.id === 'rule-form') {
      const id = form.dataset.id;
      const payload = {
        ...data,
        ip_is_private: form.querySelector('[name="ip_is_private"]')?.checked || false
      };
      if (id) {
        await api(`/api/routing/rules/${id}`, { method: 'PUT', body: JSON.stringify(payload) });
        toast('路由规则已更新');
      } else {
        await api('/api/routing/rules', { method: 'POST', body: JSON.stringify(payload) });
        toast('路由规则已添加');
      }
      closeModal();
      load('routing');
    }
    else if (form.id === 'cert-selfsigned-form') {
      await api('/api/certificates/self-signed', {
        method: 'POST',
        body: JSON.stringify({
          domain: data.domain,
          applyToPanel: form.querySelector('[name="applyToPanel"]')?.checked || false
        })
      });
      toast('10 年自签 SSL 证书已生成并自动绑定！');
      closeModal();
      load('certificates');
    }
    else if (form.id === 'cert-acme-form') {
      toast('正在调用 ACME 申请证书，请稍候...');
      await api('/api/certificates/acme', { method: 'POST', body: JSON.stringify(data) });
      toast('ACME 证书签发成功并已同步绑定至面板与全部节点！');
      closeModal();
      load('certificates');
    }
    else if (form.id === 'cert-custom-form') {
      await api('/api/certificates/custom', { method: 'POST', body: JSON.stringify(data) });
      toast('自定义证书已保存并绑定！');
      closeModal();
      load('certificates');
    }
    else if (form.id === 'settings-form') {
      const payload = {
        ...data,
        strictBasePath: form.querySelector('[name="strictBasePath"]')?.checked || false
      };
      const res = await api('/api/settings', { method: 'PUT', body: JSON.stringify(payload) });
      toast('面板设置已保存');
      const nextBase = (res.settings?.webBasePath || '/').replace(/\/+$/, '');
      if (nextBase !== BASE_PATH) {
        setTimeout(() => { window.location.href = `${nextBase || ''}/`; }, 600);
      } else {
        load('settings');
      }
    }
    else if (form.id === 'account-form') {
      await api('/api/auth/account', { method: 'POST', body: JSON.stringify(data) });
      toast('管理员账号与密码已更新，请重新登录');
      showLogin();
    }
    else if (form.id === 'restore-backup-form') {
      await api('/api/restore', { method: 'POST', body: JSON.stringify({ backup: JSON.parse(data.backupJson) }) });
      toast('面板备份已恢复！');
      closeModal();
      load('settings');
    }
  } catch (err) {
    if (form.id === 'login-form') $('#login-error').textContent = err.message;
    else toast(err.message, true);
  }
});

$('#refresh')?.addEventListener('click', () => load(state.page));
$('#quick-config-btn')?.addEventListener('click', async () => {
  try {
    const data = await api('/api/singbox/config');
    const jsonStr = JSON.stringify(data.config, null, 2);
    openModal('Sing-box 完整配置文件预览', data.status?.configPath || 'config.json', `
      <div class="stack">
        <div class="codebox">${esc(jsonStr)}</div>
        <div style="display:flex;justify-content:flex-end"><button class="primary" data-copy="${esc(jsonStr)}">复制完整 JSON 配置</button></div>
      </div>
    `);
  } catch (err) { toast(err.message, true); }
});
$('#logout')?.addEventListener('click', async () => {
  await api('/api/auth/logout', { method: 'POST' }).catch(() => {});
  showLogin();
});
$('#menu-toggle')?.addEventListener('click', () => $('#app').classList.toggle('sidebar-open'));
$('#sidebar-scrim')?.addEventListener('click', () => $('#app').classList.remove('sidebar-open'));

// Boot application
(async () => {
  try {
    const savedTheme = localStorage.getItem('nexusgate-theme');
    setTheme(savedTheme || 'light');
  } catch { setTheme('light'); }

  try {
    const sess = await api('/api/auth/session');
    if (sess.authenticated) {
      state.session = sess;
      showApp();
      setPage('overview');
    } else {
      showLogin();
    }
  } catch {
    showLogin();
  }

  setInterval(() => {
    const isSearching = document.activeElement && document.activeElement.matches && document.activeElement.matches('[data-search]');
    if (state.session && !$('#modal')?.open && !isSearching && ['overview', 'inbounds', 'outbounds'].includes(state.page)) {
      load(state.page);
    }
  }, 4000);
})();
