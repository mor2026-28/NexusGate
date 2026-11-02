'use strict';

const BASE_PATH = (window.__NG_BASE_PATH__ && window.__NG_BASE_PATH__ !== '/')
  ? window.__NG_BASE_PATH__.replace(/\/+$/, '')
  : '';

const state = {
  session: null,
  page: 'overview',
  search: '',
  overview: null,
  catalog: { inboundProtocols: [], outboundProtocols: [], ssMethods: [], realityPresets: [], knownVersions: [] },
  inbounds: [],
  outbounds: [],
  routing: { final: 'direct', rules: [], ruleSets: [] },
  dns: { strategy: 'prefer_ipv4' },
  certificates: [],
  settings: {},
  admin: {},
  migrations: [],
  migrationPreview: null
};

const $ = (sel, root = document) => root.querySelector(sel);
const $$ = (sel, root = document) => [...root.querySelectorAll(sel)];
const esc = (v) => String(v == null ? '' : v).replace(/[&<>'"]/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', "'": '&#39;', '"': '&quot;' })[c]);
const selected = (v, cur) => String(v) === String(cur) ? ' selected' : '';

function fmtBytes(bytes) {
  let n = Number(bytes || 0);
  if (!Number.isFinite(n) || n <= 0) return '0 B';
  const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
  let i = 0;
  while (n >= 1024 && i < units.length - 1) { n /= 1024; i += 1; }
  return `${n >= 10 || i === 0 ? n.toFixed(0) : n.toFixed(1)} ${units[i]}`;
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

function setTheme(theme) {
  const next = theme === 'dark' ? 'dark' : 'light';
  document.documentElement.dataset.theme = next;
  try { localStorage.setItem('nexusgate-theme', next); } catch { /* ignore */ }
  const metaTheme = $('meta[name="theme-color"]');
  if (metaTheme) metaTheme.content = next === 'dark' ? '#0e1420' : '#f5f7fc';
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
    label.textContent = `Sing-box 运行中`;
  } else if (sb.state === 'error') {
    dot.classList.add('error');
    label.textContent = `Sing-box 异常`;
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
    } else if (page === 'outbounds') {
      const data = await api('/api/outbounds');
      state.outbounds = data.outbounds || [];
      state.inbounds = data.inbounds || [];
    } else if (page === 'routing') {
      const data = await api('/api/routing');
      state.routing = data.routing || { final: 'direct', rules: [] };
      state.dns = data.dns || { strategy: 'prefer_ipv4' };
      state.inbounds = data.inbounds || [];
      state.outbounds = data.outbounds || [];
    } else if (page === 'migrate') {
      const [ov, st] = await Promise.all([api('/api/overview'), api('/api/settings')]);
      state.overview = ov;
      state.migrations = st.migrations || [];
    } else if (page === 'certificates') {
      const [certs, st] = await Promise.all([api('/api/certificates'), api('/api/settings')]);
      state.certificates = certs.certificates || [];
      state.settings = st.settings || {};
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
    outbounds: '出站与中转节点',
    routing: '路由与分流规则',
    migrate: '3x-ui 无损迁移',
    certificates: 'SSL 证书与订阅',
    settings: '面板设置与安全'
  };
  $('#page-title').textContent = titles[page] || '控制台';
  $('#breadcrumb').textContent = `NEXUSGATE / ${titles[page] || ''}`;
  load(page);
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

  const metrics = [
    ['入站节点', counts.inbounds || 0, `${counts.activeInbounds || 0} 个运行中`, '#3478ee'],
    ['活跃客户端', counts.clients || 0, '独立凭据与订阅分发', '#159f70'],
    ['中转与出站', counts.outbounds || 0, `${counts.relayBindings || 0} 条入站直绑中转`, '#8a4ef7'],
    ['分流规则', counts.rules || 0, '3x-ui 风格域名/IP/协议分流', '#e8a63c'],
    ['SSL 证书', counts.certificates || 0, 'ACME 自动续签与自签证书', '#d84d61']
  ];

  const barClass = (pct) => (pct >= 88 ? 'crit' : pct >= 70 ? 'warn' : '');
  const versionOptions = (state.catalog.knownVersions || ['v1.12.23', 'v1.12.15', 'v1.12.0', 'v1.11.15'])
    .map((v) => `<option value="${esc(v)}">${esc(v)}</option>`)
    .join('');

  const auditHtml = (ov.audit || []).map((a) => `
    <div class="health-row">
      <div><b>${esc(a.action)}</b><span>${esc(a.actor)} · ${esc(a.target)}</span></div>
      <small>${fmtDate(a.at)}</small>
    </div>
  `).join('');

  return `
    ${ov.local3xuiExists ? `
      <div class="notice" style="margin-bottom:16px;display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:10px">
        <div><b>检测到本机存在 3x-ui 数据库 (/etc/x-ui/x-ui.db)</b> · 可一键无损迁移全部入站节点、客户端凭据、中转出站与分流规则到 Sing-box。</div>
        <button class="primary" data-action="jump-migrate">前往一键无损迁移 →</button>
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
            <p>${esc(sys.hostname || 'Server')} · ${esc(sys.platform || '')} · 面板内存仅占 ${fmtBytes(sys.panelMemoryBytes || 0)}</p>
          </div>
          <span class="tag">运行 ${fmtUptime(sys.uptime)}</span>
        </div>
        <div class="panel-body">
          <div class="gauge-grid">
            <div class="gauge-card">
              <div class="gauge-head"><b>CPU 负载 (${sys.cpu?.cores || 1} 核)</b><strong>${cpuPct}%</strong></div>
              <div class="gauge-bar"><i class="${barClass(cpuPct)}" style="width:${cpuPct}%"></i></div>
              <div class="gauge-sub"><span>负载: ${(sys.loads || [0, 0, 0]).join(' / ')}</span><span>${esc((sys.cpu?.model || '').slice(0, 22))}</span></div>
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

          <div style="margin-top:14px;padding-top:12px;border-top:1px solid var(--line);display:grid;grid-template-columns:repeat(3,1fr);gap:10px;font-size:12px">
            <div><span class="muted">实时速率</span><strong style="margin-top:3px">↑ ${fmtBytes(sys.netIO?.up || 0)}/s · ↓ ${fmtBytes(sys.netIO?.down || 0)}/s</strong></div>
            <div><span class="muted">累计总流量</span><strong style="margin-top:3px">↑ ${fmtBytes(sys.netTraffic?.sent || 0)} · ↓ ${fmtBytes(sys.netTraffic?.recv || 0)}</strong></div>
            <div><span class="muted">连接数 / 公网 IP</span><strong style="margin-top:3px">TCP ${sys.tcpCount || 0} / UDP ${sys.udpCount || 0} · ${esc(sys.publicIP?.ipv4 || '127.0.0.1')}</strong></div>
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
          <div class="health-row">
            <div>
              <b>当前 Sing-box 内核版本</b>
              <span>配置文件: ${esc(sb.configPath || '/etc/nexusgate/sing-box/config.json')}</span>
            </div>
            <span class="tag">${esc(sb.version || '未安装')}</span>
          </div>

          ${sb.lastError ? `<div class="notice warning">内核诊断信息: ${esc(sb.lastError)}</div>` : ''}

          <div style="display:flex;flex-wrap:wrap;gap:8px">
            <button class="primary" data-action="sb-control" data-cmd="restart">↻ 启动 / 重启内核</button>
            <button data-action="sb-control" data-cmd="stop">■ 停止内核</button>
            <button data-action="sb-control" data-cmd="check">✓ 校验配置</button>
            <button data-action="sb-logs">📋 查看运行日志</button>
            <button data-action="sb-config-preview">｛｝ 预览 Sing-box JSON</button>
          </div>

          <div style="padding-top:12px;border-top:1px solid var(--line)">
            <label>
              更换 / 升级 Sing-box 内核版本 (官方 Release 自动匹配架构下载)
              <div class="input-row" style="margin-top:4px">
                <select id="sb-version-select" style="max-width:180px">
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
        <div><h2>最近操作审计日志</h2><p>记录面板登录、节点变更、中转配置与 3x-ui 迁移事件</p></div>
        <button class="ghost" data-action="quick-add-inbound">＋ 快速新建入站节点</button>
      </div>
      <div class="panel-body">
        ${auditHtml || `<div class="empty"><b>暂无操作记录</b><span>创建节点或导入配置后将在此显示</span></div>`}
      </div>
    </section>
  `;
}

function renderInbounds() {
  const q = state.search.toLowerCase();
  const filtered = state.inbounds.filter((item) =>
    [item.remark, item.tag, item.protocol, item.port, item.outboundTag].join(' ').toLowerCase().includes(q)
  );

  const rows = filtered.map((item) => {
    const protoBadge = item.protocol.toUpperCase();
    const secBadge = item.security && item.security !== 'none' ? `<span class="tag tls">${esc(item.security.toUpperCase())}</span>` : '';
    const netBadge = item.transport && item.transport !== 'tcp' ? `<span class="tag">${esc(item.transport.toUpperCase())}</span>` : '';
    const methodBadge = item.protocol === 'shadowsocks' ? `<small>${esc(item.method)}</small>` : '';
    const directNote = item.protocol === 'direct'
      ? `<small>转发目标: ${esc(item.overrideAddress || '未设')}:${esc(item.overridePort || 0)} (${esc(item.network || 'tcp,udp')})</small>`
      : '';

    let relayHtml = `<span class="tag">默认路由</span>`;
    if (item.outboundTag && item.outboundTag !== 'default') {
      if (item.outboundTag === 'direct') {
        relayHtml = `<span class="tag tls">本地直连 (direct)</span>`;
      } else if (item.outboundTag === 'block') {
        relayHtml = `<span class="status disabled">黑洞拦截</span>`;
      } else {
        const targetOut = state.outbounds.find((o) => o.tag === item.outboundTag);
        relayHtml = `<span class="tag relay">⇄ 中转: ${esc(targetOut ? targetOut.remark : item.outboundTag)}</span>`;
      }
    }

    return `
      <tr>
        <td>
          <strong>${esc(item.remark)}</strong>
          <small>Tag: ${esc(item.tag)} · 监听: ${esc(item.listen || '::')}</small>
          ${directNote}
        </td>
        <td>
          <span class="tag">${esc(protoBadge)}</span>${secBadge}${netBadge}
          ${methodBadge}
        </td>
        <td><strong>:${esc(item.port)}</strong></td>
        <td>${relayHtml}</td>
        <td>
          <strong>${(item.clients || []).length} 个客户端</strong>
          <small>↑ ${fmtBytes(item.up)} · ↓ ${fmtBytes(item.down)}</small>
        </td>
        <td>
          <span class="status ${item.enable !== false ? 'active' : 'disabled'}">
            ${item.enable !== false ? '已启用' : '已停用'}
          </span>
        </td>
        <td>
          <div class="actions">
            ${item.protocol !== 'direct' ? `<button class="primary" data-action="inbound-links" data-id="${esc(item.id)}">链接 / 二维码</button>` : ''}
            <button data-action="edit-inbound" data-id="${esc(item.id)}">编辑</button>
            <button data-action="toggle-inbound" data-id="${esc(item.id)}">${item.enable !== false ? '停用' : '启用'}</button>
            <button class="danger" data-action="delete-inbound" data-id="${esc(item.id)}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="page-intro">
      <p>支持搭建 VLESS (Reality/TLS/WS/gRPC)、AnyTLS、Hysteria 2 (HY2)、SS AES-128/256-GCM、SS 2022 (128/256)、SOCKS5、Trojan、VMess、TUIC 及 Direct 端口转发。每个入站均可直接绑定中转出站节点。</p>
      <button class="primary" data-action="add-inbound">＋ 新建入站节点</button>
    </div>

    <div class="quick-bar">
      <span>⚡ NexusGate 快捷模板:</span>
      <button data-action="quick-inbound" data-preset="vless-reality">VLESS + Reality + Vision</button>
      <button data-action="quick-inbound" data-preset="anytls">AnyTLS (Sing-box 1.12+)</button>
      <button data-action="quick-inbound" data-preset="hysteria2">Hysteria 2 (HY2 高速 UDP)</button>
      <button data-action="quick-inbound" data-preset="ss2022-128">SS 2022 · 128-GCM</button>
      <button data-action="quick-inbound" data-preset="ss2022-256">SS 2022 · 256-GCM</button>
      <button data-action="quick-inbound" data-preset="ss-128">SS · AES-128-GCM</button>
      <button data-action="quick-inbound" data-preset="socks">SOCKS5 代理</button>
      <button data-action="quick-inbound" data-preset="direct">Direct 端口转发中转</button>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div class="toolbar">
          <input class="search" data-search placeholder="搜索备注、Tag、协议、端口或中转出站..." value="${esc(state.search)}">
          <span class="tag">共 ${state.inbounds.length} 个入站</span>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>备注 / Tag</th>
              <th>协议与传输</th>
              <th>端口</th>
              <th>出站 / 中转绑定</th>
              <th>客户端与流量</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            ${rows || `<tr><td colspan="7"><div class="empty"><b>还没有入站节点</b><span>点击上方“⚡ 快捷模板”或“＋ 新建入站节点”可在数秒内完成部署</span></div></td></tr>`}
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

  const rows = filtered.map((item) => {
    const boundInbounds = state.inbounds.filter((i) => i.outboundTag === item.tag);
    const detourBadge = item.detour ? `<span class="tag relay">前置链式: ${esc(item.detour)}</span>` : '';
    const addrText = item.builtin
      ? '系统内置引擎出站'
      : (['urltest', 'selector'].includes(item.type)
          ? `包含节点: ${(item.outbounds || []).join(', ')}`
          : `${item.server || '—'}:${item.port || '—'}`);

    return `
      <tr>
        <td>
          <strong>${esc(item.remark)}</strong>
          <small>Tag: <code>${esc(item.tag)}</code></small>
        </td>
        <td>
          <span class="tag">${esc(item.type.toUpperCase())}</span>
          ${item.security && item.security !== 'none' ? `<span class="tag tls">${esc(item.security.toUpperCase())}</span>` : ''}
          ${detourBadge}
        </td>
        <td>
          <strong>${esc(addrText)}</strong>
          ${item.method ? `<small>加密: ${esc(item.method)}</small>` : ''}
        </td>
        <td>
          ${boundInbounds.length
            ? boundInbounds.map((i) => `<span class="tag relay">入站: ${esc(i.remark)}</span>`).join('')
            : '<small>可在入站节点或分流规则中引用</small>'}
        </td>
        <td>
          <span class="status ${item.enabled !== false ? 'active' : 'disabled'}">${item.enabled !== false ? '已启用' : '已停用'}</span>
        </td>
        <td>
          <div class="actions">
            ${item.builtin ? '<small class="muted">系统保留</small>' : `
              <button data-action="edit-outbound" data-id="${esc(item.id)}">编辑</button>
              <button class="danger" data-action="delete-outbound" data-id="${esc(item.id)}">删除</button>
            `}
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="page-intro">
      <p>管理中转落地节点与外部代理出站。支持直接粘贴外部节点的分享链接（vless://、ss://、hy2://、anytls://、trojan://、vmess://、socks5://、tuic://）一键解析为 Sing-box 出站，并在入站节点或分流规则中绑定中转。</p>
      <div style="display:flex;gap:8px">
        <button data-action="import-outbound-uri">🔗 粘贴节点链接一键导入</button>
        <button class="primary" data-action="add-outbound">＋ 手动添加出站节点</button>
      </div>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div class="toolbar">
          <input class="search" data-search placeholder="搜索出站备注、Tag、协议或落地服务器地址..." value="${esc(state.search)}">
          <span class="tag">共 ${state.outbounds.length} 个出站</span>
        </div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>出站备注 / Tag</th>
              <th>协议类型</th>
              <th>目标落地地址 / 参数</th>
              <th>关联中转入站</th>
              <th>状态</th>
              <th>操作</th>
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

function renderRouting() {
  const rules = state.routing.rules || [];
  const outboundOpts = state.outbounds
    .map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, state.routing.final)}>${esc(o.remark)} (${esc(o.tag)})</option>`)
    .join('');

  const rows = rules.map((r, idx) => {
    const conds = [];
    if (r.inbound?.length) conds.push(`入站: ${r.inbound.join(', ')}`);
    if (r.domain?.length) conds.push(`域名/Geosite: ${r.domain.join(', ')}`);
    if (r.domain_suffix?.length) conds.push(`后缀: ${r.domain_suffix.join(', ')}`);
    if (r.domain_keyword?.length) conds.push(`关键词: ${r.domain_keyword.join(', ')}`);
    if (r.ip_cidr?.length) conds.push(`IP/GeoIP: ${r.ip_cidr.join(', ')}`);
    if (r.source_ip_cidr?.length) conds.push(`源IP: ${r.source_ip_cidr.join(', ')}`);
    if (r.port?.length) conds.push(`端口: ${r.port.join(', ')}`);
    if (r.protocol?.length) conds.push(`协议: ${r.protocol.join(', ')}`);
    if (r.network) conds.push(`网络: ${r.network.toUpperCase()}`);
    if (r.rule_set?.length) conds.push(`规则集: ${r.rule_set.join(', ')}`);
    if (r.ip_is_private) conds.push(`私有内网 IP (ip_is_private)`);

    const targetHtml = r.action === 'sniff'
      ? '<span class="tag">协议嗅探 (Sniff)</span>'
      : (r.outbound === 'block'
          ? '<span class="status disabled">拦截 (block)</span>'
          : (r.outbound === 'direct'
              ? '<span class="tag tls">直连 (direct)</span>'
              : `<span class="tag relay">⇄ 路由至: ${esc(r.outbound)}</span>`));

    return `
      <tr>
        <td><strong>#${idx + 1}</strong></td>
        <td><strong>${esc(r.remark || '分流规则')}</strong></td>
        <td><small style="max-width:520px">${esc(conds.join(' · ') || '全局匹配')}</small></td>
        <td>${targetHtml}</td>
        <td><span class="status ${r.enabled !== false ? 'active' : 'disabled'}">${r.enabled !== false ? '启用' : '停用'}</span></td>
        <td>
          <div class="actions">
            <button data-action="move-rule" data-id="${esc(r.id)}" data-dir="up" title="上移优先级">↑</button>
            <button data-action="move-rule" data-id="${esc(r.id)}" data-dir="down" title="下移优先级">↓</button>
            <button data-action="edit-rule" data-id="${esc(r.id)}">编辑</button>
            <button class="danger" data-action="delete-rule" data-id="${esc(r.id)}">删除</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="page-intro">
      <p>支持 3x-ui 风格的多维度路由分流（按入站 Tag、Geosite/域名后缀/关键词、GeoIP/CIDR、端口、协议类型如 BitTorrent/QUIC、私有网络匹配），自动编译为 Sing-box 高性能路由表与 SRS 规则集。</p>
      <button class="primary" data-action="add-rule">＋ 添加分流规则</button>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div><h2>全局默认路由与一键分流模板</h2><p>按从上到下的顺序依次匹配分流规则；未命中任何规则时走下方“默认兜底出站”</p></div>
      </div>
      <div class="panel-body">
        <div class="form-grid" style="margin-bottom:14px">
          <label>
            默认兜底出站 (Final Outbound)
            <select id="routing-final-select">${outboundOpts}</select>
          </label>
          <label>
            DNS 解析 IP 策略
            <div class="input-row">
              <select id="routing-dns-select">
                <option value="prefer_ipv4"${selected('prefer_ipv4', state.dns.strategy)}>优先 IPv4 (prefer_ipv4)</option>
                <option value="prefer_ipv6"${selected('prefer_ipv6', state.dns.strategy)}>优先 IPv6 (prefer_ipv6)</option>
                <option value="ipv4_only"${selected('ipv4_only', state.dns.strategy)}>仅 IPv4 (ipv4_only)</option>
                <option value="ipv6_only"${selected('ipv6_only', state.dns.strategy)}>仅 IPv6 (ipv6_only)</option>
              </select>
              <button class="primary" data-action="save-routing-global">保存全局策略</button>
            </div>
          </label>
        </div>

        <div class="quick-bar" style="margin-bottom:0">
          <span>⚡ 一键添加 3x-ui 常用分流规则:</span>
          <button data-action="routing-preset" data-preset="block-ads">🛡 屏蔽广告域名 (Ads -> Block)</button>
          <button data-action="routing-preset" data-preset="cn-direct">🇨🇳 大陆域名与 IP 直连 (CN -> Direct)</button>
          <button data-action="routing-preset" data-preset="ai-relay">🤖 OpenAI / Claude / Gemini 分流</button>
          <button data-action="routing-preset" data-preset="media-relay">🎬 Netflix / YouTube / Disney+ 分流</button>
        </div>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><h2>分流规则列表 (${rules.length} 条)</h2><p>说明：入站节点直接绑定的中转出站会自动置于自定义规则之前优先转发</p></div>
      </div>
      <div class="table-wrap">
        <table>
          <thead>
            <tr>
              <th>优先级</th>
              <th>规则备注</th>
              <th>匹配条件 (入站 / 域名 / IP / 端口 / 协议)</th>
              <th>目标出站 / 动作</th>
              <th>状态</th>
              <th>操作</th>
            </tr>
          </thead>
          <tbody>
            ${rows || `<tr><td colspan="6"><div class="empty"><b>暂无自定义分流规则</b><span>可点击上方快捷模板或添加规则</span></div></td></tr>`}
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
          <h2>3x-ui 数据解析预览结果</h2>
          <p>解析成功！共识别到 ${preview.summary.inboundsCount} 个入站 (${preview.summary.clientsCount} 个客户端)、${preview.summary.outboundsCount} 个自定义中转出站、${preview.summary.rulesCount} 条分流规则</p>
        </div>
        <span class="status valid">可无损迁移</span>
      </div>
      <div class="panel-body stack">
        <div class="codebox" style="max-height:220px">${esc(JSON.stringify({
          summary: preview.summary,
          inboundsPreview: preview.inbounds.map((i) => ({ tag: i.tag, remark: i.remark, protocol: i.protocol, port: i.port, security: i.security, outboundTag: i.outboundTag, clientsCount: i.clients?.length || 0 })),
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
      <td>${m.rulesCount || 0} 条分流规则</td>
    </tr>
  `).join('');

  return `
    <div class="page-intro">
      <p>完全兼容 3x-ui 的 SQLite 数据库 (<code>x-ui.db</code>) 与 Xray 配置文件。无损迁移全部入站节点（保留原端口、UUID、密码、Reality 公私钥、shortIds、TLS 证书路径、客户端流量与到期时间）、Dokodemo 端口转发、全部中转出站及路由分流规则。</p>
    </div>

    ${previewHtml}

    <section class="grid-2">
      <article class="panel">
        <div class="panel-head">
          <div><h2>方式一：上传 x-ui.db 数据库文件或读取本机 3x-ui</h2><p>推荐直接上传备份的 /etc/x-ui/x-ui.db 文件</p></div>
        </div>
        <div class="panel-body stack">
          <label class="upload-dropzone" for="xui-db-file">
            <input type="file" id="xui-db-file" accept=".db,.sqlite,.sqlite3,.json" class="hidden">
            <b style="display:block;font-size:15px;margin-bottom:6px">📁 点击选择或拖拽上传 3x-ui 的 <code>x-ui.db</code> 数据库文件</b>
            <span class="muted" style="font-size:12px" id="xui-file-label">支持 SQLite3 数据库文件 (x-ui.db) 或 JSON 配置文件</span>
          </label>

          <label>
            迁移合并策略
            <select id="migrate-mode">
              <option value="merge">智能合并（保留当前面板已有节点，同端口/同Tag自动更新）</option>
              <option value="replace">完整替换（清空当前节点，100% 还原为 3x-ui 的入站、出站与分流）</option>
            </select>
          </label>

          <div style="display:flex;flex-wrap:wrap;gap:8px">
            <button data-action="preview-xui-file">🔍 预览上传文件解析结果</button>
            <button class="primary" data-action="apply-xui-file">🚀 上传并立即执行无损迁移</button>
          </div>

          <div style="padding-top:12px;border-top:1px solid var(--line)">
            <label>
              或者直接从本机路径读取 <code>x-ui.db</code>
              <div class="input-row" style="margin-top:4px">
                <input id="local-xui-path" value="/etc/x-ui/x-ui.db" placeholder="/etc/x-ui/x-ui.db">
                <button class="primary" data-action="migrate-local-xui">一键迁移本机 3x-ui</button>
              </div>
              <small>本机状态: ${state.overview?.local3xuiExists ? '✅ 已检测到 /etc/x-ui/x-ui.db' : '未在默认路径检测到 /etc/x-ui/x-ui.db（可填入自定义路径或上传文件）'}</small>
            </label>
          </div>
        </div>
      </article>

      <article class="panel">
        <div class="panel-head">
          <div><h2>方式二：粘贴 3x-ui 配置 JSON / 导出数据</h2><p>支持粘贴 3x-ui 的 xrayTemplateConfig JSON 或入站数组 JSON</p></div>
        </div>
        <div class="panel-body stack">
          <label>
            3x-ui / Xray JSON 内容
            <textarea id="xui-json-input" style="min-height:190px" placeholder='{"inbounds": [...], "outbounds": [...], "routing": {"rules": [...]}}'></textarea>
          </label>
          <div style="display:flex;justify-content:flex-end;gap:8px">
            <button data-action="preview-xui-json">🔍 预览 JSON 解析</button>
            <button class="primary" data-action="apply-xui-json">🚀 从 JSON 执行无损迁移</button>
          </div>
        </div>
      </article>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><h2>历史迁移记录</h2><p>历次 3x-ui 数据导入审计</p></div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>迁移时间</th><th>模式</th><th>入站与客户端</th><th>迁移出站</th><th>迁移分流规则</th></tr></thead>
          <tbody>
            ${historyRows || `<tr><td colspan="5"><div class="empty"><b>尚无迁移记录</b><span>上传 x-ui.db 或粘贴 JSON 后将在此记录</span></div></td></tr>`}
          </tbody>
        </table>
      </div>
    </section>
  `;
}

function renderCertificates() {
  const s = state.settings || {};
  const proto = window.location.protocol;
  const host = s.webDomain || s.publicIPv4 || window.location.hostname || '127.0.0.1';
  const portPart = window.location.port ? `:${window.location.port}` : (s.webPort ? `:${s.webPort}` : '');
  const subPath = (s.subPath || '/sub/').replace(/\/+$/, '');
  const baseSubUrl = `${proto}//${host}${portPart}${subPath}/all`;

  const certRows = (state.certificates || []).map((c) => {
    const isPanelCert = s.webCertFile === c.certPath;
    return `
      <tr>
        <td>
          <strong>${esc(c.domain)}</strong>
          <small>${esc(c.subject || '')}</small>
        </td>
        <td>
          <span class="tag">${esc(c.type || 'cert')}</span>
          ${isPanelCert ? '<span class="tag tls">当前面板 HTTPS 证书</span>' : ''}
        </td>
        <td>
          <small>证书: <code>${esc(c.certPath)}</code></small>
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
            <button data-action="apply-cert-panel" data-cert="${esc(c.certPath)}" data-key="${esc(c.keyPath)}">设为面板 HTTPS</button>
            <button class="danger" data-action="delete-cert" data-id="${esc(c.id)}">移除记录</button>
          </div>
        </td>
      </tr>
    `;
  }).join('');

  return `
    <div class="page-intro">
      <p>集中管理用于 AnyTLS、Hysteria 2、VLESS-TLS、Trojan、TUIC 入站节点以及面板 HTTPS 的 SSL 证书；同时提供多格式聚合订阅链接。</p>
      <div style="display:flex;flex-wrap:wrap;gap:8px">
        <button data-action="cert-selfsigned">⚡ 一键生成 10 年自签证书</button>
        <button data-action="cert-custom">📋 粘贴 / 导入已有证书</button>
        <button class="primary" data-action="cert-acme">🌐 ACME 自动申请证书 (域名/IP)</button>
      </div>
    </div>

    <section class="panel">
      <div class="panel-head">
        <div><h2>SSL 证书列表 (${state.certificates.length} 张)</h2><p>在创建 AnyTLS、Hysteria 2 或 TLS 节点时可直接下拉选择此处已管理的证书</p></div>
      </div>
      <div class="table-wrap">
        <table>
          <thead><tr><th>域名 / 标识</th><th>类型</th><th>文件路径</th><th>到期时间 / 签发者</th><th>状态</th><th>操作</th></tr></thead>
          <tbody>
            ${certRows || `<tr><td colspan="6"><div class="empty"><b>尚未添加自定义或 ACME 证书</b><span>点击右上角“⚡ 一键生成 10 年自签证书”或“🌐 ACME 自动申请证书”即可创建</span></div></td></tr>`}
          </tbody>
        </table>
      </div>
    </section>

    <section class="panel">
      <div class="panel-head">
        <div><h2>全客户端聚合订阅中心</h2><p>自动聚合所有已启用入站节点的客户端链接，支持按客户端 User-Agent 自动识别或通过参数指定格式</p></div>
      </div>
      <div class="panel-body">
        <div class="subscription-row">
          <div>
            <b>V2Ray / Shadowrocket / 通用 Base64 订阅</b>
            <code>${esc(baseSubUrl)}</code>
          </div>
          <div style="display:flex;gap:6px">
            <button class="primary" data-copy="${esc(baseSubUrl)}">复制订阅链接</button>
            <button data-qr="${esc(baseSubUrl)}">二维码</button>
          </div>
        </div>
        <div class="subscription-row">
          <div>
            <b>Clash / Mihomo 智能分流 YAML 订阅 (含 AnyTLS / HY2 / Reality)</b>
            <code>${esc(`${baseSubUrl}?format=clash`)}</code>
          </div>
          <div style="display:flex;gap:6px">
            <button class="primary" data-copy="${esc(`${baseSubUrl}?format=clash`)}">复制 Clash 订阅</button>
            <button data-qr="${esc(`${baseSubUrl}?format=clash`)}">二维码</button>
          </div>
        </div>
        <div class="subscription-row">
          <div>
            <b>Sing-box 客户端 JSON 配置订阅</b>
            <code>${esc(`${baseSubUrl}?format=singbox`)}</code>
          </div>
          <div style="display:flex;gap:6px">
            <button class="primary" data-copy="${esc(`${baseSubUrl}?format=singbox`)}">复制 Sing-box 订阅</button>
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
    ...(state.certificates || []).map((c) => `<option value="${esc(c.certPath)}|${esc(c.keyPath)}"${s.webCertFile === c.certPath ? ' selected' : ''}>${esc(c.domain)} (${esc(c.type)})</option>`)
  ].join('');

  return `
    <div class="page-intro">
      <p>配置面板端口（支持一键随机端口）、安全访问根路径（<code>webBasePath</code>）、公网 IP / 域名、面板 HTTPS 证书以及管理员账号密码。</p>
      <div style="display:flex;gap:8px">
        <a class="button" href="${BASE_PATH}/api/backup" target="_blank">⬇ 导出完整面板备份 (.json)</a>
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
            <small>默认 0.0.0.0 监听全部网卡；仅本机反代可填 127.0.0.1</small>
          </label>
          <label>
            面板监听端口 (webPort)
            <div class="input-row">
              <input name="webPort" id="setting-webport" type="number" min="1" max="65535" value="${esc(s.webPort || 2053)}" required>
              <button type="button" data-action="random-port">🎲 随机端口</button>
            </div>
            <small>类似 3x-ui，建议使用 10000–60000 之间的随机高位端口</small>
          </label>

          <label class="wide">
            面板安全根路径 (webBasePath)
            <div class="input-row">
              <input name="webBasePath" id="setting-webpath" value="${esc(s.webBasePath || '/')}" placeholder="/ 或 /secretpath/">
              <button type="button" data-action="random-path">🎲 随机安全路径</button>
              <button type="button" data-action="reset-path">设为 /</button>
            </div>
            <small>设置非 <code>/</code> 的安全路径后，直接访问根路径将返回 404，防止面板被扫描探测</small>
          </label>

          <label>
            服务器公网 IPv4 (用于生成节点链接)
            <input name="publicIPv4" value="${esc(s.publicIPv4 || '')}" placeholder="如 203.0.113.10">
          </label>
          <label>
            面板 / 节点默认域名 (webDomain)
            <input name="webDomain" value="${esc(s.webDomain || '')}" placeholder="如 gate.example.com">
          </label>

          <div class="section-title">面板 HTTPS (SSL 证书配置)</div>
          <label class="wide">
            快速绑定已管理的 SSL 证书
            <select id="setting-cert-picker">${certSelectOpts}</select>
          </label>
          <label>
            面板公钥证书路径 (webCertFile)
            <input name="webCertFile" id="setting-cert-file" value="${esc(s.webCertFile || '')}" placeholder="/etc/nexusgate/certs/.../fullchain.pem">
          </label>
          <label>
            面板私钥文件路径 (webKeyFile)
            <input name="webKeyFile" id="setting-key-file" value="${esc(s.webKeyFile || '')}" placeholder="/etc/nexusgate/certs/.../privkey.pem">
          </label>

          <div class="section-title">订阅与 Sing-box 联动</div>
          <label>
            订阅路径前缀 (subPath)
            <input name="subPath" value="${esc(s.subPath || '/sub/')}" placeholder="/sub/">
          </label>
          <label>
            Sing-box 日志级别
            <select name="singboxLogLevel">
              <option value="info"${selected('info', s.singboxLogLevel)}>info (推荐)</option>
              <option value="warn"${selected('warn', s.singboxLogLevel)}>warn (精简)</option>
              <option value="debug"${selected('debug', s.singboxLogLevel)}>debug (调试)</option>
              <option value="error"${selected('error', s.singboxLogLevel)}>error (仅错误)</option>
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
              <input name="username" value="${esc(state.admin.username || 'admin')}" required>
            </label>
            <label>
              新登录密码 (至少 6 位)
              <input name="newPassword" type="password" required placeholder="输入新密码">
            </label>
            <div class="form-actions">
              <button type="submit" class="primary">修改账号与密码</button>
            </div>
          </form>
        </article>

        <article class="panel">
          <div class="panel-head">
            <div><h2>SSH 命令行管理菜单 (类似 3x-ui)</h2><p>在服务器 SSH 终端输入 <code>nexusgate</code> 或 <code>ng</code> 即可呼出交互式管理菜单</p></div>
          </div>
          <div class="panel-body">
            <div class="command-item"><div><b>呼出交互式管理菜单</b><code>nexusgate</code> 或 <code>ng</code></div><button data-copy="nexusgate">复制</button></div>
            <div class="command-item"><div><b>查看当前面板端口、安全路径与访问地址</b><code>nexusgate info</code></div><button data-copy="nexusgate info">复制</button></div>
            <div class="command-item"><div><b>命令行重置账号密码 / 随机端口 / 安全路径</b><code>nexusgate account</code> / <code>nexusgate port</code></div><button data-copy="nexusgate port">复制</button></div>
            <div class="command-item"><div><b>命令行一键无损迁移本机 3x-ui 数据库</b><code>nexusgate migrate</code></div><button data-copy="nexusgate migrate">复制</button></div>
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
    outbounds: renderOutbounds,
    routing: renderRouting,
    migrate: renderMigrate,
    certificates: renderCertificates,
    settings: renderSettings
  };
  $('#content').innerHTML = (views[state.page] || renderOverview)();
}

/* ==================== MODALS & ACTIONS ==================== */

async function openInboundModal(existing = null, preset = '') {
  let item = existing ? JSON.parse(JSON.stringify(existing)) : {
    remark: '',
    tag: '',
    protocol: 'vless',
    listen: '::',
    port: Math.floor(Math.random() * 40000) + 15000,
    security: 'reality',
    transport: 'tcp',
    flow: 'xtls-rprx-vision',
    method: '2022-blake3-aes-128-gcm',
    password: '',
    outboundTag: 'default',
    reality: {
      serverName: 'www.tesla.com',
      target: 'www.tesla.com:443',
      privateKey: '',
      publicKey: '',
      shortIds: ['1a2b3c4d'],
      fingerprint: 'chrome'
    },
    clients: [{ email: 'user_1', id: '', password: '', flow: 'xtls-rprx-vision', enable: true }]
  };

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
  if (!existing && !item.password) {
    try {
      const sk = await api('/api/tools/ss-key', { method: 'POST', body: JSON.stringify({ method: item.method }) });
      item.password = sk.password;
    } catch { /* ignore */ }
  }

  const outboundOpts = [
    `<option value="default"${selected('default', item.outboundTag)}>默认路由 (按分流规则表处理)</option>`,
    ...state.outbounds.map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, item.outboundTag)}>${o.builtin ? '' : '⇄ 中转出站: '}${esc(o.remark)} (${esc(o.tag)})</option>`)
  ].join('');

  const certOpts = [
    '<option value="">自动使用内置自签证书 / 填写下方路径</option>',
    ...(state.certificates || []).map((c) => `<option value="${esc(c.domain)}" data-cert="${esc(c.certPath)}" data-key="${esc(c.keyPath)}"${selected(c.domain, item.tlsDomain)}>${esc(c.domain)} (${esc(c.type)})</option>`)
  ].join('');

  const c0 = (item.clients && item.clients[0]) || {};

  openModal(
    existing ? '编辑入站节点' : '新建入站节点',
    existing ? `${existing.remark} (:${existing.port})` : '配置 Sing-box 入站协议与中转绑定',
    `
    <form id="inbound-form" class="form-grid" data-id="${esc(existing?.id || '')}">
      <label>
        节点备注名称
        <input name="remark" value="${esc(item.remark)}" placeholder="如 香港-VLESS-Reality" required>
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

      <label class="wide">
        ⇄ 指定出站 / 中转落地节点绑定 (Inbound -> Outbound Relay)
        <select name="outboundTag">${outboundOpts}</select>
        <small>若选择某个中转出站节点，进入此入站的所有流量将直接通过该出站节点转发（免去手动编写分流规则）。</small>
      </label>

      <!-- Protocol Specific Fields -->
      <div id="inb-dynamic-fields" class="form-grid wide" style="margin:0"></div>

      <div class="form-actions">
        <button type="button" data-close>取消</button>
        <button type="submit" class="primary">${existing ? '保存修改并应用' : '立即创建并启动'}</button>
      </div>
    </form>
    `
  );

  const renderDynamicFields = () => {
    const proto = $('#inb-proto-select').value;
    const box = $('#inb-dynamic-fields');
    if (!box) return;

    if (proto === 'direct') {
      box.innerHTML = `
        <div class="section-title">Direct 端口转发 (Dokodemo-door 隧道中转配置)</div>
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
          <small>SS 2022 要求 16 字节 (128位) 或 32 字节 (256位) Base64 密钥，点击右侧按钮自动生成。</small>
        </label>
        <label class="wide">
          客户端标识名称 (Email/Remark)
          <input name="clientEmail" value="${esc(c0.email || 'ss_client_1')}">
        </label>
      `;
      return;
    }

    if (proto === 'socks') {
      box.innerHTML = `
        <div class="section-title">SOCKS5 认证凭据</div>
        <label>
          SOCKS5 用户名
          <input name="socksUser" value="${esc(item.socksUser || c0.username || 'ng_user')}" required>
        </label>
        <label>
          SOCKS5 密码
          <input name="socksPassword" value="${esc(item.socksPassword || c0.password || '')}" required>
        </label>
      `;
      return;
    }

    if (proto === 'anytls') {
      box.innerHTML = `
        <div class="section-title">AnyTLS 认证与 TLS 证书配置</div>
        <label>
          AnyTLS 访问密码
          <input name="password" value="${esc(item.password || c0.password || '')}" required>
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
          <input name="tlsDomain" id="inb-tls-domain" value="${esc(item.tlsDomain || state.settings.webDomain || 'www.bing.com')}">
        </label>
        <label>
          证书路径 (留空自动使用内置自签证书)
          <input name="certPath" id="inb-cert-path" value="${esc(item.certPath || '')}" placeholder="/etc/nexusgate/certs/.../fullchain.pem">
        </label>
        <label>
          私钥路径
          <input name="keyPath" id="inb-key-path" value="${esc(item.keyPath || '')}" placeholder="/etc/nexusgate/certs/.../privkey.pem">
        </label>
      `;
      return;
    }

    if (proto === 'hysteria2') {
      box.innerHTML = `
        <div class="section-title">Hysteria 2 (HY2 UDP) 认证与带宽配置</div>
        <label>
          HY2 认证密码
          <input name="password" value="${esc(item.password || c0.password || '')}" required>
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
          <input name="tlsDomain" id="inb-tls-domain" value="${esc(item.tlsDomain || state.settings.webDomain || 'www.bing.com')}">
        </label>
        <label>
          证书路径 (留空自动使用内置自签证书)
          <input name="certPath" id="inb-cert-path" value="${esc(item.certPath || '')}">
        </label>
        <label>
          私钥路径
          <input name="keyPath" id="inb-key-path" value="${esc(item.keyPath || '')}">
        </label>
      `;
      return;
    }

    // VLESS / Trojan / VMess / TUIC
    const sec = item.security || (proto === 'tuic' ? 'tls' : 'reality');
    const trans = item.transport || 'tcp';
    box.innerHTML = `
      <div class="section-title">${esc(proto.toUpperCase())} 客户端凭据与传输安全</div>
      <label>
        客户端 UUID / 密码
        <input name="uuid" value="${esc(c0.id || item.password || '')}" placeholder="留空自动生成随机 UUID">
      </label>
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
          <option value="tls"${selected('tls', sec)}>TLS (需证书或自签)</option>
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
            <div class="section-title">Reality 伪装与 X25519 密钥对</div>
            <label>
              伪装目标预设 (SNI)
              <select id="inb-reality-preset">
                <option value="">— 选择常用大厂 SNI 预设 —</option>
                ${state.catalog.realityPresets.map((p) => `<option value="${esc(p.serverName)}" data-target="${esc(p.target)}"${selected(p.serverName, r.serverName)}>${esc(p.label)}</option>`).join('')}
              </select>
            </label>
            <label>
              伪装域名 (ServerName / SNI)
              <input name="realityServerName" id="inb-reality-sni" value="${esc(r.serverName || 'www.tesla.com')}" required>
            </label>
            <label>
              握手目标地址 (Handshake Target)
              <input name="realityTarget" id="inb-reality-target" value="${esc(r.target || 'www.tesla.com:443')}" required>
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
            <div class="section-title">TLS 证书配置</div>
            <label>
              选择已管理证书
              <select id="inb-cert-select">${certOpts}</select>
            </label>
            <label>
              TLS SNI 域名
              <input name="tlsDomain" id="inb-tls-domain" value="${esc(item.tlsDomain || state.settings.webDomain || '')}">
            </label>
            <label>
              公钥证书路径 (留空自动使用自签证书)
              <input name="certPath" id="inb-cert-path" value="${esc(item.certPath || '')}">
            </label>
            <label>
              私钥路径
              <input name="keyPath" id="inb-key-path" value="${esc(item.keyPath || '')}">
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

function openInboundLinksModal(inbound) {
  const links = inbound.links || [];
  const rows = links.map((l, idx) => `
    <div class="subscription-row">
      <div>
        <b>${esc(l.name)} (${esc(l.protocol.toUpperCase())})</b>
        <code>${esc(l.uri)}</code>
      </div>
      <div style="display:flex;gap:6px">
        <button class="primary" data-copy="${esc(l.uri)}">复制链接</button>
        <button data-qr-inline="qr-box-${idx}" data-qr-text="${esc(l.uri)}">显示二维码</button>
      </div>
      <div id="qr-box-${idx}" class="subscription-qr hidden"></div>
    </div>
  `).join('');

  openModal(
    `节点分享链接与二维码 · 端口 :${inbound.port}`,
    inbound.remark,
    `
    <div class="stack">
      ${rows || `<div class="empty"><b>该入站暂无可用客户端链接</b><span>请检查客户端是否已启用</span></div>`}
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
      .map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, item.detour)}>前置代理: ${esc(o.remark)} (${esc(o.tag)})</option>`)
  ].join('');

  openModal(
    existing ? '编辑出站节点' : '新建中转 / 落地出站节点',
    existing ? `${existing.remark} (${existing.tag})` : '配置中转落地机或外部出站协议',
    `
    <form id="outbound-form" class="form-grid" data-id="${esc(existing?.id || '')}">
      <label>
        出站备注名称
        <input name="remark" value="${esc(item.remark)}" placeholder="如 日本落地机-SS2022" required>
      </label>
      <label>
        出站唯一标识 (Tag)
        <input name="tag" value="${esc(item.tag)}" placeholder="如 jp-exit-1 (留空自动生成)">
      </label>

      <label>
        出站协议类型
        <select name="type">
          ${state.catalog.outboundProtocols.filter((p) => !['direct', 'block'].includes(p.id)).map((p) => `<option value="${esc(p.id)}"${selected(p.id, item.type)}>${esc(p.name)}</option>`).join('')}
        </select>
      </label>
      <label>
        前置链式代理 (Detour 多跳中转)
        <select name="detour">${detourOpts}</select>
      </label>

      <label>
        落地服务器地址 (IP 或域名)
        <input name="server" value="${esc(item.server || '')}" placeholder="如 198.51.100.8">
      </label>
      <label>
        落地服务器端口
        <input name="port" type="number" min="1" max="65535" value="${esc(item.port || 443)}">
      </label>

      <div class="section-title">凭据与加密参数 (按所选协议填写对应项)</div>
      <label>
        UUID (VLESS / VMess / TUIC)
        <input name="uuid" value="${esc(item.uuid || '')}" placeholder="UUID">
      </label>
      <label>
        密码 / 密钥 (SS / HY2 / AnyTLS / Trojan / SOCKS5)
        <input name="password" value="${esc(item.password || '')}" placeholder="连接密码或 Base64 密钥">
      </label>

      <label>
        Shadowsocks 加密方式
        <select name="method">
          ${state.catalog.ssMethods.map((m) => `<option value="${esc(m.id)}"${selected(m.id, item.method)}>${esc(m.label)}</option>`).join('')}
        </select>
      </label>
      <label>
        SOCKS5 / HTTP 用户名 (可选)
        <input name="username" value="${esc(item.username || '')}" placeholder="用户名">
      </label>

      <div class="section-title">TLS / Reality / 传输层参数 (可选)</div>
      <label>
        传输安全 (Security)
        <select name="security">
          <option value="none"${selected('none', item.security)}>无 (None · SS/明文)</option>
          <option value="tls"${selected('tls', item.security)}>TLS (AnyTLS / HY2 / Trojan / VLESS-TLS)</option>
          <option value="reality"${selected('reality', item.security)}>Reality (VLESS Reality 落地)</option>
        </select>
      </label>
      <label>
        传输协议 (Transport)
        <select name="transport">
          <option value="tcp"${selected('tcp', item.transport)}>TCP / QUIC 原生</option>
          <option value="ws"${selected('ws', item.transport)}>WebSocket (WS)</option>
          <option value="grpc"${selected('grpc', item.transport)}>gRPC</option>
        </select>
      </label>
      <label>
        SNI 域名 (Server Name)
        <input name="sni" value="${esc(item.sni || '')}" placeholder="TLS 或 Reality 的 SNI">
      </label>
      <label>
        Reality 公钥 (Public Key) / ShortId
        <div class="input-row">
          <input name="publicKey" value="${esc(item.publicKey || '')}" placeholder="pbk 公钥">
          <input name="shortId" value="${esc(item.shortId || '')}" placeholder="sid" style="max-width:100px">
        </div>
      </label>

      <div class="form-actions">
        <button type="button" data-close>取消</button>
        <button type="submit" class="primary">保存出站节点</button>
      </div>
    </form>
    `
  );
}

function openRuleModal(existing = null) {
  const r = existing || {
    remark: '',
    inbound: [],
    domain: [],
    domain_suffix: [],
    domain_keyword: [],
    ip_cidr: [],
    source_ip_cidr: [],
    port: [],
    protocol: [],
    network: '',
    rule_set: [],
    ip_is_private: false,
    outbound: 'direct'
  };

  const outboundOpts = state.outbounds
    .map((o) => `<option value="${esc(o.tag)}"${selected(o.tag, r.outbound)}>${esc(o.remark)} (${esc(o.tag)})</option>`)
    .join('');

  openModal(
    existing ? '编辑分流规则' : '新建 3x-ui 风格分流规则',
    existing ? r.remark : '配置域名、IP、协议或入站分流',
    `
    <form id="rule-form" class="form-grid" data-id="${esc(existing?.id || '')}">
      <label>
        规则备注
        <input name="remark" value="${esc(r.remark)}" placeholder="如 OpenAI 走日本落地机" required>
      </label>
      <label>
        目标出站 (Outbound Tag)
        <select name="outbound">${outboundOpts}</select>
      </label>

      <label>
        指定入站 Tag (逗号分隔，留空匹配所有入站)
        <input name="inbound" value="${esc((r.inbound || []).join(', '))}" placeholder="如 vless-443, hy2-8443">
      </label>
      <label>
        规则集 (Sing-box SRS RuleSet，逗号分隔)
        <input name="rule_set" value="${esc((r.rule_set || []).join(', '))}" placeholder="如 geosite-cn, geoip-cn, geosite-openai">
      </label>

      <label>
        域名 / Geosite 表达式 (兼容 3x-ui 格式，逗号分隔)
        <input name="domain" value="${esc((r.domain || []).join(', '))}" placeholder="如 geosite:cn, domain:google.com, full:ip.sb">
      </label>
      <label>
        域名后缀 (Domain Suffix，逗号分隔)
        <input name="domain_suffix" value="${esc((r.domain_suffix || []).join(', '))}" placeholder="如 openai.com, netflix.com, cn">
      </label>

      <label>
        IP CIDR / GeoIP (兼容 3x-ui 格式，逗号分隔)
        <input name="ip_cidr" value="${esc((r.ip_cidr || []).join(', '))}" placeholder="如 geoip:cn, 1.1.1.0/24, 8.8.8.8/32">
      </label>
      <label>
        目标端口或端口范围 (Port，逗号分隔)
        <input name="port" value="${esc((r.port || []).join(', '))}" placeholder="如 53, 443, 1000-2000">
      </label>

      <label>
        嗅探应用层协议 (逗号分隔)
        <input name="protocol" value="${esc((r.protocol || []).join(', '))}" placeholder="如 bittorrent, quic, tls, http">
      </label>
      <label>
        网络层类型 (Network)
        <select name="network">
          <option value=""${selected('', r.network)}>TCP + UDP (不限)</option>
          <option value="tcp"${selected('tcp', r.network)}>仅 TCP</option>
          <option value="udp"${selected('udp', r.network)}>仅 UDP</option>
        </select>
      </label>

      <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
        <input type="checkbox" name="ip_is_private" style="width:16px;min-height:16px" ${r.ip_is_private ? 'checked' : ''}>
        <span>匹配私有内网 IP 地址 (ip_is_private / geoip:private)</span>
      </label>

      <div class="form-actions">
        <button type="button" data-close>取消</button>
        <button type="submit" class="primary">保存分流规则</button>
      </div>
    </form>
    `
  );
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
  if (copyBtn) { copyText(copyBtn.dataset.copy, '链接/命令'); return; }

  const qrBtn = e.target.closest('[data-qr]');
  if (qrBtn && window.NexusGateQR) {
    const text = qrBtn.dataset.qr;
    openModal('订阅二维码', '使用客户端扫码导入', `<div class="subscription-qr">${window.NexusGateQR.svg(text)}<p class="muted" style="margin-top:10px;font-size:11px;word-break:break-all">${esc(text)}</p></div>`);
    return;
  }

  const qrInlineBtn = e.target.closest('[data-qr-inline]');
  if (qrInlineBtn && window.NexusGateQR) {
    const box = $(`#${qrInlineBtn.dataset.qrInline}`);
    if (box) {
      box.classList.toggle('hidden');
      if (!box.innerHTML) box.innerHTML = window.NexusGateQR.svg(qrInlineBtn.dataset.qrText);
    }
    return;
  }

  const actEl = e.target.closest('[data-action]');
  if (!actEl) return;
  const action = actEl.dataset.action;

  try {
    if (action === 'jump-migrate') { setPage('migrate'); }
    else if (action === 'quick-add-inbound' || action === 'add-inbound') { openInboundModal(); }
    else if (action === 'quick-inbound') { openInboundModal(null, actEl.dataset.preset); }
    else if (action === 'edit-inbound') {
      const inb = state.inbounds.find((x) => x.id === actEl.dataset.id);
      if (inb) openInboundModal(inb);
    }
    else if (action === 'inbound-links') {
      const inb = state.inbounds.find((x) => x.id === actEl.dataset.id);
      if (inb) openInboundLinksModal(inb);
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
    else if (action === 'delete-outbound') {
      if (!confirm('确认删除该出站节点？')) return;
      await api(`/api/outbounds/${actEl.dataset.id}`, { method: 'DELETE' });
      toast('出站节点已删除');
      load('outbounds');
    }
    else if (action === 'import-outbound-uri') {
      openModal('一键导入外部节点作为中转出站', '粘贴节点分享链接 (URI)', `
        <form id="import-uri-form" class="form-grid">
          <label class="wide">
            节点分享链接 (支持 vless://, ss://, hysteria2://, anytls://, trojan://, vmess://, socks5://, tuic://)
            <textarea name="uri" placeholder="粘贴如 vless://... 或 ss://... 链接" required></textarea>
          </label>
          <label>自定义出站备注 (可选)<input name="remark" placeholder="留空自动使用链接内名称"></label>
          <label>自定义出站 Tag (可选)<input name="tag" placeholder="如 hk-relay-1"></label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">解析并添加为出站节点</button>
          </div>
        </form>
      `);
    }
    else if (action === 'save-routing-global') {
      const finalOut = $('#routing-final-select')?.value || 'direct';
      const dnsStrategy = $('#routing-dns-select')?.value || 'prefer_ipv4';
      await api('/api/routing', { method: 'PUT', body: JSON.stringify({ final: finalOut, dnsStrategy }) });
      toast('全局默认出站与 DNS 策略已保存');
      load('routing');
    }
    else if (action === 'add-rule') { openRuleModal(); }
    else if (action === 'edit-rule') {
      const r = (state.routing.rules || []).find((x) => x.id === actEl.dataset.id);
      if (r) openRuleModal(r);
    }
    else if (action === 'delete-rule') {
      await api(`/api/routing/rules/${actEl.dataset.id}`, { method: 'DELETE' });
      toast('分流规则已删除');
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
      const customOut = state.outbounds.find((o) => !o.builtin)?.tag || 'direct';
      await api('/api/routing/presets', {
        method: 'POST',
        body: JSON.stringify({ preset, outbound: customOut })
      });
      toast('已添加分流预设规则');
      load('routing');
    }
    else if (action === 'sb-control') {
      const cmd = actEl.dataset.cmd;
      const res = await api('/api/singbox/control', { method: 'POST', body: JSON.stringify({ action: cmd }) });
      if (cmd === 'check') {
        if (res.result.valid) toast('✅ Sing-box 配置文件校验通过');
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
      if (!file) { toast('请先选择要上传的 x-ui.db 文件', true); return; }
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
        toast(`🎉 无损迁移完成: 已导入 ${res.summary.inboundsCount} 个入站、${res.summary.outboundsCount} 个出站、${res.summary.rulesCount} 条规则！`);
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
      toast(`🎉 本机 3x-ui 无损迁移完成: 入站 ${res.summary.inboundsCount} 个，出站 ${res.summary.outboundsCount} 个`);
      load('migrate');
    }
    else if (action === 'preview-xui-json' || action === 'apply-xui-json') {
      const raw = $('#xui-json-input')?.value.trim();
      if (!raw) { toast('请粘贴 3x-ui JSON 内容', true); return; }
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
        toast(`🎉 从 JSON 无损迁移完成！`);
        load('migrate');
      }
    }
    else if (action === 'cert-selfsigned') {
      openModal('一键生成自签 SSL 证书', '免域名快速生成 10 年有效期证书', `
        <form id="cert-selfsigned-form" class="form-grid">
          <label class="wide">
            伪装域名或公网 IP (Common Name / SAN)
            <input name="domain" value="${esc(state.settings.webDomain || 'www.bing.com')}" required>
            <small>可用于 Hysteria 2、AnyTLS、TUIC 入站或面板 HTTPS 访问</small>
          </label>
          <label class="wide" style="flex-direction:row;align-items:center;gap:8px">
            <input type="checkbox" name="applyToPanel" style="width:16px;min-height:16px">
            <span>同时将该证书设为当前面板的 HTTPS 证书</span>
          </label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">立即生成证书</button>
          </div>
        </form>
      `);
    }
    else if (action === 'cert-acme') {
      openModal('ACME 自动申请受信任证书', '支持 Let\'s Encrypt HTTP-01、Cloudflare DNS 与短期 IP 证书', `
        <form id="cert-acme-form" class="form-grid">
          <label>
            申请域名或公网 IP
            <input name="domain" placeholder="如 node.example.com" required>
          </label>
          <label>
            通知邮箱 (可选)
            <input name="email" placeholder="admin@example.com">
          </label>
          <label class="wide">
            验证模式
            <select name="mode">
              <option value="standalone">HTTP-01 Standalone (需本机 80 端口公网可达)</option>
              <option value="cf">Cloudflare DNS-01 (无需开放 80 端口，需填写 CF Token)</option>
              <option value="ip">Let's Encrypt IP 短期证书 (3x-ui 同款 IP 证书，需 80 端口)</option>
            </select>
          </label>
          <label class="wide">
            Cloudflare API Token (仅 DNS-01 模式需要)
            <input name="cfToken" type="password" placeholder="Edit zone DNS Token">
          </label>
          <div class="form-actions">
            <button type="button" data-close>取消</button>
            <button type="submit" class="primary">开始签发并安装</button>
          </div>
        </form>
      `);
    }
    else if (action === 'cert-custom') {
      openModal('导入或粘贴自定义 SSL 证书', '支持粘贴 PEM 内容或指定服务器已有证书路径', `
        <form id="cert-custom-form" class="form-grid">
          <label class="wide">
            域名或证书标识名称
            <input name="domain" placeholder="如 example.com" required>
          </label>
          <label>
            方式 A: 服务器已有公钥路径 (可选)
            <input name="certPath" placeholder="/root/cert/fullchain.pem">
          </label>
          <label>
            方式 A: 服务器已有私钥路径 (可选)
            <input name="keyPath" placeholder="/root/cert/privkey.pem">
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
            <button type="submit" class="primary">保存并验证证书</button>
          </div>
        </form>
      `);
    }
    else if (action === 'apply-cert-panel') {
      await api('/api/settings', {
        method: 'PUT',
        body: JSON.stringify({ webCertFile: actEl.dataset.cert, webKeyFile: actEl.dataset.key })
      });
      toast('已绑定为面板 HTTPS 证书，服务正在平滑重启');
      load('certificates');
    }
    else if (action === 'delete-cert') {
      await api(`/api/certificates/${actEl.dataset.id}`, { method: 'DELETE' });
      toast('证书记录已移除');
      load('certificates');
    }
    else if (action === 'random-port') {
      const el = $('#setting-webport');
      if (el) el.value = Math.floor(Math.random() * 45000) + 15000;
    }
    else if (action === 'random-path') {
      const chars = 'abcdefghijklmnopqrstuvwxyz0123456789';
      let s = '';
      for (let i = 0; i < 8; i += 1) s += chars[Math.floor(Math.random() * chars.length)];
      const el = $('#setting-webpath');
      if (el) el.value = `/${s}/`;
    }
    else if (action === 'reset-path') {
      const el = $('#setting-webpath');
      if (el) el.value = '/';
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
    const [cPath, kPath] = e.target.value.split('|');
    if ($('#setting-cert-file')) $('#setting-cert-file').value = cPath || '';
    if ($('#setting-key-file')) $('#setting-key-file').value = kPath || '';
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
      const payload = {
        remark: data.remark,
        protocol: data.protocol,
        listen: data.listen,
        port: Number(data.port),
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
      if (id) {
        await api(`/api/outbounds/${id}`, { method: 'PUT', body: JSON.stringify(data) });
        toast('出站节点已更新');
      } else {
        await api('/api/outbounds', { method: 'POST', body: JSON.stringify(data) });
        toast('出站节点已添加');
      }
      closeModal();
      load('outbounds');
    }
    else if (form.id === 'import-uri-form') {
      await api('/api/outbounds/import-uri', { method: 'POST', body: JSON.stringify(data) });
      toast('已成功解析分享链接并添加为出站节点');
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
        toast('分流规则已更新');
      } else {
        await api('/api/routing/rules', { method: 'POST', body: JSON.stringify(payload) });
        toast('分流规则已添加');
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
      toast('10 年自签 SSL 证书已生成');
      closeModal();
      load('certificates');
    }
    else if (form.id === 'cert-acme-form') {
      toast('正在调用 ACME 申请证书，请稍候...');
      await api('/api/certificates/acme', { method: 'POST', body: JSON.stringify(data) });
      toast('ACME 证书签发成功！');
      closeModal();
      load('certificates');
    }
    else if (form.id === 'cert-custom-form') {
      await api('/api/certificates/custom', { method: 'POST', body: JSON.stringify(data) });
      toast('自定义证书已保存并验证通过');
      closeModal();
      load('certificates');
    }
    else if (form.id === 'settings-form') {
      const res = await api('/api/settings', { method: 'PUT', body: JSON.stringify(data) });
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
    if (state.session && state.page === 'overview' && !$('#modal')?.open) {
      load('overview');
    }
  }, 6000);
})();
