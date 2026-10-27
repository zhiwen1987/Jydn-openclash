'use strict';

(() => {
  const STATUS_LABELS = {
    ok: '正常',
    running: '进行中',
    pending: '等待中',
    warning: '需关注',
    error: '异常',
    stale: '已过期',
    unknown: '未知'
  };

  const PAGE_META = {
    overview: { label: '总览', title: '网络总览', description: '查看真实业务出口、分阶段同步和待处理事项。' },
    routing: { label: '业务分流', title: '业务分流', description: '查看真实策略链与最终出口，管理登录后可受控切换现有选项。' },
    nodes: { label: '节点管理', title: '节点管理', description: '搜索、过滤并对单个真实 provider 节点发起原生测速，不会切换业务策略。' },
    subscriptions: { label: '订阅与同步', title: '订阅与同步', description: '区分信息采集、节点检测、受控发布和 Clash 运行验证。' },
    dns: { label: 'DNS', title: 'DNS 状态', description: '只读展示实际配置、上游和健康证据，刷新页面不会修改或清空 DNS。' },
    monitors: { label: '业务监控', title: '业务监控', description: '查看中心汇总的真实检测结果，或进入同源 Kuma 高级面板。' },
    backups: { label: '备份与恢复', title: '备份与恢复', description: '创建中心数据与配置备份，跟踪真实任务状态并在登录后下载。' },
    activity: { label: '操作记录', title: '操作记录', description: '按接口返回的真实时间与结果回看同步、选择、测速和备份活动。' }
  };

  const ERROR_LABELS = {
    login_failed: '管理密钥不正确',
    login_rate_limited: '登录尝试过于频繁，请稍后重试',
    login_required: '请先解锁管理',
    session_or_csrf_invalid: '管理会话已过期，请重新登录',
    conflict: '当前状态已变更，请刷新后重试',
    invalid_choice: '所选项已不在真实策略成员中',
    writes_disabled: '当前环境已关闭写操作'
  };

  const state = {
    data: null,
    session: { authenticated: false, csrf: '' },
    page: 'overview',
    loading: false,
    dataError: '',
    lastFetchAt: null,
    activeTabs: { routing: 'summary', subscriptions: 'sources', monitors: 'summary' },
    nodeFilter: { query: '', provider: 'all', status: 'all' },
    activityFilter: { query: '', status: 'all' },
    overviewIssuesExpanded: false,
    routeDrafts: new Map(),
    nodeTests: new Map(),
    expandedNodes: new Set(),
    backupJob: null,
    backupPoll: null,
    frameTimers: new WeakMap()
  };

  const main = document.getElementById('main-content');
  const refreshButton = document.getElementById('refresh-button');
  const sessionButton = document.getElementById('session-button');
  const updatedAt = document.getElementById('updated-at');
  const breadcrumb = document.getElementById('breadcrumb-label');
  const sidebar = document.getElementById('sidebar');
  const sidebarBackdrop = document.getElementById('sidebar-backdrop');
  const mobileMenu = document.getElementById('mobile-menu');
  const loginDialog = document.getElementById('login-dialog');
  const loginForm = document.getElementById('login-form');
  const loginError = document.getElementById('login-error');
  const adminToken = document.getElementById('admin-token');

  function cleanStatus(value) {
    const status = String(value || 'unknown').toLowerCase();
    return Object.prototype.hasOwnProperty.call(STATUS_LABELS, status) ? status : 'unknown';
  }

  function statusLabel(value) {
    return STATUS_LABELS[cleanStatus(value)];
  }

  function evidenceState(value) {
    const status = String(value || 'unknown').toLowerCase();
    const mapped = {
      available: 'ok', healthy: 'ok', success: 'ok', ready: 'ok',
      checking: 'running', queued: 'pending', cooldown: 'warning', degraded: 'warning',
      unavailable: 'error', failed: 'error', expired: 'stale'
    }[status] || status;
    return cleanStatus(mapped);
  }

  function evidenceLabel(value) {
    const status = String(value || 'unknown').toLowerCase();
    return {
      available: '可用', healthy: '正常', success: '成功', ready: '已就绪',
      checking: '检测中', queued: '已排队', cooldown: '冷却中', degraded: '降级',
      unavailable: '不可用', failed: '失败', expired: '已过期'
    }[status] || statusLabel(status);
  }

  function valueOrUnknown(value) {
    return value === null || value === undefined || value === '' ? '未知' : String(value);
  }

  function finiteNumber(value) {
    if (value === null || value === undefined || value === '') return null;
    const number = Number(value);
    return Number.isFinite(number) ? number : null;
  }

  function formatTime(value, fallback = '无时间记录') {
    if (value === null || value === undefined || value === '' || value === 0) return fallback;
    let date;
    if (typeof value === 'number') date = new Date(value < 1e12 ? value * 1000 : value);
    else if (/^\d+(\.\d+)?$/.test(String(value))) {
      const number = Number(value);
      date = new Date(number < 1e12 ? number * 1000 : number);
    } else date = new Date(value);
    if (Number.isNaN(date.getTime())) return fallback;
    return new Intl.DateTimeFormat('zh-CN', {
      year: 'numeric', month: '2-digit', day: '2-digit',
      hour: '2-digit', minute: '2-digit', second: '2-digit', hour12: false
    }).format(date).replace(/\//g, '-');
  }

  function formatBytes(value) {
    const bytes = finiteNumber(value);
    if (bytes === null || bytes < 0) return '未知';
    const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
    let number = bytes;
    let index = 0;
    while (number >= 1024 && index < units.length - 1) {
      number /= 1024;
      index += 1;
    }
    return `${number >= 10 || index === 0 ? number.toFixed(0) : number.toFixed(1)} ${units[index]}`;
  }

  function safeArray(value) {
    return Array.isArray(value) ? value : [];
  }

  function icon(name, className = '') {
    const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
    if (className) svg.setAttribute('class', className);
    svg.setAttribute('aria-hidden', 'true');
    const use = document.createElementNS('http://www.w3.org/2000/svg', 'use');
    use.setAttribute('href', `#i-${name}`);
    svg.append(use);
    return svg;
  }

  function appendChildren(node, children) {
    children.flat(Infinity).forEach(child => {
      if (child === null || child === undefined || child === false) return;
      node.append(child instanceof Node ? child : document.createTextNode(String(child)));
    });
    return node;
  }

  function h(tag, attrs = {}, ...children) {
    const node = document.createElement(tag);
    Object.entries(attrs || {}).forEach(([key, value]) => {
      if (value === null || value === undefined || value === false) return;
      if (key === 'class') node.className = value;
      else if (key === 'text') node.textContent = value;
      else if (key === 'htmlFor') node.htmlFor = value;
      else if (key === 'dataset') Object.assign(node.dataset, value);
      else if (key === 'style' && typeof value === 'object') Object.assign(node.style, value);
      else if (key.startsWith('on') && typeof value === 'function') node.addEventListener(key.slice(2).toLowerCase(), value);
      else if (key in node && !key.startsWith('aria-')) node[key] = value;
      else node.setAttribute(key, value === true ? '' : String(value));
    });
    return appendChildren(node, children);
  }

  function heading(page, actions = []) {
    const meta = PAGE_META[page];
    return h('div', { class: 'page-heading' },
      h('div', {}, h('h1', { text: meta.title }), h('p', { text: meta.description })),
      actions.length ? h('div', { class: 'page-heading-actions' }, actions) : null
    );
  }

  function panel(title, body, options = {}) {
    const box = h('section', { class: `panel ${options.className || ''}`.trim() });
    if (title || options.headerActions || options.subtitle) {
      const titleBlock = h('div', {}, title ? h(options.headingLevel || 'h2', { text: title }) : null,
        options.subtitle ? h('p', { text: options.subtitle }) : null);
      box.append(h('div', { class: 'panel-header' }, titleBlock, options.headerActions || null));
    }
    box.append(h('div', { class: `panel-body${options.flush ? ' flush' : ''}` }, body));
    return box;
  }

  function badge(status, customLabel) {
    const normalized = cleanStatus(status);
    return h('span', { class: `status-badge ${normalized}`, text: customLabel || STATUS_LABELS[normalized] });
  }

  function emptyState(title, detail) {
    return h('div', { class: 'empty-state' }, icon('empty'), h('strong', { text: title }), h('p', { text: detail }));
  }

  function notice(text, type = 'warning') {
    const node = h('div', { class: `notice ${type === 'warning' ? '' : type}`.trim(), role: type === 'danger' ? 'alert' : 'status' });
    node.append(icon(type === 'danger' ? 'alert' : 'info'), h('span', { text }));
    return node;
  }

  function table(headers, rows, emptyTitle, emptyDetail) {
    if (!rows.length) return emptyState(emptyTitle, emptyDetail);
    const head = h('thead', {}, h('tr', {}, headers.map(label => h('th', { scope: 'col', text: label }))));
    return h('div', { class: 'table-wrap', tabindex: '0', role: 'region', 'aria-label': emptyTitle },
      h('table', {}, head, h('tbody', {}, rows))
    );
  }

  function titleCell(title, detail = '') {
    return h('td', {}, h('div', { class: 'cell-title', text: valueOrUnknown(title) }), detail ? h('div', { class: 'cell-sub', text: detail }) : null);
  }

  function detailCell(value, className = '') {
    return h('td', { class: className, text: valueOrUnknown(value) });
  }

  function apiErrorMessage(payload, status) {
    const code = payload && payload.error;
    if (status === 409) return '当前状态已被其他操作更改，已拒绝覆盖。请刷新后重试。';
    if (code && ERROR_LABELS[code]) return ERROR_LABELS[code];
    if (payload && typeof payload.message === 'string') return payload.message;
    if (payload && typeof payload.detail === 'string') return payload.detail;
    if (code) return `操作未完成：${code}`;
    return `请求失败（HTTP ${status}）`;
  }

  async function api(path, options = {}) {
    const method = options.method || 'GET';
    const headers = { Accept: 'application/json' };
    if (options.body !== undefined) headers['Content-Type'] = 'application/json';
    if (method !== 'GET' && state.session.csrf) headers['X-CSRF-Token'] = state.session.csrf;
    let response;
    try {
      response = await fetch(path, {
        method,
        headers,
        credentials: 'same-origin',
        cache: 'no-store',
        body: options.body === undefined ? undefined : JSON.stringify(options.body),
        signal: options.signal
      });
    } catch (error) {
      if (error.name === 'AbortError') throw error;
      throw new Error('无法连接中心接口，请检查服务与当前网络。');
    }
    let payload = {};
    const text = await response.text();
    if (text) {
      try { payload = JSON.parse(text); }
      catch (_) { payload = { detail: '服务返回了无法解析的响应' }; }
    }
    if (!response.ok) {
      const error = new Error(apiErrorMessage(payload, response.status));
      error.status = response.status;
      error.code = payload.error;
      throw error;
    }
    return payload;
  }

  function toast(message, isError = false) {
    const region = document.getElementById('toast-region');
    const item = h('div', { class: `toast${isError ? ' error' : ''}`, role: isError ? 'alert' : 'status' },
      icon(isError ? 'alert' : 'check'), h('span', { text: message }));
    region.append(item);
    window.setTimeout(() => item.remove(), 5200);
  }

  function sessionActionButton(label, handler) {
    return h('button', { class: 'button button-secondary', type: 'button', onClick: handler }, icon('lock'), label);
  }

  function requireLogin(message = '此操作需要先解锁管理。') {
    if (state.session.authenticated) return true;
    toast(message, true);
    openLogin();
    return false;
  }

  function canWrite() {
    return state.data?.capabilities?.writes !== false;
  }

  function setBusy(value) {
    state.loading = value;
    document.body.classList.toggle('is-refreshing', value);
    refreshButton.disabled = value;
  }

  async function loadSession() {
    try {
      const session = await api('/api/center/session');
      state.session = {
        authenticated: session.authenticated === true,
        csrf: session.authenticated === true && typeof session.csrf === 'string' ? session.csrf : ''
      };
    } catch (_) {
      state.session = { authenticated: false, csrf: '' };
    }
    updateSessionButton();
  }

  async function refreshData(options = {}) {
    if (state.loading) return;
    setBusy(true);
    try {
      const data = await api('/api/center/overview');
      if (!data || typeof data !== 'object') throw new Error('中心接口未返回有效数据。');
      state.data = data;
      reconcileRouteDrafts(data);
      state.dataError = '';
      state.lastFetchAt = Date.now();
      updatedAt.textContent = data.updated_at ? `更新于 ${formatTime(data.updated_at)}` : '未返回更新时间';
      updatedAt.classList.remove('error');
      if (options.background && shouldPreserveInteractiveView()) updateRouteDraftDom();
      else renderPage();
      if (!options.silent) toast('已刷新真实观测数据。');
    } catch (error) {
      state.dataError = error.message;
      updatedAt.textContent = state.data ? '刷新失败 · 保留上次数据' : '无法获取数据';
      updatedAt.classList.add('error');
      if (state.data) {
        if (!(options.background && shouldPreserveInteractiveView())) renderPage();
        if (!options.silent) toast(error.message, true);
      }
      else renderFatalError(error.message);
    } finally {
      setBusy(false);
    }
  }

  function shouldPreserveInteractiveView() {
    if (main.querySelector('iframe')) return true;
    if (state.page === 'routing' && state.routeDrafts.size) return true;
    const active = document.activeElement;
    return Boolean(active && main.contains(active) && active.matches('input, select, textarea, [contenteditable="true"]'));
  }

  function renderFatalError(message) {
    main.replaceChildren(h('div', { class: 'page-error', role: 'alert' },
      icon('alert'), h('h1', { text: '无法读取中心状态' }), h('p', { text: message }),
      h('button', { class: 'button button-primary', type: 'button', onClick: () => refreshData() }, icon('refresh'), '重试')
    ));
  }

  function updateSessionButton() {
    const span = sessionButton.querySelector('span');
    span.textContent = state.session.authenticated ? '退出管理' : '管理登录';
    sessionButton.classList.toggle('is-authenticated', state.session.authenticated);
    sessionButton.title = state.session.authenticated ? '当前已解锁管理操作' : '解锁受保护的管理操作';
  }

  function openLogin() {
    loginError.hidden = true;
    loginError.textContent = '';
    adminToken.value = '';
    loginDialog.showModal();
    window.setTimeout(() => adminToken.focus(), 0);
  }

  async function logout() {
    if (!window.confirm('退出当前管理会话？只读页面仍可继续查看。')) return;
    try {
      await api('/api/local/logout', { method: 'POST', body: {} });
      state.session = { authenticated: false, csrf: '' };
      updateSessionButton();
      renderPage();
      toast('已退出管理会话。');
    } catch (error) {
      toast(error.message, true);
    }
  }

  function renderPage() {
    if (!state.data) return;
    document.querySelectorAll('#primary-nav a').forEach(link => {
      if (link.dataset.page === state.page) link.setAttribute('aria-current', 'page');
      else link.removeAttribute('aria-current');
    });
    breadcrumb.textContent = PAGE_META[state.page].label;
    document.title = `${PAGE_META[state.page].label} · 进源Clash Center`;
    const renderers = {
      overview: renderOverview,
      routing: renderRouting,
      nodes: renderNodes,
      subscriptions: renderSubscriptions,
      dns: renderDns,
      monitors: renderMonitors,
      backups: renderBackups,
      activity: renderActivity
    };
    const rendered = renderers[state.page]();
    const headingNode = rendered.querySelector('.page-heading');
    const banners = [];
    if (state.data.environment === 'isolated') {
      banners.push(notice('隔离验收环境，非生产状态。本页数据与操作结果不代表生产环境。', 'warning'));
    }
    if (state.dataError) {
      const evidenceTime = state.data.updated_at ? formatTime(state.data.updated_at) : (state.lastFetchAt ? formatTime(state.lastFetchAt) : '未知');
      banners.push(notice(`实时刷新失败，当前展示的是已过期数据（最后成功数据时间：${evidenceTime}）。原因：${state.dataError}`, 'danger'));
    }
    if (headingNode && banners.length) headingNode.after(...banners);
    main.replaceChildren(rendered);
  }

  function metric(label, value) {
    const unknown = value === null || value === undefined;
    return h('div', { class: 'metric' }, h('span', { class: 'metric-label', text: label }),
      h('strong', { class: `metric-value${unknown ? ' unknown' : ''}`, text: unknown ? '未知' : String(value) }));
  }

  function renderSummaryStrip() {
    const overall = state.data.overall || {};
    const status = cleanStatus(overall.state);
    const metrics = state.data.metrics || {};
    const orbIcon = status === 'ok' ? 'check' : status === 'error' || status === 'warning' ? 'alert' : status === 'unknown' ? 'info' : 'refresh';
    return panel('', h('div', { class: 'summary-strip' },
      h('div', { class: 'overall-state' },
        h('span', { class: `state-orb ${status}` }, icon(orbIcon)),
        h('div', {}, h('strong', { text: overall.title || statusLabel(status) }), h('span', { text: overall.detail || '当前没有更多运行说明' }))
      ),
      metric('活动节点', metrics.nodes),
      metric('订阅来源', metrics.subscriptions),
      metric('业务选择', metrics.selectors),
      metric('规则', metrics.rules)
    ), { flush: true });
  }

  function stageIcon(status) {
    if (status === 'ok') return 'check';
    if (status === 'error' || status === 'warning' || status === 'stale') return 'alert';
    if (status === 'running' || status === 'pending') return 'refresh';
    return 'info';
  }

  function renderSyncPanel() {
    const sync = state.data.sync || {};
    const stages = safeArray(sync.stages);
    let body;
    if (!stages.length) {
      body = emptyState('暂无分阶段同步证据', '接口未返回信息来源读取、节点检测、受控发布或运行加载状态。');
    } else {
      const flow = h('div', { class: 'sync-flow', role: 'list', 'aria-label': '同步阶段' });
      stages.forEach((stage, index) => {
        const status = cleanStatus(stage.state);
        const lastSuccess = stage.last_success ? `最后成功：${formatTime(stage.last_success)}` : '最后成功：无记录';
        const nextDue = stage.next_due ? `下次重试：${formatTime(stage.next_due)}` : '下次重试：未安排';
        flow.append(h('div', {
          class: `sync-stage ${status}${status === 'ok' && index < stages.length - 1 ? ' is-complete' : ''}`,
          role: 'listitem'
        },
        h('span', { class: 'sync-marker' }, icon(stageIcon(status))),
        h('span', { class: 'sync-stage-title', text: stage.label || stage.id || `阶段 ${index + 1}` }),
        h('span', { class: 'sync-stage-state', text: statusLabel(status) }),
        h('p', { class: 'sync-stage-detail', text: stage.detail || '未返回详细原因' }),
        h('div', { class: 'sync-stage-time' }, h('div', { text: lastSuccess }), h('div', { text: nextDue }))));
      });
      body = h('div', {}, flow);
      const sourceInfo = [];
      if (sync.information_sources !== null && sync.information_sources !== undefined) sourceInfo.push(`信息来源：${valueOrUnknown(sync.information_sources)}`);
      if (sync.node_sources !== null && sync.node_sources !== undefined) sourceInfo.push(`节点来源：${valueOrUnknown(sync.node_sources)}`);
      if (sourceInfo.length) body.append(notice(`${sourceInfo.join(' · ')}。信息来源数不等于已发布节点数；Clash 加载仅按已返回的名称/数量等证据表述，不代表全部端点和业务已通过。`, 'info'));
    }
    return panel('同步状态', body, { className: 'sync-panel', headerActions: badge(sync.state) });
  }

  function routeChain(value) {
    const values = Array.isArray(value) ? value : value ? [value] : [];
    if (!values.length) return h('span', { class: 'cell-sub', text: '未返回策略链' });
    const node = h('div', { class: 'route-chain' });
    values.forEach((part, index) => {
      if (index) node.append(icon('chevron'));
      node.append(h('span', { text: valueOrUnknown(part) }));
    });
    return node;
  }

  function overviewBusinesses(limit = 6) {
    const businesses = safeArray(state.data.businesses);
    const isPool = item => /(?:节点池|专用|稳定节点|pool)/i.test(`${item.name || ''} ${item.id || ''}`);
    const eligible = businesses.filter(item => !isPool(item));
    const selected = [];
    const used = new Set();
    const priorities = [
      { match: /chatgpt/i, preferred: /^chatgpt$/i },
      { match: /gemini/i, preferred: /^gemini$/i },
      { match: /(^|[^a-z])grok([^a-z]|$)/i, preferred: /^grok$/i },
      { match: /google/i, preferred: /^google$/i },
      { match: /国内/, preferred: /国内(?:网站|直连)/ }
    ];
    priorities.forEach(({ match, preferred }) => {
      const matches = eligible.filter(item => !used.has(item) && match.test(`${item.name || ''} ${item.id || ''}`));
      matches.sort((left, right) => {
        const leftName = String(left.name || left.id || '');
        const rightName = String(right.name || right.id || '');
        return Number(!preferred.test(leftName)) - Number(!preferred.test(rightName)) || leftName.length - rightName.length;
      });
      if (matches[0]) { selected.push(matches[0]); used.add(matches[0]); }
    });
    eligible.forEach(item => { if (!used.has(item) && selected.length < limit) { selected.push(item); used.add(item); } });
    return selected.slice(0, limit);
  }

  function renderBusinessRows(limit) {
    const selected = overviewBusinesses(typeof limit === 'number' ? limit : 6);
    return selected.map(item => h('tr', {},
      titleCell(item.name || item.id, item.detail || ''),
      detailCell(item.selection),
      h('td', {}, routeChain(item.chain)),
      detailCell(item.leaf),
      h('td', {}, badge(item.state))
    ));
  }

  function issueList() {
    const issues = safeArray(state.data.issues);
    if (!issues.length) return emptyState('暂无待处理事项', '接口当前未返回需要关注的真实问题。');
    const visible = state.overviewIssuesExpanded ? issues : issues.slice(0, 3);
    const list = h('ul', { class: 'issue-list', id: 'overview-issues-list' });
    visible.forEach(item => {
      const page = PAGE_META[item.page] ? item.page : null;
      list.append(h('li', { class: `issue-item ${cleanStatus(item.state)}` },
        h('div', { class: 'issue-top' }, h('span', { class: 'issue-title', text: item.title || '未命名事项' }), badge(item.state)),
        h('div', { class: 'issue-detail', text: item.detail || '未返回详细原因' }),
        page ? h('div', { class: 'issue-action' }, h('a', { href: `#/${page}`, text: `前往${PAGE_META[page].label}` })) : null
      ));
    });
    if (issues.length <= 3) return list;
    const toggle = h('button', {
      class: 'issue-list-toggle', id: 'overview-issues-toggle', type: 'button',
      'aria-controls': 'overview-issues-list', 'aria-expanded': String(state.overviewIssuesExpanded),
      onClick: () => {
        state.overviewIssuesExpanded = !state.overviewIssuesExpanded;
        renderPage();
        document.getElementById('overview-issues-toggle')?.focus();
      }
    }, state.overviewIssuesExpanded ? '收起，仅显示 3 条' : `查看全部（${issues.length}）`);
    return h('div', {}, list, h('div', { class: 'issue-list-footer' }, toggle));
  }

  function eventTimeline(limit) {
    const events = safeArray(state.data.events);
    const selected = typeof limit === 'number' ? events.slice(0, limit) : events;
    if (!selected.length) return emptyState('暂无操作记录', '接口当前未返回带真实结果的活动记录。');
    return h('ol', { class: 'timeline' }, selected.map(item => h('li', { class: `timeline-item ${cleanStatus(item.state)}` },
      h('span', { class: 'timeline-dot', 'aria-hidden': 'true' }),
      h('div', { class: 'timeline-time', text: formatTime(item.at) }),
      h('div', { class: 'timeline-title', text: item.title || '未命名操作' }),
      h('div', { class: 'timeline-detail', text: item.detail || '未返回详细结果' })
    )));
  }

  function renderServicePanel() {
    const services = safeArray(state.data.services);
    const rows = services.map(item => h('tr', {},
      titleCell(item.name || item.id, item.detail || ''),
      detailCell(formatTime(item.checked_at)),
      h('td', {}, badge(item.state))
    ));
    return panel('核心服务', table(['服务', '检查时间', '状态'], rows, '暂无服务证据', '接口未返回核心服务检测结果。'), { flush: true });
  }

  function renderOverview() {
    const page = h('div', { class: 'page' }, heading('overview'), renderSummaryStrip(), renderSyncPanel());
    const businessRows = renderBusinessRows(6);
    page.append(h('div', { class: 'overview-grid' },
      panel('业务速览', table(['业务', '当前策略', '策略链', '最终出口', '状态'], businessRows, '暂无业务分流证据', '接口当前未返回业务策略与最终出口。'), { flush: true }),
      panel('需要关注', issueList(), { flush: true })
    ));
    page.append(h('div', { class: 'overview-grid' }, renderServicePanel(), panel('最近操作', eventTimeline(5))));
    return page;
  }

  function tabs(group, values) {
    return h('div', { class: 'tabs', role: 'tablist', 'aria-label': '视图切换' }, values.map(item => h('button', {
      class: 'tab-button', type: 'button', role: 'tab',
      'aria-selected': state.activeTabs[group] === item.id ? 'true' : 'false',
      onClick: () => { state.activeTabs[group] = item.id; renderPage(); }
    }, item.label)));
  }

  function advancedGate(kind) {
    return h('div', { class: 'empty-state' }, icon('lock'), h('strong', { text: `先解锁统一管理，再打开${kind}` }),
      h('p', { text: '统一会话只控制入口；高级面板仍保留其自身认证与权限。' }),
      h('button', { class: 'button button-primary', type: 'button', onClick: openLogin }, icon('lock'), '管理登录'));
  }

  function embeddedFrame(path, title, options = {}) {
    if (options.requiresSession && !state.session.authenticated) return advancedGate(title);
    const loading = h('div', { class: 'frame-loading', role: 'status' }, h('span', { class: 'spinner' }), `正在加载${title}…`);
    const fallback = h('div', { class: 'frame-fallback' },
      notice(`${title}未正常加载。请确认同源固定代理已配置，并检查其自身认证状态。`, 'danger'),
      h('a', { class: 'button button-secondary button-small', href: path, target: '_blank', rel: 'noopener' }, icon('external'), '在新窗口打开')
    );
    fallback.hidden = true;
    const frame = h('iframe', {
      class: 'embedded-frame', src: path, title, loading: 'lazy',
      onLoad: () => {
        loading.hidden = true;
        const timer = state.frameTimers.get(frame);
        if (timer) window.clearTimeout(timer);
        try {
          const documentText = `${frame.contentDocument?.title || ''} ${frame.contentDocument?.body?.innerText || ''}`.slice(0, 240);
          fallback.hidden = !(!frame.contentDocument?.body || /(?:404|not found|page not found|页面不存在)/i.test(documentText));
        } catch (_) {
          fallback.hidden = true;
        }
      },
      onError: () => { loading.hidden = true; fallback.hidden = false; }
    });
    const timer = window.setTimeout(() => {
      if (!loading.hidden) fallback.hidden = false;
    }, 12000);
    state.frameTimers.set(frame, timer);
    return h('div', { class: 'embedded-wrap' }, fallback, loading, frame);
  }

  function reconcileRouteDrafts(data = state.data) {
    const businesses = safeArray(data?.businesses);
    state.routeDrafts.forEach((draft, group) => {
      const current = businesses.find(item => String(item.id) === String(group));
      draft.conflict = '';
      draft.current = current?.selection;
      if (!current) draft.conflict = '该策略组已不在最新数据中';
      else if (String(current.selection) !== String(draft.expected)) {
        draft.conflict = `后端当前值已从「${valueOrUnknown(draft.expected)}」变为「${valueOrUnknown(current.selection)}」`;
      } else if (!safeArray(current.options).map(String).includes(String(draft.choice))) {
        draft.conflict = `草稿选项「${draft.choice}」已不在最新成员中`;
      }
    });
  }

  function updateRouteDraftDom() {
    document.querySelectorAll('.route-control[data-route-group]').forEach(control => {
      const draft = state.routeDrafts.get(control.dataset.routeGroup);
      const warning = control.querySelector('.route-draft-warning');
      const apply = control.querySelector('[data-route-apply]');
      const discard = control.querySelector('[data-route-discard]');
      if (warning) {
        warning.hidden = !draft?.conflict;
        warning.textContent = draft?.conflict ? `${draft.conflict}。草稿已保留，请放弃草稿后基于新状态重选。` : '';
      }
      if (apply) apply.disabled = !canWrite() || !draft || Boolean(draft.conflict);
      if (discard) discard.hidden = !draft;
    });
  }

  async function selectRoute(item, select, button) {
    if (!requireLogin('切换业务策略需要先解锁管理。')) return;
    if (!canWrite()) { toast('当前环境已关闭写操作。', true); return; }
    const draft = state.routeDrafts.get(String(item.id));
    if (!draft) return;
    if (draft.conflict) { toast(`${draft.conflict}。草稿未提交，请放弃后重新选择。`, true); return; }
    const choice = draft.choice;
    const expected = draft.expected;
    if (!choice || choice === expected) return;
    if (!window.confirm(`确认将「${item.name || item.id}」从「${valueOrUnknown(expected)}」切换为「${choice}」？\n\n服务端会再次核对当前值与选项成员，冲突时不会覆盖。`)) {
      return;
    }
    button.disabled = true;
    select.disabled = true;
    try {
      await api('/api/center/select', { method: 'POST', body: { group: item.id, choice, expected } });
      state.routeDrafts.delete(String(item.id));
      toast('策略选择已提交，正在重新读取真实结果。');
      await refreshData({ silent: true });
    } catch (error) {
      toast(error.message, true);
      if (error.status === 401 || error.status === 403) {
        state.session = { authenticated: false, csrf: '' };
        updateSessionButton();
      }
      await refreshData({ silent: true });
    }
  }

  function routeControl(item) {
    const options = safeArray(item.options).map(String);
    if (!options.length) return h('span', { class: 'cell-sub', text: '接口未返回可选成员' });
    const group = String(item.id);
    const draft = state.routeDrafts.get(group);
    if (draft) reconcileRouteDrafts(state.data);
    const select = h('select', { 'aria-label': `更改 ${item.name || item.id} 的策略`, disabled: !canWrite() });
    if (draft && !options.includes(String(draft.choice))) {
      select.append(h('option', { value: draft.choice, text: `${draft.choice}（已不在成员中）`, selected: true, disabled: true }));
    }
    options.forEach(choice => select.append(h('option', { value: choice, text: choice, selected: choice === String(draft?.choice ?? item.selection) })));
    const button = h('button', { class: 'button button-primary button-small', type: 'button', dataset: { routeApply: '' }, disabled: !draft || Boolean(draft.conflict) }, '应用');
    const discard = h('button', {
      class: 'button button-link button-small', type: 'button', dataset: { routeDiscard: '' }, hidden: !draft,
      onClick: () => { state.routeDrafts.delete(group); renderPage(); }
    }, '放弃草稿');
    const warning = h('div', { class: 'route-draft-warning', role: 'alert', hidden: !draft?.conflict,
      text: draft?.conflict ? `${draft.conflict}。草稿已保留，请放弃草稿后基于新状态重选。` : '' });
    select.addEventListener('change', () => {
      if (select.value === String(item.selection)) state.routeDrafts.delete(group);
      else {
        const existing = state.routeDrafts.get(group);
        state.routeDrafts.set(group, { choice: select.value, expected: existing ? existing.expected : item.selection, conflict: '', current: item.selection });
      }
      reconcileRouteDrafts(state.data);
      updateRouteDraftDom();
    });
    button.addEventListener('click', () => selectRoute(item, select, button));
    const controls = h('div', { class: 'route-select' }, select, button, discard);
    return h('div', { class: 'route-control', dataset: { routeGroup: group } }, controls, warning);
  }

  function renderRoutingSummary() {
    const businesses = safeArray(state.data.businesses);
    const rows = businesses.map(item => h('tr', {},
      titleCell(item.name || item.id, item.detail || ''),
      detailCell(item.selection),
      h('td', {}, routeChain(item.chain)),
      detailCell(item.leaf),
      h('td', {}, badge(item.state)),
      h('td', {}, routeControl(item))
    ));
    const body = h('div', {}, !state.session.authenticated ? notice('当前为只读模式。选择实际成员并应用前需管理登录；提交时会使用 expected 保护拒绝覆盖并发更改。', 'info') : null,
      table(['业务 / 策略组', '当前选择', '真实策略链', '最终出口', '状态', '受控选择'], rows, '暂无业务分流数据', '接口当前未返回业务策略组、实际成员或最终出口。'));
    return body;
  }

  function renderRouting() {
    const actions = state.session.authenticated ? [] : [sessionActionButton('管理登录', openLogin)];
    const page = h('div', { class: 'page' }, heading('routing', actions));
    const current = state.activeTabs.routing;
    const body = current === 'summary' ? renderRoutingSummary() : embeddedFrame('/cgi-bin/luci/', 'OpenClash 高级管理', { requiresSession: true });
    page.append(panel(current === 'summary' ? '实际业务走向' : 'OpenClash 高级管理', body, {
      flush: true,
      headerActions: tabs('routing', [{ id: 'summary', label: '统一视图' }, { id: 'advanced', label: '高级 LuCI' }])
    }));
    return page;
  }

  function nodeIdentity(node) {
    return { provider: node.provider || node.source || '', name: node.name || node.label || node.id || '' };
  }

  function nodeTestKey(node) {
    const identity = nodeIdentity(node);
    return `${identity.provider}\u0000${identity.name}`;
  }

  function nodeLatency(node) {
    const test = state.nodeTests.get(nodeTestKey(node));
    if (test?.state === 'running') return '测试中…';
    if (test?.error) return test.error;
    const value = test?.latency_ms ?? node.latency_ms ?? node.delay_ms ?? node.delay;
    const number = finiteNumber(value);
    if (number === null || number <= 0) return '未取得';
    const stale = test?.latency_ms === undefined && nodeFreshness(node).state === 'stale';
    return `${Math.round(number)} ms${stale ? '（旧数据）' : ''}`;
  }

  function nodeFreshness(node) {
    const ownsFresh = Object.prototype.hasOwnProperty.call(node, 'fresh');
    const freshUntil = finiteNumber(node.fresh_until);
    if (node.fresh === true) {
      return { state: 'ok', label: '有效期内', detail: freshUntil === null ? '未返回到期时间' : `有效至 ${formatTime(freshUntil)}` };
    }
    if (freshUntil !== null && freshUntil <= Date.now() / 1000) {
      return { state: 'stale', label: '样本已过期', detail: `有效期截止于 ${formatTime(freshUntil)}` };
    }
    if (ownsFresh && node.fresh === false) {
      return {
        state: 'stale', label: '样本已过期',
        detail: freshUntil === null ? '接口已明确标记样本不新鲜' : `接口未标记为新鲜；返回的有效期至 ${formatTime(freshUntil)}`
      };
    }
    return {
      state: 'unknown',
      label: ownsFresh ? '未确认新鲜' : '未返回新鲜度',
      detail: freshUntil === null ? '无到期时间证据' : `接口返回的有效期至 ${formatTime(freshUntil)}，但未标记为新鲜`
    };
  }

  function nodeDisplayState(node, test) {
    if (test?.state === 'running' || test?.state === 'error') return cleanStatus(test.state);
    const base = cleanStatus(node.state);
    if (base === 'ok' && node.fresh !== true) return nodeFreshness(node).state;
    return base;
  }

  function nodeDetailId(node) {
    const key = nodeTestKey(node);
    let hash = 2166136261;
    for (let index = 0; index < key.length; index += 1) {
      hash ^= key.charCodeAt(index);
      hash = Math.imul(hash, 16777619);
    }
    return `node-detail-${(hash >>> 0).toString(36)}`;
  }

  function evidenceItem(label, value, detail = '') {
    const valueNode = value instanceof Node ? value : h('strong', { text: valueOrUnknown(value) });
    return h('div', { class: 'node-evidence-item' },
      h('span', { class: 'node-evidence-label', text: label }),
      h('div', { class: 'node-evidence-value' }, valueNode),
      detail ? h('span', { class: 'node-evidence-sub', text: detail }) : null
    );
  }

  function formatConfidence(value) {
    const number = finiteNumber(value);
    if (number === null) return '未知';
    const percent = number >= 0 && number <= 1 ? number * 100 : number;
    return `${Math.round(percent)}%`;
  }

  function capabilityTable(node) {
    const capabilities = node.capabilities && typeof node.capabilities === 'object' && !Array.isArray(node.capabilities) ? node.capabilities : {};
    const parentStale = nodeFreshness(node).state === 'stale';
    const rows = Object.entries(capabilities).slice(0, 32).map(([name, recordValue]) => {
      const record = recordValue && typeof recordValue === 'object' ? recordValue : {};
      const success = finiteNumber(record.consecutive_success);
      const failure = finiteNumber(record.consecutive_failure);
      const streak = success === null && failure === null ? '未知' : `成功 ${success === null ? '未知' : success} / 失败 ${failure === null ? '未知' : failure}`;
      const previousLabel = evidenceLabel(record.status);
      const statusCell = parentStale
        ? h('td', {}, badge('stale', '已过期'), h('div', { class: 'cell-sub', text: `上次${previousLabel}` }))
        : h('td', {}, badge(evidenceState(record.status), previousLabel));
      return h('tr', {},
        titleCell(name),
        statusCell,
        detailCell(formatTime(record.last_checked)),
        detailCell(formatConfidence(record.confidence)),
        detailCell(streak),
        detailCell(record.reason || '未返回原因码', record.reason ? 'cell-mono' : '')
      );
    });
    return table(['业务能力', '状态', '上次检查', '置信度', '连续样本', '原因码'], rows,
      '暂无业务能力证据', '接口未返回 capabilities，不能将该节点标记为任何业务可用。');
  }

  function nodeDetailRow(node) {
    const identity = nodeIdentity(node);
    const schedule = node.health_schedule && typeof node.health_schedule === 'object' && !Array.isArray(node.health_schedule) ? node.health_schedule : {};
    const summary = node.latency_summary && typeof node.latency_summary === 'object' && !Array.isArray(node.latency_summary) ? node.latency_summary : {};
    const egress = node.egress && typeof node.egress === 'object' && !Array.isArray(node.egress) ? node.egress : {};
    const freshness = nodeFreshness(node);
    const sampleSource = schedule.latency_source || (node.latency_kind && node.latency_kind !== 'unknown' ? node.latency_kind : '未知');
    const sampleAt = schedule.latency_sample_at || node.updated_at;
    const nextDue = schedule.next_due ? formatTime(schedule.next_due) : '未安排';
    const cooldown = schedule.cooldown_until ? formatTime(schedule.cooldown_until) : '无冷却截止证据';
    const scheduleValue = freshness.state === 'stale'
      ? h('div', {}, badge('stale', '已过期'), h('div', { class: 'cell-sub', text: `历史状态：${evidenceLabel(schedule.status)}` }))
      : h('div', { class: 'cell-actions' }, badge(evidenceState(schedule.status), evidenceLabel(schedule.status)));
    const egressName = [egress.country, egress.colo].filter(Boolean).join(' / ') || '未知';
    const median = finiteNumber(summary.median_ms);
    const p95 = finiteNumber(summary.p95_ms);
    const jitter = finiteNumber(node.jitter_ms);
    const samples = finiteNumber(summary.samples);
    const qualityParts = [
      median === null ? null : `中位 ${Math.round(median)} ms`,
      p95 === null ? null : `P95 ${Math.round(p95)} ms`,
      jitter === null ? null : `抖动 ${Math.round(jitter)} ms`
    ].filter(Boolean);
    const detail = h('div', { class: 'node-detail', id: nodeDetailId(node) },
      h('h3', { class: 'node-detail-heading', text: `${identity.name || '未命名节点'} · 证据详情` }),
      h('div', { class: 'node-evidence-grid' },
        evidenceItem('样本新鲜度', badge(freshness.state, freshness.label), freshness.detail),
        evidenceItem('健康检测调度', scheduleValue, `下次复测：${nextDue} · 冷却截止：${cooldown}`),
        evidenceItem('上次延迟样本', sampleSource, `${sampleAt ? formatTime(sampleAt) : '无样本时间'}${samples === null ? '' : ` · ${samples} 个样本`}`),
        evidenceItem('观测出口', egressName, egress.last_checked ? `检查于 ${formatTime(egress.last_checked)}${finiteNumber(egress.changed_count) === null ? '' : ` · 变化 ${egress.changed_count} 次`}` : '无出口检查时间'),
        evidenceItem('延迟摘要', qualityParts.length ? qualityParts.join(' · ') : '未知', `单次延迟不等于业务可用性`),
        evidenceItem('节点评分 / 置信度', `${finiteNumber(node.score) === null ? '未知' : node.score} / ${formatConfidence(node.confidence)}`, '仅展示接口已返回证据'),
        evidenceItem('上次观测', formatTime(schedule.last_observation || node.updated_at), `上次成功：${formatTime(schedule.last_success)}`),
        evidenceItem('上次出现', formatTime(node.last_seen), schedule.reason ? `调度原因码：${schedule.reason}` : '未返回调度原因码')
      ),
      h('h3', { class: 'node-detail-heading', text: '业务能力证据' }),
      h('div', { class: 'capability-table' }, capabilityTable(node)),
      h('p', { class: 'node-details-note', text: '“可用”只代表对应业务能力项的最近有效证据；未返回、已过期或处于冷却期的项不会推断为可用。' })
    );
    return h('tr', { class: 'node-detail-row' }, h('td', { colSpan: 5 }, detail));
  }

  async function testNode(node, button) {
    if (!requireLogin('原生节点测速需要先解锁管理。')) return;
    if (!canWrite()) { toast('当前环境已关闭写操作。', true); return; }
    const identity = nodeIdentity(node);
    if (!identity.provider || !identity.name) { toast('该行缺少 provider 或节点名，无法发起真实测速。', true); return; }
    const key = nodeTestKey(node);
    state.nodeTests.set(key, { state: 'running' });
    button.disabled = true;
    renderNodeRows();
    try {
      const result = await api('/api/center/node-test', { method: 'POST', body: identity });
      const latency = result.latency_ms ?? result.delay_ms ?? result.delay;
      state.nodeTests.set(key, { state: cleanStatus(result.state || 'ok'), latency_ms: latency, detail: result.detail || '' });
      const measured = finiteNumber(latency);
      toast(measured === null || measured <= 0 ? '节点测试已完成，未取得有效的正延迟数值。' : `节点真实测速完成：${Math.round(measured)} ms。`);
    } catch (error) {
      state.nodeTests.set(key, { state: 'error', error: error.message });
      toast(error.message, true);
    }
    renderNodeRows();
  }

  function filteredNodes() {
    const query = state.nodeFilter.query.trim().toLocaleLowerCase('zh-CN');
    return safeArray(state.data.nodes).filter(node => {
      const identity = nodeIdentity(node);
      const capabilityNames = node.capabilities && typeof node.capabilities === 'object' ? Object.keys(node.capabilities).join(' ') : '';
      const egress = node.egress && typeof node.egress === 'object' ? `${node.egress.country || ''} ${node.egress.colo || ''}` : '';
      const text = `${identity.name} ${identity.provider} ${node.detail || ''} ${capabilityNames} ${egress}`.toLocaleLowerCase('zh-CN');
      return (!query || text.includes(query)) &&
        (state.nodeFilter.provider === 'all' || identity.provider === state.nodeFilter.provider) &&
        (state.nodeFilter.status === 'all' || cleanStatus(node.state) === state.nodeFilter.status);
    });
  }

  function nodeRows() {
    return filteredNodes().flatMap(node => {
      const identity = nodeIdentity(node);
      const test = state.nodeTests.get(nodeTestKey(node));
      const actions = h('div', { class: 'cell-actions' });
      const detailId = nodeDetailId(node);
      const expanded = state.expandedNodes.has(nodeTestKey(node));
      const detailButton = h('button', {
        class: 'button button-secondary button-small', type: 'button',
        'aria-expanded': String(expanded), 'aria-controls': detailId,
        onClick: () => {
          const key = nodeTestKey(node);
          if (state.expandedNodes.has(key)) state.expandedNodes.delete(key);
          else state.expandedNodes.add(key);
          renderNodeRows();
          document.querySelector(`[aria-controls="${detailId}"]`)?.focus();
        }
      }, expanded ? '收起详情' : '查看详情');
      const button = h('button', {
        class: 'button button-secondary button-small', type: 'button',
        disabled: test?.state === 'running' || !identity.provider || !identity.name || !canWrite(),
        onClick: event => testNode(node, event.currentTarget)
      }, test?.state === 'running' ? '测试中' : '原生测速');
      actions.append(detailButton, button);
      const row = h('tr', {},
        titleCell(identity.name || '未命名节点', node.detail || ''),
        detailCell(identity.provider || '来源未知'),
        h('td', {}, badge(nodeDisplayState(node, test))),
        titleCell(nodeLatency(node), test?.detail || (node.updated_at || node.checked_at || node.tested_at ? `样本时间：${formatTime(node.updated_at || node.checked_at || node.tested_at)}` : '无测速时间记录')),
        h('td', {}, actions)
      );
      return expanded ? [row, nodeDetailRow(node)] : [row];
    });
  }

  function renderNodeRows() {
    const container = document.getElementById('node-table-container');
    if (!container) return;
    const displayedNodes = filteredNodes().length;
    const rows = nodeRows();
    container.replaceChildren(table(['节点', 'Provider', '状态', '真实延迟', '操作'], rows, '没有匹配的节点', '请调整搜索或过滤条件；若未设置过滤，则接口当前未返回节点。'));
    const count = document.getElementById('node-filter-count');
    if (count) count.textContent = `显示 ${displayedNodes} / ${safeArray(state.data.nodes).length}`;
  }

  function renderNodes() {
    const nodes = safeArray(state.data.nodes);
    const providers = [...new Set(nodes.map(node => nodeIdentity(node).provider).filter(Boolean))].sort((a, b) => a.localeCompare(b, 'zh-CN'));
    const statuses = [...new Set(nodes.map(node => cleanStatus(node.state)))];
    const query = h('input', { type: 'search', value: state.nodeFilter.query, placeholder: '搜索节点名、Provider 或详情', 'aria-label': '搜索节点' });
    query.addEventListener('input', event => { state.nodeFilter.query = event.target.value; renderNodeRows(); });
    const providerSelect = h('select', { 'aria-label': '按 Provider 过滤' }, h('option', { value: 'all', text: '全部 Provider' }));
    providers.forEach(provider => providerSelect.append(h('option', { value: provider, text: provider, selected: provider === state.nodeFilter.provider })));
    providerSelect.addEventListener('change', event => { state.nodeFilter.provider = event.target.value; renderNodeRows(); });
    const statusSelect = h('select', { 'aria-label': '按状态过滤' }, h('option', { value: 'all', text: '全部状态' }));
    statuses.forEach(status => statusSelect.append(h('option', { value: status, text: statusLabel(status), selected: status === state.nodeFilter.status })));
    statusSelect.addEventListener('change', event => { state.nodeFilter.status = event.target.value; renderNodeRows(); });
    const toolbar = h('div', { class: 'toolbar' }, h('label', { class: 'search-field' }, icon('search'), query), providerSelect, statusSelect,
      h('span', { class: 'filter-count', id: 'node-filter-count', text: `显示 ${nodes.length} / ${nodes.length}` }));
    const tableContainer = h('div', { id: 'node-table-container' }, table(['节点', 'Provider', '状态', '真实延迟', '操作'], nodeRows(), '暂无节点', '接口当前未返回真实节点数据。'));
    const actions = state.session.authenticated ? [] : [sessionActionButton('管理登录', openLogin)];
    const page = h('div', { class: 'page' }, heading('nodes', actions),
      notice('原生测速只测试所选 provider 节点，不切换任何策略组，也不将单次延迟冒充为业务可用性。', 'info'),
      panel('节点列表', h('div', {}, toolbar, tableContainer), { flush: true }));
    return page;
  }

  function subscriptionUsage(provider) {
    const metrics = provider.metrics && typeof provider.metrics === 'object' && !Array.isArray(provider.metrics) ? provider.metrics : null;
    const usage = provider.usage && typeof provider.usage === 'object' && !Array.isArray(provider.usage) ? provider.usage : provider;
    const validBytes = value => {
      if (typeof value === 'boolean') return null;
      const number = finiteNumber(value);
      return number !== null && number >= 0 ? number : null;
    };
    let used;
    let totalRaw;
    if (metrics) {
      const upload = validBytes(metrics.upload);
      const download = validBytes(metrics.download);
      const combined = upload !== null && download !== null ? upload + download : null;
      used = combined !== null && Number.isFinite(combined) ? combined : null;
      totalRaw = validBytes(metrics.total);
    } else {
      used = validBytes(usage.used_bytes ?? usage.used);
      totalRaw = validBytes(usage.total_bytes ?? usage.total ?? usage.quota_bytes);
    }
    const unlimitedOrUnknown = totalRaw === 0;
    const total = totalRaw !== null && totalRaw > 0 ? totalRaw : null;
    if (used === null && total === null && !unlimitedOrUnknown) return h('span', { class: 'cell-sub', text: '未返回用量' });
    const usedText = used === null ? '已用未知' : formatBytes(used);
    const totalText = unlimitedOrUnknown ? '总量未知或不限量' : total === null ? '总量未提供' : formatBytes(total);
    const text = `${usedText} / ${totalText}`;
    if (used === null || total === null) return h('span', { text });
    const percent = Math.max(0, Math.min(100, used / total * 100));
    const level = percent >= 95 ? 'error' : percent >= 80 ? 'warning' : '';
    return h('div', {}, h('div', { text: `${text} · ${percent.toFixed(1)}%` }), h('div', { class: 'usage-track', 'aria-hidden': 'true' }, h('div', { class: `usage-fill ${level}`, style: { width: `${percent}%` } })));
  }

  function subscriptionExpiry(provider) {
    const metrics = provider.metrics && typeof provider.metrics === 'object' && !Array.isArray(provider.metrics) ? provider.metrics : null;
    let provided = false;
    let value;
    if (metrics && Object.prototype.hasOwnProperty.call(metrics, 'expire')) {
      provided = true;
      value = metrics.expire;
    } else {
      for (const key of ['expires_at', 'expire_at']) {
        if (Object.prototype.hasOwnProperty.call(provider, key)) {
          provided = true;
          value = provider[key];
          break;
        }
      }
    }
    if (!provided || value === null || value === undefined || value === '') return '未提供到期时间';
    if (typeof value === 'boolean') return '到期时间无效';
    const timestamp = finiteNumber(value);
    if (timestamp === 0) return '无到期时间';
    if (timestamp === null || timestamp < 0) return '到期时间无效';
    return formatTime(timestamp, '到期时间无效');
  }

  function subscriptionLastSuccess(provider) {
    const value = Object.prototype.hasOwnProperty.call(provider, 'last_success')
      ? provider.last_success
      : provider.updated_at || provider.checked_at;
    if (typeof value === 'boolean') return '无成功记录';
    return formatTime(value, '无成功记录');
  }

  function renderSourceSync(sync) {
    if (!sync || typeof sync !== 'object' || Array.isArray(sync)) return emptyState('暂无来源同步证据', '接口未返回 source_sync 状态。');
    return h('div', { class: 'kv-grid' },
      h('div', { class: 'kv-label', text: '状态' }), h('div', { class: 'kv-value' }, badge(sync.state)),
      h('div', { class: 'kv-label', text: '详情 / 原因' }), h('div', { class: 'kv-value', text: sync.detail || '未返回详情' }),
      h('div', { class: 'kv-label', text: '最后成功' }), h('div', { class: 'kv-value', text: formatTime(sync.last_success) }),
      h('div', { class: 'kv-label', text: '下次重试' }), h('div', { class: 'kv-value', text: sync.next_due ? formatTime(sync.next_due) : '未安排' })
    );
  }

  function renderSubscriptions() {
    const subscriptions = state.data.subscriptions || {};
    const providers = safeArray(subscriptions.providers);
    const rows = providers.map(provider => h('tr', {},
      titleCell(provider.name || provider.id, provider.detail || ''),
      h('td', {}, subscriptionUsage(provider)),
      detailCell(subscriptionExpiry(provider), ''),
      h('td', {}, badge(provider.state || provider.sync_state)),
      detailCell(subscriptionLastSuccess(provider))
    ));
    const sourceBody = h('div', {},
      h('div', { class: 'two-column', style: { padding: '16px 16px 0' } },
        panel('来源同步', renderSourceSync(subscriptions.source_sync), { flush: true }),
        panel('语义边界', h('div', {}, notice('信息来源数仅表示已读取用量/到期等信息，不等于已发布节点数。', 'info'), notice('“Clash 已加载”只展示接口已取得的名称/数量比对等证据，不表示所有端点与业务全部通过。', 'warning')))
      ),
      table(['订阅来源', '用量', '到期时间', '同步状态', '最后成功'], rows, '暂无订阅来源', '接口当前未返回 provider 来源、用量或同步证据。')
    );
    const current = state.activeTabs.subscriptions;
    const body = current === 'sources' ? sourceBody : embeddedFrame('/classic/subscriptions', '原生订阅编辑器');
    return h('div', { class: 'page' }, heading('subscriptions'), renderSyncPanel(),
      panel(current === 'sources' ? '订阅来源' : '原生订阅编辑器', body, {
        flush: true,
        headerActions: tabs('subscriptions', [{ id: 'sources', label: '来源与用量' }, { id: 'classic', label: '原生编辑器' }])
      }));
  }

  function dnsConfigRows(dns) {
    const definitions = [
      ['mode', '运行模式'], ['listen', '监听地址'], ['port', '监听端口'],
      ['enhanced_mode', '增强模式'], ['fake_ip_range', 'Fake-IP 范围'],
      ['redirect', 'DNS 劫持 / 重定向'], ['cache', '缓存'], ['ipv6', 'IPv6']
    ];
    const rows = [];
    definitions.forEach(([key, label]) => {
      if (dns[key] !== null && dns[key] !== undefined && dns[key] !== '') rows.push([label, typeof dns[key] === 'boolean' ? (dns[key] ? '已启用' : '未启用') : String(dns[key])]);
    });
    const config = dns.config && typeof dns.config === 'object' && !Array.isArray(dns.config) ? dns.config : {};
    definitions.forEach(([key, label]) => {
      if (!rows.some(row => row[0] === label) && config[key] !== null && config[key] !== undefined && config[key] !== '') {
        rows.push([label, typeof config[key] === 'boolean' ? (config[key] ? '已启用' : '未启用') : String(config[key])]);
      }
    });
    if (!rows.length) return emptyState('暂无 DNS 配置证据', '接口未返回监听、模式或重定向等实际配置。');
    return h('div', { class: 'kv-grid' }, rows.flatMap(([label, value]) => [
      h('div', { class: 'kv-label', text: label }), h('div', { class: 'kv-value cell-mono', text: value })
    ]));
  }

  function dnsProbe(dns, key, label) {
    const probes = dns.probes && typeof dns.probes === 'object' ? dns.probes : {};
    const evidence = dns.evidence && typeof dns.evidence === 'object' ? dns.evidence : {};
    const raw = probes[key] ?? evidence[key] ?? dns[key];
    let probe = {};
    if (typeof raw === 'boolean') probe = { state: raw ? 'ok' : 'error' };
    else if (typeof raw === 'string') probe = { state: raw };
    else if (raw && typeof raw === 'object' && !Array.isArray(raw)) probe = raw;
    const status = evidenceState(probe.state || (probe.ok === true ? 'ok' : probe.ok === false ? 'error' : 'unknown'));
    const details = [];
    if (probe.detail) details.push(String(probe.detail));
    if (finiteNumber(probe.status) !== null) details.push(`HTTP ${probe.status}`);
    if (probe.checked_at || probe.at) details.push(`检查于 ${formatTime(probe.checked_at || probe.at)}`);
    return h('div', { class: 'probe-item' },
      h('div', { class: 'probe-item-top' }, h('span', { class: 'probe-item-title', text: label }), badge(status)),
      h('div', { class: 'probe-item-detail', text: details.join(' · ') || '接口未返回该分项探针证据' })
    );
  }

  function renderDns() {
    const dns = state.data.dns || {};
    const upstreams = safeArray(dns.upstreams);
    const upstreamList = upstreams.length ? h('div', { class: 'upstream-list' }, upstreams.map((upstream, index) => {
      const item = typeof upstream === 'string' ? { name: upstream } : upstream || {};
      const latency = finiteNumber(item.latency_ms ?? item.delay_ms);
      return h('div', { class: 'upstream-item' },
        h('div', {}, h('div', { class: 'upstream-name cell-mono', text: item.name || item.address || item.url || `上游 ${index + 1}` }),
          h('div', { class: 'upstream-detail', text: item.detail || (item.checked_at ? `检查于 ${formatTime(item.checked_at)}` : '未返回检查详情') })),
        h('div', { class: 'cell-actions' }, latency === null ? null : h('span', { text: `${Math.round(latency)} ms` }), badge(item.state))
      );
    })) : emptyState('暂无 DNS 上游证据', '接口当前未返回上游地址或健康检测。');
    const probes = h('div', { class: 'probe-grid', 'aria-label': 'DNS health 与 ready 分项证据' },
      dnsProbe(dns, 'health', 'Health 健康探针'),
      dnsProbe(dns, 'ready', 'Ready 就绪探针')
    );
    const page = h('div', { class: 'page' }, heading('dns'),
      panel('DNS 整体状态', h('div', {}, h('div', { class: 'cell-actions' }, badge(dns.state), h('span', { text: dns.detail || '未返回详细健康证据' })),
        probes,
        notice('本页只读。Health/Ready 仅是已配置目标的分项证据，不承诺全网 DNS 或所有域名均可解析；刷新不修改配置、不清空缓存、不重启 DNS。', 'info'))),
      h('div', { class: 'two-column' }, panel('实际配置', dnsConfigRows(dns), { flush: true }), panel('上游与健康', upstreamList))
    );
    return page;
  }

  function renderMonitorSummary() {
    const monitors = safeArray(state.data.monitors);
    const rows = monitors.map(item => h('tr', {},
      titleCell(item.name || item.id, item.detail || ''),
      h('td', {}, badge(item.state)),
      detailCell(item.latency_ms === null || item.latency_ms === undefined ? '未返回' : `${Math.round(Number(item.latency_ms))} ms`),
      detailCell(formatTime(item.checked_at))
    ));
    return table(['监控项', '状态', '延迟', '最后检查'], rows, '暂无业务监控证据', '接口当前未返回业务端点、检测时间或结果。');
  }

  function renderMonitors() {
    const current = state.activeTabs.monitors;
    const body = current === 'summary' ? renderMonitorSummary() : embeddedFrame('/dashboard', 'Kuma 高级监控', { requiresSession: true });
    const actions = state.session.authenticated ? [] : [sessionActionButton('管理登录', openLogin)];
    return h('div', { class: 'page' }, heading('monitors', actions),
      panel(current === 'summary' ? '统一监控结果' : 'Kuma 高级监控', body, {
        flush: true,
        headerActions: tabs('monitors', [{ id: 'summary', label: '统一视图' }, { id: 'advanced', label: '高级 Kuma' }])
      }));
  }

  function backupDownload(backup) {
    const status = cleanStatus(backup.state);
    if (status !== 'ok' && backup.ready !== true && backup.download_ready !== true) return h('span', { class: 'cell-sub', text: '尚未可下载' });
    if (!state.session.authenticated) return h('button', { class: 'button button-secondary button-small', type: 'button', onClick: openLogin }, icon('lock'), '登录后下载');
    if (backup.id === null || backup.id === undefined || backup.id === '') return h('span', { class: 'cell-sub', text: '缺少备份 ID' });
    return h('a', { class: 'button button-secondary button-small', href: `/api/center/backups/${encodeURIComponent(String(backup.id))}/download`, download: '' }, icon('download'), '下载');
  }

  function renderBackupJob() {
    if (!state.backupJob) return null;
    const job = state.backupJob;
    const progress = finiteNumber(job.progress);
    return panel('当前备份任务', h('div', {},
      h('div', { class: 'cell-actions' }, badge(job.state), h('span', { class: 'cell-mono', text: `任务 ${valueOrUnknown(job.job_id || job.id)}` })),
      job.stage ? h('p', { text: `当前阶段：${job.stage}` }) : null,
      job.detail ? h('p', { class: 'cell-sub', text: job.detail }) : null,
      progress === null ? null : h('div', { class: 'usage-track', role: 'progressbar', 'aria-valuemin': '0', 'aria-valuemax': '100', 'aria-valuenow': String(Math.max(0, Math.min(100, progress))) },
        h('div', { class: 'usage-fill', style: { width: `${Math.max(0, Math.min(100, progress))}%` } }))
    ));
  }

  function backupRows() {
    return safeArray(state.data.backups).map(item => h('tr', {},
      titleCell(item.name || item.id, item.detail || ''),
      detailCell(formatTime(item.created_at || item.at)),
      h('td', {}, badge(item.state)),
      detailCell(item.size_bytes === null || item.size_bytes === undefined ? '未返回' : formatBytes(item.size_bytes)),
      h('td', {}, backupDownload(item))
    ));
  }

  async function pollBackupJob() {
    if (!state.backupJob) return;
    const id = state.backupJob.job_id || state.backupJob.id;
    if (!id) return;
    try {
      const job = await api(`/api/center/jobs/${encodeURIComponent(String(id))}`);
      state.backupJob = { ...job, job_id: job.job_id || job.id || id };
      if (state.page === 'backups') renderPage();
      const status = cleanStatus(job.state);
      if (status === 'running' || status === 'pending' || status === 'unknown') {
        state.backupPoll = window.setTimeout(pollBackupJob, 2500);
      } else {
        state.backupPoll = null;
        if (status === 'ok') {
          toast('备份任务已完成，正在更新备份列表。');
          await refreshData({ silent: true });
        } else toast(job.detail || '备份任务未成功完成。', true);
      }
    } catch (error) {
      state.backupJob = { ...state.backupJob, state: 'error', detail: error.message };
      state.backupPoll = null;
      if (state.page === 'backups') renderPage();
      toast(error.message, true);
    }
  }

  async function createBackup(button) {
    if (!requireLogin('创建和下载备份需要先解锁管理。')) return;
    if (!canWrite()) { toast('当前环境已关闭写操作。', true); return; }
    if (!window.confirm('创建一个新的中心数据/配置备份？\n\n此任务不包含路由器整机备份，也不会自动恢复任何数据。')) return;
    button.disabled = true;
    try {
      const result = await api('/api/center/backup', { method: 'POST', body: {} });
      state.backupJob = result;
      if (state.backupPoll) window.clearTimeout(state.backupPoll);
      renderPage();
      toast('备份任务已创建，页面将跟踪真实任务状态。');
      state.backupPoll = window.setTimeout(pollBackupJob, 1200);
    } catch (error) {
      toast(error.message, true);
      button.disabled = false;
    }
  }

  function renderBackups() {
    const create = h('button', { class: 'button button-primary', type: 'button', disabled: !canWrite(), onClick: event => createBackup(event.currentTarget) }, icon('backup'), '创建备份');
    const actions = [create];
    if (!state.session.authenticated) actions.unshift(sessionActionButton('管理登录', openLogin));
    const page = h('div', { class: 'page' }, heading('backups', actions));
    const jobPanel = renderBackupJob();
    if (jobPanel) page.append(jobPanel);
    page.append(h('div', { class: 'two-column' },
      panel('备份范围与恢复边界', h('div', { class: 'backup-guidance' },
        h('div', { class: 'guidance-step' }, h('span', { class: 'guidance-number', text: '1' }), h('div', {}, h('strong', { text: '先下载并离线保存' }), h('p', { text: '备份可能含敏感信息，仅有效管理会话可下载。' }))),
        h('div', { class: 'guidance-step' }, h('span', { class: 'guidance-number', text: '2' }), h('div', {}, h('strong', { text: '备份不等于整机灾备' }), h('p', { text: '成功备份以 included 清单为准：包含中心配置与数据库快照（包括 Kuma 数据库），不包含路由器系统、部署凭据、Kuma 完整数据目录或宿主机整机；实际未列入 included 的内容不作包含承诺。' }))),
        h('div', { class: 'guidance-step' }, h('span', { class: 'guidance-number', text: '3' }), h('div', {}, h('strong', { text: '恢复必须在受控维护窗口执行' }), h('p', { text: '本页不提供一键恢复。恢复前应校验文件、备份当前状态、停止写入，并保留独立回退点。' })))
      )),
      panel('安全说明', h('div', {}, notice('创建备份只启动后台任务；未完成时不会显示下载入口。', 'info'), notice('不要将备份发送到公开网盘、聊天群或未受控终端。', 'warning')))
    ));
    page.append(panel('已有备份', table(['备份', '创建时间', '状态', '大小', '下载'], backupRows(), '暂无备份记录', '接口当前未返回已完成或进行中的备份。'), { flush: true }));
    return page;
  }

  function filteredEvents() {
    const query = state.activityFilter.query.trim().toLocaleLowerCase('zh-CN');
    return safeArray(state.data.events).filter(item => {
      const text = `${item.title || ''} ${item.detail || ''}`.toLocaleLowerCase('zh-CN');
      return (!query || text.includes(query)) && (state.activityFilter.status === 'all' || cleanStatus(item.state) === state.activityFilter.status);
    });
  }

  function renderActivityList() {
    const container = document.getElementById('activity-list-container');
    if (!container) return;
    const events = filteredEvents();
    container.replaceChildren(events.length ? h('ol', { class: 'timeline' }, events.map(item => h('li', { class: `timeline-item ${cleanStatus(item.state)}` },
      h('span', { class: 'timeline-dot', 'aria-hidden': 'true' }), h('div', { class: 'timeline-time', text: formatTime(item.at) }),
      h('div', { class: 'cell-actions' }, h('div', { class: 'timeline-title', text: item.title || '未命名操作' }), badge(item.state)),
      h('div', { class: 'timeline-detail', text: item.detail || '未返回详细结果' })
    ))) : emptyState('没有匹配的操作记录', '请调整搜索或状态过滤；页面不会伪造缺失的时间或结果。'));
    const count = document.getElementById('activity-filter-count');
    if (count) count.textContent = `显示 ${events.length} / ${safeArray(state.data.events).length}`;
  }

  function renderActivity() {
    const events = safeArray(state.data.events);
    const statuses = [...new Set(events.map(item => cleanStatus(item.state)))];
    const query = h('input', { type: 'search', value: state.activityFilter.query, placeholder: '搜索操作标题或详情', 'aria-label': '搜索操作记录' });
    query.addEventListener('input', event => { state.activityFilter.query = event.target.value; renderActivityList(); });
    const statusSelect = h('select', { 'aria-label': '按结果过滤' }, h('option', { value: 'all', text: '全部结果' }));
    statuses.forEach(status => statusSelect.append(h('option', { value: status, text: statusLabel(status), selected: status === state.activityFilter.status })));
    statusSelect.addEventListener('change', event => { state.activityFilter.status = event.target.value; renderActivityList(); });
    const toolbar = h('div', { class: 'toolbar' }, h('label', { class: 'search-field' }, icon('search'), query), statusSelect,
      h('span', { class: 'filter-count', id: 'activity-filter-count', text: `显示 ${events.length} / ${events.length}` }));
    return h('div', { class: 'page' }, heading('activity'),
      panel('真实活动时间线', h('div', {}, toolbar, h('div', { id: 'activity-list-container', class: 'panel-body' }, eventTimeline())), { flush: true }));
  }

  function closeSidebar() {
    sidebar.classList.remove('open');
    sidebarBackdrop.hidden = true;
    mobileMenu.setAttribute('aria-expanded', 'false');
    mobileMenu.setAttribute('aria-label', '打开导航');
  }

  function handleHashChange() {
    const requested = window.location.hash.replace(/^#\/?/, '').split('/')[0];
    const page = Object.prototype.hasOwnProperty.call(PAGE_META, requested) ? requested : 'overview';
    if (requested !== page) history.replaceState(null, '', `#/${page}`);
    state.page = page;
    closeSidebar();
    renderPage();
    main.focus({ preventScroll: true });
    window.scrollTo({ top: 0, behavior: 'auto' });
  }

  refreshButton.addEventListener('click', () => refreshData());
  sessionButton.addEventListener('click', () => state.session.authenticated ? logout() : openLogin());
  mobileMenu.addEventListener('click', () => {
    const open = !sidebar.classList.contains('open');
    sidebar.classList.toggle('open', open);
    sidebarBackdrop.hidden = !open;
    mobileMenu.setAttribute('aria-expanded', String(open));
    mobileMenu.setAttribute('aria-label', open ? '关闭导航' : '打开导航');
  });
  sidebarBackdrop.addEventListener('click', closeSidebar);
  document.getElementById('login-cancel').addEventListener('click', () => loginDialog.close());

  loginForm.addEventListener('submit', async event => {
    event.preventDefault();
    const token = adminToken.value;
    adminToken.value = '';
    loginError.hidden = true;
    const submit = document.getElementById('login-submit');
    submit.disabled = true;
    try {
      const result = await api('/api/local/login', { method: 'POST', body: { token } });
      state.session = { authenticated: true, csrf: typeof result.csrf === 'string' ? result.csrf : '' };
      if (!state.session.csrf) await loadSession();
      updateSessionButton();
      loginDialog.close();
      renderPage();
      toast('管理操作已解锁。');
    } catch (error) {
      loginError.textContent = error.message;
      loginError.hidden = false;
      adminToken.focus();
    } finally {
      submit.disabled = false;
    }
  });

  window.addEventListener('hashchange', handleHashChange);
  window.addEventListener('keydown', event => {
    if (event.key === 'Escape' && sidebar.classList.contains('open')) closeSidebar();
  });

  async function start() {
    if (!window.location.hash || !/^#\/(overview|routing|nodes|subscriptions|dns|monitors|backups|activity)$/.test(window.location.hash)) {
      history.replaceState(null, '', '#/overview');
    }
    handleHashChange();
    await loadSession();
    await refreshData({ silent: true });
    window.setInterval(() => {
      if (!document.hidden && !state.loading) refreshData({ silent: true, background: true });
    }, 30000);
  }

  start();
})();
