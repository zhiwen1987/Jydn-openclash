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
    dns: { label: 'DNS', title: 'DNS 管理', description: '管理受控上游、本地记录和重写；修改先进入草稿与预览，应用后读回核验。' },
    monitors: { label: '业务监控', title: '监控管理', description: '在统一登录下查看、编辑和停启受支持的 Kuma 监控，所有操作均读回验证。' },
    diagnostics: { label: '诊断中心', title: '诊断中心', description: '区分 DNS、TCP、TLS 和业务阶段，聚合污染、泄漏与路径证据。' },
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
    ,binding_required: '监控后端尚未完成安全绑定',
    auth_failed: '监控后端认证失败',
    protocol_mismatch: '监控后端协议版本不兼容',
    configuration_busy: '配置正在被其他任务处理',
    migration_required: '当前配置需先完成受控迁移',
    version_conflict_refresh_page: '自建节点版本已变更，已拒绝覆盖；草稿仍保留',
    busy_retry_later: '另一个发布任务正在进行',
    pending_recovery_retry_later: '上次发布正在恢复，请等待读回',
    publish_failed_previous_retained: '发布失败，上一已验证版本已保留',
    native_kernel_rejected_configuration: '旁路由同版内核拒绝了该配置',
    native_validation_unavailable: '旁路由内核校验暂不可用'
  };

  const state = {
    data: null,
    session: { authenticated: false, csrf: '' },
    page: 'overview',
    loading: false,
    dataError: '',
    lastFetchAt: null,
    activeTabs: { routing: 'summary', subscriptions: 'sources', dns: 'configuration', monitors: 'monitors', diagnostics: 'dns' },
    nodeFilter: { query: '', provider: 'all', status: 'all' },
    activityFilter: { query: '', status: 'all' },
    overviewIssuesExpanded: false,
    routeDrafts: new Map(),
    nodeTests: new Map(),
    expandedNodes: new Set(),
    backupJob: null,
    backupPoll: null,
    frameTimers: new WeakMap(),
    management: null,
    managementError: '',
    operationJobs: new Map(),
    operationPolls: new Map(),
    dnsDraft: { upstreamAddress: '', upstreamProtocol: 'udp', hostName: '', hostValue: '', rewriteFrom: '', rewriteTo: '' },
    diagnosticDraft: { domain: '', qtype: 'A', resolver: '', transport: 'udp', mode: 'quick', perspective: 'container' },
    monitorDraft: { name: '', type: 'http', target: '', port: '', interval: '60', parent: '', dnsType: 'A', dnsResolver: '' },
    monitorEditor: null,
    notificationDraft: { name: '', httpMethod: 'post', webhookContentType: 'json', webhookURL: '', webhookCustomBody: '', webhookAdditionalHeaders: '' },
    notificationEditor: null,
    localPublisher: { status: null, error: '', busy: false, draftText: '', preview: null, previewText: '', mode: 'merge', editing: '' },
    subscriptionEditor: null,
    overviewFollowupTimer: null,
    overviewFollowupAttempt: 0
  };

  const OVERVIEW_FOLLOWUP_DELAYS = [1000, 2000, 4000, 8000];

  const main = document.getElementById('main-content');
  const refreshButton = document.getElementById('refresh-button');
  const sessionButton = document.getElementById('session-button');
  const updatedAt = document.getElementById('updated-at');
  const breadcrumb = document.getElementById('breadcrumb-label');
  const sidebar = document.getElementById('sidebar');
  const sidebarBackdrop = document.getElementById('sidebar-backdrop');
  const mobileMenu = document.getElementById('mobile-menu');
  const sidebarClose = document.getElementById('sidebar-close');
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

  function timeValue(value) {
    if (value === null || value === undefined || value === '') return 0;
    const numeric = Number(value);
    if (Number.isFinite(numeric)) return numeric < 1e12 ? numeric * 1000 : numeric;
    const parsed = Date.parse(String(value));
    return Number.isFinite(parsed) ? parsed : 0;
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
      state.management = null;
      state.managementError = '';
    }
    updateSessionButton();
  }

  async function loadManagement() {
    if (!state.session.authenticated) {
      state.management = null;
      state.managementError = '';
      return;
    }
    try {
      const data = await api('/api/center/manage/snapshot');
      if (!data || typeof data !== 'object' || data.schema !== 2 || !data.modules || typeof data.modules !== 'object') {
        throw new Error('管理接口未返回可验证的 schema 2 快照。');
      }
      state.management = data;
      state.managementError = '';
    } catch (error) {
      state.managementError = error.message;
      if (error.status === 401 || error.status === 403) {
        state.session = { authenticated: false, csrf: '' };
        state.management = null;
        updateSessionButton();
      }
    }
  }

  async function loadLocalPublisher() {
    if (!state.session.authenticated) {
      state.localPublisher.status = null;
      state.localPublisher.error = '';
      return;
    }
    try {
      const status = await api('/api/local/status');
      state.localPublisher.status = status && typeof status === 'object' ? status : null;
      state.localPublisher.error = '';
      if (!state.session.csrf && typeof status.csrf === 'string') state.session.csrf = status.csrf;
    } catch (error) {
      state.localPublisher.error = error.message;
    }
  }

  function managementModule(name) {
    const module = state.management?.modules?.[name];
    return module && typeof module === 'object' && !Array.isArray(module)
      ? module
      : { state: state.managementError ? 'error' : 'unsupported', revision: null, capabilities: { actions: [] } };
  }

  function moduleActions(name) {
    const actions = managementModule(name).capabilities?.actions;
    if (Array.isArray(actions)) return actions.filter(action => typeof action === 'string');
    if (actions && typeof actions === 'object') return Object.entries(actions)
      .filter(([, metadata]) => metadata === true || (metadata && typeof metadata === 'object' && metadata.supported === true))
      .map(([action]) => action);
    return [];
  }

  function canModuleAction(name, action) {
    if (!state.session.authenticated || !moduleActions(name).includes(action)) return false;
    const capabilities = managementModule(name).capabilities || {};
    const definitions = capabilities.actions;
    const metadata = capabilities.action_meta?.[action]
      || (definitions && !Array.isArray(definitions) && typeof definitions === 'object' ? definitions[action] : null);
    return metadata && typeof metadata === 'object' && metadata.write === false ? true : canWrite();
  }

  function resolveAction(name, ...candidates) {
    const actions = moduleActions(name);
    return candidates.find(candidate => actions.includes(candidate)) || null;
  }

  function managementGate(moduleName, detail) {
    if (!state.session.authenticated) return advancedGate(detail || '该管理功能');
    if (state.managementError) return notice(`管理快照读取失败：${state.managementError}。只读运行状态仍可查看。`, 'danger');
    const module = managementModule(moduleName);
    if (module.state === 'unsupported') return emptyState('当前版本未接入', `后端未提供${detail || moduleName}的可验证管理能力，页面不会生成假按钮。`);
    return null;
  }

  function jobFor(moduleName) {
    const jobs = [...state.operationJobs.values()].filter(job => job.module === moduleName);
    return jobs.sort((left, right) => timeValue(right.created_at) - timeValue(left.created_at))[0] || null;
  }

  function operationCard(moduleName) {
    const job = jobFor(moduleName);
    if (!job) return null;
    const status = cleanStatus(job.state === 'conflict' ? 'warning' : job.state);
    const finished = ['ok', 'error', 'conflict'].includes(job.state);
    return h('div', { class: `operation-card ${status}`, role: job.state === 'error' ? 'alert' : 'status' },
      h('div', { class: 'operation-card-top' }, badge(status), h('strong', { text: `${job.action || '管理操作'} · ${job.stage || job.state || '等待'}` })),
      h('p', { text: job.detail || job.error || (finished ? '操作已结束，页面已重新读取运行状态。' : '任务在后台执行，页面会继续核对结果。') }),
      h('span', { class: 'cell-sub', text: `任务 ${valueOrUnknown(job.job_id || job.id)}${job.completed_at ? ` · 完成于 ${formatTime(job.completed_at)}` : ''}` })
    );
  }

  async function pollOperation(jobId) {
    if (state.operationPolls.has(jobId)) return;
    const poll = async () => {
      try {
        const job = await api(`/api/center/jobs/${encodeURIComponent(jobId)}`);
        const previous = state.operationJobs.get(jobId) || {};
        state.operationJobs.set(jobId, { ...previous, ...job });
        const finished = ['ok', 'error', 'conflict'].includes(job.state);
        if (finished) {
          window.clearInterval(state.operationPolls.get(jobId));
          state.operationPolls.delete(jobId);
          await loadManagement();
          await refreshData({ silent: true, preserve: true });
          toast(job.state === 'ok' ? '操作已完成并读回核验。' : (job.error || '操作未完成。'), job.state !== 'ok');
        }
        const detailHydration = finished && job.state === 'ok' && /(?:monitor|notification)_detail$/.test(String(job.action || ''))
          && ((state.monitorEditor && !state.monitorEditor.dirty) || (state.notificationEditor && !state.notificationEditor.dirty));
        if (detailHydration || !shouldPreserveInteractiveView()) renderPage();
      } catch (error) {
        window.clearInterval(state.operationPolls.get(jobId));
        state.operationPolls.delete(jobId);
        toast(error.message, true);
      }
    };
    state.operationPolls.set(jobId, window.setInterval(poll, 1200));
    await poll();
  }

  async function startOperation(moduleName, action, params = {}, button = null) {
    if (!requireLogin()) return null;
    const module = managementModule(moduleName);
    if (!canModuleAction(moduleName, action)) {
      toast('当前后端未声明支持该操作，已拒绝提交。', true);
      return null;
    }
    if (button) button.disabled = true;
    try {
      const job = await api('/api/center/operations', {
        method: 'POST',
        body: { module: moduleName, action, expected_revision: module.revision, params }
      });
      if (!job.job_id) throw new Error('后端未返回任务 ID，无法核验操作结果。');
      state.operationJobs.set(job.job_id, { ...job, module: moduleName, action, params: operationContextParams(moduleName, action, params) });
      toast('操作已进入受控任务队列。');
      await pollOperation(job.job_id);
      return job;
    } catch (error) {
      toast(error.message, true);
      if (error.status === 409) await loadManagement();
      return null;
    } finally {
      if (button) button.disabled = false;
    }
  }

  function operationContextParams(moduleName, action, params) {
    if (!params || typeof params !== 'object') return {};
    if (moduleName === 'subscriptions' && /^subscriptions\.source\.(add|update)$/.test(action)) {
      return params.source_id ? { source_id: params.source_id } : {};
    }
    if (moduleName === 'monitors' && /notification_(create|update|test)$/.test(action)) {
      return params.id ? { id: params.id } : {};
    }
    if (moduleName === 'monitors' && /monitor_(create|update)$/.test(action)) {
      const source = params.monitor || params.patch || {};
      const redacted = { ...source };
      ['url', 'basic_auth_user', 'basic_auth_pass', 'bearer_token', 'headers', 'body'].forEach(key => delete redacted[key]);
      return params.id ? { id: params.id, patch: redacted } : { monitor: redacted };
    }
    return params;
  }

  async function waitForOperation(jobId, timeoutMs = 90000) {
    const started = Date.now();
    while (Date.now() - started < timeoutMs) {
      const job = state.operationJobs.get(jobId);
      if (job && ['ok', 'error', 'conflict'].includes(job.state)) return job;
      await new Promise(resolve => window.setTimeout(resolve, 500));
    }
    throw new Error('等待任务证据超时，不将未完成检测标记为通过。');
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
      if (state.session.authenticated) await Promise.all([loadManagement(), loadLocalPublisher()]);
      if (!options.followup) cancelOverviewFollowup(true);
      scheduleOverviewFollowup();
      updateOverviewEvidenceStamp();
      updatedAt.classList.remove('error');
      if ((options.background || options.preserve) && shouldPreserveInteractiveView()) updateRouteDraftDom();
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
      if (options.followup && state.data?.refreshing === true) {
        scheduleOverviewFollowup();
        updateOverviewEvidenceStamp();
      }
    } finally {
      setBusy(false);
    }
  }

  function cancelOverviewFollowup(reset = false) {
    if (state.overviewFollowupTimer !== null) {
      window.clearTimeout(state.overviewFollowupTimer);
      state.overviewFollowupTimer = null;
    }
    if (reset) state.overviewFollowupAttempt = 0;
  }

  function updateOverviewEvidenceStamp() {
    if (!state.data) return;
    const parts = [state.data.updated_at ? `更新于 ${formatTime(state.data.updated_at)}` : '未返回更新时间'];
    const age = finiteNumber(state.data.evidence_age_seconds);
    if (state.data.stale === true) parts.push(age === null ? '证据已过期' : `证据已过期 ${Math.max(0, Math.round(age))} 秒`);
    if (state.data.refreshing === true) {
      parts.push(state.overviewFollowupAttempt >= OVERVIEW_FOLLOWUP_DELAYS.length && state.overviewFollowupTimer === null ? '后台仍在采集' : '后台采集中');
    }
    updatedAt.textContent = parts.join(' · ');
  }

  function scheduleOverviewFollowup() {
    if (state.data?.refreshing !== true) {
      cancelOverviewFollowup(true);
      return;
    }
    if (document.hidden || state.overviewFollowupTimer !== null || state.overviewFollowupAttempt >= OVERVIEW_FOLLOWUP_DELAYS.length) return;
    const delay = OVERVIEW_FOLLOWUP_DELAYS[state.overviewFollowupAttempt];
    state.overviewFollowupTimer = window.setTimeout(async () => {
      state.overviewFollowupTimer = null;
      if (document.hidden) return;
      if (state.loading) {
        scheduleOverviewFollowup();
        updateOverviewEvidenceStamp();
        return;
      }
      state.overviewFollowupAttempt += 1;
      await refreshData({ silent: true, background: true, preserve: true, followup: true });
    }, delay);
  }

  function shouldPreserveInteractiveView() {
    if (main.querySelector('iframe')) return true;
    if (state.page === 'routing' && state.routeDrafts.size) return true;
    if (main.querySelector('[data-preserve-form="true"]')) return true;
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
      state.management = null;
      state.localPublisher.status = null;
      state.localPublisher.preview = null;
      state.localPublisher.previewText = '';
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
      diagnostics: renderDiagnostics,
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

  function localNodeState(value) {
    return {
      queued: ['pending', '待评估'], unknown: ['unknown', '未评估'], healthy: ['ok', '健康'],
      degraded: ['warning', '降级'], unhealthy: ['error', '不可用'], stale: ['stale', '结果过期'],
      available: ['ok', '可用'], unavailable: ['error', '不可用']
    }[String(value || '').toLowerCase()] || ['unknown', '未知'];
  }

  async function localPublisherRequest(path, body, button = null) {
    if (!requireLogin()) return null;
    if (state.localPublisher.busy) return null;
    state.localPublisher.busy = true;
    if (button) button.disabled = true;
    try {
      return await api(`/api/local/${path}`, { method: body === undefined ? 'GET' : 'POST', body });
    } catch (error) {
      if (error.status === 409) await loadLocalPublisher();
      toast(error.message, true);
      return null;
    } finally {
      state.localPublisher.busy = false;
      if (button) button.disabled = false;
    }
  }

  async function previewLocalNodes(button) {
    const text = state.localPublisher.draftText.trim();
    if (!text) {
      toast('请先粘贴至少一条节点链接。', true);
      return;
    }
    const preview = await localPublisherRequest('preview', { text }, button);
    if (!preview) return;
    state.localPublisher.preview = preview;
    state.localPublisher.previewText = text;
    renderPage();
    toast(`预览通过：${finiteNumber(preview.count) ?? safeArray(preview.nodes).length} 个去重节点，尚未发布。`);
  }

  async function publishLocalNodes(button) {
    const local = state.localPublisher;
    const text = local.draftText.trim();
    if (!text || local.previewText !== text || !local.preview) {
      toast('草稿已变化，请先重新解析预览。', true);
      return;
    }
    if (!local.editing && local.mode === 'replace' && !window.confirm('确认替换全部自建节点？\n\n被移除且正在使用的自定义入口会先阻断，不会自动改走其他出口。')) return;
    const status = local.status || {};
    const payload = { mode: local.editing ? 'edit' : local.mode, version: status.version, text };
    if (local.editing) payload.id = local.editing;
    const result = await localPublisherRequest('publish', payload, button);
    if (!result) return;
    local.draftText = '';
    local.preview = null;
    local.previewText = '';
    local.editing = '';
    local.mode = 'merge';
    await loadLocalPublisher();
    renderPage();
    toast(result.status === 'unchanged' ? '内容未变，无需重复发布。' : '已发布并等待旁路由读回核验；健康检测会独立排队。');
  }

  async function removeLocalNode(node, button) {
    if (!window.confirm(`删除自建节点「${node.label || node.id}」？\n\n若它正在被业务选择，自定义入口会先阻断。`)) return;
    const result = await localPublisherRequest('publish', { mode: 'remove', ids: [node.id], version: state.localPublisher.status?.version }, button);
    if (!result) return;
    await loadLocalPublisher();
    renderPage();
    toast('节点已删除并完成读回核验。');
  }

  function localPreviewCard() {
    const preview = state.localPublisher.preview;
    if (!preview) return notice('先解析预览，确认去重数量和类型后才允许发布。未准入节点只进入隔离检测队列，不加载到生产 Clash。', 'info');
    const nodes = safeArray(preview.nodes);
    return h('div', { class: 'preview-card', role: 'status' },
      h('div', { class: 'preview-card-title' }, badge('ok', '内核校验通过'), h('strong', { text: `${finiteNumber(preview.count) ?? nodes.length} 个去重节点` })),
      h('div', { class: 'preview-node-list' }, nodes.map(node => h('span', { text: `${node.label || '未命名'} · ${node.type || '未知类型'}` }))),
      h('p', { class: 'cell-sub', text: '预览只显示脱敏名称与类型；原链接、密码和凭据不会列出。' }));
  }

  function renderLocalPublisher() {
    if (!state.session.authenticated) return advancedGate('自建节点管理需统一登录；浏览、筛选和现有节点状态仍可直接查看。');
    const local = state.localPublisher;
    if (local.error) return notice(`无法读取自建节点发布器：${local.error}`, 'danger');
    const status = local.status;
    if (!status) return emptyState('正在读取自建节点', '请稍候或点击顶部刷新。');
    const rows = safeArray(status.nodes).map(node => {
      const mapped = localNodeState(node.health);
      return h('tr', {}, titleCell(node.label || node.id, `ID ${node.id}`), detailCell(node.type), h('td', {}, badge(mapped[0], mapped[1])),
        detailCell(node.evaluated_at ? formatTime(node.evaluated_at) : '无评估时间'),
        h('td', {}, h('div', { class: 'cell-actions' },
          h('button', { class: 'button button-secondary button-small', type: 'button', onClick: () => {
            local.editing = node.id; local.mode = 'edit'; local.draftText = ''; local.preview = null; local.previewText = ''; renderPage();
            window.setTimeout(() => document.getElementById('local-node-links')?.focus(), 0);
          } }, icon('edit'), '编辑'),
          h('button', { class: 'button button-danger button-small', type: 'button', onClick: event => removeLocalNode(node, event.currentTarget) }, icon('trash'), '删除')
        )));
    });
    const textarea = h('textarea', { id: 'local-node-links', rows: 5, value: local.draftText, placeholder: local.editing ? '粘贴该节点的新完整链接' : '每行一条 ss://、vmess://、vless://、trojan://、hysteria2:// 等节点链接', 'aria-label': '自建节点链接' });
    textarea.addEventListener('input', event => {
      local.draftText = event.target.value;
      local.preview = null;
      local.previewText = '';
      const publish = document.getElementById('local-node-publish');
      if (publish) publish.disabled = true;
    });
    const mode = h('select', { 'aria-label': '发布模式', disabled: Boolean(local.editing) },
      h('option', { value: 'merge', text: '合并到已有自建节点', selected: local.mode === 'merge' }),
      h('option', { value: 'replace', text: '替换全部自建节点', selected: local.mode === 'replace' }));
    mode.addEventListener('change', event => { local.mode = event.target.value; });
    const previewButton = h('button', { class: 'button button-secondary', type: 'button', onClick: event => previewLocalNodes(event.currentTarget) }, '解析并校验');
    const publishButton = h('button', { id: 'local-node-publish', class: 'button button-primary', type: 'submit', disabled: !local.preview || local.previewText !== local.draftText.trim() }, local.editing ? '保存编辑并发布' : '发布并读回验证');
    const form = h('form', { class: 'local-publisher-form', dataset: { preserveForm: 'true' } },
      h('div', { class: 'local-publisher-heading' }, h('div', {}, h('h3', { text: local.editing ? '编辑自建节点' : '添加自建节点' }), h('p', { text: '草稿仅保存在当前页面内存中；发布前必须通过本地解析和旁路由同版内核校验。' })),
        local.editing ? h('button', { class: 'button button-secondary', type: 'button', onClick: () => { local.editing = ''; local.mode = 'merge'; local.draftText = ''; local.preview = null; local.previewText = ''; renderPage(); } }, '取消编辑') : null),
      mode, textarea, localPreviewCard(), h('div', { class: 'cell-actions' }, previewButton, publishButton));
    form.addEventListener('submit', event => { event.preventDefault(); publishLocalNodes(event.submitter); });
    const summary = h('div', { class: 'local-publisher-summary' },
      h('div', {}, h('span', { class: 'cell-sub', text: '已保存' }), h('strong', { text: `${finiteNumber(status.count) ?? safeArray(status.nodes).length} 个` })),
      h('div', {}, h('span', { class: 'cell-sub', text: '发布版本' }), h('strong', { text: valueOrUnknown(status.version) })),
      h('div', {}, h('span', { class: 'cell-sub', text: '旁路由读回' }), h('strong', { text: status.router_loaded ? '已加载并核验' : '等待中' })),
      h('div', {}, h('span', { class: 'cell-sub', text: '恢复状态' }), h('strong', { text: status.pending_recovery ? '正在恢复上一版' : '无待恢复任务' }))
    );
    return h('div', {}, summary, form, table(['自建节点', '类型', '健康', '评估时间', '操作'], rows, '尚未添加自建节点', '现有机场节点和业务选择保持原状。'));
  }

  function renderNodes() {
    const nodes = safeArray(state.data.nodes);
    const nodeModule = managementModule('nodes');
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
    const inventoryNotice = nodeModule.inventory_scope === 'loaded_runtime_only'
      ? notice(`列表只展示已加载的生产运行节点。候选通道：${valueOrUnknown(nodeModule.candidate_channel)}；候选进入生产：${nodeModule.candidate_nodes_in_runtime === false ? '否' : '未返回证据'}。`, 'info')
      : null;
    const page = h('div', { class: 'page' }, heading('nodes', actions),
      notice('原生测速只测试所选 provider 节点，不切换任何策略组，也不将单次延迟冒充为业务可用性。', 'info'),
      inventoryNotice,
      panel('自建节点发布', renderLocalPublisher(), { subtitle: '原生解析预览 → 同版内核校验 → 受控发布 → 旁路由读回；候选不进入生产 Clash。' }),
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

  function lifecycleLabel(value) {
    return {
      discovered: '已发现', checking: '解析 / 检测中', quarantined: '已隔离', published: '已发布',
      loaded: 'Clash 已加载', pending_retirement: '待退役', retained_by_selection: '仍被业务引用', error: '异常'
    }[String(value || '')] || '未知';
  }

  function lifecycleState(value) {
    return {
      discovered: 'pending', checking: 'running', quarantined: 'warning', published: 'ok', loaded: 'ok',
      pending_retirement: 'warning', retained_by_selection: 'warning', error: 'error'
    }[String(value || '')] || 'unknown';
  }

  function sourceStageFlow(source) {
    const stages = safeArray(source.stages);
    if (!stages.length) return h('span', { class: 'cell-sub', text: '未返回分阶段证据' });
    return h('div', { class: 'compact-stage-flow', 'aria-label': `${source.name || source.id || '订阅'}接入阶段` }, stages.map(stage => {
      const status = cleanStatus(stage.state);
      return h('span', { class: `compact-stage ${status}`, title: `${stage.detail || '无详情'}${stage.at ? ` · ${formatTime(stage.at)}` : ''}` },
        h('span', { 'aria-hidden': 'true' }), stage.label || {
          information: '发现', parse: '解析', admission: '准入', publish: '发布', load: '加载'
        }[stage.id] || stage.id || '阶段');
    }));
  }

  function subscriptionAdmissionEvidence(source) {
    const admission = source.admission && typeof source.admission === 'object' && !Array.isArray(source.admission) ? source.admission : {};
    const values = [
      ['解析', admission.parsed_count ?? source.node_count],
      ['候选', admission.candidate_count ?? source.candidate_count],
      ['已检测', admission.tested_count],
      ['准入', admission.approved_count ?? source.approved_count]
    ].map(([label, value]) => `${label} ${valueOrUnknown(finiteNumber(value))}`);
    const nextDue = admission.next_due || safeArray(source.stages).find(stage => stage.id === 'admission')?.next_due;
    const detail = [source.reason || source.last_error, nextDue ? `下次检测 ${formatTime(nextDue)}` : '未返回下次检测时间'].filter(Boolean).join(' · ');
    return h('div', {}, h('div', { text: values.join(' · ') }), h('div', { class: 'cell-sub', text: detail }));
  }

  function subscriptionSourceActions(source) {
    if (source.origin !== 'managed') return h('span', { class: 'cell-sub', text: '显式 Provider 受保护' });
    const box = h('div', { class: 'cell-actions' });
    const update = resolveAction('subscriptions', 'subscriptions.source.update');
    if (update) box.append(h('button', { class: 'button button-secondary button-small', type: 'button', onClick: () => {
      state.subscriptionEditor = { sourceId: source.id, name: source.name || '' };
      renderPage();
      window.setTimeout(() => document.getElementById('subscription-source-name')?.focus(), 0);
    } }, icon('edit'), '编辑'));
    const enabled = source.desired !== 'absent' && source.desired !== 'disabled';
    const toggle = resolveAction('subscriptions', enabled ? 'subscriptions.source.disable' : 'subscriptions.source.enable');
    if (toggle) box.append(h('button', { class: 'button button-secondary button-small', type: 'button', onClick: event => startOperation('subscriptions', toggle, { source_id: source.id }, event.currentTarget) }, enabled ? '停用' : '启用'));
    const remove = resolveAction('subscriptions', 'subscriptions.source.delete');
    if (remove) box.append(h('button', { class: 'button button-danger button-small', type: 'button', onClick: event => {
      if (window.confirm(`确认删除受管订阅「${source.name || source.id}」？\n\n系统会写入独立 tombstone，OpenClash 转换后续同步不会将它自动复活。`)) startOperation('subscriptions', remove, { source_id: source.id }, event.currentTarget);
    } }, icon('trash'), '删除'));
    return box.childElementCount ? box : h('span', { class: 'cell-sub', text: '当前仅可查看' });
  }

  function subscriptionSourceForm() {
    const editor = state.subscriptionEditor;
    const action = resolveAction('subscriptions', editor ? 'subscriptions.source.update' : 'subscriptions.source.add');
    if (!action) return null;
    const form = h('form', { class: 'compact-form subscription-source-form', dataset: { preserveForm: 'true' } });
    const name = h('input', { id: 'subscription-source-name', value: editor?.name || '', placeholder: '例：第四家订阅', required: true, autocomplete: 'off' });
    const url = h('input', { type: 'password', placeholder: editor ? '留空表示不更换订阅 URL' : '粘贴订阅 URL', required: !editor, autocomplete: 'new-password', spellcheck: false });
    const submit = h('button', { class: 'button button-primary', type: 'submit' }, editor ? '保存并安排自动对账' : '添加并安排自动对账');
    const actions = h('div', { class: 'cell-actions' });
    if (editor) actions.append(h('button', { class: 'button button-secondary', type: 'button', onClick: () => { state.subscriptionEditor = null; renderPage(); } }, '取消'));
    actions.append(submit);
    form.append(
      h('div', { class: 'subscription-form-copy' }, h('h3', { text: editor ? '编辑受管订阅' : '新增受管订阅' }), h('p', { text: 'URL 只提交到 0600 私有覆写文件，不回显、不进入任务日志或浏览器存储。' })),
      h('label', {}, h('span', { text: '机场 / 来源名称' }), name),
      h('label', {}, h('span', { text: '订阅 URL（敏感）' }), url),
      notice('提交只安排后台闭环；发现、解析、准入、发布和 Clash 加载仍分阶段显示。未准入候选不进入生产。', 'info'), actions
    );
    form.addEventListener('submit', async event => {
      event.preventDefault();
      const params = editor ? { source_id: editor.sourceId, name: name.value.trim() } : { name: name.value.trim(), url: url.value.trim() };
      if (editor && url.value.trim()) params.url = url.value.trim();
      const job = await startOperation('subscriptions', action, params, submit);
      url.value = '';
      if (job) {
        state.subscriptionEditor = null;
        renderPage();
        toast('已安排订阅自动对账；URL 输入已从页面清除。');
      }
    });
    return panel(editor ? '编辑订阅来源' : '添加订阅来源', form);
  }

  function renderSubscriptions() {
    const subscriptions = state.data.subscriptions || {};
    const module = managementModule('subscriptions');
    const inventory = safeArray(module.sources).length ? safeArray(module.sources) : safeArray(module.source_inventory);
    const fallbackProviders = safeArray(subscriptions.providers);
    const byId = new Map(fallbackProviders.map(provider => [String(provider.id), provider]));
    const rows = inventory.length ? inventory.map(source => {
      const usage = byId.get(String(source.id)) || {};
      const dependencies = safeArray(source.dependencies).length ? safeArray(source.dependencies) : safeArray(source.retire_dependencies);
      const providers = source.providers && typeof source.providers === 'object' ? source.providers : {};
      const providerName = providers.active || source.provider_name || '尚未进入正式 Provider';
      return h('tr', {},
        titleCell(source.name || source.id, `${source.origin === 'managed' ? '自动发现' : '显式来源'} · ${providerName}`),
        h('td', {}, subscriptionUsage(usage)),
        h('td', {}, badge(lifecycleState(source.lifecycle || source.stage), lifecycleLabel(source.lifecycle || source.stage))),
        h('td', {}, sourceStageFlow(source)),
        h('td', {}, subscriptionAdmissionEvidence(source), dependencies.length ? h('div', { class: 'cell-sub', text: `依赖：${dependencies.join('、')}` }) : h('div', { class: 'cell-sub', text: `期望 ${valueOrUnknown(source.desired)} · 实际 ${valueOrUnknown(source.actual)}` })),
        h('td', {}, subscriptionSourceActions(source))
      );
    }) : fallbackProviders.map(provider => h('tr', {},
      titleCell(provider.name || provider.id, provider.detail || '尚未返回节点发布生命周期'),
      h('td', {}, subscriptionUsage(provider)),
      h('td', {}, badge(provider.state || provider.sync_state)),
      detailCell('未接入分阶段证据'),
      detailCell(subscriptionLastSuccess(provider)), detailCell('等待生命周期契约')
    ));
    const gate = managementGate('subscriptions', '订阅生命周期');
    const reconcile = module.reconcile && typeof module.reconcile === 'object' ? module.reconcile : {};
    const journal = reconcile.journal && typeof reconcile.journal === 'object' ? reconcile.journal : {};
    const publishingGuard = journal.state === 'publishing'
      ? notice('订阅正在发布，请勿直接在 OpenClash/Mihomo 面板切换策略组；请等待发布完成，仅使用 249 统一入口操作。检测到并发变更时中止接受，并尝试安全回退；结果见发布记录。', 'danger')
      : null;
    const previewAction = resolveAction('subscriptions', 'subscriptions.preview');
    const validateAction = resolveAction('subscriptions', 'subscriptions.validate');
    const lifecycleActions = h('div', { class: 'cell-actions' });
    if (previewAction) lifecycleActions.append(h('button', { class: 'button button-secondary', type: 'button', onClick: event => startOperation('subscriptions', previewAction, {}, event.currentTarget) }, '预览自动对账'));
    if (validateAction) lifecycleActions.append(h('button', { class: 'button button-secondary', type: 'button', onClick: event => startOperation('subscriptions', validateAction, {}, event.currentTarget) }, '校验候选发布'));
    const reconcileSummary = h('div', { class: 'three-column' },
      panel('来源同步', renderSourceSync(subscriptions.source_sync), { flush: true }),
      panel('自动适配', h('div', { class: 'kv-grid' },
        h('div', { class: 'kv-label', text: '受管来源' }), h('div', { class: 'kv-value', text: valueOrUnknown(reconcile.managed_count) }),
        h('div', { class: 'kv-label', text: '待退役' }), h('div', { class: 'kv-value', text: valueOrUnknown(reconcile.retiring_count) }),
        h('div', { class: 'kv-label', text: '当前 Provider' }), h('div', { class: 'kv-value cell-mono', text: valueOrUnknown(reconcile.active_provider || reconcile.provider_name) }),
        h('div', { class: 'kv-label', text: '候选检测通道' }), h('div', { class: 'kv-value cell-mono', text: valueOrUnknown(reconcile.candidate_channel || '隔离准入队列') }),
        h('div', { class: 'kv-label', text: '检测范围' }), h('div', { class: 'kv-value cell-mono', text: valueOrUnknown(reconcile.detector_scope) }),
        h('div', { class: 'kv-label', text: '周期耗时 / 上限' }), h('div', { class: 'kv-value', text: `${valueOrUnknown(finiteNumber(reconcile.cycle_elapsed_seconds))} / ${valueOrUnknown(finiteNumber(reconcile.cycle_budget_seconds))} 秒` }),
        h('div', { class: 'kv-label', text: '候选暴露到生产' }), h('div', { class: 'kv-value', text: reconcile.candidate_exposed === false ? '否' : reconcile.candidate_exposed === true ? '是（需检查）' : '未返回' }),
        h('div', { class: 'kv-label', text: '发布版本' }), h('div', { class: 'kv-value cell-mono', text: valueOrUnknown(reconcile.release_id) })
      ), { flush: true }),
      panel('安全边界', h('div', {}, notice('新增或删除来源自动对账；删除的节点仍被当前选择引用时，先保留并显示依赖。', 'info'), notice('未准入候选仅在私有缓存和 loopback 独立内核中检测，不加载生产 Clash、不出现在 GLOBAL；任一失败继续保留上一已验证 release。', 'warning')))
    );
    return h('div', { class: 'page' }, heading('subscriptions', lifecycleActions.childElementCount ? [lifecycleActions] : []), publishingGuard, renderSyncPanel(), operationCard('subscriptions'), gate,
      subscriptionSourceForm(),
      reconcileSummary,
      panel('订阅全生命周期', table(['订阅来源', '用量', '当前状态', '接入阶段', '准入 / 节点', '操作'], rows,
        '暂无订阅来源', '接口当前未返回信息来源或节点发布生命周期。'), { flush: true })
    );
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

  function dnsItemValue(item) {
    if (typeof item === 'string') return item;
    if (!item || typeof item !== 'object') return '未知';
    return item.target || item.address || item.url || item.name || item.domain || item.from || item.source || '未知';
  }

  function dnsDraftObjectId(kind) {
    let random = Math.floor(Math.random() * 0xffffffff).toString(36);
    if (window.crypto?.getRandomValues) {
      const values = new Uint32Array(2);
      window.crypto.getRandomValues(values);
      random = [...values].map(value => value.toString(36)).join('');
    }
    return `${kind}-ui-${Date.now().toString(36)}-${random}`;
  }

  function dnsDeleteButton(kind, item, module) {
    const action = resolveAction('dns', 'dns.draft_update', 'draft_update');
    if (!action) return null;
    if (!item || typeof item !== 'object' || !item.id) return h('span', { class: 'cell-sub', text: '缺少稳定 ID，不可修改' });
    return h('button', {
      class: 'button button-danger button-small', type: 'button',
      'aria-label': `删除 ${dnsItemValue(item)}`,
      onClick: event => {
        if (!window.confirm(`将「${dnsItemValue(item)}」加入 DNS 变更草稿？\n\n这不会立即影响运行配置，仍需预览并应用。`)) return;
        startOperation('dns', action, { expected_revision: module.revision, operations: [{ kind, action: 'delete', id: item.id }] }, event.currentTarget);
      }
    }, icon('trash'), '删除');
  }

  function dnsManagedList(kind, items, emptyText, module) {
    if (!items.length) return emptyState(emptyText, '当前已受管区域未返回该类记录。');
    return h('div', { class: 'managed-list' }, items.map((item, index) => {
      const detail = typeof item === 'object' && item ? Object.entries(item)
        .filter(([key]) => !['id', 'target', 'address', 'url', 'name', 'domain', 'from', 'source'].includes(key))
        .map(([key, value]) => `${key}: ${value}`).join(' · ') : '';
      return h('div', { class: 'managed-item' },
        h('div', {}, h('strong', { class: 'cell-mono', text: dnsItemValue(item) }), detail ? h('span', { text: detail }) : null),
        dnsDeleteButton(kind, item, module)
      );
    }));
  }

  function dnsAddForm(kind, title, fields, operationFactory, module) {
    const action = resolveAction('dns', 'dns.draft_update', 'draft_update');
    if (!action) return null;
    const form = h('form', { class: 'compact-form', dataset: { preserveForm: 'true' } });
    form.append(h('h3', { text: title }));
    fields.forEach(field => {
      let input;
      if (field.options) {
        input = h('select', { name: field.key, 'aria-label': field.label });
        field.options.forEach(option => input.append(h('option', { value: option.value, text: option.label, selected: String(state.dnsDraft[field.key]) === String(option.value) })));
      } else input = h('input', { name: field.key, value: state.dnsDraft[field.key] || '', placeholder: field.placeholder || '', required: true, 'aria-label': field.label });
      input.addEventListener('input', event => { state.dnsDraft[field.key] = event.target.value; });
      form.append(h('label', {}, h('span', { text: field.label }), input));
    });
    const button = h('button', { class: 'button button-secondary', type: 'submit' }, icon('plus'), '加入草稿');
    form.append(button);
    form.addEventListener('submit', async event => {
      event.preventDefault();
      const operation = operationFactory(state.dnsDraft);
      await startOperation('dns', action, { expected_revision: module.revision, operations: [operation] }, button);
    });
    return form;
  }

  function dnsDraftPanel(module) {
    const draft = module.draft && typeof module.draft === 'object' ? module.draft : null;
    if (!draft) return notice('当前没有待应用的 DNS 草稿。新增、编辑或删除先进入草稿，不会立即改变全网解析。', 'info');
    const previewAction = resolveAction('dns', 'preview', 'dns.preview');
    const applyAction = resolveAction('dns', 'apply', 'dns.apply');
    const actions = h('div', { class: 'cell-actions' });
    if (previewAction) actions.append(h('button', { class: 'button button-secondary', type: 'button', onClick: event => startOperation('dns', previewAction, { draft_id: draft.id || draft.draft_id }, event.currentTarget) }, '校验与预览'));
    if (applyAction) actions.append(h('button', { class: 'button button-primary', type: 'button', onClick: event => {
      if (window.confirm('确认应用该 DNS 草稿？\n\n服务端必须通过语法、外部校验和运行读回；失败时不应保留未验证配置。')) startOperation('dns', applyAction, { draft_id: draft.id || draft.draft_id, expected_revision: module.revision }, event.currentTarget);
    } }, '应用并验证'));
    const impact = draft.impact && typeof draft.impact === 'object' ? draft.impact : {};
    const impactText = Object.entries(impact).flatMap(([kind, value]) => {
      if (!value || typeof value !== 'object') return [];
      return [`${kind}：+${safeArray(value.added).length} / -${safeArray(value.removed).length} / 变更${safeArray(value.changed).length}`];
    }).join(' · ');
    return h('div', {},
      h('div', { class: 'cell-actions' }, badge(draft.state || 'pending'), h('strong', { text: `草稿 ${valueOrUnknown(draft.id || draft.draft_id)}` })),
      h('p', { class: 'cell-sub', text: impactText || draft.summary || `待处理变更 ${safeArray(draft.operations).length} 项` }), actions);
  }

  function dnsMigrationPanel(module) {
    const action = resolveAction('dns', 'dns.draft_update', 'draft_update');
    if (!action) return notice('当前 Corefile 需迁移，但后端未声明草稿能力；本页保持只读。', 'warning');
    const button = h('button', { class: 'button button-secondary', type: 'button', onClick: event => {
      if (!window.confirm('生成 DNS 接管影响草稿？\n\n此步只采用现有 forward 生成受管候选，不立即修改运行 Corefile。生成后仍需预览、明确确认和读回验证。')) return;
      startOperation('dns', action, { expected_revision: module.revision, operations: [{ kind: 'migration', action: 'adopt' }] }, event.currentTarget);
    } }, '生成接管影响草稿');
    return h('div', {}, notice('当前 Corefile 尚无受管区域。系统不会直接覆盖；需先将现有 forward 采用为草稿，再经预览和应用。', 'warning'), button);
  }

  function dnsRollbackPanel(module) {
    const last = module.last_apply && typeof module.last_apply === 'object' ? module.last_apply : null;
    const action = resolveAction('dns', 'dns.rollback', 'rollback');
    if (!last || !action || !(last.id || last.apply_id)) return null;
    return panel('最近应用与回退', h('div', { class: 'cell-actions' },
      h('span', { text: `应用 ${last.id || last.apply_id} · ${formatTime(last.applied_at || last.created_at)}` }),
      h('button', { class: 'button button-danger', type: 'button', onClick: event => {
        if (window.confirm('确认回退最近一次 DNS 应用？\n\n回退仍会执行重载与运行读回，并使用当前 revision 防止覆盖新变更。')) startOperation('dns', action, { apply_id: last.id || last.apply_id, expected_revision: module.revision }, event.currentTarget);
      } }, '回退并读回验证')
    ));
  }

  function dnsRuntimeRequirementNotice(module) {
    const requirements = module.capabilities?.runtime_requirements;
    if (!requirements || typeof requirements !== 'object') return null;
    const labels = { writable_verified: '受管目录可写校验', validator: '外部验证器', reloader: '受控重载器', probe: '运行读回探针' };
    const missing = Object.entries(requirements).filter(([, value]) => value !== true && value?.state !== 'ok' && value?.state !== 'ready');
    if (!missing.length) return null;
    const details = missing.map(([key, value]) => `${labels[key] || key}：${typeof value === 'object' ? value.detail || value.state || '未就绪' : value === false ? '未就绪' : valueOrUnknown(value)}`);
    return notice(`DNS 运行应用尚未开放：${details.join('；')}。预览仍可用，页面不生成假“应用”按钮。`, 'warning');
  }

  function renderDns() {
    const dns = state.data.dns || {};
    const module = managementModule('dns');
    const config = module.config && typeof module.config === 'object' ? module.config : {};
    const upstreams = safeArray(config.upstreams).length ? safeArray(config.upstreams) : safeArray(dns.upstreams);
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
    const gate = managementGate('dns', 'DNS 管理');
    const management = module.capabilities?.management;
    const actions = module.state === 'unsupported' || !state.session.authenticated ? [] : [badge(module.state, module.state === 'unmanaged' ? '待接管' : undefined)];
    const addForms = h('div', { class: 'form-grid' },
      dnsAddForm('upstream', '添加上游', [
        { key: 'upstreamAddress', label: '目标', placeholder: '1.1.1.1:53 或 tls://one.one.one.one' }
      ], draft => ({ kind: 'upstream', action: 'add', id: dnsDraftObjectId('upstream'), target: draft.upstreamAddress, enabled: true }), module),
      dnsAddForm('host', '添加本地记录', [
        { key: 'hostName', label: '域名', placeholder: 'example.lan' }, { key: 'hostValue', label: 'IPv4 / IPv6', placeholder: '10.88.0.10' }
      ], draft => ({ kind: 'host', action: 'add', id: dnsDraftObjectId('host'), name: draft.hostName, address: draft.hostValue, enabled: true }), module),
      dnsAddForm('rewrite', '添加解析重写', [
        { key: 'rewriteFrom', label: '原域名', placeholder: 'old.example.com' }, { key: 'rewriteTo', label: '目标', placeholder: 'new.example.com' }
      ], draft => ({ kind: 'rewrite', action: 'add', id: dnsDraftObjectId('rewrite'), from: draft.rewriteFrom, to: draft.rewriteTo, match: 'exact', enabled: true }), module)
    );
    const managedBody = management === 'migration_required'
      ? dnsMigrationPanel(module)
      : h('div', {},
        h('div', { class: 'three-column' },
          panel('受管上游', dnsManagedList('upstream', safeArray(config.upstreams), '暂无受管上游', module)),
          panel('本地记录', dnsManagedList('host', safeArray(config.hosts), '暂无本地记录', module)),
          panel('解析重写', dnsManagedList('rewrite', safeArray(config.rewrites), '暂无解析重写', module))
        ), addForms);
    const page = h('div', { class: 'page' }, heading('dns', actions), operationCard('dns'), gate,
      panel('DNS 整体状态', h('div', {}, h('div', { class: 'cell-actions' }, badge(dns.state), h('span', { text: dns.detail || '未返回详细健康证据' })),
        probes,
        notice('Health/Ready 只是进程与已配置目标的分项证据，不承诺全网或所有域名均可解析。', 'info'))),
      h('div', { class: 'two-column' }, panel('实际配置', dnsConfigRows(dns), { flush: true }), panel('上游健康证据', upstreamList)),
      panel('DNS 变更草稿', dnsDraftPanel(module)), dnsRuntimeRequirementNotice(module), dnsRollbackPanel(module),
      managedBody
    );
    return page;
  }

  function monitorNative() {
    const module = managementModule('monitors');
    return module.kuma_native && typeof module.kuma_native === 'object' ? module.kuma_native : module;
  }

  function latestOperation(moduleName, actions, predicate = () => true) {
    const allowed = new Set(actions);
    return [...state.operationJobs.values()]
      .filter(job => job.module === moduleName && allowed.has(job.action) && predicate(job))
      .sort((left, right) => timeValue(right.created_at) - timeValue(left.created_at))[0] || null;
  }

  function renderMonitorSummary() {
    const native = monitorNative();
    const monitors = (safeArray(native.monitors).length ? safeArray(native.monitors) : safeArray(state.data.monitors))
      .filter(item => item.type !== 'group');
    const rows = monitors.map(item => {
      const latency = finiteNumber(item.ping ?? item.latency_ms);
      const uptime = finiteNumber(item.uptime_24h);
      return h('tr', {},
        titleCell(item.name || item.id, `${item.type || '类型未知'}${item.parent ? ` · 父组 ${item.parent}` : ''}`),
        h('td', {}, badge(item.status || item.state, item.active === false ? '已暂停' : undefined)),
        detailCell(latency === null ? '未返回' : `${Math.round(latency)} ms`),
        detailCell(uptime === null ? '未返回' : `${(uptime * (uptime <= 1 ? 100 : 1)).toFixed(2)}%`),
        detailCell(formatTime(item.checked_at)),
        h('td', {}, monitorActions(item))
      );
    });
    return table(['监控项', '状态', '延迟', '24h 可用率', '最后检查', '操作'], rows, '暂无业务监控证据', '接口当前未返回业务端点、检测时间或结果。');
  }

  async function openMonitorEditor(item, button) {
    state.monitorEditor = { id: item.id, seed: { ...item }, draft: null, dirty: false, loadedJobId: null };
    renderPage();
    const detail = resolveAction('monitors', 'kuma.monitor_detail', 'monitor_detail');
    if (detail) await startOperation('monitors', detail, { id: item.id }, button);
  }

  function monitorActions(item) {
    const actions = h('div', { class: 'cell-actions' });
    const detail = resolveAction('monitors', 'kuma.monitor_detail', 'monitor_detail');
    const update = resolveAction('monitors', 'kuma.monitor_update', 'monitor_update');
    if (detail || update) actions.append(h('button', { class: 'button button-secondary button-small', type: 'button', onClick: event => openMonitorEditor(item, event.currentTarget) }, icon('edit'), '查看 / 编辑'));
    const history = resolveAction('monitors', 'kuma.monitor_history', 'monitor_history');
    if (history) actions.append(h('button', { class: 'button button-secondary button-small', type: 'button', onClick: event => {
      state.monitorEditor = { id: item.id, seed: { ...item }, draft: null, dirty: false, loadedJobId: null };
      startOperation('monitors', history, { id: item.id, hours: 24, limit: 200 }, event.currentTarget);
    } }, '历史'));
    const toggle = resolveAction('monitors', item.active === false ? 'kuma.monitor_resume' : 'kuma.monitor_pause', item.active === false ? 'monitor_resume' : 'monitor_pause');
    if (toggle) actions.append(h('button', { class: 'button button-secondary button-small', type: 'button', onClick: event => startOperation('monitors', toggle, { id: item.id }, event.currentTarget) }, item.active === false ? '恢复' : '暂停'));
    const remove = resolveAction('monitors', 'kuma.monitor_delete', 'monitor_delete');
    if (remove) actions.append(h('button', { class: 'button button-danger button-small', type: 'button', onClick: event => {
      if (window.confirm(`确认删除监控「${item.name || item.id}」？\n\n默认不级联删除子项，服务端仍会检查依赖并读回结果。`)) startOperation('monitors', remove, { id: item.id, delete_children: false }, event.currentTarget);
    } }, icon('trash'), '删除'));
    return actions.childElementCount ? actions : h('span', { class: 'cell-sub', text: '当前仅可查看' });
  }

  const MONITOR_TYPES = [
    { value: 'http', label: 'HTTP(S)' }, { value: 'ping', label: 'Ping' },
    { value: 'port', label: '端口' }, { value: 'dns', label: 'DNS' }, { value: 'group', label: '分组' }
  ];

  function monitorTargetMeta(type) {
    return {
      http: { label: 'URL', placeholder: 'https://example.com/' },
      ping: { label: '主机名 / IP', placeholder: 'example.com' },
      port: { label: '主机名 / IP', placeholder: '10.88.0.10' },
      dns: { label: '查询域名', placeholder: 'example.com' },
      group: null
    }[type] || null;
  }

  function monitorTargetIsRedacted(value) {
    const raw = String(value || '');
    let decoded = raw;
    try { decoded = decodeURIComponent(raw); } catch (_) { /* 保持原文判断 */ }
    return /\[(?:invalid-url-)?hidden\]|\[redacted/i.test(`${raw} ${decoded}`);
  }

  function monitorPayload(draft, options = {}) {
    const editing = options.editing === true;
    const type = draft.type || 'http';
    const monitor = {
      name: String(draft.name || '').trim(), type,
      interval: Math.max(20, Number(draft.interval) || 60)
    };
    if (editing || draft.description) monitor.description = String(draft.description || '');
    if (draft.parent) monitor.parent = Number.isFinite(Number(draft.parent)) ? Number(draft.parent) : draft.parent;
    else if (editing) monitor.parent = null;
    if (draft.notificationId) monitor.notificationIDList = { [draft.notificationId]: true };
    else if (editing) monitor.notificationIDList = {};
    const target = String(draft.target || '').trim();
    const targetIsVisible = target && !monitorTargetIsRedacted(target);
    if (type === 'http' && targetIsVisible) monitor.url = target;
    if (['ping', 'port', 'dns'].includes(type) && targetIsVisible) monitor.hostname = target;
    if (['port', 'dns'].includes(type) && draft.port !== '') monitor.port = Number(draft.port);
    if (type === 'dns') {
      if (draft.dnsType) monitor.dns_resolve_type = draft.dnsType;
      if (editing || draft.dnsResolver) monitor.dns_resolve_server = String(draft.dnsResolver || '');
    }
    ['basic_auth_user', 'basic_auth_pass', 'bearer_token'].forEach(key => {
      if (draft[key]) monitor[key] = draft[key];
    });
    return monitor;
  }

  function monitorFields(form, draft, native, options = {}) {
    const addField = (key, label, config = {}) => {
      let input;
      if (config.options) input = h('select', { 'aria-label': label, disabled: config.disabled }, config.options.map(option => h('option', { value: option.value, text: option.label, selected: String(draft[key] || '') === String(option.value) })));
      else input = h('input', { type: config.type || 'text', value: draft[key] || '', placeholder: config.placeholder || '', required: Boolean(config.required), min: config.min, max: config.max, autocomplete: config.autocomplete || 'off', 'aria-label': label });
      input.addEventListener('input', event => {
        draft[key] = event.target.value;
        if (options.editor) options.editor.dirty = true;
        if (key === 'type' && options.rerender) options.rerender();
      });
      form.append(h('label', { class: config.className || '' }, h('span', { text: label }), input, config.help ? h('small', { text: config.help }) : null));
      return input;
    };
    addField('name', '名称', { required: true, placeholder: '例：业务·Google' });
    addField('type', '类型', { options: MONITOR_TYPES, disabled: options.lockType });
    addField('description', '描述', { placeholder: '可选，编辑时可清空' });
    const target = monitorTargetMeta(draft.type);
    if (target) addField('target', target.label, { required: !options.editor, placeholder: options.editor ? `${target.placeholder}（留空保留原目标）` : target.placeholder, className: 'field-span-2', help: options.editor ? '后端无法安全回显的 URL 会保持空白，空白不会覆盖原值。' : '' });
    if (['port', 'dns'].includes(draft.type)) addField('port', '端口', { required: true, type: 'number', min: '1', max: '65535', placeholder: draft.type === 'dns' ? '53' : '443' });
    if (draft.type === 'dns') {
      addField('dnsType', '记录类型', { options: ['A', 'AAAA', 'CNAME'].map(value => ({ value, label: value })) });
      addField('dnsResolver', '解析器', { required: !options.editor, placeholder: options.editor ? '1.1.1.1（可清空）' : '1.1.1.1' });
    }
    addField('interval', '检查间隔（秒）', { required: true, type: 'number', min: '20', placeholder: '60' });
    const groups = safeArray(native.groups);
    if (groups.length && draft.type !== 'group') addField('parent', '所属分组', { options: [{ value: '', label: '不指定' }, ...groups.map(group => ({ value: group.id, label: group.name || group.id }))] });
    const notifications = safeArray(native.notifications);
    if (notifications.length) addField('notificationId', '通知渠道', { options: [{ value: '', label: '不指定' }, ...notifications.map(item => ({ value: item.id, label: item.name || item.id }))] });
    return addField;
  }

  function monitorCreateForm(native) {
    const action = resolveAction('monitors', 'kuma.monitor_create', 'monitor_create');
    if (!action) return null;
    const form = h('form', { class: 'compact-form form-grid monitor-form', dataset: { preserveForm: 'true' } });
    const rerender = () => renderPage();
    monitorFields(form, state.monitorDraft, native, { rerender });
    const button = h('button', { class: 'button button-primary form-submit', type: 'submit' }, icon('plus'), '创建监控');
    form.append(button);
    form.addEventListener('submit', async event => {
      event.preventDefault();
      await startOperation('monitors', action, { monitor: monitorPayload(state.monitorDraft) }, button);
    });
    return panel('新建监控 / 分组', form, { subtitle: '仅显示 Kuma 2.5.6 与中心后端共同声明支持的类型。' });
  }

  function monitorEditorPanel(native) {
    const editor = state.monitorEditor;
    if (!editor) return null;
    const detailJob = latestOperation('monitors', ['kuma.monitor_detail', 'monitor_detail'], job => String(job.params?.id) === String(editor.id));
    const detail = detailJob?.result?.monitor;
    if (detail && editor.loadedJobId !== detailJob.job_id && !editor.dirty) {
      const rawTarget = detail.type === 'http' ? detail.url : detail.hostname;
      const target = monitorTargetIsRedacted(rawTarget) ? '' : rawTarget;
      const notificationId = Object.entries(detail.notificationIDList || {}).find(([, enabled]) => enabled)?.[0] || '';
      editor.draft = { ...detail, target: target || '', notificationId, dnsType: detail.dns_resolve_type || 'A', dnsResolver: detail.dns_resolve_server || '', interval: String(detail.interval || 60) };
      editor.loadedJobId = detailJob.job_id;
    }
    const draft = editor.draft || { ...editor.seed, target: editor.seed.url || editor.seed.hostname || '', interval: String(editor.seed.interval || 60), dnsType: 'A' };
    editor.draft = draft;
    const detailAction = resolveAction('monitors', 'kuma.monitor_detail', 'monitor_detail');
    const update = resolveAction('monitors', 'kuma.monitor_update', 'monitor_update');
    const form = h('form', { class: 'compact-form form-grid monitor-form', dataset: { preserveForm: 'true' } });
    monitorFields(form, draft, native, { editor, lockType: true });
    if (draft.type === 'http' && update) {
      const advanced = h('details', { class: 'advanced-fields field-span-all' }, h('summary', { text: '身份凭据（可选）' }));
      const fields = h('div', { class: 'form-grid' });
      const secretFields = [
        ['basic_auth_user', '基本认证用户名', 'username'], ['basic_auth_pass', '基本认证密码', '留空保留原值'], ['bearer_token', 'Bearer Token', '留空保留原值']
      ];
      secretFields.forEach(([key, label, placeholder]) => {
        const input = h('input', { value: '', type: key === 'basic_auth_user' ? 'text' : 'password', placeholder, autocomplete: 'new-password', 'aria-label': label });
        input.addEventListener('input', event => { draft[key] = event.target.value; editor.dirty = true; });
        fields.append(h('label', {}, h('span', { text: label }), input));
      });
      advanced.append(notice('敏感值不会回显；留空表示保留原秘密，本页不提供隐式清除。', 'info'), fields);
      form.append(advanced);
    }
    const footer = h('div', { class: 'dialog-actions field-span-all' },
      h('button', { class: 'button button-secondary', type: 'button', onClick: () => { state.monitorEditor = null; renderPage(); } }, '关闭'),
      update ? h('button', { class: 'button button-primary', type: 'submit', disabled: Boolean(detailAction && !detail), title: detailAction && !detail ? '等待脱敏详情读取完成，避免用列表摘要覆盖完整配置。' : '' }, '保存并读回验证') : null
    );
    form.append(footer);
    if (update) form.addEventListener('submit', event => {
      event.preventDefault();
      const patch = monitorPayload(draft, { editing: true });
      startOperation('monitors', update, { id: editor.id, patch }, event.submitter);
    });
    const historyJob = latestOperation('monitors', ['kuma.monitor_history', 'monitor_history'], job => String(job.params?.id) === String(editor.id));
    const beats = safeArray(historyJob?.result?.beats).slice(0, 12);
    const history = beats.length ? table(['时间', '状态', '延迟', '证据'], beats.map(beat => h('tr', {}, detailCell(formatTime(beat.time)), h('td', {}, badge(beat.status)), detailCell(finiteNumber(beat.ping) === null ? '未返回' : `${Math.round(Number(beat.ping))} ms`), detailCell(beat.msg || (beat.important ? '重要事件' : '无附加信息')))), '暂无历史', '未返回历史样本。') : null;
    return panel(`监控详情 · ${draft.name || editor.id}`, h('div', {}, detailJob && detailJob.state !== 'ok' ? notice('正在读取脱敏配置，当前表单使用列表摘要。', 'info') : null, form, history));
  }

  function renderMonitorGroups(native) {
    const groups = safeArray(native.groups);
    if (!groups.length) return emptyState('暂无监控分组', '后端未返回 Kuma 监控组或组为空。');
    return h('div', { class: 'card-grid' }, groups.map(group => h('article', { class: 'mini-card' },
      h('div', { class: 'mini-card-top' }, h('strong', { text: group.name || group.id }), badge(group.active === false ? 'warning' : 'ok', group.active === false ? '已暂停' : '活动')),
      h('p', { text: `子项 ${safeArray(group.children_ids).length} 个` }),
      monitorActions({ ...group, type: 'group' })
    )));
  }

  function notificationActions(item) {
    const box = h('div', { class: 'cell-actions' });
    const detail = resolveAction('monitors', 'kuma.notification_detail', 'notification_detail');
    const update = resolveAction('monitors', 'kuma.notification_update', 'notification_update');
    if (detail || update) box.append(h('button', { class: 'button button-secondary button-small', type: 'button', onClick: event => {
      state.notificationEditor = { id: item.id, seed: { ...item }, draft: null, dirty: false, loadedJobId: null };
      renderPage();
      if (detail) startOperation('monitors', detail, { id: item.id }, event.currentTarget);
    } }, icon('edit'), '查看 / 编辑'));
    const test = resolveAction('monitors', 'kuma.notification_test', 'notification_test');
    if (test) box.append(h('button', { class: 'button button-secondary button-small', type: 'button', onClick: event => startOperation('monitors', test, { id: item.id }, event.currentTarget) }, icon('play'), '发送测试'));
    const remove = resolveAction('monitors', 'kuma.notification_delete', 'notification_delete');
    if (remove) box.append(h('button', { class: 'button button-danger button-small', type: 'button', onClick: event => {
      if (window.confirm(`确认删除通知渠道「${item.name || item.id}」？`)) startOperation('monitors', remove, { id: item.id }, event.currentTarget);
    } }, icon('trash'), '删除'));
    return box.childElementCount ? box : h('span', { class: 'cell-sub', text: '当前仅可查看' });
  }

  function notificationForm(native, editor = null) {
    const action = resolveAction('monitors', editor ? 'kuma.notification_update' : 'kuma.notification_create', editor ? 'notification_update' : 'notification_create');
    if (!action) return null;
    const detailJob = editor ? latestOperation('monitors', ['kuma.notification_detail', 'notification_detail'], job => String(job.params?.id) === String(editor.id)) : null;
    const detail = detailJob?.result?.notification;
    if (editor && detail && editor.loadedJobId !== detailJob.job_id && !editor.dirty) {
      editor.draft = { ...detail, webhookURL: '', webhookCustomBody: '', webhookAdditionalHeaders: '' };
      editor.loadedJobId = detailJob.job_id;
    }
    const draft = editor ? (editor.draft || { ...editor.seed, webhookURL: '', webhookCustomBody: '', webhookAdditionalHeaders: '' }) : state.notificationDraft;
    if (editor) editor.draft = draft;
    const form = h('form', { class: 'compact-form form-grid', dataset: { preserveForm: 'true' } });
    const add = (key, label, config = {}) => {
      const input = config.options ? h('select', { 'aria-label': label }, config.options.map(option => h('option', { value: option.value, text: option.label, selected: String(draft[key] || '') === String(option.value) })))
        : h(config.multiline ? 'textarea' : 'input', { value: draft[key] || '', placeholder: config.placeholder || '', required: Boolean(config.required), rows: config.multiline ? 3 : undefined, autocomplete: config.secret ? 'new-password' : 'off', 'aria-label': label });
      input.addEventListener('input', event => { draft[key] = event.target.value; if (editor) editor.dirty = true; });
      form.append(h('label', { class: config.className || '' }, h('span', { text: label }), input));
    };
    add('name', '名称', { required: true, placeholder: '例：运维 Webhook' });
    add('httpMethod', '方法', { options: [{ value: 'post', label: 'POST' }, { value: 'get', label: 'GET' }] });
    add('webhookContentType', '内容类型', { options: [{ value: 'json', label: 'JSON' }, { value: 'form-data', label: 'Form Data' }, { value: 'custom', label: '自定义' }] });
    add('webhookURL', 'Webhook URL', { required: !editor, placeholder: editor ? '留空保留原 URL' : 'https://example.com/webhook', secret: true, className: 'field-span-2' });
    add('webhookCustomBody', '自定义请求体', { multiline: true, placeholder: editor ? '留空保留原值' : '可选', secret: true });
    add('webhookAdditionalHeaders', '额外请求头', { multiline: true, placeholder: editor ? '留空保留原值' : '可选', secret: true });
    form.append(notice(editor ? '敏感 URL、请求头和请求体不会回显；留空保留原值。' : '敏感值只提交给后端，不写入浏览器存储。', 'info'));
    const footer = h('div', { class: 'dialog-actions field-span-all' });
    if (editor) footer.append(h('button', { class: 'button button-secondary', type: 'button', onClick: () => { state.notificationEditor = null; renderPage(); } }, '关闭'));
    footer.append(h('button', { class: 'button button-primary', type: 'submit' }, editor ? '保存并读回验证' : '创建 Webhook'));
    form.append(footer);
    form.addEventListener('submit', event => {
      event.preventDefault();
      const notification = { name: draft.name, type: 'webhook', active: true, httpMethod: draft.httpMethod || 'post', webhookContentType: draft.webhookContentType || 'json' };
      ['webhookURL', 'webhookCustomBody', 'webhookAdditionalHeaders'].forEach(key => { if (draft[key]) notification[key] = draft[key]; });
      const params = editor ? { id: editor.id, notification } : { notification };
      startOperation('monitors', action, params, event.submitter);
    });
    return form;
  }

  function renderNotifications(native) {
    const rows = safeArray(native.notifications).map(item => h('tr', {},
      titleCell(item.name || item.id, item.type || '类型未知'), h('td', {}, badge(item.active === false ? 'warning' : 'ok', item.active === false ? '已停用' : '启用')),
      detailCell(item.is_default ? '默认渠道' : '非默认'), detailCell('敏感配置不回显'), h('td', {}, notificationActions(item))
    ));
    const createForm = notificationForm(native);
    return h('div', {}, state.notificationEditor ? panel('编辑 Webhook 通知', notificationForm(native, state.notificationEditor)) : null,
      createForm ? panel('新建 Webhook 通知', createForm) : null,
      table(['通知渠道', '状态', '用途', '配置', '操作'], rows, '暂无通知渠道', '接口未返回通知渠道证据。'));
  }

  function kumaBindingForm(native) {
    const action = resolveAction('monitors', 'kuma.bind');
    if (!action || !['binding_required', 'auth_failed', 'unbound'].includes(String(native.state || native.connection?.state || ''))) return null;
    const form = h('form', { class: 'compact-form form-grid', dataset: { preserveForm: 'true' } });
    const username = h('input', { autocomplete: 'username', required: true, 'aria-label': 'Kuma 用户名' });
    const password = h('input', { type: 'password', autocomplete: 'new-password', required: true, 'aria-label': 'Kuma 密码' });
    const totp = h('input', { type: 'password', inputmode: 'numeric', autocomplete: 'one-time-code', 'aria-label': 'Kuma 一次性验证码' });
    const submit = h('button', { class: 'button button-primary form-submit', type: 'submit' }, '安全绑定 Kuma');
    form.append(
      notice('这是中心后端的一次性绑定，不是第二个管理入口。凭据不进入状态、任务、审计或重试队列。', 'warning'),
      h('label', {}, h('span', { text: '用户名' }), username),
      h('label', {}, h('span', { text: '密码' }), password),
      h('label', {}, h('span', { text: 'TOTP（如启用）' }), totp), submit
    );
    form.addEventListener('submit', async event => {
      event.preventDefault();
      submit.disabled = true;
      try {
        const params = { username: username.value, password: password.value };
        if (totp.value) params.totp = totp.value;
        const job = await api('/api/center/kuma/bind', { method: 'POST', body: { expected_revision: native.revision, params } });
        username.value = ''; password.value = ''; totp.value = '';
        if (!job.job_id) throw new Error('后端未返回绑定任务 ID。');
        state.operationJobs.set(job.job_id, { ...job, module: 'monitors', action: 'kuma.bind', params: {} });
        await pollOperation(job.job_id);
        toast('绑定任务已进入受控队列，凭据输入已清除。');
      } catch (error) {
        username.value = ''; password.value = ''; totp.value = '';
        toast(error.message, true);
      } finally { submit.disabled = false; }
    });
    return panel('Kuma 后端绑定', form);
  }

  function renderMonitors() {
    const current = state.activeTabs.monitors;
    const native = monitorNative();
    const body = current === 'monitors' ? h('div', {}, monitorEditorPanel(native), monitorCreateForm(native), renderMonitorSummary())
      : current === 'groups' ? h('div', {}, monitorCreateForm(native), renderMonitorGroups(native)) : renderNotifications(native);
    const actions = state.session.authenticated ? [] : [sessionActionButton('管理登录', openLogin)];
    const gate = managementGate('monitors', 'Kuma 原生监控管理');
    const connection = native.connection && typeof native.connection === 'object' ? native.connection : {};
    return h('div', { class: 'page' }, heading('monitors', actions), operationCard('monitors'), gate, kumaBindingForm(native),
      panel('Kuma 原生监控', body, {
        flush: true,
        subtitle: native.version ? `Kuma ${native.version} · ${connection.detail || '已通过中心后台连接'} · 证据 ${formatTime(connection.checked_at)}` : '无需第二次登录；当前能力以后端声明为准。',
        headerActions: tabs('monitors', [{ id: 'monitors', label: '监控项' }, { id: 'groups', label: '分组' }, { id: 'notifications', label: '通知' }])
      }));
  }

  function diagnosticJobs() {
    const diagnosticActions = new Set(['query', 'dns.query', 'diagnose', 'dns.diagnose', 'leak_test', 'dns.leak_test']);
    return [...state.operationJobs.values()].filter(job => job.module === 'dns' && diagnosticActions.has(job.action))
      .sort((left, right) => timeValue(right.created_at) - timeValue(left.created_at));
  }

  function diagnosticStages(value) {
    if (Array.isArray(value)) return value;
    if (!value || typeof value !== 'object') return [];
    return Object.entries(value).map(([id, stage]) => typeof stage === 'object' && stage
      ? { id, ...stage }
      : { id, state: stage, detail: '未返回分项详情' });
  }

  function diagnosticResult() {
    const job = diagnosticJobs()[0];
    if (!job) return emptyState('尚未执行诊断', '选择检测对象和视角后启动。诊断只收集证据，不会自动改 DNS 或业务选择。');
    const result = job.result && typeof job.result === 'object' ? job.result : {};
    const stages = diagnosticStages(result.stages);
    const sites = safeArray(result.sites);
    return h('div', { class: 'diagnostic-result' },
      h('div', { class: 'diagnostic-summary' },
        h('div', {}, h('span', { class: 'cell-sub', text: '结论' }), h('strong', { text: result.state === 'anomaly' ? '发现异常，需继续核对' : result.state === 'ok' ? '本次观测未发现异常' : '证据不足或检测失败' })),
        h('div', {}, h('span', { class: 'cell-sub', text: '证据范围' }), h('strong', { text: valueOrUnknown(result.evidence_scope) })),
        h('div', {}, h('span', { class: 'cell-sub', text: '可信度' }), h('strong', { text: formatConfidence(result.confidence) })),
        h('div', {}, h('span', { class: 'cell-sub', text: '检查时间' }), h('strong', { text: formatTime(result.checked_at || job.completed_at) }))
      ),
      stages.length ? panel('分阶段证据', h('div', { class: 'probe-grid' }, stages.map(stage => h('div', { class: 'probe-item' },
        h('div', { class: 'probe-item-top' }, h('span', { class: 'probe-item-title', text: stage.label || stage.id || '检测阶段' }), badge(stage.state)),
        h('div', { class: 'probe-item-detail', text: stage.detail || stage.error || '未返回详情' })
      )))) : null,
      sites.length ? panel('多站点结果', table(['站点', '方式', '结果', '证据'], sites.map(site => h('tr', {},
        titleCell(site.name || site.id, site.perspective || ''), detailCell(site.mode || '未知'), h('td', {}, badge(site.state)), detailCell(site.detail || site.error || '未返回')
      )), '暂无站点证据', '接口未返回多站点检测结果。'), { flush: true }) : null,
      result.browser_plan ? notice('当前结果是浏览器侧执行计划，尚不是检测成功证据。需由当前浏览器完成指定随机查询并提交返回结果。', 'warning') : null
    );
  }

  async function runBrowserLeakTest(action, button) {
    if (button) button.disabled = true;
    try {
      const planStart = await startOperation('dns', action, { perspective: 'browser', mode: 'quick', phase: 'plan' });
      if (!planStart?.job_id) return;
      const planJob = await waitForOperation(planStart.job_id);
      if (planJob.state !== 'ok') throw new Error(planJob.error || '浏览器泄漏检测计划生成失败。');
      const plan = planJob.result?.browser_plan;
      const probeRows = plan?.probe_urls;
      if (!plan?.plan_id || !Array.isArray(probeRows) || probeRows.length < 1 || probeRows.length > 64) throw new Error('后端未返回 1–64 条有效的浏览器检测计划。');
      const urls = probeRows.map(item => typeof item === 'string' ? item : item?.url);
      if (urls.some(value => typeof value !== 'string' || !value)) throw new Error('检测计划包含缺失的探针地址，已拒绝部分执行。');
      const expiresAt = timeValue(plan.expires_at);
      if (expiresAt && expiresAt <= Date.now()) throw new Error('浏览器检测计划已过期，需重新发起；旧计划不作为检测证据。');
      const safeUrls = urls.filter(value => {
        try {
          const url = new URL(value);
          return url.protocol === 'https:' && (url.hostname === 't.dnsleak.dev' || url.hostname.endsWith('.t.dnsleak.dev'));
        } catch (_) { return false; }
      });
      if (safeUrls.length !== urls.length) throw new Error('检测计划包含未授权站点，浏览器已拒绝执行。');
      const rawOptions = plan.fetch_options && typeof plan.fetch_options === 'object' ? plan.fetch_options : {};
      const fetchOptions = {
        method: String(rawOptions.method || 'GET').toUpperCase() === 'GET' ? 'GET' : 'GET',
        mode: ['cors', 'no-cors'].includes(rawOptions.mode) ? rawOptions.mode : 'no-cors',
        credentials: 'omit',
        cache: ['default', 'no-store', 'reload', 'no-cache'].includes(rawOptions.cache) ? rawOptions.cache : 'no-store',
        redirect: ['follow', 'error'].includes(rawOptions.redirect) ? rawOptions.redirect : 'follow',
        referrerPolicy: 'no-referrer'
      };
      if (!window.AbortController) throw new Error('当前浏览器不支持有界探针超时，已拒绝执行。');
      const controller = new AbortController();
      const probeTimeout = window.setTimeout(() => controller.abort(), 5000);
      try {
        await Promise.allSettled(safeUrls.map(url => fetch(url, { ...fetchOptions, signal: controller.signal })));
      } finally {
        window.clearTimeout(probeTimeout);
      }
      const delay = Math.max(500, Math.min(10000, Number(plan.readout_after_ms) || 1500));
      await new Promise(resolve => window.setTimeout(resolve, delay));
      if (expiresAt && expiresAt <= Date.now()) throw new Error('检测计划在读取前已过期，需重新发起。');
      const readout = await startOperation('dns', action, { perspective: 'browser', mode: 'quick', phase: 'readout', plan_id: plan.plan_id });
      if (!readout?.job_id) return;
      const readoutJob = await waitForOperation(readout.job_id);
      if (readoutJob.state !== 'ok') throw new Error(readoutJob.error || '浏览器检测证据读取失败。');
      const result = readoutJob.result && typeof readoutJob.result === 'object' ? readoutJob.result : {};
      const automatic = safeArray(result.sites).find(site => String(site.id || '').toLowerCase() === 'dnsleak.dev');
      const observed = finiteNumber(automatic?.lookups);
      const incomplete = result.state === 'ok' && (observed === null || observed < safeUrls.length);
      if (incomplete) {
        const patchedResult = { ...result, state: 'unknown', confidence: 'limited' };
        patchedResult.stages = { ...(result.stages || {}), readout: { state: 'unknown', detail: `官方站点仅返回 ${valueOrUnknown(observed)} / ${safeUrls.length} 条查询证据` } };
        patchedResult.sites = safeArray(result.sites).map(site => String(site.id || '').toLowerCase() === 'dnsleak.dev'
          ? { ...site, state: 'unknown', detail: `查询证据不足：${valueOrUnknown(observed)} / ${safeUrls.length}` }
          : site);
        state.operationJobs.set(readout.job_id, { ...readoutJob, result: patchedResult });
      }
      toast(incomplete ? '已执行全部浏览器探针，但返回数量不足，结果保持未知。' : '浏览器视角检测已完成，请查看多站点证据；未知结果不会标记为安全。', incomplete);
      renderPage();
    } catch (error) {
      toast(error.message, true);
    } finally {
      if (button?.isConnected) button.disabled = false;
    }
  }

  function diagnosticForm() {
    const form = h('form', { class: 'diagnostic-form', dataset: { preserveForm: 'true' } });
    const domain = h('input', { value: state.diagnosticDraft.domain, placeholder: '输入域名，例如 example.com', 'aria-label': '诊断域名' });
    const qtype = h('select', { 'aria-label': '记录类型' }, ['A', 'AAAA', 'CNAME'].map(value => h('option', { value, text: value, selected: state.diagnosticDraft.qtype === value })));
    const resolver = h('input', { value: state.diagnosticDraft.resolver, placeholder: '指定解析器（可选）', 'aria-label': '指定解析器' });
    const perspective = h('select', { 'aria-label': '检测视角' }, [
      { value: 'container', label: '中心容器' }, { value: 'resolver', label: '指定 DNS' }, { value: 'browser', label: '当前浏览器' }
    ].map(item => h('option', { value: item.value, text: item.label, selected: state.diagnosticDraft.perspective === item.value })));
    [[domain, 'domain'], [qtype, 'qtype'], [resolver, 'resolver'], [perspective, 'perspective']].forEach(([input, key]) => input.addEventListener('input', event => { state.diagnosticDraft[key] = event.target.value; }));
    qtype.addEventListener('change', () => {
      if (qtype.value === 'CNAME' && !resolver.value.trim()) {
        resolver.value = '127.0.0.1:53';
        state.diagnosticDraft.resolver = resolver.value;
        toast('CNAME 需要显式解析器，已使用当前 CoreDNS 127.0.0.1:53。');
      }
    });
    form.append(h('label', { class: 'diagnostic-domain' }, h('span', { text: '域名' }), domain),
      h('label', {}, h('span', { text: '记录' }), qtype), h('label', {}, h('span', { text: '解析器' }), resolver), h('label', {}, h('span', { text: '视角' }), perspective));
    const buttons = h('div', { class: 'diagnostic-actions' });
    const operations = [
      { kind: 'query', candidates: ['dns.query', 'query'], label: '单次查询', params: () => ({ domain: state.diagnosticDraft.domain, qtype: state.diagnosticDraft.qtype, resolver: state.diagnosticDraft.resolver || undefined, transport: state.diagnosticDraft.transport }) },
      { kind: 'diagnose', candidates: ['dns.diagnose', 'diagnose'], label: '快速路径诊断', params: () => ({ mode: 'quick', perspective: state.diagnosticDraft.perspective, domains: [state.diagnosticDraft.domain], resolver: state.diagnosticDraft.perspective === 'resolver' ? state.diagnosticDraft.resolver : undefined }) },
      { kind: 'leak', candidates: ['dns.leak_test', 'leak_test'], label: '多站点泄漏检测', params: () => ({ mode: 'quick', perspective: state.diagnosticDraft.perspective }) }
    ];
    operations.forEach(definition => {
      const action = resolveAction('dns', ...definition.candidates);
      if (!action) return;
      const button = h('button', { class: 'button button-secondary', type: 'submit', dataset: { action } }, definition.label);
      button.addEventListener('click', () => { form.dataset.selectedAction = action; form.dataset.selectedKind = definition.kind; form._operationParams = definition.params; });
      button.dataset.operationKind = definition.kind;
      buttons.append(button);
    });
    const syncPerspectiveControls = () => {
      const browserOnly = perspective.value === 'browser';
      buttons.querySelectorAll('button[data-operation-kind]').forEach(button => {
        const blocked = browserOnly && button.dataset.operationKind !== 'leak';
        button.disabled = blocked;
        button.title = blocked ? '浏览器视角只能执行浏览器泄漏计划；查询和路径诊断请选中心容器或指定 DNS。' : '';
      });
    };
    perspective.addEventListener('change', syncPerspectiveControls);
    syncPerspectiveControls();
    form.append(buttons);
    form.addEventListener('submit', event => {
      event.preventDefault();
      const action = form.dataset.selectedAction;
      if (!action || typeof form._operationParams !== 'function') return;
      if (form.dataset.selectedKind !== 'leak' && !state.diagnosticDraft.domain.trim()) {
        toast('单次查询和路径诊断需要输入域名。', true);
        domain.focus();
        return;
      }
      if (state.diagnosticDraft.perspective === 'browser' && form.dataset.selectedKind !== 'leak') {
        toast('浏览器视角只支持泄漏检测；普通查询和路径诊断不会伪装成浏览器证据。', true);
        return;
      }
      if (form.dataset.selectedKind === 'diagnose' && state.diagnosticDraft.perspective === 'resolver' && !state.diagnosticDraft.resolver.trim()) {
        toast('指定 DNS 视角的路径诊断需要填写解析器。', true);
        resolver.focus();
        return;
      }
      if (form.dataset.selectedKind === 'query' && state.diagnosticDraft.qtype === 'CNAME' && !state.diagnosticDraft.resolver.trim()) {
        resolver.value = '127.0.0.1:53';
        state.diagnosticDraft.resolver = resolver.value;
      }
      const button = event.submitter;
      if (form.dataset.selectedKind === 'leak' && state.diagnosticDraft.perspective === 'browser') runBrowserLeakTest(action, button);
      else startOperation('dns', action, form._operationParams(), button);
    });
    return form;
  }

  function leakSiteCards() {
    const module = managementModule('dns');
    const sites = safeArray(module.capabilities?.leak_sites);
    if (!sites.length) return emptyState('暂无泄漏站点能力证据', '后端未声明已验证的自动或人工对照站点。');
    const knownLinks = {
      ipleak: 'https://ipleak.net/', browserleaks: 'https://browserleaks.com/dns', dnsleaktest: 'https://www.dnsleaktest.com/'
    };
    return h('div', { class: 'card-grid' }, sites.map(siteRaw => {
      const site = typeof siteRaw === 'string' ? { id: siteRaw } : siteRaw || {};
      const manual = site.mode === 'manual_external' || site.mode === 'browser';
      const href = knownLinks[String(site.id || '').toLowerCase()];
      return h('article', { class: 'mini-card' },
        h('div', { class: 'mini-card-top' }, h('strong', { text: site.name || site.id || '未命名站点' }), badge(manual ? 'warning' : 'unknown', manual ? '人工 / 浏览器' : '自动接口')),
        h('p', { text: site.detail || (manual ? '需在浏览器中执行，容器结果不能冒充终端证据。' : '由后端受限调用，单站失败不抹掉其他结果。') }),
        manual && href ? h('a', { class: 'button button-secondary button-small', href, target: '_blank', rel: 'noopener' }, icon('external'), '打开人工对照') : null
      );
    }));
  }

  function renderDiagnostics() {
    const gate = managementGate('dns', 'DNS 诊断与泄漏检测');
    return h('div', { class: 'page' }, heading('diagnostics'), gate,
      notice('解析结果不同不等于污染；系统会结合 Fake-IP、本地记录、CDN 差异、TCP/TLS 及重复证据分级，无证据时保持“无法判断”。', 'info'),
      panel('发起检测', diagnosticForm()),
      panel('最新诊断结果', diagnosticResult()),
      panel('检测站点与能力', leakSiteCards())
    );
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
    mobileMenu.querySelector('use')?.setAttribute('href', '#i-menu');
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
    mobileMenu.querySelector('use')?.setAttribute('href', open ? '#i-close' : '#i-menu');
    if (open) window.setTimeout(() => sidebarClose.focus(), 210);
  });
  sidebarBackdrop.addEventListener('click', closeSidebar);
  sidebarClose.addEventListener('click', () => { closeSidebar(); mobileMenu.focus(); });
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
      await Promise.all([loadManagement(), loadLocalPublisher()]);
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
  document.addEventListener('visibilitychange', () => {
    if (document.hidden) cancelOverviewFollowup(false);
    else {
      scheduleOverviewFollowup();
      updateOverviewEvidenceStamp();
    }
  });
  window.addEventListener('keydown', event => {
    if (event.key === 'Escape' && sidebar.classList.contains('open')) closeSidebar();
  });

  async function start() {
    if (!window.location.hash || !/^#\/(overview|routing|nodes|subscriptions|dns|monitors|diagnostics|backups|activity)$/.test(window.location.hash)) {
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
