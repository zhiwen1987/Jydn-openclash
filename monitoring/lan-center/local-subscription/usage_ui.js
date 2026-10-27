(function (global) {
  'use strict';
  const statusLabels = {ok: '正常', cached: '缓存', checking: '等待获取', unavailable: '获取失败'};
  const errors = {transport_unavailable: '连接暂不可用，将自动重试', http_429: '来源限流，已延后重试',
    information_header_missing: '来源未提供套餐信息', information_header_incomplete: '来源套餐字段不完整',
    information_header_invalid: '来源套餐字段无效', metadata_worker_error: '采集暂不可用，将自动重试',
    invalid_information_url: '信息地址无效', ambiguous_information_origin: '合并来源无法确定独立套餐'};
  function bytes(value) {
    if (!Number.isFinite(value) || value < 0) return '未获取';
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB'];
    let index = 0;
    while (value >= 1024 && index < units.length - 1) { value /= 1024; index++; }
    return value.toFixed(index ? 1 : 0) + ' ' + units[index];
  }
  function date(value) { return Number.isFinite(value) && value > 0 ? new Date(value * 1000).toLocaleString() : '未提供'; }
  function node(tag, text, className) {
    const el = document.createElement(tag);
    if (className) el.className = className;
    if (text != null) el.textContent = text;
    return el;
  }
  function styles() {
    if (document.getElementById('jydn-usage-style')) return;
    const el = node('style'); el.id = 'jydn-usage-style';
    el.textContent = '.jydn-usage-grid{display:grid!important;grid-template-columns:repeat(auto-fit,minmax(min(100%,190px),1fr));gap:8px;max-height:300px;overflow:auto;min-width:0}.jydn-usage-grid .provider-card{min-width:0;max-width:100%;padding:10px;overflow-wrap:anywhere}.jydn-usage-grid p{margin:4px 0;line-height:1.45}.jydn-usage-summary{grid-column:1/-1;margin:0!important}.jydn-usage-meta{font-size:12px}.jydn-usage-grid:focus-visible{outline:2px solid currentColor;outline-offset:2px}.jydn-usage-status{font-weight:600}';
    el.textContent += ".jydn-usage-grid .provider-card{padding:10px!important;display:block!important}.jydn-usage-grid p{padding:0!important;margin:4px 0!important;line-height:1.45!important}.jydn-usage-grid .jydn-usage-summary{margin:0!important}#subscription-info-display:has(.jydn-usage-grid){height:auto!important;min-height:180px}.config-file-content:has(.jydn-usage-grid),.sub-card:has(.jydn-usage-grid){height:auto!important}";
    document.head.appendChild(el);
  }
  function render(root, data) {
    if (!root) return;
    styles(); root.replaceChildren(); root.classList.remove('oc-hidden');
    root.classList.add('jydn-usage-grid'); root.setAttribute('aria-live', 'polite');
    root.setAttribute('aria-label', '各订阅来源的用量和获取状态'); root.tabIndex = 0;
    const rows = Array.isArray(data.providers) ? data.providers : [];
    let summary = '自动识别 ' + rows.length + ' 个启用来源';
    if (data.registry_state === 'error') summary += ' · 来源配置读取失败，保留上次清单';
    else if (data.registry_state !== 'ok') summary += ' · 用量服务暂不可用，等待恢复';
    root.appendChild(node('p', summary, 'jydn-usage-summary'));
    if (!rows.length) {
      root.appendChild(node('p', data.registry_state === 'ok' ? '暂无启用的订阅来源。' : '暂时无法读取来源，未将其标成零用量。'));
      return;
    }
    for (const source of rows) {
      const card = node('div', null, 'provider-card');
      card.dataset.sourceId = source.id || '';
      card.appendChild(node('div', source.name || source.provider_name || source.id, 'subscription-info-title'));
      const status = source.usage_status || 'unavailable';
      card.appendChild(node('p', statusLabels[status] || '状态未知', 'jydn-usage-status'));
      const metrics = source.metrics;
      if (metrics && Number.isFinite(metrics.total) && Number.isFinite(metrics.upload) && Number.isFinite(metrics.download)) {
        const used = metrics.upload + metrics.download;
        const remaining = Math.max(0, metrics.total - used);
        card.appendChild(node('p', '已用 ' + bytes(used) + ' / 总量 ' + (metrics.total === 0 ? '不限量（来源返回 0）' : bytes(metrics.total))));
        if (metrics.total > 0) card.appendChild(node('p', '剩余 ' + bytes(remaining)));
        card.appendChild(node('p', '到期：' + (metrics.expire === 0 ? '长期（来源返回 0）' : date(metrics.expire))));
        card.appendChild(node('p', '最后成功：' + date(source.last_success), 'jydn-usage-meta'));
        if (status === 'cached') card.appendChild(node('p', source.stale ? '结果已过期，仅供参考，不是本次实时用量。' : '本次未能获取，显示上次成功值。', 'jydn-usage-meta'));
      } else {
        card.appendChild(node('p', '用量和到期：未获取'));
      }
      if (source.error) card.appendChild(node('p', errors[source.error] || (/^http_\d{3}$/.test(source.error) ? '来源返回 HTTP ' + source.error.slice(5) : '暂未取得有效信息，将按计划重试'), 'jydn-usage-meta'));
      root.appendChild(card);
    }
  }
  const api = {render, bytes, date}; global.JydnUsageUI = api;
  // The native status script is patched only for metadata caching/zero-source
  // handling. Existing non-auto rendering remains owned by OpenClash.
  if (typeof SubscriptionManager !== 'undefined' && !SubscriptionManager.jydnUsageInstalled) {
    const previous = SubscriptionManager.displaySubscriptionInfo;
    SubscriptionManager.displaySubscriptionInfo = function (data) {
      if (!data || !data.auto_mode) return previous.call(this, data);
      const outer = document.getElementById('subscription-info-display');
      const details = document.getElementById('subscription-info-details');
      if (outer) outer.classList.remove('oc-hidden');
      if (details) details.style.display = 'flex';
      render(document.getElementById('subscription-progress-section'), data);
    };
    SubscriptionManager.jydnUsageInstalled = true;
  }
  if (typeof document !== 'undefined') {
    const target = document.getElementById('subscription-usage-cards');
    if (target) {
      let pending = false;
      const update = async () => {
        if (pending) return;
        pending = true;
        try {
          const result = await fetch('/api/subscription-usage', {cache: 'no-store'});
          if (!result.ok) throw new Error('metadata_unavailable');
          render(target, await result.json());
        } catch (_) {
          render(target, {providers: [], registry_state: 'worker_unavailable'});
        } finally { pending = false; }
      };
      update(); setInterval(update, 30000);
    }
  }
  if (typeof module !== 'undefined') module.exports = api;
})(typeof window !== 'undefined' ? window : globalThis);
