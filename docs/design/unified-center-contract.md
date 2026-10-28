# 进源Clash Center：统一入口与验收契约

## 方向

服务现有局域网管理者，解决地址分散、同步含义不清、异常难定位和操作结果难确认的问题。目标是让日常查看、定位、操作和核验在同一个地址中完成，降低误操作和维护成本。产品采用清楚、克制、可信的浅色后台：白色表面、冷灰画布、蓝色主色，状态同时使用图标与文字。优先呈现整体运行、真实业务走向、分阶段同步、待处理事项及操作结果。保留完整模块和高级管理，按任务逐步展开；移动端同样可以查看与操作。所有运行状态来自真实接口，未连接和过期都明确显示，不生成假成功率或假进度。

用户提供的 Logo 原文件放在 `monitoring/lan-center/unified-center/assets/logo.png`，品牌文字为“进源Clash Center”。仅复用原文件，不改图案。视觉参考图位于本机生成目录，属设计示意，示意数字不进入运行默认数据。

## 模块与路径

统一主入口为原订阅管理地址的 `/`，内部导航用 `#/overview`、`#/routing`、`#/nodes`、`#/subscriptions`、`#/dns`、`#/monitors`、`#/diagnostics`、`#/backups`、`#/activity`。静态资源统一 `/center-assets/`。原 provider 路径、Token 和允许来源不变。自建节点复用现有 `/api/local/status / preview / publish`，但交互已收口到节点页：批量粘贴→脱敏预览→同版内核校验→发布→旁路由读回。Kuma 的 HTTP、Ping、端口、DNS、分组和 Webhook 通知在监控页原生管理，不用 iframe，不再把 3101 或另一次 Kuma 登录当作主入口。

## 前后端接口

`GET /api/center/overview` 返回下列结构，字段无证据时为 null/unknown，单部分失败不使其他部分消失：

```json
{"schema":1,"updated_at":0,"refreshing":false,"stale":false,"evidence_age_seconds":null,"overall":{"state":"unknown","title":"等待检测","detail":""},"metrics":{"nodes":null,"subscriptions":null,"selectors":null,"rules":null},"sync":{"state":"unknown","stages":[],"information_sources":null,"node_sources":null},"services":[],"businesses":[],"nodes":[],"subscriptions":{"providers":[],"source_sync":{}},"dns":{"state":"unknown","upstreams":[],"detail":""},"monitors":[],"backups":[],"events":[],"issues":[],"capabilities":{"writes":true,"advanced_router_path":"/cgi-bin/luci/"}}
```

`refreshing:true` 是后台单飞采集的唯一短轮询信号；`overall.state` 可表达真实业务状态，不用于猜测是否采集中。首次返回采集中时，前端以 1/2/4/8 秒有界退避复查，最多四次；后台的 single-flight 保证不重复启动慢源。页面隐藏时停止短轮询，恢复可见后若仍为 `refreshing:true` 再继续；四次后仍未结束显示“后台仍在采集”，保留现有证据。`stale` 和 `evidence_age_seconds` 只表达证据新鲜度。

通用状态为 `ok / running / pending / warning / error / stale / unknown`，前端均译成中文。`sync.stages` 每项有 `id,label,state,detail,last_success,next_due`；区分信息来源读取、节点检测、受控发布和运行加载，明确“信息来源 N 家”不等于“已发布 N 家节点”。加载验证只报告已取得的证据，例如节点名/数量一致，不冒充端点和业务全部通过。

`businesses` 每项含 `id,name,selection,leaf,chain,options,state,detail`；`id` 为真实策略名。`services` 每项含 `id,name,state,checked_at,detail`。`issues` 每项含 `id,title,detail,page,state`，`page` 为上述模块键。`events` 每项含 `at,title,detail,state`，无真实时间则不伪造。

`GET /api/center/session` 返回 `{authenticated:false}` 或 `{authenticated:true,csrf:"..."}`，不返回管理密钥。登录和退出沿用 `/api/local/login`、`/api/local/logout`，Cookie 路径支持 `/api`。

需登录、同源和 CSRF 的操作：

- `POST /api/center/select`：`{group,choice,expected}`，先核对当前值仍等于 expected，验证 choice 为实际成员；只能选择，不修改组定义。冲突返回 409。
- `POST /api/center/node-test`：`{provider,name}`，只测真实 provider 节点，不切换任何组；返回真实毫秒值和结果。
- `POST /api/center/backup`：`{}`，创建中心数据/配置备份任务，返回 `202 {job_id,state}`；不创建路由器备份，不暗示整机灾备。
- `GET /api/center/jobs/<id>`：任务状态与阶段；完成后才给出下载地址。
- `GET /api/center/backups/<id>/download`：需有效管理会话，备份含敏感信息，不能匿名下载。

原 `/api/local/status / preview / publish` 继续服务自建节点管理，不用新代码绕过既有解析、发布或校验。页面中的刷新只更新观测数据，不触发节点发布或清空 DNS。

### 统一管理快照与任务

`GET /api/center/manage/snapshot` 返回 `schema:2`、全局 `revision`、`updated_at`及 `modules.subscriptions/nodes/dns/monitors`。每个模块必须带 `state`、`revision`和 `capabilities.actions`；未接入时明确返回 `state:unsupported`。`capabilities.action_meta[action]` 可声明 `write/scope/timeout_seconds/sensitive_input/sensitive_fields`，`unavailable_actions` 返回稳定原因。动作名必须原样使用，前端不猜测、不去前缀、不生成假按钮；敏感字段不进入页面任务上下文。

`POST /api/center/operations` 请求为 `{module,action,expected_revision,params}`，返回 `202 {job_id,state:"pending",stage:"queued"}`。页面通过 `GET /api/center/jobs/<id>` 显示排队、执行、读回、成功、异常或冲突。`409` 绝不覆盖新状态，表单草稿也不会因轮询或失败被清空。

### 模块约束

- **订阅**：显示“发现→解析→准入→发布→Clash加载”五阶段。准入只展示解析、候选、已检测、准入的原始计数和下次检测时间，不从数量推导虚假百分比。受管来源的新增、编辑、停用、启用和删除分别使用 `subscriptions.source.*`；显式 legacy Provider 受保护，页面不显示误导性写按钮。订阅 URL 用密码式输入，仅写入 0600 私有覆写，提交后立即清空，不回显、不进 job/audit/toast。未准入 Candidate 仅在私有缓存与 loopback 独立内核中检测，不加载生产 Clash，不在 GLOBAL 或策略选项中可见。只有准入后才进入正式 `Managed_Auto`。
  - 当 `reconcile.journal.state="publishing"` 时，统一页必须以 `role="alert"` 显示发布中维护约束：等待发布完成，且只使用 249 统一入口操作；不得同时在 OpenClash/Mihomo 面板直接切换策略组。`selection_consistency.direct_openclash_change_during_publish="detected_and_rolled_back"` 表示后端检测到并发变更时中止接受，并尝试安全回退；CAS 或并发所有权保护可能拒绝覆盖新状态，最终结果以发布记录为准。该保护不替代前端维护约束；警告只由真实 journal 状态触发，发布结束后随快照消失。
- **DNS**：上游、本地记录与重写先进草稿，操作格式固定为 `{kind:"upstream|host|rewrite",action:"add|update|delete|enable|disable",id,...}`，创建草稿同时传入模块 `expected_revision`。通过预览、语法/外部校验和运行读回后才应用，应用与回退也使用当前 revision 防止覆盖新变更。首次 `migration_required` 时，页面只在用户确认后创建 `{kind:"migration",action:"adopt"}` 影响草稿，不立即覆盖 Corefile。
- **DNS 诊断**：容器/解析器视角与浏览器视角分开；普通 query/diagnose 不接受 browser 视角，resolver 诊断必须给出解析器，CNAME 查询无显式解析器时使用当前 CoreDNS `127.0.0.1:53`。浏览器检测由服务端生成受限随机探测计划，必须严格验证 1–64 条 URL 全部属于 `https://*.t.dnsleak.dev` 后才全部触发，不静默截断；共享 AbortController 在 5 秒硬截止，再按计划时间读取结果。官方 readout 查询数少于计划探针数时保持 unknown，不标记通过。IPLeak、BrowserLeaks 和 DNSLeakTest 保持人工对照；未知、超时或单站失败不标记为通过。
- **Kuma**：通知 URL、header、body、Basic Auth 和 Bearer Token 不回显。编辑时敏感字段留空表示保留原值，本页不使用隐式清除；包含 `[hidden]`、`[redacted]` 或 URL 编码占位符的目标不会写回。所属组、通知绑定、描述和 DNS 解析器属于非秘密字段，编辑时可以显式清空，并分别提交 `parent:null`、`notificationIDList:{}`、`description:""`、`dns_resolve_server:""`。脱敏详情读取完成前禁用保存，避免列表摘要覆盖完整配置。Kuma 2.5.6 没有可验证的通用“立即测试监控”接口，因此不显示该按钮；Webhook 通知的受控测试仍按 capability 显示。

## 前端交互与可访问性契约

- 导航及主要操作可键盘到达，焦点环不被去除；粗指针与小屏控件的最小高度为 44px。
- 390×844 使用同一份 DOM 和数据，不起第二套假移动页；表格可水平滚动，表单收为单列，主要操作不被遮挡。
- 常态 30 秒轮询和采集中的有界短轮询只更新证据，焦点位于草稿表单时不重建该页；输入值同步到内存草稿，409、后端异常和读回失败均不清空。
- 无证据时使用“未知”、“未返回”或“当前版本未接入”，不计算成功率、不用绿色能力标签暗示检测已通过。

## 实施边界

已有后端为 Python 原生 HTTP 与无构建依赖的 HTML/JS，本次延续此架构，静态资源随镜像发布，不依赖外部 CDN。保留现有认证和真实接口；不在前端或镜像写入生产密码、Token、节点密钥。新的统一入口通过环境开关启用，关闭后可恢复原页面。

隔离测试不得修改生产 DNS、业务选择、节点拉取地址或生产数据。生产上线由主代理统一执行，必须备份、独立回退守卫、比较运行基线。新镜像先在独立数据副本和测试端口验收，确认后再安排生产切换。
