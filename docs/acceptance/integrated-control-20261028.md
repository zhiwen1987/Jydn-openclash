# 进源 Clash Center 完整接管：隔离与生产验收门槛

> 2026-10-28 交接说明：本文包含 0.3 开发设计/验收计划，不代表生产已切换；生产仍为 0.2.0。实际状态见 [AI 交接入口](../../AI_HANDOFF.md)。

本文是 `0.3` 完整接管改造的执行门槛，不是完成声明。只有每项取得可复核证据、P0/P1 均为 0，才允许生产切换。单元测试、容器 `healthy`、页面能打开或第三方网站显示绿色，均不能单独替代业务验收。

## 1. 验收原则

- 隔离环境使用生产数据的受限副本或脱敏 fixture，不连接生产写接口，不发布生产 provider，不修改生产 DNS 和选择。
- 生产只做备份、身份核对、切换及非破坏性读回；故障注入、删除、回退演练全部在隔离环境完成。
- 每个结论包含测量视角、时间、新鲜度和证据。无证据为 `unknown`，过期为 `stale`，不能补成成功。
- 进程健康、DNS 查询、Clash 加载、节点联网和真实业务能力是不同层级，分别验收。
- 性能门槛先测当前 `0.2` 基线，再比较相同主机、数据和请求负载下的新版本。拒绝用无测量来源的固定“99%”代替验收。
- 第三方 DNS 泄漏站点各自独立；站点不可用、限流或格式变化不影响本地诊断，也不能被多数投票隐藏。

## 2. 必须保护的生产状态

切换前后分别获取散列和语义快照。下列任意非预期变化都是 P0：

| 保护对象 | 比较方式 |
|---|---|
| OpenClash 源配置、运行配置、UCI 配置 | 完整字节 SHA-256 |
| CoreDNS Corefile、hosts 及当前 DNS 运行配置 | 完整字节 SHA-256；DNS 页面只读不产生迁移 |
| 原两家 provider URL、Token 归属和 provider ID | URL 只比较脱敏身份散列；ID 与数量逐项比较 |
| 当前业务选择 | 排除技术探针组后，84 个 Selector 名和值逐项比较 |
| 运行规则和 Clash 内核 | 规则字段逐项比较；PID 与启动时间比较 |
| Kuma 数据和通知设置 | SQLite 在线备份、完整性和逻辑表指纹 |
| 其他容器 | 容器 ID、镜像、挂载、端口、运行/重启状态比较 |

`monitoring/lan-center/acceptance/protected_state.py` 只记录名称、长度和 SHA-256，不复制或输出文件内容。对 provider URL 身份、业务选择等 JSON 语义对象，用 spec 中的 `json_values[].pointers` 精确选取后只保存规范化散列；不把 URL、Token 或选择值写入报告。敏感状态和备份只保存在生产主机权限为 `0700/0600` 的事务目录，不能进入 Git。

## 3. 可执行验收矩阵

### 3.1 统一登录、控制与同步

| 编号 | 场景 | 合格标准 |
|---|---|---|
| AUTH-01 | 未登录读取管理快照 | `401 login_required`，不返回模块数据 |
| AUTH-02 | 错误 Origin、Content-Type、Cookie、CSRF | 分别拒绝，写模块未被调用，无状态变化 |
| AUTH-03 | 唯一中心登录 | 订阅、节点、DNS、监控均使用同一中心会话；浏览器不获得后台管理密钥 |
| CTRL-01 | 两个并发操作者使用同一 revision | 仅一个可进入事务；另一个 `409 operation_revision_conflict` |
| CTRL-02 | 队列满、任务中断、容器重启 | 有界队列返回 `429`；中断任务恢复为明确 error，不永久显示 running |
| CTRL-03 | 外部修改 Clash/DNS/Kuma | 中心识别 revision 变化并显示冲突，不静默覆盖 |
| CTRL-04 | 单个模块读取失败 | 其他模块继续显示真实状态；整体提示部分异常 |
| CTRL-05 | 审计 | 记录操作者会话指纹、对象、前后 revision、结果及时间，不记录 Token/密码/完整订阅 URL |
| CTRL-06 | 路由事务 apply 后端故障 | 中心已提交但路由 API 失败时，Guard 持续存活并重试补偿；不先停 Guard 再留下 `rollback_api_pending` |
| CTRL-07 | Guard 与 operations.lock 竞争 | 守卫在截止时间内有界重试；不因一次非阻塞锁失败永久退出，也不因无限阻塞锁越过回退窗口 |
| CTRL-08 | prepared/Guard init 中断 | 任一写入点中断后可判定所有权并撤销；无残留事务或无主守卫 |
| CTRL-09 | pending 重试前外部选择变化 | 每次重试重新检查当前选择/依赖；不绕过 Managed 节点直选阻断，不覆盖操作者新选择 |
| CTRL-10 | 公开 snapshot/job/audit | 不包含请求 `params`、完整订阅/节点 URL、URL query/credentials；不依赖通用 token 正则，按模块公开 schema 白名单验证 |

统一后端快照应为 schema 2，包含 `subscriptions/nodes/dns/monitors` 四模块，各模块必须给出真实 revision、状态和实际支持的 actions。没有后端动作的 UI 不得渲染为可用按钮。

### 3.2 订阅生命周期和 Clash 加载

| 编号 | 场景 | 合格标准 |
|---|---|---|
| SUB-01 | 现有两家 + 第三家 | 第三家从信息清单进入候选解析；原两家 ID、URL 身份和已接受节点不变 |
| SUB-02 | 第三家解析 | 协议、名称、重复项、非法字段逐项校验；原始凭据不出现在日志/API/UI |
| SUB-03 | 私有候选隔离 | 候选仅在 `admission_queue` 私有缓存和 loopback 独立检测 core 中；候选名称/数量/来源身份精确一致，且生产 `/providers/proxies`、`/proxies`、`GLOBAL` 都不得出现未准入节点或 `Managed_Candidate` |
| SUB-04 | 检测与准入 | 独立 core 执行真实联网/能力门槛；仅通过的节点进入生产 `Managed_Auto`，延迟成功不冒充业务可用 |
| SUB-05 | 发布接受 | manifest、provider 文件、Clash 读回的来源、节点名称和数量完全一致，才显示已加载 |
| SUB-06 | 单来源解析/检测/拉取失败 | 该来源记录失败和下次复测，其他来源及当前 accepted pointer 不变 |
| SUB-07 | 一次失败与恢复 | 确认失败后冷却 1 小时；到期复测成功可重新准入，不永久排除，也不频繁抖动 |
| SUB-08 | 新增 N 个来源 | 1、3、32、允许上限及超限边界；无硬编码第三家，幂等且重启恢复 |
| SUB-09 | 删除未使用来源 | 先从候选停止更新，成功发布不再引用后才清理；其他来源不变 |
| SUB-10 | 删除被当前选择/策略组引用来源 | 状态为待退役，列出依赖，拒绝破坏性清理，业务选择不变 |
| SUB-11 | 候选 smoke 失败/Clash refresh 失败 | 自动恢复上一个 accepted release，文件和运行 provider 读回一致 |
| SUB-12 | 订阅更新后重启 | 来源名、用量、candidate/approved 数量、accepted pointer 及冷却状态恢复 |
| SUB-13 | CRUD override 与 reconcile trigger | override 提交和触发状态一致；trigger 失败时要么回滚 override，要么明确返回“已提交，降级为定时同步”，不得显示全失败但之后偷偷生效 |
| SUB-14 | 私有准入结果到期 | 新节点或冷却恢复准入后有界唤醒 publisher；不因两套调度相位叠加额外等待近 1–2 小时 |
| SUB-15 | 禁用来源更新语义 | 更新名称/URL 不隐式启用已禁用来源，除非界面明确要求并二次确认 |
| SUB-16 | 受管 provider 身份冲突 | `Managed_Auto` 与旧 provider ID/名称冲突时启动/发布拒绝，不覆盖原 provider |
| SUB-17 | 恶意/异常显示名 | 订阅名和节点名可按文本显示，`<img onerror>` 等不会生成 DOM 或执行；渲染不使用 `innerHTML` |
| SUB-18 | PENDING 恢复与 CURRENT 分叉 | 分别演练 CURRENT=候选、CURRENT=前版、CURRENT=更新外部 pointer；只恢复自己拥有的分支，绝不覆盖更新 pointer，journal 读回可判定 |
| SUB-19 | N 来源公平调度 | 显式/受管来源均用持久 cursor 轮转；前方慢源或持续失败不饿死后续来源，超时返回后无 late write |
| SUB-20 | 多来源 admission 公平性 | 每源至少获得一个有界 slice，持久 source cursor 重启后继续；`published/queued/cooling/due` 分别计数，不用旧发布数冒充本轮已检测 |
| SUB-21 | finalize 前选择漂移 | 网络检查和依赖快照在全局锁外有界执行；final pointer/probation 提交前再次校验选择，PENDING 保留到 post-check 结束 |
| SUB-22 | UI 发布 journal | 界面区分 pending/recovery/probation/已接受/失败，并显示新鲜度；不将 pointer 存在直接标为发布完成 |
| SUB-23 | CRUD revision 稳定性 | 只有 registry/override/current pointer/serving manifest 身份等真实配置变化使 add/update 的 CAS 失效；health epoch、检测进度和 heartbeat 更新不产生 409 循环，页面轮询不丢表单草稿 |

第三家真实验收必须保存脱敏的五段证据：发现、解析、私有隔离检测、`Managed_Auto` 发布、生产 Clash 加载。还必须保存一份否定证据：所有未准入候选在生产代理清单、provider 和 `GLOBAL` 中都不存在。只看信息来源数量、文件存在或 HTTP 200 均不合格。

### 3.3 节点和策略管理

| 编号 | 场景 | 合格标准 |
|---|---|---|
| NODE-01 | 节点清单 | 来源、协议、状态、延迟种类、业务能力、检查时间、下次复测均来自真实接口 |
| NODE-02 | 单测/批测 | 有界并发与超时；批测不改变业务选择；单节点失败不取消其他结果 |
| NODE-03 | 人工切换 | expected revision 校验、成员校验、执行后读回；409 不覆盖用户新选择 |
| NODE-04 | 人工固定/严格出口 | 只有存在实际持久化和控制器尊重机制才显示可用；严格出口失效按契约阻断 |
| NODE-05 | 外部原生面板修改 | 中心在新鲜度窗口内识别并显示，不被轮询悄悄改回 |
| NODE-06 | 节点名相同但来源不同 | 使用稳定来源身份区分，不能按显示名称错误合并 |

### 3.4 DNS 管理、污染和泄漏检测

| 编号 | 场景 | 合格标准 |
|---|---|---|
| DNS-01 | 首次打开 DNS 页面 | 只读；没有受管块时显示 unmanaged，不改 Corefile |
| DNS-02 | 上游/host/rewrite CRUD | 先创建草稿，验证地址、域名、DoT SNI、引用和 CoreDNS 临时配置；预览影响后才能应用 |
| DNS-03 | 删除被引用对象/最后可用上游 | 显示引用并拒绝普通删除；不能生成不可启动配置 |
| DNS-04 | revision 冲突 | 基线字节变化后拒绝应用，保留外部修改 |
| DNS-05 | reload/readback 失败 | 原子恢复配置、重新加载并读回旧状态；失败不显示已应用 |
| DNS-06 | A/AAAA、UDP/TCP、CNAME、NXDOMAIN、SERVFAIL、timeout | 每阶段单独报告，IPv4/IPv6 不互相掩盖 |
| DNS-07 | Fake-IP、hosts、过滤与 CDN | 先按当前策略解释预期差异，不把合理差异判为污染 |
| DNS-08 | DNSSEC | 仅在实际验证链证据存在时显示通过/失败；DO/AD 位或请求 DNSSEC 记录不冒充验证 |
| DNS-09 | DNS/连接/TLS/HTTP | 分阶段判断；解析正常但 TLS/业务失败不能标记 DNS 污染 |
| DNS-10 | 容器、指定 resolver、浏览器视角 | 明确 evidence_scope；容器结果不能冒充终端或全网结果 |
| DNS-11 | dnsleak.dev/IPLeak | 使用已核验公开协议；随机会话、过期清理、限流和单站超时 |
| DNS-12 | BrowserLeaks/DNSLeakTest | 无稳定授权 API 时仅人工对照，不能显示自动通过 |
| DNS-13 | 第三方结果冲突 | 展示各站证据和 unknown/anomaly，不用简单多数投票生成安全结论 |
| DNS-14 | 隐私 | 随机测试域名，不上传真实浏览历史、内部域名、订阅或凭据 |
| DNS-15 | supervisor 在重启前拒绝 | budget/hash/expiry 等在停进程前拒绝时，管理器恢复文件并仅 probe；不伪造 recovery，不发起第二次 reload；只有已进入重启且后续 probe 失败才允许与原 request 绑定的 recovery |

### 3.5 Kuma 原生融合

| 编号 | 场景 | 合格标准 |
|---|---|---|
| MON-01 | 统一查看 | 从中心 API 返回监控、分组、heartbeat 与时间；进程健康和子监控失败分开 |
| MON-02 | 历史/分页 | 真实历史，有限分页和时间范围；大数据不阻塞总览 |
| MON-03 | 新建/编辑/暂停/恢复/删除 | 中心认证、CSRF、expected revision、Kuma 官方协议和操作后读回 |
| MON-04 | 删除被引用/分组监控 | 先显示影响并按 Kuma 约束拒绝或受控处理 |
| MON-05 | 通知渠道 | 只暴露实际支持的动作；密钥保持隐藏，测试通知结果可追溯 |
| MON-06 | Socket 断线/慢响应/格式变化 | 有界连接、超时和重连；标记 stale/unsupported，不直接改 SQLite 冒充成功 |
| MON-07 | 重启恢复 | 监控、分组、通知、中心映射和 revision 恢复，后台认证未被关闭或重置 |
| MON-08 | 单一入口 | 宿主 `3101/tcp` 不可连接，Docker inspect/Compose 无 published 3101；Kuma `3001` 仅容器内桥接 |
| MON-09 | 无 Kuma 二次登录/无 Kuma 嵌套面板 | 统一中心登录后直接返回原生列表、CRUD、启停、历史和通知；无 Kuma iframe、无 Kuma 登录页、无公开 GUI 反代 |
| MON-10 | 生产数据保持 | 切换前后均为 22 个监控、1 个 webhook 通知；字段指纹不变，且中心容器重启后读回一致 |
| MON-11 | 脱敏目标编辑语义 | 包含 query/header/凭据的 URL 不回显、不进入 job/audit；留空表示保留原值，“明确清空”使用单独意图并读回，不将脱敏占位或空串意外覆盖生产目标 |

### 3.6 UI、性能和资源

目标流程：`登录 → 总览 → 订阅新增/退役预览 → 节点筛选与检测 → DNS 草稿/诊断 → 监控编辑 → 活动与恢复证据`。

| 编号 | 场景 | 合格标准 |
|---|---|---|
| UI-01 | 页面身份和首屏 | 正确 Logo/名称、非空、无框架错误覆盖层、无 relevant console error |
| UI-02 | 桌面/手机 | 1478×1066、390×844 无文档横向滚动、遮挡或触控目标过小 |
| UI-03 | 键盘和表单 | 可见 focus、标签明确、错误靠近字段；轮询不丢草稿、焦点和筛选 |
| UI-04 | 状态语义 | 颜色 + 文本 + 图标，unknown/stale/error 不显示绿色成功 |
| UI-05 | 写操作反馈 | 影响预览、执行中、读回结果；409 不覆盖表单；失败给出证据和恢复入口 |
| UI-06 | 无假操作 | capability 未返回动作时按钮不存在或明确 unsupported，不能点后才伪装失败 |
| PERF-01 | 快照缓存 | 热缓存顺序和 4 并发测量无错误；P95 与 0.2 基线比较 |
| PERF-02 | 慢模块 | DNS 泄漏/Kuma 历史/节点批测异步或独立缓存，不拖慢总览和选择读回 |
| PERF-03 | 资源 | 同样数据下比较 CPU、RSS、线程/进程、磁盘写、镜像总大小与增量，差异有解释 |
| PERF-04 | 长时间运行 | 隔离环境持续观察任务数、内存、SQLite、日志和重启次数，不出现无界增长 |
| PERF-05 | 总览 fan-out 硬时限 | 在整套测试和并发负载下仍不越过配置 deadline；超时模块明确为 timeout，不等待遗留 worker，不用单测单独偶然通过代替满负载复测 |

## 4. 性能测量方法

2026-10-28 的 `0.2` 初步基线（仅瞬时样本，不是长期容量结论）：同主机 `/overview` 8 次为 `677.76, 12.59, 12.24, 12.05, 14.79, 12.27, 11.52, 11.67 ms`；首次冷请求与后续热请求必须分开记录。同时容器瞬时资源为 CPU `1.49%`、内存 `277.3 MiB / 640 MiB`、PIDs `47`。候选版必须在相同宿主、数据和并发度下复测，并单独记录新常驻 worker/Socket 的内存增量。

1. 在相同 249 宿主、同一份只读数据副本、无其他构建任务时，分别运行 `0.2` 与候选镜像。
2. 预热 5 次；顺序 20 次、4 并发共 12 次读取统一快照，记录 median、P95、并发 P95、最大响应字节及错误数。
3. 候选必须零错误；P95 不超过基线的 130%，且额外延迟不超过门槛计算中的较宽者；响应体不超过基线 125% 或多 16 KiB 的较宽者。若基线本身异常，应先排除宿主抖动再比较。
4. 总览、选择读回另做同样测量。慢诊断采用异步 job，只测提交延迟、完成时间和并发上限，不把外部站点耗时计入总览预算。
5. 记录主机 CPU/磁盘抖动、容器 CPU/RSS/PID、其他容器状态，避免把宿主异常误判成代码回归。

HTTP 探针命令示例（Cookie 与 CSRF 只通过进程环境注入，报告不包含它们）：

```powershell
$env:CENTER_ACCEPTANCE_COOKIE = '<临时隔离会话 Cookie>'
$env:CENTER_ACCEPTANCE_CSRF = '<临时隔离 CSRF>'
python monitoring/lan-center/acceptance/acceptance.py `
  --base-url http://127.0.0.1:测试端口 `
  --report D:\验收证据\candidate.json `
  --baseline D:\验收证据\baseline.json `
  --allow-isolated-contract-writes
```

生产候选门槛还应加入（数值依当次同主机基线确定）：

```powershell
python monitoring/lan-center/acceptance/acceptance.py `
  --base-url http://127.0.0.1:隔离端口 `
  --report D:\验收证据\candidate.json `
  --baseline D:\验收证据\baseline.json `
  --require-complete `
  --expected-monitor-count 22 `
  --expected-notification-count 1 `
  --forbid-host-port 127.0.0.1:3101 `
  --require-candidate-isolation `
  --run-subscription-validation `
  --required-action monitors=monitor_create `
  --required-action monitors=monitor_pause `
  --required-action monitors=monitor_resume `
  --required-action monitors=notification_test
```

`--forbid-host-port` 只验证当前网络命名空间的 TCP 不可达，还必须保存 Docker inspect/Compose 证据，确认没有任何 host 3101 published 映射。

默认不带 `--allow-isolated-contract-writes` 时只读，可用于生产复核。该开关在 overview 报告 production 时会主动拒绝写契约测试。

### 4.1 真实镜像隔离启动器

`monitoring/lan-center/acceptance/isolated_lab.py` 只读取操作员预先复制的私有快照，不连接生产、不发布宿主机端口，也不把凭据写入报告。私有输入必须为独立目录（Linux 上目录 `0700`、文件 `0600`），布局可用下列命令查看：

```bash
python3 monitoring/lan-center/acceptance/isolated_lab.py layout
```

最小输入包括：

- `private.env`：`OPENCLASH_SECRET`、`SUBSCRIPTION_PUBLISH_TOKEN`、`SUBSCRIPTION_HMAC_KEY`；禁止提交 Git 或复制进验收报告。
- `control/unified/kuma-bridge.jwt`、`control/local-source/admin-token`、`control/subscription-controller/current.json` 及其引用的 release/state 文件；此目录映射容器 `/data`。
- `kuma/kuma.db` 及独立 Kuma 数据卷中的其他文件；此目录单独映射 `/app/data`，不得与 `/data` 合并。
- `coredns/Corefile`、`Corefile.managed`、`hosts`；隔离副本的全部 `forward .` 必须只指向 `127.0.0.1:1153`。
- `router/runtime.yaml`、`provider-map.json`、`providers/*`；可选 `selector-state.json`。运行配置只取拓扑和 profile，规则固定为 `MATCH,DIRECT`，因此不能冒充生产 144 条规则等价验收。

镜像必须使用不可变 `sha256` ID 或仓库 digest。推荐执行顺序：

```bash
python3 monitoring/lan-center/acceptance/isolated_lab.py prepare \
  --input /root/private/clash-center-lab-input \
  --output /root/private/clash-center-lab-bundle \
  --image sha256:<64位镜像ID>
python3 monitoring/lan-center/acceptance/isolated_lab.py boot \
  --bundle /root/private/clash-center-lab-bundle
python3 monitoring/lan-center/acceptance/isolated_lab.py verify \
  --bundle /root/private/clash-center-lab-bundle
python3 monitoring/lan-center/acceptance/isolated_lab.py destroy \
  --bundle /root/private/clash-center-lab-bundle --remove-network
```

启动器建立 Docker `--internal` 网络且无 host published port，并限制为 `0.7 CPU / 768 MiB / 192 PIDs`，运行真实镜像内 CoreDNS、Kuma、统一中心和真实 Mihomo core；候选节点不会写入生产内核，`Managed_Candidate` 出现即拒绝。DNS 上游只复用不可变镜像内 `passive_control.py` 唯一启动的 fixture，不另起冲突进程，并严格验证 UDP/TCP 均为 `NOERROR` 且唯一 A 记录是文档保留地址 `192.0.2.1`。这只是隔离 stub 身份证据，不能冒充真实 DNS 解析。验证还包括真实 CoreDNS 子进程 UDP/TCP、Kuma 2.5.6 的 22 个监控与 1 个通知摘要、统一登录 HTTP 契约、Candidate 隔离和缓存性能。`control`、`kuma` 与生成 bundle 必须继续按私有证据管理，销毁容器后默认保留以便复核。

该启动器明确不证明：生产完整规则等价、真实互联网业务健康、真实第三家订阅解析/检测/发布/加载，以及浏览器桌面/移动端渲染。它们仍是后续独立门槛；不得用“进程存活”替代。

## 5. 分层执行顺序

1. 源码：编译、单元、fixture、JS 语法、敏感值扫描。
2. 协议：真实 HTTP 生命周期、统一登录、CSRF、冲突、队列、任务恢复、Socket.IO 双向帧。
3. 隔离镜像：真实镜像启动、DNS UDP/TCP、Kuma、订阅候选/发布/回退、重启恢复。
4. 浏览器：桌面和手机全部页面、目标交互、console、网络失败、轮询保持。
5. 数据：第三家真实解析/检测/发布/加载，模拟新增 N 和依赖退役。
6. 恢复：镜像回退、配置 CAS、损坏备份拒绝、并发漂移拒绝。
7. 生产准备：两端备份、身份与磁盘空间、独立限时回退守卫、保护状态基线。
8. 生产切换：只重建中心服务，立即验证 DNS/Kuma/中心/Clash、保护项和其他容器。
9. 接受：真实业务抽样、观察窗口、停止临时守卫、保留人工回退；同步 GitHub、文档和脱敏证据。

## 6. 缺陷等级与上线条件

- P0：认证绕过、凭据泄露、数据丢失、回退不可用、DNS/分流/选择被非预期修改、假成功、其他生产业务受影响。必须为 0。
- P1：核心 CRUD/同步/检测不可用，状态误导，单模块故障拖垮全局，明显性能回归，桌面或手机关键流程失败。必须为 0。
- P2：不影响正确性和恢复的易用性或视觉改进。可以记录，但必须说明范围和后续处理。

生产接受不是“所有互联网业务永久正常”。最终报告应分别列出：实现并通过、隔离通过、生产读回通过、真实业务待用户确认、已知外部告警与未覆盖范围。

## 7. 当前证据状态（不是最终上线声明）

- 统一中心最新源码全量：`90` 项执行通过，`1` 项仅因默认未启用 Linux 真实 CoreDNS 环境门槛而跳过。
- 该 Linux 门槛已在相同审计镜像中显式启用并独立执行：真实临时 CoreDNS `ready`、UDP/TCP 查询和进程清理共 `5/5` 通过，耗时 `1.819 s`；私有脱敏证据为 `integrated-control-1793135265/real-dns-validator.json`。首次 `EPERM` 已确认为容器 capability 环境分类 `coredns_execution_denied`，随后用 `cap-drop ALL + NET_BIND_SERVICE` 重跑通过，不能记为二进制缺失。
- 本文隔离启动器及通用 HTTP 验收辅助测试目前 `17/17` 通过，Python 编译和 diff whitespace 检查通过。
- 上述 DNS 证据使用独立 NXDOMAIN baseline；镜像 passive fixture 则返回 `NOERROR + 192.0.2.1`。二者用途不同，不得合并为同一证明。
- 这些证据仍需在最终唯一镜像 hash 上复跑；真实第三家订阅当前外部返回 `502`，因此第三家解析、两次隔离准入、发布和 Clash 加载仍未通过，不能写成已上线。
