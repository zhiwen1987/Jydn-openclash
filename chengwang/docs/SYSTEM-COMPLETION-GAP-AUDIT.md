# 澄网系统完成度与闭环差距审计

2026-10-26 阅读更新：当前执行索引以 [任务清单](LIVE-TASKS.md) 和 [SYS-06 实施记录](SYS06-MIHOMO-LIFECYCLE-IMPLEMENTATION.md) 为准。固定双配置正常发布、UNKNOWN 不重发、持久 S2 及首次真实 Completion 四模式已有精确提交的限定隔离验收。最新接受 `4bbbe70` 的 Completion CI `40226840814` 及9 ZIP／167成员独立复算通过；此前失败保持。后续 v4 的首轮提交 `a9774e5` 已真实失败：foundation 名称摘要错误在 Go 前阻断，独立 full Go 编译又发现缺 collector 构造函数；最小修正已合入待重验，空结构 pin 保持 fail closed。产品恢复 API、恢复后普通发布和第二恢复仍未验收。后续进展不能反推下文 2026-10-18 的历史审计已完成，也不证明完整系统或生产上线。本轮未操作生产、main 或 Registry。

2026-10-24阅读补充：本页主体仍是2026-10-18历史审计。当前执行索引为[任务台账](LIVE-TASKS.md)，开发源码5f17544的[能力状态纠正](P2-CAPABILITY-TRUTH.md)已有260前端／2670父门实际证据，但镜像lint和探针仍失败，整轮未通过；后续[快照解码与诊断修正](P2-SNAPSHOT-WIRE-VALIDATION.md)尚待新CI。不能把本地配置清单更新当部署或运行健康。订阅局部实现、主动探针只读底座及其隔离证据已有后续进展，广义自动编排、生产数据面与企业系统仍未闭环。下文历史“当前”仅指其审计日期，不代表现在全部源码或设备实时状态。

阅读边界（2026-10-23）：下文是 2026-10-18 的历史审计，不能直接当作当前全部模块的实时状态。主动探针的安全只读 API、后台缓存和控制台接线此后已有[基础隔离验收](P1-PROBE-READBACK-ACCEPTANCE.md)；新的真实 agent→只读 API 实验见[分层实验说明](../deploy/probe-readback/README.md)，是否通过以确切提交的原始 CI 与独立重放为准。基础接线、实验、正常 TLS 浏览器闭环、真实互联网与生产上线是不同证据等级，不因其中一项通过而自动提升其他项。机器能力清单中的旧主动探针描述尚需单独同步验收，本页不将它冒充当前运行态事实；其余企业功能也没有因本说明而自动完成。

## 1. 审计结论

审计日期：2026-10-18（Asia/Shanghai）

当前源码已经具备一个安全边界较清楚的 **Shadow 控制面基础版**，但尚不是完整的企业网络自治系统，也不具备生产流量接管、自动发布或自动修复闭环。现阶段可以确认的能力集中在本地领域模型、策略校验、Mihomo 兼容片段生成、本地版本存储、代理接口模型校验、Web 控制台、Mihomo Controller 只读状态读取与有限字段读回对账，以及静态身份认证、范围授权、耐久操作记录和本地证据协调。

必须把两条事实线分开：身份、operation schema v2、控制服务和 Shadow operations API 已于 2026-10-18 部署到 `10.88.0.254`，但生产未配置身份文件，`CHENGWANG_OPERATION_WRITES_ENABLED=false`，也没有设备执行器。因此生产只验证了默认锁定和失败关闭边界，未验证真实身份操作，更没有形成生产写入闭环。

当前最重要的事实边界如下：

- “控制面存活”不等于 DNS、互联网、代理节点或真实业务可用。
- “编译成功”只代表生成了 Mihomo 兼容片段，不代表形成了可启动的完整配置。
- “读回一致”只覆盖当前实现的策略组成员和部分域名规则，不代表规则顺序、DNS、出口、TLS、账号能力或稳定性正确。
- `POST /api/v1/publish` 当前只写入本地版本库；它不下发路由器、不重载 Mihomo，也不形成生产发布闭环。
- `/api/v1/operations` 当前源码只记录本地 Shadow 计划、审批和预检；默认锁定，且明确没有设备执行器。
- `snapshot` 明确标记 `dataSource=demo`，其中的业务、节点池和事件不能作为运行态证据。
- 部署记录证明 2026-10-18 完成了 Mihomo 只读、证据完整性和默认锁定 Shadow 操作控制面的生产读回；它是一次发布证据，不是持续可用性证明。
- 文档中的自治、DNS、订阅、多内核、反向代理、隧道、多租户、HA、灾备和 AI 能力大部分仍是设计基线。

因此，当前合理结论是：**基础架构与只读对账闭环部分成立，生产写入闭环、业务可用性闭环和企业治理闭环均未成立。** 不应宣称系统已经“100%完成”或达到任何多位数可用率目标。

## 2. 审计依据与证据等级

本次审计核对了：

- `README.md`、架构边界、功能基线、自治运维、企业闭环、交互规格与部署记录。
- `cmd/server`、`internal` 下的 Go 实现及单元测试。
- `web` 下的 React 界面、API 客户端和界面测试。
- Dockerfile、Compose、安全运行边界和恢复说明。
- 本地执行 `go test -count=1 ./...` 与 `go vet ./...`，审计时全部通过。
- 本地执行前端 `npm test -- --run`（20/20）、`npm run lint` 和 `npm run build`，审计时全部通过。

证据等级定义：

| 状态 | 定义 |
| --- | --- |
| `implemented+tested` | 代码已存在，并有本地自动测试覆盖主要成功或失败路径；不自动等同于生产可用。 |
| `implemented-local-only` | 本地代码或界面存在，但未接入真实数据面，或只有演示/草稿语义。 |
| `read-only production evidence` | 部署记录显示曾从生产目标只读取得真实证据；不会修改生产。 |
| `design-only` | 仅有文档、静态页面、能力描述或接口设想，没有可执行闭环。 |
| `blocked` | 需要尚未提供的外部依赖、隔离验收环境、身份源、独立探针、第二故障域或明确生产授权。 |

## 3. 当前能力清单

| 能力 | 当前状态 | 已有证据 | 尚缺边界 |
| --- | --- | --- | --- |
| 控制面 HTTP 服务与静态前端 | `implemented+tested` | API、SPA fallback、安全响应头、SIGINT/SIGTERM 优雅关停测试与生产重启证据 | 尚无就绪/存活分离、完整依赖健康聚合和全局资源背压 |
| 领域模型 | `implemented+tested` | 策略、节点池、DNS、接口、版本等结构及调用测试 | 与企业基线中的租户、站点、设备、操作、证据对象仍相差较大 |
| 策略校验 | `implemented+tested` | ID、引用、空池、域名、部分 DNS 和切换参数测试 | 未覆盖规则冲突、遮蔽、不可达、回退有效性、IPv4/IPv6、DNS/出口一致性、跨内核语义损失 |
| Mihomo 兼容片段编译 | `implemented+tested` | 确定性输出测试 | 不是完整配置；无目标内核语法启动测试、版本兼容矩阵、rule-provider、DNS、代理源和凭据合并 |
| 可解释路由核心 | `implemented+tested` | 业务优先、国内直连、兜底、AND 条件测试 | 未与真实连接、DNS 或运行中规则联动；证据对象和规则优先级模型不完整 |
| 内核适配器注册表 | `implemented+tested` | 注册、重复拒绝、能力去重测试 | 没有可运行的 Mihomo 写适配器、sing-box 或 Xray 适配器实例 |
| 代理接口模型与校验 | `implemented+tested` | 端口冲突、LAN 认证、远程 API、TUN 约束测试 | 不会创建监听器、账号、ACL、防火墙或证书；界面保存仅限会话草稿 |
| 本地原子版本文件 | `implemented+tested` | 乐观锁与并发单赢家测试 | 无版本签名、读时摘要校验、跨文件事务、回滚 API、保留策略、备份恢复演练和租户隔离 |
| 能力真实性清单 | `implemented+tested` | 能力状态注册表及 API 测试 | 仍需作为发布门禁的机器可验证事实源，并与部署、探针、审计证据自动关联 |
| Mihomo Controller 只读适配器 | `implemented+tested` | 仅 GET、令牌、重定向禁止、响应上限、错误脱敏、对账测试 | 不覆盖规则优先级、provider、DNS、节点能力、连接或流量证据 |
| Mihomo 生产读回 | `read-only production evidence` | 部署记录中有版本、策略组、规则和浏览器读回证据 | 本次未重新在线验证；没有持续采集、签名证据、独立探针或告警 |
| Web 总览、业务和代理接口页面 | `implemented-local-only` | React 测试和明确 Shadow/演示边界 | 多个页面仍含静态能力矩阵或占位状态，不能作为运行态事实 |
| 本地策略发布 | `implemented-local-only` | 默认锁定、令牌、`If-Match`、原子存储测试 | 仅写本地版本；无真实身份、审批、审计主体、设备事务、读回、业务验证和回滚 |
| 本地静态身份认证 | `implemented+tested`，生产未配置 | 严格 Bearer 解析、重复头拒绝、SHA-256 摘要常数时间比较、禁用/生效/过期与文件权限测试；生产能力读回为 `blocked` | 不是密码系统、会话、MFA、SSO、热轮换或企业 IdP；尚未配置生产身份文件 |
| 范围授权与职责分离 | `implemented+tested`（源码） | 默认拒绝角色矩阵、租户/站点/对象/环境范围、高风险独立审批和 break-glass 边界测试 | 仅供本地控制服务使用；没有组织目录、策略管理后台或企业审批系统 |
| schema v2 耐久操作库 | `implemented+tested`，生产已加载空库 | 原子快照、重启恢复、幂等、发起人/审批人绑定、单写者锁、`Close()`、poison/commit-unknown 和迁移测试；生产权限与重启读回通过 | 单控制器；不是数据库/共识；schema v1 迁移为 `legacy_unbound` 后永久冻结；生产尚无真实操作 |
| Shadow 操作控制 API | `implemented+tested`，生产默认锁定 | Bearer、范围检查、写开关、幂等、前置/结果证据、错误码和设备执行阶段拒绝测试；生产无身份时返回 503 | 只允许本地计划/审批/预检记录；无设备执行器，生产写开关为 false |
| 本地证据协调强化 | `implemented+tested`，生产已部署 | `AppendOnce`、重启索引、单写者锁、截断/篡改/重复键、poison 与 `checkpoint_stale` 测试；生产重启后完整性通过 | 非 WORM、无独立副本；`checkpoint_stale` 需人工恢复；未审计全部 HTTP 请求 |
| Docker Shadow 部署 | `read-only production evidence` | 非 root、只读根文件系统、健康检查、备份和恢复说明；候选 Compose 已声明能力全丢弃及 CPU/内存/PID 限额 | 主机网络扩大可达面；新增资源限制尚待本轮候选与生产验证；缺少镜像签名/SBOM和持续恢复演练 |
| 订阅系统 | `design-only` | 功能和闭环文档 | 无抓取、自动识别、去重、隔离、签名/来源、转换、准入、回退 |
| DNS 数据面 | `design-only` | DNS 闭环与 DDI 设计 | 无 DNS 服务、策略执行、缓存、健康切换、DNSSEC、泄漏检测、出口一致性验证 |
| 持续被动观测 | `production-shadow-initial-gates-passed`，24 小时浸泡待签署 | Mihomo 周期只读、共享串行读取、有界摘要历史、TTL、时钟回拨、匿名聚合、受保护历史、生产备份与回滚验证 | 只证明 Controller 周期读回；尚无独立故障域或节点/业务主动探针，长期浸泡未完成 |
| 主动路径和真实业务探测 | `implemented+tested local-only`（M2b-0）；M2b-1 仅候选文件与静态校验 | 命令入口、严格许可目录、固定 DoT、全 CNAME 链与地址校验、固定 IP/SNI、HTTPS 分类、耐久启动账本、有界调度、独立 spool、严格进程健康、只读状态语义验证、归档前后复验、BLOCKED 宿主出口取证/双栈 bootstrap 计划、静态 canary 合同、供应链结构校验、恢复合同与安全本地证据落盘、已签署的 Linux root/ext4-XFS 静态 CI，以及默认关闭的隔离容器定义 | Linux 静态 CI 已签署但不等于容器运行态；无 API/控制面接入/获批且实测的 canary/真实密码学验签/Registry 读回/已证明唯一出口；`internal` 网络与真实出口合同未闭合；未完成 Docker 构建运行与真实掉电/宿主故障注入；M2b-2 仍为设计态，未访问公共业务、未验证单节点能力或生产路径 |
| 自动诊断和修复 | `design-only` | A0-A5、动作预算、监督器设计 | 无事件状态机、计划器、动作执行器、独立验证器、抑制和回滚执行链 |
| Mihomo 写入生命周期 | `design-only` | 架构与发布状态机 | 无备份、隔离启动、金丝雀、排空、写后读回、观察和自动回滚 |
| sing-box / Xray | `design-only` | 能力矩阵和注册接口 | 无真实适配器、编译器、进程管理、版本兼容与 E2E 测试 |
| 企业身份与多租户治理 | `implemented-local-only` | 本地静态身份、RBAC/范围授权和职责分离源码 | 无 IdP、会话、MFA、在线撤销、组织目录、租户数据隔离、双人工作流与企业紧急访问 |
| 操作记录与防篡改审计 | `implemented-local-only` | schema v2 操作快照、本地追加哈希链、幂等和控制服务；生产空库与锁文件已验收 | 非 WORM、无独立副本/可信时间/导出验签；非全请求审计；生产未配置身份且无真实操作 |
| HA / 灾备 / 独立监测 | `blocked` | 故障模型和恢复设计 | 目前只有单控制面和单路由器环境；缺少独立故障域、外部探针、恢复目标和演练基础设施 |

## 4. 已发现的真实性与闭环风险

### 4.1 界面和 API 可能被误读

- `snapshot` 虽然标记为演示数据，但 API 仍返回看似真实的业务状态、节点延迟和历史事件。任何新客户端都可能忽略 `dataSource` 后误用。
- 部分内核、协议和接口页面展示的是能力设想或影子配置，不是设备发现结果。
- `AuditEnabled=true` 只是接口模型字段，当前没有真实审计落库，不能显示为“已记录审计”。

修复原则：所有运行态字段必须携带 `source`、`observedAt`、`expiresAt`、`confidence` 和 `evidenceRef`；演示对象不得进入生产 API 默认响应。

### 4.2 当前发布不是发布闭环

本地策略发布只有旧管理员令牌、乐观锁和版本文件。新的 Shadow operation 路径虽已有静态身份、范围授权、幂等和证据协调，但它与 `publish` 仍是不同边界，且没有设备执行器、恢复点、适配器租约、设备读回、技术验证、业务验证、观察窗口和失败补偿。因此即使解除 `CHENGWANG_ALLOW_PUBLISH` 或 `CHENGWANG_OPERATION_WRITES_ENABLED`，也不能据此授权写现网。

### 4.3 版本库不是审计库或灾备库

当前版本对象有摘要，但读取时不验证摘要；版本文件和 `CURRENT` 指针是两次写入，没有事务日志。Evidence 虽有本地哈希链、checkpoint、幂等索引和单写者锁，仍没有密钥签名、WORM 或独立副本，主机管理员可以成套替换日志与 checkpoint。`checkpoint_stale` 有意失败关闭并要求人工取证恢复；不能自动提升额外尾部为已提交事实。上述实现足以作为单机基础原型，不足以承担企业审计或灾备真相源。

### 4.4 健康检查范围过窄

容器健康检查只证明 `/api/v1/health` 返回。它没有检查版本库读写、Mihomo 可读性、DNS、出口、真实业务、时间同步、磁盘空间、证据队列或审计链。因此不得把容器 `healthy` 汇总为“网络健康”。

### 4.5 测试主要是单元和同进程集成测试

当前缺少：真实 Mihomo 隔离启动、sing-box/Xray、DNS 服务、订阅恶意样本、跨设备发布、断电/磁盘满/时钟漂移/网络分区、长时间浸泡、性能容量、安全扫描、浏览器弱网和真实业务事务测试。

## 5. P0：任何生产写权限之前必须完成

P0 的含义是生产发布的不可绕过门槛，不代表完成后即可自动接管全网。

| P0 工作项 | 依赖 | 验收门 | 回滚/失败门 |
| --- | --- | --- | --- |
| 真实认证、RBAC/ABAC 和对象范围 | IdP 或本地离线身份源；密钥存储 | 未认证请求默认拒绝；viewer/operator/approver/auditor 权限矩阵全测；会话撤销、超时、MFA、租户范围通过 | 身份源异常时冻结所有写入，只保留最小只读和受控救援入口；不能自动降级为匿名管理员 |
| 追加式操作记录和防篡改审计 | 稳定身份 ID、可信时间、独立存储 | 每个读写请求、审批、发布阶段、回滚和导出均有 trace ID、actor、目标、前后版本、结果；哈希链与独立副本可验证 | 审计不可写、时钟异常或链断裂时阻止写操作；保留本地排队上限和人工恢复流程 |
| 期望/实际/观测三态存储 | 稳定对象 ID、证据模型 | 三态不混淆；字段级来源、时间、TTL、置信度可追溯；未知状态不得显示绿色 | 任一真相源不可用时停止协调，不用演示值或缓存值覆盖设备实际状态 |
| 操作状态机、幂等和单一写入者租约 | 持久任务库、分布式或设备级租约 | 重试、刷新、重复提交和控制器重启不重复执行；旧版本不能覆盖新版本；租约丢失立即停止扩大 | 租约、状态库或幂等记录不可确认时冻结写入；人工接管必须先终止自动租约并留下事件 |
| 订阅隔离准入 | 抓取器、解析沙箱、来源策略、密钥引用 | 支持 1/N 订阅自动识别、去重、稳定 ID、变更差异、恶意/超限输入隔离、上次有效版本回退 | 抓取或转换异常不得清空生产节点；新订阅默认隔离，失败时继续使用已验证版本 |
| 完整规则分析和编译门禁 | 统一规则 IR、目标内核版本矩阵 | 检出重复、冲突、遮蔽、不可达、空池、失效回退、循环、IPv4/IPv6 和 DNS/出口不一致；目标二进制真实语法检查 | 编译能力不支持或语义损失时阻止发布；不得静默降级或丢弃规则 |
| Mihomo 生命周期适配器 | 隔离实例、备份接口、真实 Controller 写权限 | 发现→能力协商→生成→语法检查→隔离启动→冒烟→金丝雀→读回→观察→提交全链有证据 | 任一步失败停止扩大，恢复前一已验证配置；回滚失败进入救援模式，禁止循环重启 |
| 独立技术与真实业务探针 | 至少同站点不同进程，关键业务最好不同主机/出口 | DNS、TCP、TLS、HTTP、出口 IP、地区和业务事务分别判定；403/429 分类；结果有位置、路径、TTL 和独立性 | 探针本身不可靠、证据过期或结论冲突时不得自动切换；状态标记未知并升级人工 |
| DNS 执行和防泄漏闭环 | DNS 数据面适配器、内部域信息、可控客户端/网关 | 内部/国内/境外/关键业务路径、缓存、DNSSEC、上游切换、IPv4/IPv6、绕过和泄漏检测通过；解析出口与流量出口一致 | DNS 发布独立版本和恢复点；两分钟/阈值内业务失败自动回退上个已验证版本，但不得绕过内部权威 DNS |
| 安全基线和供应链门禁 | CI、依赖清单、镜像仓库、秘密管理 | SAST、依赖/镜像扫描、SBOM、签名验证、固定版本、秘密扫描、最小权限、资源限额、速率限制和输入模糊测试通过 | 高危漏洞、签名异常或依赖来源不可信时阻止构建/部署；保留上一签名镜像和离线恢复包 |
| 备份与恢复演练 | 版本/任务/审计/密钥引用/配置清单 | 定义 RPO/RTO；在隔离环境从备份恢复并通过配置、技术、业务和审计四层验收 | 备份无法校验或恢复演练失败时禁止生产写入；旧系统继续保持现状 |

### P0 退出条件

只有同时满足以下条件，才能进入 Mihomo 小范围生产写入试点：

1. 所有 P0 门均有自动化证据，且证据在有效期内。
2. 写路径默认关闭，必须绑定明确环境、租户、站点、设备和变更版本。
3. 在隔离环境完成成功、超时、断网、磁盘满、进程崩溃、设备重启、控制器重启、重复请求和回滚失败注入。
4. 在一台非关键设备或一个非关键业务上完成金丝雀，观察窗口内无新增异常。
5. 回滚和管理权恢复由与主控制面独立的路径验证。

## 6. P1：形成可用的企业业务闭环

| P1 工作项 | 验收门 | 回滚/降级门 |
| --- | --- | --- |
| 节点能力与稳定性评估 | 分层测量、业务能力、出口身份、P50/P95/P99、丢包、抖动、结果 TTL、历史稳定性可复算；空池和过期证据明确 | 评估不可用时保留人工锁定/上个稳定节点，不按单次延迟自动切换 |
| 受控自动修复 A1/A2 | 只执行低风险、可逆动作；动作预算、冷却、最大影响、抑制、因果验证和独立复验齐全 | 超预算、结论冲突、业务恶化或回滚失败立即冻结该领域并转人工 |
| sing-box 适配器 | 真实编译、版本协商、隔离启动、协议矩阵、灰度、读回和回滚测试 | 不支持字段阻止发布或明确选择其他数据面，不得静默转换 |
| Xray 适配器 | 与 sing-box 相同生命周期；重点覆盖 VMess/VLESS/Reality、入站和路由语义 | 同上；不能用静态能力矩阵替代运行时协商 |
| 多租户与组织治理 | 稳定租户/站点/对象 ID、数据与密钥隔离、配额、委派管理、跨租户拒绝测试 | 租户上下文缺失时拒绝访问；迁移失败恢复原归属和授权 |
| 反向代理/API 网关适配 | TLS/mTLS、证书轮换、路由、限流、熔断、金丝雀和访问审计全链测试 | 保留上一配置和证书；证书/上游健康异常停止扩大 |
| 隧道与零信任适配 | 身份、设备姿态、应用级授权、重叠地址空间、路由泄漏和故障转移测试 | 控制面失效保持最后授权状态；不自动扩大网段权限 |
| 操作记录中心与证据导出 | 页面能够回答谁、为何、做了什么、设备实际状态、验证、回滚和残余风险；导出可独立验签和脱敏 | 前端断线/刷新不重放任务；证据不完整时状态不得为完成 |
| 可观测性与 SLO | 指标、日志、追踪、流量、DNS、任务、审计统一 trace ID；告警有去重、抑制、升级和恢复事件 | 观测缺口显示未知；遥测压力不得拖垮数据面，超限降采样并保留关键审计 |

## 7. P2：高可用、灾备与自治增强

| P2 工作项 | 验收门 | 回滚/降级门 |
| --- | --- | --- |
| 控制面 HA 和脑裂保护 | 多控制器选主、单调版本、租约、网络分区和时钟漂移测试；无领导者时冻结写入 | 任一脑裂迹象进入只读；不以“多数服务存活”替代写安全证明 |
| 独立监测故障域 | 至少不同主机；关键场景要求不同站点/运营商/云；能发现控制面自报健康但业务失败 | 外部监测失联时降低自动化等级，不能继续高风险自治 |
| 灾备和管理权恢复 | 主库、控制器、管理网、身份源和备份介质失效演练；救援入口双人控制且全审计 | 恢复失败保持数据面最后配置，禁止反复覆盖；进入明确救援模式 |
| 跨系统事务 | DNS、路由、证书、代理、身份变更采用 Saga/补偿；故障注入覆盖每一步 | 补偿失败保留中间状态证据、隔离受影响对象并转人工 |
| AI 辅助诊断 | AI 输出引用证据、模型/提示版本、置信度；提示注入、幻觉、降级和熔断测试 | AI 不可用或低置信时回退确定性剧本；高风险写操作永不由 AI 单独批准 |
| 受控学习 | 候选规律离线回放、影子、审批、灰度、版本化和可撤销 | 数据污染、概念漂移或收益不确定时撤回模型/规则，不直接改生产策略 |
| 容量、成本与供应商治理 | 达到明确节点、规则、连接、事件规模；背压、队列、配额、成本和供应商故障演练 | 超容量时拒绝低优先级新任务并保护数据面与审计链 |

## 8. 推荐依赖顺序

```text
真实性清单与稳定对象 ID
        ↓
身份/RBAC ── 审计/可信时间 ── 秘密管理
        ↓             ↓
三态存储 ── 操作状态机/幂等/租约 ── 证据存储
        ↓
订阅隔离 + 完整规则分析 + 目标内核真实校验
        ↓
只读持续对账 + 独立技术/业务探针 + DNS 观察
        ↓
Mihomo 隔离写入适配器
        ↓
单设备/单业务金丝雀 + 自动回滚
        ↓
DNS 执行闭环 + A1/A2 低风险自治
        ↓
sing-box / Xray / 反代 / 隧道
        ↓
多租户治理 + HA/灾备 + 外部独立监测
        ↓
AI 辅助与受控学习
```

不得跳过身份、审计、状态机、独立探针和恢复门，直接从当前 Shadow 版本打开生产发布。

## 9. 每次发布的统一验收门

每个可执行能力都必须复用以下关闭条件：

1. **意图门**：请求绑定稳定对象 ID、环境、风险、范围、目标版本和操作者。
2. **预检门**：依赖、能力、容量、权限、审计、时间和证据新鲜度通过。
3. **恢复门**：备份可读、摘要正确、恢复命令已生成、目标仍可达。
4. **隔离门**：目标内核/服务真实加载候选配置并通过语法和启动测试。
5. **金丝雀门**：仅最小故障域生效，连接排空和会话策略明确。
6. **读回门**：设备实际状态与目标逐字段对账，不使用提交值冒充读回值。
7. **技术门**：DNS、路由、TCP、TLS、HTTP、出口身份和性能通过。
8. **业务门**：按业务契约执行真实事务；403、429、认证和地区限制分类正确。
9. **观察门**：达到业务定义的稳定窗口，且没有新增高等级事件。
10. **关闭门**：提交版本、审计、证据、残余风险和责任人；否则只能处于部分成功、未知、回滚或人工接管状态。

## 10. 回滚统一原则

- 回滚目标必须是“最近已独立验证的版本”，不是“最近保存的版本”。
- 回滚也必须执行读回、技术验证、业务验证和观察，不能以命令返回 0 结束。
- 数据面继续转发优先于控制面功能恢复；控制面失效不得清空最后有效配置。
- 回滚连续失败达到预算后停止自动动作，进入救援模式，防止重启和切换震荡。
- DNS、路由、证书、代理和身份的跨系统变更必须有补偿顺序，不能只回滚其中一个组件。
- 恢复凭据、恢复包和紧急入口必须独立保管、定期演练且使用本身被审计。

## 11. 最近四个可交付里程碑

### M1：可信控制面底座

交付身份、RBAC、审计事件、可信时间、三态对象、任务状态机、幂等、租约和能力真实性门禁。完成后仍保持 Shadow，不写生产。

### M2：持续只读观测闭环

交付 Mihomo 周期读回、规则/provider/DNS 摘要、证据 TTL、漂移事件、独立技术探针和真实业务探针。完成后可以持续发现问题，但仍不自动修复。

当前 **M2a 被动观测底座已完成生产 Shadow 初始门禁**：周期读取 Mihomo Controller，持久化去敏摘要并暴露分层新鲜度；24 小时稳定性浸泡尚未签署。它没有主动探测，也未完成 provider/DNS 摘要、漂移事件、节点稳定 ID、业务契约、独立探针或长期浸泡，所以 M2 仍未完成。M2b 主动探针正在按“本地隔离实现 → 候选隔离容器 → 批准目标生产 Shadow”推进，必须使用版本化许可清单、固定预算和零任意 URL 接口。

### M3：Mihomo 单目标受控发布闭环

交付完整规则编译、目标内核真实检查、备份、隔离启动、单目标金丝雀、读回、业务验证、观察和自动回滚。只允许隔离环境和非关键业务试点。

### M4：DNS 与低风险自治闭环

交付 DNS 版本化执行、防泄漏、上游健康、出口一致性、A1/A2 修复、预算、冷却、抑制和失败转人工。通过长时间浸泡和故障注入后，才评估扩大范围。

## 12. 当前可签字的验收结论

- 可以验收：本地基础代码、测试覆盖的校验/编译/版本/路由/接口能力、Shadow 安全默认值、Mihomo 只读适配器和演示数据边界。
- 可以验收为当前单次生产证据：部署文档记录的安全加固 Shadow 镜像、最小公开证明、失败关闭、优雅重启和回滚烟测；它仍不是持续可用性或写入闭环证明。
- 不能验收：生产配置下发、DNS 接管、订阅自动化、真实业务健康、自动修复、多内核运行、多租户、企业审计、HA、灾备和 AI 自治。
- 不能承诺：绝对无故障、绝对无 Bug、100% 准确或 99.999999% 端到端可用率。

下一步并行保留 M2a 的 24 小时生产浸泡，并在隔离 Linux 候选机验证主动代理镜像、进程健康、独立 bridge、默认拒绝出口、自有无副作用目标、耐久启动预算和故障注入；未完成这些前置条件和许可目标审批前，不部署 M2b 生产探针。固定可信解析器、耐久启动账本、结构化 preflight、只读状态语义验证和归档前后复验已有本地实现与测试，但不能代替容器运行态证据。静态 canary 合同与供应链证据候选也已实现并保持 `BLOCKED`：前者还没有真实 DNS/TLS/HTTP 观测和审批验签，后者还没有真实 DSSE/镜像验签、X.509/Rekor、Registry digest 读回、防重放账本或 Linux 文件系统证据。

恢复合同层已在 run `39162519874` / job `117778615130` / commit `5ca68f8...` 通过 Ubuntu 离线门禁：四类新合同与 11 份 Draft 2020-12 schema 由固定验证器编译并验证正反实例，恢复状态机/拓扑语义与合同执行差分一致，Go 普通/race 和签章器均零测试用例 skip。该证据只把“严格合同和解析语义”提升为已实现；签名字段仍是未验证声明，尚无真实外部 CAS/WORM 读回、安全证据发布 coordinator、Docker 构建或 live 切换。产品镜像因基础镜像未锁摘要继续 `BLOCKED`，恢复脚本继续在切换前返回 78。

恢复协调器目前新增的是 **blocked model**，不是可用能力：backup v3 解析结果已绑定原始输入字节 SHA-256；模型可演练本地 evidence publish/readback 后再写 journal、split-commit 重试、尾事件全等、持久化 store 重开及 `INPUT_VERIFIED` 边界。run `39169948542` / job `117800728560` 已在 Linux/ext4-XFS 真实执行该重开场景，并固定输出 `authorization=BLOCKED_TRUSTED_INPUTS_MISSING`。后续新增的 `internal/restorelease` 是单独的 Linux 安全原语：固定使用与 shell 相同的两个 flock 路径，按全局后候选顺序获取、反序释放，并将 trusted parent、base、候选目录、锁和 marker 的长持 FD 与设备/inode/mount ID 绑定；Windows 明确不支持，验证失败永久 poisoned。run `39172099478` / job `117807132828` 已在受限 Linux root 容器中通过 13 个场景、2 个 shell 互操作场景和零 skip；全仓离线门禁同时报告 `GO_JSON_GATE=PASS files=2 semanticRunEvents=2936 packages=29 skips=0`。该原语尚未接入协调器，重启后也不能证明旧租约连续。协调器仍刻意没有公开生产构造器，内部可信时间、独立当前配置/旧状态/拓扑采集、backup-v3 collector 和正式 Resume/Reconcile 均未实现；不能签署恢复协调器已上线或可授权 live 动作。

状态采集链现补入一个仍被隔离的只读基础：`LockedStateSnapshot` 在 spool→ledger 两把 writer lock 均持有后生成报告，并在消费报告前复验锁路径和全树摘要；失败会 sticky-poison，失败路径与关闭路径均反序释放。测试覆盖跨进程 writer 互操作、第二把锁失败与语义失败无泄漏、exec 不继承、路径/根替换、非协作内容变更、复制别名和并发生命周期。它仍是 process-local、依赖协作式 flock 的 advisory 原语；`Verify` 与边界外动作之间仍存在 TOCTOU，不合作的 root writer 仍属于 TCB。它没有接入 coordinator，Windows 仅具 advisory 诊断等级，Linux 也尚未长持 trusted-parent dirfd 或绑定 mount ID；因此它不能代替独立 current config/image/Compose/topology/runtime observer，不能解除恢复授权阻断。

新增的 `internal/restorecurrent` 只关闭“当前四份固定配置完全由调用方填入”的一小段缺口：它持有 lifecycle lease 和 kernel clock，以候选根 identity 为锚通过 dirfd/openat 读取 config 目录与 `probe.env`、catalog、DoT CA、egress policy，输出的只有摘要、固定服务/挂载常量、局部时钟观察和稳定排序的阻断码。它不读取 state，不调用 Docker，不观测 live 容器，不执行 quiesce，不生成 `StateOnlyCurrent`，也没有 coordinator 依赖。九项阻断覆盖 CandidateID、Compose source/rendered、镜像、live container、quiesce、writer 停止、state 路径绑定和外部时间锚。run `39178627641` / job `117826454347` / commit `a212563...` 已以 ordinary/race 两份 transcript 各精确验收 42 个 Linux root 场景且零 skip；整仓 3062 个 Go 语义 run event、31 个包、144 个 Python 测试、13 个 shell 脚本和 11 份 schema 同步通过。因此状态提升到 `ADVISORY_CONFIG_BOUND`，但仍固定 `authorization=BLOCKED_RUNTIME_ATTESTATIONS_MISSING`，不是可信 current-state、生产恢复或已部署能力。

P0-a 在此基础上补入 `ADVISORY_LOCAL_IDENTITY_BOUND`，但没有把本地 identity 误记为外部证明。`candidate-identity.json` 的 FD、元数据、原始摘要、严格字段集和交叉绑定已纳入同一 lease/clock 生命周期；身份文件路径替换、原位修改、unlink、超限和不安全文件对象均会永久 poison 当前 handle。由于候选根的特权写者仍可同时重建 nonce、Candidate ID 与文件，本地一致性无法证明防回滚或来源独立，`CANDIDATE_ID_ATTESTATION_MISSING` 与另外八项 blocker 继续全部保留。run `39181172717` / job `117834039374` / commit `2d94be3914bdda471d54a9fa47c5250336a7bf62` 已以 ordinary/race transcript 各精确验收 56 个 Linux root 场景、零 skip，并通过整仓 3094 个 Go 语义 run event、31 个包、144 个 Python 测试、13 个 shell 脚本和 11 份 schema metaschema。下一缺口仍是独立 Release/Compose source/rendered 证明；在它完成前不应先接 Docker runtime observer，更不能执行 quiesce 或生产恢复。

P0-b 现已补齐 **本地自声明 Release/Compose 一致性**，但仍未补齐独立 attestation。三个专用证据文件被绑定到候选 identity、环境摘要、源/渲染原始摘要和版本化语义投影；root/openat/no-follow/nlink/device/mount、重验和 sticky-poison 边界均进入 Linux root 门。真实 Docker Compose v2.38.2 的 `config --format json` 输出已在 run `39202982653` / job `117899713507` / commit `8c9e52f08fecc7e9cdd2ad1fe5cb030bd088e17d` 通过精确兼容测试；ordinary/race 各通过 87 个 root 场景，整仓通过 3324 个 Go 语义 run event、31 个包、155 个 Python 测试、13 个 shell 脚本、Go vet 与 11 份 schema metaschema。这个结果只把边界推进到 `ADVISORY_LOCAL_RELEASE_BOUND`：构建上下文仍是外部路径声明，renderer 二进制身份、镜像来源/Registry 读回、live 容器身份、quiesce、writer 停止、state 路径绑定和外部时间仍未证明，九项 blocker 一个都未解除，授权仍是 `BLOCKED_RUNTIME_ATTESTATIONS_MISSING`。下一步只能开发不具写权限的 Docker runtime observer；在其独立证据与后续门禁通过前，不得停止容器、切换状态或接入生产恢复。

run `39175647549` / job `117817635191` / commit `2ad8f25...` 已补齐该切片的 Linux 执行证据：Ubuntu 24.04.5、Linux 6.17、Go 1.23.12；普通与 race 两份 transcript 中 probe 各 260 个 run event，整仓合计 3028 个语义 run event、30 个包且零 skip；Go vet、Python 141 项、shell 13 项和 schema metaschema 同时通过。该结论只提升 advisory 状态快照原语，不提升恢复协调器或生产能力状态。

宿主出口取证工具也只生成 BLOCKED 报告，因为 `internal` 网络、首次启动、可信 DoT/唯一测试向量、全局 nftables 效果和共享 Go 合同尚未闭合。启动门不会执行 `compose up`。同时保留 M1 尚未完成的企业 IdP、独立审计副本和可信时间缺口。每个里程碑都必须同时提交代码、自动测试、故障注入记录、部署证据、恢复演练和残余风险清单；只有这些证据共同成立，才能把状态从“设计”升级为“已实现”，再从“已实现”升级为“生产已验收”。

## 13. M1 源代码底座进展（2026-10-18）

本轮源码新增并强化七项 M1 基础能力：

- `internal/authn`：只保存 SHA-256 摘要的静态高熵 Bearer 身份文件，严格 Authorization 解析、禁用/生效/过期门禁和常数时间摘要比较；它不是密码、JWT、会话、MFA、SSO 或轮换服务。
- `internal/truth`：期望/实际/观测三态隔离、来源约束、证据引用、置信度和新鲜度协调门禁。
- `internal/authz`：默认拒绝角色矩阵、租户/站点/对象/环境范围、职责分离和限时 break-glass 策略。
- `internal/operation`：schema v2 显式状态机、终态冻结、幂等、发起人/审批人耐久绑定、原子文件快照、单写者锁、重启恢复、`Close()` 和不确定提交后的 poison/fail-closed。schema v1 只迁移为 `legacy_unbound`，禁止继续转换或用新身份重新绑定。
- `internal/evidence`：JSONL 追加、前序哈希链、本地 checkpoint、`AppendOnce` 幂等、进程生命周期单写者锁、篡改/截断/额外尾部检测、敏感字段拒绝和 `fsync`。checkpoint 落盘不确定时 poison 当前实例；`checkpoint_stale` 必须人工恢复。
- `internal/control`：认证主体经 authz 决策后先写 pre-evidence，再改变本地操作状态，最后写 result evidence；结果证据异常显式返回 `audit_degraded`，目录持久性不确定显式返回 `commit_unknown`，不会乐观宣称完成。
- `internal/api`：受保护的 operations 读/写/转换接口，要求 Bearer、范围与幂等键，写入另受 `CHENGWANG_OPERATION_WRITES_ENABLED` 控制；响应不返回事件正文和原始身份，并阻止进入任何设备执行阶段。

上述源码已由最终集成者重新执行全量 Go、race、vet 和前端回归。默认锁定的 Shadow 控制面也已部署到生产，并完成健康、能力事实、operations 失败关闭、证据完整性、Mihomo 只读、容器重启和旧镜像独立回滚烟测。生产没有配置身份文件，操作写开关为 `false`，操作库为空，且不存在设备执行器，因此这些证据不能解释为真实身份操作或生产写入闭环。

同日安全加固进一步把匿名接口压缩为常量成本的健康与 Shadow 证明，完整 runtime/readback/versions/evidence 校验改为身份和管理范围保护；管理凭据在非回环监听上强制 TLS，浏览器在局域网明文 HTTP 上不会发送令牌；Mihomo Controller 令牌增加回环 HTTP/远程 HTTPS 白名单与禁环境代理边界；运行态刷新增加缓存、单航班、等待者上限和明确陈旧语义；版本库增加分批枚举和发布前硬配额。该候选经独立绕过审查、源码门禁、候选容器、生产切换、重启和旧镜像烟测后部署。生产继续保持无身份、写入关闭和无执行器。

M1 仍未完成：操作库只有单机跨进程互斥，没有分布式租约或共识；证据链仍非 WORM/独立副本；静态身份不是企业 IdP；三态模型没有连接真实对象存储和可信时间。两项明确 P1 运维缺口是本机无密钥链/非 WORM，以及 `checkpoint_stale` 仍需人工取证与恢复。因此不得把这些源码底座解释为生产写入、企业治理闭环或 `99.999999%` 可用率。

## P0-c 运行态观察候选缺口

P0-c 已进入仓库候选实现，但没有进入生产。安全审计否决了“观察器直接连接 Docker socket”的方案，现改为特权 GET-only 采集代理与无特权观察客户端两个权限域。代理只允许固定标签容器列表及完整 container/image/network ID inspect，输出不含 Env、health log、原始 labels、宿主 mount source 或 Docker 错误正文；客户端固定连接专用 socket，对代理投影和 `OpenReleaseBound` handle 分别双读。

工作流使用固定摘要、隔离网络、无端口无生产挂载的短生命周期 daemon fixture，并要求 ordinary/race 精确 transcript 和清理读回。run `39206352055` / job `117909922290` / commit `c9b466481614afe5deff1032b8b2bd1d31e59b29` 已通过该真实 daemon 门和整仓 3466 个 Go 语义 run event、35 个包、158 个 Python 测试、11 份 schema、普通/race/vet。它仍是 **已验收仓库候选但未安装**；九项 blocker、`authorization=BLOCKED`、镜像/daemon/host 同源信任缺口和生产恢复禁令全部保留。

## P0-d1 本地镜像字节关联缺口

本阶段新增 `internal/restoreimage`，使预期 manifest digest、原始 manifest、config descriptor 和原始 config 摘要形成一致链，并与 P0-c opaque observation 的本地 Docker image ID 关联。它是纯字节处理候选：只接受受限单平台 manifest，严格拒绝歧义 JSON、digest/size/media type/platform 漂移和 blocker 缺失；不包含文件、网络或恢复执行入口。

成功仅为 `ADVISORY_LOCAL_IMAGE_ASSOCIATION / authorization=BLOCKED`。仓库引用与平台仍是本地声明；layer 内容、Registry 远端和 RepoDigests、Sigstore/DSSE、独立审批信任根、防重放、不可变 Compose 部署和真实 Capture→BindLocal 集成均未完成。因此镜像 blocker 与其余八项继续全部保留；详见 `P0D1-LOCAL-OCI-IDENTITY.md`。

## P0-d2 层字节图与候选环境进展

新增有界内存 `ValidateLocalLayers`，逐层核对原始 blob 摘要/长度、完整解压 diff_id、顺序与累计预算，gzip 仅支持单 member，压缩输入和解压输出都检查取消。结果仍是 `ADVISORY_LOCAL_OCI_DIGEST_GRAPH_BOUND`；没有 tar/overlay 验证、Registry 与签名来源证明或恢复授权，全部九项 blocker 保留。

2026-10-20 只读检查确认 10.88.0.240 有 Ubuntu/Docker 和可用资源，但已承载 ERP。主机尚未部署澄网，也没有改动现有服务。后续必须使用独立候选项目及资源限制；环境基线和首次观察到的 SSH 指纹记录于 `DEPLOYMENT-240-PREFLIGHT.md`，实施前需重新读取。

## P0-d3 标准验签候选进展（2026-10-22）

以下 P0-d3 至 P0-d6 是各阶段当时的缺口快照；P0-d5 补入受管信任/撤销/防回放候选库底座，P0-d6 补入产品 API/RBAC 和独立候选入口，P0-d7 再补入自动刷新及健康跨库审计恢复，但 UI、原主入口后端注入、生产可信发放与上线仍未完成。不能把历史缺口文字或后续测试当成当前生产状态。

新增独立 Go 1.25.8 `tools/image-verifier`，使用官方 `sigstore-go v1.3.0` 验证 messageSignature 与 DSSE 的 artifact digest、精确 issuer/SAN、Fulcio 链、SCT、同一 Rekor v1 条目的 SET/proof/checkpoint。它只产生 `ADVISORY_SIGSTORE_BUNDLE_VERIFIED / authorization=BLOCKED`，没有升级主项目 Go 1.23，也没有生产安装。已修复并回归官方分片样本的两个不同 index 语义，原始 fixtures 摘要不变；最终本地/CI 证据详见 `P0D3-STANDARD-SIGSTORE-VERIFIER.md`。

这只填补标准验签底座的一部分：root/policy 独立批准、Registry 仓库平台读回、签名与OCI graph绑定、源码/builder准入、防重放、真实部署、出口与业务验证均未闭合。conformance 测试材料已补查固定 README 的 Apache 2.0 明确声明并保留来源，但产品完整依赖许可审查仍未完成。旧供应链校验与九项 blocker 保持不变，M2b、M3、M4 和整体生产运营仍未完成。

## P0-d4 镜像签名、批准与 Registry 绑定（2026-10-22）

新增独立 `tools/image-binding`，把 Ed25519 批准文档、精确 Sigstore 签名对象和实际 Registry 单平台 manifest/config/layer 图关联。批准绑定 Registry 仓库、域名、IP、正常 TLS 和叶 SPKI，以及签名身份与信任根摘要。候选提交 `90299930429c147ebde14c71739159ea20c5e6d7` 已通过隔离 Linux CI：新模块普通/race 各 234 场景、3 包；真实 Distribution 两类签名普通/race 读回；原主项目 4134 语义事件、36 包、0 skip。详见 [P0-d4 验收记录](P0D4-APPROVED-REGISTRY-BINDING.md)。

这是 `implemented+tested isolated-only` 的库，不是已接入产品的批准/部署系统。测试批准密钥和惰性测试镜像不是生产批准者或澄网发布制品；可信策略存储、源码/builder 语义准入、吊销/防回放、运行容器绑定与发布恢复执行器仍缺。没有生产变更，所有结果 advisory/BLOCKED，九项 blocker、M2b/M3/M4 与整体生产运营状态不因这些测试而解除。

## P0-d5 可信策略、撤销与单次 grant（2026-10-22）

新增 `trustcatalog`、`truststate` 和不透明 `ManagedResult`，把带外 Anchor、Ed25519 根双阈值轮换、严格代际、永久撤销/floor 高水位和持久 RESERVED→CONSUMED 接入真实签名/Registry 绑定。网络读取期间允许同一实例更新撤销，最终持久读回后重新检查 catalog 与批准时效。失败/崩溃后的已预留 grant 不自动回收；可信根显式签发新 grant 才能重试。

代码 `6a387bcd8a11a0590e5990723c5638fefa445adf` 已通过隔离 Linux CI：绑定 run `39755876523` / job `119747626282`，ordinary/race 各 379 场景、5 包、0 fail/skip，保留旧 234 场景指纹；真实 Distribution 两类签名均完成受管成功、重开与拒重放。主项目 run `39755876519` / job `119747626733` 保持 4134 语义事件、36 包、0 skip。37 个模块源码文件 CI 摘要逐一匹配 Git 原始 blob，386 远端模块/版本和 go.sum 无漂移。具体失败修复、独立复核与限制见 [P0-d5 验收记录](P0D5-TRUST-REVOCATION-REPLAY.md)。

这只推进到 `implemented+tested isolated-only / ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND / authorization=BLOCKED`。没有产品 API/UI/RBAC、生产信任发放、自动在线撤销刷新、外部单调见证、真实发布镜像准入、临执行复验或部署恢复集成；不抵御整个磁盘/Anchor 一并回滚，不证明物理掉电，不提供部署 exactly-once。64 代历史与 4096 消费账本是失败关闭预算，不是已实现长期自动运维。九项 blocker、生产环境和 M2b/M3/M4 状态全部不变；本阶段未访问或修改生产，也未合并 main。

## P0-d6 产品 API、RBAC 与候选入口（2026-10-22）

新增主模块纯接口 `imagetrust`、产品三个受保护 image-trust API 与分动作/固定 scope RBAC；独立 Go 1.25.8 product 后端接入真实 Store、ManagedBind 与审计。独立候选入口使用同一个产品 api.New，私有配置、已有 Store/审计、默认写关闭、非回环 TLS、仅固定 allowlist；原 cmd/server 未注入后端或部署更新。撤销仍需有效阈值签名的新 catalog，API admin 不能直接替代签名。成功仍为 advisory，不是执行权限。

代码与最终场景门 `5107ebd5b51f42d9b70cddf3027b4626ade99942` 已通过绑定 run `39763836641` / job `119774275129` 与主项目 run `39763836481` / job `119774274234`。子模块普通/race 各 490 场景、7 包、0 skip；主项目 4504 个 Test 语义运行事件、37 包、0 skip。完整产品 HTTPS API 到无适配真实 Distribution 的两类签名验证与持久拒重放均实际执行；491 项跨模块源码、49 项子模块源码逐 Git 原始 blob 复核，386 依赖集合不变。候选二进制已在 CI 构建并核对 revision/help/摘要，但未发布或安装。详见 [P0-d6 验收记录](P0D6-PRODUCT-API-RBAC-ACCEPTANCE.md)。

状态仅为 `implemented+tested isolated-only / authorization=BLOCKED`。UI、企业身份/审批/根密钥运维、多 Store/分布式租约、周期审计健康刷新、更新/全局资源配额、两库持久协调与自动恢复、在线撤销送达、外部单调见证、正式签名镜像、设备执行器与生产灰度均未完成。审计消费记录不代表客户端已收到成功；进程内预算/poison 不是持久治理闭环。九项 blocker、M2b/M3/M4 与整体运营状态全部不变；本阶段未访问或改动任何生产主机、爱快、DNS 或 OpenClash，未合并 main。

## P0-d7 自动撤销刷新与健康跨库审计恢复（2026-10-22）

新增固定 HTTPS/CA/hostname/IP/SPKI 来源的有界自动刷新、顺序中间代下载、真实受管验签安装和精确 generation/hash 新鲜度。BeginTracked 在预留事务内检查源截止与版本，Complete 和结果审计后继续检查；最终第二次观测不能把新代确认误用到旧结果。独立候选显式启用自动刷新、每 15 秒重新核验审计，后台取消并等待后再关库。原 cmd/server 未装配，所有生产服务未更新。

新增同一 bbolt record 的 operation journal/outbox，使 catalog 提交、RESERVED/CONSUMED 与恢复事实原子绑定。启动在 HTTP 前核对全部保留操作的 scope/原审计前缀/prepared hash/ACK hash，只幂等补健康两库之间的审计投递缺口，不重做业务、回收 grant 或伪造 HTTP 成功。旧业务必须已经停止；这不是热切换 API。坏 checkpoint/路径/盘/整盘回滚不自动修复，致命错误停止候选，未安装 supervisor。

最终代码 `d4f413e808dc03c30e5aca15ca4a5d79aab531ec`：绑定 run `39769625166` / job `119793601116`、父 run `39769625246` / job `119793601382` 均 success。子模块普通/race 各 627 场景、8 包，保留旧 234/379/490；父 4514 次 Test 运行、37 包，保留旧 2252 pair，零 fail/skip。12 个真实 product 子进程退出持久边界、真正 API/Sigstore CONSUMED 后审计故障恢复、真实 TLS 源网络中撤销及原无适配 Distribution 均实际执行；507/61 项源码摘要逐 Git raw blob 核对、386 依赖集合不变。失败任务与静态竞态修正未隐藏，详见 [P0-d7 验收记录](P0D7-REFRESH-RECOVERY-ACCEPTANCE.md)。

状态仍为 `implemented+tested isolated-only / authorization=BLOCKED`。并非完整 TUF、即时未知撤销、坏文件自愈、WORM/独立副本、外部时间/单调见证、长期容量与资源治理、企业身份/UI/审批、分布式 HA 或正式镜像发布。过期中间代与固定源故障会失败关闭；journal/审计满后需受控运维，不承诺免维护、无 bug 或任何高可用率。九项 blocker、M2b/M3/M4、整体正式运营状态不变；本轮没有访问/变更生产主机、爱快、DNS、OpenClash，没有 main 合并或设备执行授权。

## P0-d8 可信状态与受保护操作记录界面（2026-10-22）

在 P0-d7 基础上新增只读 history API、独立 `image_trust.history` RBAC，以及真实候选的独立 `trust.html`。来源新鲜度、目录有效期、审计核验和启动补审计分别显示，未知不视为健康。历史读取核对 journal 与审计的全部保留绑定，正常并发返回 409 而非误 poison；读取不刷新源、不消费 grant、不补审计。前端支持显式内存凭据、搜索、分页、摘要展开、手工刷新、断开清除和权限失败状态，没有部署/写入入口。

最终代码 `ecb1a4e6fc3206d7cb87abd51eb60ee8352a46bb`，绑定 run `39778238811` / job `119822560806` 与父 run `39778238648` / job `119822560164` 均 success。子模块普通/race 各 669 个 Test pair、8 包；父各 2311 个 Test pair，37 包中 36 pass、1 个显式允许的 domain 无测试包 skip，测试场景零 fail/skip。另 77 前端测试、11 个 pidfd guard 测试、159 Python、13 shell、11 schema 通过；真实 Chrome→真实候选执行 38 项检查、14 个同源 GET、4 张实际截图，并验证 25 项签名定义、22 条 journal、44 条审计经只读访问后不变。保留 P0-d7 与更早完整基线，真实 Distribution 签名/API 链继续通过。535/70 项源码清单逐 Git 原始 blob 复核，386 远端依赖版本不变。首轮只读缓存失败及随后绿色 CI 的中文字形方框均未计最终验收，修正并重跑后才通过。详见 [P0-d8 验收记录](P0D8-TRUST-CONSOLE-ACCEPTANCE.md)。

状态仅为 `implemented+tested isolated-only / authorization=BLOCKED`。企业身份/审批、原主入口真实后端装配、浏览器 HTTPS/证书验收、正式签名产品镜像、生产灰度/读回/观察、长期资源治理、坏库自动修复、独立 WORM/见证和分布式 HA 仍未完成。浏览器 CI 使用 loopback HTTP 与显式记录的 CI-only `--no-sandbox`，不冒充生产安全边界。九项 blocker、M2b/M3/M4 和整体正式运营状态不变；未访问或修改生产，未合并 main。

## P0-d9 完整产品候选组合与正常 HTTPS（2026-10-22）

从父主服务抽取Go1.23共享runtime，原主入口保留原测试与默认门；独立Go1.25.8候选通过显式 `-product-config` 将真实trust backend装配到同一个完整基础API和共享Audit。私有typed配置绑定身份/TLS/租户/站点/已有状态，强制candidate+TLS，不继承全局发布开关。启动恢复先于监听，停止admission、取消并等待handler/worker后才关库；超时失败且保留资源，不称为成功关服。此处完整指既有基础API组合，并非全部企业模块完成；原主入口默认仍无trust backend。

最终代码 `875db6da9a68c03f3ea0588071925550cfb94fee`，绑定run `39799680041` 与父run `39799679868` 均completed/success。子普通/race各700 Test pair、D9新增31，父各2320、runtime新增9，所有旧完整集合保留。另77前端、6 Node、11进程guard、52 JSON负例、15门测试、Linux160 Python/0skip、13 shell、11 metaschema通过。真实Chrome→完整产品候选HTTP40/HTTPS45检查，精确title/URL、console错误/警告0、三类坏证书在HTTP/Bearer前拒绝；正常私有NSS验证TLS1.3与父API200，journal22/audit44只读不变。8张实际中文截图、546/74条源码逐Git blob和386远端依赖核对通过；真实Registry144不可变读取200保持。初轮Vitest误收Node文件失败和后来title/console证明缺口均保留记录，不拿旧成功替代新断言验收。详见 [P0-d9 验收](P0D9-PRODUCT-HTTPS-ACCEPTANCE.md)与[候选操作说明](PRODUCT-CANDIDATE-OPERATOR-NOTES.md)。

状态仍为 `implemented+tested isolated-only / authorization=BLOCKED`。完整主App/企业IdP/审批、正式容器与签名发布、真实release部署、公共/企业证书生命周期、跨浏览器/IPv6/LAN、完整入口SDK网络中途崩溃、长期soak、坏库自愈、外部见证/WORM、分布式HA、全网络与设备执行均未完成。Docker基础镜像未固定门不绕过；CI-only Chrome仍为no-sandbox，外层隔离不等同浏览器sandbox。九项恢复blocker和M2b/M3/M4状态不解除，未访问/改变生产，未合并main，不承诺无bug、免维护或可用率。

## P0-d10 真实产品候选镜像与隔离运行（2026-10-23归档）

新增独立scratch路径，不修改旧Dockerfile/M2b浮动基础来源门。真实Go1.25.8静态产品程序与7个trust Web文件经严格ELF/buildinfo/源码与摘要白名单打包，实际Docker构建/镜像层文件读回，默认非root入口运行，不挂载替代程序。4个镜像端点与可信实例同容器重启共5次运行，实际PID1程序摘要、只读根、cap0/NNP、精确mount/资源限额/无host端口分别有读回。5次退出0、3轮四组Store/Audit独立重开、正常TLS/API重启读回与4类真入口启动失败关闭实际通过；gen3/25测试定义/journal22/audit44/零消费不变。

最终代码 `fbe6f0605abb3eb83f541bf62774c08df8a11456` 的绑定run `39808957939`、父run `39808957928` 均completed/success，子普通/race各700、父各2320完整集合保持，Linux18新检查器0skip。新镜像真实Chrome正常NSS HTTPS45检查/16GET/console错误警告0、3证书反证通过；旧HTTP40/HTTPS45和真Registry144不可变读取保持。95工件/12原始截图、553+76条源码逐Git原字节与386依赖复核完成。首轮5b016cc的browser路径/清理权限失败保留，fbe只修3文件只读且源码绑定的harness可达路径，未删检查。详见 [D10验收](P0D10-IMAGE-RUNTIME-ACCEPTANCE.md)。

状态仅为 `PRODUCT_CANDIDATE_IMAGE=BUILT_AND_EXECUTED_ISOLATED / authorization=BLOCKED`。本地Docker config imageID不是Registry manifest，产品镜像未远端读回、签名/批准或发布；旧Registry测试不是该产品镜像绑定。镜像内真实SDK/Registry写链及自动刷新故障矩阵、独立来源/builder attestation/SBOM/多架构、正式安装/生产灰度与长期soak、企业治理/证书/完整网络功能仍缺。健康状态重开不证明坏盘自修或物理掉电恢复；D10证书反证是客户端零请求观察，无镜像内服务端独立计数器。原主入口默认、九项blocker、M2b/M3/M4及生产环境均未改变，未合并main，不提供整体完成率或可用率承诺。

## P0-d11 真实产品镜像与隔离受管Registry（2026-10-23归档）

最终代码 `3e766db7fd3aaa905abab0f439236a7fe91d021d` 的绑定39826356698/job119990563178、父39826356692/job119990563070均completed/success，主代理和独立代理实际重放最终49份关联输入、原700/Registry3/父各2320完整集合。两类真实测试签名/批准绑定本轮真实镜像：正常TLS上传后回拉原字节、config/layer/diffID/8打包文件关联、镜像内API消费/重放/篡改/交叉bundle、同容器重启、有效撤销/回滚拒绝/错误SPKI、健康双库重开全部通过；每类final seq44/journal10/audit20/ledger3，44独立流量快照中2次成功产品验证及18零HTTP窗口。4次产品正常退出0、Registry实际退出0、D11精确3容器及外层D10清理均PASS。五轮失败及其未知值边界保留，未删门换绿。详见[D11实际验收](P0D11-PRODUCT-REGISTRY-ACCEPTANCE.md)。

此阶段只补上D10缺口中的**真实产品镜像隔离Registry读回、测试authority签名/批准和镜像内SDK验证写链**，不等于正式来源或发布。仍 `authorization=BLOCKED / releaseAuthorized=false / deviceActionsExecuted=false`。自动撤销刷新/跨库异常恢复在该镜像内的故障矩阵、正式Registry发行与企业密钥/IdP/审批、独立builder/source证明/SBOM、多架构、生产灰度恢复/长期soak、坏盘自修/WORM/外部见证、完整主App/多内核/DNS/节点业务仍未完成。九项恢复blocker、旧Dockerfile/M2b、设备执行器和生产环境均不变；没有main合并或生产流量变化。

## P0-d12 前置机制历史轮605，产品生命周期当时未完成（2026-10-23）

605f67eb63b2a9c738ce703f9b6f78d7a71179b7的绑定39834169047/job120017946250、父39834169008/job120018134988均completed/success。主代理与独立代理分别下载151文件工件并复算：lease20、feed33、checker13项通过/0skip，8源文件及568+79=647条源码记录逐Git原bytes吻合；成功与已知失败轮的专用树清理均有原始结果。原700/Registry3/父2320、D11原49关联和浏览器40/45/45回归保留。已知d35目录错误分类失败保留，605只修具体错误枚举，不删门。[D12前置验收](P0D12-FIXTURE-PREFLIGHT-ACCEPTANCE.md)。

**状态仅为fixture prerequisites implemented+tested isolated-only，不是D12整阶段完成。** 实际产品尚未接这两个新fixture；自动刷新、镜像在途异常和预置中间态恢复矩阵仍待验，三个productProven字段明确false。无产品故障开关、运行逻辑变更、正式发布、main合并或生产操作；原企业功能、九项blocker和长期运行缺口不解除。

## P0-d12 自动刷新/正常重启镜像子门已验，异常矩阵仍缺（2026-10-23）

上节605为历史前置门范围。本轮957271a855fa19991b77ebd5b1d2a8e4200c0aa0的绑定39840587359/job120040237746、父39840587362/job120040240510均completed/success。真实默认入口产品镜像在独立正常TLS source/Registry下执行两类签名各18动作：未确认拒绝、自动更新撤销B、精确同代no-op、消费/重放、自然陈旧拒绝、恢复、同容器正常重启重新确认。主代理及独立子代理各下载217文件工件，64本门文件/65摘要关联与outcome重算相同；72计数快照、4成功产品读取/30零请求窗口、最终seq31/gen2/journal7/audit14/ledger2、4产品正常退出及3容器/2来源清理通过。来源各18完整响应/0未完整；停止窗口无新增事件，不宣称触发在途取消。

lease20/feed34/checker13、新profile5/verifier27均通过/0skip；旧700/Registry3/父2320及浏览器40/45/45保留，D11原49关联独立重放通过。655源码记录逐Git原blob一致；未放宽产品运行限制、修改时钟或新增产品故障开关。[D12实际镜像子门验收与剩余项](P0D12-PRODUCT-LIFECYCLE-ACCEPTANCE.md)。

**957历史轮状态仅为 actual automatic-refresh/graceful-restart subgate implemented+tested isolated-only。** 当时外部lease实际产品接线、异常终止/跨库补审计、六阶段健康中间态与损坏拒绝、追代/来源负矩阵/在途撤销仍未完成；后续三阶段verify子门进度见下一节。物理掉电、长期soak、正式authority/发行/灰度及原完整企业功能缺口不变；九项blocker不解除，未合并main、未部署或变动生产。

## P0-d12 三阶段verify中断恢复子门已隔离验收，完整矩阵仍缺（2026-10-23）

代码89dfade40f4cf916a6ee3ea6670a581c27338ff3，绑定39854485066/job120088990361、父39854486241/job120088994194均completed/success。实际默认产品镜像在独立正常TLS Registry和静态catalogue下执行PREPARED/RESERVED/CONSUMED×两签名：外部Linux租约、真实pidfd SIGKILL、首次恢复补审计、同容器二次重启幂等、原批准末次probe。六格cut seq2/4/5→首次恢复5/6/6→最终10/journal2/audit4；RESERVED与CONSUMED保持烧毁状态，原在途POST均无HTTP成功且只发一次。

主代理及两名独立代理各下载367文件工件并重算147本门文件/151摘要关系，与outcome相同。60计数快照，12恢复/二次启动零请求窗口，加四个拒绝probe共16零窗口；原请求SDK预算与排空单独核验。8条真实内核等待关系/16样本、6次137、12次正常0、Registry正常0与精确7容器/8helper/6请求进程join/清理通过。native14含真实foreign namespace只读alias回归，profile6/verifier27及原lease20/feed34/checker13均具名零skip；原700/Registry3/父2320、D11原49、D12原65及浏览器40/45/45保留。667源记录/584unique逐Git原bytes及before-after核对一致。

三轮失败分别留档：8b未取得helper根因、a415定位foreign bind失败、e3a完成六格但root0600计数文件交接失败；不补写旧报告或删断言。后续仅修测试屏障的跨namespace clone和受限计数读取，不修改产品运行逻辑。[三阶段实际验收及未完成项](P0D12-INTERRUPTION-ACCEPTANCE.md)、[失败记录](P0D12-INTERRUPTION-FAILURES.md)。

**状态仅为 actual three-stage verify interruption subgate implemented+tested isolated-only。** update/verify全部六阶段与损坏拒绝矩阵、自动刷新崩溃/撤销竞态组合、坏盘/断电、长期soak、正式身份/发行/恢复授权、生产灰度及原完整企业功能仍未闭合。仍authorization=BLOCKED、production=false、completeCrashMatrixProven=false，九项blocker不解除；未合并main或操作生产。

## P0-d12 预置状态启动矩阵已隔离验收，不冒充完整crash矩阵（2026-10-23）

上节为89dfade历史边界。本轮0633c4b6e94cc2c95071bfd195e052a3c173e5b9，绑定39860200458/job120108634673、父39860200452/job120108635009均success；主代理及两独立子代理分别下载1275文件工件并重算906本门报告/909输入关联一致。三lane/六健康/八拒绝/两签名的36健康与48拒绝格，每格独立store/grant/签名authority/container；72正常退出0、96自然拒绝1、672快照/168启动零请求窗口、24真实SDK seed及85所属容器精确清理通过。负类logical record摘要/journal/审计与坏checkpoint原字节不变，健康二启幂等，later-invalid在前项修复前整体拒绝。

实际Linux新8/32测试、旧700/race700/Registry3/race3/父2320每轮、浏览器40/45/45及native14/原前置门均保持；旧D11 49、D12 65、crash151关联重放通过。676源记录/591unique逐Git原bytes及before-after一致。[验收与证据](P0D12-STATE-MATRIX-ACCEPTANCE.md)、[固定矩阵协议](P0D12-STATE-MATRIX-PROTOCOL.md)。

**状态仅为 preseeded startup matrix implemented+tested isolated-only。** 此门不新增84次真实crash；早期持久语义重复不称独有状态。自动刷新实际崩溃/在途撤销竞态、来源负矩阵/追代组合、update等全实际中断边界、坏盘/断电/全盘回滚、长期soak、正式authority/发行/恢复授权和完整企业功能仍未闭合。仍authorization=BLOCKED、production=false、completeCrashMatrixProven=false；九项blocker不解除，未SSH、合并main或部署生产。

## P0-d12 自动刷新重复拒绝保护已隔离验收（2026-10-23）

ed756d74719891c2fc473b90867dbfda95f37f0c的绑定39865484513/job120126497803、父39865484625/job120126498445均success。发现并修复同一坏候选持续重试耗尽journal的实际缺陷：固定16槽/每次真实只读重验，首次完整拒绝审计，重复仍返回错误且不续Fresh，时间转有效后恢复原事务；不改变普通管理员Update。

新增Store8/product16/runtime4，ordinary/race各728项实际run/pass、0skip/fail，精确保留原700摘要，父各2320及Registry各3不变。主代理和独立子代理下载1275原工件，重放49/65/151/909关联与CI canonical相同；686条源记录/597unique逐Git原bytes一致，原镜像/浏览器/前置/清理门保持。[实际验收及未完成项](P0D12-REFRESH-REJECTION-ACCEPTANCE.md)、[实施协议](P0D12-REFRESH-REJECTION-GUARD.md)。

**状态仅为 rejection guard implemented+tested isolated-only。** 新4项是真实同进程正常TLS runtime来源/追代集成，不是新增Docker来源负矩阵；超过16种坏候选或重启仍可能增长journal，不宣称完整DoS防护。完整镜像来源拒绝/在途撤销/其他真实故障边界、长期soak及企业/生产闭环仍未完成；未改生产、main或正式发行，九项blocker不解除。

## P0-d12 异常来源fixture前置已隔离验收（2026-10-23）

57fd54c56a256da04ceb3f28e5450e56dab062a8的绑定39871985050/job120148358838、父39871985012/job120148358676均success。新fixture24项（8格式/16Linux）、checker32合成项具名0skip；34观测段/54连接/201事件/19wire经root及独立代理重算一致。40条HTTP阶段事件不等于40个成功HTTP，当前stall不证明产品timeout。旧728/race728/父2320/Registry3及全部49/65/151/909镜像门保持，695条/605unique源记录逐Git原bytes一致。[实际验收与未完成项](P0D12-SOURCE-FIXTURE-ACCEPTANCE.md)、[失败记录](P0D12-SOURCE-FIXTURE-FAILURES.md)。

**状态仅为 source fixture prerequisites implemented+tested isolated-only。** 产品运行逻辑未改；完整真实镜像来源拒绝/顺序追代/在途撤销尚未接入，单因TLS及probe污染窗口、真实timeout hold/屏障需继续完成。所有企业功能、长期soak、正式authority/发行、生产灰度及九项恢复blocker保持未闭合；无生产/main/正式Registry变更。

## P0-d12 真实产品异常来源第一批已隔离验收（2026-10-23）

上节57fd为历史前置范围。本批代码563e51aa855079ad7c0ffd7d830356e3a4cde6a2，绑定39877834480/job120167678960、父39877834614/job120167678578均attempt1/success。三个独立流程×两签名六格实际默认产品镜像，原始签名目录/原计划/来源JSONL/API/离线双库交叉重放：403后未确认或自然陈旧再恢复；坏签首拒绝后反复请求不追加journal/审计、不续Fresh再有效G2恢复；真实2.json的合法G2提交、坏G3拒绝且整批不确认，再有效G3恢复。各流程两格式最终分别seq1/J0/A0/G1、seq9/J2/A4/G2、seq13/J3/A6/G3，ledger均0，本门未调用SDK消费。

主代理及三名独立子代理分别下载1354原工件，重算新72工件/75输入关系和原49/65/151/909门；67条完整TLS/HTTP连接、268事件、18动作、10journal/20实际审计、36Registry快照/12运行及重开零请求窗口、6产品正常退出0/6来源TERM join0/7所属容器精确清理保持。原728/race728、父各2320、Registry各3、浏览器40/45/45均保留；新8profile/32verifier为合成检查器测试，不当产品业务证据。612checkout+92module＝704源记录，612唯一文件逐Git原blob一致，无CRLF归一化。[实际验收、原证据与未完成项](P0D12-PRODUCT-SOURCE-WAVE1-ACCEPTANCE.md)。

**状态仅为 actual-product source wave1 implemented+tested isolated-only。** 没有修改产品运行逻辑或生产服务。TLS CA/SAN/SPKI单因负矩阵、完整HTTP/帧/真实超时/hint/gap/fork/两类64及字节预算、来源重启、实际在途撤销内核屏障、其他异常恢复边界、长期soak、正式authority/发行/企业功能和生产灰度仍未闭合；不解除九项blocker，不承诺可用率或零bug。无SSH、main合并、正式Registry发布或生产变更。

## P0-d12 首次来源 TLS 故障与同进程恢复已隔离验收（2026-10-23）

上节为历史第一批范围。本批代码 b8abe163fdd40f0dffe327c97989cf6f858fb762，绑定 39883622207/job120186562390、父 39883621995/job120186561748 均 attempt1/success。CA/SAN/SPKI 单因故障×两签名六格，共 12 条故障来源连接/0 HTTP/API 未确认，正常来源 6 条完整原 G1 HTTP 后同产品 PID/startTime/二进制/两配置摘要恢复 Fresh。每格 G1/sequence1/J0/A0/L0，初始/最终实际逻辑记录、审计日志和 checkpoint 原摘要不变。18 连接/60 事件、24 动作、114 自有工件/117 输入关系、48 Registry 快照/18 零请求窗口、7 容器/12 来源/6 产品正常退出与精确清理独立复算通过。

主代理及三名独立子代理分别下载 1470 原工件，OpenSSL 与另写 Node X.509/Ed25519 交叉验证原证书/目录/批准和实际 API/fence，不从 TLS failed 枚举单独归因。原五门 49/65/151/909/75 与新增 117 的 CLI 结果均与原 CI outcome 逐字相同；普通/race 各 728、父各 2320、Registry 各 3 和浏览器 40/45/45 保留。新 profile8/checker32 是合成反例，实际 Linux 0skip，不能当 40 项产品业务。619checkout+94module＝713 记录/619unique 逐 Git 原 blob 匹配，前后原清单相同，无 CRLF 归一化。[原始证据和边界](P0D12-PRODUCT-SOURCE-TLS-ACCEPTANCE.md)。

**状态仅为 initial-source-TLS rejection/recovery implemented+tested isolated-only。** 已确认后的 TLS 陈旧、在线轮换/冷确认、完整来源/超时/预算、真实在途撤销及消费后屏障、长期 soak/正式发行/生产灰度仍未完成。主服务仍未接入主动 probe 读回，控制台仍含明确 demo，编译不是完整可运行配置，publish 不下发设备，executor 仍缺失；订阅、DNS、多内核、自动修复和企业闭环不能被本批测试替代。下一产品主线为[真实探针只读 API/工作台接入（设计态）](P1-PROBE-READBACK-INTEGRATION-PROTOCOL.md)，再推进订阅准入/完整配置与实验设备发布回滚。未动生产、main 或正式 Registry，不解除九项 blocker。
