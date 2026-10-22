# 澄网 · 网络自治中心

澄网是一套独立于 OpenClash/LuCI 的多内核网络代理、策略路由与自治控制系统。它参考成熟代理软件的能力，但拥有自己的领域模型、可插拔内核适配层、版本管理、可解释精确路由、节点能力评估和中文管理界面。

当前源码阶段是 **可离线运行、可选连接 Mihomo 只读控制器，并带受保护本地操作记录的 Shadow 控制面基础版**：

- 默认只监听 `127.0.0.1:7811`。
- 默认运行在 `shadow` 模式，不接管生产流量。
- 未设置管理员令牌时，发布接口保持关闭。
- 可以读取系统快照、编辑策略草稿、校验并编译为 Mihomo 兼容片段。
- 已建立多内核适配器注册表和可解释路由引擎；sing-box、Xray 的真实编译器尚未接入。
- 可通过 Mihomo Controller API 只读获取版本、运行配置摘要、策略组和规则，并与策略草稿执行读回对账。
- 可通过能力事实接口区分生产只读、本地实现、仅设计和受阻能力，避免把页面占位或设计文档误报为生产完成。
- 可选加载只保存 SHA-256 摘要的静态高熵 Bearer 身份文件，并以默认拒绝的角色、租户、站点、对象和环境范围策略保护本地操作接口。
- 本地操作库使用 schema v2 原子快照，持久绑定发起人和审批人；schema v1 只能迁移为 `legacy_unbound` 并冻结，系统不会猜测旧身份。
- 操作创建和有限状态转换采用前置/结果证据、幂等键和 `commit_unknown` 语义；所有接口只记录本地 Shadow 状态，不执行设备动作。
- M2b-0 已在本地实现默认关闭的主动探针执行链：命令入口、严格许可目录、固定 DoT、安全解析/固定拨号、业务分类、耐久启动账本、有界调度、独立 spool、去敏聚合和仅反映进程/调度/时钟/存储的健康协议。M2b-1 已有默认不启动的隔离容器候选文件，但当前开发机未完成 Docker 构建或运行验收，出口和 canary 仍被阻断；没有 API、控制面挂载或生产部署。
- 主动探针状态校验新增显式生命周期的 `LockedStateSnapshot`：按 spool→ledger 获取既有写锁，报告读取前重新核对锁路径与完整状态树，失败后永久失效，并在关闭时逆序释放。它仍是 process-local、依赖协作式文件锁的 advisory 只读原语；`Verify` 与外部消费者动作之间仍存在边界外 TOCTOU，且尚未接入恢复协调器，也不证明 Docker 当前镜像、Compose、拓扑或 live 容器身份。
- 每次发布都使用乐观锁和原子版本存储，为后续灰度、回滚和设备适配器留出明确边界。
- image-trust 候选已实现受保护的可信策略、撤销/防回放 API、固定来源自动刷新、健康两库间的审计补投递，以及只读状态/操作记录控制台；新增显式完整产品候选入口，共用主服务 runtime、基础产品 API 与审计，并通过正常浏览器 HTTPS/证书拒绝验收。**原主入口默认仍不注入 trust backend，未部署生产**。见 [P0-d7](docs/P0D7-REFRESH-RECOVERY-ACCEPTANCE.md)、[P0-d8](docs/P0D8-TRUST-CONSOLE-ACCEPTANCE.md)、[P0-d9 验收](docs/P0D9-PRODUCT-HTTPS-ACCEPTANCE.md)及[完整候选操作说明](docs/PRODUCT-CANDIDATE-OPERATOR-NOTES.md)；这不是全企业功能已完成或发布授权。
- P0-d10 新增独立scratch产品候选镜像，已在隔离CI实际执行镜像默认程序、正常HTTPS浏览器、停止重开、同状态重启读回与4类失败关闭；原回归保留。**只证明该候选实际构建/运行，不是已签名发布或生产上线**；本地imageID不是Registry manifest，旧Dockerfile/M2b门与九项恢复blocker不解除。见 [D10验收与未完成项](docs/P0D10-IMAGE-RUNTIME-ACCEPTANCE.md)。
- P0-d11 已让同轮真实镜像完成隔离Registry正常TLS回拉、两类测试签名/批准、镜像内真实API消费、撤销、防回放与同容器重启，最终49份证据关联及精确清理独立重放通过。**测试authority不是正式发行或上线授权**；自动刷新/跨库故障矩阵、企业密钥与正式发布仍待完成。见[D11实际验收与边界](docs/P0D11-PRODUCT-REGISTRY-ACCEPTANCE.md)。
- P0-d12 正补自动刷新/异常恢复的独立 Linux 测试机制：低权限 TLS 来源与外部文件租约屏障。**前置机制通过不等于真实镜像生命周期已验收**；实际镜像自动刷新和故障矩阵仍待接线，见[D12分层合同](docs/P0D12-LIFECYCLE-CONTRACT.md)。

> 源码实现不等于生产能力已经开放。`10.88.0.254` 已部署并验收默认锁定的 Shadow 操作 API 与“操作中心”，但没有配置身份文件，`CHENGWANG_OPERATION_WRITES_ENABLED=false`，也不存在设备执行器；因此线上只证明失败关闭、只读读回和界面边界，未形成生产写入闭环。见 [10.88.0.254 部署记录](docs/DEPLOYMENT-10.88.0.254.md)。

## 本地启动

```powershell
cd chengwang
go test ./...
go run ./cmd/server
```

另一个终端启动前端：

```powershell
cd chengwang/web
npm install
npm run dev
```

浏览器访问 `http://127.0.0.1:5173`。Vite 会把 `/api` 代理到 Go 服务。

## Docker 部署

仓库根目录提供单容器 `Dockerfile` 和 `compose.yaml`。容器同时提供前端与 API，固定以非 root 用户、只读根文件系统和 `shadow` 模式运行；详细备份、验收和恢复步骤见 [Docker 部署与恢复](docs/DOCKER-DEPLOYMENT.md)。

## 启用 Mihomo 只读读回

默认不连接任何设备。需要读回隔离环境中的 Mihomo 时，在启动控制面前设置：

```text
CHENGWANG_MIHOMO_URL=http://127.0.0.1:9090
CHENGWANG_MIHOMO_TOKEN=<保存在本机环境变量中的控制器令牌>
```

匿名最小状态接口：

```text
GET  /api/v1/capabilities
GET  /api/v1/kernels/mihomo/status
GET  /api/v1/attestation/shadow
```

受身份和管理范围保护的诊断接口：

```text
GET  /api/v1/evidence/integrity
GET  /api/v1/versions
GET  /api/v1/kernels/mihomo/runtime
POST /api/v1/kernels/mihomo/readback
```

`capabilities` 是当前可执行能力的事实清单；它同时披露每项能力的证据入口和限制，不是产品路线图完成度，也不代表端到端业务可用率。

`evidence/integrity` 只返回本机证据日志的哈希链与 checkpoint 校验结果，不返回事件正文。证据库支持幂等追加、单写者锁和异常写入后的 poison/fail-closed；`checkpoint_stale` 需要人工核查恢复，不会自动采信额外日志尾部。它仍是单机防误改基础，不是 WORM、独立副本或企业审计闭环，也没有自动记录全部 HTTP 请求。

`readback` 请求体为策略草稿，响应会报告策略组缺失、成员或顺序漂移、域名规则缺失和规则目标漂移。该适配器只调用 Mihomo 的 `GET /version`、`GET /configs`、`GET /proxies` 和 `GET /rules`，不会重载配置、切换节点、清理缓存或重启内核。详细契约见 [Mihomo 只读适配器](docs/MIHOMO-READONLY-ADAPTER.md)。

可以从独立客户端运行只读验收器，执行 6 项检查：健康、HTTP 安全头、能力事实、持续被动观测真实性、operations 失败关闭和最小 Shadow 证明。验收器不携带凭据、不读取敏感运行态，也不会调用写接口：

```powershell
go run ./cmd/verify-shadow -base-url http://<CONTROL-PLANE-IP>:7811 -timeout 20s -expected-capabilities 16
```

退出码 `0` 表示全部检查通过，`1` 表示至少一项检查失败，`2` 表示参数或验收器本身出错。输出是可保存的 JSON 证据，但生成时间来自验收客户端本机，并不是可信时间戳。

## 启用本地 Shadow 操作接口

源码提供以下受保护接口：

```text
GET  /api/v1/operations
POST /api/v1/operations
POST /api/v1/operations/{id}/transitions
```

它们要求 `CHENGWANG_IDENTITIES_FILE` 指向权限严格的身份文件；写请求还必须显式设置 `CHENGWANG_OPERATION_WRITES_ENABLED=true`。默认未配置身份文件且写开关为 `false`，因此接口保持关闭。即使启用，响应也会明确返回 `effect=local_record_only`、`deviceActionsExecuted=false`，并禁止进入执行、验证、观察或终态；没有设备执行器，也不会修改 OpenClash、Mihomo、DNS、路由或防火墙。

身份文件只存高熵 Bearer 的 SHA-256 摘要，目录在 Linux 上必须为 `0700`、文件为 `0600`，且不能经过符号链接。任何 Bearer 身份或管理员令牌启用时，服务必须使用原生 TLS，或只监听本机回环并由同机 HTTPS 反向代理接入；浏览器会在局域网明文 HTTP 页面直接锁住令牌输入。它不是密码库、JWT、会话、MFA、SSO 或轮换服务。详细配置、占位符请求示例、备份和恢复步骤见 [Docker 部署与恢复](docs/DOCKER-DEPLOYMENT.md)。

## 安全地启用发布

只有在完成隔离环境验收后，才可以同时设置：

```text
CHENGWANG_MODE=staging
CHENGWANG_ADMIN_TOKEN=<本机生成的高强度随机值>
CHENGWANG_ALLOW_PUBLISH=true
```

发布请求还必须携带当前版本的 `If-Match`，避免旧页面覆盖新配置。当前版本只写入本地版本库，不连接路由器。

## 目录

```text
cmd/server          HTTP 服务入口
cmd/verify-shadow   无凭据、只读的 Shadow 运行时验收器
cmd/probe-agent     默认关闭的主动探测命令与严格进程健康协议（未部署）
internal/domain     独立领域模型
internal/policy     策略校验与编译
internal/routing    精确分流和命中证据
internal/kernel     多内核能力与适配器注册表
internal/store      原子版本库
internal/authn      静态 Bearer 摘要身份文件
internal/authz      默认拒绝的角色、职责分离与范围授权
internal/operation  schema v2 耐久状态机、身份绑定、幂等与单写者锁
internal/evidence   幂等追加、哈希链、checkpoint、单写者与失败关闭
internal/control    授权、操作和前置/结果证据协调（不执行设备动作）
internal/truth      期望、实际、观测三态与新鲜度门禁
internal/observation 周期只读观测、分层未知语义与有界摘要历史
internal/api        安全 API 与演示快照
web                 React + Vite 中文控制台
docs/design         视觉设计基准
```

## 设计文档

- [企业智能网络平台功能基线 v1.0](docs/FUNCTIONAL-BASELINE-v1.0.md)：大型企业目标范围、系统分层、功能边界、故障模型、发布状态机和验收标准。
- [人性化操作与系统闭环设计 v1.0](docs/UX-AND-CLOSED-LOOPS-v1.0.md)：角色与设备自适应、统一任务工作台、关键操作流程、系统闭环和闭环验收标准。
- [自治运维与主动排错方案 v2.0](docs/AUTONOMOUS-OPERATIONS-v2.0.md)：运行自知、世界模型、故障假设、主动取证、受控修复、独立验证、自主学习和失控保护。
- [企业级闭环补强方案 v2.1](docs/ENTERPRISE-CLOSED-LOOPS-v2.1.md)：平台升级、跨系统事务、回滚失败生存、交互安全、数据隐私、审计防篡改、AI生命周期、独立监测和管理权恢复。
- [操作详情与执行时间线交互规格 v2.1](docs/OPERATION-DETAIL-INTERACTION-v2.1.md)：选定方案2的页面结构、状态模型、权限、敏感信息和验收规则。
- [系统完成度与闭环差距审计](docs/SYSTEM-COMPLETION-GAP-AUDIT.md)：当前可验收能力、P0/P1/P2 缺口、统一验收门、回滚门和四个实施里程碑。
- [M2a 持续被动观测](docs/M2A-PASSIVE-OBSERVATION.md)：周期只读、分层未知语义、持久化边界、安全门和生产浸泡条件。
- [M2b 主动路径与业务探针](docs/M2B-ACTIVE-PROBES.md)：隔离执行器、严格许可目录、SSRF/重绑定防护、分层业务语义、资源预算和分阶段验收。
- [产品规格](docs/PRODUCT-SPEC.md)：多内核代理与精准分流的产品能力。
- [架构边界](docs/ARCHITECTURE.md)：控制面、数据面、适配器和当前实现状态。

## 尚未接入生产的能力

- Mihomo 配置下发、灰度、写后读回、回滚和路由器生命周期适配
- 订阅抓取与隔离准入
- DNS 代理和缓存进程
- 主动探测的候选机运行、唯一出口、自有 canary、控制面只读接入和生产 Shadow
- 自动修复执行器
- 企业 IdP、会话、MFA、令牌轮换与独立审计身份源

这些能力必须在后续阶段分别实现、故障注入、灰度验证，不能通过复用演示数据宣称已完成。

仓库中的主动探测容器 profile、blocked 示例和离线校验器只用于 M2b-1 候选准备。它们默认不启动，隔离网络当前不具备公网出口；静态校验通过不等于镜像已构建、容器已运行、出口已证明或业务已验证。

M2a 源码已实现 Mihomo Controller 的周期只读采集、单一共享读取门、4096 个原子小段组成的有界摘要历史、证据 TTL、时钟回拨门禁、跨进程单写锁、匿名最小状态接口和受保护历史接口。它不会测速、访问第三方业务、切换节点或修改 OpenClash。节点技术能力、互联网、业务和 DNS 仍明确为 `unknown`；这只是持续被动观测底座，不是完整 M2，也不是节点能力评估完成。

M1 已新增静态身份认证、默认拒绝授权、schema v2 耐久操作库、前置/结果证据协调、证据幂等和三态真值门禁及 race 测试。2026-10-18 已把默认锁定的 Shadow 操作 API 与“操作中心”部署到 `10.88.0.254:7811`；生产未配置身份文件、写开关为 `false`、设备执行器不存在，因此认证和操作能力仍如实显示为 `blocked`。这次部署只增加安全失败关闭的本地控制面基础，不代表生产写入、企业治理闭环或 `99.999999%` 可用率。
