# SYS-01–30 功能基线事实核对（只读）

- 核对对象：`D:/CodexData/workspace/chengwang-unified-root-20261102-r2m_22eh/r`
- Git commit：`8e5fd014ed3858b25593142dece069b6f1ea7769`
- Git tree：`35f812d7cb15a178c7576339e207d40280d966a8`
- 工作树：本次核对时 tracked files clean
- 日期：2026-11-03
- 结论边界：这是源代码与文档事实基线，不是编译、Go 测试、隔离运行、生产部署或全产品验收。
- 状态规则：测试列的“有”只表示测试源码存在，本次未执行；运行或生产原件缺失时写 `unknown`。历史隔离证据不能迁移为当前生产证据。
- 总控证据：`chengwang/docs/LIVE-TASKS.md:286` 明确 SYS 表只是执行索引，不代表模块全部实现；`:323` 要求先取得实际结果，缺证据继续保持待补验/待完成。

| SYS | 需求／包 | 设计证据 | 当前实现与源码位置 | 源码测试（仅存在性） | 隔离 runtime 证据 | 生产证据 | 明确缺口 |
|---|---|---|---|---|---|---|---|
| 01 | 功能事实清单；页面/API/运行态对账 | `LIVE-TASKS.md:290` | 部分：能力注册 `internal/capability/registry.go:14,24,33`；Web 入口 `internal/webui/handler.go:16`；事实决策 `internal/truth/decision.go:17,25` | 有：`internal/capability/registry_test.go:8`、`internal/webui/handler_test.go:12` | 文档仅称本地能力页与 CPU 检查；真实浏览器/runtime = unknown | unknown | 全页面、API、运行态逐项闭环；真实浏览器与真实后端证据 |
| 02 | 后端控制面、RBAC、审计、耐久状态异常矩阵 | `LIVE-TASKS.md:291` | 部分：控制服务 `internal/control/service.go:26,139,167`；RBAC 模型 `internal/authz/model.go:69,80,102,151`；证据存储 `internal/evidence/store.go:69,95,107`；耐久操作 `internal/operation/file_store.go:73,91` | 有：`internal/control/service_test.go:125`、`internal/authz/policy_test.go:12`、`internal/evidence/store_test.go:20` | 当前 exact-head 端到端异常矩阵 = unknown | unknown | 跨库异常、轮换、恢复、背压、资源边界全矩阵 |
| 03 | 完整订阅 B01–B23 | `LIVE-TASKS.md:292` | 部分：存储 `internal/subscription/store.go:36`；模型 `internal/subscription/model.go:56,180,193`；服务 `internal/subscriptionctl/service.go:34,76`；合同 `internal/subscriptionctl/contract.go:64,90,112` | 有：`internal/subscription/pipeline_test.go:19` 及 subscription/ctl 多个测试文件 | 当前完整 B01–B23 真实 runtime = unknown | unknown | 真实分页、多源、坏数据、写门、重启持久化、scope/owner 拒绝与移动操作 |
| 04 | 1/N 识别、转换、去重、隔离、安全刷新 | `LIVE-TASKS.md:293` | 部分：抓取策略 `internal/subscription/fetch.go:30,42,63`；刷新状态/租约/账本 `internal/subscription/refresh.go:74,123,154,185,227,240`；控制合同 `internal/subscription/control.go:80,88,101,117,146` | 有：`internal/subscription/refresh_test.go:148` 等 | 自动调度和真实失败链 = unknown | unknown | 真实失败保留 LKV、来源变化、回退、自动调度闭环 |
| 05 | 完整配置编译、冲突/遮蔽、业务自定义分流 | `LIVE-TASKS.md:294` | 部分：策略模型 `internal/domain/model.go:16,24,39,46`；校验 `internal/policy/validate.go:15`；Mihomo 片段编译 `internal/policy/compile.go:15`；路由引擎 `internal/routing/engine.go:11,16,45` | 有：`internal/policy/validate_test.go:22`、`internal/routing/engine_test.go:25` | 完整目标配置与真实内核链 = unknown | unknown | 冲突/遮蔽全检、规则顺序、DNS 与出口一致性；片段编译不能代替完整配置 |
| 06 | Mihomo 写适配器与发布生命周期 | `LIVE-TASKS.md:295` | 已有受限实现：只读 client `internal/adapter/mihomo/client.go:105,180,275`；写 client `internal/adapter/mihomo/write_client.go:80,106,174`；实验 backend 明示非生产边界 `internal/mihomodeploy/lab_backend.go:11,20,31` | 有：`internal/adapter/mihomo/write_client_test.go`、`internal/mihomodeploy/*_test.go` | 文档称 normal/UNKNOWN/旧 S2/首次 Completion 四模式“限定隔离通过”；不外推 | unknown；生产写门默认关闭 | 产品恢复 API、普通 epoch 接续、第二恢复、完整故障矩阵、生产灰度 |
| 07 | sing-box 实际适配器 | `LIVE-TASKS.md:296` | 仅通用内核接口/注册表：`internal/kernel/registry.go:17,23,30,36`；bounded inventory 未发现 sing-box adapter 源目录 | 未发现对应 actual-adapter 测试 | unknown | unknown | 版本协商、编译、真实进程、协议兼容、读回、回滚 |
| 08 | Xray 实际适配器 | `LIVE-TASKS.md:297` | 同 SYS-07：仅 `internal/kernel/registry.go:17,23,30,36`；未发现 Xray adapter 源目录 | 未发现对应 actual-adapter 测试 | unknown | unknown | 完整生命周期与真实协议矩阵 |
| 09 | 正向代理接口与代理服务端 | `LIVE-TASKS.md:298` | 模型/校验：`internal/domain/model.go:98`；`internal/proxyiface/validate.go:12,14,27,33`；API 只见接口/校验入口 `internal/api/server.go:243,253` | 有：`internal/proxyiface/validate_test.go:19,30,40,48` | 实际 listener = unknown | unknown | 监听、账号/ACL、证书、限额、审计、防火墙边界 |
| 10 | 自建节点与协议扩展 | `LIVE-TASKS.md:299` | 只见通用 kernel 注册扩展面 `internal/kernel/registry.go:30,36,43`；未发现自建私有协议实现 | 专属互通测试未发现 | unknown | unknown | 互通、认证、密钥轮换、兼容、安全评估；不得承诺规避识别 |
| 11 | DNS 数据面、缓存、内部/国内/境外路径 | `LIVE-TASKS.md:300` | 只见 DNS 策略数据结构 `internal/domain/model.go:46`；未发现完整 DNS data-plane 包 | 完整 DNS data-plane 测试未发现 | unknown | unknown | 独立版本/回滚、缓存、DNSSEC、双栈、上游故障恢复 |
| 12 | DNS 泄漏、绕过、解析/流量出口一致性 | `LIVE-TASKS.md:301` | 只见探针 DNS 解析安全结构 `internal/probe/security.go:20`；未发现端到端 DNS/egress 验证器 | 对应端到端测试未发现 | unknown | unknown | 终端→网关→DNS→出口实测；内部权威域与恢复路径 |
| 13 | 节点能力、业务可用性、稳定性评估 | `LIVE-TASKS.md:302` | 探针底座：`internal/probe/store.go:21,26,37`；调度 `internal/probe/scheduler.go:28,39,52,79,104`；状态校验 `internal/probe/state_validation.go:27,48,88` | 有：`internal/probe/scheduler_test.go:12,42,243,295` 等 | 文档只认“探针底座”；真实公共业务与长期历史 = unknown | unknown | 丢包/抖动/TLS/HTTP/出口身份/业务、TTL/置信度、历史结果闭环 |
| 14 | 专用池、空池、固定出口、防抖切换 | `LIVE-TASKS.md:303` | 可复用策略/路由/节点池模型：`internal/domain/model.go:24,39`、`internal/routing/engine.go:45`；未见完整自治切换器 | 只有策略/路由局部测试 | unknown | unknown | 基于 SYS-13 的过期/冲突证据处理；支付/交易固定出口；空池与防抖 |
| 15 | 反向代理与 API 网关 | `LIVE-TASKS.md:304` | bounded inventory 未定位专属 gateway/reverse-proxy 实现；现有 API server `internal/api/server.go:32,98` 不能代证 | 专属测试未发现 | unknown | unknown | TLS/mTLS、轮换、路由、限流、熔断、灰度、审计 |
| 16 | 隧道与零信任 | `LIVE-TASKS.md:305` | 未定位专属 tunnel/zero-trust data plane | 专属测试未发现 | unknown | unknown | 身份、设备姿态、应用授权、重叠网段、泄漏与恢复 |
| 17 | 多节点/站点管理与 SSH 部署 | `LIVE-TASKS.md:306` | deploy 下存在候选脚本/场景目录，但未定位产品级多主机管理器；不得把 deploy candidate 当产品上线 | 产品级多站点 E2E 未发现 | unknown | unknown | 主机身份、最小权限、幂等安装、受限执行、版本读回、独立恢复、凭据保护 |
| 18 | 自主诊断与受控自动修复 | `LIVE-TASKS.md:307` | 操作/恢复协调底座：`internal/operation/model.go:52,63,73`、`internal/restorecoordinator/coordinator.go:45,57,148,193`；未见完整自主执行器 | 有局部 store/coordinator 测试，如 `internal/restorecoordinator/coordinator_test.go:213` | 自主闭环 = unknown | unknown | 事件→计划→预算→执行→独立验证→回滚；冷却/抑制/冻结/不可达恢复 |
| 19 | AI 建议、学习、受控执行 | `LIVE-TASKS.md:308` | 未定位产品 AI/learning 包或受控执行桥 | 专属测试未发现 | unknown | unknown | 数据脱敏、来源证据、注入防护、审计、审批；AI 不替代业务证据 |
| 20 | 企业身份、多租户、组织、委派 | `LIVE-TASKS.md:309` | 本地身份 `internal/authn/store.go:79,86,102,109`；RBAC `internal/authz/model.go:69,80,102,151` | 有：`internal/authn/store_test.go:19`、`internal/authz/policy_test.go:12` | 企业 IdP/多租户 runtime = unknown | unknown | IdP/SSO/MFA、会话撤销、租户数据/密钥隔离、配额、紧急访问 |
| 21 | 操作记录、统一遥测、证据导出 | `LIVE-TASKS.md:310` | 操作 `internal/operation/model.go:52,63,73`；证据 `internal/evidence/store.go:69,95,107`；观测存储 `internal/observation/store.go:40,56,117,176`；签名 `internal/attestation/attestation.go:54,68,87,197,218` | 有：operation/evidence/attestation 测试；`internal/evidence/store_test.go:20`、`internal/attestation/attestation_test.go:18` | 统一集中链 = unknown | unknown | 谁/为何/做什么/实际/验证/回滚；脱敏、独立验签、集中保管 |
| 22 | 告警去重、抑制、升级、恢复通知 | `LIVE-TASKS.md:311` | 未定位专属 alert/escalation/channel 产品包 | 专属测试未发现 | unknown | unknown；且文档明确未授权微信推送 | 真实故障/恢复事件、渠道权限、限流、审计 |
| 23 | 全功能真实 UI、拓扑、操作闭环 | `LIVE-TASKS.md:312` | 工作台/API 入口：`internal/webui/handler.go:16`、`internal/api/server.go:98,170,243`；deploy 中存在 browser-scene 候选场景 | 有：`internal/webui/handler_test.go:12,18,59`；候选 browser checker 不等于产品验收 | 真实浏览器+真实 backend 全页面 = unknown | unknown | 所有页面接真实后端；拓扑 hover/详情、权限、恢复、键盘/读屏/视口/反馈 |
| 24 | HA、主备、脑裂保护、独立故障域 | `LIVE-TASKS.md:313` | 未定位 HA controller/quorum/fencing 产品实现 | 专属测试未发现 | unknown；环境未具备 | unknown | 单控制器不能冒称 HA；管理路径、状态业务和故障域演练 |
| 25 | 供应链、签名、撤销、正式发行 | `LIVE-TASKS.md:314` | 签名/防回放底座 `internal/attestation/attestation.go:54,68,197,218,291,303`；镜像信任合同 `internal/imagetrust/contract.go:49,57,124,133,148`；deploy/m2b-candidate 有候选检查器 | 有：`internal/attestation/attestation_test.go:18`、`internal/imagetrust/contract_test.go:9` | 文档仅称“已有隔离验收”；不可迁移为正式发行 | unknown | 企业密钥、轮换/故障/来源矩阵、依赖审查、正式 Registry 与 release |
| 26 | 整套备份与恢复演练 | `LIVE-TASKS.md:315` | 局部恢复组件：`internal/restorecoordinator/coordinator.go:45,57,148,193` 及多个 restore* 包；局部 evidence existing snapshot `internal/evidence/archive_existing.go:18,25,34,48,61` | 有局部恢复测试：`internal/restorecoordinator/coordinator_test.go:213` 等 | 整套一致恢复/RPO/RTO = unknown | unknown | 配置、状态、身份引用、任务、证据一致恢复；实测 RPO/RTO |
| 27 | 全系统性能、容量、故障、长期浸泡 | `LIVE-TASKS.md:316` | deploy 下有 mihomo-capacity-fixture/profile/lifecycle-lab 候选；它们不是全系统运行态 | 有候选 fixture/checker 源码；本次未执行 | 全系统 soak = unknown | unknown | 端到端资源背压、断网/崩溃/磁盘满/依赖异常、长期趋势 |
| 28 | 小范围生产灰度 | `LIVE-TASKS.md:317` | 只有计划/候选工具，不构成授权 | 不适用 | 未授权 | 未授权/unknown | 前置验收、明确目标、备份、回滚包、独立恢复、停止条件；须先通知用户 |
| 29 | 生产读回与实际业务验收 | `LIVE-TASKS.md:318` | 存在 Mihomo 只读 client `internal/adapter/mihomo/client.go:180,275` 和 API readback 入口 `internal/api/server.go:310`，但不是当前生产验收 | 局部 client 测试存在 | 当前 exact-head 生产读回 = unknown | 未授权/unknown | 版本、配置、权限、DNS、路由、出口、真实业务逐项核对；CI 不能代证 |
| 30 | 升级、回滚、故障处置、运营手册 | `LIVE-TASKS.md:319` | 文档与局部恢复/部署候选存在；未形成已签署的全产品运营闭环 | 局部脚本测试/恢复测试存在 | 全流程演练 = unknown | unknown | 可执行手册、证据路径、回滚/救援演练、交接和验收签署 |

## 横向结论

1. **不是“30 包已完成”**：当前可确认的是控制面、订阅、Mihomo 实验生命周期、探针、身份/审计、恢复与供应链等若干底座；SYS-07/08、11/12、15/16、19、22、24 等仍没有对应完整产品实现。
2. **源码测试存在不等于本次通过**：本核对禁止 Go 和长套件，所有测试状态仅为“源码存在”。编译、测试执行、Linux UID/runtime 与浏览器结果均未在本次产生。
3. **隔离证据不等于生产**：SYS-06 和 SYS-25 的文档有受限隔离证据，但生产仍为 unknown；SYS-28/29 仍待授权。
4. **当前阻断修复不是全项目完成**：即使当前 source gates/CI 修复全部通过，仍需按 SYS-01–30 的缺口继续产品实现与分层验收。
5. **优先顺序建议（仅事实导向，不执行）**：先完成 SYS-01 能力真值闭环；再补 SYS-05/06/07/08/11/12 的真实数据面；随后 SYS-13/14、15/16/17、20–25；最后 SYS-26/27 与经授权的 SYS-28/29/30。

## 有界核对方法

- 只读：`git rev-parse`、`git status --porcelain`、`rg --files`、`rg -n`、指定行读取。
- 未运行：Go/gofmt、产品进程、网络、浏览器、Linux UID、生产服务、部署脚本。
- 未读取：凭据、私有 payload、原始运行日志。
- “未发现”仅限本次 bounded inventory，不能证明宇宙意义上的绝对不存在；它准确表示在上述 commit 的目标目录和已定位源路径中未找到相应产品实现。
