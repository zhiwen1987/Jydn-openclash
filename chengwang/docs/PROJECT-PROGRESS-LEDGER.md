# 澄网项目进度台账

更新日期：2026-10-23。开发分支：`codex/chengwang-security-hardening`。后端原生验收源码：`700ea9ed2f58b267d1530ffcacc0a3f3cdba2dbb`；能力事实同步源码：`2fe1231de851417e7825b9c8b02083acf1ad08f3`。本台账由单一集成者按实际证据更新，不是产品自动生成的完成率。

当前结果：`cadb9f4b5ecf63f3bf1556ffe61ed274d304c0a2` 的 CDP 与原生 Playwright 已分别完成真实浏览器闭环及原 ZIP 独立重放，正常 TLS、实际证据读回/自然过期、8 错误计数全 0、Node/Chrome 正常退出均通过；父门及原生后端也已独立复验。镜像信任绑定 CI 已 success，前端 117/117、子模块 ordinary/race 各 732、旧基线和源码绑定已独立核验；未逐一独立重放全部旧产品子 CLI。摘要单飞与超时/迟到结果所有权修复通过本轮，但不据此声称已唯一证明历史取消根因。详见[双浏览器验收记录](P1-PROBE-BROWSER-ACCEPTANCE.md)。未修改生产、未合并 main、未正式发布镜像。不将测试数量折算为整个企业系统的完成百分比。

## 当前阶段进度

| 编号 | 交付项 | 实际状态 | 证据与剩余边界 |
| --- | --- | --- | --- |
| P1-01 | 安全 reader、缓存、匿名摘要与 RBAC 明细 | 已实现并隔离验收 | [基础接线验收](P1-PROBE-READBACK-ACCEPTANCE.md)；默认关闭，不等于生产已启用 |
| P1-02 | 真实 agent 经正常 DoT/HTTPS 写入结果 | 已实现并隔离验收 | 两轮 6 个原始结果，ledger 7/13 联合结算；[本阶段证据](P1-PROBE-NATIVE-BACKEND-ACCEPTANCE.md) |
| P1-03 | 真实主 API、重启读回、自然过期 | 已实现并隔离验收 | fresh/重启均读回 6 样本；到期后 0 样本、3 目标 unknown；源数据不变 |
| P1-04 | 独立检查器与失败关闭反例 | 已实现并隔离验收 | 44 辅助检查、24 wire 前置检查；原始 22 输入独立重放，失败历史保留 |
| P1-05 | 原有后端回归 | 已复验 | 最新 `cadb9f4` ordinary/race 均各 2403 Test run/pass；新增 12 项实际执行，旧 2391/2320 名单哈希均保留；各 12 Fuzz 另计 |
| P1-06 | 控制台探针页面 | 已实现并隔离验收 | `cadb9f4` 的真实 API/正常 TLS 浏览器读回、清除及过期交互通过；本地及隔离 CI 的 117 模拟前端测试通过，其中新 7 项单飞反例；CI 原名单/增量检查门独立复核通过，模拟测试不代替真实浏览器 |
| P1-07 | 正常 TLS 浏览器展示真实 runID 与过期状态 | 两路径均已独立隔离验收 | `cadb9f4` 的 [39925504923](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39925504923) CDP/PW 原 ZIP、精确 Git checker、后端 22 输入均独立重放通过；每引擎 18 捕获、8 错误计数全 0、实际正常退出，完整摘要见[验收记录](P1-PROBE-BROWSER-ACCEPTANCE.md)。不代表公网、生产、其他浏览器或整套企业产品已验收 |
| P1-08 | 机器能力事实清单与新探针状态同步 | 已实现并隔离验收 | 默认 blocked，配置后仅 implemented_local；匿名清单不调用 probe reader；完整业务评估保持 design_only；4 API＋8 registry 测试实际执行；`2fe1231` 阶段父门/原生/镜像 CI success 是历史证据，不替代本轮镜像回归 |
| P1-09 | 生产挂载、授权、公网业务与观察窗口 | 未执行 | 需要另行授权、备份及可验证回滚；本实验没有公共互联网出口 |

## 整套系统交付台账

### P2 当前增量：订阅准入底座

本阶段[实施合同](P2-SUBSCRIPTION-ADMISSION.md)覆盖实际提供者格式、独立来源和私有隔离，不用演示库存替代。源码 `d0e55c6ac7e9528f2c27bd6cbc872fc6e544d3de` 的新增核心 87 项 ordinary/race 实际执行及旧 2403/2391/2320 名单已独立复验；完整主模块每轮 2490 Test。原生后端和 CDP/Playwright 原 ZIP/原 Git checker 重放均通过；镜像回归 success，实际前端 117、子模块 ordinary/race 各 732 及旧名单也已独立核验，未逐项独立重放所有旧产品 CLI。详见[本轮验收记录](P2-SUBSCRIPTION-ACCEPTANCE.md)。核心原型已测不等于产品订阅管理已接线或已上线。

| 编号 | 内容 | 当前状态 | 本轮尚未证明 |
| --- | --- | --- | --- |
| P2-01 | 范围、预算、私有 DTO 与 HMAC 身份合同 | 已实现，8 项 ordinary/race 隔离验收通过 | 产品身份授权接线 |
| P2-02 | 提供者 YAML / URI / base64 解析 | 已实现，26 项 ordinary/race 隔离验收通过；固定依赖来源/摘要已核验 | 全部格式/协议选项、真实内核可用；AST 后置预算不等于进程沙箱 |
| P2-03 | 私有隔离库、本地接纳、回退和审计 | 已实现，34 项 ordinary/race 隔离验收通过 | 故障注入不等于断电；外部审计和整套备份恢复尚未完成 |
| P2-04 | 批准来源 HTTPS 有界读取 | 已实现，18 项＋1 条跨组件 ordinary/race 隔离验收通过 | DNS/dial 为明确 fixture；无真实公网、产品来源批准或调度闭环 |
| P2-05 | 产品 API / RBAC / 独立写门 | 未接线 | 授权发生在读取和抓取之前 |
| P2-06 | 真实订阅资源界面与浏览器闭环 | 未实现 | 当前订阅页仍是占位，不是实际库存 |
| P2-07 | 自动调度、完整内核验证与运行发布 | 未实现 | 导入成功不等于节点可用或生产生效 |

完整 `subscription_orchestration` 能力继续保持 `design_only`，不会因为新 helper 包或单元测试而自动改成生产能力。

### 完整系统范围

下表保留完整目标，不把“当前后端实验完成”改称“整个系统完成”。历史证据不冒充本轮生产实时状态。

| 领域 | 当前可确认进度 | 下一项退出条件 |
| --- | --- | --- |
| 后端与只读观测 | 基础控制面、身份/范围授权、部分耐久操作和本阶段探针读回已有实现及分层证据 | 各真实数据入口、异常恢复和产品事实清单逐项对账 |
| 前端与交互 | 基础工作台、部分真实 HTTPS 界面及本轮双浏览器探针读回已有独立隔离验收 | 完整功能页逐项接入真实后端，仍需其他业务/视口/浏览器与系统级交互验收 |
| 镜像信任、策略、撤销与防回放 | 已有[分层验收记录](P1-PROBE-READBACK-ACCEPTANCE.md)及候选镜像子门 | 完整故障/轮换/来源矩阵、企业密钥与正式发行不能由已有子门替代 |
| 测试与证据 | 本阶段源码、原始日志、工件摘要与独立重放已关联 | 容量、长期浸泡、完整故障矩阵及永久集中归档仍需完成 |
| 备份与恢复 | 已有局部状态验证、恢复合同及隔离子门 | 整套配置/状态/身份引用/证据的系统级恢复演练与 RPO/RTO 验收 |
| 订阅与精确分流 | 已有模型、校验和部分编译/只读对账；不等于完整数据面发布 | 1/N 订阅准入、完整配置、真实内核校验、出口与业务验证 |
| DNS、节点评估与自动修复 | 不能由本阶段封闭实验宣称全网可用或免维护 | DNS 数据面、防泄漏、真实节点能力、动作预算与独立复验闭环 |
| 多内核、反代、隧道、AI 与企业治理 | 仍需按[完整能力缺口](SYSTEM-COMPLETION-GAP-AUDIT.md)逐项复核实现与验收 | 实际适配器、设备运行、隔离性、回滚及业务证据，不接受静态能力矩阵替代 |
| 灰度部署 | 本阶段未进入生产灰度 | 获批对象、备份、隔离测试、金丝雀、观察及停止扩大条件 |
| 生产读回 | 仅有历史 Shadow 部署记录；本轮未访问生产验证现态 | 部署版本/配置/身份/运行态/业务读回与验收签署 |
| 回滚与运营闭环 | 整套系统未闭环，不能承诺上线或任意高可用率 | 独立管理恢复路径、失败演练、集中证据及持续观察 |

## 最近变更记录

| 提交或阶段 | 结果 | 不应误读为 |
| --- | --- | --- |
| `2cf4a34` | 安全只读接线、前端合成 API 与既有镜像回归验收 | 真实探针浏览器闭环或上线 |
| `a8a5216` | 首轮真实采集/API 执行成功，独立 checker 因 namespace 历史编号假设拒绝 | 整轮 CI 成功；原失败保留 |
| `700ea9e` | 修正生命周期/tick 判断，完整新 CI 成功，原工件重放通过 | 公网业务、浏览器、正式 Registry 或生产完成 |
| `2fe1231` | 能力事实同步，父门精确接入新增 12 项；父门/原生后端/候选镜像回归 CI 均成功 | 已配置等于健康、浏览器闭环或生产完成 |
| `f366f8a` | CI 专用工具与共享合同：实际 Node22.23.3/core1.64.1 接口和 33 项辅助检查通过，8 份 Git 原 blob 与源码不变独立核对；同源码父门 2403/旧基线均保留 | 已启动 CDP/Playwright 或真实浏览器 E2E 通过 |
| `f6d8a0a` | 双驱动、真实 runner 和独立 gate 候选；[首轮 CI 39908581078](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39908581078) 两条路径均在参数阶段因 `PATH_WRITABLE` 拒绝；编译和辅助检查成功。保留原失败，下一次将 Node ELF 复制到专用输入区，并记录祖先权限，不放宽检查 | 浏览器已启动、已得到页面/TLS/正常退出证据，或真实验收通过 |
| `a7ad322` | [第二轮 CI 39908991138](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39908991138) 的实际路径记录确认 Node 副本通过，但共享 Chrome 的 `/opt`、`/opt/google`、目录及 ELF 均为 `0777`，仍在启动前拒绝。下一轮复制完整 Chrome 分发目录到 root-owned 专用区，按原字节记录摘要、移除副本的组/其他写权限和 setuid 位，不改共享源 | 已启动浏览器或完成真实浏览器验收 |
| `3afb2d8` | [第三轮 CI 39910032190](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39910032190) 已越过输入权限及完整 Chrome 复制阶段，但两条路径均在 `PREWARM` 拒绝；原诊断不足以归因 NSS/启动器/驱动，下一轮只增加闭集 checkpoint 观测，不放宽安全门。父门及原生 CI 均 success | 预热成功、业务页面已访问或浏览器验收完成 |
| `a121c8e` | [第四轮 CI 39910597365](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39910597365) 两条路径均越过 NSS 导入/回读并进入 `LAUNCH`，未到 `IDENTITY`。尚不能确定具体启动根因；下一轮保留闭集错误类别和启动交接/退出观测，并使用私有 cwd 与隔离 Python 启动。父门及原生 CI 均已独立验收 | Chrome 正常启动、身份已验证，或浏览器验收通过 |
| `03557f5` | [第五轮 CI 39911508872](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39911508872) 两条路径的故障 sidecar 均确认 launcher 真实交接、Chrome 实际 wait `-6`（SIGABRT），未到 `IDENTITY`；仍不能确定 abort 原因。下一轮仅提取受限 Chromium FATAL 源文件/行号，不输出原始消息。父门已独立验收，原生 CI success | 修改 cwd/Python 启动就已解决根因，或浏览器验收通过 |
| `8b69465` | [第六轮 CI 39912217069](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39912217069) 两路径均给出 `chrome/browser/process_singleton_posix.cc:313`，实际 wait `-6`，未到 `IDENTITY`。现有长 TMPDIR 可能超 Unix socket 上限，但尚无实际版本对应的完整归因；下一轮仅在浏览器私有 mount namespace 使用短路径 `/var/tmp` tmpfs（0700、10001:10001、nosuid/nodev/noexec），三层环境同步，绝不改宿主目录或放宽 TLS。父门普通/race 各 2403 Test，原生 22 输入已独立重放通过 | 已证明具体 fatal 消息、浏览器启动成功或真实验收通过 |
| `76ad3bd` | [第七轮 CI 39913536643](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39913536643) 两条路径均实际进入 `IDENTITY/READY`；CDP 在 `FRESH/FLOW` 失败，Playwright 在 `EXPIRED` 失败，后者实际 Chrome wait=0 但控制器非零。尚不能确定页面流程具体断点；下一轮增加 12 个固定 flow 入口和首次失败操作枚举，失败时仅导出已通过白名单 writer/令牌扫描的候选 capture，显式不具备验收效力。父门及原生后端独立验收通过 | 两条真实浏览器闭环已通过，或 Chrome 退出 0 等于整个流程成功 |
| `7ee2c91` | [第八轮 CI 39914889474](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39914889474) CDP 断点为 `FRESH_DESKTOP`、无 driver 操作异常；Playwright 到 `EXPIRED`，候选中已有 fresh/withdrawn API、fresh/cleared/withdrawn DOM 和 3 张 PNG，但无 expired API，尚未到发布。下一轮仅给 CDP 加原生 Playwright headless 默认已有的 `--hide-scrollbars`，保留严格无横向溢出/PNG 宽校验；过期读回细分 6 个闭集 checkpoint。父门及原生后端独立验收通过；实际后端原 API 三阶段的纯模型回放通过，不是真浏览器证明 | 候选截图意味着完整闭环、已确定 CDP 根因或已上线 |
| `938b0d0` | [第九轮 CI 39916035176](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39916035176) CDP 修后越过桌面/移动端和旧结论撤回；两引擎均在 `EXPIRED_MODEL` 失败，未进入 `EXPIRED_GENERATION`。纯测试已复现：TTL 等待期积压的自动摘要被误当作刷新响应，旧摘要与新明细跨世代时过早触发 phase 校验。修正先处理已完成队列，严格完整 shape 校验后才允许世代不同有界重读，匹配后仍执行原 phase/TTL/样本语义；不声称 completion ordinal 证明点击请求因果。父门/原生 CI 终态 success | 已通过浏览器 gate；单凭细分入口已证明唯一真实根因；或修改验证标准强行变绿 |
| `a284291` | [第十轮 CI 39917846275](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39917846275) 两引擎实际越过 `EXPIRED_PUBLISH`，失败转到控制器 `CLOSE`。完整 18 capture 仍仅为失败候选，PW 已独立核对摘要、4 PNG 完整性、684 个 Git 原 blob，过期 0 样本/3 unknown；Chrome 实际 wait=0，但缺完整后端 22 输入及 flow/driver/build/processes，不能验收。下一轮只细分正常关闭各入口，不改变退出/无残留/无强制干预判断；父门普通/race 各 2403 Test 已独立验收 | 18 capture 或 Chrome wait0 已证明正常生命周期、完整 gate 或上线 |
| `01af8d2` | [第十一轮 CI 39919271011](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39919271011) 真实关闭细分定位在 `CLOSE_SCAN`，未进入 `CLOSE_GUARD`。静态检查发现扫描所有同 UID 进程时，错误提前套用 Chrome 专属的正 pgrp/session 要求；隔离 PID namespace 内无关 API/controller 可合法显示 0。下一轮分离通用进程解析与严格 Chrome 身份解析，保留实际 Chrome pid/group/session、启动 tick、profile、argv 和无存活/无强制干预约束。父门普通/race 各 2403 Test 已独立验收，原生 CI 终态 success；浏览器仍失败 | 已完成正常退出、已用完整运行证据证明唯一根因，或放宽真实 Chrome 身份要求 |
| `aba1049` | [第十二轮 CI 39920337249](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39920337249) CDP 在 CI 工作机内 gate success，但独立下载重放发现上传包漏 `web/.vite/manifest.json`；完整 gate 必须拒绝，不补造原字节。PW 正常采集/生命周期子验已过，但 driver 有 1 次 API 请求失败，CI 工作机内 gate 严格拒绝，公开记录尚不能区分取消或传输失败。两引擎原 backend22 及捕获/进程子验证通过，不代替完整验收。下一轮仅补有隐藏项白名单的公开归档及固定失败类别诊断，原计数和所有 gate 不变；父门普通/race 各 2403 Test 已独立验收 | CI 绿色已等于完整可重放工件；或可直接忽略 PW 的请求失败 |
| `06543d4` | [第十三轮 CI 39922631837](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39922631837) CDP 原 ZIP 已含 898 字节 Vite manifest，完整原 Git checker/backend22 重放与 CI 报告逐字一致；browser canonical SHA256 `9069665f86fd863569fa49f58a5bb5ec2bfb2ba4b7f88a0a857fb844911fc566`。PW 仍严格失败，唯一非零为 `failedRequests=1`，固定诊断 `PROBE_STATUS:CANCELED:ABORTED:RUNNING`；日志不能唯一绑定自动/手动重叠或 10 秒 deadline。父门 ordinary/race 各 2403 Test、原生后端 22 输入已独立复验。下一轮修正摘要请求单飞和 owner 隔离，增加 7 个确定性前端反例与安全耗时类别，不改失败计数、10 秒 deadline 或完整 B gate | CDP 一条通过等于双路径已验收；推测取消根因等于事实；辅助单元测试等于真实浏览器成功 |
| `cadb9f4` | [第十四轮双浏览器 CI 39925504923](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39925504923) 两路径各自实际采集、正常 TLS/页面/自然过期和正常进程生命周期均通过；下载原 ZIP 后原 Git 后端22/browser checker 完整重放，与 CI 报告逐字一致。CDP/PW 的 8 计数全 0，父门及原生后端独立复验通过；镜像信任绑定 CI success，实际 117 前端、732 ordinary/race、旧基线与源码绑定已核验；旧产品子 CLI 未逐项独立重放。7 新模拟反例通过且原名单未替换 | 本轮修复已唯一归因历史取消；公网业务、高可用、生产或整个企业系统已经完成 |
| `d0e55c6` | 订阅准入核心 87 项隔离 ordinary/race 通过，完整主模块每轮 2490 Test 且旧基线保持；原生后端、CDP/PW 原工件/原 Git checker 重放通过；镜像 CI success，前端 117、子模块 732/旧 Registry 3 名单独立通过，未逐项独立重放全部旧产品 CLI。详见[P2 验收](P2-SUBSCRIPTION-ACCEPTANCE.md) | 产品订阅 API、真实资源页、自动刷新、完整内核和生产发布已完成；本地接纳等于运行健康 |

下一顺序：订阅产品 API/独立 RBAC/审计协调 → 真实资源页及双浏览器 → 完整内核配置及隔离内核校验 → 单目标隔离发布/读回/回滚 → 获批后才进入生产备份、灰度和观察。现有 `executor_not_configured`/授权阻断不因浏览器通过而解除。每次阶段结束更新提交、已验/未验项、原始证据路径和生产变更记录。
