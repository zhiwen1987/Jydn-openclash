# P2：受信来源批准、角色交接与真实抓取

状态：新场景实现与纯 CPU 回归已完成，真实 Linux CI/浏览器尚未验收。本文不是验收成功或生产部署记录。

## 从当前事实开始

现有产品已经具备来源目录、批准、两种抓取模式、显式确认与本地决定 API/界面；缺的是这条路径的真实浏览器及 wire 联合验收。既有创建/回执、双来源本地导入场景保持其独立合同和计数，不向旧工件里塞入新业务动作。

本阶段新增独立 `remote_fetch` 场景，用原已批准的隔离 Linux CI 分别运行 CDP 与 Playwright。目标流程：订阅页 → 创建一个来源 → Approver 批准 `good-b` → Operator 显式交接该批准 → 正常 DoT/HTTPS 抓取 → 待审候选 → Approver 明确接纳 → 读取真实回执、清会话与正常退出。目录同时列 `good-a`、`good-b`，策略版本均为 1；Operator 下拉选择 A 不得被描述成已验证抓取 A，实际目标必须由批准 B 和 wire B 证明。

## 事前冻结的动作与状态

| 动作 | 身份 | 来源版本 | 权威结果 |
| --- | --- | --- | --- |
| 创建来源 | Operator | 0 → 1 | 本地来源记录，不抓取网络 |
| 批准 good-b | Approver | 1 → 1 | approved，approval ID 等于真实批准 command ID |
| 交接抓取 | Operator | 1 → 2 | 正常 DoT/HTTPS 得到 quarantined 候选，不自动接纳 |
| 明确接纳 | Approver | 2 → 3 | admitted_local，节点仍 unknown，设备发布仍禁止 |

预计固定终态：一个来源、一个候选、四个命令、一个批准、三条本地审计、八条外部 prepared/result 审计。批准不会增加来源版本，也不产生本地导入审计；不能按“所有 POST 都递增版本”假设解释回执。动态 source/candidate/command/digest 必须从真实 API 取得，不预造。

33 个预定步骤涵盖批准准备/取消/重准备、同来源同版本刷新保留批准、切换引用清除会话批准、跨身份清会话、交接输入、抓取准备/取消、编辑交接版本与切换模式撤销旧确认、最终抓取、明确接纳、回执、切导航与清会话。步骤名单由独立新合同冻结，不能在看到 CI 结果后生成预期。

## 不借用旧场景的证明

- 新场景公开原件为 21 个：旧中性证据类别 14 个，加 wire ready/events/stopped 以及 source/resolver 四个公有 CA/leaf 文件。旧两个场景仍为各自原来的 14 个原件。
- 新 DOM 外层增加固定 `wireFence={eventCount,bytes,sha256}`，DOM 本体沿用现有公开 collector，不读取 React 私有状态。每个阶段真实采样安全 wire 日志前缀；独立 checker 对最终原始日志重算前缀。抓取确认前应为 0，完成后为 12，随后不增加。这是阶段围栏，不声称每个 HTTP 回调都有精确 wire 因果边界。
- wire 为独立实际进程，固定独立私有根，保持旧 fixture 原源码；正常一次抓取应有 A/AAAA 两条 DoT 和一条 HTTPS，共三个连接、十二个事件并全部关闭。独立核实际 ready、TLS、事件、SIGTERM/wait/join、无 worker/listener 遗留与第四个进程 profile。
- 私有 namespace 仅 lo 与其中的 `8.8.4.4/32`，无 IPv4/IPv6 默认路由；只有新场景在该 netns 配置低端口并实际读回。API、resolver、source CA 分离，不能把浏览器信任当作 DoT 或来源证书已验证。
- 原 84/76 辅助项和 v3 依赖 86 项继续保留；新 Node/Python 辅助原日志单列。合成事件、实际浏览器和真实 wire 分开验，不累加重复场景的相同测试为新增能力。
- 验收只能使用精确 Git 的原始 CLI、原 ZIP/摘要/CRC、producer/fresh 报告逐字比对。原失败必须保留，不能重跑挑绿。仅下载公开 JSON/log/PNG/公有证书工件，不下载 Chrome、DEB、keyring 等运行时二进制到本机。

## 已完成的纯 CPU 验证（不算真实浏览器）

根代理实际运行并保留原始输出：既有 84 项、既有 76 项、新远程辅助 86 项（Node 32、fixture 16、checker 26、辅助门 12）及原依赖 86 项，共 332 项零跳过。三个辅助日志门均按事前名单摘要重验通过；7 个 Python 文件 AST、4 个新 JS 语法和 11 个工作流 shell 块 `bash -n` 通过。没有安装依赖、启动浏览器、服务器、wire 或构建产品。

根原件位于 `C:/Users/Administrator/AppData/Local/Temp/cw-remote-root-cpu-sp0rri2c/`，汇总为 `root-cpu.json`。这些是提交前工作树的纯测试记录，绑定的 `parentCommit` 只是父提交，不能被解释为新提交的真实 CI 源码证明。后续需实际六 producer（3 场景 × 2 引擎）与六 fresh；新远程成功 producer 预期 48 个公开成员、fresh 6 个，旧场景仍分别 36/4 个。当前无新场景成功结论。

## 本阶段不冒称完成的内容

Operator 可按服务端规则交接批准 ID，但不能因此读取 Approver 的完整回执。当前场景不把跨 owner 查询说成成功；真实 403、错误/被替换批准、策略变化、错误 source/CAS 等矩阵仍须另外完成，不能据正向流宣称 B08/B09/B10 全部完成。

来源正常 fixture 不等于公网订阅或节点可用；UI 的“未核验交接”必须一直明确，直到服务端真实结果读回。B01–B23 其余权限、分页、审计降级、同库重启、故障、全系统备份恢复、旧完整回归、灰度、生产与长期观察继续留在[项目台账](PROJECT-PROGRESS-LEDGER.md)。不提供整系统完成率或“任意高可用”承诺。
