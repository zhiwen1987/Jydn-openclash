# P2：受信来源批准、角色交接与真实抓取

状态：新场景实现、纯 CPU 回归和单引擎正向流已验证；首轮整体失败，未通过双引擎验收，未部署生产。

后续状态：`dbc3f23` 原40033595196的既定三场景双引擎及六fresh已实际通过，根/独立代理原CLI报告同字节，详见[后续限定验收](P2-CDP-NAVIGATION-DIAGNOSTICS.md)。本页保留96e首轮失败，不回填成功；历史偶发根因仍未证明，新诊断真实失败分支仍未触发，完整B01–B23和生产继续未完成。

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

根原件位于 `C:/Users/Administrator/AppData/Local/Temp/cw-remote-root-cpu-sp0rri2c/`，汇总为 `root-cpu.json`。这些是提交前工作树的纯测试记录，绑定的 `parentCommit` 只是父提交，不能被解释为新提交的真实 CI 源码证明。后续需实际六 producer（3 场景 × 2 引擎）与六 fresh；新远程成功 producer 预期 48 个公开成员、fresh 6 个，旧场景仍分别 36/4 个。提交前尚无新场景成功结论；首轮实际结果如下。

## 首轮真实 CI：部分成功，整体未通过

源码 `96e51e475bfbe2cf67666ede4deaeac94eabcacb`，原 [UI run 40030609894](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40030609894)，attempt 1，终态 **failure**，没有 rerun/cancel。按前端测试技能区分真实呈现与合成测试；Browser plugin/browser skill 不可用，沿用获准的隔离 CI CDP 与项目固定 Playwright，不启动本机浏览器。

| 场景 | CDP | Playwright |
| --- | --- | --- |
| 既有创建/回执 | 失败 | 成功 |
| 既有双来源本地准入 | 成功 | 成功 |
| 新批准/交接/真实抓取 | 失败 | 成功 |

整个 `fresh` 由于 `needs: browser` 失败而跳过，只有一个未展开占位 job `120678292305`，不是六个实际 fresh。不能把四个成功 producer 说成双引擎全组成功。

根已获取并按 API SHA-256、ZIP CRC 和逐成员摘要核六个公开原 ZIP，共 215 个成员（27/32 为两失败诊断工件，36/36/36/48 为四成功工件）。根与 B 的三个旧成功完整产品 CLI、根与 C 的新 Playwright 完整产品 CLI 均与原 producer 报告逐字一致；每份成功报告绑定 900 个 Git blob。六份依赖及旧84/76辅助报告、新远程两份86辅助报告也由根原 CLI 重验与 producer 逐字一致。两失败工件原完整 CLI 均拒绝，无成功报告。没有 fresh 报告可比。

新 Playwright 实际在 `https://127.0.0.1:17891/` 操作 33 步、47 请求、四次写入；批准 B、下拉 A、交接批准 B、正常 DoT A/AAAA 和 HTTPS B、隔离候选、明确接纳、读回/清会话均已实际核。终态 1 source/revision3、1 candidate、4 command、1 approval、local audit3/external8，3 连接/12 wire 事件、四进程正常 wait0，八错误计数全0。API/source/resolver 三类正常 TLS 均在录制时点独立核验。根已看桌面1440×900、手机375×900原 PNG：首屏非空、无框架覆盖、未见水平溢出；手机只是首屏，未验证完整滚动操作。仍不是公网订阅、节点健康或全系统验收。

根首轮离线四产品 CLI 因当前进程 PATH 缺 `openssl` 原样拒绝，日志保留。直接诊断原函数定位到 `verify_tls` 的 WinError2，而不是 CI 产品失败。后续仅对子进程 PATH 加入已经安装的 Git `usr/bin`，同一 exact-LF 短副本、同一原 checker/原件重放成功；没有安装、更改全局 PATH、证书校验、原时间或源码。原拒绝与后续报告分文件保存。

两 CDP 失败只有 `UI_RUN` 与 `ENVIRONMENT/LAUNCH/NAVIGATE` 检查点，controller exit1、各6条 DOCUMENT/ASSET/SNAPSHOT 200捕获、0次捕获写入；无最终 DOM/driver/PNG。旁路的 host/source 前后读回一致、没有 inner timeout。remote 退出诊断还显示 wire exit0、forcedSignals2；create 为 forcedSignals1，均无遗留 owned process。**现有证据不能唯一确定具体失败语句，更不能断言点击、DNS、TLS 或 wire 根因。**

原件与汇总：`C:/Users/Administrator/AppData/Local/Temp/cw-96e-root-originals-hd4v8a5m/`；独立 B：`.../cw96b-1d307fee/`，独立 C：`.../rf96c-5ed771a8/`。[机器证据](evidence/p2-subscription-remote-fetch-96e51e4.json) 保存 SHA、job、环境拒绝及剩余范围。A 另行核父门40030609903普通/race各2644 Test；旧订阅40030609922两Linux成功、80项/889Git，Windows原POSIX门仍拒绝，不能抵消 UI 失败。

## 下一步：补诊断，不凭推测修业务

先用固定阶段与受限错误代码区分导航返回、页面就绪、导航控件命中、真实输入、匿名 DOM 和 TLS 证明；记录八计数及 bounded metadata，不输出原错误消息、令牌、headers、DOM文本或原URL。旧成功闭集/验收条件不能放宽，不自动重试写操作，不重跑旧 run 挑绿。

已查阅 GitHub 官方实现，固定 Playwright `20a2087ea43412b90c172c88faef80786ee18b8b` 的 [dom.ts](https://github.com/microsoft/playwright/blob/20a2087ea43412b90c172c88faef80786ee18b8b/packages/playwright-core/src/server/dom.ts#L434-L442) 在指针动作前检查可见、启用、稳定和非 inert；这只是与当前原生 CDP 一次命中检查的差异，**不是本轮失败根因证据**。不明确的实现继续先核仓库、固定版本上游源码与测试，再决定是否修改。

## 本阶段不冒称完成的内容

Operator 可按服务端规则交接批准 ID，但不能因此读取 Approver 的完整回执。当前场景不把跨 owner 查询说成成功；真实 403、错误/被替换批准、策略变化、错误 source/CAS 等矩阵仍须另外完成，不能据正向流宣称 B08/B09/B10 全部完成。

来源正常 fixture 不等于公网订阅或节点可用；UI 的“未核验交接”必须一直明确，直到服务端真实结果读回。B01–B23 其余权限、分页、审计降级、同库重启、故障、全系统备份恢复、旧完整回归、灰度、生产与长期观察继续留在[项目台账](PROJECT-PROGRESS-LEDGER.md)。不提供整系统完成率或“任意高可用”承诺。
