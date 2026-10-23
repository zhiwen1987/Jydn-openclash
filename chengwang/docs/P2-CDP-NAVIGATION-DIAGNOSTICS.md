# P2：CDP 导航失败的受限观测

状态：实现及纯 CPU 验证完成；尚未运行本增量的真实 CI。没有修复或证明上一轮 CDP 故障根因，没有上线。

## 为什么先补证据

`96e51e4` 原 UI40030609894 的 create/CDP 和 remote/CDP 都在 `UI_RUN/NAVIGATE` 失败，各只留下6条启动捕获、0次捕获写入。现有材料不能区分目标命中、输入返回、DOM或证书证明的具体失败点。[上一轮实际结果](P2-SUBSCRIPTION-REMOTE-FETCH-UI.md)及原失败保持不变，不 rerun 挑绿。

本增量只给两个失败路径补观测，不改按钮、业务规则、等待预算、TLS、安全边界或成功验收条件。Browser plugin/browser skill 不可用，继续采用已有隔离 Linux CI CDP 与项目固定 Playwright；本机不安装依赖、构建或启动浏览器/服务。

## 字段和信任边界

- 只在失败 catch 中、任何紧急清理前同步复制状态，然后写一次私有 `driver-navigation.private.json`；最大8192字节、10001/0600、O_EXCL/NOFOLLOW，稳定检查文件身份。写诊断失败不替代原异常，原错误继续抛出。
- 原生 CDP 记录已进入前缀：NAVIGATE_RETURN、READY、NAV_TARGET_FOUND、NAV_TARGET_ACTIONABLE、INPUT_DISPATCHED、ANON_DOM、API_CERT、TLS_VERIFIED。仅最后一阶段允许未完成；原因码由实际分支指定，不解析异常 message 猜原因。
- Playwright 不可公开观察内部 actionability，故只有7阶段，不伪造其 CDP mouse ACK。原生三次鼠标命令记录0/1/3/7 ACK位图；Playwright只记录公开 click 是否返回。
- 匿名 DOM 阶段区分原等待、身份、形状、步骤和内容围栏拒绝。没有新探测、重复点击、额外 evaluate/RPC、等待扩容或自动写入重试。
- 八计数是失败、清理前瞬时快照，不是生命周期总数。不可用时只有 `available:false`；没有假造的0或空计数。异步清理后的最终 captures 可以多于该瞬时快照，不据此制造逐HTTP因果证明。
- 不导出原异常、stack、headers、令牌、DOM文本、输入值、证书正文或私有文件。supervisor严格验证后只投影进既有 `failure.json.driverDiagnostics`。成功 PUBLIC14/21、driver/DOM/capture schema 和旧业务门均不变。
- 当前仅 instrument `create_receipt` 与 `remote_fetch`；`local_admission` 未新增浏览器诊断，缺失材料仍明确不可用。

独立 Python 检查器不导入 producer reader/validator。available=true 必须核新合同、模块、reader、driver、runner、checker及中性依赖的精确 Git/source绑定；阶段、引擎、原因、ACK与计数独立复算。对历史缺诊断原件可核原source/host/capture并输出 `UNAVAILABLE_NOT_ACCEPTANCE`，但 `diagnosticSourceBindingsVerified=false`，不声称新工具曾在旧源码中存在。观测通过也绝不是产品、浏览器或唯一根因验收。

## 已验证与仍待验证

根代理实际运行旧84＋旧76＋remote86＋依赖86＋新诊断58（Node24、reader16、独立checker18），共390项，零跳过。四个冻结名单辅助日志门通过；三个“复制原日志再重复实际事件”的接线负例均拒绝。6个 Python AST、5个 Node 语法和13个工作流 shell 块语法通过。原件：`C:/Users/Administrator/AppData/Local/Temp/cw-nav-root-cpu-0g7rv3ad/`；`root-cpu.json` SHA256 `ad3f24a8dd50eb504690751521d1c0d4686a00a8698c867466428e4863d47ddf`。

根/C对原96e remote/CDP完整新 CLI 均返回 UNAVAILABLE，报告逐字同 SHA256 `e51549018c25307b528397baf41685cf3ee2bbb90ae0bcb95251b4d101c714d6`：核900个原Git blob、host/source、6捕获，未补诊断或根因。这只是历史后审，不替代新源码运行。

集成复核发现失败目录由root创建且保持0700：若普通用户 `test -f` 会静默跳过诊断。已把条件与检查器都改为既有sudo路径，没有放宽目录权限，并在新reader的既有测试内增加该接线回归断言。修正后根再次完整实跑390项/四日志门/13shell语法通过，原件 `C:/Users/Administrator/AppData/Local/Temp/cw-nav-root-cpu-fk4tnm63/`；首轮原日志保留。

本次 CI 继续保留三个场景×两个引擎以及六个fresh。每个producer辅助原日志新增4成员（navigation node/reader/checker日志＋synthetic报告）；成功旧场景预期40成员、新remote52成员，fresh分别6/8。失败时才额外输出受限诊断独立报告及日志；成功原件14/21本体不变。producer任一失败仍阻止整个fresh，不改依赖关系。

下一步核新源码首轮真实原件：若出现失败，严格核诊断可用性与失败分支；若没有失败，也只能证明该次流程成功，不能据此声称历史偶发故障已修复或真实失败诊断已执行。保留所有原失败，不重跑同源码挑绿。B01–B23其余矩阵、完整旧回归、备份恢复、灰度、生产读回和长期观察仍待完成。

## 上游参考不是本轮根因证明

实现前已查固定 GitHub 官方源码：[Playwright20a2087的动作检查](https://github.com/microsoft/playwright/blob/20a2087ea43412b90c172c88faef80786ee18b8b/packages/playwright-core/src/server/dom.ts#L434-L442)、[鼠标输入实现](https://github.com/microsoft/playwright/blob/20a2087ea43412b90c172c88faef80786ee18b8b/packages/playwright-core/src/server/chromium/crInput.ts#L126-L155)及[CDP7245ec5的navigate返回](https://github.com/ChromeDevTools/devtools-protocol/blob/7245ec551bc9d450170193456ab3965bb7e716cb/pdl/domains/Page.pdl#L924-L945)。这些仅用于区别命令返回、可操作性与业务状态，没有据上游差异替历史运行补造原因。
