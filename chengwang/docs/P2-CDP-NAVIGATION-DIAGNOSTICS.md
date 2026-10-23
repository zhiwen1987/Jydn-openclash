# P2：CDP 导航失败的受限观测

状态：实现及纯 CPU 验证完成；既定三场景双引擎的首轮真实 CI 与原件重放通过。没有证明上一轮偶发 CDP 故障根因已修复，没有实际触发新失败分支，没有上线。

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

## 首轮真实原件验收：dbc3f23

精确源码 `dbc3f23952a22dc79fcf332ecda26b3de3a25d58`，原 [UI40033595196](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40033595196)，attempt1。六producer（create/local_admission/remote × CDP/PW）及六fresh均success；没有cancel/rerun。成功原件本体仍分别14/21成员，辅助报告后的producer为40/52、fresh为6/8，实际12 ZIP共304成员。

根已按API大小/digest、ZIP CRC、逐成员摘要和原CLI重放后的字节核304成员，再与独立B/C获取的12原ZIP逐字比较全部相同。根32份原离线CLI报告均等于producer：6产品、6依赖、6新navigation58、2 remote86另有对应fresh，实际20份fresh报告逐字相同；旧84/76的12份辅助报告只与producer比较，不伪造不存在的fresh报告。B独立核旧四产品/C独立核新两产品均与原producer/fresh同字节，每个成功产品报告核910个精确Git blob。原checker、原件和原失败均未修改。

根本机顺序离线重放在local_admission/CDP超出本地包装器240秒，orchestrator exit1/TimeoutExpired，原报告未生成。已确认对应本机python/git不再运行，保留原脚本、线程原异常及 `local-wrapper-timeout-preserved.json`；没有把它当产品通过、产品失败或CI重试。后来仅对缺失的6份离线报告采用600秒本地包装器（复用已完成的26份），同源码/原checker/原件补验通过，旧拒绝记录和新报告分文件。这个预算不是CI验收门或产品超时，未修改CI22/10分钟及浏览器等待预算。

remote两个引擎都实际完成33步、47请求、4命令/1批准、local3/external8、来源revision3、1候选/2节点unknown、3连接12wire；正常API/DoT/HTTPS证书和四进程正常退出、八错误计数全0。根查看新remote/CDP 1440×900与375×900 PNG，B另看旧四场景8张PNG：首屏非空、无错误覆盖、未见水平溢出。手机仅首屏，未证明完整滚动流程。

**本轮没有真实失败**：没有failure.json或navigation-diagnostic.json；新writer/reader/available:true独立诊断路径只有实现与合成证据，还没有真实故障端到端证据。历史96e两次CDP失败仍保留，唯一根因、长期稳定及失败分支运行不能填PASS。CI成功只支持既定三场景/本次运行，不代表完整B01–B23或全系统。

A另核父40033595211普通/race各2644 Test、各4 Fuzz顶层/8 seed；旧订阅40033595140两Linux通过、80实际测试/899Git，原报告同字节；Windows原POSIX门仍拒绝，未适配。未在本阶段独立完成全部旧探针/镜像回归，不能拿父门替代它们。

根原件与完整报告：`C:/Users/Administrator/AppData/Local/Temp/cw-dbc-root-originals-vnrkomaj/`；[机器证据](evidence/p2-navigation-diagnostics-dbc3f23.json)。下一阶段按[独立B09负例卡](P2-SUBSCRIPTION-HANDOFF-NEGATIVE-PLAN.md)补真实授权、批准、策略与CAS反例；该卡目前只做代码语义核对，没有实施或运行。

## 上游参考不是本轮根因证明

实现前已查固定 GitHub 官方源码：[Playwright20a2087的动作检查](https://github.com/microsoft/playwright/blob/20a2087ea43412b90c172c88faef80786ee18b8b/packages/playwright-core/src/server/dom.ts#L434-L442)、[鼠标输入实现](https://github.com/microsoft/playwright/blob/20a2087ea43412b90c172c88faef80786ee18b8b/packages/playwright-core/src/server/chromium/crInput.ts#L126-L155)及[CDP7245ec5的navigate返回](https://github.com/ChromeDevTools/devtools-protocol/blob/7245ec551bc9d450170193456ab3965bb7e716cb/pdl/domains/Page.pdl#L924-L945)。这些仅用于区别命令返回、可操作性与业务状态，没有据上游差异替历史运行补造原因。
