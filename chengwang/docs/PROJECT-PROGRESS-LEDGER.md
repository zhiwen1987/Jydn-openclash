# 澄网项目进度台账

日常查看：[项目任务清单](LIVE-TASKS.md)（当前优先项、完整剩余功能、依赖与验收条件）。[实时执行动态](http://127.0.0.1:8765)复用本机现有监控台；其估算百分比不代表项目完成率。任务清单由实际结果驱动更新，不冒称每秒自动同步或生产已上线。

## 最新核对：2026-10-26 SYS-06 首次真实 Completion 四模式通过限定隔离验收

后续 `a9774e5` 的真实首轮已失败：foundation 在 Go 前的25名称摘要误用整文件摘要；独立 full diagnostic 已调用 Go1.23.12，但两处缺少 `newLabRecoveryCollectorAt`，没有实际图诊断 output／pass，不能填 pin。原 full ZIP 240931字节／18成员与1377源已独立核，失败收据 SHA256 `17b0c6751da91d252d0e18779a81319f7e52a8170b1866c4a0594299fb866e8e`。最小修订恢复名称域并补exact session派生 collector stage，同stage贯穿全部证据sink；旧fixed兼容、688名单及空pin保持，须下一真实 Linux 重验。原格式0只覆盖10文件，不冒称完整144门。

后续源码阶段：已按冻结补丁将 v4 的 37 声明路径合入开发工作区，来源 SHA256 `529e80f52fbc7dec6867bbbe9466c4d1fa39e95bfd30db41148e0bee04cd43f7`，重基独审 SHA256 `d0cd138ee1bf3a7404c7a7691284210b803ebee86f4f59aeb5fce0227ef1fbb5`。声明 150／58／688／88／144／188 闭集，原 661 历史链保留；尚未 Go 编译／运行。空 clone pin 保持 fail closed，下一实际 Linux diagnostic 读回结构摘要，不猜值。下段 4bbbe 接受结论只对应其精确提交，不覆盖这些新增源码。

精确提交 `4bbbe70b1f13e53fa07201e32129366cf254ccee` 的新 Completion `40226840814` 全部 11 任务成功。9 ZIP／167 成员和完整 1364 跟踪路径来源已核；四模式原 checker main 直接复演 ACCEPT，无平台适配；root 独立重数真实 Go、命令、格式、计数／revision／adopt／poison及四组 producer／fresh 字节一致。[限定接受收据](evidence/sys06-4bbbe70-first-completion-acceptance-20261026.json) SHA256 `ea936d1bfd27c36f725afae251d81dca23a2ed8a58ce6268c32f0012eaebe8b5`。同提交基础、容量诊断和旧 S2 三条 CI 终态也 success，本轮只记录状态、不声称重新复算全部旧门。

本次接受仅关闭首次 Completion 四模式与 positive 首次 opaque runtime adopt，完整私有 WAL 独立证明、产品 service 换绑／恢复 API、恢复后普通发布、第二次恢复、完整系统和生产仍未完成。v4 源码与 CI 候选已完成 fresh 授权顺序修订、独立审查、重基和工作区合入，尚未编译；空 clone pin 仍 fail closed。旧故障胶囊在消费后拒绝后续 PUT，新连续 API 实验须另设有界、按真实 operation／epoch 绑定的测试合同，不能 reset 旧 issuer 或改旧实验来伪造连续性。

## 历史核对：2026-10-26 a988首次真实 Completion 未通过

03:24（Asia/Shanghai）核对开发提交 `a9882e481cc76f7ca9b29f1f37559b0279d65370`：基础门 `40225294575`、容量诊断 `40225294602` 和旧 S2 `40225294675` 均已终结 success；新 Completion `40225294759` 已终结 failure。[机器记录](evidence/sys06-a988-ci-status-20261026.json)仅证明精确提交的工作流终态，不声称新原件独立验收。

后续 positive 原 ZIP 28625 字节、39 成员及 SHA256 `af25d8cd4f52de42ed1046eb5fc00ee0d436fbb3a34a8479513e18e9d1873a80` 已由 root 独立读完 CRC、逐成员与解包字节和关键三源 Git blob；Go 顶层实际 10.90 秒 PASS，包 10.909 秒，四命令退出 0，外层 attempt 为 1。首个拒绝来自 reader 的错误 cwd 后缀假设：正式只读 module alias、实际 Popen 和真实 receipt 均为 `/tmp/mihomo-apply-source`，不是 `/chengwang` 结尾。另有真实 9904 字节非空 gofmt 差异，格式进程退出 0 不等于格式门通过。两个门须分别修正，不伪造 receipt、不放宽空格式要求；旧 `fdc2587` 的 Go 前失败保留且不再作为新版原因。独立有限收据为 `D:/CodexData/workspace/mihomo-a988-positive-root-audit-xsrab0by/receipt.json`，SHA256 `f682004746d80bb85ccdba2b45dd8f902abf6422185aebcc0a029704eb5cc59c`；它不证明完整 positive reader 或四模式通过。

当前已接受的限定基线仍为 `c1f9`：普通／race／full 各 1937 语义与 661 必需项、旧 S2 四模式、25 ZIP／442 成员已核；其 race 包 176.367 秒，距原 180 秒仅余 3.633 秒，不宣称稳定性能余量充分。新专用采集器的 11 项 CPU 模型通过只允许进入隔离 CI。失败恢复协调器和产品 API 仍为外部候选，独立审查要求修正 fresh 授权之前的状态响应顺序，尚未集成或取得真实 Go 验收。

另补齐 `fdc2587` 的 [foundation 与 full diagnostic 四原件审计](evidence/sys06-fdc-foundation-full-diagnostic-audit-20261026.json)：四 ZIP／37 成员、完整 1360 跟踪路径来源、140 源／54 必需测试源／661 顶层；普通、race、full 各 1937 语义通过，producer／fresh／独立函数复算逐字节一致。这只是这两类旧门；未重新验收 old S2、新 Completion 或整套 CI，Windows 路径／writer 的明确适配边界保留。

[任务清单](LIVE-TASKS.md)已同步当前阶段并保留旧条目，完整 [SYS-06 记录](SYS06-MIHOMO-LIFECYCLE-IMPLEMENTATION.md)保留每次失败与证据限制。恢复后普通发布、第二恢复、DNS、多内核、企业治理、全功能 UI、容量／浸泡、灰度和生产读回仍未完成。本轮未操作生产、main 或 Registry。

## 历史实际回归：78真实诊断定位时间步骤；纠正额外时间假设候选188项CPU通过

2026-10-24 15:49：78父40072726950、订阅40072726986成功，UI40072726996旧订阅16任务成功、新能力8任务失败。4份v2 producer共144原件成员已核；首个拒绝均DOCUMENT/r1/EVENT_FINISH_TIME，另外七类错误0。独立公开投影核验通过；私有canary没有导出，未在本机重做私有fence。原始时间没有导出，尚不能区分us转换和比较、更不能断言唯一数值原因。见[78实际跟进](evidence/p2-78ffc4e-ci-followup.json)。

固定Chrome157官方8源证明导航响应通知与网络完成时间采样点不同。独立审查纠正了renderer非导航分支不能直接证明DOCUMENT响应来源的初审偏差，补齐browser主链后，候选仅把额外end>=header改为end>=start，与原独立checker和旧journal一致；其他类型、时序图、字节、八零、TLS和清理约束保留。保旧85 Node名字、加1合法时序正例，188辅助项／41枚举／21shell／7Node实际通过；候选待统一提交与真实CI。见[官方依据、改动和限制](P2-CAPABILITY-NETWORK-TIMING-CORRECTION.md)。

实际总览独立分支形成代码与严格门，117个不同CPU辅助用例通过（新55＋旧62）；内嵌实际CI35为其子集，68shell和10TS AST通过；独立源审无阻塞。Go2709／前端345仅为固定预期，尚未实际编译、运行新产品测试、HTTP或新总览浏览器。两分支均无生产／main／正式Registry变更。

## 历史实际回归：b2旧订阅原50门独立复算通过；新能力页实际失败，诊断增强187项CPU通过

2026-10-24 15:02：b2b226d已实际推送。父40068275506、订阅40068275429成功；UI40068275370的旧8个producer＋8个fresh成功，新能力4个producer＋4个fresh失败。旧订阅原50条CLI现已逐条实际exit0，50报告同producer字节，34也同fresh，16仅producer；1035源blob、16ZIP／466成员前后稳定，根再次独立重读日志、报告、源及ZIP字节通过。见[指定源码有限验收](evidence/p2-b2b226d-old-subscription-acceptance.json)。不包含完整B01–B23、新能力或生产。

新能力四份原件只能确定UI_RUN／NAVIGATE失败，normalCloseCompleted=false，capturedOriginals为空；不能依据事件计数猜根因。[证据及处理步骤](P2-CAPABILITY-FAILURE-DIAGNOSTICS.md)记录具体原件SHA和未决项。当前仅增强失败专用v2闭合诊断，保成功17文件、成功checker、旧场景源码、所有原预算和时间约束。已实际187辅助项通过（16监管＋36场景＋50检查器＋85Node，含原28场景／79Node）；静态41操作两侧一致、7Node语法和21shell块通过。先前两次真实失败保留，分别修正TAP夹具固化79及新增测试的schema表引用，未放宽运行门。见[本地诊断实现证据](evidence/p2-capability-failure-diagnostics-development.json)。候选待统一提交及真实Linux CI，不能称故障已修复。

独立实际证据总览已在隔离工作树形成代码及36项Go／39项前端测试声明，全部未编译／运行／推送。生产、main、正式Registry及原三份用户scripts保持；整套项目未完成。

## 历史实际回归：448e20b浏览器辅助门失败；修正候选702项CPU通过

2026-10-24 13:53：配额恢复后的原索引确认448父40066607879、订阅40066607931成功，浏览器40066607892失败；27 jobs已实际读取，其中UI24全部失败，12个build步骤成功而12个产品浏览器步骤全部skipped。三份代表decoded日志及五份安全原件（76成员）已保管；不能称本轮真实浏览器或普通TLS已运行。见[失败跟进](evidence/p2-448e20b-ci-followup.json)。

新common两个假进程正例在Linux读取/proc/20等宿主路径而失败，已仅改测试模型，加入残留假进程反例，运行时清理断言不变。旧navigation／feedback及扩大检查后发现的negative-handoff三个源码守卫仍定位旧inline inner/main，已改为验证固定wrapper→共享core→legacy hook的实际顺序和权限／保密／失败出口，并保旧名称及拒绝性反例。当前主代理实际19个Python模块＋8组Node共702项通过、0skip（Python404＋Node298），包含新能力173项；独立审计核对27执行记录、41源和130证据文件稳定，原lifecycle19另计。D原件`all-ui-helper-cpu-2w5g0a73`。纠正前述失败尝试计数范围：17个完整通过模块有374项，第18个失败模块另9通过／1失败，总383通过／1失败；原件不覆盖。见[修正范围](evidence/p2-shared-supervisor-helper-correction.json)。尚未提交该修正或取得新CI，不能覆盖448失败。

448订阅本机原CLI重放实际退出1，拒绝点为`public-file-open-race`；20文件只有lstat／fstat的ctime跨渠道不同，其余身份字段和各渠道前后稳定，25＋1原件及源码无变更。该次未到业务语义核验，不写通过，也不由此归因数据损坏。D失败及诊断`subscription-448-readback-3d891c96af`，暂未修改或包装原检查器。

## 历史集成：448e20b已推送；当时实际新CI待配额恢复

2026-10-24 13:34：24文件已统一提交`448e20bdac0aa657505ebb53f56b5fe1aac6c356`并推送开发分支，远端引用一致，用户三原scripts摘要保持；生产／main／正式Registry未改。最终仅修一行EOF空白后重新实跑172项CPU、21个shell块及7份Node语法，零失败／跳过。已按实际提交执行两条完整synthetic CLI，退出0／报告逐字节相等，17份源码及四原日志稳定，D证据为`capability-source-cli-a4i79l8x/result.json`。该门只证明CPU转录与提交源码绑定，不代替产品浏览器。

新CI索引实际HTTP403／remaining=0，reset=2026-10-24 05:37:17 UTC，目前没有新run句柄可确认已运行。按24路径与12个workflow规则核对，预期只触发父门、旧订阅readback、订阅UI三条，合计27 jobs；image-binding／Probe等不会由本次路径自动重跑，不能沿用旧五条预期或其成功。

前序1cde镜像六条完整产品CLI已全部补验：6／6实际退出0、六报告均同CI字节，1470原件／ZIP／1013源blob前后稳定，独立journal审计通过；主代理再核六份报告的实际字节相等。1356不同投影参与本次语义重算，另外114仅保管核验；不以此证明全部故障、完整来源矩阵、真实断电或生产。见[六门跟进](evidence/p2-1cdeba4-image-acceptance-followup.json)，本段及跟进待下一次归档。

## 历史任务核对：2026-10-24 12:59（Asia/Shanghai）

后续实际增量：新能力链路已由主代理组合执行172项CPU测试，零失败／跳过，源字节前后稳定；21个CI shell块与7份Node文件语法检查通过。根记录`D:/CodexData/workspace/capability-root-cpu-qpnnrzio/result.json`及`capability-root-preflight-h_898gvp/result.json`。首个根测试包装因过早替换subprocess.Popen阻止Windows asyncio类初始化而未开始测试，日志保留在`capability-root-cpu-g3ei2vvf`；先导入标准库再安装拒绝外部执行guard后实际172通过，不能把首个包装失败说成产品测试失败。

本机看板已接入38项任务／7阶段快照，真实浏览器验证搜索DNS得4项、展开／焦点跨刷新保持、原实时任务视图仍连接，1280桌面和390移动无横向溢出、控制台零错误／警告。监控停止／重启操作被自动审批拒绝，原进程保留；运行中尚无新文件直读接口，因此界面明确“快照预览”及采集时间。不能把本机看板的实际浏览器检查移算为澄网产品capability_truth场景通过。

[任务清单](LIVE-TASKS.md)已补当前阶段的七项交付、勾选状态、证据和下一退出条件，保留原NOW-01–08／SYS-01–30编号。本机实时看板12:57实际HTTP200且connected=true；其对话估算百分比和子代理数量不作为项目完成率或实际人员统计。

1cdeba4的五条CI已取得成功状态；镜像原件前端306、Go普通／race各732、Registry普通／race各3已由原文本检查器独立复算，完整产品六条CLI尚未独立重放。根证据为`D:/CodexData/workspace/notice-image-independent-ncxxoiry/result.json`，SHA256 `d1dd35c10a116b40ab70f3aaa6b0a99a8330376a573691455843b8dfc0a2cc44`。此项后续证据更新此前限流时的“未知”，不改写旧失败记录。

能力页真实浏览器新场景仍为本地候选：共享监管243项CPU通过、驱动79项CPU及7文件语法检查通过，独立检查器正在补验，CI接线尚未实际运行。未取得新场景的真实浏览器、视觉或生产验收；本地更新尚未另行提交推送，生产和main未动。

## 历史集成：918bc36已取得实际CI；提示窄修正当时待验收

11:58最终跟进：三文件提示修正已统一提交推送`1cdeba4bc0e7c9b5cd25c9e7608cb4ac8f9e2ef8`，远端引用确认一致；其CI索引再次403，remaining=0／reset=2026-10-24 04:37:16 UTC，停止请求，没有新句柄可确认CI状态。生产、main及用户三个scripts摘要保持。918订阅50原CLI已全部实际exit 0，34 fresh比较＋16 producer-only、16 ZIP／466成员／1011源码及50 journal独立复核完成；探针14原门也已收口。[验后机器跟进](evidence/p2-918bc36-acceptance-followup.json)明确不代证新1cdeba4，也不抵消918镜像305／306的原失败。

历史探针只读源审还排除了一个未经证实的修复方向：摘要finally清active，未发现已完成摘要被下一poll／unmount经旧active再次abort的路径；details确有成功后保留ref的独立卫生问题，但不绑定旧n5摘要失败，不能据此宣称修复。旧n5同时有NET_FAIL和JSON EOF／FINALLY，aborted=false，无ABORT／CANCEL，真实原因仍未知。下一步先增加独立有界的实际signal／所有权释放旁证，再选择行为修正，原八零门不放宽；该旁证尚未实施。

2026-10-24 11:48实际读回补充：配额重置后已核两个新源码run，旧“未确认”是此前时间状态。918镜像实际305／306通过、唯一旧未知来源提示断言失败；SnapshotTruth44／44、DemoModeTruth2／2已实测。49原公件及完整306名字集合独立核对通过，lint／Vite／Go与Registry后续未执行，整体仍失败。已做三文件固定格式错误提示分类及两旧文案断言显式迁移，306名字／其余断言／解码门不改，尚未获新CI。[实际失败和纠正](P2-SNAPSHOT-FEEDBACK-CORRECTION.md)。

918订阅UI八producer＋八fresh成功，16 ZIP／466成员保管通过，50条本机原CLI仍在执行，不借5f已完成结果代证。918探针两引擎14原CLI实际exit 0、14报告同字节，两个ZIP192成员／1011源blob前后稳定；每引擎7正常EOF、原八counter0、新旁证完整。它不能倒推历史5f／1d失败原因已修或长期可用率。父及旧订阅CI成功目前仅终态元数据层，当前源码完整原事件／旧CLI复算未补。见[分层机器记录](evidence/p2-918bc36-partial-ci.json)。

2026-10-24 11:33补充：已统一提交并推送`918bc36cdcd3fa17f0147ae7f617dbd059e0d3bd`，11个明确文件，远端读回一致。继承1d4b59d的快照／诊断修正，追加实际mode／页面只读修正、2项组件声明（候选306／14文件）、三个中性生命周期leaf及其19项独立精确门、5f静态视觉后审。205纯CPU用例、新19工作流门、当前19个Bash块／offline gate语法及AST边界检查已完成；不把重复19累加。没有本机运行Go／Vitest／tsc／lint／浏览器，完整capability_truth场景仍缺。两个新源码的真实CI均尚未读到run句柄，配额重置后才能确认；不能从git push成功推导CI运行或通过。用户原三份scripts未夹带、摘要不变，生产与main未改。

2026-10-24 11:15（Asia/Shanghai）补充：已统一提交并推送`1d4b59d2a4c80634601c96970efc71d0958da6cc`，20个明确文件，远端引用读回一致。完整快照解码、lint修正、提前ExtraInfo收集与EOF独立前置接线及5f公开机器记录已入库；原三份scripts脏改hash保持不变，未夹带提交。当前workflow62纯CPU辅助门实际通过，旧20 TAP被新Node门拒绝；旧真实260 JSON由新304门拒绝，未造304成功转录。40份TS／TSX仅AST解析、17个Bash块仅语法检查，不代表编译、Vitest或浏览器执行。

查询新源码CI索引返回HTTP403、remaining=0、reset为2026-10-24 03:37:14 UTC；已停止API请求，不换凭据／接口绕过。新run尚无可核验句柄，因此不称后台已启动或通过。继续人工审查5f原16PNG，并分别设计能力页真实场景的中性supervisor最小抽取和独立合同，未把这些设计当成可跑场景。生产、main、正式Registry未改。

11:31本地追加：原16PNG已逐图检查、原摘要稳定，可见区域中文／布局可读；8张移动首屏未覆盖下方业务动作与完整回执。[视觉后审](evidence/p2-5f17544-visual-followup.json)不覆盖能力页及完整交互。能力场景源审发现总览硬编码Shadow与candidate相矛盾，工作树已修为实际mode和仅总览只读，新2声明／候选306前端尚未执行。三个中性生命周期leaf已机械抽取，205纯CPU用例及根新19名单／事件门通过；旧场景配置不改，完整prepare／supervise／export和capability_truth仍未构造。[明确范围及下一步](P2-CAPABILITY-REAL-BROWSER-PLAN.md)。

## 前序实际事实：5f17544分项成功，整体未通过

截至2026-10-24 11:00（Asia/Shanghai），开发分支最新已推送源码仍为 `5f1754487507f6ec76d7b8872abf6e7cb89bdc07`。限流窗口结束后已取得其attempt 1实际终态；先前“未确认”仅是当时状态。以下是实际结果，不以辅助测试抵消失败：

- [订阅UI40053151066](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40053151066)八producer＋八fresh成功。本机按同源码实际执行50条原CLI，全部exit 0；34份实际fresh逐字节一致，16份旧辅助报告仅producer。16 ZIP／458成员CRC、字节及SHA前后及独立审计一致。
- [父门40053151047](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40053151047)普通／race各2670实际事件通过原检查器；依据连接器解码日志投影，不冒称原始下载日志字节保管。[旧订阅40053150974](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40053150974)CI成功，本轮完整产品CLI独立复算未补齐。
- [镜像40053151084](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40053151084)实际260前端测试通过，随后capability-report.ts的no-control-regex lint失败，后续Vite／Go／Registry未执行。字符码等价修正仅在工作树，未获新CI。
- [探针40053151058](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40053151058)PW原浏览器门通过，CDP仍failedRequests=1；两引擎被动诊断均EXPECTED_EXTRA拒绝，实际原CLI重放与CI同字节。提前ExtraInfo关联修正候选34项Node检查通过，但未证明5f缺失唯一原因，也未修复／豁免原CDP失败。

本机证据：`D:/CodexData/workspace/5f-ui-replay-a2fd685935/result.json`、`D:/CodexData/workspace/5f-ui-journal-audit-8d70910532/audit.json`、`D:/CodexData/workspace/5f-parent-final-ltcck0_s/result.json`、`D:/CodexData/workspace/5f-sidecar-reject-3qv2l13j/facts.json`。这些是本机文件，不是已推送仓库附件。见[能力纠正](P2-CAPABILITY-TRUTH.md)、[诊断边界](P2-PASSIVE-DIAGNOSTICS.md)。

前一候选e6cc的实际[探针40048820014](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40048820014)中，Playwright原完整EOF门已独立重放且与producer同字节；CDP仍failedRequests=1，应用没有CANCEL／ABORT，不能把原因继续归为冗余cancel。[订阅UI40048819951](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40048819951)7个producer成功，负交接CDP在NAVIGATE大阶段失败，fresh全部跳过。e6镜像实际240前端及Go／Registry转录原门通过，不能抵消两浏览器失败，也不能代替本次全部产品CLI独立复算。见[机器事实](evidence/p2-e6cc-partial-ci.json)。

完整快照格式校验已有工作树候选：44个新增测试声明／AST已核，nil数组、omitempty、requireCapabilities及RFC3339Nano按真实Go合同处理；前端304仅是下一门要求，尚未真实运行。能力页／内核页独立真实双浏览器实施卡已完成但未实现，不能由旧订阅／探针浏览器成功替代。原完整功能基线、备份恢复、灰度、生产读回和运营闭环仍未完成；生产、main及正式Registry未改变。

以下保留每阶段当时事实；“尚未运行／正在复核”等描述只对应各自时间，不是当前实时状态。

## 前序e4156d6订阅切片收口与e6cc实施前记录

根D 16 ZIP／446成员全部原件前后稳定，48原CLI均exit0／报告等producer，32份有fresh亦同，16旧84／76仅producer；独立代理另跑CDP反馈完整原CLI并四方同字节，48条耐久执行记录／16包再次核对。镜像1470安全成员、实际前端222及精确旧197＋新25名单、子模块各732／Registry各3、六个产品原门复算与CI同字节；16PNG已实际审看。原e415旧探针双引擎门仍failure，故整体回归不通过。[最终范围与失败](P2-SUBSCRIPTION-FEEDBACK-REPAIR.md)、[机器证据](evidence/p2-subscription-feedback-e4156d6.json)。API限流后不再live请求，最终摘要核对用已保存原API，不能称新实时刷新。

下一默认产品清理候选及独立EOF观测门已实现：完整流／UTF-8／JSON成功后仅releaseLock，失败仍取消；1旧用例显式迁移到JSON拒绝后的取消结算，旧222名字保留，新18仅AST／名单已核；新240是待运行断言，不是通过数。旧v1诊断与八计数门不改，新门实际重放两原CLI再核7个无取消的成功EOF及16份源绑定。584项辅助纯CPU通过（保旧558＋新26，零skip），31工作流shell检查通过。API限流reset01:37:14Z前停止轮询，新源码CI尚未读取。[候选与退出条件](P2-PROBE-EOF-CLEANUP.md)。生产未改、main未合并、完整目标保持。

以下为本轮较早状态，进行中项以本节与任务清单最新事实更新。

### e4156d6首轮状态快照

源码 `e4156d64341f5f92eeca9bfa7c8b09066cf69c64` 原 attempt1：订阅 UI40042582508 八 producer＋八 fresh、镜像40042582526、父40042582510及旧订阅40042582543均 success；**旧探针40042582518两引擎原门 failure**。两原 driver 均 failedRequests=1、其余七错误计数零，具体请求原因待查，原门不放宽。镜像实际前端222及候选证据正在独立复核，不以状态代完整验收。父2644 ordinary/race和旧订阅80项／926 Git已分层核查，但不代表生产或全部功能完成。

本机 C:/Temp 原解包副本出现验后字节变化，原ZIP仍与API摘要／CRC一致；不归因硬盘、内存或产品。异常不覆盖、旧本地稳定性失败不记通过；从原ZIP在 D 新目录独占创建＋fsync＋全成员前后摘要重建。根新16 ZIP／446成员的48原CLI复算正在进行，已完成十份按原工具 exit0／摘要保留，只补38缺项；旧分析进程确实缺失后才补，不重跑CI。并行子代理继续镜像、保管／截图及探针诊断，唯一集成者更新；生产未改、main未合并。详见[当前成果、失败与边界](P2-SUBSCRIPTION-FEEDBACK-REPAIR.md)。

下一退出条件：新 D 原件与实际报告复验稳定，逐项核镜像前端／Go／候选证据，并查明探针失败；真实 unknown／timeout、完整B01–B23、灰度／回滚／生产读回仍未完成。不折算虚构完成百分比。

## 本阶段历史提交：fbddae3 首轮前端5失败

实际源码 fbddae3 的 UI40042077078／attempt1 八 producer＋八 fresh success，但镜像40042077114／attempt1 前端原 JSON 为222项中217 passed／5 failed；不是全绿或上线。失败来自一个旧测试的重复 status/alert 文案与四个新测试的宽泛文本匹配，原失败保留。最小修正区分提示并精确定位未决说明，旧197和新25名单／锁断言均不变，修正后新源码尚待实际 CI。详见[原记录和修正边界](P2-SUBSCRIPTION-FEEDBACK-REPAIR.md)。

下段保留首次提交前实现状态；实际 CI 以上方新事实为准，不把先前“尚未执行”误读为从未运行。

已修改产品反馈：已知拒绝清除旧等待；未知／超时改为待核对且保留未决锁；历史回执不得覆盖在途提示或解锁无关命令。新增 25 项前端测试仅完成 AST 解析和名单核对，尚未运行 Vitest／类型检查。根实际纯 CPU 558 项、零 skip，保留旧 498，新增反馈辅助 60；双引擎真实反馈补层与 fresh 接线已实现，尚无本阶段 CI 结果。原九份前端测试未改，前端 CI 门保留旧 197 及新 25 名单。三子代理交叉复核、单一集成者提交；本机未安装／构建／启动服务或浏览器，生产未改、main 未合并。[本阶段实现与验收边界](P2-SUBSCRIPTION-FEEDBACK-REPAIR.md)。

下一退出条件：新源码原 attempt1 的实际构建／222 项前端测试／双引擎业务与反馈／fresh 及旧回归完成，原件独立复算与截图审看后再更新状态；不能把辅助测试通过写成产品修复已验或已上线。

## 最近已完成的有限验收：cc86661，业务负例通过，历史UX缺口保留

[原CI40039043139](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40039043139)/attempt1八producer＋八fresh全success，无重跑或取消。根44原CLI均通过且与producer逐字同，其中真实fresh28份同；旧84/76的16份仅与producer比较。16原ZIP426成员摘要/CRC/逐byte及B/C同包均核，925Git，16PNG已分工实际审看。新场景49阶段/79浏览器请求/10浏览器POST＋2独立nativePOST/11命令/3批准/23外审/A2B1/隔离候选及unknown节点/3连接12wire，4进程正常退出，8counter0。498纯CPU保旧390与新108零skip。**但明确拒绝后仍显示旧“正在等待”notice，属于看图实测且尚未修复的UX问题，不称无bug或全闭环。** [实际记录](P2-SUBSCRIPTION-HANDOFF-NEGATIVE-PLAN.md)、[机器证据](evidence/p2-subscription-handoff-negative-cc86661.json)。

| 当前交付 | 实际状态 | 下一退出条件 |
| --- | --- | --- |
| B09授权、批准交接拒绝、失败回执与stale CAS | 已实现并完成本轮双引擎业务隔离验收 | 策略退役/材料轮换/真实并发及完整B09仍需补齐 |
| 原创建/回执、本地准入、远程正向抓取 | 同源码双引擎回归及原件复算通过 | 不替代全部旧探针/镜像回归 |
| 失败/未知操作反馈与页面闭环 | 部分完成；已确认notice残留 | 优先修复已知拒绝/未知/超时的反馈，增加回归与真实UI证据 |
| 完整B01–B23及整套企业功能 | 未完成 | 继续按完整缺口逐项实施，不折算整体百分比 |
| 备份恢复、灰度、生产读回、长期运营 | 本阶段未执行 | 单独授权、备份、回滚与实际运行验收；生产未改 |

## 历史阶段快照

下列“当前/待实施”等措辞按当时状态保留，由上方最新事实更新，不回填历史失败为成功。父40039043164及旧订阅40039043154本轮分层通过详见最新实际记录，不能替代完整旧回归。

更新日期：2026-10-24（Asia/Shanghai）。开发分支：`codex/chengwang-security-hardening`。后端原生验收源码：`700ea9ed2f58b267d1530ffcacc0a3f3cdba2dbb`；能力事实同步源码：`2fe1231de851417e7825b9c8b02083acf1ad08f3`。本台账由单一集成者按实际证据更新，不是产品自动生成的完成率。

**最新有限验收通过：dbc3f23三场景双引擎。** 原UI40033595196/attempt1六producer＋六fresh全success；根六产品/六依赖/六nav58/两remote86原CLI与producer/fresh同字节，旧84/76十二报告只与producer比；32原CLI均通过，每成功产品910Git。12原ZIP304成员APIsha/CRC/验后逐byte核并与B/C原ZIP相同，根看新CDP两PNG、B看旧8PNG。新失败前快照/闭集投影/独立诊断已实现，390纯CPU保留旧332零skip；但本轮无真实失败，available:true失败链路及96e偶发根因仍未实证，不能称已修或全系统上线。root240秒离线包装器超时原记录保留，仅补缺失报告且原checker/CI/浏览器预算均未改。[本轮实际成果](P2-CDP-NAVIGATION-DIAGNOSTICS.md)、[机器证据](evidence/p2-navigation-diagnostics-dbc3f23.json)。

**当前开发中：B09真实负例，尚未完成真实CI验收。** 三子代理分别实现隔离fixture/驱动/独立检查器，主集成维护辅助原日志门、CI与台账。唯一事前合同在 `tools/subscription-ui-browser/handoff-negative-contract.json`：49阶段、10个真实界面POST与2个单列API-only POST、6个界面回执GET；预期11命令/3批准/23外审/A2B1/1隔离候选/12wire均为待验证断言，不是实际成果。不得把来源版本增长或时间流逝当作自动废除批准；失败命令仍产生prepared/result外审。新增场景不扩旧成功合同，旧导航失败诊断暂不支持该新场景。[负例实施卡](P2-SUBSCRIPTION-HANDOFF-NEGATIVE-PLAN.md)会在真实原件验收后补实测。父40033595211和旧订阅40033595140的历史分层通过，不能替代本阶段全旧探针/镜像回归、B01–B23、故障/恢复、正式灰度及生产读回。本阶段没有生产变更。

本阶段提交前实际集成检查已进至498项纯CPU全通过、零skip：旧390＋新108，五原日志门/四重复事件反例/7AST/6JS语法/14shell通过；新八producer/八fresh只完成接线，真实运行与原件复验尚待执行。未因新测试通过提升生产能力等级，也未声称完整B09或整个系统已交付。

**本轮部分实现已验，整体未通过：96e51e4批准 → 交接 → 真实抓取。** 原UI40030609894/attempt1终态failure：新remote/PW成功，remote/CDP及旧create/CDP失败，另三个旧producer成功；整个fresh仅占位job跳过、未展开六重放。根/C新PW完整原CLI与CI报告逐字同，33steps/47requests/4mutations/900Git、正常三类TLS/3conn12wire/4进程wait0/8counter0；根/B三个旧成功完整原CLI同producer。两CDP仅UI_RUN/NAVIGATE/6启动捕获/0捕获写入，尚无唯一根因，不猜测修复。六原ZIP215成员APIsha/CRC已核，原失败保留不rerun；没有生产、main合并或正式发布。[本阶段实际结果](P2-SUBSCRIPTION-REMOTE-FETCH-UI.md)、[机器证据](evidence/p2-subscription-remote-fetch-96e51e4.json)。

提交前根实跑纯 CPU：旧84＋旧76＋新remote86＋依赖86＝332项，零跳过；三辅助原日志门及7 Python AST/4新JS语法/11工作流shell语法通过。原件在 `C:/Users/Administrator/AppData/Local/Temp/cw-remote-root-cpu-sp0rri2c/`。无本地依赖安装、构建、浏览器或服务运行；真实 Linux 双引擎、原件独立重放与 PNG 检查仍待执行，不能把332项测试当上线或完整B08/B09/B10通过。

上述提交前状态由首轮实测补充：四个成功产品完整原CLI已由根及独立代理重放，8张成功首屏PNG已看（新PW2张由根看，旧6张由B看）；但双引擎整组/fresh仍未通过。根本机首轮openssl缺PATH的四拒绝保留，后来仅子进程加入已有Git/usr/bin、同源码原CLI通过，不改全局或原门。A另行核父40030609903 ordinary/race各2644与旧订阅40030609922原80项/889Git，两Linux报告同字节；Windows完整旧POSIX门仍拒绝。下一步只补CDP受限诊断，先查固定GitHub官方实现，不以假设替代证据。

**本轮有限隔离CI通过：7fdd401固定pin私有Signed-By。** 原UI40027039958/attempt1四producer＋四fresh success；根/B/C四个原依赖完整CLI报告、根/B四个原产品完整CLI报告分别与producer/fresh逐字一致，160原成员三方逐byte核对。实际原86项35＋26＋10＋15保留旧64且零skip；旧84/新76产品辅助项单列，每份新产品报告886个Git源blob、八错误计数全0。B与根已实际看8张原桌面1440/手机375首屏PNG。根初次CRLF及后续临时长路径拒绝均保留，最终在新短exact-LF副本完成同原门，不改原checker。仅两个既定场景/两个引擎范围，不等于完整B01–B23、长期稳定或上线。[实际成果与边界](P2-CI-PRIVATE-APT-SOURCES.md)、[机器证据](evidence/p2-ci-pinned-keyring-7fdd401.json)。

**本轮父门/旧后端另行分层通过。** A独立核7fdd401父门40027039955/job120665721182的ordinary/race各2644实际Test配对及原gate/旧基线转录重放，Fuzz各4顶层＋8 seeds另计；旧订阅40027039924两Linux原门、80实际单测/20文件/875 Git和逐字同报告通过。Windows原POSIX custody仍拒绝public-file-open-race，未绕过。这些结果不替代新UI完整原件验收，也不证明公网业务、完整系统或生产。

**历史失败与保管勘误保留。** fe8968e原UI40025542946四producer仍为PRIVATE_KEYRING_MODE、fresh skipped，原64/24成员事实不变；a76ec5e/5657e33同样不回填成功。A后审根三旧CRLF clone：初次CLI虽exit1/noPASS，但sourcebind先行阻断，不能当作已验证outcome拒绝。另建exact-LF副本核原Git字节和sourceInputs后，12次原完整依赖CLI均exit1/noPASS，补足拒绝验证；旧clone/原JSON/logs未改。追加审计23909B、SHA `6c149e9aaac029932d26428e2d0ddd9d2a22239597cda1c727be057412176a33`，已归档[机器勘误](evidence/p2-ci-historical-custody-correction-20261024.json)，路径及分轮解释见[保管勘误](P2-CI-PRIVATE-APT-SOURCES.md)。不以新的成功覆盖历史失败。

**前序c7失败保留**：[c7b64c4实际验收](P2-CI-DEPENDENCY-ACQUISITION.md)：原run40018960129终态failure；两PW实际安装/包字体读回及既定产品原CLI通过，根/B产品报告逐字同、各879 Git blobs，根/B/C依赖报告逐字同；两CDP均INSTALL240s退出124，浏览器未启动，fresh跳过。四份新26原输出均逐名核验零skip，80原ZIP成员三方同；这些证明限时退出/拒绝生效，**不证明下载可用性修复或整组UI回归通过**。具体网络根因未证，后续方案已先核GitHub源码/测试，未改生产。父门40018960021及旧订阅40018960055成功，根核状态/A分层原件复验，不冒称根完整旧POSIX CLI通过。[机器台账](evidence/p2-ci-dependency-acquisition-c7b64c4.json)

**前序已验增量 `8c4852c`**：双来源本地准入及历史候选决定按钮修复隔离验收通过；四producer/四fresh成功，根/独立子代理四完整原CLI逐字同，实际859 Git blobs。历史候选6条按钮禁用、当前待审8条启用，4张新首屏PNG已查看。前端193/193零跳过原JSON/日志与原Git gate已根/子代理复验，旧190基线保留；镜像CI成功。[原件与边界](P2-SUBSCRIPTION-LOCAL-ADMISSION-UI.md)。该源码旧探针CDP回归因failedRequests=1严格失败，历史整体失败保留；完整 B01–B23、全旧产品子CLI独立重放、灰度和生产未完成。不会以新UI成功抵消旧门失败。

前序 `c15eda3`：双来源正常流通过，但6条真实DOM历史候选仍可准备决定；[原机器证据](evidence/p2-subscription-local-admission-c15eda3.json)保留缺口。`8c4852c` 的新原件只证明后续修复，不回填历史。更早 `aedd194` 的创建/回执[历史验收](P2-SUBSCRIPTION-UI-REAL-FLOW.md)仍按该源码与范围解释。

当前实现增量：[隔离请求关联诊断](P2-PROBE-REQUEST-BINDING.md) 已落默认关闭的匿名身份头、同次取消结果观察、独立受限FD与原件验真。16ad525两条真实浏览器原件经根+C各16原CLI重放，CI/根/C报告逐字一致；各7请求全绑定、7取消均RESOLVED、八错误计数全0，872源blob独立核实。b68a55e原197项前端/9文件通过且原193名单保留；父门/旧订阅已分层复核。**原订阅UI40013130002三条producer验真通过，最后admission/CDP在61.2MB字体依赖获取未完成时超过22分钟上限而cancelled，fresh跳过，整组不通过；下载阻塞根因未证明。本轮无真实失败探针请求，历史8c偶发故障未归因。4eca新增TS错误、b68新增CI传参错误原失败均保留；不等于全系统或生产完成。** [机器证据](evidence/p2-probe-request-binding-16ad525.json)

订阅页前序结果：P2-06a 源码 `8f610a4` 已接订阅资源页、安全权限元数据及明确的批准交接双模式。父门ordinary/race各2644、前端190、子模块各732及旧名单已按原始证据复验；镜像CI及订阅producer/fresh Linux原门成功。但旧探针CDP回归因一次取消请求严格失败，PW成功，原因仍未唯一归因，故该轮整体 **未验收通过**。详见[该轮验收记录](P2-SUBSCRIPTION-UI-ACCEPTANCE.md)及[机器证据](evidence/p2-subscription-ui-8f610a4.json)；[首轮失败](evidence/p2-subscription-ui-attempt-9c622a2.json)保留，不靠重试覆盖。P2-06b 的[订阅双浏览器完整计划](P2-SUBSCRIPTION-BROWSER-ACCEPTANCE-PLAN.md)仍待逐项完成，不能借下文探针页面的历史成功。生产、本轮完整系统发布和灰度均未执行。

前序增量 `ad3e4db`：闭集诊断与新订阅DOM collector已实现，五条隔离CI均终态。父门各2644、前端190/子模块各732、订阅两Linux原门及原生backend22均按原工件复验；旧浏览器该轮CDP成功、PW因一次取消严格失败，整体未验收。两诊断均收81条、无观察的应用ABORT/cleanup且流到EOF，缩小排查范围但未证明唯一根因。该轮Chrome未pin、revision/Node原stdout未归档，不能事后补造。详见[该轮实际验收](P2-STATUS-DIAGNOSTIC-ACCEPTANCE.md)及[机器记录](evidence/p2-status-diagnostic-ad3e4db.json)。历史失败保留，新的保管成果见下文，不能回填旧工件。生产未动。

P1历史结果（不替代上述最新失败）：`cadb9f4b5ecf63f3bf1556ffe61ed274d304c0a2` 的 CDP 与原生 Playwright 已分别完成真实浏览器闭环及原 ZIP 独立重放，正常 TLS、实际证据读回/自然过期、8 错误计数全 0、Node/Chrome 正常退出均通过；父门及原生后端也已独立复验。镜像信任绑定 CI 已 success，前端 117/117、子模块 ordinary/race 各 732、旧基线和源码绑定已独立核验；未逐一独立重放全部旧产品子 CLI。摘要单飞与超时/迟到结果所有权修复通过该历史轮次，但不据此声称已唯一证明取消根因。详见[双浏览器验收记录](P1-PROBE-BROWSER-ACCEPTANCE.md)。未修改生产、未合并 main、未正式发布镜像。不将测试数量折算为整个企业系统的完成百分比。

最新前置增量 `22f0757`：两真实浏览器均成功，身份侧录及原80输出保管、新56合成门均完成独立验原；根从两原 ZIP 重放12个 CLI 报告逐字相同。实际仍运行旧 Chrome155（revision已真实侧录），不能据本次绿色消除历史偶发取消。候选CfT157已在两Linux取得/重算，并完成根端来源审核，另起参考pin记录真实SHA；**尚未由执行门消费、尚未运行**。父门各2644/native22/订阅两Linux及镜像CI均成功；镜像190前端、Go各732、Registry各3与旧名单亦经原三CLI代理/根复验，另七旧产品CLI未逐项独立重放。[实际成果和剩余边界](P2-BROWSER-IDENTITY-ACQUISITION.md)；[机器证据](evidence/p2-browser-identity-acquisition-22f0757.json)。新订阅页E2E、候选正负矩阵和系统上线仍未完成，生产未动。

## 当前阶段进度

最新已验增量 `409aa9c`：[pin强制消费/安全展开](P2-BROWSER-PIN-CONSUMPTION.md)已在原 run39988647783 的 producer/fresh 两Linux实际通过，根/代理复核小包原件及精确Git5。实际301文件/309成员、全部CRC与落地hash、305061192B Chrome ELF结构一致；20合成项只计producer一次。没有执行浏览器，不证明runtime或取消修复；父门39988647521与订阅39988647516均终态成功，尚未在本阶段逐项独立重放其全套原门。历史参考pin未改。

最新已验增量 `7291655`：[五case正常TLS/CDP/PW固定候选矩阵](P2-BROWSER-STREAM-MATRIX-ACCEPTANCE.md)原run39993513218五job均success。真实Chrome157/revision/ELF已读回，104原事件0skip；每引擎5case/6请求/18网络事件/24server事件、正常TLS与三进程真实wait0，无强制干预。5原小包/41原文件核对，829Git；producer/fresh/根/代理完整报告四方逐字一致。首轮 `de875c0` 原失败保留，仅按精确Chromium源码修正成功FINISH时间语义，未改原时间或忽略失败。[机器证据](evidence/p2-browser-stream-matrix-7291655.json)保留旧失败与新实测。

另行原件验收：父门39993513211终态success，根/代理精确Git checker复验ordinary/race各2644 Test恰一次、零skip/fail，各12 Fuzz另计；订阅39993513263两Linux完整原门success，原20/46/4/26/102、819Git和80实际单位名单经代理语义复验，根/代理核两原包摘要及报告相同。Windows完整POSIX custody仍原样拒绝，不冒称本机全门通过。**实际产品候选接线、新订阅页面E2E、旧产品浏览器/镜像的新候选回归、灰度和生产均未完成**；不把协议矩阵替代这些要求。

| 编号 | 交付项 | 实际状态 | 证据与剩余边界 |
| --- | --- | --- | --- |
| P1-01 | 安全 reader、缓存、匿名摘要与 RBAC 明细 | 已实现并隔离验收 | [基础接线验收](P1-PROBE-READBACK-ACCEPTANCE.md)；默认关闭，不等于生产已启用 |
| P1-02 | 真实 agent 经正常 DoT/HTTPS 写入结果 | 已实现并隔离验收 | 两轮 6 个原始结果，ledger 7/13 联合结算；[本阶段证据](P1-PROBE-NATIVE-BACKEND-ACCEPTANCE.md) |
| P1-03 | 真实主 API、重启读回、自然过期 | 已实现并隔离验收 | fresh/重启均读回 6 样本；到期后 0 样本、3 目标 unknown；源数据不变 |
| P1-04 | 独立检查器与失败关闭反例 | 已实现并隔离验收 | 44 辅助检查、24 wire 前置检查；原始 22 输入独立重放，失败历史保留 |
| P1-05 | 原有后端回归 | 已复验 | P1历史 `cadb9f4` 各2403，当前 `7291655` ordinary/race各2644原门已独立复验，旧名单保留；各12 Fuzz函数/seed另计，不折算产品完成率 |
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
| P2-05 | 产品 API / RBAC / 独立写门 | `f0c23d6` 有界隔离验收通过：ordinary/race 各 2620 Test，新 130 齐全；原生/CDP/Playwright 原工件重放通过；同源码镜像 CI success，前端 117、子模块各 732、原 Registry/source/source-TLS 三门独立重放通过；详见[应用验收](P2-SUBSCRIPTION-API-ACCEPTANCE.md) | 仅本地准入后端，非完整编排/生产；后续独立主进程/公共地址 fixture Fetch 见 P2-05b；订阅资源页与其余旧产品完整 CLI 独立重放仍未完成 |
| P2-05b | 独立 cmd/server 与受信公共地址 pin 抓取产品链路 | `2b0a472` 有界隔离验收通过：80 辅助项实际通过，46 API/4独立进程/26连接/102事件，两Linux原门报告与本机原字节语义重放一致；同源码 ordinary/race 各2620/旧名单保持。详见[阶段验收](P2-SUBSCRIPTION-PRODUCT-ACCEPTANCE.md)，首轮[失败](evidence/p2-subscription-product-attempt-2a68973.json)不覆盖 | 本机Windows不是完整POSIX CLI；私库只是安全投影；公网地址fixture不是真实互联网，节点仍unknown；未验UI/调度/内核/备份/发布/生产 |
| P2-06a | 订阅资源界面与安全权限元数据 | `8f610a4` 已实现并完成部分隔离验收：Go各2644、前端190、子模块各732及旧名单通过，镜像CI/旧订阅后端成功；但旧CDP一次取消导致整体未验收。[实际记录](P2-SUBSCRIPTION-UI-ACCEPTANCE.md) | CDP原因未定，不能被PW成功抵销；新订阅浏览器/跨角色批准上下文自动读回/任意URL与私有CA目录编辑器仍未实现；未上线 |
| P2-06b-0 | 固定浏览器原件消费与正常TLS协议前置矩阵 | `409aa9c` pin/解压与 `7291655` CDP/PW五场景及fresh原件均隔离验收，完整四方重放一致 | 独立协议fixture，不是产品新页面、历史取消根因或生产验收 |
| P2-06b | 真实订阅页面双浏览器闭环 | `7fdd401` 在v3私有Signed-By下四producer/fresh与根/B原完整产品报告逐字一致，每份886 Git、8PNG已看，旧84/新76单列；限创建/回执和双来源本地准入两个既定流程。[最新依赖与复验](P2-CI-PRIVATE-APT-SOURCES.md)，业务原计划见[原验收](P2-SUBSCRIPTION-LOCAL-ADMISSION-UI.md) | 历史8c旧CDP失败不回填；完整B01–B23、来源批准/交接/DoT抓取、跨scope后端拒绝、分页/故障/同库重启、全部旧产品回归仍待完成，未上线 |
| P2-06 诊断增量 | 有界取消观察与订阅DOM collector | `ad3e4db`历史独立80合成门与诊断原件重放通过；该轮PW严格失败不覆盖 | 原因未唯一证明，不能回填该轮缺失的revision/Node stdout；订阅DOM仅合成。[记录](P2-STATUS-DIAGNOSTIC-ACCEPTANCE.md) |
| P2-06 身份与保管前置 | 真实revision/ELF/进程绑定、原80输出、候选获取 | `22f0757`双浏览器真实身份及原12 CLI报告根重放；原80/新56分别通过；候选两Linux获取与来源审核通过 | 参考pin尚未被执行门消费；alpha候选尚未运行、严格正负矩阵/新订阅E2E未做；本轮成功不证明历史偶发取消消除。[记录](P2-BROWSER-IDENTITY-ACQUISITION.md) |
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
| `7fdd401` | 原四producer/四fresh成功；原86/旧64、根/B/C四依赖与根/B四完整产品报告逐字同，每份886 Git/84＋76/八计数0，160原成员、8PNG已核；两次本地保管失败保留后根短LF副本完成。A另核父门各2644及旧后端80/20/875 Git | 手机完整交互、全部B01–B23/旧子门、清单PGP独立验证、长期下载/自动轮换或生产完成 |
| `fe8968e` | 原64项纯测试四份全通过，但真实UI四producer为PRIVATE_KEYRING_MODE、fresh跳过；原24成员保留。根初次CRLF源绑定拒绝不作outcome证据，A新LF副本四CLI拒绝补验；父门与旧后端分层通过 | 实际mode数值/来源已知、历史UI转绿；初次泛型exit1即证明正确业务拒绝；Windows完整POSIX CLI通过或上线 |
| `5657e33` | 18个闭集原因/原51测试；四producer定位PRIVATE_KEYRING_READ、fresh跳过。根初次CRLF sourcebind拒绝保留，A新LF副本四CLIexit1/noPASS补验 | 具体坏权限/软链等原因已证、初次泛型拒绝已到outcome、私有源/安装/UI成功或上线 |
| `a76ec5e` | 原49测试；四producer PRIVATE_SOURCES，APT2.8.3、host指纹同且未update/install。原24成员保留；根初次CRLF拒绝勘误，A新LF副本四原CLI拒绝补验 | 私有镜像已生效、初次CRLF副本符合精确原字节、安装期限/下载/UI/fresh通过 |
| `c7b64c4` | CI依赖有界准备/读回实现及26唯一测试；两PW真实安装与既定产品流程/879源/84+76原辅助门，根/代理原件复验；两CDP安装240s退出124，fresh跳过，原run整体failure | 下载阻塞已解决、两CDP浏览器通过、fresh已复验、所有业务/全系统完成或生产已上线 |
| `8c4852c` | 新UI资格及正常流程四方原CLI验收；859 Git、历史false/当前待审true；前端193原件/原190基线复验、镜像CI成功。父门各2644与旧订阅分层复验；旧探针CDP failedRequests1严格失败保留 | 本轮整体回归通过、全部旧子CLI已独立重放、根因已证明、完整订阅/节点可用或上线 |
| `c15eda3` | 双来源正常流四方原CLI验收；实际发现历史候选决定按钮资格缺口 | 正常流通过等于完整交互通过，或后续补丁能回填原缺口 |
| `aedd194` | 实际订阅页 CDP/PW 创建/回执，四原 job 成功，846 Git/14请求/11DOM/唯一POST/正常TLS/wait0/八计数0；四方原CLI逐字一致、四张PNG实际查看；父门各2644及旧订阅分层复验 | B01–B23全部完成、候选旧产品全回归、抓取/节点可用、镜像/灰度/生产或历史取消唯一根因已解决 |
| `7291655` | 精确Chromium源码支持的时间语义修正；双引擎真实157/五场景/正常TLS/退出、104新辅助事件及四方原件重放通过；父门各2644与订阅原门分别复验 | 实际产品已切候选、订阅页E2E、补丁二进制祖先、历史偶发问题或生产已解决 |
| `de875c0` | 原run39992474501首轮96合成通过、两实际执行成功，但独立CLI时间假设拒绝，整体failure/fresh skipped；原件与失败保留 | 新源码通过可以回填旧源码成功 |
| `409aa9c` | 两Linux真实强制pin/安全解压/CRC/落地hash/ELF结构验证通过 | 已执行浏览器或已修复产品问题 |
| `22f0757` | 真实身份、原80 stdout/事件保管、独立新56门；两原浏览器原ZIP/12 CLI根重放逐字同CI；候选官方原ZIP两Linux取得重算，并另起参考pin。父门/native/订阅/镜像关键原门均复核，七旧产品CLI等缺口明确留存 | 参考pin已经消费、候选157已经运行、历史偶发取消已消除、新订阅页E2E、完整产品或生产已完成 |
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
| `f0c23d6` | 订阅本地准入 API/RBAC/批准/耐久回执与恢复隔离验收：新 130、全主模块每轮 2620 与旧名单保持；原生/CDP/PW 原工件双重重放，同源码镜像 CI success 与原三 CLI/前端门独立重放；两轮父门失败、一次 native stop 失败和未执行 pending 均保留。详见[应用验收](P2-SUBSCRIPTION-API-ACCEPTANCE.md) | 订阅资源页、完整公共来源抓取/内核、自动调度、所有旧产品 CLI 独立重放、完整编排或生产已完成 |
| `2a68973` / `2b0a472` | 独立订阅产品实验首轮严格失败并保留；修正fixture有界发送计数、独立门不放宽，第二轮producer+freshLinux完整原门通过，原报告三方一致；同源码父门2620/旧名单完整复验。详见[P2-05b记录](P2-SUBSCRIPTION-PRODUCT-ACCEPTANCE.md) | fixture公网地址等于真实互联网、节点业务健康、订阅UI、调度、系统恢复或生产已完成 |

下一顺序：已审候选 pin 消费、正常TLS协议矩阵、真实创建/回执及双来源正常准入/当前CAS回退已分层验收；完整角色/异常矩阵仍未完成。先基于官方源码及单次请求关联诊断解决旧探针CDP失败，不预判根因 → 来源批准/交接/实际DoT抓取 → 分页、未决命令、故障与同库重启 → 候选旧探针/全部旧产品子CLI完整回归（本轮镜像CI成功不能替代全量独立重放）→ 自动刷新/完整内核配置及隔离校验 → 单目标隔离发布/读回/回滚 → 获批后才进入生产备份、灰度和观察。不放宽失败计数、TLS、no-store或字节/时间预算，不以多次运行挑绿灯。现有 `executor_not_configured`/授权阻断不因局部API或浏览器通过而解除。每次阶段结束更新提交、已验/未验项、原始证据路径和生产变更记录。
