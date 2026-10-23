# P2：批准交接负例的下一阶段实施卡

状态：`cc86661adb969ecd4c958ca16769e8b90bd1afbc` 的隔离业务负例与原件分层验收通过，存在已实测、未修复的notice UX缺口。不是完整B09、B01–B23、全系统或生产验收。本卡不授权生产变更。

## 原CI进展与已发现缺口

[原运行40039043139](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40039043139) attempt1已终态success，八producer＋八fresh全部成功，没有重跑或取消。主集成已独立核16个公开ZIP/API摘要/CRC/426个成员，原件在 `C:/Users/Administrator/AppData/Local/Temp/cw-cc8-root-originals-nygdlf81/`；精确Git短LF副本 `C:/Users/Administrator/AppData/Local/Temp/cwcc8-y3hp5_y9/r`。根44次原完整CLI离线复算均exit0，与producer全部逐字一致；有真实fresh的28份也逐字一致，旧84/76共16份只对producer，不虚构fresh。全部ZIP与B/C独立获取的原ZIP逐字相同，成员验后未变；本轮没有离线包装器超时或任何CI重跑。[机器证据](evidence/p2-subscription-handoff-negative-cc86661.json)记录每次原CLI与原件摘要。

原新场景两个引擎各报告49阶段/79浏览器请求/10浏览器POST＋2原生API POST/6界面回执GET；11命令/3批准/local audit3/external23/A2B1/1quarantined候选/2unknown/3连接12wire，925个Git源blob。根/C原完整CLI报告与producer/fresh四方逐字一致。每引擎四个UI交接409、跨owner GET403、五个本人failed receipt GET200，以及单列native批准403/staleCAS409，按case/actor/source/receipt绑定；命令prepared/result各11＋denied1，不按相邻假设配对。正常API/DoT/HTTPS证书按捕获时间离线验证、八错误计数0、四进程正常退出/无强制信号；控制器前缀不是perHTTP包级因果或独立执行公证。

根已实际看新两引擎4PNG，B看旧create/admission8PNG，C看旧remote4PNG；合计16张，桌面1440×900与手机375×900，手机仅首屏不等于完整移动流程。没有空白或框架overlay，仍发现下述notice缺口。正常业务证据不代替视觉审看；PNG校验自身也不证明体验无问题。

本轮新增的是隔离验收、原生HTTPS安全采样与证据闭环，没有修改产品后端或React实现，更没有新增生产分流能力。根44次原版离线CLI分解为8产品＋8依赖＋8导航辅助＋2远程辅助＋2负例辅助＋16旧84/76辅助；不能说成44次完整业务运行。实际业务只在原Linux CI运行，离线重放不启动服务器、浏览器或数据面。

父门[40039043164](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40039043164)及旧订阅[40039043154](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40039043154)另由A分层复验：父ordinary/race各2644 Test、每种4 Fuzz顶层＋8 seeds（不是持续fuzz）、static176/shell13/增量26；旧订阅80项/20输入/914 Git，两Linux2496字节原报告一致。Windows完整POSIX reader仍按原门拒绝public-file-open-race；未改门、未冒称根本机完整POSIX CLI通过。这些不等于全部旧探针/镜像新回归或整套产品已验。

**实际看图发现、尚未修复的UX缺口：** 两引擎 `unknown_failed` 桌面截图已显示明确拒绝、来源与候选标旧，但仍保留“正在等待服务端结果；尚未确认成功。”进度提示。`Subscriptions.tsx` 的submit先写入notice，catch/timeout未更新；DOM collector尚未投影notice，所以原业务门没有覆盖此状态文案。本轮授权/回执/审计断言成功不能升级为UX完全闭环或无bug。下一增量需按已知拒绝与未知/超时分别结束等待或显示待核对，保留回执和未决锁，并增加测试；本提交不偷偷改旧成功合同或回填看图结果。

## 集成进度与实现边界

三子代理分别负责隔离fixture、双引擎驱动与独立检查器，主集成负责辅助转录检查门、CI接线、交叉审查和台账。唯一集成合同为 `tools/subscription-ui-browser/handoff-negative-contract.json`，暂定49阶段/22公开原件；不另建deploy副本，原有14/21文件成功合同不变。新场景导航失败明细目前不受旧诊断合同支持，不借用旧场景身份冒充已采集。

原生API sampler只发两个API-only POST，与浏览器CDP捕获分开。仍在原Node控制器进程内使用原生HTTPS，不增加服务、依赖或绕过TLS；证书实测在响应回调、socket尚未关闭时复制，END再核complete/aborted。安全头仅导出command ID与denial audit，不能导出令牌/任意请求头。

已核Node v22.23.3固定源码提交 `80dc632040e6bada37aac1220dde9c79581c9c22` 的[HTTPS实现](https://github.com/nodejs/node/blob/80dc632040e6bada37aac1220dde9c79581c9c22/lib/https.js)、[TLS实现](https://github.com/nodejs/node/blob/80dc632040e6bada37aac1220dde9c79581c9c22/lib/internal/tls/wrap.js)及[官方TLS文档](https://github.com/nodejs/node/blob/80dc632040e6bada37aac1220dde9c79581c9c22/doc/api/tls.md)，不凭猜测调用旧 `_tls_wrap` 内部入口。根另行读取该固定提交HTTPS/TLS文档，22115/101672字节，SHA256分别 `0a86b0bfeea5ad082eaef7b99f681c876854c58f7f7244f5867ab9196ea6972b` / `47d582676d584b53643c79475f6c61770ca5ff21db89372b8d3d73146debbf87`。这些只证明资料核对，不证明新sampler已真实运行。浏览器插件不可用，验收继续沿现有已批准隔离CI/CDP与Playwright两路径，不在本机安装、构建或启动运行环境。

提交前旧回归已于本工作树纯CPU实跑：390项（84创建/回执、76本地准入、86远程辅助、86依赖、58导航）零skip，四原日志检查门通过，14个CI shell块全部通过bash语法检查。原件目录 `C:/Users/Administrator/AppData/Local/Temp/cw-handoff-root-cpu-pr2oycvx/`。该检查只证明旧辅助合同暂未被新增分支破坏，不证明新49阶段、真实浏览器、API或全系统验收；整合后的新旧测试仍须重跑。

后续集成纯CPU已实跑498项，旧390保留，新增108=fixture16＋独立checker32＋辅助日志checker12＋Node合同32/API mocks16；零skip。五原日志门、四份真实转录复制后重复事件反例拒绝、7 Python AST、6 JS语法、14 shell块均通过。原件 `C:/Users/Administrator/AppData/Local/Temp/cw-handoff-root-cpu-znx1hue2/`，`root-cpu.json` 4447字节/SHA256 `c6e4c006493e2cb2403d30cd71d1d9ad14e952c6697930aa1b548bc042e9d561`。B48名单按原辅助门约定sorted LF/no尾换行SHA `62550e3a811d1f717c585de07911f855a01b0de470d013ed45781cd72897c3ce`；有尾换行是不同摘要，不能混作漂移。全部仍是纯CPU，不是新49阶段运行结果。

交叉审查已修三处实现风险，均不冒称真实故障已发生：CDP HEADERS/FINISH各自不早于START而不强加相互时间顺序；新来源自动GET可能早于异步响应体学得ID，先闭集校验、最终由两CREATE回执逐路由绑定而不阻挡真实UI；失败收尾时sampler同步/关闭异常不得短路浏览器关闭和部分证据保留，正常成功路径仍严格要求关闭成功。同句柄串行 `writeFile` 的追加位置依据另核[固定Node官方实现](https://github.com/nodejs/node/blob/80dc632040e6bada37aac1220dde9c79581c9c22/lib/internal/fs/promises.js#L451-L483)，不是靠函数名字推断。

| 交付部分 | 当前事实状态 | 尚需证据 |
| --- | --- | --- |
| 单一合同、隔离fixture、双引擎驱动、独立API sampler及检查器 | 已实现、498纯CPU＋本轮真实隔离业务验收通过 | 其余完整订阅与系统矩阵 |
| CI八producer及八fresh接线 | 原attempt1全success；根44原CLI复算、独立代理与16PNG审看完成 | 不是正式发布/生产证据 |
| 实际49阶段、正常TLS、11命令/23外审 | 原API/DOM/审计/wire/进程绑定通过 | 私库投影为可信runner观察，不是独立原库证明 |
| 写入失败后的notice反馈 | 看图确认旧等待文案残留，尚未修复 | 下一增量修复并补已知失败/未知/超时与真实UI反馈验收 |
| 完整B01–B23、企业系统、灰度生产与回滚 | 未完成 | 不以本切片替代完整目标 |

## 保持独立场景与证据来源

另建 `remote_handoff_negative`，不扩大既有33步/4命令/8外审的正向合同。新journal按case/actor/source/command精确允许预期403/409，不能全局放行错误或吞transport/CSP/console/asset异常。继续固定正常API/DoT/HTTPS、私有无默认路由wire、同Git构建/进程/审计与独立fresh验证。

先经真实UI创建A/B（各revision1），Approver依次批准A旧=good-a/P1、A新=good-b/P1、B=good-a/P1。预期setup为5命令、3批准、local audit2、external audit10；没有候选或wire。

| case及请求来源 | 事前预期 | 必须独立核的副作用 |
| --- | --- | --- |
| UI交接未知但格式合法command ID | 409 `subscription_approval_required` | 新失败命令1、prepared/result外审2；资源库存、local audit、wire不变 |
| UI来源A交接B的批准 | 同上 | 同上，来源与批准不可串联 |
| UI交接A新批准、填policyRevision2 | 同上 | 同上，不把下拉选择当批准依据 |
| UI交接已被A新批准取代的A旧批准 | 同上 | 同上，不称基于时间TTL过期 |
| UI Operator读取Approver A新command回执 | 403 `subscription_forbidden`，无result/command ID头 | 无新命令、local/external audit或wire；不能假设所有403均有denied审计 |
| API-only Operator直接POST批准 | 403 `subscription_forbidden`，无result/command ID头；健康审计时denial header为recorded | 无新命令/local audit/wire，外部denied事件1；UI仅验按钮禁用和无POST，不冒称UI自然发出此请求 |
| UI Operator A新/P1/expected1合法fetch | 200 committed，A升revision2 | 新命令1、local audit1、外审2；1quarantined候选/base2，2节点unknown；3连接/12wire事件，不自动接纳 |
| API-only A新/P1/expected1再次fetch（此时实际A2） | 409 `subscription_command_conflict` | 新失败命令1、外审2；资源库存/local audit/wire不变；UI没有任意expectedRevision编辑入口，不注入React冒称UI测试 |

进入Execute的五类失败POST应返回安全 `X-Chengwang-Command-ID`，而非成功result。每次用本人读该失败回执：GET200、state failed、对应public code、auditRecorded=true、stateMayHaveChanged=false、两外审hash有、无localAuditHash；revision为提交expectedRevision（上述为1），不能当成当前库存revision。GET不能增加业务命令、审计或wire。每次失败后按页面真实stale/刷新合同恢复，不能直接覆盖状态。

按表中顺序事前预期终态：A2/B1、3批准、1quarantined候选/2unknown、11命令、local audit3、external audit23（22 command事件＋1 denied）、3连接/12wire。必须逐case冻结实际API/DOM、失败回执、审计和wire前缀，不能只对总数。本段保留事前合同；本轮实际验证及边界另见上方，不用事前预期冒充结果。

## 不虚构过期或竞态

当前fetchApproval不比较批准时source revision与当前revision，也没有批准时间TTL。跨revision复用应另设实际正向对照，不能据代码无比较就写成已通过；原旧lab同revision noop不是这个证明。时间TTL仍是未实现/未验事项。

真正策略材料/revision变更需正常TERM/wait0后，同库新server加载新受信fixture；不能修改磁盘文件就假设热加载。post-network CAS现有Go测试使用policy seam调用Store.Import，不能冒称浏览器或真实API已经覆盖；真实双会话竞态须另立安全构造。当前同Service对同source的claim串行性必须纳入设计。

## 已检查的源码依据

- `internal/api/subscriptions.go`：86行两种409映射，342–373行失败POST的错误envelope/安全command ID头，386–404行失败命令的只读回执。
- `internal/subscriptionctl/service.go`：367–404行接纳命令与prepared/result，501–531行批准/策略/CAS校验，691–725行owner回执规则，729–768行独立denied审计。
- `internal/subscription/control.go`：409–427行当前批准选择，448–488行批准不递增来源版本。
- `web/src/Subscriptions.tsx`：交接字段、只读回执、当前版本准备及角色禁用行为。后续实施前须按新精确Git重新核行号/合同，不以本卡替代真实接口验收。

仍须补齐B01–B23其余授权、分页、恢复、故障、长稳、完整旧回归，以及正式备份/灰度/生产读回与回滚。不能把此卡缩成整个系统的完成条件。
