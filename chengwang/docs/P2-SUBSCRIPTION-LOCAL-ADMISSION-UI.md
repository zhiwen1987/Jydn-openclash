# P2-06b：真实双来源本地准入 UI 增量

状态：`8c4852c` 的历史候选决定按钮修复与本地正常流程已实际隔离验收，**旧探针回归失败，本轮整体未通过**，不是上线。新 [UI CI 40005313485](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40005313485) 四 producer/四 fresh 成功；根与独立子代理完整原 CLI 重放及四方报告逐字一致，见[本次机器证据](evidence/p2-subscription-decision-eligibility-8c4852c.json)。前一版 [c15eda3 原证据](evidence/p2-subscription-local-admission-c15eda3.json)保留正常路径及交互缺口，不能回填。完整范围继续由 [B01–B23 合同](P2-SUBSCRIPTION-BROWSER-ACCEPTANCE-PLAN.md)约束。

## 固定场景

[机器合同](../deploy/subscription-ui-browser/admission-contract.json)固定 `local_admission` 场景、37 个 DOM 步骤、10 次写入及独立 schema。正常 API origin、NSS/TLS、三进程隔离和退出机制复用现有受限实验；每次运行仍使用新的独立 UUID、身份、私有文件、profile 和数据库。旧 `create_receipt` 默认合同及计数不被扩大，新 CI 同时复验旧场景。

| 顺序 | 真实业务动作 | `c15eda3` 两引擎实际观察结果 |
| --- | --- | --- |
| 1–2 | Operator 创建 A、B 两来源 | A r1、B r1 |
| 3–4 | A、B 经真实 file input 导入同一份私有文件 | 各 r2、各一个 quarantined 候选；安全节点 ID 集合不相交 |
| 5 | 独立 Approver 接纳 A1 | A r3，accepted=A1 |
| 6–7 | Operator 导入不同 A2，Approver 接纳 | A r4→r5，accepted=A2 |
| 8–9 | Operator 导入不同 A3，Approver 拒绝 | A r6→r7，accepted 仍 A2，latest=A3/rejected |
| 10 | Approver 显式勾选并回退历史 A1 | 以当前 r7 CAS 提交，A r8，accepted=A1；不是以 A1.BaseRevision=r2 提交 |

在这些动作之间切换 Viewer、Auditor、Operator、Approver，实际读取资源权限与安全节点、检查禁止的写按钮，并证明清会话与切来源不会串页。准备/取消不得增加 mutation；回执查询必须 GET，不重发 POST。候选按实际 ID 选择，不以列表顺序推测创建先后。最终桌面/移动截图及原 DOM、审计、私库安全投影互相绑定。

## 独立验收要求

- 两引擎均操作真正编译的产品页面和真实 `cmd/server`，正常 TLS，无 fetch/React 注入、mock API、fault hook 或证书绕过。
- 文件经真实 CDP `DOM.setFileInputFiles` / PW `locator.setInputFiles` 输入；驱动私下比对实际 POST 解码字节与本 fixture 文件。公开只保字节数量及安全请求字段，不公开文件原文、contentBase64、原文件 SHA 字典 oracle 或私有名称。
- 四角色令牌和每个私有名称/用户名/密码/文件 basename 的原值及编码/摘要变体在导出前扫描。响应 base64 必须先解码独立扫描；截图前确认私有输入清空并检查可见文字。
- 独立检查器从实际 POST 的 CAS、目标与回执重建状态机，与各 GET 资源版本、DOM、20 个外审事件及最终两来源/四候选/10 命令安全投影核对，不相信单个自报 pass。
- Viewer/Auditor 的 `writesEnabled=true` 不代表有写权限；动作按实际 metadata 核验。来源 `approve` 是远程来源批准，不是本地 `decide`，本场景 approvals 应为 0。
- 拒绝保持旧 accepted，回退真正改变 accepted A2→A1；两来源和四候选的节点始终 `unknown`，不能把本地接纳称为节点健康或设备发布。
- 保留全部首次失败和安全诊断。新 Linux fresh、根及独立子代理完整原 CLI 重放与 producer 报告逐字相等，实际查看 PNG 后，才记录相应子范围通过。

源码依据：`subscription/store.go` 的导入/决定/回退及 ID 排序、`subscriptionctl/service.go` 的审计与回执所有者规则、实际 `Subscriptions.tsx` 文件读取/确认/切源行为。外部接口参考为 [官方 CDP GitHub 定义](https://github.com/ChromeDevTools/devtools-protocol/blob/master/pdl/domains/DOM.pdl)和 [Playwright 官方 file input 文档](https://playwright.dev/docs/api/class-locator#locator-set-input-files)，不是拿相似 Issue 当本项目根因。

## 本阶段仍不能覆盖

来源策略批准/交接/DoT 抓取、真实后端未授权拒绝与跨 scope 矩阵、跨 20 条分页、并发版本变化、未决/降级写入、同库重启和系统级备份恢复、完整旧产品及镜像回归、灰度/生产/长期观察仍须后续实现和验收。正常流不补造失败流结论；当前全部实现与运行保持 `production=false`、`authorization=BLOCKED`。

## `c15eda3` 前序实际验收与交互缺口

每引擎实际 100 请求、37 DOM、10 写入、20 外审事件；两来源/四候选、A r8/B r2、回退节点 ID 与最初接纳相同。旧创建/回执场景仍为 14 请求/11 DOM/唯一创建。正常 TLS、三进程 wait=0、八错误计数全 0，858 Git blobs 精确核验；旧84/新76辅助测试原始输出分别复验，不换算为真实业务覆盖率。四张新准入 PNG 已实际查看，仅首屏 1440×900/375×900，不声称下折叠控件全部视觉验收。

父门原日志经根与子代理按原 Git checker 复验：ordinary/race 各2644、Fuzz各12、零跳过。旧订阅两 Linux 原 CLI 成功；Windows完整原 CLI 仍严格拒绝 `public-file-open-race`，根/子代理仅对原字节执行 `read_inputs` 适配后的语义复核（20文件/46 captures/4 epochs/26连接/102事件），不是完整 POSIX 保管验收。

实际缺口：两引擎的 `nodes_restored/final_desktop/final_mobile` 共6条原 DOM，历史 A1 已 `admitted_local`、BaseRevision=2、来源 r8，接纳/拒绝按钮仍为 true。服务端仍拒绝不合法决定，不能替代前端精准提示。新资格 checker 已对这6条原值实际拒绝，原工件未改。

修复实现：前端直接派生角色、quarantined、当前版本资格并给中文原因，不增加 effect/请求；原接纳/拒绝正例改用合法待审候选，新增3个禁用反例。CI门保留原190项全部名称与摘要，单独增加3项为193，不以新总数替换旧基线。回退规则、37步/10写入和旧创建合同不变。

## `8c4852c` 新原件验收

根与独立子代理从8个原小ZIP逐一核API digest及124项解压字节。四个完整原checker CLI全部真实退出0；每份核859 Git blobs，producer/fresh/根/子代理四方报告逐字一致。旧84/新76原辅助输出也分别完整重放，8份根/子代理报告逐字一致。

主代理原件目录为 `C:/Users/Administrator/AppData/Local/Temp/chengwang-admission-8c4852c-root-5c1a5fd475324afe823e22d8f3513ec1`，独立子代理位置与报告SHA详见机器证据。GitHub原工件保留14天；本机Temp不是永久集中归档，该运营缺口仍未关闭。

新准入仍为每引擎100请求/37DOM/10写入/20外审事件/A r8/B r2；正常TLS、三进程wait0、八错误计数0。实际原DOM中，两引擎最终历史A1的6条接纳/拒绝按钮均false；独立检查器另核8条当前quarantined、base=current的Approver记录，两按钮均true。四张新准入首屏PNG已实际查看；按钮的下折叠实际状态由DOM验证，不冒称四张首屏图能看到这些按钮。

同源码父门 [40005313520](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40005313520) 原日志经根/子代理原7 Git checker重放通过：各2644 Test与12 Fuzz另计，零测试跳过/失败。旧订阅 [40005313448](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40005313448) 两Linux原CLI成功；Windows仍仅是原字节读取适配后的语义复核，不改变完整POSIX CLI拒绝结论。

镜像门 [40005313397](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40005313397) 原job `120591615814` 已success；根/子代理独立核原6,409,567B公开报告ZIP的API摘要。实际前端JSON为71,770B，193/193通过、9文件、零失败/跳过/pending/todo；原日志摘要一致，根/子代理各用8c原Git gate完整重放通过。原190全部名字/摘要保留，Subscriptions为原32+新增3=35；实际新35摘要 `98752b4912285685197f89f7918138050769b3d06fa8a3b69d315c1d472a9ef3`。typecheck/lint/build在原CI完成；本机只验原件，不执行Vitest/构建/运行服务。镜像Registry与完整候选作业success，不等于逐个独立重放了全部旧产品子CLI，更不等于正式发布镜像。

### 整体回归未通过

原旧探针 [40005313533](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40005313533) CDP作业 `120591765720` 在独立浏览器checker步骤失败，PW作业 `120591766143` 成功。根/子代理核验原小ZIP，CDP实际Chrome155.0.8059.39、`failedRequests=1`、其余七类0，硬门原样拒绝；81条诊断中有一次 `PROBE_STATUS:CANCELED:ABORTED:RUNNING/HTTP_2XX:AGE_LT1S`，`abortRecords=0`、`causalRequestBindingProven=false`。

这不能证明用户代码主动取消、不能证明由本修复引起，也不能用JS的EOF观察消掉原网络失败计数。原失败和诊断保留，不重跑挑绿、不放宽旧门。下一步是单次请求关联的有界诊断与官方源码核实，根因仍未证明。完整旧产品回归、B01–B23、灰度和生产均未完成。

已查[官方CDP Network定义](https://github.com/ChromeDevTools/devtools-protocol/blob/master/pdl/domains/Network.pdl)、[Streams源码](https://github.com/whatwg/streams/blob/main/index.bs)与[Fetch源码](https://github.com/whatwg/fetch/blob/main/fetch.bs)。CDP网络终态与JS流读取是不同观测；Streams规范的闭流cancel直接完成，不能据EOF后的cancel调用推断此次网络取消。当前规范也不证明Chrome155的实现根因。

仓库实际诊断分别用AbortSignal→`{m,r}`及CDP requestId→`s`，尚无共同请求键；`CANCEL AFTER`只是调用返回，不是Promise已完成。下一诊断**仅为待设计/未实施建议**：隔离构建的匿名status请求使用唯一非秘密请求头，冻结白名单/容量后绑定JS请求与CDP session/requestId，再收集取消Promise结果及两层终态；缺失、重复、乱序仍须拒绝因果推断。不能加query参数（现API拒绝），不能先删finally、放宽错误门或用升级后的绿色反推旧根因。
