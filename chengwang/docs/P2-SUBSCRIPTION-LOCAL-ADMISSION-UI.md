# P2-06b：真实双来源本地准入 UI 增量

状态：`c15eda3` 的正常业务路径已经实际隔离验收，但发现历史候选决定按钮资格缺口，不能称完整交互通过，更不是上线。原 [CI 40002939736](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40002939736) 的四 producer/四 fresh 全部 success；根与独立子代理完整原 CLI 重放及四方报告逐字一致，见[机器证据](evidence/p2-subscription-local-admission-c15eda3.json)。完整范围继续由 [B01–B23 合同](P2-SUBSCRIPTION-BROWSER-ACCEPTANCE-PLAN.md)约束。

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

## 实际验收与交互缺口

每引擎实际 100 请求、37 DOM、10 写入、20 外审事件；两来源/四候选、A r8/B r2、回退节点 ID 与最初接纳相同。旧创建/回执场景仍为 14 请求/11 DOM/唯一创建。正常 TLS、三进程 wait=0、八错误计数全 0，858 Git blobs 精确核验；旧84/新76辅助测试原始输出分别复验，不换算为真实业务覆盖率。四张新准入 PNG 已实际查看，仅首屏 1440×900/375×900，不声称下折叠控件全部视觉验收。

父门原日志经根与子代理按原 Git checker 复验：ordinary/race 各2644、Fuzz各12、零跳过。旧订阅两 Linux 原 CLI 成功；Windows完整原 CLI 仍严格拒绝 `public-file-open-race`，根/子代理仅对原字节执行 `read_inputs` 适配后的语义复核（20文件/46 captures/4 epochs/26连接/102事件），不是完整 POSIX 保管验收。

实际缺口：两引擎的 `nodes_restored/final_desktop/final_mobile` 共6条原 DOM，历史 A1 已 `admitted_local`、BaseRevision=2、来源 r8，接纳/拒绝按钮仍为 true。服务端仍拒绝不合法决定，不能替代前端精准提示。新资格 checker 已对这6条原值实际拒绝，原工件未改。

修复候选：前端直接派生角色、quarantined、当前版本资格并给中文原因，不增加 effect/请求；原接纳/拒绝正例改用合法待审候选，新增3个禁用反例。CI门保留原190项全部名称与摘要，单独增加3项为193，不以新总数替换旧基线。回退规则、37步/10写入和旧创建合同不变。当前仅已实现、纯CPU检查通过，**新源码浏览器与真实 Vitest 仍待运行**，不得回填 `c15eda3` 的交互缺口。
