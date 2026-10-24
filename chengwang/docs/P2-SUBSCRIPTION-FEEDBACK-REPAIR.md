# P2：订阅操作反馈修复与补充验收

更新：2026-10-24。状态：e4156d6 的订阅反馈切片已完成 D 副本原件复算及独立复核；父门、旧订阅及镜像亦有分层验收。旧探针双引擎门仍失败，整体回归未通过。仅开发分支，不授权生产变更。

## 最终有限收口：不等于完整系统或整轮回归通过

根新D副本16 ZIP／446成员、源码exact-LF副本及全部48份执行记录已齐全：48次原CLI均实际exit0，报告与producer逐字一致，其中32份有真实fresh亦逐字一致；旧84／76共16份仅比较producer，不虚构fresh。10份先前实测exit0按固定摘要保留，38份新独占执行；中断的旧分析日志不覆盖，每条最终执行结果均独立落盘并fsync。输入原件与报告／日志在末次复核时摘要稳定。`root-originals.json` SHA256 `ea44f0444f63d00f05b17c066d1a1cadb66431332730199f6e7e37be69c257a4`。

独立代理另行重放CDP反馈完整原CLI，实际exit0、50.531秒，报告与producer／fresh／根逐字相同，SHA256 `58797f9c2900225eb33c940691fdbb1f64796e28e848b7332845af625c98ba80`；同时复核48 journal的exit/source/report/log摘要和16 ZIP的CRC／保存API／成员字节。独立最终事实77544字节，SHA256 `d2f09b7eebbfabce960f3406f2d588a65b47a5f3f2628b22eb31f0b59a0b2996`，已归档[机器证据](evidence/p2-subscription-feedback-e4156d6.json)。

镜像新原件1470个安全成员完成前后SHA复核；前端实际222/222、旧197＋新25精确名单、零skip，CI内tsc／ESLint／Vite通过，子模块ordinary/race各732、Registry各3。前端门／Go事件门与六个产品Registry／生命周期／崩溃／状态／来源／TLS原门实际重放通过，六报告与CI逐字一致。此为隔离候选镜像，不是正式Registry发行或生产镜像上线。主审计10083字节，SHA256 `2ededc222475c404f364f5dc7c667c3a3bc9428b02a66a9150e21eac351aa3a7`。

16张真实原PNG已由独立代理逐张审看；根此前实际审看新负例两引擎的桌面／手机首屏。明确409后的桌面不再残留WAITING，手机截图是后续历史回执阶段，不能冒充同一409或完整移动流程。49反馈阶段是来源绑定的可信CI枚举观测，不是原文独立公证；真实unknown／timeout、键盘／读屏、完整B01–B23及生产均未完成。

API后续刷新遇403限流，已停止重复请求，不换凭据或接口绕过；最终保管复核采用先前保存且摘要一致的原API元数据，**不是新的实时GitHub刷新**。C副本字节变化、OOM和本机包装错误均保留，不推断硬件原因。下一探针[EOF清理候选](P2-PROBE-EOF-CLEANUP.md)另算尚待真实CI的增量，不能借本e415切片收口声称新清理已验。

## 当前源码的实际结果与验收中断记录

源码 `e4156d64341f5f92eeca9bfa7c8b09066cf69c64`，均原 attempt1：

- [订阅 UI 40042582508](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40042582508)：八 producer＋八 fresh success。两个反馈报告各 49 阶段，仍只覆盖明确拒绝／历史回执，不证明真实 unknown／timeout。
- [镜像 40042582526](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40042582526)：终态 success；实际前端名单／JSON、Go 子模块、Registry 和候选镜像证据正在独立复核，不把终态当全部逐项通过。
- [父门 40042582510](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40042582510)及[旧订阅 40042582543](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40042582543)：success。已分层复核父 ordinary/race 各 2644 Test（各 10811 事件，另有各 4 Fuzz 顶层＋8 seed，非持续 fuzz）、旧订阅 80 项／20 输入／926 Git 与两 Linux 报告字节一致。Windows 原 POSIX reader 仍拒绝，不冒称本机完整旧 CLI 通过。
- [旧探针 40042582518](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40042582518)：failure，两引擎真实运行步骤 success、原独立门 exit1。新 D 副本原 CLI 与只读 trace 均定位原 `validate_driver` 的八计数须全零条件；两个原 driver 均 `failedRequests=1`、其余七计数零。具体哪个请求及原因仍在查，不能借订阅成功抵消此失败，也不放宽原门。

**本机证据副本异常，不归因产品或系统硬件：** 原 C:/Temp 解包后的 JSON/log/PNG 在初次摘要校验之后出现字节变化，个别不再是 JSON；根及独立子代理均复现。原 ZIP 仍与 GitHub API digest／长度及 ZIP CRC／原成员摘要相同。原异常文件不覆盖，历史“验后稳定”只代表当时采样，不能当作当前稳定保管结论。根旧 fbdd 本地重放最终稳定性断言失败，不记全通过；代理 C 的一次本地离线 Python preinitialization Out of memory 亦保留为本机分析失败，不记 CI 失败。原因尚未证实，没有运行磁盘修复、系统设置修改或生产操作。

当前从仍 API 摘要一致的原 ZIP，在独立 D 盘目录以 O_EXCL／flush／fsync／写后逐 byte／全成员前后摘要重建。根 `D:/CodexData/workspace/cfr-_b6cmgfu/`：16 ZIP／446 成员已重建校验，原 48 CLI 复算进行中。父／旧订阅已锚原件另保管于 `D:/CodexData/workspace/cw-e4156d6-original-a-c89dc74ba5f14166904035773934e477/e415-parent-oldsub/`，42 份文件及前后字节已核，D manifest SHA256 `4361e808a10366422b9c62159f3b059f2049c24ce5d272ef2ce272acfadfb90a`。D 副本本次采样稳定也不等于未来耐久或本机根因已修。

目标续轮后旧本地分析句柄已不存在，且 Win32_Process 未见对应进程；未据“等待超时”重复启动。根保留已在上一工具输出观察到 exit0 且 SHA 固定的十份 D 报告，只补缺少的 38 份；旧中断日志保留，不是重跑或取消 CI。全局最多两条重型 Git 原件复算，其余子代理先核保管、截图和原始诊断，避免盲目增加并发。

另已按实际 lock 的 Testing Library 10.4.2 核官方 [单对象查询实现](https://github.com/testing-library/dom-testing-library/blob/6049cc0bc7cf2201625c476c95fa6299d0e2fa8b/src/query-helpers.ts)及[文本查询实现](https://github.com/testing-library/dom-testing-library/blob/6049cc0bc7cf2201625c476c95fa6299d0e2fa8b/src/queries/text.ts)，确认多匹配拒绝及默认精确字符串语义。GitHub tag 实际解析到提交 `6049cc0bc7cf2201625c476c95fa6299d0e2fa8b`；本次只参考定位行为，没有引入新依赖或复制上游实现。

## 首轮真实 CI 失败记录，不回填成功

源码 `fbddae37ffe1e6f9cf86b8b1afe975f7abe081b6` 的[原 UI 40042077078](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40042077078) attempt1：八 producer＋八 fresh 均 success，原件离线重放与视觉复核正在进行，不能提前写成全部验收完成。

同源码[镜像门 40042077114](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40042077114)／job120715244206 为 failure。原前端 JSON 实际执行 222 项，217 passed／5 failed／0 pending／0 todo，10 文件中 2 失败。一个旧测试因本补丁把同句“服务端结果或审计待确认”同时置于 status 与 alert 而多匹配，四个新测试因宽泛 `/存在未决命令/` 同时命中禁用原因和未决说明而多匹配。不是类型检查通过就等于测试通过，也不把失败归咎环境或重跑取绿。

A 独立原件目录 `C:/Users/Administrator/AppData/Local/Temp/cw-fbddae3-original-a-c861295e321941b0bc4d2e84a8e33742/`；原工件12538674932为406451字节，SHA256 `50c0216ca24909222d0716840c3003bd4fe4e6f8acf73616c29c3b4443191e89`，49成员已按 CRC/字节摘要核对。原 `frontend-vitest.json` 149445字节，SHA256 `e86218f4e1718027272c2ad0bd5de5baade01e27ea808b105c3536a6a4797a59`。

最小修正保留旧 197 名单与源码、新 25 名单及所有锁断言：pending receipt 的 status 改用已有待核对提示，alert 保留旧具体审计提示；新四处断言定位完整未决说明而非模糊子串。没有删除测试、降低通过数、跳过用例或改写旧失败原件。修正后的实际 222 项结果仍待新提交的原 attempt1。

修正后根再次实际运行 558 项纯 CPU 全通过、零 skip；原件 `C:/Users/Administrator/AppData/Local/Temp/cw-feedback-root-cpu-k7af13ok/`，`root-cpu.json` SHA256 `a886d8c27866328f4a8c8fc7d2167cd29b1588d0deb309c4b1d47c9fc34c76db`。25 个前端测试名称摘要仍相同，此检查仍不是 Vitest 重跑。本机未运行安装、编译、服务或浏览器。

## 已证实的问题与修复范围

前序源码 `cc86661adb969ecd4c958ca16769e8b90bd1afbc` 的[原 CI](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40039043139)业务负例通过，但两引擎原 `unknown_failed` 桌面截图仍在明确拒绝后显示“正在等待服务端结果；尚未确认成功。”。原业务 DOM 合同未采集 notice，不能以原绿灯否认该 UX 缺口。历史原件和[原验收记录](P2-SUBSCRIPTION-HANDOFF-NEGATIVE-PLAN.md)不修改、不回填。

本次实际修改产品 `web/src/Subscriptions.tsx`，不是仅增加测试：

- 已知拒绝结束等待提示；认证失效清除会话及旧提示。
- 未知结果、审计待确认、写入超时改为“待核对”，有命令 ID 提示读取回执；无 ID 提示管理员对账。
- 读取历史回执不把仍在途的写入显示为结束；不因读取无关回执释放另一个未决写入。
- 回执读取失败或超时保留未决提示，无未决写入时清除过期成功提示。

未修改 API、回执 owner 校验、写锁、意图归属、重试或会话存储语义；没有增加自动重提、轮询或 React effect。

## 首次提交前的分层证据与退出条件（历史状态）

| 层级 | 当前事实 | 不能据此声称 |
| --- | --- | --- |
| 产品修复与新增 25 项前端测试 | 已写入；现有 TypeScript parser 的 AST 解析无诊断，25 个测试声明名单已核 | 不等于类型检查、Vitest 或浏览器通过 |
| 旧 498＋新 60 项辅助检查 | 根实际纯 CPU 运行 558 项、零跳过；六个转录检查门通过 | 不等于新增 25 项前端测试运行，不等于真实产品验收 |
| 双引擎 49 阶段反馈补层 | 合同、同次 DOM 采样、两层安全投影、独立检查器及 fresh 接线已实现 | 未运行前不能称 49 阶段实际反馈通过 |
| 全系统与生产 | 本阶段未部署、未改生产、未合并 main | 不等于 B01–B23、企业系统、长期稳定或上线 |

根纯 CPU 原件：`C:/Users/Administrator/AppData/Local/Temp/cw-feedback-root-cpu-hx4ovguy/`。`root-cpu.json` SHA256 `97977212cda32675da0624f3ca8be2d58e6a0bb067ba94d5e86f72047b5327c1`。新增 60 项为 Python 投影 16、独立反馈检查器 20、Node 反馈合同 24；三份实际转录复制后重复事件均被拒绝。16 个 CI shell 块、前端门 shell、7 处 Python AST、4 个 JS 语法检查通过。旧九个前端测试文件与父提交的 LF 字节一致；前端 CI 门保留旧 197 名单，另核新 25，总预期 222，而不是用数量替代名单。

交叉复核实际发现并修正一个集成错误：原公共 DOM 导出器 `exclusive` 默认且显式 fchmod 为 0644，新投影读取却要求 0600，会确定性拒绝。现两处公共 DOM 读取保持 root/0644，与原导出一致；私有日志仍 root/0600，不放宽。原 test16 增加跨模块默认值／fchmod／两处调用对照，不改测试名单。修正后完整 558 项再次实际通过，原件 `C:/Users/Administrator/AppData/Local/Temp/cw-feedback-root-cpu-zsgf_4r2/`，`root-cpu.json` SHA256 `eb1cb0cc721f47bf9fc21559fca6ae2703c3573b5fedc30a356470395400c19b`。这证明检查与修正已做，不把尚未发生的 CI 故障写成已实测运行。

本机没有依赖安装、Go 编译/测试、npm/Vitest/构建、服务器、浏览器、Docker 或网络命名空间运行。实际构建、类型检查、222 项前端测试及双引擎产品运行只走已有隔离 Linux CI；不重跑或取消失败运行以取得绿灯。

## 真实反馈补层的信任边界

唯一新合同 `tools/subscription-ui-browser/handoff-feedback-contract.json` 固定原负例的 49 阶段。原 PUBLIC14/21/22、旧 DOM/driver/capture schema、旧测试名单和八 producer／八 fresh 矩阵不变。

在原 DOM 读取的同一个同步浏览器任务中，额外读取订阅面板的 status/alert，映射成闭集枚举及真实可见性；不导出原文。每条观测绑定原 DOM 行（包括 LF）的 SHA256。私有驱动日志仅在原场景成功收尾后提取闭集 49 行，再经外层成功门二次投影到公开 supervisor 日志；失败不发布该成功反馈投影。日志按 root owner/0600 及稳定读取要求验证。

独立反馈检查器不导入生产者投影算法，先完整重放原业务检查器并逐字匹配原 `independent.json`，再核对 49 行反馈、原 DOM 行摘要、真实 Git blob、运行副本和读取前后稳定性。报告位于证据目录之外，成功后才复制到工件；fresh 从原件独立复算并逐字比较。

这是来源绑定的可信 CI 同任务 DOM 枚举证据，不是独立浏览器执行公证、原始文字独立验真或 per-HTTP 包级因果。新增真实运行只计划覆盖四次明确交接 409、一次跨 owner 403 及五次本人失败回执的既有阶段；没有真实未知结果或超时注入，不能把 25 项 mock 测试当作这些场景的浏览器证明。截图仍需实际审看，首屏检查不等于完整移动端或无障碍闭环。

## 下一步

继续实施并隔离验收[EOF清理增量](P2-PROBE-EOF-CLEANUP.md)，不放宽旧零错误门；随后推进完整订阅和整套系统功能。任何失败保留原件，先查源码和实际错误；方案不明确时查官方 GitHub 源码、文档、Issue 和测试，不猜测修复。由唯一集成者更新台账；不以部分成功宣告整套系统验收完成、正式发布或上线。下方早期“进行中／待执行”等描述均是对应时点历史，由本节最终证据更新，不回填旧失败。
