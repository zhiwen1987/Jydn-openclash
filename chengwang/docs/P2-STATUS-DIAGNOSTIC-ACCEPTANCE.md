# P2-06 请求取消诊断：实际验收记录

更新：2026-10-23。实际运行源码 `ad3e4db2b2c7585843344110b5d3258671613512`。**整体未验收通过，未上线。** 五条隔离CI均已终态；没有取消/重启工作流来覆盖失败。原始run/job/artifact、字节与SHA见[机器记录](evidence/p2-status-diagnostic-ad3e4db.json)。

## 实际完成与证据

实现了[闭集诊断合同](P2-PROBE-STATUS-DIAGNOSTIC-CONTRACT.md)：真实匿名status signal的生命周期/流读取观测、两个浏览器adapter的独立时钟网络观测、Python严格再投影及独立来源门。没有修改产品abort策略、timeout、缓存或流式预算。另实现新订阅页的共享安全DOM collector，修正stale层级误投影及失真的签出/hidden合成fixture；它仍不是实际订阅E2E。

| 原始CI | 实际结果 | 独立复核范围 |
| --- | --- | --- |
| [父门39973741998](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39973741998) | 普通/race各2644 Test，每对一次、0 Test skip/fail；Fuzz函数+seed每轮12另计，无测试domain包skip另列 | 两轮原事件与旧名单保持；五个精确Git helper原CLI，代理及根会话均重放通过 |
| [镜像39973742012](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39973742012) | CI success；9文件190全通过、0 skip/todo，旧117和40/32/App1保持；lint/build及子模块各732/Registry各3通过 | 根会话核对原ZIP五份JSON、精确Git shell/heredoc/checker，再重放三门。97模块/778checkout源码记录保持；旧7产品CLI仅CI成功/来源绑定，未逐个独立重放 |
| [订阅39973741865](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39973741865) | producer和fresh Linux原门均success；80辅助、46API、4epochs、26连接/102事件，源码778原blob保持 | 根会话及代理重放原ZIP20文件语义，2496B报告与两Linux原报告逐字相等；Windows完整POSIX输入custody仍拒绝，未伪称通过 |
| [原生探针39973741831](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39973741831) | success；6样本、自然过期清零、3目标unknown；4次正常退出，无forced；原44辅助+24wire prerequisites逐项通过 | 代理及根会话均用精确Git原backend22完整CLI重放，3585B报告与CI逐字相同。仅NATIVE_BACKEND_ONLY |
| [旧探针浏览器39973741878](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39973741878) | CDP成功；PW原browser门因failedRequests=1失败，其他7计数0 | 两backend22、两新诊断门及CDP browser门均重放并与原报告逐字相同；PW browser门原样拒绝，无伪造通过报告 |

两浏览器都实际跑了新增独立80项，报告的数量/冻结名字指纹已核对，不能混入190或2644。**该辅助runner未归档新Node各组原stdout，只保存其SHA及已检查报告，故不能称原stdout逐字独立重放；下一增量补齐保管。** 原始ZIP/日志留于平台与本机UUID Temp；平台保留期和临时目录不是永久WORM归档。

根会话一次额外以`python -I`调用旧browser checker时，Python按设计不提供脚本目录的隐式兄弟模块导入，调用在import阶段失败；随后按原CI的`python -B <script>`入口重放才得到上述结果。未改变检查器或CI。镜像辅助缓存曾因heredoc末尾LF口径不同中止；核对Git原shell，按真实6727B原文重放，未改变名单或门。

## 新诊断真正查明了什么

每个engine实际81条：57条JS、7次NET_START，META拒绝0/overflow=false；均只观察到1次MOUNT、0 ABORT、0 CLEANUP，所有观察的signal.aborted=false。这里的complete仅为诊断sink和闭集完整，不表示业务通过或JS/CDP唯一因果。

PW的关键到达序列如下；q仅为收集到达顺序：

| q | 实际观察 |
| --- | --- |
| 37–38 | JS request r4，POLL；ARM的mount相对时间30003ms |
| 39–42 | 网络s4：开始、200头、canceled/aborted；CDP单调时刻分别288542502/288544349/288544768us |
| 43–44 | JS r4：EOF，455字节；READ_END=EOF_OK、f=true |
| 45–47 | JS r4：EOF后同步CANCEL尝试前后、FINALLY；最后相对时间30006ms |

本轮没有应用deadline或cleanup触发abort的观察证据，不能继续把它们当作已确定原因。JS r4与网络s4仍是同序相邻观察，未添加改变请求的关联头/URL，也未取得唯一绑定；没有跨时钟相减。NET_FAIL早于EOF/CANCEL的**到达顺序**不能证明底层取消原因，也不支持宣称“EOF后的cancel已被证实导致该取消”。不据缺少某条观测作绝对排除。

## GitHub查证：相关上游修复，不冒充本项目根因

按用户要求搜索并阅读了[Playwright #42742](https://github.com/microsoft/playwright/issues/42742)。它记录了no-store流读取到EOF但浏览器报告取消的相似问题；维护者指向上游修复。官方Gerrit REST确认[CL8508456](https://chromium-review.googlesource.com/c/chromium/src/+/8508456)于2026-10-06合并为[`62473ad0f747e245e514c93e741bb8e168a2a207`](https://chromium.googlesource.com/chromium/src/+/62473ad0f747e245e514c93e741bb8e168a2a207)，包括终态重入处理及完成/错误与DevTools测试。这里不复制上游代码或增加依赖。

源码核对的边界必须区分：官方[`155.0.8059.39`源码tag](https://chromium.googlesource.com/chromium/src/+/refs/tags/155.0.8059.39/third_party/blink/renderer/platform/loader/fetch/response_body_loader.cc)缺少该提前终态处理；[`157.0.8091.0`源码tag](https://chromium.googlesource.com/chromium/src/+/refs/tags/157.0.8091.0/third_party/blink/renderer/platform/loader/fetch/response_body_loader.cc)包含它。**这不证明某tag已发行可下载二进制，不证明首个修复发行版，更不证明本轮实际binary的补丁祖先。**

本轮固定的是Playwright `1.64.1`；workflow实际复制宿主`/opt/google/chrome`，**浏览器版本没有pin**。两engine观测product为`Chrome/155.0.8059.39`，实际ELF297798984B、SHA`9bfb381296dffe75f3419d07b6cc64525105ed117d1453a4ef3b291cb97d2b58`。`Browser.getVersion`虽然被调用，但现有工件只存product，未保存revision/protocolVersion，不能事后回填。[协议确实提供这些字段](https://raw.githubusercontent.com/ChromeDevTools/devtools-protocol/master/pdl/domains/Browser.pdl)。

因此，上游缺陷和源码补丁已经查实，但本项目根因与修复结果仍未证明。只升级Playwright不会替换当前external executablePath的Chrome；外部浏览器组合还要独立兼容验收。[Playwright官方边界](https://playwright.dev/docs/api/class-browsertype#browser-type-launch-option-executable-path)

## 下一步和仍未完成

1. 补独立闭集browser identity sidecar，保存revision/protocolVersion及现有ELF/fixture/engine绑定；补80项原stdout保管，不改旧报告schema。
2. 查实官方可取得、可固定、含修复的二进制及工具链组合。先运行独立no-store分块正例、超限/HTTP截断/显式abort负例，再跑完整原门。不会以no-cache、无界json、clone预读或忽略失败取代原约束；尚未取得可溯源版本时不宣称升级修复。
3. 仍须实现并执行[新订阅页双浏览器计划](P2-SUBSCRIPTION-BROWSER-ACCEPTANCE-PLAN.md)。目前只有DOM collector合成模型，没有新页真实server/harness、正常TLS操作、独立网络/审计门或截图。视觉P0、移动端、键盘与完整无障碍均未验，不能填0。
4. 自动调度、完整内核/数据面、备份恢复、授权发布、生产灰度、读回和长期观察继续在[总台账](PROJECT-PROGRESS-LEDGER.md)中保留，不因本轮局部回归成功被改成已完成。
