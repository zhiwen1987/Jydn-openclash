# P2-06：请求取消诊断增量合同

更新：2026-10-23。当前为开发候选，**不是取消问题已经修复或新订阅页真实浏览器通过**。生产、本地路由/服务/浏览器运行均不在本轮范围。

实际执行补充：源码`ad3e4db`五条隔离CI已终态，旧浏览器CDP成功/PW失败，整体未验收；诊断与根会话原门重放结果见[实际验收记录](P2-STATUS-DIAGNOSTIC-ACCEPTANCE.md)。以下合同和名单冻结于该CI之前，不根据新结果放宽。

## 已知问题与参考依据

`8f610a4` 的旧探针 Chrome/CDP 回归因为一次取消请求而失败，PW成功。两者实际 served 构建相同；旧记录没有足够生命周期观测，不能唯一定位到10秒deadline、cleanup、读取/解码拒绝或浏览器自身。保留[失败记录](P2-SUBSCRIPTION-UI-ACCEPTANCE.md)，不以一次重跑成功替代根因证明。

用户要求代码方案不明确时先查GitHub。本轮查看了以下上游材料；它们是参考，不是本项目根因：

- [React #25962](https://github.com/facebook/react/issues/25962)：讨论请求级controller与effect清理的所有权。该历史案例不能证明本项目生产构建执行了开发期额外effect；当前不移除StrictMode。
- [WHATWG Streams #1255](https://github.com/whatwg/streams/issues/1255)和[#1287](https://github.com/whatwg/streams/issues/1287)：区分流、reader和abort操作，不能由方法名称推出浏览器网络事件的唯一调用原因。
- [Angular FetchBackend源码](https://github.com/angular/angular/blob/main/packages/common/http/src/fetch.ts)：可参考完成状态、销毁和超限取消的显式区分。但其框架和流处理不同，本轮未复制其实现、增加依赖或据此删除现有cancel。

上述链接按本次查阅记录，main链接不是固定版本依赖。后续若实际采用源码或特定补丁，必须补具体commit、许可证、适用版本与本项目反例。

## 产品观测（不改变控制策略）

仅匿名status signal经WeakMap绑定mount/request整数编号，未绑定的明细signal不输出。使用固定单参`console.info`前缀`CW_PROBE_STATUS:`，最多128行、每行256 ASCII字节，无持久化。仅允许闭集枚举、整数和布尔，不接受异常文本、URL、令牌或响应正文。

事件为MOUNT、BEGIN（INITIAL/MANUAL/POLL）、ARM、HEADERS、EOF、ABORT（DEADLINE/CLEANUP，BEFORE/AFTER）、CLEANUP、READ_END、CANCEL和FINALLY。READ_END区分fetch、headers、read、UTF8、size、JSON失败与EOF_OK。EOF在实际reader.done被观测时记录；EOF_OK只表示流/UTF8/JSON成功，不表示DTO形状通过。

原10秒deadline、30秒poll、单飞、所有权围栏、abort调用和reader.cancel/releaseLock保留，不增加重试、controller、listener或React状态。新增观测遵循React transient值原则，不为诊断触发额外渲染。

计时边界：t是同mount的`performance.now()`相对整数毫秒，BEGIN至ARM包围原setTimeout调用，ARM不是纳秒精确的arm时刻。CANCEL前后仅表示同步调用尝试，不表示取消promise完成。观测与console有未测同步开销，可能扰动竞态；缺少事件、达到预算或本轮不再失败均不能证明历史问题解决。

## 浏览器与公开边界

两个真实adapter继续使用原门。诊断旁路只采集同源、无Authorization/Cookie/代理鉴权、GET status及固定文档/已知frame。输出`CW_PROBE_DIAG:`严格JSON，最多511事件加1个META、每行512字节。request/frame/loader仅匿名编号，不输出原始ID。

JS的t（mount相对ms）、console的u（epoch us）、CDP的x（monotonic us）和w（epoch us）分别保留，**不可直接跨时钟相减或按完成序号宣称请求因果**。Meta的over/rej或缺失收尾使完整性不成立；sinkClosed不等于浏览器正常退出或原门通过。

Python从最多327680B的私有日志再次做重复键、闭集字段、canonical JSON、类型/枚举/行数/字节及连续q校验，只输出`lab/status-diagnostic.json`。无效行计数但绝不回显，原始私有日志不公开。新文件不进入旧backend22或browser capture闭集。

新增独立checker重新解码记录，要求实际frontend/network观测，以及新两个copied helper与源码前后记录/精确Git blob绑定。报告位于实验树之外，只能给出OBSERVATIONS_COMPLETE/INCOMPLETE；browserAcceptanceProven和causalRequestBindingProven始终false。它不覆盖原browser门的失败。

## 首次CI前冻结的独立辅助门

以下80项只为合成合同，不并入原32 JS、原13/35/12/32 Python、前端190或Go2644名单。排序、LF分隔、无尾LF的名称SHA：

| 合同 | 数量 | 名称SHA256 |
| --- | --- | --- |
| 浏览器诊断解析/采集 | 12 | `525077090b05dae125d8f3cdc21ba8f8c998b27d88ad50c78ea2c1ed65c2f693` |
| 新订阅页DOM采集 | 36 | `ad5fe9a1b5cc63e0cf38e50d537d815369313041347cb721eca5327cc3b61f82` |
| 前端观测模块 | 12 | `f631cf66f1842329b466bf0139c930409b9fb2d2d4ab9fe2a589050b0dfe1b03` |
| Python严格投影/接线 | 12 | `ce6bbc4cf5dff4e6f047a465bbe94282b11e787c30b9e62d8dc2a81e6b939f11` |
| 独立诊断工件checker | 8 | `da6a8fb45b108e2fbf605d3ac469ed40f69515ecafae376fe44a1b87b3db0622` |

本机纯辅助80项已实际通过，另有TypeScript/定点ESLint通过；这不是实际CI或浏览器结果。CI接线使用既有web-build的TypeScript，不安装新增依赖，不改产品lock。后续实际run/job/artifact及失败均另行登记，不从输出绿灯重新冻结名单。

## 新订阅页面进度与退出条件

独立目录`tools/subscription-browser`增加同一自包含DOM表达式供未来CDP/PW共用、严格schema和canary检查；不扩大旧probe driver权限。交叉审修正了节点stale被误记为候选stale及签出/hidden合成fixture失真。其36项仅合成模型；没有真实页面PNG或新订阅E2E。

先用诊断候选取得可区分的实际观测，再选择符合证据的修复。若未重现或绑定仍歧义，明确未定，不扩大timeout、不删除cancel猜修、不忽略failedRequests、不重试挑绿灯。然后仍须完成[新订阅页双浏览器计划](P2-SUBSCRIPTION-BROWSER-ACCEPTANCE-PLAN.md)的独立server/harness、网络/审计、正常TLS、实际操作、截图、进程收尾及独立重放；本增量不缩减该目标。
