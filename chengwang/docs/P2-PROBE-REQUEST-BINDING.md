# P2：隔离探针请求关联与取消结果观察

当前状态：实现与纯CPU增量检查完成；首次真实CI因新增TypeScript类型错误在构建阶段失败，后续类型修正已通过CI构建。第二次Probe在新增辅助门的提交SHA传参处失败，真实浏览器仍未执行，保留原失败并修正显式参数传递。不是网络取消修复、系统上线或生产操作记录。

## 要解决的证据缺口

前序 `8c4852c` 原运行 [40005313533](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40005313533) 的CDP硬门因 `failedRequests=1` 失败，PW成功。旧诊断81条中有一次 `NET_FAIL/ABORTED`，但没有JS请求与CDP请求的共同身份键，不能据邻近的EOF或相同序号认作同次请求，更不能推断取消原因。原失败不覆盖。

本增量按[固定机器合同](../deploy/probe-readback/request-binding-contract.json)分别补齐：默认关闭的诊断构建开关、匿名请求身份关联、同一次取消调用的实际Promise结果、独立原件检查器。它只提高可定位性，不使失败自动成为成功。

## 实际实现

| 层 | 已实现行为 | 不应误读为 |
| --- | --- | --- |
| Web | 仅显式CI构建开关为1、精确loopback origin、固定匿名status路径及已绑定signal时，加入非秘密文档随机标识/mount/request头；正常构建及details不加头 | 通用追踪、认证信息或任意地址请求头 |
| 取消观察 | 原取消恰一次；不等待、不新增超时，不改变releaseLock/原错误/单飞；区分RESOLVED、REJECTED、THREW、NO_BODY | 旧CANCEL AFTER就是Promise已完成，或Promise完成证明网络未失败 |
| Node | CDP真实session字符串/PW真实CDPSession对象、default execution context/main frame、私下header键关联；公开仅整数别名 | 使用PW私有_sessionId、按时间邻近猜请求，或原始线上头公证 |
| 独立文件 | root预开0600、单链接普通文件FD；跨受限角色显式继承并验证精确目标；Node写单独512KiB闭集流，Chrome不继承此通道 | 扩大旧329728B日志预算、输出私有协议ID/令牌/原错误 |
| 验真 | 独立重算顺序、计数、双射、旧原件SHA和必要Git源；缺失/重复/多对一拒绝完整证明 | 诊断成功抵消原浏览器错误、私库独立验证、生产授权 |

旧status-v1、原80/56/32/92辅助门及native22/browser文件闭集保持不变；新sidecar只在lab顶层。八错误计数、正常TLS、no-store、deadline、单飞与禁止重试保持原语义。

## 当前实际验证

新增纯CPU：frontend16、Node24、Python投影16/验真24/FD运行器8，共88项实际执行通过，零跳过；原始stdout/TAP/unittest日志另行核名单与摘要，六个篡改/跳过/替代模型被新门实际拒绝。新88不是旧80的替代，也不是浏览器请求数量或业务覆盖率。

前端追加4个Vitest反例/正常路径，197门精确扣除新增4名后仍核旧193的全部名称/摘要；**实际197项Vitest仍待CI**。原observer12项实际保留，原Python92项也实际全部通过（200.972秒、零跳过）；未在本机运行Go、npm安装、构建、Vitest、浏览器、产品服务或Docker。

首次本机组合反例的预算fixture把“256合法”错当作超限，原失败保留在本机临时证据根；冻结后改为257条反例，48项Python实际通过，预算未放宽。新原输出读取器还实测到Windows lstat/fstat的ctime值不同；只在各自API前后验证完整稳定性，跨API仍核inode/device/mode/links/size/mtime，不丢弃ctime检查，也不改旧POSIX验真门。[CPython官方对应Issue](https://github.com/python/cpython/issues/157671)仅作语义参考，本机实测差异才是本轮证据。

主代理本机原输出：`C:/Users/Administrator/AppData/Local/Temp/chengwang-request-binding-root-020d73d7dec94322999a124a9719a69a`；它不是永久集中归档。

## 首次真实CI与最小类型修正

源码 `4ecaeddf7543ec86591a29b6cf0f5f871af29e2b` 的原 [Probe CI 40012629719](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40012629719)、[UI CI 40012629568](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40012629568) 与 [镜像 CI 40012629715](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40012629715) 均因新增代码的TypeScript类型错误构建失败，197项Vitest及真实浏览器未执行。四UI producer原日志均确认 `probe-api.test.ts:122` 的reader缓冲区类型过宽，`probe-api.ts:10` 的随机数回调参数/返回类型过宽。UI artifact数为0、fresh跳过；缺失原件不补造。

根据锁定TypeScript6.0.3的[官方DOM定义](https://github.com/microsoft/TypeScript/blob/v6.0.3/src/lib/dom.generated.d.ts)及[TypedArray定义](https://github.com/microsoft/TypeScript/blob/v6.0.3/src/lib/es5.d.ts)，只将随机数回调和新增测试reader的缓冲区显式限定为 `ArrayBuffer`，不使用any、不升级依赖或放宽strict。两文件修正前后的纯CPU转译JS逐字一致，16项纯检查再次通过；转译不是完整类型检查，修正仍待新的原CI验证。原失败run不重跑、不取消、不覆盖。

首次CI主代理日志：`C:/Users/Administrator/AppData/Local/Temp/chengwang-request-binding-4ecaedd-root-6d1779c2f2d840789488056c59ef218d`。前序文档提交 `9104264` 的原父门40008278980现已终态success，但不能代替本次源码回归。

类型修正源码 `b68a55e5cfea743c92db0d52a293c70a35734111` 的 [Probe原CI40013129942](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40013129942) 已通过真实编译；PW原job120618389518中新增16前端/24Node/48Python均实际通过，但新原输出门调用依赖的 `GITHUB_SHA` 在既有 `env -i` 子shell内不存在，触发unbound-variable拒绝，后续真实runtime跳过。根负责的CI接线遗漏不是浏览器故障。只通过原有显式位置参数逐层传入同一CI提交SHA，保留env -i、严格模式、失败门和全部名单；不恢复整个环境。新源码仍须首次原CI验收，不重跑旧失败。

## 真实运行退出条件

1. 新源码首次原CI，两引擎真实正常TLS运行；实际默认上下文、独立FD、绑定头和取消结果被捕获，不靠mock或时间推测。
2. 每条引擎的新sidecar、旧诊断、build和必要Git blobs经独立完整CLI复核；producer/独立重放报告逐字一致。缺失或未完成须保留INCOMPLETE，不补造旧build。
3. 保持原八计数硬门，`NET_FAIL`即使已唯一对应，也只能记录诊断事实。一次新运行未复现不证明旧故障已解决。
4. 原193+新增4的真实Vitest、旧辅助与父门、订阅及镜像回归分别核原件，不把步骤状态或前一版成功当新源码通过。
5. 实际完成、失败、未验项目及原运行ID写回台账。未合并main、未正式发布镜像、未访问/修改生产。

## 官方技术依据与限制

协议依据锁到前序实际Chrome155 revision的[Chromium Network PDL](https://github.com/chromium/chromium/blob/3ff7ac5a9224be9156d7f8703a06e22890aafd34/third_party/blink/public/devtools_protocol/domains/Network.pdl)，不是拿最新协议代替旧实现。ExtraInfo可缺失和乱序，本轮仅证明requestWillBeSent元数据关联，明确不声称原始线上头已独立公证。

同源请求与取消语义参考固定版本[Fetch](https://github.com/whatwg/fetch/blob/59afe349913d56898c947576216f1c2579308be7/fetch.bs)与[Streams](https://github.com/whatwg/streams/blob/337e8e4f06b2d9e482d4eae7fb6b6bed58de6445/index.bs)。规范是设计依据，不证明具体Chrome155取消根因。新增头和观察微任务也可能扰动复现时序，必须保留旧失败及后续原始结果。
