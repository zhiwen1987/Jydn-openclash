# 实际总览真实浏览器验收合同

本合同定义新场景 `overview_ui`，由仓库内 [contract.json](../deploy/overview-ui-browser/contract.json) 作为机器可读唯一字段表。它是实施与验收约定，不是浏览器已运行、CI 已通过或生产已上线的证据。当前源码基础为 `aed4712253f840d1c68b2482bd0c0edf4fa4e7f4`；后续真正构建与采集必须绑定各自实际的新提交，不能拿这个历史标签替代来源绑定。

两个固定 profile 分别为 `evidence_disabled` 和 `evidence_enabled_unknown`，均在 Chrome/CDP、Playwright 两条真实浏览器路径执行。每次使用真实 `cmd/server`、真实构建的 Web 和独立私有 NSS 信任，通过普通 TLS 访问同一个固定回环 origin `https://127.0.0.1:17891`。不得拦截或模拟 fetch、替换 React 状态、关闭证书校验、跳过 CSP，或改动产品的 cancel 行为方便采集。

## 两个真实配置及证据边界

两者的服务端角色环境各有固定 16 项，只有 `CHENGWANG_LIVE_OVERVIEW_ENABLED` 在 false/true 间改变。身份、Mihomo、周期观测、探针和订阅均未接入；发布、操作和订阅写门始终为 false。`profilePolicies` 明确列出每项环境值与禁止出现的配置，不接收任意环境注入。

`runtime-facts.json` 必须关联实际服务端进程 PID/startTicks/可执行文件和参数摘要、读取到的 `/proc/.../environ` 与 profile，而不能只照抄期望值。`liveOverview.enabled` 证明这里的配置事实，不证明控制器连接、源数据新鲜、业务健康或用户已认证。源端点 `127.0.0.1:17892` 前后无监听的检查也是本次局部事实，不是生产网络证明。

`storage-readback.json` 的计数只属于本次私有隔离目录。未构造的订阅组件记 constructed=false；新建操作库的 commandCount=0 不表示生产库存为空。管理 scope 是 tenant/site 为空的 candidate/control-plane/local，不将其解释成浏览器已取得授权。统一边界为 `SOURCE_BOUND_TRUSTED_CI_NOT_INDEPENDENT_PRIVATE_STORAGE_ATTESTATION`。

## 完整交互与请求数量

`App` 的 snapshot effect 只随 App 挂载一次。切换数据源、详情页和返回不会重新获取 snapshot。`EvidenceOverview` 每次挂载获取一次 overview；已完成后的刷新再取一次；单纯调整 viewport 和重复点击同一数据源不取新请求。不得把开发 StrictMode 的重复 effect 当成这里的生产构建预算。

disabled 必须经过下表 11 个 DOM 点。enabled 另在第二次实际总览后依次点击设备、节点、订阅三个真实 CTA，并逐次通过导航返回，合计 17 点。不得删掉详情访问来压低请求数。

| disabled 检查点 | 动作 | 累计 overview GET | PNG |
| --- | --- | ---: | --- |
| demo_desktop | 默认演示，1440×900 | 0 | demo-desktop.png |
| actual_enter_desktop | 点击实际证据 | 1 | actual-desktop.png |
| actual_refresh_desktop | 完成后点击重新读取 | 2 | actual-refreshed-desktop.png |
| demo_return_desktop | 切回演示 | 2 | demo-return-desktop.png |
| actual_reenter_desktop | 再次进入实际 | 3 | — |
| kernels_page_desktop | 导航内核与协议 | 3 | — |
| actual_return_from_kernels | 返回总览 | 4 | actual-remount-desktop.png |
| actual_mobile | 仅调整到 375×900 | 4 | actual-mobile.png |
| actual_mobile_refresh | 手机宽度刷新 | 5 | — |
| demo_mobile | 切回演示 | 5 | demo-mobile.png |
| actual_mobile_reenter | 再进入实际 | 6 | actual-reenter-mobile.png |

enabled 的完整顺序、导航页、实际 view、h1 与累计 API 次数全部在 `stepFences.evidence_enabled_unknown`，其中新增点为：

| 检查点 | 真实动作 / h1 | 累计 overview GET |
| --- | --- | ---: |
| device_page_desktop | 查看设备读回 / 设备读回与差异 | 3 |
| actual_return_from_device | 返回实际总览 | 4 |
| nodes_page_desktop | 查看代理节点 / 代理节点观测 | 4 |
| actual_return_from_nodes | 返回实际总览 | 5 |
| subscriptions_page_desktop | 查看订阅与提供者 / 订阅资源 | 5 |
| actual_return_from_subscriptions | 返回实际总览 | 6 |

此后内核页仍为 6，返回实际为 7，手机 resize 为 7、刷新为 8、演示为 8、重新进入实际为 9。导航名不能冒充详情标题；尤其设备页 h1 不是“设备读回”，订阅页 h1 不是“订阅与提供者”。

节点时限必须有实际 driver.actionTimings 记录，不能仅凭源码有 guard 就说离线已测到 10 秒：disabled 的 nodeVisit 为 null；enabled 从节点 CTA 点击之前，到返回实际总览最终 settled/guard 之后，记录 enteredMonotonicUs/returnedMonotonicUs。两者是非负安全整数，返回不早于进入，差值最多 10,000,000 微秒。进入向下取整、返回向上取整形成保守上界；它包含点击、读取、DOM 核验、离页及返回开销。报告注明 1 微秒量化与 source-bound trusted-CI 单进程时钟边界，不把这当成外部时间公证。不得用 API request start 时间推算精确完整访问时长。

每个 profile 固定一份 snapshot。enabled 节点页还会真实获取一次 `/api/v1/observations/status` 和一次 `/api/v1/probes/status`；设备、订阅页面保持未登录，不点击管理读取或填写 token。节点页从进入到两个正文完成、DOM 核验并离开的连续动作预算最多 10 秒；产品原有 30 秒轮询保持不变。任何额外 poll 都必须记录后拒绝本次场景，不能删掉。短驻留不证明轮询正确。

请求上限包含完整 64 个资产的能力：disabled 为 `64 + 1 document + 1 snapshot + 6 overview = 72`；enabled 为 `64 + 1 + 1 + 9 overview + 1 observation + 1 probe = 77`。每个 profile 恰好采集上述 8 张 PNG，截图尺寸必须匹配检查点 viewport。

每个检查点前，所有已启动请求必须有真实终态，当前正文观测任务必须结束，API 累计计数必须准确，当前实际 DOM 必须绑定本次对应 overview。不能拿先前挂载的报告或另一个 profile 代替。终态时间与 header 时间分别要求不早于 request start，不额外要求终态时间晚于 header 事件的观测时间。

## API 正文与未知值

所有 API 为匿名、固定同源 GET，不接受 query、fragment、userinfo、Authorization、Cookie、请求正文或重定向。200 overview 正文必须完整可读，最大 64 KiB，严格 UTF-8、JSON、精确键和真实 DTO 约束；字段来自 `internal/overview/model.go`，不是根据前端随意造字段。

enabled 无上游时，真实 DTO 为 `chengwang.overview-snapshot/v1` / dataSource=live / mode=candidate / readOnly=true / advisoryOnly=true；coverage=none，并保留七项 missing。观测配置和工作进程均 false，三个 layer 都是 unknown/not_configured、时间 null；探针 coverage=null；订阅 sourceCount/nodeCount=null；五项尚未采集均为 true。不能将 null 变成 0、0 ms、0% 或绿色健康。

`generatedAt` 是当前服务端组装时间，不是上游采样时间。它必须为合法非 Go-zero 的 UTC RFC3339Nano，DOM `<time>` 的文本和 dateTime 精确匹配本步响应。不同响应不强加单调递增，也不拿客户端当前时钟推断缓存新鲜度。disabled observation/probe status 中 Go `omitempty` 省略的时间字段与 overview 中必填 null 的时间字段有意不同，不得补造。

snapshot 保留 source-bound 的真实 seed/demo 语义并与当前构建、真实响应绑定，不声称该页展示了实时节点/DNS健康。进入非实际总览时 TopBar 回到编辑器 Snapshot 作用域，是页面选择语义，不是 HTTP 错误回退。

## 503 的真实终态与正文缺口

disabled overview 返回真实 503，Go 错误若能读取必须精确为 `{"code":"overview_not_configured","message":"实际证据汇总尚未启用"}`。产品 `overview-api.ts` 在非 OK 时先 cancel body，再抛固定中文 HTTP 错误；采集器不能为了获得正文改动这一行为。

只允许这一 profile、这一匿名同源路径、这一 GET 与真实 JSON 503 headers 的同一 alias 使用受控 union：

1. `FINISH`；或真实 `NET_FAIL`，且实际 canceled=true、无 blockedReason、无 CORS error。
   `FINISH` 不报告取消或拦截/CORS 标志，因此 capture.terminal 中 canceled/blockedReasonPresent/corsErrorPresent 三项必须为 null，不能填 false 冒充观察；encodedDataLength 为非负安全整数。`NET_FAIL` 的 encodedDataLength 则为 null，三个失败字段必须来自真实事件，且只有 true/false/false 的组合才具备本场景资格。机器表位于 `captureRules.terminalScalarRules`。
2. 两种终态都真实尝试 `getResponseBody`。RPC fulfilled 后，base64、UTF-8、大小、秘密扫描、JSON、固定错误正文等任何失败都导致拒绝，不能归入“正文不可用”。
3. 只有该 RPC 的 await 本身 rejected，才记录 `bodyState=unavailable`、`bodyUnavailableReason=BODY_RPC_REJECTED_AFTER_EXPECTED_503`、bodyRPC={attempted:true,outcome:rejected}，并保留实际 captureErrors+1。responseBase64/SHA256/bytes/errorCodeObserved 四项均为 null。不得伪造空正文或推断已读到错误 code。
4. `NET_FAIL.canceled` 和 body RPC rejected 是两个独立观察，不断言哪一条 JS 调用造成后者。200、document、asset 以及其他路径一律没有这项缺正文豁免。

raw 八项计数使用原始 runtimeErrors/consoleErrors/consoleWarnings/cspErrors/assetErrors/forbiddenRequests/failedRequests/captureErrors。runtimeErrors、consoleWarnings、cspErrors、assetErrors、forbiddenRequests 五项严格为零；其余真实保留，不扣减、不归零。独立检查器必须从 alias、kind、请求、headers、实际终态、RPC outcome、CAPTURE 和 ERROR 事件重算资格，而不是信任一份 qualification 数组。enabled profile 仍要求八项全部为零。

disabled profile 可出现闭合 `LOG_NETWORK_ERROR`：只能绑定此前已经观察到 REQUEST 和安全 HEADERS 的匿名同源 OVERVIEW GET 503，source=network、level=error、urlSameRequest=true、workerIdPresent=false、categoryPresent=false、beforeClose=true，同一 alias 最多一次。category 字段即便值为 null/undefined 但实际存在也不能取得资格。事件可位于终态前或正文捕获后，不猜测 console 文本；每个真实合格事件使 raw consoleErrors 加一。其余 error/warning/security 日志仍走原 ERROR 并导致拒绝，不能忽略或归零。无认证、无 query、无200豁免。

独立报告按事件 seq 重算 `qualifiedExpected503NetworkLogs`，同时要求 `unexpectedConsoleErrors=raw consoleErrors-合格唯一日志数=0`；它不信任 producer 资格数组，也不接受旧 ERROR(console_error) 作为合格事件。503 关联不是因果证明或无泄漏证明，不输出 raw text/url。beforeClose 是源绑定可信 CI 投影，并非外部进程时序公证。

报告单列 `qualifiedExpected503ReportedCanceled` 和 `qualifiedExpected503BodyUnavailable`，并要求 unexpectedFailedRequests/unexpectedCaptureErrors 为零。`ERROR` 必须携带 alias、kind、capture_error 和闭合原因，其他 capture_error 不能借此豁免。这是新场景的受控例外，不能称原有“八零”合同通过。

disabled 六份错误正文全部取得时 errorBodyCompleteness 才为 true；任一缺失必须为 false，并逐 alias 记录 coverageGaps。enabled 无该错误正文集合时为 null/not_applicable。缺正文不能证明错误字节、code 或正文不存在泄漏。

## DOM、几何与时间提示

实际总览固定展示“本次读回的服务端组装时间”、徽标“汇总时无当前证据”“汇总时覆盖未知”，并明确“以下状态对应本次读回的服务端汇总时点。页面不会自动更新，状态可能已变化；请重新读取确认。”这限定显示时点，不等于已验证健康后过期或页面自动更新。

enabled 需核对三张来源卡、四个 summary span、十个来源时间“未记录”、唯一 generatedAt time、无 current 徽标、无探针数量健康指标、未采集区及未知订阅清单。disabled 则保留中文受控错误、零来源卡/summary/未采集区、可重试刷新、未核验 TopBar，并且不自动切回演示。

pending 若被实际观察到，旧 report/card/summary 必须撤销，刷新 disabled、TopBar 未核验；快速响应可能不产生可采到的中间样本，不能伪造 pending 点。默认演示、实际错误、实际未知、详情和内核 view 分开采集。

present、rendered、inViewport、unobstructed 是独立事实。375 宽度时 `.version` 节点仍存在但被 CSS 隐藏，不能说用户看到了来源徽标。下方 CTA 可 rendered 但在屏幕外，必须真实滚动后进行 native 点击，不能直接触发产品 handler 或设置状态。各 DOM 点还检查无水平溢出、固定 zh-CN/UTC、空 local/session/cookie 存储。

详情中的 `authenticatedResultVisible` 仅记录真实可见的受保护结果迹象（设备健康状态点、探针详情、订阅范围）；不能由 DOM 推断“有没有发生认证读取”，更不能根据 profile 直接填 false。字段原拟名 `authenticatedReadPerformed` 容易混淆两种事实，因此只在新采集 schema 中更正；实际无 Authorization、无私有 API 请求必须从 captures/请求事件图单独重建，DOM 布尔不能替代。

## 导出、预算与正常退出

新成功工件闭集恰好 19 件：11 个无前缀 JSON/JSONL 框架文件与 8 张 PNG，名单见 `publicFiles`。私有 input、秘密文件、原始 CDP ID、stdout/stderr、动态 token 和独立 verification report 都不得混入这一闭集。input 为 UID10001/0600，root 私有 secret 为 UID0/0600，不把两者所有权混写。

favicon 仅允许 `web/index.html` 与受信 helper 逐字一致的固定内联 data URI，仍要求匿名 GET、无正文/redirect，最多四个独立且不复用的私有 request ID，并单独计数。任意其他 data URI 或网络 `/favicon.ico` 都没有该豁免。先前合同将其误写成同源 `/favicon.ico`，已对照实际源码更正；没有因此改动产品或增加网络豁免。

新场景独立限制：DOM 单行 128 KiB、总文件 2 MiB，driver 1 MiB，captures 24 MiB，全部 decoded response 16 MiB，最多 512 事件、每事件 1,024 字节，真实 manifest 256 KiB、每 PNG 4 MiB。这些是同时成立的独立上限，不保证 17 行都能各占满单行上限；不得据乘法放宽总预算。旧场景预算保持原样。

manifest 必须来自真实 `.vite/manifest.json` 字节并匹配 dist hash/size，保留 Vite 合法额外 names 数组，按 entry/import/CSS/asset 图核对实际资产。真实 TLS 证书链、私有信任、Chrome pin 消费与正常浏览器关闭必须具备来源证据；不能仅看到一份 success boolean 就接受。

机器字段 `manifestAlgorithm` 逐字段沿用现有 capability 合同，不新增 Vite 属性：src/file/css/assets/isEntry/name/names/isDynamicEntry/imports/dynamicImports。入口 index.html 与递归静态 imports 的文件/CSS 属于 required；可达 dynamicImports 的文件/CSS/assets 进入 allowed，不因此强迫浏览器触发所有懒加载。复用的纯 `manifestGraph` 使用两个独立集合 visited/staticVisited，分别跟踪允许图与强制静态图；先从动态路径遇到的共享项，稍后通过静态路径访问时仍须纳入 required。它处理环而不跳过强制闭包，不把 trust.html 或不相干条目变成必需资产。此处补齐的是既有算法的机器键表，实际图仍从本次 source-bound manifest 字节计算，不是合成固定资产清单。

最终还需所有请求终结、所有正文任务 settled、正常 Chrome/session/launcher 退出；父进程单独证明 Node/server joined、exit0、forcedSignals0、无存活自有进程及 host/source 前后稳定。报告在 repo 和 evidence 目录外 exclusive create，全部输入字节前后稳定。失败场景不能作为成功 19 件接纳，也不能因为其他场景成功而覆盖失败。

## 仍未证明

本轮两个固定 profile 不能强制同一个挂载 ready→HTTP error、晚到响应、忽略 abort 的传输、旧 finally 释放新 owner、客户端 5 秒超时、服务端软 500 ms 锁等待等转移。没有真实健康→过期/停止/时钟回拨，也没有业务、节点池、全网、端到端 DNS、生产发布或任意可用率百分比证明。CPU 合同检查、单元测试、构建和浏览器验收须分别报告；任何一层通过都不等于上线。
