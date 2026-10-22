# P0-d8 可信策略只读控制台与受保护操作记录

本阶段把 P0-d7 的自动撤销刷新、跨库恢复事实接入可操作的只读界面，不新增生产执行权。实现、测试和部署必须分别记账。本文件是实施合同，不是验收成功证明；最终执行结果另行记录。

## 范围与约束

- 单一集成者，后端历史/RBAC、前端交互、候选静态入口与 CI 三个子代理并行，主代理集成并复核证据。
- 仅开发分支和隔离 CI；不连接或修改生产旁路由、爱快、DNS、Kuma、Docker/ERP 主机。不合并 main。
- 保留 Go 1.23 产品边界与独立 Go 1.25.8 验证模块；不更换依赖、根信任或 Registry 来源。
- 结果始终 advisory、`authorization=BLOCKED`、`deviceActionsExecuted=false`。九项恢复 blocker 不解除。
- 不在 UI 加入“验证一下”“恢复授权”“部署”按钮；读取页面不能消费 grant、改策略、刷新源或修审计。

## 真实功能清单

| 能力 | 本阶段实现边界 | 不代表 |
|---|---|---|
| 可信目录状态 | 真实候选 Store、目录代次、摘要、有效期、账本与撤销计数 | 实际网络或业务可用 |
| 来源刷新 | 显示 P0-d7 进程内精确来源确认及截止；未启用明确显示 | 发布方没有隐藏新撤销、完整 TUF |
| 恢复观察 | 真实本次启动补审计计数、已绑定的持久操作结果 | 自动修坏库、重放业务、HTTP 成功送达 |
| 操作记录 | auditor/admin 受保护、只读脱敏、严格分页快照 | 通用全系统日志或独立 WORM |
| 浏览器页面 | 同源显式认证、搜索、分页、摘要展开、刷新、清除 | SSO/企业 IdP、多租户管理后台或正式上线 |

## API 与跨库只读一致性

`GET /api/v1/image-trust/history` 通过现有真实认证、传输约束、固定 scope，再检查独立 `image_trust.history` action。仅 auditor/admin 可用；不继承 BreakGlass。旧 Backend 保持兼容，另加可选 HistoryBackend。

参数 `limit` 默认 20、范围 1..50；`offset` 默认 0、范围 0..4096；`sequence` 默认 0 表示首次读取，之后必须与当前 Store sequence 相同。不接受未知、重复、编码别名、非规范数字、请求体或错误方法。身份不能从请求参数传入。身份/权限校验先于参数和 backend 访问。

按 journal 追加顺序从旧到新，而非虚构时间排序。跨库读取：Inspect → Journal → 审计 RecoverySnapshot → Inspect → 全量绑定投影 → Inspect。正常并发变更返回 409，不混接不同页，也不误将正常 writer 当篡改而 poison。审计坏前缀、坏 ACK 或冲突仍失败关闭，不在读取时修复。每次读有界，但会检查全部保留 journal 和受限审计快照；这不是无限大历史库的索引分页。

只返回操作 ID、actor、kind、state/outcome、ACK、策略/grant ID、目录 generation/hash、prepared/result 审计 hash 和实际绑定事件时间。未绑定时间为 `0`（未知），不用当前时间伪造。无原始 Data、bundle、approval、私钥、身份配置、token、来源 URL/认证信息。

Status 新增本次 `observedAtUnix` 和实际缓存审计核验 `auditVerifiedAtUnix`。GET 本身不续审计健康租期、不触发 Verify，也不刷新撤销源。

## 界面方向、组件与交互闭环

方向：专业、克制、可追溯，沿用既有浅蓝灰控制台，不改主导航布局和顶部任务栏。先展示“隔离候选 / 未发布 / BLOCKED / 只读”，再展示目录、来源与审计三个独立状态，最后呈现当前策略和受权限保护的操作记录。不用营销式视觉、演示正常值或装饰性拓扑证明能力。

复用语义 token：主蓝 `#1769e8`、浅蓝 `#eef5ff`、边线 `#dfe5ee`、主文字 `#172033`、次文字 `#52627a`、核验绿 `#08764b`。组件为连接表单、四项摘要、目录事实、分页策略卡、分页操作记录、原生 details 摘要；只读操作与状态分开。375px 单列、按钮最小高度 44px、可见键盘 focus、aria-live、reduced-motion。

一次完整操作路径：打开 `/trust.html` → 初始全未知且不自动请求 → 输入 Bearer 并连接 → 两个独立 GET → 搜索/展开/翻页/手工刷新 → viewer 记录 403 但已授权状态仍可见 → 断开清除；401 清除全部，409 清页并要求手刷，503/超时/坏 schema 回未知。不无限自动重试、不自动网络轮询。

- token 只驻留组件内存与遮罩输入，不进 URL、日志、cookie、localStorage 或 sessionStorage。换 token/baseUrl、断开、卸载均清状态并 Abort；请求代次拒迟到响应。
- 只允许固定同源 HTTPS 或本机 loopback HTTP；禁止任意 API 地址、重定向、浏览器环境代理凭据跳转和跨源发送 Bearer。GET 使用 omit/no-store/no-referrer。
- 前端严格验证 boundary、BLOCKED/false、字段类型、尺寸和真实摘要格式：目录/镜像为 `sha256:<64hex>`，审计 hash 为裸 64hex。1MiB 流式响应上限；超限或非 JSON 失败关闭。
- 来源/目录/审计时效独立显示；客户端以服务观察时间加请求耗时、单调时钟和向前墙钟的保守高水位老化，切回标签页立即重算；一次观察过期后不能因本地回拨而重新变绿。
- 策略每页 20 条，本地搜索；记录每页 20 条，明确“仅搜索当前页”，sequence 冲突后不自动追页。新目录读回重置策略页，防旧页码落到空页。
- 不把 React/Vitest mock 通过当实际 API 可用，也不把 localhost 静态渲染当完整 E2E。

## 候选静态入口

现有 App 加入“可信策略”入口，但原产品 `cmd/server` 不因本阶段自动拥有真实 trust backend。独立 `trust.html` 不加载 demo Snapshot；可选候选 `webDir` 通过真实 Vite manifest，只服务 trust entry 可达的已构建资源。

默认不开静态 UI。可信绝对目录、逐段 nofollow、所有者/权限/nlink/regular-file 校验、读取前后 inode/大小/mtime/ctime 复验；最多 64 个资产、每个 2MiB、总 8MiB、HTML/manifest 各 256KiB。内存快照服务，不能退回通用 FileServer、目录列表或 SPA fallback；不暴露 index、manifest、源码、身份文件和未知 API。

CSP self-only，无 inline/eval/第三方脚本；no-store、nosniff、DENY、no-referrer。Vite manifest 与多入口构建，不用正则猜 JavaScript 依赖图。HTML 资源引用必须属于受限可达集合。

## 验收分层与失败处理

1. 本地已有 lockfile 依赖执行全部 Vitest、TypeScript、ESLint、Vite build。当前 Windows Go 缓存不可信，不本机运行 Go。
2. Browser 插件在本会话不可用，采用已有 Playwright MCP 检查本机真实页面的初始状态、桌面/375px、控制台、截图；这只是未认证静态交互层。
3. Ubuntu 隔离 CI 在线阶段仅获取固定 Go 模块、Registry 测试镜像、`npm ci --ignore-scripts` lockfile 依赖及锁 commit/摘要的官方 Noto CJK 测试字库和原许可，不执行仓库构建或测试；不向生产镜像添加字体依赖。
4. 无外网、non-root、cap=0、NoNewPrivs、源码及依赖只读的 namespace 中执行 Go ordinary/race/vet、前端测试/类型/lint/build；所有生成文件落 private run root。
5. 启动真实候选 `run()`，使用真实 Store、真实 evidence、真实认证身份、25 项实际签名目录定义与 22 条受审计操作。预装 Chrome + Node builtin WebSocket 通过 CDP 实际点击：认证、200/401/403、搜索、详情、策略 20→5 / 历史 20→2 分页、刷新、断开、移动端、键盘和 reduced-motion。不得 route/mock/inject fetch 或跳过 TLS 校验。字库只读挂载、fontconfig/cache 私有，检查实际字体文件摘要及中文匹配；通过 CDP 读取真实标题所用平台字体与 glyphCount，并查看截图。DOM 含中文不代表已经可读，截图方框必须记为视觉失败。
6. Chrome 的 CI-only `--no-sandbox` 必须显式记录；外层 namespace 不能取消。浏览器走 127.0.0.1 HTTP，**不声称已完成浏览器 HTTPS/证书验收**；Go 的既有实际 TLS 测试独立保留。
7. 保留旧子模块 627 场景、父模块 2257 场景基线及真实 Distribution 链；新 D8 场景独立计数，最终按下载的完整 transcript 实测校准、锁定，不预编造总数。
8. 归档只含脱敏报告/截图/摘要，不能包含 ready.json、私钥、配置、浏览器 profile。候选停止后检查 Store/journal/audit 未被 UI 读取改变，再清除临时身份与敏感文件。浏览器采用“管道门 → 私有身份记录原子发布 → exec”的进程崩溃可见交接，并由 Node finally 与独立 shell trap 共用 pidfd guard；惰性进程的 supervisor SIGKILL、父退子存、逃逸 crashpad、错 PID/start 和相似路径不误杀测试必须单独通过。它不是恶意进程 sandbox，也不是实际 Chrome SIGKILL 或断电测试；监督者本身同时被 SIGKILL/主机断电仍只能依靠外部 CI 生命周期回收，不能报告自身已完成清理。

任一步失败均不能标验收成功。记录失败、修正及重新运行，不以删除旧用例、弱化断言、增加跳过、修改 trust/clock 或关闭生产安全门换绿。

## 本阶段不关闭的缺口

没有生产部署/读回、长期浸泡、真实浏览器 HTTPS 证书路径、企业 SSO/IdP、WORM/外部单调见证、分布式事务、坏文件自动修复、journal 自动压缩、任意离线追赶、写操作 UI、镜像签发/正式 Registry 发布、主服务 backend 接线或真实设备执行。完整企业网络系统、多内核、反代/隧道、实际分流与业务评估等不能因本页完成而记为已交付。不承诺零 Bug 或 99.999999% 端到端可用率。

参考：[Vite 多页构建](https://vite.dev/guide/build.html#multi-page-app)、[Vite build manifest](https://vite.dev/config/build-options.html)、[Chrome DevTools Protocol](https://chromedevtools.github.io/devtools-protocol/)、[Node WebSocket](https://nodejs.org/api/globals.html#class-websocket)、[Linux pidfd_send_signal](https://www.man7.org/linux/man-pages/man2/pidfd_send_signal.2.html)、[Open Group 进程组 ID 生命周期](https://pubs.opengroup.org/onlinepubs/009696699/basedefs/xbd_chap04.html)、[Crashpad 官方参数说明](https://chromium.googlesource.com/crashpad/crashpad/%2Bshow/HEAD/handler/crashpad_handler.md)。runner 镜像清单只是工具可用性提示，实际 Chrome/Node 版本必须以当次 CI 探测和浏览器报告为准。
