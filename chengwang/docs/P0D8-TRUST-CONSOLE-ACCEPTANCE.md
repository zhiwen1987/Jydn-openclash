# P0-d8 可信控制台与操作记录隔离验收

日期：2026-10-22（Asia/Shanghai）。结论：**本阶段 implemented+tested isolated-only，未上线**。P0-d7 的自动撤销刷新与健康跨库恢复保持完整回归，本阶段补上真实产品只读状态、受保护操作记录及可见交互。没有生产部署批准，没有 main 合并，没有设备执行授权。

## 实际完成

- 新增 `GET /api/v1/image-trust/history` 和独立 `image_trust.history` action。真实认证、传输与固定 scope 校验在参数和 backend 访问前执行；仅 auditor/admin 可读，不继承 BreakGlass。严格数字、未知/重复参数拒绝，limit 1..50、offset 0..4096、sequence 快照防混页。
- 后端核对 Store、全部保留 journal 与受限审计快照的绑定投影；前后读到正常写入返回 409，真正坏前缀/ACK/语义冲突仍失败关闭。只读不修复、不续审计租期、不刷新源、不重做业务。未绑定时间返回 0，不伪造当前时间。DTO 不返回原始 Data、bundle、认证材料或来源凭据。
- 只读控制台分开显示目录、来源新鲜度、审计健康及本次启动补审计；策略搜索/20 条本地分页、记录 20 条服务端分页、完整摘要展开、手工刷新、断开清除。页面始终标注隔离候选、未发布、BLOCKED、只读。
- 凭据仅组件内存和遮罩输入；同源 HTTPS/本机 loopback HTTP，GET-only、禁止重定向、无自动网络轮询。401 清除全部，403 保留独立已授权状态，409 清页要求重刷，失败回未知；有超时、请求代次、流式尺寸上限、早拒绝 body 取消。保守时效高水位防墙钟回拨让过期状态复绿。
- 独立 `trust.html` 不加载演示 Snapshot；候选静态入口默认关闭，只服务 Vite manifest 可达资产，严格路径/权限/文件身份/大小、内存预加载、self-only CSP 与安全响应头。不是通用 FileServer 或 SPA fallback。原 `cmd/server` 未注入真实 trust backend。
- 三个子智能体并行负责后端/RBAC、前端交互、候选入口与 CI，并交叉独立审查；主代理集成、下载原始工件并逐源码 blob 复核。操作说明见 [候选控制台手册](TRUST-CONSOLE-OPERATOR-NOTES.md)，范围合同见 [实施合同](P0D8-IMPLEMENTATION-CONTRACT.md)。

## 最终代码及实际执行结果

代码：`ecb1a4e6fc3206d7cb87abd51eb60ee8352a46bb`。以下均为该提交真实 CI 执行及下载复核结果；后续仅文档归档不代替该代码验收点。

| 层级 | 最终事实 |
| --- | --- |
| 绑定与浏览器 CI | [run 39778238811 / job 119822560806](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39778238811/job/119822560806)，success |
| 父项目 CI | [run 39778238648 / job 119822560164](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39778238648/job/119822560164)，success |
| 子模块 Go | ordinary/race 各 669 个精确 Test pair、8 包、0 fail/skip；vet 通过。root61、cmd97、policy127、product90、refresh64、registry73、catalog89、state68 |
| 子模块基线 | 原 627/490/379/234 集合及旧 product47/cmd46 保留，完整 669 pair SHA256 `a55d7427fd64491017c7a0fe20756cac0051cfb426218d7082e0ccb83baeb4eb`。名称基线不等于宣称所有旧测试体从未调整 |
| 父项目 Go | ordinary/race 各 2311 个 Test pair，合计 4622 次语义运行；37 包中 36 pass、1 个显式允许的 `internal/domain` 无测试包 skip，测试场景零 fail/skip；原 2257/2252 集合保留，新增 API42、authz11、DTO1 共 54 场景全部执行 |
| 父完整场景指纹 | 2311 pair SHA256 `58b9ebb71b6261184580b9b2ed55b893fd7a4172c7326ba1f74d38e6b6281da1`；原 2257 pair SHA256 `7a45962e28c5ab719bf968abbbd8a5b357b07a006218b4d496b3b9766524e4f0` |
| 前端 | 77 个 Vitest、5 文件、0 fail/skip；原有 3 文件20、Console21、ImageTrust API36。保留先前实际通过的 69 项逐名集合，新增 8 项真实 ReadableStream 取消场景；TypeScript、ESLint、Vite build 通过，依赖和 lockfile 未更换 |
| 浏览器清理器 | 11 项通过：3 项纯解析与 8 项 Linux 真惰性进程故障测试。覆盖 supervisor 退出、leader 退出后子进程、TERM 忽略、私有 crashpad、错 PID/start、相似路径不误杀、重复清理；是模拟 Chrome 的进程测试，不是实际 Chrome SIGKILL 证明 |
| 其他门 | Python159（canary39/supply-chain45/egress19/bootstrap29/tests27）、shell13、schema11；真实 Draft2020 metaschema 验证通过。绑定 JSON 门自测 49 负例，原门与旧 required 基线保留 |
| 真实 Registry | 无适配 Distribution 3.1.2，两类签名 ordinary/race 各 3 个场景；managed 与产品 API 原 8 条标记、D7 刷新/恢复 4 条标记均保留。144 次不可变 digest GET/HEAD 200（GET48、HEAD96），另有 1 次 `/v2/` 健康 GET 200，不混计 |
| 构建 | Go1.25.8、trimpath、revision 为上述提交、modified=false；候选 SHA256 `d0d97b3d827a87fa750d725b6a96931d3251f79cebfbe51530058661b69d4f85`。只核对 CI 摘要/buildinfo/--help，本体未上传，不冒充独立下载重哈希、签名产品镜像或正式安装 |

### 真实浏览器 QA

目标路径：实际候选 `/trust.html` → 显式认证 → 真实 Status/history → 搜索/详情/分页/刷新 → viewer403 与错误凭据401 → 断开清除。不是 fetch mock、route stub 或仅静态页面截图。

- 环境：Ubuntu 隔离 CI；实际 **Chrome/155.0.8059.39、Node v22.23.3**；桌面 1440×1000、移动 375×812、横屏 812×375。不同 run 的 runner 版本可能不同，不能把前一轮 Chrome156/Node22.23.4 填入本轮。
- Browser plugin not available：本机静态初始页面用已有 Playwright MCP 检查；完整候选用 runner 预装 Chrome、Node builtin WebSocket/CDP，不安装新浏览器依赖。两个层级证据不混用。
- 共 38 个检查事件、14 次同源只读 GET：200=11、401=2、403=1；runtimeErrors/CSP/asset/forbiddenRequests 均为 0。
- 实际候选使用 25 项临时签名目录定义、22 条 journal 和 44 条审计。策略 20→5、历史 20→2、真实 `sha256:` 摘要展开、当前页历史搜索、手动刷新、viewer 权限区分、401 全清、重新连接、断开清除均通过。
- 页面身份/非空/无框架错误遮罩/控制台健康/截图/交互六项均通过；移动无横向溢出、可见按钮至少 44px、键盘 focus、reduced-motion 通过。观察窗口无自动网络请求，不声称证明无限期行为。
- 首屏和认证态实际截图经主代理及独立代理查看，中文可读、布局无已发现遮挡。CDP 实测标题使用 `Noto Sans CJK SC / NotoSansCJKsc-Bold`，glyphCount=7、custom=false；不是仅凭 DOM 有中文判定。
- 停止并重开候选后，真实 Store sequence、generation、ledger 和审计计数未因 UI GET 改变；`browserGroupStopped=true`，临时身份、凭据、profile 清理门通过。

| 实际 PNG | 尺寸 | 字节 |
| --- | --- | --- |
| trust-console-desktop-disconnected.png | 1425×1300 | 134837 |
| trust-console-desktop-auditor.png | 1425×6024 | 456035 |
| trust-console-desktop-viewer-forbidden.png | 1425×2899 | 271395 |
| trust-console-mobile-auditor.png | 375×8698 | 448431 |

桌面全页宽度因滚动条为 1425，不伪报为完整 1440。截图在 CI 脱敏附件中，不提交生产材料或浏览器 profile。

浏览器仅 HTTP `127.0.0.1`，**不是浏览器 HTTPS/证书验收**。CI-only Chrome `--no-sandbox` 已显式记录，外层 namespace non-root/cap=0/NoNewPrivs/loopback-only 不取消；不能把外层隔离说成 Chrome sandbox 开启。源码、Go 模块缓存、node_modules、字体为 kernel 只读；生成/编译/字体缓存在 private run root 可写，生成 dist 为权限只读并内存预加载，不冒充独立 kernel RO dist mount。

## 工件、源码与依赖核对

- 最终绑定工件 52 个文件，无 ready/config/identities/profile/私钥或二进制本体。主代理目录：`C:\Users\Administrator\AppData\Local\Temp\chengwang-p0d8-ci-39778238811`；独立代理目录同级 `chengwang-p0d8-review-39778238811/image-binding-39778238811-1`。Temp 与 Actions 保留期不是永久备份。
- `checkout-before/after.sha256` 535 项、子模块 `source-before/after.sha256` 70 项前后相同；主代理和独立代理逐个与 ecb 提交的 Git raw blob 对照，不能拿工作树换行转换后的摘要冒充原始源码。
- 386 个远端模块/版本在线与离线集合完全相同，原 D4 集合未变，只有两个既有本地 replace；三个模块 go.mod/go.sum 未变。官方在线/离线 `go mod verify` 均为 all modules verified。Windows 不能原样复用 Linux 绝对路径约束检查器；主代理另核语义映射与 Git blob，不修改工件路径或削弱 CI 检查器。
- 父 CI 不上传附件，独立代理下载完整 job log，7751670 字节，SHA256 `40703c1bf24e8ba5cccc5530cca180531fbdd50e9780ee33ef102ba4a8568bc6`；本机路径同级 `chengwang-p0d8-parent-ecb1-independent-05abcea489aa4ac08011d26fe6f6ae38/parent-job.log`。精确 Test pair 和新旧指纹从原始 JSON 事件核实，不只看绿色图标。
- 浏览器报告 SHA256 `c874bae3ca6ee4df84c7081c9b4264c93cfa695ae577e805e2c5fee13aa8ef7c`。
- CI-only 字库来自官方 [notofonts/noto-cjk](https://github.com/notofonts/noto-cjk/tree/f8d157532fbfaeda587e826d4cd5b21a49186f7c)，固定 commit `f8d157532fbfaeda587e826d4cd5b21a49186f7c`，普通体 SHA256 `2c76254f6fc379fddfce0a7e84fb5385bb135d3e399294f6eeb6680d0365b74b`、粗体 `b5f0d1a190a7f9b43c310a8850630af12553df32c4c050543f9059732d9b4c0a`、SIL OFL1.1 原许可 `6a73f9541c2de74158c0e7cf6b0a58ef774f5a780bf191f2d7ec9cc53efe2bf2`；在线仅取固定原始文件并核大小/摘要，离线私有 fontconfig/cache、kernel 只读字体、真实 fc-match/平台字形检查。未 apt 安装全局字体，未给生产镜像加依赖；附件只存 manifest/许可/匹配事实，不存字体本体。

## 失败、修正与再次验收

1. `9ba1e1d` 首轮绑定 [run 39775804055](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39775804055) 失败：Vitest5 默认 module cache 尝试写只读源码 node_modules，1 个 suite 收集失败，另 4 文件 48 项通过；Go/browser/Registry 未执行，未计整体通过。`db1f018` 把 cache 放到 private run root，不改源码只读隔离或减少测试。
2. `db1f018` 的 [绑定 run 39776115304](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39776115304) 和父 run39776115354 虽成功，实际 PNG 人工复核发现中文方框。该轮不计视觉验收。最终 ecb 引入 CI-only 固定 Noto 字体、真实 glyph/截图检查并重跑；不拿 Windows 正常中文截图替代 Linux 故障。
3. 集成中修正 bare64 假摘要 fixture 与真实 `sha256:64hex` 格式差异、过期状态可能回拨复绿、新目录页码残留、隐藏控件误测、CDP selector false-green 与早拒绝不取消 body。新增/强化测试后全量重新运行；旧集合保留不是删场景换绿。
4. Chrome 清理从仅 Node finally 提升为 gated spawn→私有 PID/start/uid/profile 原子交接→exec，独立 pidfd guard 和 shell trap 共同收尾，crashpad 只认规范私有路径。交接是进程崩溃可见，不是 fsync 断电耐久。Supervisor 与主机一起被杀/掉电仍需外部 CI 回收，不宣称内部清理器能处理自身不存在。

本机 Go 缓存问题没有通过放宽时钟、根信任或重新下载运行修补；实际 Go 执行在隔离 Ubuntu。既有官方 Sigstore fixtures、Go 版本边界、依赖和 Registry 来源没有替换。

## 可复验入口

- 本地已有依赖：`npm test -- --run`、`npx tsc -b`、`npm run lint`、`npm run build`（`chengwang/web`）；本地结果仅前端层，不能代替 Linux Go/真实候选门。
- 实际 CI 入口：[image-binding workflow](../../.github/workflows/chengwang-image-binding.yml) 与[父项目 workflow](../../.github/workflows/chengwang-m2b-candidate.yml)。普通/race JSON、完整门禁日志、browser report、fixture 清理、4 张 PNG 共同组成证据；不单独运行未隔离的测试脚本冒充同等验收。
- 完整真实浏览器使用 `web/scripts/verify-trust-browser.mjs` 与 `tools/image-binding/scripts/run-browser-gate.sh`；私有配置、Store、Audit、fixture 与字体由隔离门创建/收尾，不在文档写生产令牌。

## 实际未完成与后续门

1. 原产品 `cmd/server` 的真实 image-trust backend 装配、企业 IdP/SSO/MFA/多租户身份运维、完整审批及写操作 UI 未完成。现有导航入口不等于原主服务已具备真实 backend。
2. 浏览器 HTTPS、生产证书与真实企业浏览器/设备兼容矩阵未验收；当前仅指定桌面/移动 Chrome 与本机初始页面，不声称 Safari/Firefox/所有终端通过。
3. 未构建/发布正式签名产品镜像，未做生产灰度、读回、长时间 soak、回滚演练或生产凭据/信任发放；实际 E2E 调用真实候选 run()，不是已安装 release binary。
4. 自动刷新不是完整 TUF 或发布方未知撤销的即时发现；固定源故障、过期中间代和时效到期会失败关闭。健康两库间补审计不是修坏盘/坏 checkpoint、恢复 grant 或保证 HTTP exactly-once。P0-d7 的真实断点/撤销测试继续保留，完整边界见 [P0-d7 验收](P0D7-REFRESH-RECOVERY-ACCEPTANCE.md)。
5. 历史遍历与审计有保留预算；超大历史压力/长期容量自动治理、独立 WORM/副本/外部单调见证、整盘回滚防护、分布式租约/HA 未完成。pidfd guard 真进程测试不等于实际 Chrome 任意时刻 SIGKILL、物理断电或恶意进程隔离验收。
6. 九项恢复 blocker 全部保留；所有结果 advisory、`authorization=BLOCKED`、`deviceActionsExecuted=false`。M2b/M3/M4 与整个企业系统正式运营尚未完成，不能从测试数量推算总完成率、无 bug、免维护或任何高可用率。

本阶段未访问或修改 10.88.0.240/.249/.254、爱快、DNS、OpenClash、Kuma、ERP 或生产 Docker；未合并 main。下一阶段应先完成明确的候选 HTTPS/真实主入口装配合同和隔离验收，再另行申请生产范围；本记录本身不是执行许可。
