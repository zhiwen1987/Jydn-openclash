# P2-06 后续：真实订阅 UI 双浏览器验收计划

状态：**下一阶段待实现、待实际运行的验收契约**，不是浏览器通过记录。本文件只规定后续实施与退出条件，不授予生产、宿主网络、浏览器安装或本机实验权限。当前订阅页面、client 和 access 元数据的源码/合成测试不因本计划升级为真实浏览器证据。

验收目标是在各自独立的隔离 fixture 中，用 Chrome/CDP 和固定版本 Playwright 分别操作同一份真实编译 Web 页面，通过正常 TLS 访问真正的独立 `cmd/server`，核对权限、来源隔离、本地准入、回执与恢复。两条 engine 都须独立通过，不能互相补证。

边界保持 `LOCAL_SUBSCRIPTION_ADMISSION_ONLY`、`authorization=BLOCKED`、`production=false`、`deviceActionsExecuted=false`。本地接纳不是节点健康、设备发布、系统回滚或公网订阅可用性。

## 1. 已有事实与不可借用的证据

| 已有实现或证据 | 本计划允许复用的部分 | 不允许据此声称 |
| --- | --- | --- |
| [独立订阅产品实验](P2-SUBSCRIPTION-PRODUCT-ACCEPTANCE.md) | 私有身份、API/resolver/source 分离 CA、正常 API/DoT/来源链路、真实服务进程、Store/evidence、fixture 及安全采集方法 | 已操作订阅 UI；其固定 46 captures/4 epochs/20 文件包含新 UI 行为 |
| [原探针双浏览器](P1-PROBE-BROWSER-ACCEPTANCE.md) | 已验工具链、CDP/PW 真实启动机制、独立 NSS、实际进程与退出观测、构建绑定方法 | 探针截图就是订阅截图；探针 3 targets/15 layers/6 samples 或自然 TTL 撤回适用于订阅 |
| 当前 `Subscriptions.tsx`、`subscription-api.ts`、access API | 后续真实运行的产品实现和源码绑定输入 | jsdom、mock fetch 或纯 Node 合成测试就是浏览器/正常 TLS/实际网络证据 |
| [订阅应用 API](P2-SUBSCRIPTION-API.md) | 服务端鉴权、写门、CAS、批准、幂等和审计合同 | 浏览器按钮元数据替代服务端权限或目录引用已经批准 |

原订阅 46 步与原 20 文件 verifier、原探针 backend22 和原浏览器 gate 保留独立回归。新 UI 写操作会改变 command、approval、local audit 与外部 audit 数量，**不得把额外动作塞入原实验后仍套用旧精确计数**，不得扩大旧 allowlist 或伪造旧 outcome 以通过。

## 2. 从真实接口得出的复用约束

1. `tools/probe-browser/browser-driver.mjs` 不是通用浏览器驱动接口：`launchProbeDriver` 固定 probe root/harness 配对，origin 为 `https://127.0.0.1:17861`；`safeRequest` 只允许固定 GET 路径；`fill` 只允许 `#probe-token`；`collectProbeDOM` 与 `NetworkJournal` 绑定探针。订阅实验实际 API 为 `https://127.0.0.1:17871`，存在合法 POST、鉴权错误和 CAS/写门拒绝，不能直接追加到旧探针闭集。
2. `exerciseProbeBrowser` 固定 fresh/cleared/withdrawn/expired、3 个目标、15 层与样本时效。订阅资源的新鲜性按来源 revision、分页 revision、权限和读取失败后的 stale 状态判定；**不得把页面缓存期限称为证据 TTL，或套用探针自然过期证明**。
3. `probe_chrome_launcher.py` 固定原配置 schema、根目录配对、profile、真实 wait 记录；`run_probe_browser.py` 继承探针 `Lab` 的采集时序。新订阅 runner 不得通过改全局常量、monkeypatch、换文件名或伪造原配置来复用它们。
4. `web/scripts/trust-browser-tls.mjs:inspectPublicTLS` 明确要求测试 CA/leaf 尚有效且到期不晚于当前时刻加 24 小时；现订阅后端 fixture 生成 `-days 2` 证书。新浏览器 fixture 须生成满足原限制的独立短期证书，不能直接接两天证书后放宽原 TLS 门。离线复核仍按实际捕获时刻 `-attime` 验证，禁系统 CA 回落。
5. 独立 CI 工具包仍用已有 `tools/probe-browser/package-lock.json` 中的固定工具链；不改产品 Web lock，不为订阅复制另一套依赖。下载、构建和真正执行只能由另行授权的隔离 CI 承担。
6. 正常主服务已有 `CHENGWANG_WEB_DIR`/`webui.New` 接线，可从同一正常 TLS origin 提供编译 dist 和真实 `/api/`；不得改为 Vite dev server、fake API、`RunWith`、`httptest` 或注入 dial 来冒充本阶段。

建议最小文件切分为：闭集共享浏览器底座、订阅专用 contract/flow/CLI、订阅浏览器 runner、独立 checker/反例测试以及独立 CI 接线。共享底座仅抽出实际启动、NSS、TLS、CDP/PW、进程 wait、PNG/构建保管等中性机制；旧 probe wrapper 的签名、profile 和闭集原样保持。新订阅 wrapper 必须采用独立固定 profile，不允许任意 origin/路由/选择器回调绕过安全策略。具体文件名、DTO、精确输入集合与测试名单须在实施前冻结，本计划不伪称这些新接口已存在。

## 3. 每个 engine 的隔离与启动条件

- 每条 engine 使用独立 UUID 私有根、空初始库存、独立身份 tokens、NSS/profile、cmd/server 与 wire 进程；不可跨 engine 使用来源 ID、命令 ID、截图或报告。
- Linux 私有 network/mount/PID namespace；仅 lo 和 namespace 内的 `8.8.4.4/32`，无 IPv4/IPv6 默认路由。UID/GID 10001、补充组为空、全部 capabilities 为零、NNP=1。只有编排层可执行经批准的 mount/setpriv；非 root 产品/浏览器不获得额外权限。
- API、resolver 与 source CA 分离；CA 私钥、服务私钥、身份文件、source URL/token、订阅原文仅留在本 UUID 的 0700/0600 私有目录。浏览器仅信任实际 API CA，DoT/source 不借用浏览器或宿主根证书。
- Chrome 分发、Node、PW、Git 源码、字体、dist 原字节经有界复制、SHA 和权限检查后只读提供；完整 dist 包含 `index.html`、`trust.html`、`assets/` 和 `.vite/manifest.json`。仅要求实际页面引用的主入口及实际请求 assets 发生匹配，不假称浏览过全部入口。
- Chrome 使用现有 CI-only 外层隔离模型；`--no-sandbox` 不称为 Chrome 自身 sandbox。禁所有证书绕过 flag、`ignoreHTTPSErrors`、关闭 CSP、请求 mock、route fulfill、注入 fetch、storageState、trace、HAR 与原始 console/异常导出。
- Node/Chrome 不继承宿主 HOME、代理、SSL 或私有产品环境；NSS 采用私有 XDG 目录并确认旧 `.pki/nssdb` 不存在。短 `/var/tmp` 只在浏览器私有 mount namespace 中挂载 tmpfs，不改宿主目录。
- `cmd/server` 提供真实正常 TLS API 和已编译 dist，订阅默认/写门按该实验显式配置。宿主 namespace、端口 sysctl、系统 CA 和源码 before/after 分别观测；只能据所采字段声称相同，不扩大为全宿主不变证明。

## 4. 产品页面和选择器约束

真实入口是 App 主导航中可访问名称精确为“订阅与提供者”的按钮，随后可见 `.subscriptions` / `section[aria-label="订阅资源工作区"]` 及标题“订阅资源”。不得以探针 `.probe-readback`、旧截图或只显示导航文字代验。

| 操作区域 | 当前真实定位 | 自动化要求 |
| --- | --- | --- |
| 会话 | `#subscription-token`；“连接订阅会话”“清除会话与令牌” | 密码输入，连接后输入值清空；不得读取并导出 token 值 |
| 来源 | `#subscription-source-label`、`.subscription-source-list` | 以实际 API source ID 绑定可见来源；不以列表顺序推断身份 |
| 导入 | `#subscription-format`、`#subscription-file` | 真实浏览器文件输入；私有文件名、原文与 credentials 不进入截图/公开 DOM；准备后输入清空 |
| 目录 | `#subscription-reference`、`#subscription-handoff` | 只取真实 access refs；交接 ID 仅语法提示，不称客户端已验证批准 |
| 候选/节点 | `.subscription-candidate-list`、`.subscription-nodes`；“候选分页”“节点分页” | 按 source/candidate ID、revision 及实际 API 页绑定，不按固定第几个元素假定目标 |
| 确认 | `.subscription-confirmation[role="alertdialog"]`；“确认并提交本地操作”“取消本次操作” | 必须真实点击确认；回退另需明确勾选，不能程序直接调用 React handler |
| 回执 | `#subscription-command`、“读取命令回执” | 实际 GET 回执，不通过重发 mutation 模拟查询 |

控件名称/ID 变化须先更新冻结契约及合成反例，不能加宽到任意 CSS 选择器。通用交互只能经真实 DOM、PW/CDP 输入事件、原生 select/file input；禁向 React 状态写入伪造结果。截图前必须核对可见区域、viewport、目标控件唯一且无遮挡；等待使用实际响应/状态条件和总 deadline，不用固定 sleep/轮询次数冒充完成。

App 当前采取隐藏挂载保留订阅内存会话：离开导航并不等于 unmount。验收须分别检查“切导航再返回”的会话/未决状态保持、显式清会话清理，以及真正 unmount/重载的请求清理；不得把 `hidden` 当作 token 已销毁。

## 5. 必须逐项完成的真实浏览器清单

以下编号是实施前的验收项，不是已运行次数、最终 capture 数或 Go/Node 测试名。实施时须将其拆成固定 step/预期状态/所需角色，并提前冻结精确名单。每个 engine 独立记录通过、失败或未覆盖，不能把未能安全构造的项填成 PASS。

### 会话、资源权限与目录

- B01：首次加载及未连接时不发订阅 Bearer 请求/写请求，无演示订阅库存。正常 API/UI 不依赖 legacy AdminToken。
- B02：Viewer/Auditor 真实读取已授权库存、安全节点/目录；写按钮按实际 collection/source metadata 禁用。Operator、Approver 的七项动作逐资源精确展示；collection manage 只能用于创建，不能代 source import/approve/fetch/decide/rollback。
- B03：匿名/错误 token/foreign scope/其他 source grant 的实际后端拒绝保持；按钮隐藏不是服务端 401/403 的替代证据。若拒绝由可信 Python API 采样器而非 UI 动作取得，必须单独标来源，不能说浏览器发出了该请求。
- B04：目录 ready 只列有效、安全 referenceId/revision；not_configured/unavailable 不显示虚构引用或 URL，不能把配置就绪说成来源健康。手工导入权限与目录可列举性分开。
- B05：修改身份、切 scope、切 source、清会话时旧权限、候选、批准、文件原文与确认意图按产品合同失效；迟到请求不复活旧会话。登录后密码框为空，存储/cookie 无 token，未输入新身份时不自动读取订阅。

### 实际写入、本地准入与角色交接

- B06：Operator 创建两条独立来源；准备和取消均无业务 POST。显式确认仅一个实际 mutation 请求，回执中的 sourceId/revision 与页面刷新一致；不能用“已准备”显示成功。
- B07：真实私有订阅文件经浏览器 file input 读取、确认后导入，进入 quarantined；原文/私有名字不展示，安全 NodeView 仍 unknown。相同内容重复、rename/reorder 或错误格式仅按真实 backend 合同判定，不由 UI 自算权威 ID。
- B08：Approver 在实际来源和 revision 批准真实目录 reference；批准返回后同 source/revision 的必要刷新不能无故清掉仍有效的批准。改变 source/revision/reference 必须撤销不匹配的旧批准，不能界面选新 reference 而实际 fetch 仍使用旧 reference 的批准。
- B09：独立 Approver → Operator 的批准交接必须实际执行。Operator 可输入安全 command ID 并由服务端核验批准/source/policy/CAS；**不放宽 ReadReceipt owner 规则**，不能假设 Operator 能读取别人的完整批准回执。无效/过期/错误 source 或 revision 的交接仍由真实服务拒绝，库存及 wire 按冻结预期不变。
- B10：抓取实际经过正常 DoT/HTTPS/source fixture；拿到候选不自动接纳。Approver 显式决定 admitted_local/rejected；只有真实成功回执和随后一致来源读回可显示已提交，节点保持未评估、设备发布锁定。
- B11：回退选择真实已接纳历史候选，以当前 source revision 做 CAS，额外勾选后提交；产生新单调本地 revision。不把本地指针回退称为设备回滚，不用旧 candidate.BaseRevision 代当前 CAS。
- B12：两来源即使导入相同私有内容也保持来源隔离/不同节点 ID 集合；选择另一来源不混入旧来源页、节点、批准或确认，所有写只影响明确目标。

### 未决命令、分页、失败与恢复

- B13：提交等待、超时、审计降级或 commit_unknown 不显示成功，不自动重试 mutation。只有可验证 command ID 才能发起只读查询；读取无关历史成功回执不能解除另一条未决写锁。无 ID 时明确需要对账，不能建议新 key 等价重写。
- B14：若要声称真实浏览器覆盖 unknown/审计降级，须先冻结无产品 fault hook、无 mock 响应的安全故障构造及其外部证据；构造尚未实现时保留为未覆盖。jsdom 的 unknown 反例、正常网络 503 或单纯中止浏览器请求不能充作实际 commit_unknown。
- B15：候选/节点分页须有足以跨实际 PAGE_SIZE=20 的独立 fixture 数据，验证首/次/返页的 ID 集合、offset/revision/no duplicates。两条节点或一条候选不能证明真实翻页。并发来源 revision 变化造成真实 409 时清旧页/暂停写，不能拼接不同代次。
- B16：来源读取或分页失败保留 LKV 时明确 stale 并禁止依赖旧数据的写入；scope/shape 不匹配须清相应私有视图，不能保留“已确认当前”的旧权限。恢复后须真实重新读取，不以定时器到点或配置 true 复绿。
- B17：真实坏 YAML/来源拒绝/CA/SAN/超限响应按服务合同拒绝并保持最后有效候选；正常 backend fixture 证据与 UI 错误/旧数据展示都要绑定。TLS server-side enum 不能当准确客户端拒绝原因，oversize 成功 send 返回计数不能称完整物理传输量。
- B18：先正常 TERM/wait=0/join 服务，再启动同库新的真实 `cmd/server`。重新连接后库存、admitted pointer、旧 immutable command receipt 正确；历史查询不能重做 fetch/import，重放与 noop 只能按实际服务语义计数。
- B19：独立进程关闭订阅写门后，metadata writesEnabled 为服务与 API 两层 gate 的交集，角色 actions 不伪变为无权限；实际 mutation 423，库存/wire 不变，已有读取仍可用。
- B20：切导航保留必要未决上下文且没有隐藏自动 mutation；显式清会话/真正卸载中止旧等待、释放私有文件/意图，不宣称撤销已到达服务端的动作。不得在浏览器重载后声称拥有未持久化的客户端未决保护。

### 布局、安全出口与结束

- B21：实际订阅页面在 1440 桌面与 375 移动 viewport 可见、非空、无横向溢出/阻挡控件；来源/候选/节点/回执及确认/错误区域具有真实可访问名称，移动主导航仍能打开此页。截图采集位置和滚动位置明确。
- B22：清会话后公开 DOM 不含旧来源/候选/节点/回执/token；密码框值、file input 值、浏览器存储、cookies 仅输出安全空/非空断言，不导出内容。浏览器截图不能替代原始 public JSON 及进程/网络/权限验证。
- B23：正常关闭前排空实际请求；Chrome、Node、所有 cmd/server/wire 正常 wait=0、join、无 live owned process、无强制信号介入，私有 fixture/profile/NSS/bundle 清理成功。失败 emergency 清理不能升级 normal pass。

## 6. 新工件、因果绑定和独立 verifier 要求

新公开 namespace 使用独立的订阅 browser schema/prefix，不能修改旧 probe capture schema 或旧订阅 PUBLIC_FILES。实施前须固定完整文件闭集、大小/数量预算、精确单测名单及报告路径；报告必须在证据树外 O_EXCL 创建，禁止覆盖原始输入。

最小证据类别必须包括：

1. 每个 engine 的精确 Git sourceCommit、attempt/job、构建输入/output manifest、源码 before/after 原字节 SHA；新 checker/runner/flow/contract/shared helper 及工具原 bytes 与同一 Git blob 绑定。原 dist/实际 served assets 逐字节 SHA 对应，含隐藏 `.vite/manifest.json`，不称独立可复现构建或 Chrome 供应链公证。
2. 原始公开 API response bytes、长度、SHA 和 actual decoded-body scope；network 完成序号、请求 method/闭集 path、status、授权是否存在、接收时刻；所有 mutation 的 source/candidate/revision、闭集 requestPublic、commandIdHeader、immutable receipt 绑定。绝不导出 Authorization、完整 request headers、token、source URL、policy Material、私有导入 body 或其 contentBase64。
3. 独立安全 DOM 投影与 PNG 原字节/时间/viewport/SHA；显示的 source/candidate/node/receipt ID 与其实际 API 页、source revision 一一对应。不取 React 内部状态，不凭截图 OCR 生成业务事实。PNG 校验与人工看图范围分别说明。
4. 实际 CA/leaf 原始公有证书与浏览器 CDP 得到的 DER chain，正常 TLS security details、叶子/CA 摘要、IP SAN、捕获时间验证；不拿 `tlsBypass=false` 单一布尔、配置文件或来源 helper 的 tls enum 作链路证明。
5. 真实 Node/Chrome/cmd-server/wire PID、startticks、原 argv/executable 的安全 SHA、UID/GID/caps/NNP/ns、只读 mount 与精确 wait/normal close；Chrome argv 与真实 profile/分发 SHA 绑定，不暴露凭据。close API 成功不是 wait=0 的替代。
6. source fixture 原 ready/events/stopped 完整日志、实际 prefix fences；外部 audit 原事件/CP 按真实顺序重算 hash-chain，并按 operation ID 与服务 metadata 绑定，**不假设 prepared/result 必相邻**。私有 Store 只提供经允许字段的安全 projection，仍注明可信 runner 投影，不称私库原字节独立验证。
7. 所有 tokens、source tokens/URL、私有节点名字/密码及编码变体作为私有 canary。原始 response bytes 在 base64 前扫描，再扫描全部最终公开文本；截图前检查可见文本和私有输入清空，扫描不能声称证明任意图像隐写都不存在。

完成 ordinal 只证明响应完成/日志落盘顺序，不是请求开始或按钮因果。UI 并行读取 overview/access 或 candidate/access 时可不同完成顺序；验证基于资源/revision/完整 DTO，不硬排并行完成顺序。毫秒来源的时刻按其实际区间解释，不声称纳秒精度。

合法业务 401/403/409/423/503 应按冻结 case 单独核验，不能全部要求 HTTP 200，也不能因为是预期业务拒绝就吞掉 transport/CSP/console/asset/捕获错误。共享浏览器八类错误计数保持逐类闭合；意外中止/重复请求/未知路由仍失败，不修改旧 probe failedRequests 规则。

## 7. 退出条件与明确未完成

只有两条 engine 的原始工件经精确同 Git checker 在新鲜 Linux 环境完整重放，并与 producer canonical 报告逐字相等，且旧订阅产品/探针原生/原探针双浏览器/父门和镜像基线未削弱，才能记录新订阅浏览器已通过。CI green、合成测试、截图存在、driver 自报 runtime=true 或运行完成 marker 均不足。

实施前另行冻结各实验 step/预期状态、dataset、故障方法、公开 DTO/文件集合、普通/反例 exact tests 与总时间预算。未实现项列为待实现或 blocked；任何一条 engine 或硬条件失败保留原失败 ZIP/log/安全诊断，不取消/重跑旧 handle 取代失败，不先把本计划写成验收记录。

本阶段不包含生产授权、真实用户订阅下载、公网能力、设备发布/节点探测、企业 SSO/WORM、永久证据归档、全提供者兼容、长时间/容量/断电恢复。不得改变宿主信任、时钟、网络或现有执行器来通过测试。最终进度仍按[项目台账](PROJECT-PROGRESS-LEDGER.md)分层报告，不给整系统虚构完成百分比。
