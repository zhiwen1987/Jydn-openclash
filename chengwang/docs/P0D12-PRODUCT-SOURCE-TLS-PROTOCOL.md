# D12 真实产品来源 TLS 拒绝与同进程恢复协议

状态：代码 `b8abe163fdd40f0dffe327c97989cf6f858fb762` 已完成本批六格真实镜像隔离验收，主代理及三名独立子代理原工件复算通过。见[实际证据与未完成项](P0D12-PRODUCT-SOURCE-TLS-ACCEPTANCE.md)。此前[第一批来源验收](P0D12-PRODUCT-SOURCE-WAVE1-ACCEPTANCE.md)与本批分别保留证明边界。只使用隔离 CI 的临时来源、临时 CA、临时签名 authority 和真实候选镜像；不访问生产设备、不合并 main、不发布正式镜像。根代理为单一集成者。

## 目标与明确不证明的内容

每种签名格式（message-signature、dsse）运行 CA、SAN、SPKI 三种单因故障，共六格。每格有独立产品容器、信任库、审计库、身份、grant 和目录签名 authority。产品从启动到恢复使用同一容器、实际 PID/startTime、默认入口、二进制、只读配置、独立可信 CA 和固定 SPKI；修复来源，不修改产品信任规则，也不重启产品。

本批仅覆盖“首次刷新遇到错误证书→拒绝→更正来源→同进程恢复”。它不证明已确认后的 TLS 故障与自然陈旧、证书在线轮换、来源完整异常矩阵、真实网络超时、在途撤销、消费后屏障、长时间 soak、企业系统已完成或生产已上线。

## 单因证书矩阵

| 场景 | 故障来源证书 | 与正常证书必须相同 | 独立复核 |
| --- | --- | --- | --- |
| CA | 由另一个不受产品信任的 CA 签发 | 公钥、正确的 `feed.fixture.invalid` SAN | 原始证书/两个 CA 的链验证、SAN、SPKI 摘要 |
| SAN | 仅使用 `wrong.fixture.invalid` SAN | 受信签发 CA、公钥 | 受信链成立、正确域名拒绝、错误域名验证成立、SPKI 相同 |
| SPKI | 换用另一把公钥 | 受信签发 CA、正确的 feed SAN | 受信链和域名成立、原始 SPKI 与产品配置 pin 不同 |

产品真实 `refresh/client.go` 先进行正常 CA/主机名验证，再在 `VerifyConnection` 比较固定 SPKI；不关闭证书验证、不修改系统时钟、不通过跳过校验制造通过。证书由独立 checker 对公开原始 PEM/DER 做 OpenSSL 固定参数复算；不能把来源自报的布尔值或 stderr 文本当成证书归因。

## 每格必须闭合的顺序

1. 准备相同候选镜像的原始 manifest/config/layer 并通过真实 Distribution Registry 正常 TLS 上传及逐字节读回。创建 G1 信任库，记录初始逻辑记录、空审计日志和 checkpoint 的原字节摘要。准备故障、正常两个来源 phase，分别提供同一个有效签名 G1。
2. 启动故障来源。就绪只检查原子 ready 文件、实际源进程身份、代码/证书绑定、网络命名空间和限制；不得主动 TCP/TLS/HTTP 探测来源。所有来源连接因此只能由实际产品产生。
3. 启动真实默认产品 PID1。正常校验产品 API 的独立 TLS 身份；固定 CA、SPKI、URL、刷新间隔/有效期/超时不变。
4. 实际观察至少两条已经关闭、非 stopping/timeout 的故障来源 TLS 尝试，且该 phase HTTP 事件为零；之后经认证 API 读回产品仍健康、G1/sequence 1、history/journal/audit/ledger 零、`RefreshFresh=false` 且 LastSuccess/Until 为零。来源事件原字节前缀摘要必须覆盖这些尝试。
5. 对故障来源精确 SIGTERM 并完整 join，原始日志和 ready 保留不覆盖。再以同端口 5444 启动正常来源，使用不同私有目录、进程、ready 和事件日志。停源或切换间隙不能被计入 TLS 拒绝正证。
6. 不重启产品。先实际看到正常来源完整发出原 G1 的 200 响应，再经认证 API 读回同 G1/sequence 1/空历史且刷新 Fresh、LastSuccess/Until 正确。前后产品实际容器/PID/startTime、二进制和配置摘要必须相同。
7. 正常 SIGTERM 产品并验证 exit 0/no OOM。离线重开真实 Store 和 Audit，仅通过只读核验接口读取；逻辑信任记录、原审计日志和 checkpoint 与初始摘要相同。无 SDK 验证、无 grant 预留/消费、无目录 PUT 或人工确认刷新。
8. 正常停止并 join 正常来源。核实准备窗口的精确 Registry 上传/读回预算，以及所有实际运行/离线读取窗口零 Registry 请求。最后验证六个产品、十二个来源、一个 Registry 的实际退出和精确清理，保留外层候选镜像及原归档。

不能把源端 TLS `ok`/`failed` 枚举直接解释为 CA/SAN/SPKI 的准确原因；特别是客户端拒绝 SPKI 时，服务端 TLS 可能已经完成。拒绝成立依赖单因证书原证据、真实产品配置绑定、故障期真实尝试且无 HTTP、API 未确认和恢复后的实际业务状态。这里不声称捕获了产品自己的 PeerCertificates 数组。

## 接口与证据边界

- 新 Go driver 仅通过 `productregistry,productlifecycle,productsource,productsourcetls` 四个显式 tag 编译为 `product-source-tls.test`，入口为 `TestProductSourceTLSD12Fixture`。不进入普通/race 728 名字集合，不替换旧来源入口。
- `CHENGWANG_D12_TLS_{ROOT,FAULT,KIND,ACTION,COMMIT,IMAGE_ID,ARCHIVE}` 为闭集参数；fault 只有 `ca|san|spki`，action 只有 `prepare|reject|recover|reopen`。
- 产品私有路径 `/tmp/chengwang-product-lifecycle-<32hex>/refresh/tls-<fault>/<kind>`；来源 case 为 `source-tls-<fault>-bad` 与 `source-tls-<fault>-good`。只有新 `product-source-tls` inspect profile 可以接受六个新路径；旧 profile 不扩大权限，所有容器硬化约束不变，不能使用 crash/startup-rejected 例外。
- 外层工件统一 `product-tls-*`，与旧 `product-source-*` 闭集分离。公开 PEM、G1 目录、计划、来源事件、API 和真实持久投影是评审输入；不得导出私钥、token、bundle、数据库、私有 graph 或原私有错误日志。
- 新 driver DTO 为 `chengwang.product-source-tls-driver/v1`，恰含 `schema,sourceCommit,localImageID,fault,kind,action,authorization,production,deviceActionsExecuted,material,observations,offline`。material 包含原 `sourceMaterial`、原始公共证书、bad/good 原计划，以及初始持久原字节摘要。
- prepare/reopen 无运行观察；reject/recover 各一个实际观察，带 phase 和原始事件前缀 fence。offline 只允许在正常停止后的 reopen 中出现。私有兼容 adapter 只用于复用既有离线读取函数，不得导出或冒充旧第一批运行证据。
- 独立 checker 要重算证书、目录/approval 签名、来源完整事件链、实际 API 时序、镜像/进程/配置身份、真实离线状态、原字节摘要和精确清理。具名合成反例测试仅证明 checker 拒绝能力，不得计为真实镜像业务验收。

## 回归与验收

所有既有镜像门、来源 fixture 前置门与第一批门保留。CI 必须绑定本批实际提交、镜像和未改写原 ZIP/API 日志；普通/race 名字集合、父项目测试、源码前后清单及 Git raw blob 必须独立复算。失败保持可追溯，不用重写失败工件、改基线、放宽 TLS 或跳过测试换取绿色。只有取得对应实际证据后才把本协议状态改为本批已验收；任何本批通过都不等于完整系统、生产发布或可用率保证。
