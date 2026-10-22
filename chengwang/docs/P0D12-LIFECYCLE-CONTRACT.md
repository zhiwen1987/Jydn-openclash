# P0-d12 自动刷新与跨库恢复：分层验收合同

本阶段沿用“先不要动生产环境”。所有构建和实验只在开发分支与一次性 CI 中执行；不 SSH、不操作任何生产路由器/服务，不合并 main，不向正式 Registry 发布镜像。

## 1. 当前交付边界

D11 的真实镜像/Registry/签名/批准/消费/重放验收继续保留，其后台刷新未启用，撤销通过管理员手动 PUT。因此不能把 D11 写成已完成实际镜像的自动撤销刷新。

D12 先验证两个必要的外部测试机制，再接真实镜像。前置门即使通过，仍不代表自动刷新或真实产品进程故障矩阵已经通过。

当前前置门已由代码605f67e在真实隔离Linux CI验收，见[实际结果与失败记录](P0D12-FIXTURE-PREFLIGHT-ACCEPTANCE.md)。正常自动刷新/重启子门另由957271a验收；三个真实verify中断边界由89dfade隔离验收，见[中断验收与剩余项](P0D12-INTERRUPTION-ACCEPTANCE.md)和[实施协议](P0D12-INTERRUPTION-PROTOCOL.md)。0633c4b另验[预置健康/拒绝启动矩阵](P0D12-STATE-MATRIX-ACCEPTANCE.md)，不是更多真实crash。来源负矩阵及其他真实边界仍未验。

ed756d7进一步修复同一坏候选重复自动刷新耗尽journal的问题：[拒绝保护验收](P0D12-REFRESH-REJECTION-ACCEPTANCE.md)。新增28项（完整ordinary/race各728，保留原700），其中4项为同进程正常TLS runtime来源/追代集成；原全部真实镜像门重新通过，但不等于新增完整镜像来源负矩阵已验。

57fd54c另验[异常HTTPS来源fixture前置](P0D12-SOURCE-FIXTURE-ACCEPTANCE.md)：真实24项/32项合成checker、34观测段/19wire及原全部镜像回归通过。它只补测试工具，完整产品来源矩阵仍未接入；0.75s stall不能证明产品整数秒timeout，runner自身readiness probe必须与产品连接窗口分离，详见该验收剩余项。

| 层 | 本层能证明 | 不能据此宣称 |
| --- | --- | --- |
| 独立 fixture 前置门 | 真实 Linux 跨进程文件租约阻塞/解除；低权限正常 TLS 固定源站与安全访问记录 | 产品镜像已使用这些机制、已自动刷新/恢复 |
| 真实镜像自动刷新正常子门（已隔离验收） | 实际默认程序自行 Fetch→Apply→Confirm；自动 actor 与两库/来源日志关联 | 手工 PUT 或直接 ConfirmRefresh 等于自动刷新；正常子集等于全部异常来源矩阵 |
| 真实 API 中断恢复三阶段子门（已隔离验收） | PREPARED/RESERVED/CONSUMED实际在途verify被外部阻塞后终止，重启补审计、保留已烧毁批准、再次重启幂等 | 所有六个内部边界均被真实镜像命中、自动刷新崩溃组合已验、坏盘/断电自修 |
| 预置中间态恢复/拒绝门（已隔离验收） | 真实 constructor 对三lane/六健康/八拒绝/两签名的84格明确预置状态启动与二启 | 预置状态等于真实 API 崩溃或物理故障 |

## 2. 前置门实施与验收

入口：`tools/image-binding/scripts/run-linux-ci.sh` 在既有私有 mount/net namespace 中运行独立 fixture runner，然后原样进入原非 root offline gate。

- source、依赖缓存为只读；namespace 只有 loopback、没有默认路由；不获取新依赖。
- root 仅为可信测试 orchestrator，用于建立严格 UUID 测试目录、设置 owner/mode、启动/回收指定子进程；它不是产品权限模型，也不宣称宿主 Unix sockets 已隐藏。
- 被测 lease/feed helper 必须实际运行于 UID/GID `10001`、所有 capability 集为空、`NoNewPrivs=1`；helper 自检失败立即拒绝。
- 每套真实 Linux 测试有 180 秒总截止时间，缺内核能力/权限/工具必须失败，不得 skip 或回退为模拟。Windows 仅 shape 辅助测试，明确跳过 Linux 部分，不能生成前置 PASS。
- 前置门另建子 mount namespace，将本轮专用 native `/tmp` backing tree 挂为 `/tmp`；超时后的清理不枚举或删除宿主 `/tmp`。本 CI 的 source/run root 必须位于 `/tmp` 之外，避免被遮蔽。仅清理事先核对的专用 UUID 子目录；未知对象应失败而不是扩大删除范围。清理成功和退出0共同满足后才可生成最终 PASS。
- 独立 checker 从本次 Git 原 bytes 提取完整具名测试集合，核对每一项 `ok`、唯一 summary 和严格 marker；缺项、重命名、重复、skip、辅助 marker、任意额外输出均拒绝。
- 发布安全 test transcript 和 `product-lifecycle-preflight.json`；源文件摘要必须与当前 commit 原 bytes 一致。报告明确 `actualProductLifecycleProven=false`、`productAutomaticRefreshProven=false`、`productImageFaultInjectionProven=false`。
- D10/D11 原门、49 份关联集合及普通/race 的 700/父 2320 集合不修改、不缩减、不合并计数。

### 外部审计写屏障

`fixture_lease.py` 仅读取指定 `events.jsonl` 并持有 Linux read lease；不改日志、checkpoint、数据库或权限，不向产品发送信号。测试实际检查：读打开成功、写打开阻塞、显式 release 后写打开成功、TERM/deadline 失败解除，以及 SIGKILL holder 后内核释放；文件原 bytes 保持不变。拒绝错误 owner/gid/mode、symlink、hardlink、FIFO、替换 inode、过期 control 和不合法路径。

只读取 `/proc/sys/fs/lease-break-time`，不改 sysctl；自身 deadline 必须先于内核强制解除。`BLOCKED` 表示观察到 SIGIO，**不能单凭这个 JSON 证明指定产品正阻塞**；后续必须同时绑定实际操作/持久状态和独立进程观察。

产品接线必须先确认产品 ready，再安装租约；否则会阻塞 `evidence.Open` 自身的写打开，而不是目标操作阶段。租约的内核语义见 [Linux file leases](https://man7.org/linux/man-pages/man2/F_GETLEASE.2const.html)。

### 独立 TLS feed

`fixture_feed.py` 只在 loopback 提供固定 `/feed/latest.json` 和 canonical 正整数代文件；无 HTTP 控制路由。私有原子 plan 绑定单调 epoch 和原始 plan bytes，200 body 按内容摘要读取；一次响应模式在并发下至多提供一次。回退、同 epoch 分叉、坏 plan、错误摘要、非法方法/路径/Authorization 均失败关闭。

日志只保存固定 schema、ordinal/epoch、固定路径类别/代、状态、实际响应 body 摘要、字节和发送完成状态、TLS/Authorization 布尔及错误枚举，不回显任意 URL/header/body/证书私钥。正常 CA/SAN 客户端和错误信任/SAN 反证属于独立 fixture 的能力；产品 SPKI 拒绝必须另由真实产品门证明。

其中 `sentComplete=false` 时摘要仅绑定拟发送的表示，`bytes=0` 是“未确认完整发送”的哨兵，不证明对端实际收到零字节，也不假定已知部分发送量。已完成事件才可按完整 body bytes 关联。

## 3. 真实镜像完整矩阵与剩余项

下述自动刷新中的正常来源、精确同代、自动撤销、自然陈旧/恢复及正常重启子集已由957271a真实镜像子门验收，见[实际结果与未完成项](P0D12-PRODUCT-LIFECYCLE-ACCEPTANCE.md)。89dfade另接受静态catalogue下三个verify中断边界；0633c4b另验84格预置状态启动/拒绝门。追代、来源负矩阵、在途竞态和其他实际异常边界仍未完成，不能把本节整个清单视为已验。

自动刷新：未确认来源拒绝且不消费；顺序追赶；精确同代 no-op；自动撤销；回滚/同代分叉/缺代拒绝；坏签与过期候选拒绝；断源自然变陈旧；恢复来源后重新确认；同容器重启丢弃内存 freshness 但保留烧毁记录；在途刷新停机取消并 join。来源正常 TLS/固定 IP/CA/SPKI 及真实 Registry 流量分别独立观察，不硬编码带抖动的轮询总次数。

区分 Fetch 拒绝与 Apply 拒绝：前者不产生更新操作，后者可能合法增加 REJECTED journal/audit；不能用“一切计数不变”掩盖真实执行。当前实际 interval 下限 1 秒；每进程每分钟 4 次是 verify 启动预算，不是刷新间隔。不得放宽产品限制或修改系统时钟来加速验收。

实际中断：先覆盖 PREPARED→prepared audit 打开、RESERVED→真实 Registry 响应、CONSUMED→result audit 打开的独立外部屏障；保留两类签名。精确终止本轮指定容器，分别报告计划内异常退出与正常退出0；重启仅补审计/ACK，不重做领域验证、不解烧毁，第二次重启幂等。

另列 update/verify×六阶段×两签名的预置健康中间态，以及审计缺失/错误前缀/键冲突/scope/checkpoint 损坏的启动拒绝矩阵。不得为此给产品暴露 fault HTTP/env/config 开关。不可恢复的数据冲突应继续失败关闭，不能自动采信不明日志尾部。

## 4. 不变的发布边界

所有测试 authority 均为 `EPHEMERAL_TEST_ONLY`，`authorization=BLOCKED`、`production=false`、`deviceActionsExecuted=false`。即使 D12 全矩阵通过，也不等于正式密钥/SLSA/发布安装/企业身份/全功能或生产上线，不解除九项恢复 blocker，不证明物理掉电、磁盘损坏、整盘回滚、WORM 或 exactly-once。

## 5. 真实镜像自动刷新子门（已在隔离CI验收）

接受代码957271a，绑定39840587359/job120040237746和父39840587362/job120040240510均success；主代理和独立子代理下载并重算64文件/65关联一致。两类签名本轮来源各18完整响应、0未完整响应；停止窗口内无新增事件，因此本轮不证明实际在途取消。具体身份、日志/工件摘要及边界以[验收记录](P0D12-PRODUCT-LIFECYCLE-ACCEPTANCE.md)为准。

使用同轮实际镜像与私有 archive，D11 原门返回后另起独立 Registry 和 UUID。两类签名各自使用一个真实产品容器，正常停止后启动同一个容器，不更换 grant、不重置验证预算。所有业务 POST 各发一次；只读状态等待可以有界重读，不重试已消费或不确定的写请求。

| 进程 | 固定案例顺序 |
| --- | --- |
| 初次运行 | 来源503未确认→自动获取cat2并撤销B→同代精确no-op→A消费→A重放拒绝→B撤销拒绝→断源自然变陈旧且验证503→同cat2恢复→只发布来源503 |
| 同容器重启 | 持久cat2/消费保留但内存freshness未确认→真实来源重新确认→旧A重放拒绝→新C消费→C重放拒绝→只发布来源503 |

每种模式18份动作报告、一个graph、4个真实inspect、2个真实PID1、来源进程/停止/ready/完整events分别归档。两类共72个独立Registry before/after快照；只有A/C成功消费窗口允许产品不可变镜像读请求，其余步骤必须增量为零，准备上传单列。来源完整安全日志按实际完成顺序保存，不硬编码轮询次数，不把完成ordinal当请求开始顺序或要求跨epoch完成严格单调。

source使用独立CA和SAN `feed.fixture.invalid`。源私钥、计划、body、日志位于 `root/source/<kind>/feed`，不在产品的 `root/refresh/<kind>` 三个挂载内；产品只拿public CA和固定IP/SPKI。未确认案例需先观察实际来源503，再发验证请求。来源503不应立即抹掉之前仍有效的Fresh，须等真实期限到期；恢复同代也必须实际GET后确认，不能直接调用Confirm或用管理员PUT替代。

正常停机后实际打开两库，导出journal、checkpoint校验及每个操作的真实prepared/result安全事件，独立重算actor、trace/target/data、哈希链与ACK。自动目录更新actor必须为 `image-trust-refresh`，不能用业务管理员替代。此子门仅正常停机/重启，不宣称已经验证计划内崩溃、六边界预置状态、损坏介质、来源负矩阵、完整追代或在途撤销竞态。

新门有480秒总截止时间；保留原D10/D11与前置门。新运行清理报告固定 `product-lifecycle-runtime-cleanup.json`，不覆盖前置门的 `product-lifecycle-cleanup.json`；新检查器测试日志也不覆盖前置13项日志。只有具名全矩阵、独立流量、真实进程/两库与精确清理共同通过后才能归档本子门结果。

## 6. 后续有限门的事实边界

89dfade的三阶段verify实际中断门与0633c4b的预置状态矩阵均已独立隔离验收，分别见[实际中断记录](P0D12-INTERRUPTION-ACCEPTANCE.md)和[预置状态记录](P0D12-STATE-MATRIX-ACCEPTANCE.md)。后者覆盖三lane/六健康/八拒绝/两签名的84格实际镜像启动与二启，但不是84次真实crash，也不替代前者的Linux内核屏障/pidfd SIGKILL证据。两门及原自动刷新正常重启门同时保留；完整自动刷新竞态、实际update等中断边界、来源负矩阵、物理故障和生产恢复授权仍未闭合。
