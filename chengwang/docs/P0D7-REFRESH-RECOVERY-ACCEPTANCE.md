# P0-d7 自动撤销刷新与跨库异常恢复验收

日期：2026-10-22（Asia/Shanghai）。结论：本阶段已实现并通过隔离验收（implemented+tested isolated-only）。范围仅开发分支、隔离 Ubuntu CI；不访问或修改生产、不合并 main。不是生产上线、部署批准或全故障自愈证明。

## 实际实现范围

- 固定 HTTPS 来源、独立 CA/主机名/literal IP/SPKI、无代理/DNS/重定向的有界刷新；latest 加数字中间代路径，顺序受管验签、累计撤销与 floor 不回退，单循环退避/jitter。
- 产品端精确 generation/hash 的来源新鲜度，重启清空、过期与版本变化阻断；BeginTracked 原子核对、Complete/结果审计后再次检查。不是由 HTTP 传入来源或手工调用确认端点。
- bbolt 同 record 的操作 journal/outbox：intent、真实 prepared hash、catalog 提交/RESERVED/CONSUMED 事实、结果与真实 ACK hash。来源约束、根与审计没有由请求替换。
- 启动先核对所有已保留操作的 scope 与审计前缀/哈希，再对未 ACK 事件幂等补投递。拒绝已 ACK 缺失、prepared 丢失、前缀错误、同 key 异语义、错 scope、坏 checkpoint；不修改历史或恢复 grant。
- 候选私有显式配置自动刷新，独立 15 秒审计维护，取消/等待后台后再关库；原 cmd/server 未装配新后端。操作说明见 [模块 README](../tools/image-binding/README.md)。

## 最终实际验收

最终代码：`d4f413e808dc03c30e5aca15ca4a5d79aab531ec`。以下以该提交实际完成的任务、原始附件与独立复核为准，不用旧提交或 workflow 定义替代执行结果。

| 项目 | 实际结果 |
| --- | --- |
| 绑定任务 | [run 39769625166 / job 119793601116](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39769625166/job/119793601116)，success |
| 主项目任务 | [run 39769625246 / job 119793601382](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39769625246/job/119793601382)，success |
| 子模块普通/race/vet | 普通与 race 各 627 个精确 Test 场景、8 包，集合一致、0 fail/skip；Go vet 通过。root61、cmd68、policy127、product77、refresh64、registry73、catalog89、state68；完整八包指纹锁定 |
| 旧回归保留 | 原 234、379、490 pair 集合与旧 product47/cmd46 指纹保留。两处旧序号断言按 journal 事实强化，不能将名称保留说成测试体未修改 |
| 父项目普通/race | 各 2257 个 Test pair、37 包，合计 4514 次语义运行，0 fail/skip；原 2252 pair 无缺失，evidence52 场景锁定。Fuzz 顶层/seed 不混入该计数 |
| 真实来源与候选组合 | 显式 CA/主机名/IP/SPKI TLS 下载，同代 no-op、有界补代与拒绝；候选真实 run() 自动刷新和重启清空确认、取消后等待后台并释放锁、真实 15 秒审计维护检测故障并停止，拒重开坏 checkpoint |
| 持久恢复 | 真实 product 子进程在 update/verify 两类的 6 个外部持久边界 os.Exit，共 12 个 leaf 场景；重开原始 Store/Audit 并重复 New，对账幂等、grant 不回收。另低层真实子进程检查 intent/prepared/RESERVED/CONSUMED/COMMITTED/ACKED 原子事实；其中低层摘要是合成公共值，不伪称实际 Sigstore |
| 真正 SDK/API 组合 | 独立子进程运行真实 API/Sigstore：CONSUMED 后关闭真实 Audit 导致 503/不确定失败，再重开两库补齐消费审计、拒重放、不重访 Registry；另真实固定 TLS 刷新来源在 Registry 网络读取期间更新撤销，旧请求不得成功、RESERVED 保留。普通/race 每份各两条 D7 标记恰好一次。这两项不是物理掉电或 SDK 消费点 SIGKILL 证明 |
| 真实 Registry | 无适配 Distribution 3.1.2 的两类签名低层/managed/完整产品 API 链路继续通过；普通/race 各 3 个测试事件，原 managed 与 product API 共 8 条标记各一次；144 次不可变 GET/HEAD 全 200 |
| 源码与依赖 | 507 项跨模块与 61 项子模块源码清单前后相同，逐 Git raw blob 独立核对到最终提交；386 个远端模块/版本保持既有集合，三个模块的 go.mod/go.sum 相对上一阶段无变更，官方在线与离线 verify 均通过 |
| 构建制品 | 实际 Go 1.25.8 trimpath build 与 --help，vcs.revision 为上述提交、vcs.modified=false；CI SHA256 `e8c4554025f8fa64c96853bd1950ec80eef1fb07dbc80fe023aaff72138fda0c`。仅核对元数据/摘要，本体未上传，不冒充已下载重哈希或签名发布 |
| 其他与隔离 | 158 个 Python 测试、13 个 shell、11 份 schema 与检查器 46 个负例通过。源码/缓存只读、native ext4/XFS、普通门仅 loopback/非 root/无 caps/NoNewPrivs，真实 Registry 仅内部网络、无 host ports/持久 volumes。实际清理 PASS；34 份工件无私钥文件或 PEM 私钥块。仍有 Actions Node 迁移提示，不宣称零 warning |

三名子智能体分别实施/复核 Store journal、固定源刷新、候选组合与 CI；集成者另执行精确 JSON 门并逐源码 blob 复核。集成者证据目录 `C:\Users\Administrator\AppData\Local\Temp\chengwang-p0d7-ci-39769625166`，独立验收目录同级 `chengwang-p0d7-review-39769625166`。本地 Go 缓存故障未绕过，实际 Go 验收在 Ubuntu 隔离环境执行。

此处构建后仅 --help，真实候选监听在测试进程 run() 中，不是已安装的发布进程/system service。此处恢复是在健康两库及明确断点下验证，不签署坏盘自动修复、长期容量或生产 SLA。

## 本轮发现与处理

- 首轮代码 `4e2ae97` 的绑定 run `39767895746` 实际失败：D7 SDK 子进程返回 PASS，但未启用 verbose 的 t.Log 隐藏了验收标记；另有旧 API 场景把新增 journal 的合法序号推进误报为非法 catalog 变更。未计通过，未取消失败记录；修正为显式标记，仍严格拒绝坏签/旧代，并断言 catalog generation/原始摘要与 grant ledger 不变，同时新增拒绝 journal 的 PREPARED/REJECTED/ACK 约束。product 的对应旧序号断言也作相同事实分离，不以测试名指纹声称测试体从未改变。
- Go 对带 slash 的 t.Run 名字不会自动生成中间父 run 事件；移除原本不存在的 `/update`、`/verify` required 项，12 个真实持久边界 leaf 仍全部 required，不删实际测试。
- `cd2828e` 两条 CI 实际成功（绑定 `39768330157`、主门 `39768330222`），ordinary/race 各 627 场景、父 4514 次 Test 运行；据此才校准完整八包测试指纹，不猜数量。它不是后续修复代码的最终验收证据。
- 持久 intent 后的错误明确 `stateMayHaveChanged=true`；before-pre-audit 故障仍在任何 intent 写入前复核，保持真正零变更路径。空 Data 的 nil/空 map 按语义比对，避免 JSON omitempty 在重开时造成假冲突。
- 最终复核发现：第一次状态读取验证旧结果后，第二次 sourceBound 可能已经读到更新并确认的新代。仅判断 sourceBound 成功会把新代新鲜度误当作旧结果依据。`d4f413e` 将第二次读取的 generation/hash 与结果再比对，并在该读取之后最后检查结果有效期/取消/poison；既有测试体加强旧代拒绝、同代允许和过期拒绝。不能追溯最后检查之后才发生的新撤销，所有结果也仍无执行授权。
- time.Time 的单调时钟比较可能掩盖墙钟回拨，来源确认、读取和 Status 增加显式 UnixNano 边界；没有修改系统时间或放宽时效检查。独立外部时间锚仍未实现。

## 必须保留的边界

- 成功仍为 `ADVISORY / authorization=BLOCKED`，九项恢复 blocker 不解除；无生产发布、镜像签发、设备执行器、main 合并或生产流量变更。
- 不是完整 TUF 客户端：中间代过期不能自动追赶；发布者隐藏新撤销/重放当前未过期版本仍无法被客户端独立证明，依赖签名有效期与本地刷新窗口，不保证即时撤销。固定单源/SPKI 轮换和证书分发需独立管理；无多源容灾或 Retry-After 协商。
- 恢复只对健康持久库之间的审计投递缺口自动完成，不能自动修损坏日志、陈旧 checkpoint、路径/盘故障、整盘回滚或根配置。致命故障使候选停止，需健康文件与受控重开；未安装外部 supervisor。构造要求旧业务已停止，不是热切换协议。
- 已 RESERVED/CONSUMED 永不回收，恢复不重复 Registry/SDK；中断前尚未变更的 intent 标记 interrupted，不自动完成用户请求。审计消费不代表 HTTP 成功或客户端收讫；没有分布式事务、部署 exactly-once、外部单调见证或 WORM。
- 旧无 journal 库保持可读兼容，不是旧版本历史来源的重认证；journal 4096/审计恢复视图 16384/原 catalog 历史 64 代等硬容量仍需运维，尚无自动告警、归档或安全迁移。
- 新鲜度和重试预算是本进程状态；攻击性重启、签名 SDK CPU、I/O 硬时限与整体资源配额不是本阶段闭环。目录更新仍无独立全局配额，合法管理者或异常 feed 的重复失败可消耗 journal/审计容量。
- 无 UI、企业 SSO/MFA/审批、生产根/HSM 运维、多租户 Store 路由、分布式 HA、真实掉电或长期浸泡。子进程退出不是物理掉电，测试进程里的 run() 不是已发布服务。
- CI 工件保留 14 天；构建/help/hash 不是签名发布制品，二进制本体未下载重哈希。测试通过不等于已上线、免维护或无 bug，M2b/M3/M4 与整体生产运营状态不因此提升。
