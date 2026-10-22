# P0-d5 可信策略、撤销与防回放

日期：2026-10-22（Asia/Shanghai）。范围仅开发分支和隔离 Linux CI。状态为 `implemented+tested isolated-only`；不是已集成产品或生产上线。

## 实际实现范围

新增能力位于独立 Go 1.25.8 `tools/image-binding` 模块，主项目 Go 1.23 基线不变。

1. `trustcatalog`：带外 Anchor 钉住 Store ID、初始 envelope 摘要、根公钥与阈值；标准 Ed25519 签名验证窄用途 catalog profile。根轮换必须同时满足旧/新阈值，generation 精确 +1，历史 grant ID 不可改绑，policy floor 和永久撤销集合不可回退。
2. 策略绑定：catalog 根阈值权威签入 grant，将策略 ID、精确 image-approval payload 摘要、revision、image-approval 审批者和制品摘要绑定。catalog 根与 image-approval 审批者是不同角色；请求方不能靠改 operation ID 生成新授权。
3. `truststate`：固定 bbolt v1.4.3、默认同步事务、生命周期单写锁；Linux 原生 ext4/XFS、私有目录/文件、逐级 no-follow 和 dev/inode/mount 复核。缺失、空、截断、替换的状态不自动初始化，存储/提交不确定后当前实例永久失败关闭。
4. 单次消费：通过批准校验后先持久 RESERVED，再进行真实签名和 Registry 读回；同一实例可在网络读取期间更新撤销。完成事务与持久读回后重新检查有效期、时钟、当前代际、撤销、grant 和 trust，成功才返回 `ManagedResult`。已 RESERVED 的失败/取消/崩溃不回收；可信根显式签发新 grant 才允许新尝试。
5. 结果边界：不透明、JSON 不能导入为权威；低层 `Bind` 不能构造 `ManagedResult`。成功仍为 `ADVISORY_MANAGED_REGISTRY_SIGNATURE_BOUND / authorization=BLOCKED`，不是部署许可。

内存与磁盘预算、wire 格式和 API 见 [实施合同](P0D5-IMPLEMENTATION-CONTRACT.md) 与 [模块说明](../tools/image-binding/README.md)。签名、密钥和证书池均来自独立测试夹具，没有安装生产信任。

## GitHub 参考及采用边界

- [TUF specification](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)：参考带外根、旧/新阈值、版本高水位和时效分离。实现的是澄网窄 profile，不是完整 TUF 客户端、兼容认证或在线 refresh；catalog 版本检查不能替代业务 grant 防回放。
- [Sigstore policy-controller](https://github.com/sigstore/policy-controller/blob/main/docs/api-types/index.md)：参考镜像来源、签名身份与策略层分离；没有部署该 controller，也不声称继承其全部功能。
- [bbolt v1.4.3](https://github.com/etcd-io/bbolt/blob/v1.4.3/db.go)：使用真实固定依赖与默认同步事务；`Options.OpenFile` 接入目录绑定的文件描述符。没有另造密码学原语或事务数据库。

## 实际完成的隔离验收

代码提交 `6a387bcd8a11a0590e5990723c5638fefa445adf`，开发分支 `codex/chengwang-security-hardening`。三个子智能体分别实现/审阅 catalog、持久状态、CI 与独立验收，最终集成者另行下载附件并重新核验。

| 验收范围 | 实际读回证据 | 结果 |
| --- | --- | --- |
| 受管绑定库 | [run 39755876523 / job 119747626282](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39755876523/job/119747626282) | Go 1.25.8；ordinary/race 各 379 个 Test 场景、5 包、0 fail/skip，集合相同，vet 通过 |
| 原场景保留 | 同一任务的严格 JSON 门 | 原 P0-d4 三包 234 个场景名称集合的计数与固定 SHA256 完全不变；新增断言未弱化原超时用例 |
| 撤销与单次消费 | 两份实际 Go transcript | 根阈值轮换、不可回退 floor/撤销、历史 grant 不改绑、并发唯一赢家、网络中撤销、提交后到期/时钟回退、失败消费、checksum/链接/身份替换、容量拒绝均实际 run/pass |
| 真实进程边界 | `TestTrustStateProcessLockAndCrashDurability` | 第二进程拒绝开库，子进程在持久 RESERVED/CONSUMED 后以指定非零码退出，重开仍拒回放；不是物理掉电证明 |
| 真实 Distribution | 同任务 `registry-ordinary.json` / `registry-race.json` | 每份 3 个 Test 事件，message-signature/DSSE 均实际 managed 成功、关库重开、拒重放；四个逐 kind 标记各出现一次，0 skip；未运行产品镜像 |
| 原主项目 | [run 39755876519 / job 119747626733](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39755876519/job/119747626733) | Go 1.23.12；普通/race 合计 4134 语义事件、36 包、0 skip；158 个 Python、13 个 shell 语法检查、11 份 schema metaschema 和既有真实 Docker/恢复门通过 |

新模块各包场景为：policy 127、registry 73、binding 44、trustcatalog 88、truststate 47。这里统计 Go Test run 事件，包含父/子测试和进程 helper，不能解释为 379 种独立业务故障或生产成功率。额外 `parent-restoreimage.json` 的父校验器测试不混入这五包集合。

最终集成者下载 `image-binding-39755876523-1`，重新执行 ordinary/registry 严格 JSON 门，逐个比较 37 个模块文件的 CI SHA256 与验收提交 Git 原始 blob，全部一致；before/after 清单完全一致。独立验收子智能体另下载并核对相同证据。

新增 bbolt 直接引用与 x/sys 直接引用没有升级版本；386 项远端 MVS 集合/版本及原始 go.sum 与 P0-d4 完全一致。在线和断外网后的官方 `go mod verify` 均实际通过；本地 alias 只用于校验投影，编译保持原 module、`GOWORK=off`。`tools/image-verifier` 从 P0-d4 验收提交至本提交无差异；本阶段未另跑其完整独立 328 场景门，不能把旧结果说成新的独立运行。

真实 Registry 服务日志为 Distribution 3.1.2；96 次不可变 manifest/blob GET/HEAD 全部 HTTP 200。单位测试为仅 loopback 的 namespace，源码/缓存只读、非 root、无 capabilities、NoNewPrivs，状态目录为本次私有原生 ext4/XFS。真实 Registry 另用唯一 internal bridge、固定镜像 digest、无宿主端口、非 root、只读根和资源限额；没有补头适配器。job 实际出现 `REGISTRY_FIXTURE_CLEANUP=PASS only_owned_objects=true ephemeral_private_keys_removed=true`。

附件共 29 文件，独立扫描没有 PEM/key 文件或私钥 PEM 块。清理证据来自 job 日志，不是独立长期清理账本。以上仅验收列明的候选库与夹具链路，不是生产灰度、发布签发、真实掉电、长期可用性或整个系统完成的证据。

## 已发现问题及处理

- 独立审阅发现提交可能跨过批准/catalog 到期时间：已增加提交后实际时效复核，测试在 after-commit 才推进时钟，分别检查批准到期、catalog 先到期与时钟回退；已消费状态不能因最终失败恢复。
- 原失败消费测试可能因缺少可信 CA 提前失败，不能证明 grant 被烧毁：改为显式 `Begin -> ErrReplay`，关闭重开后再次检查确切 `ErrReplay`，不只看总流程失败。
- 首轮代码 `9d746be` 的绑定 CI 被新提交的 concurrency 规则取消，不算通过。`ae487b0` 的绑定 run `39755384539` 普通测试失败，race 与真实 Registry 未执行；唯一失败是既有 `header_deadline`，不能当作本阶段完成证据。
- 上述失败揭示 socket deadline 先触发、context timer 尚未发布 Err 的错误分类竞态。`6a387bc` 保留原 80ms 网络断言，并在同一测试内加入确定性延迟发布夹具；仅在调用方自己的 deadline 确实已到时返回 DeadlineExceeded，不等待任意 Done，不把内部批准/传输截止归成调用方超时。
- 本机 Go 缓存此前出现损坏，本阶段不使用该缓存编译或关闭 checksum 强行通过。实际编译和测试以独立 Ubuntu、固定 Go 1.25.8 与认证依赖为准。

## 明确未完成

- 没有接入产品 API、UI、RBAC、审批服务、部署器或恢复协调器；低层 `Bind` 仍是非受管原语，不能被未来执行器当作受管准入。九项恢复 blocker 全部保留。
- 没有真实发布镜像签发、生产可信 Anchor 发放、HSM/离线根流程、在线 catalog 自动刷新或即时离线撤销送达。
- 没有防整盘/带外 Anchor 一并回滚的外部单调见证。公共 record checksum 仅检测意外损坏，不抵御恶意 root/同 UID 管理者。`os.Exit` 进程崩溃测试不是物理掉电证明。
- 至多一次 RESERVED 尝试不等于部署 exactly-once，也不自动停止已运行镜像或撤回已返回结果；未来执行器必须临执行再次检查当前信任与撤销。
- 新请求在持久 RESERVED 之前拒绝不消耗 grant；之后的坏 bundle 会烧毁 grant，这是安全/可用性的明确取舍。未来服务必须在 Begin 前做认证、RBAC、限流与预算，不能暴露匿名消耗接口。目前没有对外服务。
- catalog 有效期最多 24 小时，历史最多 64 代/4 MiB、4096 历史 grant；消费账本最多 4096、record 8 MiB、DB 64 MiB。达到容量拒绝，不自动清账。长期归档迁移、外部见证、容量告警和自动运维尚未实现。
- 没有构建 provenance 内容的源码/builder 准入、完整 OCI index/认证 challenge/CDN 生态、多节点共识、企业审计不可变副本、长期观察、生产 SLA 或全仓完整安全审计。
- CI artifact 保留 14 天，不是长期 WORM。依赖缓存本体不上传，下载附件无法离线重算全部缓存字节；需结合源码绑定、原始图/pin 和 CI 官方验证日志。

本阶段未访问、重启或修改生产 .240/.249/.254，未改爱快、现网 OpenClash、DNS 或 ERP。开发分支成果不等于 main 已合并或生产已上线。M2b、M3、M4 和整体正式运营仍未完成。
