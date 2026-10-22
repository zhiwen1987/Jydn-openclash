# P0-d5 实施合同（候选，验收前不视为完成）

范围：独立 image-binding module、开发分支与隔离 CI；不访问生产，不解除九项 blocker。低层 Bind 保留为非受管原语，新增 ManagedBind 才接入本阶段信任状态。结果仍 advisory/BLOCKED。

## 参考与非目标

参考 [TUF 双阈值根轮换与版本高水位](https://github.com/theupdateframework/specification/blob/master/tuf-spec.md)、[Sigstore 策略分层](https://github.com/sigstore/policy-controller/blob/main/docs/api-types/index.md)、[bbolt 单写事务与持久提交](https://github.com/etcd-io/bbolt)。本阶段采用标准 Ed25519 和 bbolt，定义窄用途的澄网 catalog profile；不是完整 TUF 客户端或 TUF 兼容实现，不复制其完整协议或声称已有在线 TUF 刷新。

## trustcatalog 合同

- `Key{ID string, PublicKey []byte}`：ID 是公钥 SHA256 的 64 位小写 hex（不带前缀），杜绝同 ID 换钥。
- `Anchor{StoreID string, InitialSHA256 string, Keys []Key, Threshold int}`：带外配置；StoreID 为 32 位小写 hex；初始 envelope 原始字节 SHA256 独立钉住，Keys/Threshold 独立批准，不能取自候选请求。
- `Grant{ID, PolicyID, ApprovalSHA256, ApproverKeyID, ManifestSHA256 string; Revision uint64}`：ID 是批准者签发的 32 位小写 hex，策略、摘要、revision、审批者、制品摘要均签入。不能把调用方随意改的 operationID 当授权 nonce。
- `Document{Schema string; StoreID string; Generation uint64; NotBeforeUnix,NotAfterUnix int64; RootKeys []Key; Threshold int; Approvers []Key; Grants []Grant; PolicyFloors map[string]uint64; RevokedKeys,RevokedApprovals,RevokedManifests []string}`。wire 字段使用这些名字的小驼峰 JSON。
- `Signature{KeyID string; Signature []byte}`、`Envelope{Payload []byte; Signatures []Signature}`：JSON payload/signature/publicKey 为规范 base64；domain 为 `chengwang.trust-catalog/v1` 加一个 NUL。严格 UTF8/重复/别名/额外字段/整数/深度及字节预算。
- 导出 `Replay(anchor Anchor, history [][]byte) (Catalogue,error)` 只认证历史链，不表示当前时间仍可用。初始 generation=1 并通过带外 anchor 阈值和自身 root 阈值；后续必须精确 +1，旧根与新根双阈值、不同 key 只计一次，禁止同代异内容。允许过期历史，但操作必须检查最终元数据时效。
- 导出 `Advance(previous Catalogue, raw []byte, now time.Time) (Catalogue,error)`；新文档必须有效且 TTL≤24h。永久撤销集合不得减少；policy floor 不得减少或删除；当前 Grant revision 必须等于 floor。历史 Grant ID 定义不可变，不得换绑定后复用；撤销的审批者/批准/制品不得再配置为 active grant。
- Catalogue 不透明，getter：`Generation() uint64`, `SHA256() string`, `StoreID() string`, `ValidAt(time.Time) bool`, `Resolve(policyID string,now time.Time)(Grant,policy.Trust,bool)`；返回公钥副本，零值/JSON 导入无权威。
- 预算：最多8根/阈值1..N、64审批者、256 active grants、512 policy floors、每类4096撤销、4096历史grant ID；单 envelope 256KiB、history64条且总4MiB。历史只能追加，满则拒绝，不自动清账或降级。

## truststate 合同

- `Create(ctx,path string,anchor trustcatalog.Anchor,initial []byte)(*Store,error)`、`Open(ctx,path string,anchor trustcatalog.Anchor)(*Store,error)`，两个函数第一个参数均为 context.Context。Create 只创建不存在的直接叶目录；Open 缺目录/库/marker/损坏/截断一律拒绝，不初始化。
- Linux 原生 ext4/XFS，目录当前 euid:egid 0700，数据库0600、单链接；逐级 openat/O_NOFOLLOW 验证路径，持有目录与数据库 dev/inode/mount identity，操作前后重验。可信祖先仅 root/当前euid 所有且不可组/全局写；允许 root-owned sticky /tmp 类祖先。非 Linux 明确 unsupported，不内存降级。
- 用固定 `go.etcd.io/bbolt v1.4.3`（现有 checksum pin），`Options.OpenFile` 使用已钉目录的安全 openat；Open 强制无 O_CREATE，Create O_EXCL。默认同步提交，NoSync/NoGrowSync 不得打开；锁超时有界，生命周期独占写者，同进程 mutex；不暴露 DB、路径或可改同步参数。
- 一个严格 state record 原子承载 anchor fingerprint、history、sequence、last wall-clock高水位、grant ledger。事务失败/提交不确定/身份变化导致 sticky poison，不再返回成功。容量4096，禁止淘汰已消费 grant；文件上限64MiB、record8MiB。只保留公共摘要/标识，不存私钥、bundle、Registry token 或原始镜像配置。
- `Begin(ctx,policyID string,approvalRaw []byte)(Ticket,error)`：按当前有效 catalog 解析 trust，调用 policy.Verify 且核对 policyID/revision/artifact；同一事务检查 grant 从未使用，持久 RESERVED 后返回不透明 Ticket。票据 owner 绑定 Store 实例，含内部随机 token，getter `Trust() policy.Trust`, `GrantID() string`, `Generation() uint64`, `CatalogueSHA256() string`, `ManifestSHA256() string`。
- `Complete(ctx, ticket Ticket,evidenceSHA256 string) error`：重读 state 与当前 catalog，检查 ticket 仍 RESERVED、generation/hash未变化、当前撤销/时效/floor仍满足、时钟未回退；原子持久 CONSUMED 后才成功。重复票据/换ID/并发仅一个赢家，失败或崩溃的 RESERVED 永不回收。网络阶段不持 store mutex，允许同一实例并发 Update 撤销。
- `Update(ctx, raw []byte) error`：Advance 校验后与 ledger/floors 原子提交，已过期旧 catalog 可更新但不得被用于 Begin/Complete。`Close() error` 幂等。必要状态 getter 可返回不含秘密的普通审计 DTO，不能授予权威。
- Store 内时钟只用实际 time.Now，测试可使用包内非导出 hook；不要导出任意 Now 注入绕过时效。事务前后 fault hook 只包内测试用，不模拟已验证真实掉电。

## ManagedBind 与验收

ManagedBind(ctx,*truststate.Store,policyID,approval,bundle,root,registryRoots,bearer) 调 Begin → P0-d4 Bind →核对 ticket的manifest → Complete(结果公共摘要规范hash) → 返回独立不透明 ManagedResult。失败零值，完成提交后仍检查ctx，grant保持烧毁。ManagedResult 是受管验证证据，不是部署授权，不可由 JSON 导入；低层 Bind 的普通 Result 不等于 ManagedResult。

测试至少覆盖根轮换/阈值、旧根退役、元数据代际/撤销/floor防降级、签名 grant 重用与换operationID无效、进程崩溃和重启reserved、两个进程排他、并发Begin/Complete、网络期间撤销、过期/时钟回退、删库/截断/链接/目录替换、容量满、提交错误sticky poison、真实Distribution两种签名受管全链与恢复后拒重放。普通/race/vet、严格JSON门、父模块回归及原有P0-d4场景均须保留。

边界：只收到的最新撤销可执行，离线 freshness 由≤24h有效期限定；整体磁盘/目录/带外锚一并回滚无法本地自主检测，需要独立外部单调见证。至多一次尝试/消费不等于部署 exactly-once。已返回结果或运行镜像不会自动撤回，未来执行器需临执行复验。没有生产密钥发放、UI/RBAC/HSM、在线刷新或生产部署。
