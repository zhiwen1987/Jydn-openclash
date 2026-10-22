# 镜像、批准策略与 Registry 来源绑定（候选库）

本模块是独立 Go 1.25.8 候选库，不是部署器。主项目仍用原 Go 基线；不修改生产容器、旁路由、DNS 或恢复权限。低层绑定验收见 [P0-d4](../../docs/P0D4-APPROVED-REGISTRY-BINDING.md)，新增受管能力的合同见 [P0-d5](../../docs/P0D5-IMPLEMENTATION-CONTRACT.md)；文件存在不代表已通过验收。

## 一次调用实际检查什么

`Bind(ctx, trust, approvalRaw, bundleRaw, rootRaw, registryRoots, bearerToken)` 按以下顺序执行：

1. 独立批准者 Ed25519 公钥、批准文档原始字节 SHA256、key ID 和精确 revision，验证带域分隔符的批准签名。拒绝重复字段、额外字段、歧义 JSON、非规范 base64、过期或超过 24 小时的批准。
2. 批准文档绑定单平台 `host/repository@sha256:…`、OS/架构/variant、Registry IP 白名单及叶证书 SPKI 摘要，以及 Sigstore bundle 类型、签名者 issuer/SAN、日志 ID、信任根摘要、制品摘要；DSSE 另外绑定 subject name 与 predicate type。
3. 调用兄弟模块 `image-verifier` 的标准 Sigstore 校验。签名、证书、SCT、SET、包含证明、checkpoint 必须成立；签名无效时不访问 Registry。
4. 仅直连批准的 IP，正常验证 TLS CA/原始域名，再验证批准的叶公钥 SPKI；通过之前不发送 HTTP 或 bearer token。禁止 DNS、环境代理、重定向及认证 realm 跳转。只允许 GET/HEAD。
5. 从 Registry 读回精确摘要的原始 manifest、config 和所有 layer；各对象 HEAD/GET/HEAD 并最终再查 manifest。检查元数据稳定、HTTP framing、大小预算、实际摘要、平台、解压及 diff_id，并复用主模块 `ValidateLocalLayers` 生成不透明图。
6. 将签名对象、批准内容和实际图再次比对，检查取消/过期，才返回不透明进程内结果。结果只提供摘要及公共标识，固定 `Authorization() == "BLOCKED"`，JSON 导出为 `{}`。

`Trust` 必须由未来产品的独立受保护配置提供。不能把候选镜像请求携带的 key/hash/revision 当成独立批准。测试动态生成的批准私钥、CA、日志密钥仅存在于测试进程，不安装为产品信任。

## 合同与预算

- 仅支持主校验器当前平台：linux/amd64、linux/arm64（含规范 v8）。不支持 tag、manifest index 或自动选平台。
- 批准 envelope 最多 64 KiB；bundle/root 使用兄弟验签模块预算。Registry manifest/config 各最多 1 MiB、1 至 128 层、每层最多 128 MiB、总层字节最多 512 MiB；仍应在调用进程外限制内存/CPU。
- Registry 单次读回最长 2 分钟，并受调用 context 与批准到期的更早截止时间限制。签名 SDK 不能保证中途被 context 打断；只保证取消后不返回成功，硬时限需要外部进程终止。
- `Docker-Content-Digest` 可缺省；若存在必须唯一且等于期望摘要，不能代替对实际字节计算 SHA256。
- 当前要求 manifest/blob 响应都带唯一、支持的 Content-Type；部分精简 Registry 服务会因此被拒绝。普通测试夹具可显式提供该元数据，但这种适配不算原服务兼容性证据；真实 Distribution 验收不使用适配。
- 输入切片、公钥和证书池不得在调用期间被其他 goroutine 修改。TLS 叶公钥轮换需要新的独立批准；不自动相信线上读回的新公钥。
- 库返回固定错误/零结果，不返回原始 config、响应体、token、认证 challenge 或私钥。

## 受管信任、撤销和单次批准

`ManagedBind` 是与低层 `Bind` 不同的类型边界：先从带外引导的 `truststate.Store` 解析批准者、精确批准摘要和 revision，持久化预留由可信签署者签入 catalog 的单次 grant，再执行原有签名与真实 Registry 读回，最后复验当前代际、撤销与时效并持久消费。它只返回不透明 `ManagedResult`，仍为 `authorization=BLOCKED`；目前没有产品执行器消费这个类型。

- `trustcatalog` 使用标准 Ed25519 阈值签名；初始 envelope 摘要与根公钥由独立 Anchor 钉住。后续版本精确 +1，换根须同时满足旧/新根阈值。永久撤销集合和 policy floor 不可回退，历史 grant ID 不得改绑。它参考 TUF 原则，但不是 TUF 客户端或兼容实现。
- `truststate.Create` 只创建不存在的叶目录，`Open` 不创建、不自动修复缺失或损坏状态。仅支持原生 Linux ext4/XFS、当前用户私有目录和安全路径；非 Linux 返回 unsupported。使用固定版本 bbolt、默认同步事务、生命周期独占锁和路径/文件身份复核。
- 同一签名 grant 在成功持久化为 RESERVED 后只能尝试一次，后续失败、取消或进程崩溃也不回收；可信签署者必须显式签发新的 grant 才能重试。输入预算、预取消或批准无效等在 RESERVED 之前拒绝的请求不消费 grant。调用方换 request ID/policy ID、重启或重复请求不能重置账本。这是至多一次已预留尝试，不是部署 exactly-once。
- 单 catalog 最多 256 KiB、有效期不超过 24 小时；保留最多 64 代且总计 4 MiB、4096 个历史 grant。账本最多 4096 项，record 最多 8 MiB、DB 最多 64 MiB；满容量失败关闭，不淘汰已消费记录。长期运行需要另行设计有独立见证的归档/迁移，不能删库清账。
- 数据库仅存签名公共元数据和摘要；校验和用于检测意外损坏，不是能抵御恶意管理员的签名。故障/提交不确定后当前 handle 永久 poisoned，不能自动重试为成功。
- 撤销更新须送达同一个 Store；离线未知撤销、整盘连同 Anchor 回滚、已返回结果或运行镜像的撤回不在该库保证范围。需要在线刷新、外部单调见证、受保护密钥分发和未来执行器临执行复核，不能用本地账本代替。

## 验证与边界

CI 运行器见 [scripts/README.md](scripts/README.md)。普通测试包含真实本机 TLS 服务，外网被 namespace 禁止；另在唯一临时 internal 网络内运行固定 digest 的真实 Distribution Registry，上传合法惰性 OCI fixture 后进行普通/race 读回。只测试服务器可写，产品函数只读，绝不执行镜像。

支持少于完整 OCI/Registry 生态是明确的失败关闭限制：尚未支持认证挑战换 token、CDN 重定向、OCI index、制品多签阈值、在线 TUF/自动撤销刷新、企业批准工作流和生产密钥分发。catalog 的根阈值不等于镜像制品多签。没有产品调用方、CLI 服务、发布构建镜像签发、运行中容器身份绑定或恢复执行接入。九项恢复 blocker 不变；成功不表示镜像内容安全，也不表示已经部署。
