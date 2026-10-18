# 候选镜像供应链证据门禁（离线、只读、默认阻断）

这里实现的是“证据一致性候选验证器”，不是已经可放行生产镜像的签名系统。它不访问 Registry、Rekor 或 OIDC，不调用 `cosign`，不生成签名，也不修改 Docker、容器或宿主机。

无论输入多完整，当前版本只会生成：

```text
schema=chengwang.supply-chain-verification/v1
status=BLOCKED
reason=CRYPTOGRAPHIC_TRUST_GATE_NOT_IMPLEMENTED
authorizationGranted=false
exit=78
```

输入缺失、过期、矛盾或格式错误时同样是 `BLOCKED / 78`，原因改为 `EVIDENCE_CONTRACT_FAILED`。因此不能把本目录的输出接成“允许启动”信号。

## 固定输入契约

策略文件独立于证据目录，必须满足 `schemas/policy.schema.json`，并由运行时再次执行严格校验。证据目录只允许下列对象，多一个、少一个、类型不符或存在符号链接都会拒绝：

```text
evidence/
├─ manifest.json
├─ config.json
├─ blobs/
│  └─ sha256/
│     └─ <manifest 中逐层声明的 64 位小写十六进制摘要>
├─ sbom.spdx.json
├─ attestation.dsse.json
├─ signature.bundle.json
└─ signature-evidence.json
```

### 已实施的严格检查

- 只接受绝对路径；逐路径组件拒绝 symlink，文件必须是普通文件、单硬链接并受尺寸限制。
- Linux 上，输入必须 `root:root`、文件权限不宽于 `0600`、目录不宽于 `0700`，祖先目录不得被组或其他用户写入。
- JSON 重复字段、未知字段、任何浮点数、超过 64 层的嵌套、超长数组和不支持的 schema 都会拒绝；SPDX 当前只接受文档/包/purl 的明确最小子集，未实现的可选子树不会被静默忽略。
- 哈希只接受小写 `sha256:<64 hex>`；签名算法只允许策略白名单与内置白名单的交集，目前是 `ECDSA_P256_SHA256` 或 `ED25519`。
- 重新计算 OCI manifest、config、所有 layer blob、SBOM、DSSE envelope、签名 bundle、策略和验证回执的字节摘要；检查 descriptor 顺序与尺寸。
- OCI 仅接受 Linux `amd64`/`arm64`、受支持的 OCI/Docker manifest/config/layer media type，且 layer 数必须与 config 的 `rootfs.diff_ids` 数一致。每层会按 media type 限流解压、重新计算 uncompressed SHA-256、匹配对应 diff ID，并流式检查 tar 成员数量、类型、路径、链接目标、单层/总解压量与膨胀比；zstd 在固定解码器进入验收前保持阻断。
- SPDX 仅接受 2.3 严格子集；`documentDescribes` 指向的 package 必须用 purl 绑定到准确的仓库与镜像 digest。
- DSSE payload 必须是唯一镜像 subject 的 in-toto Statement v1；仓库、digest、predicate type、builder、材料摘要和构建时间窗必须满足策略。
- `signature.bundle.json` 必须把签名、证书 DER 摘要、准确 issuer/subject、证书时间窗和透明日志 inclusion proof 结构绑定到镜像 digest。
- `signature-evidence.json` 的外部校验结果必须全部为 true，并与策略、OCI、SBOM、attestation、bundle 和证书摘要逐项一致。
- 外部验证器的名称、版本、二进制 SHA-256 与信任根 SHA-256 必须被策略精确钉住；回执还必须绑定策略文件本身的字节摘要。
- 策略、attestation invocation、签名 bundle 与回执必须使用同一个 run ID，并验证“build finished 与 SBOM created 均不晚于 transparency integrated，且 integrated 不晚于 receipt verified”的有向时间关系。
- 策略最长七天，证据最大新鲜度和未来时钟偏差由策略收紧；SBOM、构建结束、签名回执和透明日志时间均受限。
- 校验前后比较整个固定证据树的设备号、inode、大小、mode、mtime/ctime；输出先在同目录写入 `0600` 临时 inode 并 `fsync`，再用原子 hard-link no-clobber 发布、删除临时名并在 POSIX 上 `fsync` 父目录，禁止覆盖既有报告。

上述校验只能证明“这些离线字节之间没有发现结构和摘要矛盾”。策略文件本身也尚无审批签名，调用者可以同时替换策略与回执；`signature-evidence.json` 中的 true 仍是外部断言。本实现没有解析 X.509、执行 DSSE/镜像签名验签、验证证书链或重算 Rekor Merkle inclusion proof，所以报告明确标记 `UNTRUSTED_EXTERNAL_ASSERTIONS_ONLY`。

## 候选机运行方式

证据必须先由独立、受审计的构建/签名流水线放入私有目录。下面命令只能用于检查，返回 78 是设计行为：

```sh
install -d -o root -g root -m 0700 /root/chengwang-supply-chain/output
python3 verify_supply_chain.py verify \
  --evidence-root /root/chengwang-supply-chain/evidence \
  --policy /root/chengwang-supply-chain/policy.json \
  --output /root/chengwang-supply-chain/output/blocked-report.json
test "$?" -eq 78
```

输出 JSON 的形状见 `schemas/report.schema.json`。缺参、未知参数和验证器内部异常也受 fail-closed 边界控制：没有合法 `--output` 时，阻断报告写到标准输出；有合法新路径时才以 no-clobber 方式写文件。schema 只是可交换文档，真正的安全边界仍是脚本里的重复字段检测、精确字段集合和字节级摘要校验；不要只运行通用 JSON Schema 校验就放行，也不要从固定旧路径读取上一次报告。

## 测试

```sh
python3 -m unittest discover -s tests -v
```

Windows 测试用于验证纯解析、摘要、时间窗、身份、路径和 no-clobber 逻辑；junction 与 symlink 都会拒绝，但 Windows 仍不能证明 Linux 的 root 所有权、mode、inode 或候选机文件系统语义，因此报告明确写入 `platformAssurance=DEVELOPMENT_ONLY_NON_POSIX`。Linux 候选机还需要重复单测，并做 symlink/hardlink、并发替换、大文件、时钟偏差和断电恢复测试。

单元测试里的签名、证书和透明日志字段全部是明确的 `fixture/test-only` 合成数据，只用于证明拒绝与关联逻辑，绝不代表真实签名或真实 `cosign` 验证结果。

## 解除 BLOCKED 前仍必须补齐

1. 选择并锁定真实签名格式和信任根，优先直接消费标准 Sigstore bundle，避免长期维护自定义 bundle。
2. 由独立审批根签署策略；在隔离的、digest 固定的验证器镜像中执行真实签名、X.509 链、Fulcio issuer/subject、Rekor SET 与 Merkle proof 离线验证；信任根本身也要版本化、签名和轮换。
3. 从真实 Registry 用 digest 拉取并做独立远端读回，证明本地 `manifest.json` 确实对应将部署的仓库对象。
4. 用 Linux `openat2(RESOLVE_BENEATH|RESOLVE_NO_SYMLINKS)` 或预打开目录 fd 的 `openat` 工作流替代当前“逐文件 fd 校验 + 整树前后快照”，关闭目录替换与换回的残余 TOCTOU 窗口。
5. 生成真实 SBOM、SLSA provenance 和签名材料，完成密钥泄露、证书过期、Rekor 不可用、策略过期、镜像重推、并发换包及回滚演练。
6. 把审批方发出的单次 nonce 或单调流水线序列接入持久、并发安全的消费账本；当前 run ID 与时间窗只能关联证据，不能阻止窗口内重放。
7. 只有标准 Sigstore 验证器或经独立审计的验签器完成上述密码学和 Registry 证明后，才设计新的 accepted schema；不得把当前报告改名后复用。

当前仓库没有提供真实证书、签名、透明日志证明或 Registry 读回证据，因此这里没有任何“验签通过”结论。
