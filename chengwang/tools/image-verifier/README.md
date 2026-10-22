# 澄网标准来源验签候选（P0-d3）

状态：**独立模块候选，已通过本地及 Linux 离线 CI，不是已上线功能，不授权部署或恢复。** 具体提交、任务与证据边界见 [P0-d3 验收记录](../../docs/P0D3-STANDARD-SIGSTORE-VERIFIER.md)。

使用官方 `sigstore-go v1.3.0`，独立 Go 1.25.8 模块；不升级主控制面 Go 1.23 基线，也不修改 OpenClash。标准库与第三方依赖锁定于 `go.mod/go.sum`，fixture 原始字节与来源见 [testdata/SOURCES.md](testdata/SOURCES.md)。

## 已实现的合同

- 离线输入：原始 bundle、原始 trust root，以及调用方独立批准的预期策略；库没有文件、网络、Docker 或恢复入口。
- 支持 bundle v0.3 的 `messageSignature` 和 DSSE `application/vnd.in-toto+json`，只接受一个 Fulcio leaf certificate、一个指定的 Rekor v1 条目和一个签名。
- 官方 SDK 实际校验 artifact SHA-256、精确 issuer/SAN、Fulcio 证书链、SCT、SET、Merkle inclusion proof 和签名 checkpoint。不启用 regex 身份、unsafe、当前时间替代或在线 root 获取选项。
- 同一个指定日志条目必须同时具有 SET、proof 和 checkpoint；不能由两个条目各补一项证明。
- DSSE 固定 in-toto Statement v1、唯一 subject、唯一 sha256 digest、精确 subject name 和 predicate type。它**不表示 predicate 中的 builder/source 已获本项目批准**。
- 每份 bundle/root 最多 1 MiB；JSON 深度 32、节点 8192；Rekor body/DSSE payload 各 256 KiB；证书、签名、SET、checkpoint 等各有独立预算。拒绝重复键、未知字段、字段别名、无效 UTF-8、孤立 surrogate、null、尾随值及超额材料。
- root 的重复日志 ID 在进入官方 map 前拒绝；每类日志、CA、证书链有数量/字节预算。
- 成功仅产生不可从 JSON 导入的 opaque `Result`，固定 `ADVISORY_SIGSTORE_BUNDLE_VERIFIED / authorization=BLOCKED`；失败返回零 Result 和固定错误（取消仅返回 context 原因），不泄露 SDK 正文或证书内容。

Rekor v1 有两个合法不同的索引：SET 使用全局 index，proof 使用 shard-local index；不能强制相等。SDK 分别验证它们对同一原始 body 的绑定。官方解释见 [Rekor client changes](https://github.com/sigstore/rekor-tiles/blob/v2.3.0/CLIENTS.md#miscellaneous-verification-bundle-changes)。两种官方样本保留原始不同索引，并覆盖独立篡改拒绝回归。

## 本地构建与测试

```sh
# 先在线获得固定 Go 1.25.8 和依赖，然后直接使用该工具链。
GOTOOLCHAIN=local GOWORK=off go mod download
GOTOOLCHAIN=local GOWORK=off go mod verify
GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly go test -count=1 ./...
GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly go test -race -count=1 ./...
GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly go vet ./...
GOTOOLCHAIN=local GOWORK=off GOFLAGS=-mod=readonly go build -trimpath -o /tmp/image-verifier ./cmd/image-verifier
```

只有设置 `GOPROXY=off` 不算禁网证明。独立 workflow 先下载固定依赖，再在 Linux 的不同 network/mount namespace、无外部接口/路由、只读源码与模块缓存、非 root、capabilities 全清、no-new-privileges 条件下运行 ordinary/race/vet，并保存 JSON transcript。门禁要求两种正例、分别的密码学负例、零 skip 和普通/race 相同测试集合；实际通过与否以 CI run 和 commit 为准。

## CLI 请求和退出语义

只接受 stdin 的一个 JSON 对象，必须 EOF，不接受命令行参数或任意文件路径：

```json
{
  "expected": {
    "artifactSHA256": "sha256:<64 lowercase hex>",
    "trustedRootSHA256": "sha256:<64 lowercase hex>",
    "logID": "<64 lowercase hex>",
    "issuer": "<exact approved HTTPS issuer>",
    "san": "<exact approved SAN>",
    "kind": "dsse",
    "subjectName": "<exact approved artifact name>",
    "predicateType": "https://slsa.dev/provenance/v1"
  },
  "bundle": "<canonical base64 of original bundle bytes>",
  "trustedRoot": "<canonical base64 of original trust-root bytes>"
}
```

message-signature 模式不允许设置 DSSE 专属策略。CLI 请求最多 3 MiB，严格拒绝重复/未知/大小写别名/null/尾随字段及非规范 base64。成功 exit 0，只输出三项摘要与 advisory/BLOCKED；任何请求/验签失败 exit 1，输出固定 `INVALID_REQUEST_OR_PROOF`，不输出输入材料。

必须由调用方提供硬时间/CPU/内存上限和进程隔离。SDK 的 `Verify` 没有可中断 context，库只在调用前后检查取消；CLI 的 SIGTERM 也不能保证打断阻塞 stdin 或正在执行的 SDK。Linux 外层示例 `timeout --signal=TERM --kill-after=2s 30s /tmp/image-verifier < approved-request.json` 仍需由部署方配置 CPU/内存限制。CI 的 `GOMEMLIMIT` 是 Go 的软目标，不是容器硬内存隔离。真实子进程测试只证明父进程硬 kill 有效，**不证明 SDK 内部可取消**。

## 尚未完成，不能误读

1. root 摘要 pin 来自调用方策略，只证明字节一致；不是独立 TUF 认证、审批、密钥轮换、撤销或可信时间治理。
2. 官方 fixture 只证明标准兼容性，其 signer/builder 不是澄网发布来源；不能批准本项目镜像。已从固定 conformance README 核实 Apache 2.0 许可声明并保留来源与许可证文本；这不是完整产品和依赖图的许可审查。
3. 不支持 Rekor v2/RFC3161、其他 bundle 版本、key-only、证书链输入、多签名、多日志阈值、intoto Rekor v1 条目或任意 predicate 业务策略；不自动回退到较弱验证。
4. 尚未连接 Registry GET/HEAD、仓库/平台远端读回、OCI layer graph、approved policy 版本、构建 commit/builder allowlist、耐久防重放或不可变部署。
5. CLI 输出不是可导入的可信 receipt，不得以客户端提供的 `verified=true` 或 JSON 成功报告替代重新验签和独立证据绑定。
6. 未接入控制面发布/恢复执行器，没有安装到 .240/.249/.254，没有更改 DNS、路由、ERP 或任何生产容器；原九项 blocker 保持不变。

本阶段只推进镜像来源验证底座，不代表整个澄网项目、M2b、M3、M4 或企业运营验收完成。
