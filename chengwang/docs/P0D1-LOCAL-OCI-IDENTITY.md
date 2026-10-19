# P0-d1 本地 OCI 字节与运行态镜像关联

## 实现与验收范围

`internal/restoreimage` 新增纯内存校验与关联 API：

```go
ValidateLocal(Expected, manifestJSON, configJSON) (Content, error)
BindLocal(Content, restoreruntime.Observation) (Association, error)
```

`Expected` 是调用者提供的本地预期，尚无独立审批签名。`Content` 和 `Association` 的字段不对调用者开放，不提供 JSON 解码入口或执行能力。失败只返回零结果与固定错误，成功关联仍固定 `authorization=BLOCKED`，九项既有 blocker 全部保留。

三类摘要逐项关联，绝不互相替代：

```text
预期 reference 的 manifest digest
    == SHA-256(原始 manifest 字节)
manifest.config.digest
    == SHA-256(原始 config 字节)
    == P0-c observation.ImageID()
```

`Content` 边界为 `ADVISORY_LOCAL_OCI_BYTES_BOUND`；`Association` 边界为 `ADVISORY_LOCAL_IMAGE_ASSOCIATION`。当前只是未部署的仓库候选。

## 校验规则

- 只接受显式 registry/repository@sha256 引用的规范子集；拒绝 tag、URL、账户密码、转义、空白、查询参数和不规范端口。不支持 IPv6 literal registry 或完整 OCI repository 名称语法的所有扩展。
- 只接受 OCI image manifest v1 或 Docker schema2 的单平台镜像；本阶段拒绝 index、多平台选择、artifact、外部 URL、内联 data、foreign layer、zstd 和空层镜像。
- 原始 manifest 与 config 各不超过 1 MiB；JSON 深度最多 32，值节点最多 32768；拒绝任意深度的重复键、关键字段大小写别名、未知关键字段、非法 UTF-8、尾随值和关键字段 null。
- config descriptor 的摘要、字节长度和 media type 必须匹配输入；layer descriptor 只接受小写 SHA-256、正整数长度和受支持的 media type，最多 128 层、单个声明尺寸最多 512 MiB。
- 平台预期只接受 linux/amd64 或 linux/arm64（variant 为空或 v8），config 平台必须精确匹配；rootfs 必须为 layers，diff_ids 的数量必须等于 manifest layer 数，格式必须有效。
- 标准 config.Env、Cmd、history 和 annotations 可参与原始摘要绑定，结果和错误都不保留、回显这些内容。
- `BindLocal` 只接收 P0-c 的 opaque Observation；验证其 schema、诊断边界、阻断状态、candidate/container/runtime 摘要以及精确九项 blocker，返回 blocker 副本。
- Go AST 门禁约束生产源文件的导入和跨包引用，防止新增文件、网络、shell、Docker 或恢复执行能力。

输入 byte slice 在调用期间必须由调用方独占，调用结束后可以修改或释放。并发修改同一 slice 属于调用方数据竞争，不在 API 保证内。

## 明确保留的缺口

本阶段没有 layer blob 输入，因此不验证 layer 字节、解压 diff_id、tar 文件系统或完整镜像图。config 的平台字段是本地字节声明，尚未与独立 Registry 或 daemon 平台事实核对。

同一份 manifest/config 可以由调用方配上另一个语法合法的 repository 引用并通过本地校验；测试专门保留这个事实，防止把摘要一致误称为仓库所有权认证。没有执行 Registry GET/HEAD、验证 Docker-Content-Digest、RepoDigests、Sigstore/DSSE、X.509、Rekor、审批策略签名、可信时间或耐久防重放。

关联对象只说明传入的 P0-c 过去样本所记录的本地 image ID 与 config 原始字节摘要一致。它不重新采集当前容器，不延长下层 handle 的有效期，也不证明 Compose 使用了不可变部署引用。现有 Compose 继续使用 release tag；只有后续独立来源、不可变部署和运行态读回都成立，才能讨论解除镜像 blocker。

因此本阶段不接入恢复协调器、不发布 accepted 授权 schema、不执行部署或容器控制。生产旁路由与 OpenClash 均未改变。

## 验收与下一阶段

测试包含原始字节变化但语义相同、manifest/config 摘要混用、descriptor/平台/rootfs 漂移、JSON 歧义与资源边界、敏感内容不泄漏、零观察值和 blocker 变异。内部 `bindFacts` 使用合成 runtime facts 测试关联规则；它不是一次真实 `Capture → BindLocal` 的端到端证明。

首次集成复核曾发现 consumer 错把 Candidate ID 当成 SHA-256 摘要，而 producer 实际格式是 `candidate-<32 lowercase hex>`，导致合法样本被拒绝。该问题已修正，并新增直接解析上游 `restorecurrent/identity.go` 格式合同的测试，避免合成样本再次掩盖两层格式不一致。

本阶段沿用整仓 ordinary/race/vet 和 Linux offline static gate，并登记测试名称精确指纹。CI run、commit、结果必须以实际返回记录；本文件不预先宣称 CI 或生产验收成功。

2026-10-19 已核实的 Linux 仓库验收：commit `23d3d41d2f2b42d22c5fa7a9c7ce2247557eeb51`，GitHub Actions [run 39208841021 / job 117917487408](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39208841021/job/117917487408)，结论 `success`。`restoreimage` ordinary/race 两份 transcript 各精确通过 201 个 Test 场景；整仓 `GO_JSON_GATE=PASS files=2 semanticRunEvents=3870 packages=36 skips=0`，158 个 Linux Python 测试、11 份 schema metaschema、Go vet 与既有真实 Docker fixture 门同步通过。该结果不包含本模块真实 Capture→BindLocal、独立来源验签或生产部署。

后续 P0-d2 需选择并锁定标准 Sigstore 验证器与独立信任根，完成 layer/Registry 字节读回、签名与 provenance、审批策略和持久防重放，再建设与真实候选运行态的集成测试。现有 `supply-chain/verify_supply_chain.py` 保持结构预检及固定 BLOCKED，不以外部布尔回执替代验签。
