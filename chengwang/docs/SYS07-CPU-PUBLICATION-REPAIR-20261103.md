# CPU 失败摘要发布修复

开发基线为 c64872682817c39fbf8c78704a3cc8df68a3b7a3。旧工作流的详细诊断投影可能被隐私或 I/O 检查拒绝，而 always 上传配合 missing warn 不能证明产物存在。该基线的 joint run41479327908 在 CPU/Go 步骤失败，CPU artifact 缺失；实际失败原因仍未知。

修复保留全部隐私上限。详细诊断失败时，独立固定大小的 CPU_DIAGNOSTIC_UNAVAILABLE 分类不读取、统计或哈希私有文件。所有摘要先写入 staging，仅从严格白名单中选择一个、缓存核验后原子发布。预存 private/stage/public 路径、目录创建失败、状态文件写入失败、发布失败和 GITHUB_OUTPUT 写入失败均令步骤失败。只有发布成功且 ready 写入成功后才允许上传；missing artifact 使用 error。

底层模型或 Go 非零仍是失败。fallback 仅表示详细诊断不可用，不表示 Go 根因已知。此改动不改 Go 测试、RBAC、内核、业务验收或生产流量。

独立审查保留两次拒绝：v1 未正确阻断预存 public 上传；v2 未检查 ready 写入失败。v3 闭合这两项及关键 I/O 非零传播；exact-c648 投影再次获 SOURCE_ACCEPT。本地正式 joint producer 实际退出 0，47/47 合成模型通过；841 来源路径仅两个 Python 来源行改变，其余839行不变。P207 正式来源检查仍为491必需测试，未执行本地 Go。

证据：

- [v1 拒绝](evidence/sys07-cpu-fallback-v1-rejected-20261103.json)
- [v2 拒绝](evidence/sys07-cpu-fallback-v2-rejected-20261103.json)
- [v3 独立审查](evidence/sys07-cpu-fallback-v3-peer-20261103.json)
- [c648 投影](evidence/sys07-cpu-fallback-c648-projection-20261103.json)
- [投影独立审查](evidence/sys07-cpu-fallback-c648-peer-20261103.json)
- [root 47项执行收据](evidence/sys07-cpu-fallback-root-joint47-20261103.json)

当前 Go 验收仍拒绝：[P207 c648审计](evidence/sys07-p207-c648-rejected-20261103.json)为489通过、2失败、0运行、0未启动，格式通过，fresh跳过。失败测试为 TestSealedArchiveV8AllControlStatesAndCheckpoint 和 TestSealedArchiveV8PrimitiveAndNameBoundaries，具体动态断言消息仍未知。本文与47项模型通过均不代表已修复这两个 Go 失败或真实业务已验收。

生产环境未改，原main未合并。本修复仅进入开发分支，仍须在隔离 Linux CI 核查实际失败摘要发布效果。
