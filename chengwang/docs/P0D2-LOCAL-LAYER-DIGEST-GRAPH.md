# P0-d2 本地镜像层摘要图

## 已实现的代码边界

新增 `ValidateLocalLayers(ctx, Expected, manifestJSON, configJSON, [][]byte)`，在原有 P0-d1 校验后按 manifest 顺序校验全部 layer 字节。输入为调用者已经取得的内存切片；模块不接收文件路径、任意 Reader、网络地址或取数回调。调用期间输入必须由调用方独占，结束后可以释放或修改。

每层需要同时满足：

```text
len(原始 blob) == manifest.layers[i].size
SHA-256(原始 blob) == manifest.layers[i].digest
SHA-256(完整解压结果) == config.rootfs.diff_ids[i]
```

原始 OCI 层以原字节作为解压结果；OCI gzip 和 Docker gzip 层只支持单个 gzip member。gzip 必须完整读取至 EOF，以验证 CRC 与 ISIZE；截断、损坏、尾随垃圾、尾随零字节及第二 member 都拒绝。media type 决定解码方式，不依据 magic bytes 自动切换。允许重复层，但每次出现都重新校验并计入总预算。

成功输出不透明 `LayerGraph`，只保留已验证的 `Content`、层数、原始/解压字节总量和版本化图摘要。边界为 `ADVISORY_LOCAL_OCI_DIGEST_GRAPH_BOUND`，没有可序列化授权或执行能力；`Graph.Content() → BindLocal` 仍保留原有诊断边界、`authorization=BLOCKED` 与全部九项 blocker。

## 固定资源与取消约束

| 约束 | 上限 |
|---|---:|
| 层数 | 128 |
| 单层原始输入 | 128 MiB |
| 全部原始输入 | 512 MiB |
| 单层解压输出 | 512 MiB |
| 全部解压输出 | 1 GiB |
| 单层膨胀预算 | max(1 MiB, 原始长度 × 200)，同时受单层和总解压上限约束 |

这些是处理预算，不代表输入已经通过 tar 或镜像规范验收。输入内存由调用方持有；解码使用固定 32 KiB 输出缓冲及标准库 gzip 工作内存，不按解压总量分配完整输出。

取消同时覆盖原始哈希、解压输入和解压输出。独立复核曾发现“仅限制输出 Read”会漏掉包含大量空 deflate 块的取消延迟，现加入同时实现 Read/ReadByte 的输入适配器，每至多 32 KiB 压缩输入检查一次 context。测试使用合法的两万个空 stored block、空输出 gzip 确认解码途中取消，不依赖定时 sleep 或 goroutine 调度。

任何失败都只返回零 `LayerGraph` 与固定 `ErrInvalid`；不把底层压缩错误、context 原因、配置内容或 layer 内容放进错误。取消是协作式的字节检查，不保证墙钟实时中断或操作系统调度时延。

## 保留的缺口

本阶段验证的是有序摘要图，不解析 tar。任意非 tar 数据或空输出，只要字节摘要链正确，也可形成图；测试专门保留该事实。因此不能据此宣称路径、链接、whiteout、overlay 结果、文件系统展开或完整镜像规范安全。

没有 Registry GET/HEAD、RepoDigests/平台独立读回、Sigstore/DSSE/X.509/Rekor、独立审批信任根、耐久防重放、不可变部署或真实 Capture→BindLocal。旧 Python 供应链验证器继续保持 BLOCKED，其 tar/文件系统检查没有被本模块替代。多成员 gzip 与 zstd 仍在当前支持范围之外。

本阶段没有部署或控制容器，也未改变旁路由、DNS、ERP 服务或生产流量。`DEPLOYMENT-240-PREFLIGHT.md` 单独记录了 10.88.0.240 的只读环境检查。

## 验收

普通/race 测试覆盖 raw、gzip、Docker、混合层、重复层与空输出，分别破坏原始摘要、diff_id、长度、层序、压缩校验码、头/尾、member 数及各项小预算；另检查原始压缩表示改变时图摘要随之变化、调用后释放输入不影响结果、途中取消以及关联后九项 blocker 不变。

Go AST 门禁仅增加经过审查的 `compress/gzip` 和 `context` 标准库导入；文件、网络、shell、Docker 和恢复执行依赖继续拒绝。整仓 Linux 门禁继续要求 ordinary/race 的测试名称精确指纹与零 skip。CI 结果以实际 run 与 commit 记录，不预填成功结论。
