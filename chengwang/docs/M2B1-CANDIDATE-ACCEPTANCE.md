# M2b-1 候选容器与闭环验收

## 1. 结论先行

M2b-1 目前新增的是 **可构建的隔离护栏候选、真实 probe-agent 的本地实现和验收工具**，不是主动探针上线。护栏程序仍只做严格 catalog 解析、spool 可写性检查、存活记录和优雅停止，协议固定声明 `activeProbes=false`。`probe-agent` 已完成固定 DoT、启动账本、证据 spool、崩溃恢复和调度器集成，但尚未放进候选 Compose。当前开发机没有 Docker，因此源码与 Go 测试可以验收，容器运行态仍须在隔离 Linux 候选机执行后才能签署。

以下四项仍是进入真实主动路径候选的阻断条件：

1. `probe-agent` 尚未容器化并接受 Linux/Docker 故障注入；
2. 自有、无副作用、带版本化合同标记的 canary 尚未提供和批准；
3. 独立 bridge 只提供隔离，不提供“唯一公网出口”证明；需要宿主机/外部防火墙或专用网关的出站策略与独立读回证据；
4. Docker 基础镜像尚未锁定经过验证的 digest，也未生成候选 SBOM/来源证明。

所以当前状态应写成：`guard and probe-agent implemented+tested local-only; container runtime not yet verified; active path blocked`。

## 2. 候选架构边界

```text
只读 catalog ─────┐
                  v
        candidate-guard (uid 10001)
        ├─ read-only rootfs
        ├─ cap_drop: ALL
        ├─ no-new-privileges
        ├─ CPU 0.25 / RAM 64 MiB / PID 64
        ├─ /run/m2b (tmpfs health)
        └─ /var/lib/chengwang-probe (独立候选 spool)
                  |
                  v
        internal Docker bridge
        （无端口、无生产卷、无 Controller、无公网证明）
```

生产控制面、OpenClash、Mihomo selector、DNS 和候选不共享数据卷，也不向候选提供令牌。候选没有写 API、Docker socket、host PID/IPC/网络或生产控制通道。

未来真实 probe-agent 只能替换护栏进程，不能放宽上述权限。若需要公网探测，必须先在容器外建立默认拒绝的 egress enforcement，并用网络命名空间/防火墙计数器/独立出口身份同时证明允许与拒绝路径；给普通 Docker bridge 增加默认路由不算通过。

## 3. 验收证据矩阵

| 门禁 | 权威证据 | 当前状态 | 失败处理 |
|---|---|---|---|
| 源码正确 | `go test ./...`、`go vet ./...`、Linux/amd64 构建 | 待集成者总验收 | 不构建候选 |
| catalog 严格性 | M2b-0 测试 + guard 无效 catalog 注入 | 本地测试已覆盖一部分；容器注入待运行 | 失败关闭 |
| 非 root / 只读 / capabilities | `docker inspect` + 容器内写入负测 | 待候选机运行 | 删除候选，不发布 |
| CPU/RAM/PID | `docker inspect` 精确值 | 待候选机运行 | 删除候选，不发布 |
| catalog/spool 边界 | Mount `RW` 读回 + 写入正负测试 | 待候选机运行 | 删除候选，保留日志 |
| 健康检查 | tmpfs 心跳新鲜度、状态固定 `activeProbes=false` | 单测通过；运行态待验证 | 容器 unhealthy，不自动升级 |
| 优雅停止 | SIGTERM 日志 + 20 秒停止窗口 + 重启持久性 | 待候选机运行 | 保留旧镜像和 spool |
| 隔离 bridge | 网络对象 `Internal=true`、无发布端口 | 待候选机运行 | 不开放 egress |
| 唯一出口 | 防火墙/网关默认拒绝、允许列表、计数器和独立出口读回 | `blocked` | 禁止真实探测 |
| 固定可信 DNS | 固定 DoT IP:port、TLS/SNI/CA、DNS 帧/记录边界、A/AAAA CNAME 一致性和重绑定注入 | 本地实现与测试通过；容器运行态未验 | 禁止真实探测 |
| 自有 canary | 所有权、无副作用、合同版本、频率和限流批准 | `blocked` | 禁止公共目标 |
| 生产不变 | 前后 hash-only manifest 完全一致 | 工具已提供，未在生产运行 | 任一变化立即停止并调查 |
| 备份/回滚 | 专用根标记、停机一致性包、类型/数量/尺寸边界、SHA-256、保留失败副本、恢复后重验 | 工具已提供，未演练 | 不得清理旧副本 |

“当前开发机没有 Docker”是缺少运行证据，不是失败，也不能写成通过。

## 4. 分阶段执行顺序

### A. 源码门禁

在 `chengwang` 目录执行：

```sh
gofmt -w deploy/m2b-candidate/cmd/candidate-guard
go test -count=1 ./...
go test -race -count=3 ./internal/probe ./deploy/m2b-candidate/cmd/candidate-guard
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/m2b-candidate-guard ./deploy/m2b-candidate/cmd/candidate-guard
```

这些命令只证明代码与目标平台可构建，不证明容器或网络状态。

### B. 生产周边只读基线

在任何候选动作前，用 `capture-baseline.sh` 生成 `before.hashes`。脚本只保留哈希，原始 Controller/UCI 临时材料退出即删除。输出目录权限必须为 `0700`，证据文件为 `0600`，不得提交 Git。

### C. 隔离护栏候选

运行 `verify-candidate.sh`。只有以下全部通过才能签署“候选容器护栏通过”：

- Compose 能解析并构建；
- uid/gid 为 `10001:10001`；
- 根目录和 catalog 不可写，spool 可写且不复用生产数据；
- `cap_drop=ALL`、`no-new-privileges`、非 privileged、无 host PID/IPC；
- CPU、内存、PID、文件描述符限制与声明一致；
- 无宿主端口和 Docker socket；
- 网络对象为专用 `internal` bridge；
- health record 新鲜，且始终声明 `activeProbes=false`；
- SIGTERM 优雅退出，重启后候选 spool 持久。

### D. 护栏故障注入

运行 `fault-injection.sh`，验证：

- 无效 catalog 导致非零退出；
- spool 只读导致非零退出；
- 停止心跳后 Docker health 变为 unhealthy；
- 恢复心跳后只恢复护栏健康，不产生探测结果。

DNS/TCP/TLS/HTTP/合同不匹配/429 等网络故障注入必须保持 `BLOCKED_NO_ACTIVE_AGENT`。这些仅在真实 agent、固定 resolver、自有 canary 和唯一出口门禁完成后执行。

### E. 前后不变门禁

候选验收后重新生成 `after.hashes`，运行 `compare-baseline.sh`。它必须输出 `UNCHANGED_GATE=PASS`。该门禁覆盖：

- 活动 OpenClash 配置内容与路径；
- OpenClash UCI；
- DHCP/DNS UCI 与 `resolv.conf`；
- selector 名称及当前选择；
- 生产澄网 Compose；
- 生产澄网镜像、用户、网络、安全限制、资源和运行/健康状态。

哈希范围外的状态仍然是未知，不能扩大结论。

## 5. 备份与回滚闭环

候选根必须是源码树内的默认 `runtime`，或 `/var/lib/chengwang-m2b-candidate/<单段实例名>`、`/srv/chengwang-m2b-candidate/<单段实例名>` 下带精确专用标记的管理员预建目录。脚本拒绝 `/opt/chengwang` 及全部后代、符号链接组件和独立/bind 子挂载，并且不对候选根本身执行 `chown/chmod`。规范化根路径以“实例名 + SHA-256 短摘要”派生独立 Compose 项目，并由 CLI `--project-name` 强制，避免同宿主多候选或环境变量互相重配。候选备份先核对容器身份与真实挂载，再停止候选，保存 catalog、整个候选 spool、不可变镜像检查结果和恰好覆盖三项的 `SHA256SUMS`。源树和生成归档都以流式方式检查，只允许普通文件/目录，并受 4096 项、128 MiB 展开尺寸和 128 MiB 压缩尺寸限制。

恢复使用双目录切换：先把三项备份与清单复制到私有暂存目录并全部校验，要求备份 catalog 与当前挂载内容一致、备份镜像 ID 与当前候选镜像一致，再以流式首遍检查压缩包的数量/尺寸/路径/类型，第二遍解包。通过后把旧 spool 改名为 `spool.failed.<timestamp>`，最后切入恢复目录。恢复成功后的暂存清理失败只产生明确告警，不把已经完成的数据切换误报为失败；只有旧 spool 实际存在时才报告保留路径。

恢复脚本要求绝对路径、合法候选根标记、容器组件标签与真实挂载源一致，并且必须设置确认短语。恢复后保持停止，重新执行候选验收；在全部通过前保留失败副本。

这只是候选 spool 的回滚，不是生产控制面的回滚。生产仍使用其现有备份和回滚镜像，M2b 候选不得修改或重启它。

## 6. 进入真实主动探针前的退出条件

只有以下证据全部存在，才允许把 M2b-1 从“护栏候选”升级为“主动路径候选”：

1. probe-agent 独立命令已通过单元和 race；仍须通过 Linux 容器故障注入；
2. resolver 返回从原 host 开始的完整 CNAME 链，固定到明确的 DoT IP:port，并验证 TLS/SNI/CA、DNS-over-TLS 帧边界、A/AAAA 链一致性，拒绝系统搜索域、mDNS、hosts 覆盖和动态 resolver 漂移；
3. 每次解析后的全部 A/AAAA 与建连前固定 IP 均通过特殊地址策略，TLS SNI 保留原 host；
4. egress 层默认拒绝，只有固定 resolver 和批准目标/网关可达，并有拒绝测试与计数器读回；
5. canary 所有权、内容合同、限流、隐私和无副作用得到书面批准；
6. 启动预算跨重启耐久，重复/时钟回拨/存储降级继续失败关闭；
7. 候选前后不变门禁通过，且 M2a 24 小时浸泡已签署；
8. 备份和回滚实际演练通过。

本地已实现不等于上述退出条件已经签署。尤其当前 Compose 仍运行 `candidate-guard`，不会调用 `probe-agent`。

在这些条件完成前，不创建生产定时任务、不开放 API、不显示“节点能力已验证”，也不将护栏容器部署到生产。
