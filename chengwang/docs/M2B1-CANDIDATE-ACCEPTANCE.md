# M2b-1 候选容器与闭环验收

## 1. 结论先行

M2b-1 目前包含 **隔离护栏候选、真实 probe-agent 的本地实现、默认关闭的独立主动代理容器定义和验收工具**，不是主动探针上线。护栏程序仍只做严格 catalog 解析、spool 可写性检查、存活记录和优雅停止，协议固定声明 `activeProbes=false`。`probe-agent` 已完成固定 DoT、启动账本、证据 spool、崩溃恢复、调度器集成、严格进程健康协议和结构化启动前校验；主动代理另有停机一致性备份、恢复暂存和启动前证据绑定脚本，但启动和恢复切换均继续失败关闭。静态 canary 合同与供应链证据候选已能发现结构和摘要矛盾，但两者始终返回 `BLOCKED/78`，既不观测真实业务，也不执行密码学验签或 Registry 读回。单独的 `compose.probe-agent.yaml` 仅在显式 profile 下存在，当前仍接入 `internal` quarantine 网络。该静态定义只表达无公网默认出口意图，不能证明宿主或同网段路径已 deny-all。Linux 静态门禁已在独立 GitHub Actions runner 上通过；当前开发机仍没有 Docker，因此镜像构建、容器运行态、唯一出口和 canary 仍须在隔离 Linux 候选机执行后才能签署。

最新已签署的 Linux 静态证据为 GitHub Actions run `39167275180`、job `117792733320`、提交 `fcd6887fb70b37d911c82876a55506195b6e83b3`：Ubuntu 24.04.5、Linux 6.17.0-1022-azure x86_64、Go 1.23.12/linux-amd64；Python 离线门禁 141 项、测试用例 0 skip、11 个 schema；13 个生命周期 shell 脚本语法通过；Go 普通与 race JSON 合计 2882 个语义 run event、27 个包、测试用例 0 skip，并执行 `go vet ./...`。11 份 Draft 2020-12 schema 已由固定的 `santhosh-tekuri/jsonschema/v6 v6.0.3` 编译并验证正反实例。固定摘要的 Python 阶段保持无网络、只读源码挂载；Go/Shell 阶段在无网络、无 capabilities、禁止提权的命名空间内运行，并在退出前证明工作树没有残留修改。该任务结论为 `success`，但仍明确输出 `DOCKER_BUILD=BLOCKED_UNPINNED_BASE_IMAGES`；固定摘要测试镜像不是产品供应链验收。

恢复状态基础库与同内核故障注入的最新权威证据为 GitHub Actions run `39156376057`、job `117760331614`、提交 `ec71f05d41d52284bb5aada822223095d1a7c1d4`，结论为 `success`。Ubuntu 24.04.5 / Linux 6.17.0-1022-azure / Go 1.23.12 环境中，固定摘要、无网络、只读根文件系统、capabilities 全清且禁止提权的容器以 root 身份在真实 ext4/XFS bind 路径执行了 14 个 `proberestore` 顶层 Linux 场景，并精确覆盖 8 个原子替换故障点；结果为 `PROBE_RESTORE_ROOT_GATE=PASS linux_root_scenarios=14 fault_stage_cases=8 skips=0 filesystem=ext4-or-xfs`。测试包括 rename 前后真实 SIGKILL、重开读回、目录同步失败中毒、合法孤儿清理以及恶意链接/权限/类型对象失败关闭；全仓普通与 race JSON 合计 2416 个 run event、25 个包、测试用例 0 skip，并继续通过 132 项 Python、13 个 shell 脚本和 `go vet ./...`。该证据只签署同一 Linux 内核下的进程崩溃可见性、root/ext4-XFS 系统调用路径及静态门禁，不签署突然断电、VM/宿主崩溃、Docker live 切换或生产恢复；schema metaschema 和产品镜像构建仍明确阻断。

以下四项仍是进入真实主动路径候选的阻断条件：

1. `probe-agent` 容器候选文件尚未完成 Linux/Docker 构建、运行和故障注入；
2. 自有、无副作用、带版本化合同标记的 canary 尚未实际提供、密码学批准并完成运行时观测；当前只有静态合同校验候选；
3. 独立 bridge 只提供隔离，不提供“唯一公网出口”证明；需要宿主机/外部防火墙或专用网关的出站策略与独立读回证据；
4. Docker 基础镜像尚未锁定经过真实验签与 Registry 读回的 digest，也未形成可信 SBOM/来源证明；当前只有始终阻断的结构一致性校验候选。

所以当前状态应写成：`guard and probe-agent implemented+tested local-only; active container files statically checked; Docker runtime and egress not proven; active path blocked`。

## 2. 候选架构边界

```text
只读 catalog ─────┐
                  v
        candidate-guard 或单独 profile 的 probe-agent (uid 10001)
        ├─ read-only rootfs
        ├─ cap_drop: ALL
        ├─ no-new-privileges
        ├─ CPU 0.25 / RAM 护栏 64 MiB、主动代理 96 MiB / PID 64
        ├─ 独立 tmpfs health
        └─ 独立候选 spool；probe-agent 另有独立 ledger
                  |
                  v
        internal Docker bridge
        （无端口、无生产卷、无 Controller、无公网证明）
```

生产控制面、OpenClash、Mihomo selector、DNS 和候选不共享数据卷，也不向候选提供令牌。候选没有写 API、Docker socket、host PID/IPC/网络或生产控制通道。

真实 probe-agent 使用单独的默认关闭 Compose/profile，不能与护栏同时被解释为同一份运行证据，也不能放宽上述权限。若需要公网探测，必须先在容器外建立默认拒绝的 egress enforcement，并用网络命名空间/防火墙计数器/独立出口身份同时证明允许与拒绝路径；给普通 Docker bridge 增加默认路由或在策略 JSON 中自报 `enforced` 都不算通过。

## 3. 验收证据矩阵

| 门禁 | 权威证据 | 当前状态 | 失败处理 |
|---|---|---|---|
| 源码正确 | `go test ./...`、`go test -race ./...`、`go vet ./...`、显式 Linux/amd64 二进制构建 | test/race/vet 已在 Linux CI 通过；两项 `CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build` 尚未由该工作流执行 | 未补齐显式二进制构建前不构建候选镜像 |
| catalog 严格性 | M2b-0 测试 + guard 无效 catalog 注入 | 本地测试已覆盖一部分；容器注入待运行 | 失败关闭 |
| 非 root / 只读 / capabilities | `docker inspect` + 容器内写入负测 | 待候选机运行 | 删除候选，不发布 |
| CPU/RAM/PID | `docker inspect` 精确值 | 待候选机运行 | 删除候选，不发布 |
| catalog/spool 边界 | Mount `RW` 读回 + 写入正负测试 | 待候选机运行 | 删除候选，保留日志 |
| 健康检查 | 护栏固定 `activeProbes=false`；主动代理严格验证 tmpfs 心跳、catalog digest、scheduler/clock/storage 且固定 `advisoryOnly=true` | 两套单测通过；运行态待验证 | 容器 unhealthy，不自动升级；不得推导业务健康 |
| 优雅停止 | SIGTERM 日志 + 20 秒停止窗口 + 重启持久性 | 待候选机运行 | 保留旧镜像和 spool |
| 隔离 bridge | 网络对象 `Internal=true`、无发布端口 | 待候选机运行 | 不开放 egress |
| 唯一出口 | 防火墙/网关默认拒绝、允许列表、计数器和独立出口读回 | `blocked` | 禁止真实探测 |
| 固定可信 DNS | 固定 DoT IP:port、TLS/SNI/CA、DNS 帧/记录边界、A/AAAA CNAME 一致性和重绑定注入 | 本地实现与测试通过；容器运行态未验 | 禁止真实探测 |
| 自有 canary | 所有权、无副作用、合同版本、频率和限流批准 | `blocked` | 禁止公共目标 |
| 出口 bootstrap | 双栈 bridge、宿主 INPUT/FORWARD 默认拒绝、显式 chain、计数器与回滚摘要 | 离线结构计划和本地测试已实现；Docker/netns/nft 安装及读回未执行，固定 `BLOCKED/78` | 不执行计划；保留现有 `internal` quarantine |
| Linux 静态 CI | 固定 Python 测试镜像、零网络、零 capabilities、Python 阶段源码只读、root/ext4-XFS 恢复系统调用与同内核故障注入、Go/Shell 阶段退出前工作树 clean，以及 Python/Go/Shell/race/vet 门禁 | `PASS`：run `39169948542` / job `117800728560` / commit `074d560...`；Ubuntu 24.04.5 / Linux 6.17 / Go 1.23.12；`proberestore` 14 个 Linux root 顶层场景和 8 个故障点；`restoreevidence` 11 个顶层场景、16 个关键子场景和 20 个故障点；blocked coordinator model 1 个真实 store 重开场景并固定 `authorization=BLOCKED_TRUSTED_INPUTS_MISSING`；141 个 Python 测试、13 个 shell 脚本、Go 普通/race/vet；2932 个 Go 语义 run event、28 个包、测试用例零 skip；11 份 Draft 2020-12 schema 经固定验证器编译并验证正反实例 | 后续 CI 失败保持 M2b 启动阻断，不降级到旧成功或 Windows 结果；不得扩大为可信输入、掉电、VM/宿主崩溃、Docker 构建、签名验真或 live 恢复证明 |
| 生产不变 | 前后 hash-only manifest 完全一致 | 工具已提供，未在生产运行 | 任一变化立即停止并调查 |
| 备份/回滚 | 专用根标记、停机一致性包、类型/数量/尺寸边界、SHA-256、保留失败副本、恢复后重验 | 护栏与主动代理备份工具均已提供、均未在 Docker 候选机演练；主动代理已实现只读 spool+ledger 语义验证及归档前后报告全等，恢复只验证私有暂存且不触碰 live，切换仍阻断 | 主动代理禁止启动；不得手工切换暂存状态或清理旧副本 |

“当前开发机没有 Docker”是缺少运行证据，不是失败，也不能写成通过。

## 4. 分阶段执行顺序

### A. 源码门禁

在 `chengwang` 目录执行：

```sh
gofmt -w cmd/probe-agent deploy/m2b-candidate/cmd/candidate-guard
go test -count=1 ./...
go test -race -count=3 ./cmd/probe-agent ./internal/probe ./deploy/m2b-candidate/cmd/candidate-guard
go vet ./...
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/m2b-candidate-guard ./deploy/m2b-candidate/cmd/candidate-guard
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build -trimpath -o /tmp/m2b-probe-agent ./cmd/probe-agent
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

上述双目录切换只适用于护栏候选 spool，不是主动代理或生产控制面的回滚。主动代理另有同一 `probe-state` 单元下的 probe-spool、probe-ledger、三份只读配置与独立镜像；专用备份脚本已覆盖这些输入并始终把候选留在停止状态。它先验证 live，归档后再解包复验，报告不全等就不发布；合法 retention 缺失会显式降级。专用恢复脚本只做严格复制、清单/结构/身份验证、私有暂存和语义复验，不停止或修改 live，并在实际切换前固定返回 78。因此当前可签“备份与恢复输入语义验证已实现（本地静态证据）”，不能签“恢复成功”或“回滚演练通过”。生产仍使用其现有备份和回滚镜像，M2b 候选不得修改或重启它。

`internal/proberestore` 现提供恢复执行器的失败关闭基础：25 个阶段、全部 25×16 拓扑组合、严格事件哈希链、单一原子 `control.json`、操作/备份/manifest 三重防重、单写者锁，以及 ext4/XFS 上的临时文件写入、文件 `fsync`、`renameat`、目录 `fsync` 和 inode 读回。Windows 只允许诊断读取，写入返回不支持。同内核 root 测试已覆盖八个原子替换故障点、rename 前后 SIGKILL/reopen、目录同步失败和孤儿临时对象处理。

`internal/restorecontracts` 新增四类严格版本化合同：backup v3 绑定镜像、Compose、配置、状态树和归档摘要；恢复证据 v1 绑定阶段、原因、序列、boot/boottime、拓扑和原始字节摘要；anchor v1 与 receipt checkpoint v1 绑定外部后端、对象键、CAS 预期版本、签名元数据和 receipt 索引。解析结果使用不透明类型，state-only 恢复仍会重新验证完整绑定。Schema 与 Go 语义通过差分测试保持一致，Go JSON 签章器固定 226 个通过名称的指纹，并显式拒绝 fail、skip、缺 terminal pass 和没有先行 run 的 pass。

`internal/restoreevidence` 已实现严格合同解析后的本地不可覆盖落盘。Linux 路径要求 root:root、目录 `0700`、文件 `0600`、普通文件、单链接、同设备和同 mount ID，并按“临时写入 → 文件 fsync → 临时目录 fsync → `linkat` no-clobber → 发布文件 fsync → 提交目录 fsync → 临时项清理与目录 fsync → 原始字节回读”执行；故障状态区分 `NotCommitted`、`Uncertain` 和 `Committed`，post-link 不确定性会中毒并保留现场。单写者锁、目录项上限、orphan、路径替换、软硬链接、时钟回拨、boot 变化和原始字节变异均失败关闭。Windows 不提供可靠发布，只返回独立的 `DIAGNOSTIC_ONLY` 结果，并拒绝 ADS、设备名及歧义叶名。

`internal/restorecoordinator` 当前只是明确阻断的 pre-live 模型：它验证“证据先提交并按原字节回读，再推进 journal”、split-commit 重试、尾事件全等和 `INPUT_VERIFIED` 边界，但没有公开生产构造器。`Prepare` 的当前时间、当前配置和旧状态摘要仍是模型输入，不能证明来源独立；全局 lifecycle lease、可信 current-state collector 和生产 Resume/Reconcile 尚未实现。因此 CI 只能输出 `authorization=BLOCKED_TRUSTED_INPUTS_MISSING`，不得把模型中的 `LOCKED` 或 `INPUT_VERIFIED` 当成真实授权状态。

这些合同和本地存储不采集业务证据、不验证签名真伪、不访问真实 CAS/WORM，也不控制 Docker 或交换 live 状态；fresh `Open` 后仍无法独立发现整个有效 control 目录或磁盘快照被回滚。后续仍须实现把采集、签名验证、外部 CAS/WORM、单调锚点和本地 store 串接起来的 evidence coordinator，以及突然断电/VM 或宿主崩溃注入和 receipts 归档轮换。产品镜像仍因基础镜像标签未锁摘要而保持构建阻断。在这些门禁完成前，`restore-probe-agent.sh` 继续固定返回 78。

## 6. 进入真实主动探针前的退出条件

只有以下证据全部存在，才允许把 M2b-1 从“护栏候选”升级为“主动路径候选”：

1. probe-agent 独立命令已通过单元和 race；仍须通过 Linux 容器故障注入；
2. resolver 返回从原 host 开始的完整 CNAME 链，固定到明确的 DoT IP:port，并验证 TLS/SNI/CA、DNS-over-TLS 帧边界、A/AAAA 链一致性，拒绝系统搜索域、mDNS、hosts 覆盖和动态 resolver 漂移；
3. 每次解析后的全部 A/AAAA 与建连前固定 IP 均通过特殊地址策略，TLS SNI 保留原 host；
4. egress 层默认拒绝，只有固定 resolver 和批准目标/网关可达，并有拒绝测试与计数器读回；
5. canary 所有权、内容合同、限流、隐私和无副作用得到书面批准；
6. 启动预算跨重启耐久，重复/时钟回拨/存储降级继续失败关闭；
7. 候选前后不变门禁通过，且 M2a 24 小时浸泡已签署；
8. 主动代理的 spool、ledger、catalog、DoT CA、出口策略和镜像形成同一备份/恢复单元，且实际演练通过。

本地已实现不等于上述退出条件已经签署。默认护栏 Compose 仍只运行 `candidate-guard`；单独的主动代理 Compose 需要显式 profile，blocked 示例会拒绝启动，且当前没有获批出口或 Docker 运行证据。

在这些条件完成前，不创建生产定时任务、不开放 API、不显示“节点能力已验证”，也不将护栏容器部署到生产。
