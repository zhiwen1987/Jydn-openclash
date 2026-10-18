# M2b-1 隔离候选骨架

这个目录提供一个可以独立构建和验收的 **候选护栏容器**。它只验证 M2b 将来运行所需的容器边界，不执行 DNS 查询、不建立网络连接、不写入探测结果，也不连接 OpenClash/Mihomo Controller。

## 当前事实

| 项目 | 状态 | 可证明内容 |
|---|---|---|
| `candidate-guard` 程序 | 已实现、本地 Go 测试通过 | 严格读取 M2b catalog、检查独立 spool 可写、发出 `activeProbes=false` 的存活记录、响应 SIGTERM |
| Compose 隔离定义 | 已实现、尚未在当前工作站运行 | 非 root、只读根、全部 capability 丢弃、资源限制、只读 catalog、独立 spool、独立 internal bridge、无端口 |
| Docker 运行时验收 | 未执行 | 当前开发机没有 Docker；必须在隔离候选机运行脚本后才能签署 |
| 固定可信解析器 | 已实现、本地测试通过 | 固定 IP:port 的 DoT、TLS/SNI/CA 校验、完整有界 CNAME 链、A/AAAA 一致性；尚未做候选容器运行态验证 |
| 唯一允许出口 | `blocked` | `internal: true` 只能证明隔离，不能证明一个可用且唯一的公网出口 |
| `probe-agent` 命令 | 已实现、本地测试通过 | 启动账本先于网络、结果先入 spool 再结算、跨重启预算、崩溃恢复和严格进程健康协议；尚未完成容器运行态验收 |
| 主动探测容器定义 | 已实现、默认关闭、仅静态校验 | 独立 profile、非 root、只读根、同一 `probe-state` 下的独立 spool/ledger、健康 tmpfs；没有 Docker 构建或运行证据 |
| 主动代理生命周期门禁 | 已实现、仅静态校验 | 严格结构化 preflight、只读状态语义验证、全局/实例互斥锁、归档前后双重验证、无 live 变更的恢复私有暂存和启动前证据绑定；启动与恢复切换仍明确阻断 |
| 宿主出口取证候选 | 已实现、仅本地测试 | 最小投影采集 Docker/netns/nftables，并校验 IPv4/IPv6 规则与计数器；因出口架构合同尚未闭合，只生成 `BLOCKED` 报告 |
| 出口 bootstrap 离线计划 | 已实现、仅本地测试 | 编译专用双栈 bridge 的 `FORWARD`/`INPUT` 默认拒绝结构、chain 归属、计数器与精确回滚摘要；不执行 Docker/nft，固定 `BLOCKED/78` |
| 静态自有 canary 合同 | 已实现、仅本地测试 | 严格绑定 catalog、域名/CNAME、公网单播 IP、TLS 与 HTTP 预期；只生成 `BLOCKED` 报告，不替代运行时 DNS/TLS/HTTP 观测或书面审批验签 |
| 镜像供应链证据候选 | 已实现、仅本地测试 | 严格检查 OCI、layer/diff ID、SPDX、DSSE/bundle/receipt 的结构和摘要；因没有真实密码学验签、Registry 读回和 Linux 候选机证据，只生成 `BLOCKED` 报告 |
| 主动业务探针 | `blocked` | 自有 canary、唯一出口、宿主防火墙计数器和容器运行门禁未完成；`internal` quarantine 只表达无公网出口意图，运行态 deny-all 未证明 |
| 生产部署 | 未执行 | 本目录不得直接替换 `/opt/chengwang` 的生产控制面 |

`probe.invalid` 是故意不可用的文档占位目标。不得把它替换为公共业务域名后直接运行。真实目标必须先成为自有、无副作用、版本化合同端点，并获得审批。

## 本地隔离验收

在安装了 Docker Compose v2 的 Linux 候选机上：

```sh
cd chengwang/deploy/m2b-candidate
cp .env.example .env
sudo sh scripts/verify-candidate.sh
sudo sh scripts/fault-injection.sh
```

默认根目录固定为本目录的 `runtime`；首次运行验收脚本时，在候选根目录范围内只会创建根目录、专用标记和 `spool`。验收还会按 Compose 构建并启动独立镜像、容器和网络。脚本不会修改候选根目录本身的属主或权限，只会把专用 `spool` 设为 uid/gid `10001:10001`、模式 `0700`。

验收脚本会按“实例名 + 规范化候选根路径摘要”派生独立项目名，构建并启动对应护栏候选，验证容器约束、读写边界、健康检查、优雅停止、重启持久性、无效 catalog 失败关闭、只读 spool 失败关闭和心跳停滞检测。结束时容器保持运行，仍处于无公网出口的隔离网络。

脚本输出的以下三项必须继续显示 `BLOCKED`，否则属于事实误报：

```text
ACTIVE_PROBE_EXECUTION=BLOCKED_SEPARATE_PROFILE_EGRESS_AND_RUNTIME_UNPROVEN
FIXED_TRUSTED_RESOLVER=IMPLEMENTED_LOCAL_ONLY_RUNTIME_NOT_PROVEN
UNIQUE_EGRESS_ENFORCEMENT=BLOCKED_NOT_PROVEN
```

## 主动探测候选文件

`compose.probe-agent.yaml` 是单独的 Compose 文件，服务只存在于显式 profile `active-probe-candidate`。示例 `.env.probe.example`、`catalog.canary.example.json` 和 `egress-policy.example.json` 故意包含阻断值；直接复制不会得到可运行探针。`Dockerfile.probe-agent.dockerignore` 只放行构建主动代理所需的最小源码，不扩大护栏镜像上下文。

离线门禁要求配置路径和权限精确固定：`config/` 必须为 `root:10001`、`0750`；容器只读挂载的 `catalog.json`、`dot-ca.pem`、`egress-policy.json` 必须为 `root:10001`、`0640`、硬链接数 1；不挂载进容器的 `probe.env` 必须为 `root:root`、`0600`、硬链接数 1。四个文件只能使用候选根下这些固定名称，避免可写父目录、不可读配置和路径别名造成静态通过、运行失败。

在任何构建或启动之前，只能先运行纯离线校验器。它不调用 Docker、不解析 DNS、不访问网络、不安装防火墙，也不启动容器、探针或网络服务；它只调用有界的本地只读检查工具。即使校验通过，最后仍固定报告 Compose 未解析、出口运行态和启动未获证明：

```sh
sh scripts/verify-probe-config.sh \
  --env /var/lib/chengwang-m2b-candidate/<instance>/config/probe.env \
  --compose /absolute/repository/path/compose.probe-agent.yaml \
  --catalog /var/lib/chengwang-m2b-candidate/<instance>/config/catalog.json \
  --dot-ca /var/lib/chengwang-m2b-candidate/<instance>/config/dot-ca.pem \
  --egress-policy /var/lib/chengwang-m2b-candidate/<instance>/config/egress-policy.json \
  --candidate-root /var/lib/chengwang-m2b-candidate/<instance>
```

预期结尾必须为：

```text
OFFLINE_INPUT_CHECK=PASS
STATIC_COMPOSE_CONTRACT=PASS
COMPOSE_PARSE=NOT_RUN
EGRESS_RUNTIME=NOT_PROVEN
ACTIVE_START=BLOCKED
```

`STATIC_COMPOSE_CONTRACT=PASS` 只表示固定仓库文件命中了离线安全片段检查，不等于 Docker Compose 已完成结构解析。`COMPOSE_PARSE=NOT_RUN` 必须保持明确；进入受控候选运行前，还要用候选机的 Docker Compose v2 解析、读回合并结果并按字段验收。

本阶段故意不提供会启动容器的命令。`scripts/start-verify-probe-agent.sh` 只读回 Compose、镜像、现存停止容器、最新备份和宿主出口证据，并固定在启动前返回 78；它不会执行 `compose up`。只有 M2a 24 小时签署、自有 canary 审批、默认拒绝出口策略安装及独立读回、允许/拒绝计数器取证、镜像来源固定和变更窗口备份全部完成后，才能实现候选机专用的受控启动步骤。

## 生产周边不变证明

`capture-baseline.sh` 只读采集并只保留 SHA-256：活动 OpenClash 配置、OpenClash UCI、DNS/DHCP UCI、`resolv.conf`、selector 当前选择、生产控制面 Compose 和生产控制面安全运行状态。Controller 原始响应和 UCI 原文只存在于权限 `0700` 的临时目录，退出时删除。

证据目录必须由当前执行用户持有、权限精确为 `0700`，路径不能包含符号链接；输出只能是该目录的直接子文件。脚本使用同目录随机临时文件、落盘同步和不覆盖发布，遇到同名文件或并发创建会失败关闭：

```sh
sudo install -d -m 0700 /root/m2b-evidence
```

在候选动作前后分别运行，输出文件必须是新文件：

```sh
export M2B_MIHOMO_URL='http://127.0.0.1:9090'
export M2B_MIHOMO_TOKEN='<只放环境变量，不写参数或日志>'
sh scripts/capture-baseline.sh \
  /root/m2b-evidence/before.hashes \
  /etc/openclash/config/<ACTIVE-CONFIG>.yaml \
  /opt/chengwang/compose.yaml

# 只运行隔离候选验收，不接触生产控制面。

sh scripts/capture-baseline.sh \
  /root/m2b-evidence/after.hashes \
  /etc/openclash/config/<ACTIVE-CONFIG>.yaml \
  /opt/chengwang/compose.yaml
sh scripts/compare-baseline.sh \
  /root/m2b-evidence/before.hashes \
  /root/m2b-evidence/after.hashes
```

只有 `UNCHANGED_GATE=PASS` 才能证明这些具体哈希在窗口内未变。它不能证明公网出口、业务可用性或没有哈希范围之外的变化。

## 候选备份与恢复

默认护栏候选和主动代理使用两套独立生命周期脚本。主动代理的 `backup-probe-agent.sh` 已实现停机一致性备份：`probe-state/probe-spool` 与 `probe-state/probe-ledger` 同包归档，并绑定 `probe.env`、catalog、DoT CA、出口期望策略、Compose 摘要和不可变镜像 ID。它先对停止后的 live 状态执行只读 `validate-state`，归档后再安全解包到私有目录，用同一不可变镜像复验并要求两份报告完全一致，才发布备份。`relationshipComplete=false` 代表合法保留淘汰造成的证据关系不完整，此时备份标记为 `PASS_DEGRADED`，不能解释为完整恢复证明。该流程尚未在 Linux/Docker 候选机演练。

主动代理的 `restore-probe-agent.sh` 目前只校验备份并解包到私有暂存目录，再用 `validate-state` 复验且要求报告与归档内报告全等。它不会停止、启动或修改 live 容器和状态，并在任何切换前输出 `PROBE_LIVE_CONTAINER_ACTION=NONE`、`PROBE_RESTORE_APPLY=BLOCKED_UNAUDITED_LIVE_STATE_SWITCH` 后返回 78。不得把“归档、配置和暂存语义校验通过”解释为恢复成功，也不得手工绕过该门禁。下面仍是默认护栏候选的独立备份/恢复步骤。

`egress/host_egress_evidence.py` 是只读取证候选，不是防火墙安装器。它只保存 Docker、network namespace 与 nftables 的最小投影，最终只输出 `chengwang.host-egress-verification/v1`、`status=BLOCKED` 并返回 78。当前 `internal: true` 网络与真实可路由出口互相冲突，首次启动、可信 DoT 交易、唯一测试向量、其他宿主 base chain 和 Python/Go 合同共享也未闭合，因此该报告绝不能改名或转换为启动门接受的 evidence。

`canary/static_canary_contract.py` 与 `supply-chain/verify_supply_chain.py` 同样是失败关闭的离线候选门禁。前者校验自有 canary 的静态期望，后者校验镜像证据之间的结构和摘要关系；二者无论输入多完整都返回 78，且不会生成启动门接受的 schema。它们尚未接入生命周期脚本，必须先在 Linux 候选机补齐权限、symlink、竞态、`fsync` 和故障注入证据；供应链门禁还必须补真实 DSSE/镜像验签、X.509/Rekor、Registry digest 读回与防重放账本。

`bootstrap/compile_egress_bootstrap.py` 只生成可复验的抽象 nft 计划。它同时约束受管 bridge 到公网的 `FORWARD` 路径和到宿主服务的 `INPUT` 路径，且每条规则显式绑定 chain；但 PID、netns、cgroup、veth、宿主全局 chain 顺序、conntrack 和已安装对象摘要必须在 Linux 运行时重新绑定。`.github/workflows/chengwang-m2b-candidate.yml` 为这些离线门禁提供独立 Linux CI。run `39149469450` / commit `3f9a4cec...` 已签署 Ubuntu 24.04 静态门禁：Python 132 项零测试用例 skip、13 个 shell 脚本、Go 普通/race/vet；23 个有测试包满足基线，`internal/domain` 是唯一允许且已核对的无测试包。该结论不签署显式 Linux 二进制构建、Docker 运行态、产品镜像或出口；schema metaschema 与产品镜像构建在同一运行中继续明确阻断。

恢复基础库、契约层、安全证据落盘与同内核故障注入的最新静态证据是 run `39169948542` / job `117800728560` / commit `074d560...`：Ubuntu 24.04.5、Linux 6.17、Go 1.23.12 环境中，`proberestore` 的 root/ext4-XFS 门禁覆盖 14 个顶层场景和 8 个原子替换故障点；`restoreevidence` 覆盖 11 个顶层场景、16 个关键子场景和 20 个故障阶段；blocked coordinator model 覆盖 1 个真实 store 关闭/重开场景，并明确输出 `authorization=BLOCKED_TRUSTED_INPUTS_MISSING`，全部零 skip。全仓普通与 race 共 2932 个 Go 语义 run event、28 个包零测试用例 skip，Python 141 项、shell 13 项和 vet 同时通过。11 份 schema 已由固定的 `santhosh-tekuri/jsonschema/v6 v6.0.3` 按 Draft 2020-12 编译并验证正反实例；其中 backup v3、恢复转换证据 v1、外部锚点 v1 和 receipt checkpoint v1 均执行严格字段、上下文绑定、阶段/拓扑与时间窗检查。锚点和 checkpoint 目前只解析为 **未验证声明**，严格结构并不等于密码学验签或外部存储读回。

`internal/proberestore` 提供 25 阶段恢复状态机、25×16 拓扑恢复决策、单一原子 `control.json`、防重 receipt 和 Linux 单写者持久化基础，并验证 rename 前后真实 SIGKILL/reopen、目录同步失败、合法孤儿清理和恶意对象失败关闭。`internal/restoreevidence` 已补上严格恢复证据的 Linux 原子 no-clobber 落盘、三态提交结果、原始字节回读、设备/inode/mount 绑定、单写者锁、容量与 orphan 失败关闭；Windows 仍仅允许诊断读取。它们都不控制 Docker 或 live 状态。该 gate 不是突然断电、VM/宿主崩溃注入，也不证明恢复成功；把采集、真实签名验真、外部 CAS/WORM 单调锚点、本地 store 和 receipt 轮换串成闭环的 coordinator 仍未实现，`restore-probe-agent.sh` 因此继续在切换前返回 78。产品镜像构建仍以 `DOCKER_BUILD=BLOCKED_UNPINNED_BASE_IMAGES` 失败关闭，不能用本次静态通过替代镜像或运行态验收。

新增的 `internal/restorecoordinator` 只是一套失败关闭的实验模型，不是生产恢复入口。它没有公开可构造的生产实例，CI 仅演练真实 journal/evidence 文件系统存储、原字节证据重读、split-commit 重试、重开后幂等确认和 `INPUT_VERIFIED` 前硬停止，并固定报告 `authorization=BLOCKED_TRUSTED_INPUTS_MISSING`。`internal/restorelease` 已实现 Linux 进程内、FD 绑定的双层生命周期租约，并与现有 shell 使用相同的全局锁和候选实例锁；它会校验 root 所有权、权限、单链接、设备、inode、mount ID、文件系统、候选根 marker 及路径重绑定，并在首次验证失败后永久 poisoned。GitHub Actions run `39172099478` / job `117807132828` 已在受限 Linux root 容器中通过 13 个 syscall/path 场景和 2 个 shell `flock` 互操作场景。该租约还没有接入协调器；进程重启也不会延续旧租约权限。在可信时钟、独立 current-state/topology collector、backup-v3 collector 和显式 Resume/Reconcile 完成前，任何模块都不得消费其阶段作为 live 操作授权。

备份脚本只接受绝对路径，并要求 spool 和备份目录都位于 `M2B_CANDIDATE_ROOT` 下；它会读回容器真实挂载源、先优雅停止候选，再备份 catalog、spool、候选镜像检查结果和校验和，并把候选保持在停止状态：

```sh
sudo install -d -m 0700 /var/lib/chengwang-m2b-candidate/site-a/backups
sudo env M2B_CANDIDATE_ROOT=/var/lib/chengwang-m2b-candidate/site-a \
  sh scripts/backup-candidate.sh \
  /var/lib/chengwang-m2b-candidate/site-a/spool \
  /absolute/path/to/catalog.json \
  /var/lib/chengwang-m2b-candidate/site-a/backups
```

默认候选根是本目录下的 `runtime`。自定义根只能是 `/var/lib/chengwang-m2b-candidate/<实例>` 或 `/srv/chengwang-m2b-candidate/<实例>` 的单层专用子目录；实例名必须以小写字母或数字开头，只含小写字母、数字、下划线、连字符且不超过 20 字符。目录必须由管理员预先创建并写入精确标记；任何 `/opt/chengwang` 及其后代、宽泛系统目录、符号链接组件和无标记目录都会被拒绝：

```sh
sudo install -d -m 0700 /var/lib/chengwang-m2b-candidate/site-a
printf '%s\n' 'chengwang-m2b-candidate-root/v1' | \
  sudo tee /var/lib/chengwang-m2b-candidate/site-a/.chengwang-m2b-candidate-root >/dev/null
sudo chmod 0600 /var/lib/chengwang-m2b-candidate/site-a/.chengwang-m2b-candidate-root
sudo env M2B_CANDIDATE_ROOT=/var/lib/chengwang-m2b-candidate/site-a \
  sh scripts/verify-candidate.sh
export M2B_CANDIDATE_ROOT=/var/lib/chengwang-m2b-candidate/site-a
sudo install -d -m 0700 "$M2B_CANDIDATE_ROOT/backups"
```

备份和恢复不会初始化根目录，也不会创建标记；它们只接受已经通过同一根目录合同的路径。spool 与备份目录不得互相嵌套。备份前后同时检查普通文件/目录白名单、最多 4096 项、展开数据最多 128 MiB，压缩包本身也不得超过 128 MiB。

每个规范化候选根会通过“实例名 + 路径 SHA-256 短摘要”派生独立的 Compose 项目、容器和网络命名空间；脚本使用 CLI `--project-name` 强制该身份并清除外部 `COMPOSE_PROJECT_NAME`，避免 `.env` 或调用环境覆盖。同一宿主可运行多个候选实例，但每次脚本调用只操作由 `M2B_CANDIDATE_ROOT` 唯一确定的一个实例。

恢复脚本要求同一候选根、确认短语和实际挂载源一致；根、spool、backups 还必须处于同一宿主挂载，禁止 bind-mount 别名。恢复单位由 `spool.tar.gz`、`catalog.json` 和 `image-inspect.json` 组成，清单必须恰好覆盖三者；复制到私有暂存目录并完整校验后，还会要求备份 catalog 与当前挂载 catalog 同 SHA-256、备份不可变镜像 ID 与当前候选容器一致。随后只允许普通文件/目录，再把被替换的候选 spool 保留为 `spool.failed.<timestamp>`：

```sh
export M2B_CONFIRM_RESTORE=RESTORE_DISPOSABLE_CANDIDATE
sudo env \
  M2B_CANDIDATE_ROOT=/var/lib/chengwang-m2b-candidate/site-a \
  M2B_CONFIRM_RESTORE="$M2B_CONFIRM_RESTORE" \
  sh scripts/restore-candidate.sh \
  /var/lib/chengwang-m2b-candidate/site-a/backups/<timestamp> \
  /var/lib/chengwang-m2b-candidate/site-a/spool
```

恢复后候选仍保持停止。重新执行 `verify-candidate.sh` 并保存结果之前，不得删除保留的旧 spool。

## 禁止事项

- 不得给护栏容器添加 `network_mode: host`、Docker socket、Controller token、代理订阅或生产数据卷。
- 不得仅凭 Docker bridge 的名称、`internal` 标志或应用 IP 校验宣称“唯一出口已证明”。
- 不得把护栏健康状态解释为节点、DNS、互联网或业务健康。
- 不得在 M2a 24 小时浸泡签署之前进入 M2b 生产 Shadow。
- 当前 Dockerfile 基础镜像仍使用可变标签；在候选机取得并验证镜像 digest、SBOM 与构建来源之前，不得签署可追溯构建门禁。
- 不得把本目录脚本直接当作生产发布脚本；生产变更仍需单独备份、候选、灰度、读回和回滚演练。
