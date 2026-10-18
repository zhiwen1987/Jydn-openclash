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
| `probe-agent` 命令 | 已实现、本地测试通过 | 启动账本先于网络、结果先入 spool 再结算、跨重启预算及崩溃恢复；尚未容器化，也没有获批 canary/出口 |
| 主动业务探针 | `blocked` | 护栏容器仍固定 `activeProbes=false`；自有 canary、唯一出口和容器运行门禁未完成 |
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

验收脚本会构建并启动独立项目 `chengwang-m2b-candidate`，验证容器约束、读写边界、健康检查、优雅停止、重启持久性、无效 catalog 失败关闭、只读 spool 失败关闭和心跳停滞检测。结束时容器保持运行，仍处于无公网出口的隔离网络。

脚本输出的以下三项必须继续显示 `BLOCKED`，否则属于事实误报：

```text
ACTIVE_PROBE_EXECUTION=BLOCKED_NOT_CONTAINERIZED_OR_EGRESS_APPROVED
FIXED_TRUSTED_RESOLVER=IMPLEMENTED_LOCAL_ONLY_RUNTIME_NOT_PROVEN
UNIQUE_EGRESS_ENFORCEMENT=BLOCKED_NOT_PROVEN
```

## 生产周边不变证明

`capture-baseline.sh` 只读采集并只保留 SHA-256：活动 OpenClash 配置、OpenClash UCI、DNS/DHCP UCI、`resolv.conf`、selector 当前选择、生产控制面 Compose 和生产控制面安全运行状态。Controller 原始响应和 UCI 原文只存在于权限 `0700` 的临时目录，退出时删除。

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
