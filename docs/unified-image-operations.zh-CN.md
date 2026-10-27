# 统一功能面板单镜像：构建、切换与回退

本文描述进源Clash Center `0.2.0` unified 的离线增量镜像和受守卫的单服务切换。它不修改路由器，不更改 provider URL、Token、DNS 或业务选择。部署会重建承载 CoreDNS、Kuma 和统一中心的同一个容器，因此 DNS、Kuma 和 3101/3102/3103 会有一次短时中断；不能表述为无中断发布。

本文是发布操作契约。本环境已于 2026-10-28 接受生产切换；最终镜像身份、隔离与生产证据、实际告警和恢复目录见[统一中心生产验收记录](unified-center-production-20261028.md)。没有在该记录列出的账号业务不能当作已经验收。

## 0. 0.2.0 入口与产品边界

- 统一主入口是 3103 的 `/`，八页分别为 `#/overview`、`#/routing`、`#/nodes`、`#/subscriptions`、`#/dns`、`#/monitors`、`#/backups`、`#/activity`；静态资源使用同源 `/center-assets/`。
- 原 3101 Kuma 和 3102 能力页面暂时保留兼容，不作为新 UI 主入口；原订阅页保留在 3103 同源 `/classic/subscriptions`。
- 管理登录与退出沿用 `/api/local/login`、`/api/local/logout`。选择、节点测试和备份等写操作要求有效登录、同源及 CSRF；Kuma 继续使用原 Kuma 认证。任何请求、日志或文档都不得写入实际密码、Token、provider 凭据或节点密钥。
- 状态只能来自真实接口：无证据为 `unknown/未知`，超过新鲜度为 `stale/已过期`，运行中、待处理、警告和错误分别显示；单部分失败不能抹掉其他可用数据，也不能生成假成功率、假进度或假事件时间。
- 同步阶段严格区分信息来源读取、节点检测、受控发布和运行加载。“信息来源 N 家”不等于“已发布 N 家节点”，加载数量一致也不代表全部端点和业务通过。刷新只读取观测，不触发发布、清空 DNS 或切换业务选择。
- 统一中心备份只覆盖中心数据与配置，不包含路由器备份、整机快照或全部外部依赖。备份完成后才提供下载，下载仍需有效管理会话，并按敏感资料保护。

## 固定边界

- 审计基镜像固定为 `sha256:eb0271488325b6f8801f7eebcf36ecf363c82b8ed7a3a8f9145250239771a8f2`。
- 构建只从仓库白名单源码生成 context；不包含生产 `/data`、数据库、`.env`、URL、Token 或账号资料。
- 禁止 `docker commit`。构建用 `docker build --network=none --pull=false`，归档用 `docker image save`。
- 新镜像继承基镜像的入口、supervisor、依赖和 healthcheck，不重构启动链。它覆盖已验收 `runtime/upstream`，将原订阅实现放到 `/subscription_impl.py`，将 portable 启动放到 `/subscription-controller.py`，并内置最新 `/local-subscription` 和 `/unified-center`。
- 生产 Compose 的目标服务为 `center`、容器名为 `clash-center`。工具只执行 `docker compose ... up -d --no-deps ... center`，不会执行全项目 `down`。
- `/data`、`/app/data`、`/etc/coredns/Corefile`、端口、网络、重启策略和原环境保持不变。只增加 `CENTER_UI_ENABLED=1`，并移除 `/node-capability.py`、`/subscription-controller.py`、`/healthcheck.sh` 三个受管代码 bind，使代码来自镜像。
- `/data/node-health/code` 与 `/data/subscription-usage/code` 保留。准备和验收会逐文件校验其内容与构建清单中的同源源码一致；不一致即拒绝。

## 1. 本地生成无私密构建 context

等 `monitoring/lan-center/unified-center/` 中后端、代理和 assets 全部就绪后执行：

```powershell
$version = "0.2.0-unified"
$commit = git rev-parse HEAD
python installer/build_unified_image.py context `
  --output installer/.build/unified-context `
  --version $version `
  --source-commit $commit
```

输出包括：

- `installer/.build/unified-context/`：Docker build context；
- `installer/.build/unified-context/context.manifest.json`：每个源码文件的 SHA-256；
- `installer/.build/unified-context.tar.gz`：确定性源码归档。

若输出目录非空、必需文件缺失、出现符号链接或私密文件名，命令会拒绝继续。

## 2. 从已审计基镜像离线构建

先确认本机已有固定基镜像，且 ID 完全相同；不要 pull 同名浮动 tag。部分旧 builder 会把 `FROM sha256:...` 误作远端引用，因此先从真实固定 ID 创建仅本机构建使用的 verified tag，再反向检查该 tag 仍解析到固定 ID：

```powershell
$base = "sha256:eb0271488325b6f8801f7eebcf36ecf363c82b8ed7a3a8f9145250239771a8f2"
$baseTag = "lan-center-base:verified-eb0271488325"
$actualBase = docker image inspect $base --format '{{.Id}}'
if ($actualBase -ne $base) { throw "audited base image ID mismatch" }
docker tag $base $baseTag
$taggedBase = docker image inspect $baseTag --format '{{.Id}}'
if ($taggedBase -ne $base) { throw "verified local tag does not resolve to audited ID" }
docker build --network=none --pull=false `
  --build-arg BASE_IMAGE=$baseTag `
  --build-arg BASE_IMAGE_ID=$base `
  -t "lan-center-unified:$version" `
  -f installer/.build/unified-context/Dockerfile `
  installer/.build/unified-context
$imageId = docker image inspect "lan-center-unified:$version" --format '{{.Id}}'
docker image save -o installer/.build/clash-center-unified.tar "lan-center-unified:$version"
python installer/build_unified_image.py bundle `
  --context installer/.build/unified-context `
  --image-archive installer/.build/clash-center-unified.tar `
  --image-id $imageId `
  --output "installer/dist/$version" `
  --version $version
```

将 bundle 用已批准的离线通道传到服务器。服务器侧先验证 `SHA256SUMS`，再 `docker image load`；不要把任何生产文件复制回构建 context。

## 3. 准备生产切换

部署 agent 是 stdlib-only。请求文件权限设为 `0600`，回执不会输出 Compose、容器环境或私密数据。以下示例中的镜像名和 manifest 路径替换为本次真实值：

```json
{
  "action": "prepare",
  "state_dir": "/opt/clash-center-ui",
  "compose_path": "/root/dpanel/compose/lan-center/docker-compose.yml",
  "service": "center",
  "container_name": "clash-center",
  "image": "lan-center-unified:0.2.0-unified",
  "manifest_path": "/opt/clash-center-ui/packages/0.2.0-unified/manifest.json",
  "expected_snapshot": {
    "container_id": "上线前重新 inspect 得到的完整容器 ID",
    "current_image_id": "sha256:eb0271488325b6f8801f7eebcf36ecf363c82b8ed7a3a8f9145250239771a8f2",
    "compose_sha256": "上线前重新计算的 Compose SHA-256",
    "service": "center",
    "mount_count": 6,
    "data_source": "/root/dpanel/compose/lan-center/data/failover",
    "app_data_source": "/root/dpanel/compose/lan-center/data/uptime-kuma",
    "corefile_source": "/opt/lan-center-unified/releases/20261025-1792941497649485821/Corefile",
    "other_container_total_count": 33,
    "other_container_running_count": 33
  },
  "guard_timeout_seconds": 900,
  "required_free_bytes": 6442450944
}
```

```bash
sudo python3 /opt/clash-center-ui/deploy.py /root/prepare-unified.json
```

部署状态默认使用 `/opt/clash-center-ui`，避免覆盖历史统一中心目录。DPanel 的 JSON Compose 会保留其他对象的解析语义；简单 block YAML 按目标服务文本修改；复杂或长格式结构继续拒绝，不能绕过检查。

`prepare` 必须全部通过才可继续。它验证：

- 新镜像 ID、平台、固定基镜像身份和构建 manifest；除固定 base-image label 外，还读取真实固定基镜像与新镜像的 `RootFS.Layers`，要求固定基镜像的完整 layers 序列是新镜像严格前缀，伪造 label 不能通过；
- 根代理刚采集并显式传入的生产快照；容器 ID、旧镜像、Compose SHA、服务、6 个挂载、两个数据源和其余容器数量任一漂移都拒绝。`other_container_total_count` 的口径是排除 `clash-center` 后的 `docker ps -aq`（包含 stopped），`other_container_running_count` 才是运行中数量；示例的 total=33 仅在没有 stopped 容器时成立，上线前必须重算；
- 运行容器的 Compose project/config/service 标签、`center` 服务和 `clash-center` 身份；
- `/data` 实际 bind、`/app/data` 实际 bind、所有原挂载和三处受管代码 bind；
- 两个 `/data/.../code` overlay 与镜像源码清单一致；`.py/.js/.html` 允许 CRLF/LF 规范化后相同，同时保存原始字节 SHA 作为后续所有权校验；
- 可用空间至少为 6 GiB，且至少覆盖两倍快照源大小再加 1 GiB；
- 原 Compose、完整私密容器 inspect（含原 env）、三处代码 SHA、其他容器指纹；
- `/data` 与 `/app/data` 的私密完整快照。SQLite 使用在线 backup API，源和备份都执行 `PRAGMA integrity_check`，并要求实际挂载中找到并备份 `kuma.db`。

备份只保存在服务器 `/opt/clash-center-ui/backups/<transaction>/`，目录 `0700`、文件 `0600`，不得作为普通回执上传或打印。

## 4. 切换、验证、接受

切换前安排短时维护窗口。`apply` 会先安装独立于 SSH 会话的 systemd 定时回退守卫，再原子修改 Compose 并只重建 `center`：

```json
{"action":"apply","state_dir":"/opt/clash-center-ui"}
```

```bash
sudo python3 /opt/clash-center-ui/deploy.py /root/apply-unified.json
```

随后使用仅指向本机固定端口的探针验收。探针可按实际健康路径调整；不要在请求中放 Token：

```json
{
  "action": "verify",
  "state_dir": "/opt/clash-center-ui",
  "probes": [
    "http://127.0.0.1:3101/",
    "http://127.0.0.1:3102/health",
    "http://127.0.0.1:3103/health"
  ]
}
```

`verify` 同时要求：新容器 ID/镜像正确、原端口/网络/重启策略/环境/非代码挂载不变、`CENTER_UI_ENABLED=1`、镜像内源码 SHA 全部匹配、overlay 未变、所有实时 SQLite 完整、其余容器指纹未变。

还需人工在主入口 3103 验收统一面板、原 provider 与 Token、DNS、业务选择、Kuma 登录和旧端口兼容。确认后才执行：

```json
{"action":"accept","state_dir":"/opt/clash-center-ui"}
```

`prepare` 会私密备份 `/opt/clash-stack/production/state.json` 的原始字节和 SHA，并要求其中 `container_id`、`manifest.image_id` 与切换前真实容器一致。`accept` 在该文件仍保持原 SHA 时，只同步新 `container_id`、新 `manifest.image_id`，加入 `unified_image` 回执和 `managed_code_overlays=false`，使原 watchdog 继续识别当前容器；其他原安装器恢复字段保持不变。随后写入 `/opt/clash-center-ui/state.json` 审计清单并停止回退守卫。若旧状态身份不一致或并发改变，accept 阻断上线。

accept 只表示本事务的技术验收被明确接受，不自动证明真实账号、全部业务或长期稳定。接受时间、最终镜像 ID 与生产证据仍必须写入[统一中心生产验收记录](unified-center-production-20261028.md)。

## 5. 手工或超时回退

未 accept 前可手工回退；超时则由 systemd 守卫调用同一动作。accept 后仍可用相同事务号显式手工回退，但已停止的旧守卫永远不会撤销已 accept 的版本：

```json
{
  "action": "rollback",
  "state_dir": "/opt/clash-center-ui",
  "transaction": "prepare 返回的 transaction"
}
```

回退只在当前 Compose SHA、新容器 ID、统一安装 state SHA 和旧安装器 state SHA 仍属于本事务时进行。后续有人改过 Compose、替换过容器、编辑过任一 state 或事务号过期，工具会写私密拒绝记录并停止，避免覆盖人工变更。

安全回退会恢复旧 Compose、旧镜像和三处旧代码 bind，然后只重建 `center`。旧安装器 state 从私密原始备份恢复，但 `container_id` 会写成刚重建出的真实新 ID（绝不写回已停用旧容器身份），`manifest.image_id` 写回旧镜像 ID，确保 watchdog 恢复正常。它不会把旧数据库复制回生产：新版运行期间产生的 `/data` 与 `/app/data` 历史全部保留。回退同样会造成该单容器内 DNS、Kuma 和中心端口的一次短时中断。

## 6. 隔离测试

Windows 或 Linux 均可运行纯临时目录测试；测试不连接生产、不调用真实 Docker/systemd：

```powershell
python -m unittest installer.tests.test_unified_deploy -v
```

覆盖正确服务、禁止 `down`、保留非代码挂载、私有覆盖拒绝、SQLite 在线备份与损坏检测、CRLF/LF 同源校验、Compose/容器并发修改保护、accept 后手工回退、旧 watchdog 身份同步，以及恢复旧镜像/Compose 但不恢复数据库。

离线打包还覆盖 Docker classic 与本环境实际 OCI/containerd 导出格式。OCI 中镜像根 manifest 的 digest 可以与 config digest 不同，程序通过完整 descriptor、blob、解压 DiffID 与 legacy 引用链核验身份，拒绝多根、多平台、路径穿越、重复成员和损坏内容。不能仅因 config digest 不同就认为镜像已损坏，也不能取消根身份校验。

本次发行是既有审计站点的三处代码 bind → 自包含镜像迁移。工具要求这些旧挂载及固定基镜像仍存在；已经迁移后的下一次纯镜像更新需要新的兼容计划，不能删除校验条件来强行重用。生产记录还保留了启动后原发布控制器自动试用候选并回退的事件，因此不将普通容器重启描述成没有任何调度行为。
