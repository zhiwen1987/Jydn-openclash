# Docker 部署与恢复

## 版本边界

本文件同时描述当前源码和后续部署所需步骤。身份认证、耐久操作库、控制服务与 `/api/v1/operations` 已随默认锁定的 Shadow 版本部署到 `10.88.0.254`，但生产未配置身份文件，操作写开关为 `false`，且没有设备执行器。只有每次新版本都完成备份、候选容器、重启、局域网读回和回滚演练，才能更新生产部署记录。任何“源码测试通过”都不能替代生产验收。

## 外部镜像仓库不可用时的离线应用层更新

只有已保存且已验证的旧镜像可以作为 `BASE_IMAGE`。该方式不升级 Alpine、Node 或 Go 基础层，只替换本次在可信构建机生成的 Linux 应用二进制与前端静态文件，适合 Docker Hub 暂时不可达时的同架构小版本更新。

```powershell
$env:CGO_ENABLED = '0'
$env:GOOS = 'linux'
$env:GOARCH = 'amd64'
go build -trimpath -ldflags='-s -w' -o release/chengwang ./cmd/server
npm --prefix web run build
Copy-Item -Recurse web/dist release/web
```

目标机必须先给当前镜像建立不可变回滚标签，再显式指定它构建候选镜像：

```sh
docker build \
  --build-arg BASE_IMAGE=chengwang:rollback-<backup-timestamp> \
  -f Dockerfile.offline \
  -t chengwang:candidate-<release-timestamp> .
```

候选镜像应先在不同端口运行，验证健康、能力事实接口、前端静态资源和非 root 身份；候选失败不得覆盖 `chengwang:local`。此流程不能替代基础镜像漏洞修复，外部仓库恢复后仍需按完整 Dockerfile 重建并重新验收。

## 安全边界

当前容器固定使用 `shadow` 模式，`CHENGWANG_ALLOW_PUBLISH=false`。它只能读取 Mihomo Controller 的版本、配置摘要、策略组和规则，不会重载 OpenClash、切换节点、修改 DNS、操作防火墙或接管流量。

源码还提供本地 Shadow 操作记录接口，但默认双重关闭：未设置 `CHENGWANG_IDENTITIES_FILE` 时不能认证，`CHENGWANG_OPERATION_WRITES_ENABLED` 缺省或为 `false` 时拒绝写入。即使两个条件都显式启用，也只更新 `/app/data/operations/operations.json` 并追加本地证据，不包含设备执行器；`effect=local_record_only` 和 `deviceActionsExecuted=false` 是协议保证，不代表设备已经变更。

容器使用主机网络，是因为目标机上的 Mihomo Controller 监听 `127.0.0.1:9090`。未配置任何管理身份时，可通过 `http://<设备IP>:7811/` 查看匿名最小状态。只要启用身份文件或管理员令牌，就必须配置原生 TLS，或把服务改为仅监听回环并由同机 HTTPS 反向代理接入；禁止通过局域网明文 HTTP 发送 Bearer。

## 首次部署

```sh
cd /opt/chengwang
cp .env.example .env
chmod 600 .env
# 在 .env 中填入目标机本地 Mihomo Controller 的 secret
mkdir -p data backups
chown 10001:10001 data
chmod 700 data backups
docker compose config
docker compose build
docker compose up -d
```

### 可选：配置本地 Shadow 身份与操作记录

身份文件只接受高熵 Bearer 的 SHA-256 十六进制摘要，不接受明文密码或明文令牌。Linux 上身份目录必须精确为 `0700`、文件为 `0600`，路径中不能有符号链接。以下内容全部为占位符：

```json
{
  "version": 1,
  "identities": [
    {
      "tokenId": "operator-01",
      "tokenHash": "<64-character-lowercase-sha256>",
      "principal": {
        "id": "operator-01",
        "tenantId": "tenant-example",
        "roles": ["operator"],
        "allowedScopes": [
          {
            "tenantId": "tenant-example",
            "siteId": "site-example",
            "objectType": "gateway",
            "objectId": "gateway-example",
            "environment": "shadow"
          }
        ],
        "breakGlassEligible": false
      }
    }
  ]
}
```

建议把文件放在独立私有目录并只读挂载，而不是写入镜像或 Git：

```yaml
services:
  chengwang:
    environment:
      CHENGWANG_IDENTITIES_FILE: /run/chengwang-auth/identities.json
      CHENGWANG_MANAGEMENT_TENANT_ID: tenant-example
      CHENGWANG_OPERATION_WRITES_ENABLED: "false"
    volumes:
      - ./data:/app/data
      - ./secrets:/run/chengwang-auth:ro
```

主机 `secrets` 和容器内挂载目录必须保持 `0700`，`identities.json` 必须为 `0600`，并由容器 UID 10001 可读。应像示例一样挂载整个私有目录，不要依赖 Docker 自动创建的文件挂载父目录，也不要放宽源码权限检查。身份文件在启动时载入；替换后必须走备份、候选和安全重启流程，不支持热轮换。

环境变量事实表：

| 变量 | 缺省/要求 | 作用 |
| --- | --- | --- |
| `CHENGWANG_IDENTITIES_FILE` | 空 | 空值表示没有本地身份源，操作接口返回未配置；非空路径必须通过严格 JSON、文件类型和权限校验。 |
| `CHENGWANG_OPERATION_WRITES_ENABLED` | `false` | 只接受精确的 `true` 或 `false`；`true` 只允许本地 Shadow 操作记录，不开放设备执行。 |
| `CHENGWANG_DATA_DIR` | `./data`；容器为 `/app/data` | 保存版本、`evidence/` 与 `operations/`。三个存储必须一并备份。 |
| `CHENGWANG_ALLOW_PUBLISH` | `false` | 控制旧的本地策略版本写入；与操作写开关相互独立，均不等于路由器发布。 |
| `CHENGWANG_MANAGEMENT_TENANT_ID` | 配置身份时必填 | 完整诊断接口的管理资源租户范围。 |
| `CHENGWANG_TLS_CERT_FILE` / `CHENGWANG_TLS_KEY_FILE` | 成对配置 | 原生 TLS 证书和私钥；管理身份在非回环监听上启用时强制要求。 |
| `CHENGWANG_MIHOMO_ALLOWED_HOSTS` | 空 | 逗号分隔的远程 HTTPS Controller 主机白名单；本机回环 Controller 不需要。 |

### 操作接口示例（全部使用占位符）

读取操作需要有效身份和明确范围：

```sh
curl -fsS \
  -H 'Authorization: Bearer <ONE-TIME-HIGH-ENTROPY-TOKEN>' \
  'https://<CONTROL-PLANE-HOST>/api/v1/operations?tenantId=tenant-example&siteId=site-example&objectType=gateway&objectId=gateway-example&environment=shadow'
```

创建低风险本地计划需要额外幂等键，重复相同请求会返回同一记录，复用同一键提交不同内容会冲突：

```sh
curl -fsS -X POST \
  -H 'Authorization: Bearer <ONE-TIME-HIGH-ENTROPY-TOKEN>' \
  -H 'Idempotency-Key: <UNIQUE-REQUEST-ID>' \
  -H 'Content-Type: application/json' \
  --data '{"resource":{"tenantId":"tenant-example","siteId":"site-example","objectType":"gateway","objectId":"gateway-example","environment":"shadow"},"risk":"low","targetVersion":"<TARGET-VERSION>"}' \
  'https://<CONTROL-PLANE-HOST>/api/v1/operations'
```

允许的 HTTP 转换仅为低/中风险 `planned -> prechecking`，以及高/关键风险 `planned -> awaiting_approval -> prechecking`；审批人必须是不同的已认证身份。执行、验证、观察、成功、失败和回滚等状态会因没有设备执行器而返回 HTTP 423：

```sh
curl -fsS -X POST \
  -H 'Authorization: Bearer <APPROVER-OR-OPERATOR-TOKEN>' \
  -H 'Idempotency-Key: <UNIQUE-TRANSITION-ID>' \
  -H 'Content-Type: application/json' \
  --data '{"resource":{"tenantId":"tenant-example","siteId":"site-example","objectType":"gateway","objectId":"gateway-example","environment":"shadow"},"to":"prechecking"}' \
  'https://<CONTROL-PLANE-HOST>/api/v1/operations/<OPERATION-ID>/transitions'
```

响应中的 `commit_unknown` 表示原子替换可能已经发生，但目录持久性无法确认。此时不能把请求当作失败后盲目重放：应停止写入、保存响应与日志、关闭该实例，检查/备份磁盘文件，再由新实例重新打开并验证。`audit_degraded` 同样不能解释为完成。

## 严格验收

```sh
docker compose ps
docker inspect --format '{{.State.Health.Status}}' chengwang
wget -qO- http://127.0.0.1:7811/api/v1/health
wget -qO- http://127.0.0.1:7811/api/v1/kernels/mihomo/status
docker logs --tail 100 chengwang
```

通过条件：容器为 `healthy`；健康接口为 `status=ok`、`mode=shadow`、`mihomoReadbackConfigured=true`；匿名 Mihomo 状态只含最小可达性和新鲜度字段，不含版本、地址、节点、策略组或规则，且日志无持续错误。完整 runtime/readback 必须在安全传输上使用受范围约束的身份。

若候选配置了身份和操作接口，还必须验证：

- 无 `Authorization`、重复 Authorization、无效令牌和范围不匹配均被拒绝。
- 写开关为 `false` 时，已认证写请求仍返回 HTTP 423。
- 开关为 `true` 的隔离候选中，相同幂等键/相同载荷只产生一个操作和一组语义事件；同键不同载荷返回冲突。
- 重启后操作仍存在，发起人/审批人绑定不变；响应不包含事件正文、Bearer、身份摘要或原始作用域。
- 接口始终报告 `local_record_only`，进入执行及后续状态返回 `executor_not_configured`；Mihomo、DNS、路由和防火墙读回无变化。
- `evidence/integrity` 为 `valid=true`；故障注入后的 `store_poisoned`、`checkpoint_stale` 或 `commit_unknown` 均停止写入而不是自动修复。

## 更新前备份

```sh
cd /opt/chengwang
stamp="$(date +%Y%m%d-%H%M%S)"
mkdir -p "backups/$stamp"
chmod 700 "backups/$stamp"
docker compose stop
cp compose.yaml .env "backups/$stamp/"
cp -a data "backups/$stamp/data"
[ -d secrets ] && cp -a secrets "backups/$stamp/secrets"
docker image inspect chengwang:local > "backups/$stamp/image-inspect.json"
# 如果本次不立即更新，再执行：docker compose start
```

`.env` 和可选 `secrets/` 含本机密钥材料，备份目录必须保持 `700` 权限，不应上传 GitHub。当前是单进程文件存储，命令先停止容器，确保没有并发写入且操作系统已随进程退出释放文件锁，再复制 `data`。直接在运行期间复制多个文件不能证明跨存储一致性。

## 恢复

```sh
cd /opt/chengwang
docker compose down
cp "backups/<时间戳>/compose.yaml" ./compose.yaml
cp "backups/<时间戳>/.env" ./.env
rm -rf data.restore
cp -a "backups/<时间戳>/data" data.restore
mv data data.failed
mv data.restore data
docker compose up -d
```

如备份包含身份目录，应在停机状态下一并恢复，并重新确认目录 `0700`、身份文件 `0600`、属主与容器 UID 可读。恢复后重新执行全部严格验收命令。确认无误后再人工清理 `data.failed`；不要在验收前删除旧数据。

Evidence 与 operation 存储都持有进程生命周期单写者锁；同一目录不能同时被两个控制器打开。两种 Store 都实现了幂等 `Close()`，供受控生命周期显式释放锁；进程退出时操作系统也会释放内核锁。当前源码会在 Linux 捕获 `SIGINT`/`SIGTERM`，先给 HTTP 请求 10 秒优雅关停窗口，再关闭两个 Store；超时会强制断开剩余请求并返回错误。该生命周期仍须随下一候选镜像做真实容器停止验收，不能只凭单元测试宣称生产已验证。遇到异常退出时，不要通过删除锁文件绕过内核锁或完整性检查；确认旧进程已经退出后再重新打开。

`checkpoint_stale` 表示日志存在超过本地 checkpoint 的连续尾部。系统有意失败关闭，因为未加密签名的本地哈希链无法证明这些额外记录由本进程提交。当前没有自动修复命令：应保持停机，备份 `events.jsonl`、`checkpoint.json`、锁文件和操作快照，完成事件来源与磁盘故障分析后再由人工选择受信任恢复点。不得只把 checkpoint 数量改大后继续运行。

## 当前 P1 运维缺口

- 本地证据链没有密钥签名、WORM 介质或独立故障域副本，主机管理员仍可成套替换日志和 checkpoint。
- `checkpoint_stale`、操作库 `commit_unknown` 和 poison 状态需要人工保存证据、选择恢复点并重启新实例；尚无经过验收的自动恢复编排。
- 身份是静态高熵 Bearer 摘要文件，没有 MFA、SSO、在线撤销、自动轮换或企业密钥管理。
- 操作控制只到计划、审批、预检记录，没有设备执行、灰度、读回、业务验证或自动回滚。
- 单机单写者锁不是多控制器租约或共识，不能用于 HA 双活。
- 源码已实现 SIGINT/SIGTERM 协调和 10 秒优雅关停，Compose 提供 20 秒停止窗口；该能力仍必须在每个候选镜像和正式容器中执行停止、日志读回和重启验收，不能只凭源码或单元测试宣称生效。

这些缺口不影响把当前功能用于 Shadow 记录和开发验收，但它们阻止任何 `99.999999%` 或企业级端到端可用率声明。
