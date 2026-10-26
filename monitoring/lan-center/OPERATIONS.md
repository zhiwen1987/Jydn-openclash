# lan-center 操作手册

> 历史操作记录：本文包含旧双容器架构及当时的监控/频率参数。当前 `clash-center` 单容器使用[最新手册](../../docs/system-guide.zh-CN.md)和[恢复说明](../../installer/RECOVERY.zh-CN.md)，当前数据目录与本次验收见[部署记录](../../docs/production-deployment-20261026.md)。不要照旧容器名执行重启或恢复命令。

适用环境：

- Docker 主机：`10.88.0.249`
- 部署目录：`/root/dpanel/compose/lan-center`
- 监控面板：`http://10.88.0.249:3101`
- 节点能力看板：`http://10.88.0.249:3102`
- 自动订阅看板：`http://10.88.0.249:3103`
- OpenClash：`10.88.0.254`
- 爱快：`10.88.0.1`

本手册不包含账号、密码、令牌或代理认证信息。真实凭据只允许保存在服务器的 `.env` 和 Kuma 数据库中，不得提交到 GitHub。

## 1. 架构和安全边界

`lan-center` 复用两个容器：

| 服务 | 作用 | 是否会修改路由 |
| --- | --- | --- |
| `uptime-kuma` | 监控面板、探测历史和状态展示 | 否 |
| `failover` | 代理观察、业务探针、ChatGPT 节点验证、节点能力评估、受控订阅发布和子进程监督 | 调整 ChatGPT 专用池；通过已验收事务更新 provider；爱快固定 `DRY_RUN=1` |

重要限制：

1. 监控系统不得主动停止 WAN、重启爱快或重启 OpenClash；只允许调整 ChatGPT 专用池及其业务组选择。
2. `failover` 的自动切换代码只用于演练；没有单独审批不得把 `DRY_RUN` 改成 `0`。
3. Kuma 显示业务可达性，不代表账号、配额、支付风控或地区版权一定可用。
4. 爱快、OpenClash 和 `lan-center` 的变更必须分别备份，不能互相替代。
5. 节点能力评估器固定为影子模式；只操作 `🧪 节点能力检测` 隔离组，不允许调整生产业务组。
6. 节点检测入站必须使用独立强认证，凭据只保存在路由器受限文件和服务器 `.env`，不得提交。
7. 订阅控制器只能发布 provider 内容，不能修改规则、DNS、端口、策略组拓扑或爱快配置。
8. 自动发布必须同时通过上游实时抓取、准入规则、异常门禁、Mihomo 内核有效数和真实业务探针；任一失败保留旧发布。

ChatGPT 控制器不把节点名称写入日志，只保存短哈希、延迟和候选数。候选先经 API 批量筛选，再通过 OpenClash 代理对 Codex 后端执行真实 POST；只有 JSON `400/401` 才算业务可用。HTML `403` 会立即回退并将节点哈希冷却一小时。已验证节点保持粘性，不按小幅延迟差主动切换。OpenClash 控制密钥仅保存在服务器 `.env`。

Kuma 通过 Docker 内网访问 `failover:8080`，该端口不映射到局域网。`failover` 会监督探针和控制器子进程，健康检查同时验证状态文件新鲜度、进程存活和本地 HTTP 接口。

## 2. 监控项目说明

原有 13 个监控用于局域网设备、OpenClash 主机、代理端口和百度连通性。

新增的 `OpenClash 分流验收` 分组包含：

| 监控 | 成功条件 | 用途 |
| --- | --- | --- |
| `DNS·国内域名` | 通过 `10.88.0.254` 返回 A 记录 | 验证国内域名 DNS |
| `DNS·海外域名` | 通过 `10.88.0.254` 返回 A 记录 | 验证海外域名 DNS |
| `业务·AMD中国·TokenFactory` | HTTP 200-399 | 验证 AMD 中国页面和 `.cn` 分流 |
| `业务·涂鸦中国` | HTTP 200-399 | 验证涂鸦中国站点可达性 |
| `业务·ChatGPT` | 本地探针 HTTP 204 | 经 OpenClash 执行 Codex POST，排除 HTML 403 节点 |
| `业务·Gemini` | 本地探针 HTTP 204 | 经 OpenClash 访问 Gemini Discovery API |
| `业务·Google策略组` | 本地探针 HTTP 204 | 经 OpenClash 访问 Google 204，验证真实规则出口 |
| `链路·实际海外出口` | HTTP 204 | 从 249 独立验证默认海外出口 |

业务项每 30 秒检测，失败后每 10 秒重试，连续重试 2 次才判定故障。

状态解释：

- 绿色：最近一次检测成功。
- 黄色：正在重试，可能是 WAN 切换时的短暂抖动。
- 红色：重试后仍失败，需要按第 7 节排查。
- 分组红色：至少一个子监控失败，应先查看具体子项，不要直接重启全部容器。

## 3. 日常查看

ChatGPT 专用池状态：

```sh
sudo tail -n 50 /root/dpanel/compose/lan-center/data/failover/chatgpt-controller.log
sudo cat /root/dpanel/compose/lan-center/data/failover/chatgpt-controller.health
```

`ok` 表示当前节点已通过 Codex POST；`fallback` 表示专用池无合格节点，已安全回退到人工智能父组；`error` 表示连回退线路也未通过或控制接口异常。

### 3.1 查看面板

在局域网打开：

`http://10.88.0.249:3101`

使用现有 Kuma 账号登录。不要在聊天、工单或截图中公开密码。

节点能力评估看板是只读页面，局域网访问：

`http://10.88.0.249:3102`

该页面没有切换、修改或删除接口；返回修改请求时固定响应 `405 read_only`。

### 3.5 查看节点评估运行状态

```sh
sudo cat /root/dpanel/compose/lan-center/data/failover/node-capability.health
sudo tail -n 50 /root/dpanel/compose/lan-center/data/failover/node-capability.log
sudo docker exec lan-center-failover-1 python3 - <<'PY'
import sqlite3
db = sqlite3.connect('/data/node-capability.db')
print(db.execute('pragma integrity_check').fetchone()[0])
print(db.execute('select state,count(*) from health_scores group by state').fetchall())
PY
```

正常时健康文件为 `status=ok`、`mode=shadow`，数据库完整性为 `ok`。日志只记录节点短哈希，不记录节点名。

V2 看板字段解释：

- `未评估`：无历史样本，会被调度器优先选中；
- `数据过期`：有历史结果，但超过本类检测的有效期，不能作为自动决策依据；
- `业务受限`：通用联网正常，但至少一项业务探针未通过；
- `可信度`：根据 7 天样本量和连续成功/失败次数计算，新节点不会因一次成功获得高可信度；
- 业务标签的鼠标提示显示失败分类和该项可信度；
- `当前生产分流验证`通过正常生产代理入口检查，与节点隔离探针分开。

调度标准：未评估节点优先，健康/降级/业务受限节点 15 分钟复检，冷却/不可用节点 5 分钟复检，业务深测 6 小时复检。订阅更新或容器重启不会清空已有评分。

### 3.6 查看自动订阅状态

局域网只读页面：`http://10.88.0.249:3103`。

```sh
curl -fsS --max-time 8 http://10.88.0.249:3103/health
sudo tail -n 50 /root/dpanel/compose/lan-center/data/failover/subscription-controller/controller.log
docker exec lan-center-failover-1 python3 /subscription-controller.py --self-test
```

关键状态：

- `published`：新版本已刷新到 Mihomo，并通过内核有效数与六项真实业务验收；
- `unchanged`：候选与当前版本一致；
- `held`：缓存源、异常变化或确认次数不足，新版本未进入生产；
- `rejected`：低于最低节点数或触发硬门禁；
- `rolled_back`：刷新、内核有效数或业务验收失败，已恢复上一个版本；
- `shadow`：只生成候选，不改变当前发布。

`node_count` 是控制器批准数，`effective_node_count` 是 Mihomo 实际接受数。两者允许有小幅差异，但单个 provider 的内核拒绝比例超过 10% 会回滚。`cached_sources` 必须为 `0` 才允许不同候选改变生产。

`publish-pending.json` 仅在发布事务进行中存在。正常空闲时必须不存在；若容器在发布中被重启，下次启动会用该文件恢复旧指针。不要手工删除该文件或改写 `current.json`。

### 3.2 查看容器状态

```sh
cd /root/dpanel/compose/lan-center
sudo docker compose ps
docker inspect --format '{{.Name}} {{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' \
  lan-center-uptime-kuma-1 lan-center-failover-1
```

正常结果应为两个容器均 `running`、`healthy`。

### 3.3 查看日志

```sh
docker logs --since 30m lan-center-uptime-kuma-1
sudo tail -n 100 /root/dpanel/compose/lan-center/data/failover/failover.log
```

只查看限定时间或限定行数，避免导出包含历史网络信息的大日志。

### 3.4 确认演练模式

```sh
docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' lan-center-failover-1 \
  | grep '^DRY_RUN='
```

生产环境必须返回：

```text
DRY_RUN=1
```

## 4. 变更前备份

每次修改 Compose、Kuma 监控项或 `failover` 脚本前都执行一次备份。

```sh
set -eu
ts=$(TZ=Asia/Shanghai date +%Y%m%d-%H%M%S)
dest="/home/zhiwen/lan-center-backups/$ts"
mkdir -p "$dest"

sudo tar -C /root/dpanel/compose --exclude='lan-center/data' \
  -czf "$dest/lan-center-config.tar.gz" lan-center

docker exec lan-center-uptime-kuma-1 \
  sqlite3 /app/data/kuma.db ".backup '/tmp/kuma-consistent.db'"
docker cp lan-center-uptime-kuma-1:/tmp/kuma-consistent.db \
  "$dest/kuma-consistent.db"
docker exec lan-center-uptime-kuma-1 rm -f /tmp/kuma-consistent.db

docker exec lan-center-failover-1 python3 -c \
  'import sqlite3; s=sqlite3.connect("/data/node-capability.db"); d=sqlite3.connect("/tmp/node-capability-consistent.db"); s.backup(d); d.close(); s.close()'
docker cp lan-center-failover-1:/tmp/node-capability-consistent.db \
  "$dest/node-capability-consistent.db"
docker exec lan-center-failover-1 rm -f /tmp/node-capability-consistent.db

docker exec lan-center-failover-1 python3 -c \
  'import sqlite3; s=sqlite3.connect("/data/subscription-controller/controller.db"); d=sqlite3.connect("/tmp/subscription-controller-consistent.db"); s.backup(d); d.close(); s.close()'
docker cp lan-center-failover-1:/tmp/subscription-controller-consistent.db \
  "$dest/subscription-controller-consistent.db"
docker exec lan-center-failover-1 rm -f /tmp/subscription-controller-consistent.db

sudo tar -C /root/dpanel/compose/lan-center/data/failover \
  --exclude='subscription-controller/controller.db*' \
  -czf "$dest/subscription-controller-files.tar.gz" \
  subscription-controller subscription-sources.json

sudo chown -R zhiwen:zhiwen "$dest"
(cd "$dest" && sha256sum lan-center-config.tar.gz kuma-consistent.db \
  node-capability-consistent.db subscription-controller-consistent.db \
  subscription-controller-files.tar.gz > SHA256SUMS)
(cd "$dest" && sha256sum -c SHA256SUMS)
echo "$dest"
```

备份成功必须同时满足：

- 命令无错误退出；
- `sha256sum -c` 全部为 `OK`；
- 压缩包、Kuma 数据库、节点能力数据库和订阅控制器数据库均存在且大小不为零。

## 5. 恢复

### 5.1 完整恢复

以下示例恢复首次变更前备份。执行前确认备份目录和目标目录完全一致。

```sh
backup=/home/zhiwen/lan-center-backups/20261013-180800-pre-monitor-hardening
project=/root/dpanel/compose/lan-center

test -f "$backup/lan-center-config.tar.gz"
test -f "$backup/kuma-pre-hardening.db"
cd "$backup"
sha256sum -c SHA256SUMS

cd "$project"
sudo docker compose down
sudo tar -C /root/dpanel/compose -xzf "$backup/lan-center-config.tar.gz"
sudo cp "$backup/kuma-pre-hardening.db" "$project/data/uptime-kuma/kuma.db"
sudo rm -f "$project/data/uptime-kuma/kuma.db-wal" "$project/data/uptime-kuma/kuma.db-shm"
cd "$project"
sudo docker compose config --quiet
sudo docker compose up -d
```

恢复后按第 8 节重新验收。

### 5.2 只恢复 Kuma 数据库

仅当 Compose 和脚本正确、只有监控配置损坏时使用：

```sh
backup=/home/zhiwen/lan-center-backups/20261013-180800-pre-monitor-hardening
project=/root/dpanel/compose/lan-center

test -f "$backup/kuma-pre-hardening.db"
cd "$backup"
sha256sum -c SHA256SUMS

cd "$project"
sudo docker compose stop uptime-kuma
sudo cp data/uptime-kuma/kuma.db "data/uptime-kuma/kuma.db.before-restore-$(date +%s)"
sudo cp "$backup/kuma-pre-hardening.db" data/uptime-kuma/kuma.db
sudo rm -f data/uptime-kuma/kuma.db-wal data/uptime-kuma/kuma.db-shm
sudo docker compose up -d uptime-kuma
```

数据库恢复必须在 Kuma 停止后执行，不能覆盖正在使用的 SQLite 文件。

### 5.3 恢复本次 V2 变更前状态

249 恢复路径：

```sh
backup=/home/zhiwen/lan-center-backups/20261013-195256-node-capability-v2-prechange
project=/root/dpanel/compose/lan-center

cd "$backup"
sha256sum -c SHA256SUMS
cd "$project"
sudo docker compose stop failover
sudo tar -xzf "$backup/lan-center-files.tar.gz" -C /root/dpanel/compose \
  --exclude='lan-center/data'
sudo cp "$backup/node-capability.db" "$project/data/failover/node-capability.db"
sudo rm -f "$project/data/failover/node-capability.db-wal" \
  "$project/data/failover/node-capability.db-shm"
cd "$project"
sudo docker compose up -d --build failover
```

OpenClash 恢复路径：

```sh
backup=/root/openclash-backups/20261013-195256-node-capability-v2-prechange
cd "$backup"
sha256sum -c SHA256SUMS
/etc/init.d/openclash stop
tar -xzf "$backup/openclash-files.tar.gz" -C /
/etc/init.d/openclash start
```

本次 V2 只更新 249 的评估器，正常回滚时不需要恢复 OpenClash。只有后续变更过路由器文件时才执行 OpenClash 恢复。

### 5.4 恢复自动订阅控制器变更前状态

备份位置：

- 249：`/home/zhiwen/lan-center-backups/20261013-215006-subscription-control-prechange`
- OpenClash：`/root/openclash-backups/20261013-215006-subscription-control-prechange`

先恢复路由器，使 OpenClash 不再依赖 249 控制器：

```sh
backup=/root/openclash-backups/20261013-215006-subscription-control-prechange
cd "$backup"
sha256sum -c SHA256SUMS
tar -tzf openclash-prechange.tar.gz >/dev/null
/etc/init.d/openclash stop
tar -xzf openclash-prechange.tar.gz -C /
/etc/init.d/openclash start
```

确认 `uci get openclash.config.config_path` 已回到备份中的原 R4 文件且业务恢复后，再恢复 249：

```sh
backup=/home/zhiwen/lan-center-backups/20261013-215006-subscription-control-prechange
project=/root/dpanel/compose/lan-center
cd "$backup"
sha256sum -c SHA256SUMS
cd "$project"
sudo docker compose stop failover uptime-kuma
sudo tar -xzf "$backup/lan-center-files.tar.gz" -C /root/dpanel/compose
sudo cp "$backup/node-capability.db" "$project/data/failover/node-capability.db"
sudo cp "$backup/kuma.db" "$project/data/uptime-kuma/kuma.db"
sudo rm -f "$project/data/failover/node-capability.db-wal" \
  "$project/data/failover/node-capability.db-shm" \
  "$project/data/uptime-kuma/kuma.db-wal" \
  "$project/data/uptime-kuma/kuma.db-shm"
cd "$project"
sudo docker compose config --quiet
sudo docker compose up -d
```

恢复顺序不能颠倒；否则原 OpenClash 仍指向已经停止的本地 provider 服务。

## 6. 安全更新流程

1. 按第 4 节备份。
2. 在本地项目修改并检查，不直接在线编辑生产文件。
3. 上传为候选文件，不立即覆盖正式 Compose。
4. 在生产目录执行：

```sh
sudo docker compose -f docker-compose.yml.candidate --env-file .env config --quiet
sudo diff -u docker-compose.yml docker-compose.yml.candidate
```

5. 只重建发生变化的服务。例如只修改 Kuma：

```sh
sudo docker compose up -d --no-deps --force-recreate uptime-kuma
```

6. 按第 8 节验收。
7. 验收失败立即恢复原 Compose 或完整备份。

禁止事项：

- 不使用 `docker compose down -v`；
- 不删除 `data/`；
- 不把 `.env`、数据库或日志提交到 GitHub；
- 不为了修复一个监控而重启 249 上全部容器；
- 不在未验证备份时更新镜像。

## 7. 故障排查

### 7.1 整个面板无法访问

依次检查：

```sh
ping 10.88.0.249
curl -I --max-time 8 http://10.88.0.249:3101/
docker inspect --format '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{end}}' \
  lan-center-uptime-kuma-1
docker logs --since 15m lan-center-uptime-kuma-1
```

只有容器停止或健康检查失败时，才单独重启 Kuma：

```sh
cd /root/dpanel/compose/lan-center
sudo docker compose restart uptime-kuma
```

### 7.2 DNS 两项同时失败

检查顺序：

1. `10.88.0.254` 是否能 Ping；
2. 53 端口和 OpenClash DNS 劫持是否正常；
3. OpenClash、Dnsmasq 是否运行；
4. 最近 OpenClash 日志是否有 DNS 超时。

不要先改业务分流规则。

### 7.3 国内业务失败、海外业务正常

重点检查：

- `.cn` 直连规则是否仍在业务规则之前；
- AMD、涂鸦域名是否命中 DIRECT；
- 国内 DNS 是否返回合理结果；
- 是否只有一个站点自身故障。

### 7.4 ChatGPT 或 Gemini 单独失败

先比较：

- 对应业务监控；
- `DNS·海外域名`；
- `业务·Google策略组` 与 `链路·实际海外出口`；
- OpenClash 对应业务组的当前节点。

DNS 和 Google 正常但业务项失败，通常是节点业务可用性或地区限制，不等于整条网络中断。ChatGPT 探针要求 Codex POST 返回 JSON `400/401`；HTML `403` 明确视为不可用。切换业务组时只改该业务，不改人工智能父组或全部海外流量。

控制器会先回退再冷却失败节点。查看时只使用哈希日志：

```sh
sudo tail -n 50 data/failover/chatgpt-controller.log
sudo cat data/failover/chatgpt-controller.health
```

不要把节点名称写入工单或监控日志。

### 7.5 Gemini 主页返回 `429`

`gemini.google.com` 主页会对自动监控产生限流或风控误报。生产监控应使用与 OpenClash Gemini 专用池一致的 Discovery API：

```text
https://generativelanguage.googleapis.com/$discovery/rest?version=v1beta
```

修改前必须使用 SQLite `.backup` 创建 Kuma 一致性备份，停止 `uptime-kuma` 后执行 `migrations/20261013-gemini-monitor.sql`，再启动并验证连续心跳。

该监控必须关闭 `cache_bust`。Discovery API 仅接受规定查询参数；Kuma 追加随机防缓存参数时会收到 HTTP 400。

### 7.6 Gemini 出现 `Header overflow`

检查 Kuma 容器：

```sh
docker inspect --format '{{range .Config.Env}}{{println .}}{{end}}' \
  lan-center-uptime-kuma-1 | grep '^NODE_OPTIONS='
```

应为：

```text
NODE_OPTIONS=--max-http-header-size=65536
```

缺失时恢复本项目的 Compose，并只重建 `uptime-kuma`。

### 7.7 `failover` 显示代理连续失败

它只记录演练动作，不会真实切换爱快。检查：

```sh
curl -I --max-time 8 http://10.88.0.254:7893/
docker logs --since 15m lan-center-failover-1
```

代理端口可连接不代表业务一定可用，应继续查看 Kuma 的业务监控。

## 8. 生产验收

每次变更后必须完成：

1. `docker compose config --quiet` 通过；
2. 两个容器均 `running / healthy`；
3. Kuma 数据库完整：

```sh
docker exec lan-center-uptime-kuma-1 \
  sqlite3 -readonly /app/data/kuma.db 'pragma integrity_check;'
```

结果必须为 `ok`。

4. 原有监控全部正常；
5. 22 个监控启用，`OpenClash 分流验收` 分组及 8 个子项全部正常；
6. `DRY_RUN=1`；
7. 最近日志没有持续的 `error`、`fatal` 或数据库异常；
8. 保存验收后备份和验收报告。

启用自动订阅时还必须满足：

9. 活动配置是 `精准稳定-v1-r4-ha-subscription-managed.yaml`，OpenClash 原生配置自动更新为 `0`；
10. 两个 provider 手动刷新返回 HTTP 204，运行时节点数与控制器报告的内核有效数一致；
11. `/health` 为 `mode=automatic`，空闲时无 `publish-pending.json`；
12. AMD 中国、涂鸦中国、Google、ChatGPT Codex POST、Gemini、GitHub 全部通过；ChatGPT 只接受 JSON `400/401`，HTML `403` 不算通过；
13. 缓存源场景必须显示 `held`，发布失败场景必须显示 `rolled_back` 且旧指针仍可用；
14. 路由器核心、控制器、节点能力和 Kuma 数据库 `integrity_check` 全部为 `ok`。

本地告警必须存在父分组绑定，并能写入：

```sh
sudo tail -n 20 data/failover/alerts.log
```

如需手机或聊天软件通知，只在服务器 `.env` 设置 `ALERT_WEBHOOK_URL`，然后重建 `failover`；不要把 Webhook 地址提交到 GitHub。

首次部署的验收证据见 `ACCEPTANCE-20261013.md`。

## 9. 凭据和账号

- `.env` 权限应限制为仅管理员可读；
- Kuma 密码、爱快令牌和代理认证信息不得写入文档、Git 提交或聊天；
- 凭据一旦出现在聊天或截图中，应立即轮换；
- 修改账号或密码不会改善网络分流，必须与网络故障分开处理。
