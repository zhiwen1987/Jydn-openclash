# 节点能力与稳定性评估系统验收

验收日期：2026-10-13
生产环境：OpenClash `10.88.0.254` + `lan-center` `10.88.0.249`
运行模式：`shadow`（影子模式）

## 1. 结论

部署验收通过。系统已开始对 74 个有效节点进行通用网络、业务能力和稳定性分层检测。它只切换 OpenClash 中的 `🧪 节点能力检测` 隔离组，不修改任何生产业务组、国家组或爱快线路。

长期统计验收尚未完成：需要继续影子运行 3–7 天，再根据样本数决定是否允许任何业务组使用评分结果。当前代码强制只允许 `shadow`，不存在误开自动接管的路径。

## 2. 变更前备份

### OpenClash

`/root/openclash-backups/20261013-185108-node-capability-prechange`

包含 UCI、活动 YAML、自定义覆写文件和 `SHA256SUMS`，校验全部为 `OK`。

### lan-center

`/home/zhiwen/lan-center-backups/20261013-185108-node-capability-prechange`

包含 Compose 配置、控制器文件、状态数据、Docker inspect 证据、Kuma 一致性数据库和 `SHA256SUMS`，校验全部为 `OK`。

验收通过后快照：

- OpenClash：`/root/openclash-backups/20261013-192538-node-capability-accepted`
- lan-center：`/home/zhiwen/lan-center-backups/20261013-192538-node-capability-accepted`

验收后快照额外包含节点能力 SQLite 一致性副本，所有文件的 `SHA256SUMS` 均已通过。

## 3. 架构验收

| 项目 | 结果 |
| --- | --- |
| OpenClash 活动配置 | `/etc/openclash/config/精准稳定-v1-r4-ha.yaml` |
| OpenClash 版本 | `0.48.002` |
| 隔离组 | `🧪 节点能力检测`，74 个节点 |
| 隔离入站 | `10.88.0.254:7895`，独立认证 |
| 未认证入站访问 | HTTP CONNECT `407`，已拒绝 |
| 已认证真实访问 | Google `204` |
| 看板 | `http://10.88.0.249:3102`，HTTP `200` |
| 看板写请求 | HTTP `405 read_only` |
| Docker 绑定 | 仅 `10.88.0.249:3102 -> 8081` |
| 主动路由切换 | `DRY_RUN=1` |
| 能力系统模式 | `CAPABILITY_MODE=shadow` |
| 数据库权限 | `0600 root:root` |
| 数据库完整性 | `ok` |
| 评估器镜像 | `lan-center-failover:3` |

## 4. 检测标准验收

1. Google、Cloudflare、Apple 三个独立目标分别连续检测两次。
2. 通用网络需要至少两个目标的两次检测均返回严格预期状态。
3. ChatGPT 使用 Codex 真实 POST，仅 JSON `400/401` 视为可用；HTML `403` 视为不可用。
4. Gemini 使用 Discovery API，要求 JSON `200`。
5. Claude 和 Netflix 独立记录，不与通用延迟混合。
6. 两次连续通用失败前进入 `cooling`，避免一次短抖动立即封禁节点。
7. 评分权重：业务可用性 50%、近期成功率 20%、传输失败/抖动 15%、延迟 10%、持续可用 5%。

首批生产样本已产生不同业务结果：通用网络通过的节点中，ChatGPT、Gemini、Claude、Netflix 仍存在分别可用和不可用的情况。这验证了系统能识别“延迟正常，但业务不可用”，没有将一种业务的结果误用到其他业务。

## 5. 原有生产功能回归

| 验收项 | 结果 |
| --- | --- |
| `failover` 容器 | `running / healthy`，重启计数 0 |
| Kuma 容器 | `running / healthy` |
| Kuma 数据库 | `integrity_check=ok` |
| Kuma 启用监控 | 22 |
| OpenClash 验收子项 | 8，最新状态全部为 1 |
| ChatGPT/Codex 业务探针 | `204` |
| Gemini 业务探针 | `204` |
| Google 策略组探针 | `204` |
| AMD 中国 TokenFactory | `200`，OpenClash 日志命中 `DIRECT` |
| 涂鸦中国 | `200` |
| 外部 Webhook/微信 | 未配置，保持仅本地日志 |

## 6. 回滚

OpenClash：

```sh
/etc/init.d/openclash stop
tar -xzf /root/openclash-backups/20261013-185108-node-capability-prechange/openclash-files.tar.gz -C /
/etc/init.d/openclash start
```

lan-center：

```sh
backup=/home/zhiwen/lan-center-backups/20261013-185108-node-capability-prechange
project=/root/dpanel/compose/lan-center
cd "$project"
sudo docker compose down
sudo tar -C "$project" -xzf "$backup/lan-center-config-data.tar.gz"
sudo cp "$backup/kuma-consistent.db" "$project/data/uptime-kuma/kuma.db"
sudo rm -f "$project/data/uptime-kuma/kuma.db-wal" "$project/data/uptime-kuma/kuma.db-shm"
sudo docker compose up -d
```

恢复前必须先在备份目录执行 `sha256sum -c SHA256SUMS`。
