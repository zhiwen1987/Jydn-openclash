# lan-center 生产验收记录（2026-10-13）

## 变更范围

- 复用现有 `lan-center`，没有新增第二套监控栈。
- 保留原有 13 个监控项。
- 新增 `OpenClash 分流验收` 分组及 7 个子监控。
- 为 Uptime Kuma 设置 `NODE_OPTIONS=--max-http-header-size=65536`，用于真实检查 Gemini 页面。
- `failover` 保持 `DRY_RUN=1`，不会修改爱快规则。
- 复用 `failover` 容器加入 ChatGPT 专用池控制循环，不新建容器。

## 验收结果

| 项目 | 结果 |
| --- | --- |
| Uptime Kuma 容器 | running / healthy |
| failover 容器 | running / healthy |
| 数据库完整性 | `pragma integrity_check` = `ok` |
| 原有监控 | 13/13 启用，13/13 正常 |
| OpenClash 验收组 | 分组和 7 个子项全部正常 |
| 国内 DNS | 正常，指定 `10.88.0.254` |
| 海外 DNS | 正常，指定 `10.88.0.254` |
| AMD 中国 TokenFactory | HTTP 200 |
| 涂鸦中国 | HTTP 200 |
| ChatGPT | HTTP 200 |
| Gemini | HTTP 200 |
| Google 204 | HTTP 204 |
| ChatGPT 控制循环 | 运行正常；当前无合格独立节点，状态为 `fallback` |

## 变更前备份

`/home/zhiwen/lan-center-backups/20261013-035740`

ChatGPT 控制器变更前备份：`/home/zhiwen/lan-center-backups/20261012-212843-chatgpt-controller`。

Gemini 监控修复前备份：`/home/zhiwen/lan-center-backups/20261013-113634-gemini-monitor-fix`。Gemini 监控已从持续返回 `429` 的主页改为 Discovery API，与 OpenClash Gemini 专用池使用相同业务入口。

修复后验收：`cache_bust=0`；Gemini 连续 5 次返回 `200 OK`，耗时 `317–690 ms`；`OpenClash 分流验收` 父监控及 7 个子监控均为 UP；Kuma 数据库 `integrity_check=ok`；`uptime-kuma` 与 `failover` 容器均为 `running/healthy`。

备份包含 `lan-center-full.tar.gz`、`kuma-consistent.db`、原 `failover.sh`、`SHA256SUMS` 和 `RESTORE.md`，校验全部通过。

## 回滚

```sh
cd /root/dpanel/compose/lan-center
sudo docker compose down
sudo tar -C /root/dpanel/compose -xzf /home/zhiwen/lan-center-backups/20261013-035740/lan-center-full.tar.gz
cd /root/dpanel/compose/lan-center
sudo docker compose up -d
```

回滚后应再次检查两个容器、端口 `3101`、Kuma 数据库完整性和原 13 个监控项。
