# lan-center 生产验收记录（2026-10-13）

## 变更范围

- 复用现有 `uptime-kuma` 与 `failover`，未增加新容器或对外端口。
- 将 ChatGPT 控制器从无效的单节点延迟接口改为“批量发现 + Codex POST 业务验证”。
- HTML `403` 节点立即回退并按节点哈希冷却一小时；已验证节点保持粘性。
- `failover` 增加子进程监督、原子健康状态、状态新鲜度检查和 5 MiB × 5 日志轮转。
- Kuma 的 HTTP/DNS 项增加明确超时；ChatGPT、Gemini、Google 改用 Docker 内网业务探针。
- 新增 `链路·实际海外出口`，验收组由 7 个增至 8 个子项。
- 增加本地持久告警与父分组绑定；外部 Webhook 为可选配置。
- Kuma 镜像固定为已验收的 SHA256 摘要；两个容器均保留 CPU、内存和 Docker 日志限制。

## 故障复现与修复证明

旧控制器把订阅节点当作顶层代理调用，74 个候选全部返回 `404`，因此长期错误回退。首次改用 OpenAI API 批量检测后，一个香港候选虽能测速，却使 Codex 后端返回 Cloudflare HTML `403`。

最终控制器对候选执行真实 `POST https://chatgpt.com/backend-api/codex/responses`：

- 第一批 5 个候选全部被淘汰；
- 第二批继续跳过冷却哈希，第三个候选返回 JSON `401`，验证通过；
- 上线后控制器重启回读仍保持该候选；
- ChatGPT 本地业务探针连续 10 次通过；
- 随后 Google 探针增加一次快速重试，连续 15 次通过。

日志只保存节点短哈希，不保存节点名称。

## 最终验收

| 项目 | 结果 |
| --- | --- |
| Uptime Kuma | `running / healthy`，版本 2.5.6，固定镜像摘要 |
| failover | `running / healthy`，镜像 `lan-center-failover:2` |
| 数据库 | `pragma integrity_check = ok` |
| 启用监控 | 22 |
| OpenClash 验收组 | 8 个子项 |
| DNS 国内/海外 | 最近 5 次全部 UP |
| AMD 中国 / 涂鸦中国 | 最近 5 次全部 UP |
| ChatGPT / Gemini | 最近 5 次全部 UP |
| Google 策略组 | 最终 UP；内部快速重试后连续 15 次通过 |
| 实际海外出口 | 最近 5 次全部 UP |
| 本地告警 | HTTP 204，日志落盘，父分组绑定 1 条 |
| 爱快保护 | `DRY_RUN=1` |
| 资源限制 | failover 64 MiB / 0.2 CPU；Kuma 384 MiB / 0.5 CPU |
| 容器重启计数 | 0 |

## 备份与回滚

最新迁移前备份：

`/home/zhiwen/lan-center-backups/20261013-180800-pre-monitor-hardening`

其中 `lan-center-config.tar.gz`、`kuma-pre-hardening.db`、`docker-compose.yml` 和 `docker-inspect.json` 的 SHA256 校验均为 `OK`。

```sh
backup=/home/zhiwen/lan-center-backups/20261013-180800-pre-monitor-hardening
project=/root/dpanel/compose/lan-center

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

回滚后必须重新检查容器健康、端口 `3101`、数据库完整性、`DRY_RUN=1` 和原监控状态。
