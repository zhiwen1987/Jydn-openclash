# lan-center

部署位置：`10.88.0.249:/root/dpanel/compose/lan-center`

完整的日常维护、备份、恢复和故障处理步骤见 [OPERATIONS.md](./OPERATIONS.md)。

这套栈复用现有两个容器：

- `uptime-kuma`：局域网监控面板，端口 `3101`。
- `failover`：检查 OpenClash 代理健康；生产环境固定 `DRY_RUN=1`，不修改爱快规则。同一容器内的 ChatGPT 控制循环每 300 秒检查真实会话入口，只调整 ChatGPT 专用池；无合格节点时回退到人工智能父组。

## OpenClash 验收组

Kuma 中的 `OpenClash 分流验收` 包含：

- 国内与海外 DNS，指定通过 `10.88.0.254` 查询；
- AMD 中国 TokenFactory；
- 涂鸦中国；
- ChatGPT；
- Gemini；
- Google 204。

HTTP 项每 30 秒检查一次，失败后每 10 秒重试，连续重试 2 次才判定故障。Gemini 使用稳定的 Discovery API，避免主页对自动检查返回 `429` 造成误报。

## 备份与恢复

首次变更前备份：

`/home/zhiwen/lan-center-backups/20261013-035740`

校验：

```sh
cd /home/zhiwen/lan-center-backups/20261013-035740
sha256sum -c SHA256SUMS
```

恢复整套配置与数据：

```sh
cd /root/dpanel/compose/lan-center
sudo docker compose down
sudo tar -C /root/dpanel/compose -xzf /home/zhiwen/lan-center-backups/20261013-035740/lan-center-full.tar.gz
cd /root/dpanel/compose/lan-center
sudo docker compose up -d
```

如只需恢复 Kuma 数据库，应先停止 `uptime-kuma`，再用备份中的 `kuma-consistent.db` 替换 `data/uptime-kuma/kuma.db`，确认属主和权限后启动；不要在容器运行时直接覆盖数据库。

## 发布约束

1. 不提交 `.env`、Kuma 数据库、日志或任何密码/令牌。
2. 发布前先执行 `docker compose config --quiet`。
3. 仅重建发生变化的服务；本次只重建 `uptime-kuma`。
4. 验收必须包含容器健康、21 个监控启用、OpenClash 验收组全部正常，以及 AMD、涂鸦、ChatGPT、Gemini 和 Google 204 的真实请求。
