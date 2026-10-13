# lan-center

生产位置：`10.88.0.249:/root/dpanel/compose/lan-center`

完整维护与回滚步骤见 [OPERATIONS.md](./OPERATIONS.md)，基础监控验收见 [ACCEPTANCE-20261013.md](./ACCEPTANCE-20261013.md)，V2 节点能力系统验收见 [ACCEPTANCE-NODE-CAPABILITY-V2-20261013.md](./ACCEPTANCE-NODE-CAPABILITY-V2-20261013.md)。

## 当前架构

- `uptime-kuma`：监控面板，局域网端口 `3101`；镜像固定到已验收的 SHA256 摘要。
- `failover`：不新增第三个容器，内部同时运行代理观察、业务探针、ChatGPT 控制器、节点能力评估器和子进程监督。
- 爱快始终保持 `DRY_RUN=1`，本服务不会自动修改爱快规则。

## 节点能力评估 V2（影子模式）

- 局域网看板：`http://10.88.0.249:3102`。
- OpenClash 使用独立组 `🧪 节点能力检测` 和独立认证入站 `10.88.0.254:7895`。
- 检测器只切换该隔离组，不会切换任何业务组、国家组或爱快线路。
- 通用检测要求 Google、Cloudflare、Apple 三目标中至少两个连续两次返回严格预期状态。
- 业务能力分开记录 ChatGPT/Codex、Gemini、Claude、Netflix、YouTube、Disney+、GitHub 和 Telegram，不再用单一延迟代替业务可用性。
- 首轮未评估节点优先；健康节点 15 分钟复检，异常节点 5 分钟复检，业务深测 6 小时复检。
- 扫描进度保存在 SQLite，容器重启后未评估节点依然优先，不再从列表第一个节点重新开始。
- 检测结果记录 DNS、连接、TLS、超时、限流、地区限制和内容异常等失败类型，并显示可信度和数据新鲜度。
- 出口只保存国家、Cloudflare 机房与 IP 哈希，不在面板或日志中暴露完整公网 IP。
- 生产分流验证每 5 分钟低频检查 AMD 中国、涂鸦中国、Google、ChatGPT、Gemini 和 GitHub，与隔离节点检测分开展示。
- SQLite 保留 30 天检测数据，评分组成为业务可用性 50%、近期成功率 20%、丢包/抖动 15%、延迟 10%、持续可用 5%。
- 当前强制 `CAPABILITY_MODE=shadow`；系统只评估和推荐，不允许自动接管生产业务组。

ChatGPT 控制器每 300 秒检查一次。候选节点先通过 OpenAI API 批量筛选，再临时选中并对 Codex 后端执行真实 POST；只接受 JSON `400/401`。HTML `403` 节点会立刻回退并进入一小时冷却名单。已通过真实检查的节点保持粘性，不因小幅延迟差主动切换。

## OpenClash 验收组

`OpenClash 分流验收` 当前有 8 个子项：

1. 国内 DNS；
2. 海外 DNS；
3. AMD 中国 TokenFactory；
4. 涂鸦中国；
5. ChatGPT/Codex 真实 POST；
6. Gemini Discovery API；
7. Google 策略组真实出口；
8. 独立监控主机的实际海外出口。

所有 HTTP 项设置明确超时并关闭随机防缓存参数。业务探针只在 Compose 内网开放；本地告警写入 `data/failover/alerts.log`，如服务器 `.env` 设置 `ALERT_WEBHOOK_URL`，还会转发到外部 Webhook。

## 最近可用备份

最近 V2 变更前一致性备份：

`/home/zhiwen/lan-center-backups/20261013-195256-node-capability-v2-prechange`

校验：

```sh
cd /home/zhiwen/lan-center-backups/20261013-195256-node-capability-v2-prechange
sha256sum -c SHA256SUMS
```

恢复前必须先停止两个容器。该备份包含配置压缩包和一致性 Kuma 数据库，恢复命令见操作手册第 5 节。

## 发布约束

1. 不提交 `.env`、数据库、日志、节点名称或任何密码/令牌。
2. 发布前必须执行 Shell 语法检查、迁移幂等测试和 `docker compose config --quiet`。
3. 只重建发生变化的服务，不使用 `docker compose down -v`。
4. 验收必须包含：22 个启用监控、验收组 8 个子项、数据库完整性、业务探针连续检查、控制器回读、容器健康和资源限制。
