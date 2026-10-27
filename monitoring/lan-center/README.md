# lan-center

> 当前入口：中心已采用 `clash-center` 单容器架构，Kuma、CoreDNS、订阅和能力评估集中运行。请优先阅读[管理页面完整手册](../../docs/management-pages.zh-CN.md)、[最新使用手册](../../docs/system-guide.zh-CN.md)、[部署记录](../../docs/production-deployment-20261026.md)与[恢复手册](../../installer/RECOVERY.zh-CN.md)。第一来源套餐信息已按[独立事务](../../docs/subscription-info-binding-20261027.md)绑定；[后续问题记录](../../docs/diagnostics-20261027.md)中的准入锁仍待修复，第二来源信息仍待绑定。下面保留的双容器说明、历史组数和检测频率用于追溯，不作为当前生产参数；外置 Grok 宿主机任务仍单独管理。

生产位置：`10.88.0.249:/root/dpanel/compose/lan-center`

当前维护与回滚以顶部的新手册为准。历史操作记录见 [OPERATIONS.md](./OPERATIONS.md)，基础监控验收见 [ACCEPTANCE-20261013.md](./ACCEPTANCE-20261013.md)，V2 节点能力系统验收见 [ACCEPTANCE-NODE-CAPABILITY-V2-20261013.md](./ACCEPTANCE-NODE-CAPABILITY-V2-20261013.md)，自动订阅控制器验收见 [ACCEPTANCE-SUBSCRIPTION-CONTROLLER-20261014.md](./ACCEPTANCE-SUBSCRIPTION-CONTROLLER-20261014.md)。

## 历史架构与检测记录（不用于当前部署）

- `uptime-kuma`：监控面板，局域网端口 `3101`；镜像固定到已验收的 SHA256 摘要。
- `failover`：不新增第三个容器，内部同时运行代理观察、业务探针、ChatGPT 控制器、节点能力评估器、订阅发布控制器和子进程监督。
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

## 自动订阅发布控制器

- 局域网只读看板：`http://10.88.0.249:3103`。
- 支持 1–N 条订阅源；生产当前配置 2 条，新增或删除来源只修改服务器受限源文件。
- OpenClash 活动配置只把两个 provider URL 指向本地控制器，99 个策略组、134 条规则、DNS、端口和业务选择结构保持不变。
- 默认先影子观察；生产验收后才使用 `automatic`。抓取失败、使用缓存、异常降幅、内核拒绝比例超限、真实业务探针失败或发布中断时均不提交新版本。
- 发布前保留旧版本指针；发布进程被重启或主机掉电时，下次启动自动恢复旧指针。
- 上游缓存只用于维持当前服务，不能推动生产版本变化；相同异常候选需要连续确认，新节点需通过能力评估才准入。
- OpenClash 原生订阅自动更新已关闭，避免旧任务覆盖本地受控 provider；控制器每小时检查一次。
- provider 下载只允许路由器和容器内部地址，并要求独立随机令牌；源 URL、令牌、节点名称和完整出口 IP 不写入 Git。

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

自动订阅控制器变更前备份：

- OpenClash：`/root/openclash-backups/20261013-215006-subscription-control-prechange`
- 249：`/home/zhiwen/lan-center-backups/20261013-215006-subscription-control-prechange`

两端 `SHA256SUMS` 已重新校验为 `OK`；路由器压缩包也已执行可读性检查。恢复命令见操作手册第 5.4 节。

自动订阅控制器验收后快照：

- OpenClash：`/root/openclash-backups/20261014-001036-subscription-control-accepted`
- 249：`/home/zhiwen/lan-center-backups/20261014-001036-subscription-control-accepted`

验收后快照通过全部 SHA256、压缩包可读性和三个 SQLite 副本完整性检查。

## 发布约束

1. 不提交 `.env`、数据库、日志、节点名称或任何密码/令牌。
2. 发布前必须执行 Shell 语法检查、迁移幂等测试和 `docker compose config --quiet`。
3. 只重建发生变化的服务，不使用 `docker compose down -v`。
4. 验收必须包含：22 个启用监控、验收组 8 个子项、三个数据库完整性、业务探针连续检查、订阅指针/事务状态、provider 内核有效数、控制器回读、容器健康和资源限制。
