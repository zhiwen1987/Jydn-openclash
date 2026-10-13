# OpenClash 自动订阅发布控制器生产验收

验收日期：2026-10-14

OpenClash：`10.88.0.254`

控制器：`10.88.0.249:3103`

生产模式：`automatic`

## 1. 结论

自动订阅发布控制器已完成生产切换并通过严格验收。

OpenClash 继续使用原 R4 的 99 个策略组、134 条规则、DNS、端口和业务拓扑；只将两个 HTTP provider 的来源切换为局域网内受控发布端点。订阅抓取、节点准入、异常确认、Mihomo 内核有效数检查、六项真实业务验证、失败回滚和中断恢复均已启用。

最终真实自动发布状态为 `published`：两条来源均为实时数据，批准 70 条，Mihomo 实际接受 68 条。2 条被内核过滤的记录集中在第二个 provider，拒绝比例低于 10% 门限；六项业务连续两轮通过后提交。

## 2. 备份和恢复点

变更前备份：

- OpenClash：`/root/openclash-backups/20261013-215006-subscription-control-prechange`
- 249：`/home/zhiwen/lan-center-backups/20261013-215006-subscription-control-prechange`

验收后备份：

- OpenClash：`/root/openclash-backups/20261014-001036-subscription-control-accepted`
- 249：`/home/zhiwen/lan-center-backups/20261014-001036-subscription-control-accepted`

四个验收后 249 文件和两个路由器文件均通过 `sha256sum -c`；三个 SQLite 备份副本的 `integrity_check` 均为 `ok`，两个压缩包均可读取。恢复命令见 `OPERATIONS.md` 第 5.4 节。

## 3. 配置不变性

| 项目 | 结果 |
| --- | --- |
| 原始配置 | `精准稳定-v1-r4-ha.yaml` |
| 活动配置 | `精准稳定-v1-r4-ha-subscription-managed.yaml` |
| proxy provider | 2 |
| 策略组 | 99，完全不变 |
| 规则 | 134，完全不变 |
| `.cn` 直连顺序 | 第 39 条，早于第 134 条最终兜底 |
| DNS、端口、业务拓扑 | 完全不变 |
| OpenClash 原生配置自动更新 | `0`，防止旧任务覆盖受控 provider |
| Mihomo 核心配置测试 | 通过 |

独立结构验证器证明，候选与原始配置只有 provider URL 和更新间隔发生变化。候选文件权限为 `600`，发布令牌不进入仓库或报告。

## 4. 自动发布门禁

已启用：

1. 1–N 来源配置与 `600` 权限检查；
2. 三次抓取重试、最大响应限制和七天本地缓存；
3. 缓存只维持当前服务，不能推动生产版本变化；
4. 订阅状态行清理、HMAC 稳定指纹和跨来源去重；
5. 旧节点粘性、确认不可用后移除；新节点连续成功且可信度达标后准入；
6. 数量骤降、单来源骤降、最低批准数和连续异常确认；
7. provider 刷新后回读 Mihomo 实际接受数，单来源拒绝超过 10% 自动回滚；
8. AMD 中国、涂鸦中国、Google、ChatGPT Codex POST、Gemini、GitHub 真实业务检查；
9. 发布事务 pending 文件、进程中断恢复和旧指针回滚；
10. 只保留最近 100 个发布版本，同时保护当前版本和事务版本。

ChatGPT 使用真实 Codex POST，只接受 JSON `400/401`。`/api/auth/session` 的 HTML `403` 不再被误用为 Codex 线路结论。

## 5. 故障场景验收

| 场景 | 结果 |
| --- | --- |
| 一条来源 HTTP 429、使用缓存 | `held`，当前版本不变 |
| provider 刷新失败 | `rolled_back`，旧指针恢复 |
| 控制接口超时 | `rolled_back`，旧指针恢复 |
| 发布过程中进程中断 | 自检证明下次启动恢复旧指针 |
| Windows 管道尾部回车 | 构建器和验证器拒绝控制字符 |
| 候选文件不存在 | 结构验证必须先通过，禁止把 Mihomo 空配置假成功作为验收 |
| 内核过滤少量节点 | 记录批准数与有效数；低于门限且业务通过才发布 |

生产最终状态：

- `mode=automatic`
- `status=ok`
- `release_status=published`
- `cached_sources=0`
- `node_count=70`
- `effective_node_count=68`
- `current_matches=true`
- `publish-pending.json` 不存在

## 6. 生产运行验收

| 项目 | 结果 |
| --- | --- |
| 活动核心进程 | 使用 managed 配置运行 |
| provider 实际节点 | 第一源 44，第二源 24，共 68 |
| DNS 查询 | 正常 |
| OpenClash DNS 劫持 | 1 条规则存在 |
| 最近核心严重错误 | 0 |
| 最近 provider 刷新错误 | 0 |
| 控制器面板 GET | HTTP 200 |
| 控制器修改请求 POST | HTTP 405 |
| failover 容器 | `running / healthy / restart=0` |
| Kuma 容器 | `running / healthy / restart=0` |
| 节点能力数据库 | `ok` |
| 订阅控制器数据库 | `ok` |
| Kuma 数据库 | `ok` |
| 启用监控 | 22 |
| OpenClash 分流验收 | 8/8 最新状态为成功 |
| ChatGPT 专用控制器 | `ok / capable_node_selected` |

发布后六项真实业务连续两轮结果均为 `PASS`。

## 7. 安全边界

1. 爱快仍为 `DRY_RUN=1`，控制器不修改 WAN 或爱快规则。
2. 节点能力评估仍为影子模式，只操作隔离检测组。
3. 支付和交易业务未改动，继续使用既定 DIRECT/固定出口策略。
4. 看板为只读；provider 下载仅允许路由器和容器内部地址，并要求独立令牌。
5. 仓库不包含真实订阅 URL、令牌、密码、数据库、日志、节点名称或完整出口 IP。
6. 本系统提高自动更新安全性，但不承诺互联网端到端 `99.999999%` 可用率；运营商、上游订阅、代理节点和目标网站仍是外部依赖。
