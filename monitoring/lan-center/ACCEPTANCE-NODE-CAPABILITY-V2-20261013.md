# 节点能力与稳定性评估 V2 生产验收

验收日期：2026-10-13
运行模式：`shadow`
部署主机：`10.88.0.249`
被测 OpenClash：`10.88.0.254`

## 1. 结论

V2 工程验收通过，已在生产环境以影子模式运行。系统只操作 `🧪 节点能力检测` 隔离组，不修改业务组、国家组、爱快策略或 WAN 状态。

本次验收证明代码、数据迁移、调度、隔离性、真实生产链路和回滚资料符合发布要求。节点长期统计质量仍需要 3–7 天样本，不把首日数据当作自动接管依据。

## 2. 发布前备份

- OpenClash：`/root/openclash-backups/20261013-195256-node-capability-v2-prechange`
- 249：`/home/zhiwen/lan-center-backups/20261013-195256-node-capability-v2-prechange`
- 两端 `SHA256SUMS` 全部校验为 `OK`。

验收后快照：

- OpenClash：`/root/openclash-backups/20261013-203308-node-capability-v2-accepted`
- 249：`/home/zhiwen/lan-center-backups/20261013-203308-node-capability-v2-accepted`
- 验收后快照同样已通过全部 SHA256 校验。

详细恢复命令见 `OPERATIONS.md` 第 5.3 节。

## 3. 已交付功能

1. 节点间调度节拍从 30 秒降为 10 秒。
2. 未评估节点优先，已评估状态和调度进度持久化到 SQLite。
3. 快速体检和业务深测分层：首轮完成前不执行全业务深测。
4. 健康/降级/业务受限 15 分钟复检，冷却/不可用 5 分钟复检，业务 6 小时复检。
5. 利用 Mihomo 节点 ID 保留改名后的历史记录，又不存储节点密钥。
6. 通用检测保留 Google、Cloudflare、Apple 三目标双次检查标准。
7. 业务画像扩展为 ChatGPT、Gemini、Claude、Netflix、YouTube、Disney+、GitHub、Telegram。
8. 失败原因分为 DNS、连接、TLS、超时、限流、地区限制、访问拒绝、上游异常和内容不匹配。
9. 看板新增扫描进度、预计剩余时间、可信度、数据过期、出口国家/机房、业务概览和节点筛选。
10. 出口 IP 只保存 16 位哈希，面板不显示完整公网 IP。
11. 新增 AMD 中国、涂鸦中国、Google、ChatGPT、Gemini、GitHub 的生产路径低频验证。
12. 面板仍为只读，不提供节点切换或配置修改接口。

## 4. 静态与迁移验收

| 项目 | 结果 |
| --- | --- |
| Python 编译检查 | 通过 |
| 评估器自检 | `node-capability self-test: OK` |
| Shell 语法检查 | 通过 |
| Compose 解析 | 通过 |
| 候选镜像构建 | 通过 |
| 生产数据库副本迁移 | 474 条探测记录迁移前后一致 |
| 迁移后 `integrity_check` | `ok` |
| 节点改名指纹自检 | 通过 |

## 5. 生产运行验收

| 项目 | 结果 |
| --- | --- |
| `failover` 镜像 | `lan-center-failover:4` |
| 容器状态 | `running / healthy / restart=0` |
| 评估模式 | `shadow` |
| 爱快模式 | `DRY_RUN=1` |
| 节点总数 | 74 |
| 首轮快速体检 | 74/74 |
| 节点指纹 | 74/74 |
| V2 业务类型 | 8 项均已生成生产样本 |
| SQLite 完整性 | `ok` |
| 看板 GET | HTTP 200 |
| 看板 POST | HTTP 405 `read_only` |
| 面板绑定 | `10.88.0.249:3102 -> 8081` |
| 密钥和数据库权限 | `600` |
| 外部 Webhook | 关闭 |

## 6. OpenClash 隔离和回归

| 项目 | 结果 |
| --- | --- |
| 活动配置 | `精准稳定-v1-r4-ha.yaml` |
| 核心运行时长 | 发布后查询约 1512 分钟，评估器发布未重启 OpenClash |
| 核心配置检查 | 使用运行进程同等 `SAFE_PATHS` 后通过 |
| 隔离入站绑定 | `10.88.0.254:7895` |
| 未认证代理请求 | HTTP CONNECT 407 |
| 已认证隔离节点验证 | HTTP 204 |
| AMD 中国连接 | 4/4 活动连接命中 `DIRECT` |
| 涂鸦中国连接 | 1/1 活动连接命中 `DIRECT` |
| 最近核心解析/panic 错误 | 0 |

## 7. 真实业务回归

V2 生产路径一次完整验收：

| 业务 | 结果 |
| --- | --- |
| AMD 中国 | HTTP 200 |
| 涂鸦中国 | HTTP 200 |
| Google | HTTP 204 |
| ChatGPT/Codex | JSON HTTP 401，判定为业务路径已通 |
| Gemini | JSON HTTP 200 |
| GitHub | HTTP 200 |

Uptime Kuma：

- 数据库 `integrity_check=ok`；
- 22 个启用监控；
- `OpenClash 分流验收` 8 个子项最新状态全部为 `1`；
- Kuma 和 failover 两个容器均为 `healthy`、`restart=0`。

## 8. 安全边界

1. 未开启节点自动接管。
2. 未修改爱快策略、WAN 状态或下一跳。
3. 未重启 OpenClash。
4. 未开启微信或外部 Webhook。
5. 未将 `.env`、数据库、日志、节点名或凭据提交到仓库。
6. 支付和交易类业务仍保持 DIRECT/固定出口边界，不参与自动节点切换。

## 9. 仍需统计验收的项目

以下项目无法通过一次发布验收得出可靠结论，需要连续运行 3–7 天：

- 不同时段的节点成功率和晚高峰衰减；
- 出口 IP/国家漂移频率；
- 业务探针的误判率；
- 订阅更新、节点改名和容器重启后的历史连续性；
- 实际用户遇到的偶发问题与探针证据的一致性。

在统计验收完成前，不允许启用生产自动切换。
