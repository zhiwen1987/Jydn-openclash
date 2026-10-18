# Mihomo 只读适配器

## 当前能力

该适配器通过 Mihomo Controller API 获取独立于用户提交值的运行时证据：

- `GET /version`：内核版本和构建类型。
- `GET /configs`：模式、监听端口、LAN、IPv6 和控制器地址等非敏感摘要。
- `GET /proxies`：策略组、当前选择和成员顺序。
- `GET /rules`：运行中的规则类型、负载和目标策略。

澄网 API：

- `GET /api/v1/kernels/mihomo/status`：匿名返回 `configured/reachable/fresh/stale/observedAt` 最小状态，不返回版本、地址、节点、策略组或规则。
- `GET /api/v1/kernels/mihomo/runtime`：经身份与管理范围授权后返回完整运行态。
- `POST /api/v1/kernels/mihomo/readback`：经身份与管理范围授权后读取实际状态，并与请求中的策略草稿对账。

通用 `/api/v1/snapshot` 仍是界面演示快照，并明确返回 `dataSource: "demo"`；它不会因为配置了 Controller URL 就冒充实际运行状态。完整真实读回只由受保护的 runtime/readback 接口返回。

## 对账规则

基础版报告以下漂移：

| 漂移类型 | 含义 |
| --- | --- |
| `missing_proxy_group` | 期望策略组在 Mihomo 中不存在 |
| `group_members_mismatch` | 策略组成员或成员顺序不一致 |
| `missing_domain_rule` | 期望的域名后缀规则不存在 |
| `rule_target_mismatch` | 域名规则存在，但实际目标策略错误 |

对账成功只证明已检查字段在该次读回时一致，不证明 DNS、网络、TLS、业务接口、账号能力或长期稳定性正常。

## 安全边界

- 没有配置 `CHENGWANG_MIHOMO_URL` 时，接口返回 `503 mihomo_not_configured`，不会使用演示数据冒充真实读回。
- Controller URL 禁止内嵌账号密码、查询参数和片段。携带令牌时，HTTP 只允许字面回环 IP；远程控制器必须使用 HTTPS 且主机必须在 `CHENGWANG_MIHOMO_ALLOWED_HOSTS` 明确白名单中。
- 控制器令牌只从 `CHENGWANG_MIHOMO_TOKEN` 读取，不写入响应、日志或状态快照。
- Controller 客户端不继承环境 HTTP(S) 代理，避免令牌交给非预期中间代理。
- 客户端禁止跟随重定向，避免令牌被转发到其他地址。
- 单个响应最大 8 MiB，默认总请求超时为 5 秒；返回对象数量有硬上限。
- 运行态采用 5 秒缓存、单航班刷新、最多 16 个等待者和 30 秒陈旧上限；刷新失败的旧快照明确为 `reachable=false/fresh=false/stale=true`。
- 完整 runtime/readback 必须通过身份、资源范围和安全传输检查；未配置身份时返回 503。
- 上游错误正文不会转发给客户端；鉴权失败、超时和普通读取失败使用不同错误代码。
- 当前适配器只发送 GET 请求，没有生产写入能力。

## 尚未覆盖

- 规则优先级和遮蔽关系的完整语义对账。
- rule-provider 内容及其更新时间对账。
- DNS 运行时配置、缓存和泄漏验证。
- 代理节点协议、证书和业务能力验证。
- 配置备份、隔离启动、灰度发布、观察窗口和自动回滚。
- 设备本地修改来源识别及持续漂移监测。

上述能力完成以前，本适配器只能作为只读证据源，不能视为生产发布闭环。

## 验收证据

自动测试覆盖：

1. 四个 Controller API 均只使用 GET。
2. Bearer 令牌正确发送且不会随重定向泄漏。
3. 完全一致时输出空漂移和 `match=true`。
4. 策略组缺失、成员顺序变化、规则缺失和目标错误均能识别。
5. 未配置控制器时失败关闭。
6. 上游鉴权错误不会泄漏响应或内部错误内容。
7. 并发刷新合并、等待者背压、陈旧快照语义和敏感字段匿名脱敏。
8. 非回环明文令牌、未在白名单的远程主机和环境代理均被拒绝或绕开。

这组测试使用本地模拟 Controller，不代表已经连接或验收任何生产路由器。
