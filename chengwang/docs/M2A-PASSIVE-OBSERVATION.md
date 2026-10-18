# M2a 持续被动观测设计与验收边界

## 1. 已实现范围

M2a 只周期读取现有 Mihomo Controller 的固定 GET 接口，并保存去敏摘要：

- 控制器版本（最多 128 字节）；
- 代理对象、策略组、叶子代理和规则数量；
- 尝试、完成时间、耗时、成功与有界错误分类；
- 最近成功、连续失败、TTL、新鲜、过期、存储和时钟状态。

它不保存节点名、provider 名、规则正文、目标域名、令牌、上游错误正文或 Controller 原始响应。历史最多 4096 条；每条是最多 4 KiB 的独立原子段，不会每个周期重写全部历史。按默认 30 秒间隔可保留约 34 小时。存储持有跨进程单写锁；损坏段原样保留并使存储状态降级，但不会阻止其余控制面启动。

## 2. 明确不做的事

- 不调用 Mihomo 写接口；
- 不切换 selector、不重载配置、不清理缓存、不重启服务；
- 不测速，不发起第三方 HTTP、TLS、DNS 或业务请求；
- 不由控制器可达推断节点、互联网、DNS、ChatGPT 或 Gemini 可用；
- 不执行自动修复。

因此 API 中 `nodeTechnical`、`internet`、`business` 和 `dns` 必须保持 `unknown`，直到后续隔离探针提供各自证据。

## 3. 运行配置

```text
CHENGWANG_OBSERVATION_INTERVAL=30s
CHENGWANG_OBSERVATION_TTL=2m
```

间隔只允许 10 秒至 10 分钟，TTL 必须不小于间隔且不超过 30 分钟。Mihomo 未配置时，不创建采集器，也不产生观测文件。

## 4. API

- `GET /api/v1/observations/status`：匿名、常量成本、只读内存聚合，不触发 Controller 请求。
- `GET /api/v1/observations/mihomo/history`：最多返回 200 条；必须经过管理身份、范围和 TLS/回环门禁。

生产没有配置管理身份时，历史接口按设计返回 503。不得为查看历史而匿名开放节点明细。

## 5. 安全和资源边界

- 后台采集与交互式读回共用串行门，避免并发放大 Controller 负载。
- 容器丢弃全部 Linux capabilities，并限制 0.5 CPU、256 MiB 内存和 128 PID。
- 原始错误只映射为 `timeout`、`authentication`、`upstream_http`、`network` 或 `read_failed`。
- 时钟回拨立即使当前观测不可用于协调；不会通过修改时间延长旧证据寿命。
- 存储失败显示 `degraded`，不得把内存结果冒充为已持久化历史。

## 6. M2a 验收门

1. Go 全量、vet、关键包 race、前端测试、ESLint 和构建通过。
2. 匿名接口不含节点、provider、规则、目标或历史样本。
3. 未授权历史请求在读取明细前失败；LAN 明文 Bearer 返回 426。
4. 控制器失败后不沿用旧绿色；有旧成功时明确为 stale/degraded。
5. 重启后历史恢复，但旧时间不因重启变新鲜。
6. 候选容器使用生产数据副本，通过停止、启动、断开 Controller、恢复和回滚测试。
7. 正式部署前建立新备份；部署后证明 OpenClash 配置哈希、进程状态和策略选择未改变。
8. 生产 Shadow 观察至少 24 小时后，才签 M2a 稳定性结论。

## 7. 后续 M2b

主动探针必须是独立隔离执行器：bridge 网络、无 Controller 令牌、无生产数据卷、无 Docker socket、固定许可目标目录、禁止任意 URL、禁止重定向、SSRF 与 DNS 重绑定防护、并发/速率/队列/磁盘硬上限。403 和 429 默认是不确定或受限状态，不得直接判业务正常。M2b 即使完成仍只观察，不自动切换节点。
