# P0-d7 自动撤销刷新与跨库异常恢复（候选合同，尚未验收）

本轮仅开发分支与隔离 CI，不访问或改变生产、OpenClash、DNS、爱快或 ERP；不合并 main。Go 1.23 主模块及 Go 1.25.8 独立验证模块保持原边界。所有结果继续 advisory / authorization=BLOCKED，九项恢复 blocker 不解除。

## 自动撤销刷新

- 必须显式启用、完整配置固定 HTTPS base URL、CA、literal IP、SPKI 和有限时间预算，且候选写门开启。HTTP 请求不能更改来源或凭据。正常 TLS 主机名验证后检查 SPKI；不使用环境代理、动态 DNS、重定向或认证跳转。
- `latest.json` 是签名 envelope；其中未经认证的 generation 只作有界下载提示。缺代经固定数字路径读取，最多 64 代和有界总字节，所有安装仍经过受审计的 Store 顺序验签/双阈值轮换/累计撤销/floor/历史 grant 检查。不是完整 TUF 实现。
- 同代必须原始 envelope 摘要完全相同才是 no-op；落后、同代异内容、坏签名、过量/慢响应不续期。周期与有界退避仅在本进程运行，不声称未知撤销已即时送达。
- 只有完整获取、安装和最终精确 generation/hash 读回后记录来源新鲜度；重启清空确认，截止取本进程最大陈旧窗口与签名到期的较早者。Verify 的 BeginTracked 在同一个 bbolt 事务核对 generation/hash/截止，不能靠 preflight 消除竞态，也不跨网络持全局锁阻断撤销。
- 陈旧仅阻断验证消费，不阻断新一轮合法刷新；Store/audit 完整性失败仍必须失败关闭，不能借刷新清除。定期审计验证负责缓存健康刷新，失败导致候选停止，而非伪报健康。
- 中间代仍需满足既有 Advance 的当前有效期；经过已过期的中间 catalog 时失败关闭，不具备任意离线追赶或 TUF expired-root 更新语义。关闭刷新时 RefreshRequired/RefreshFresh 均为 false，不把“未启用强制刷新”展示成已确认外部新鲜。

## 跨库恢复

- truststate 同一严格原子 record 增加有界 operation journal/outbox，持久保存随机 ID、actor、scope 摘要、公共输入摘要、审计前缀与阶段。不单独旁挂一个无事务 JSON；不保存凭据、bundle 或私钥。
- PrepareOperation → prepared AppendOnce → 绑定真实 prepared hash → tracked mutation。catalog 提交/RESERVED/CONSUMED 与操作事实同事务；消费事实不能由普通结果参数伪造。审计结果持久后以真实 hash ACK。
- 启动时在接受请求前核对 Store、scope、审计完整前缀、prepared/result 哈希。只允许在健康且原始前缀连续的审计上幂等补齐未 ACK 的审计，随后 ACK；已 ACK 却缺失/变更的记录必须拒绝，不允许静默重建旧历史。
- New 的恢复阶段要求旧业务已经停止；它不是同一 Store 指针的热切换 API。候选入口重新打开已有 Store 的生命周期文件锁后，且在开始 HTTP 服务前执行此阶段；不得绕过该组合约束让旧 Service 在网络中运行时并发构造新实例。
- 恢复只补写事实：已提交 catalog、已消费、仍 RESERVED 或 mutation 前中断。永不重发 Registry 验证、重用已烧 grant、伪造 HTTP 成功/客户端收讫或自动创建新 grant。恢复可重复执行，不能重复追加同语义事件；同 key 异语义必须拒绝。
- 不修复损坏/缺失/陈旧 checkpoint，不截断尾部，不清空重建库，不解除 Store poison。底层 I/O/完整性故障仍需恢复健康文件并受控重新打开；启动自动对账不等于全故障免维护。
- journal 与审计快照都有硬容量，达到容量失败关闭；本阶段不自动清理历史、不实现分布式事务、WORM、整盘/Anchor 防回滚或外部单调见证。旧 v1 无 journal 数据可只读兼容，但不能凭新 journal 补造旧操作的来源证明。

## 验收与证据

保留 P0-d4 234、P0-d5 379、P0-d6 490 场景集合；旧测试名存在不代表断言不变，仍须审查 diff。新增 tests、ordinary/race/vet、真实 TLS 固定源、连续更新与拒绝、陈旧零消费、网络中撤销、健康维护、跨库断点重开/重复恢复、错误前缀/已 ACK 丢失/冲突、原真实 Distribution 链路均须按实际执行结果报告。不能把计划、workflow 定义或纯内存 fault hook 代替真实进程退出/重开证据。

设计参考：[TUF specification](https://theupdateframework.github.io/specification/) 的版本、过期与顺序轮换边界；[Transactional outbox](https://microservices.io/patterns/data/transactional-outbox) 的同库原子事实及幂等投递约束。仅参考原则，不宣称实现对应标准全部功能或 exactly-once。
