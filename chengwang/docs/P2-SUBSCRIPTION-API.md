# P2-05 候选产品 API、批准与审计协调

状态：已接线，隔离 CI 迭代中，尚未整体验收。不将此文、源码存在或 Python 合成检查计作隔离验收或生产上线。前阶段已验证源码与结果见 [P2 底座验收](P2-SUBSCRIPTION-ACCEPTANCE.md)。完整系统目标仍按[进度台账](PROJECT-PROGRESS-LEDGER.md)保留。

## 固定边界

- 只操作本地订阅库存、来源批准与命令记录。所有 HTTP 响应保持 `LOCAL_SUBSCRIPTION_ADMISSION_ONLY` / `authorization=BLOCKED` / `deviceActionsExecuted=false`。本地接纳、回退及批准均不是设备发布、业务健康或生产权限。
- HTTP 必须正常 TLS，包括 loopback；严格 Bearer 由真实身份库认证，不复用旧 AdminToken。HTTP 与应用服务分别检查权限，固定租户、站点与环境不能来自请求正文或由哈希偷换。
- 当前 core 范围 ID 只接受 1～64 字节 ASCII 标识；更宽认证身份通过完整 identity 的持久 HMAC actor 引用适配，不截断原身份，原 owner 仅保留在私有命令记录。外部审计使用不透明 actor，避免把邮箱或凭据当作公开标识。
- 来源配置是独立的私有、不可变目录：严格 0700/0600 Linux 文件、固定 IP DoT、正常证书验证、完整 CNAME/IP 校验。只允许显式 CA bundle，不从不可枚举的系统根池声称得到精确批准绑定。原 URL、秘密版本、CA、DNS 与允许列表全部进入私有策略 Material，经持久键和 scope/source 绑定 HMAC 后才形成公开摘要。
- 目录的加载/构造不等于批准。批准命令持久绑定来源、引用、策略 revision 和有效 Material；目录任何有效配置变更使旧批准失效。Fetch 前后均复核批准与源 CAS，失败不清空已接纳库存。

## 权限与路由

集合资源为 `subscription-store/<managementObjectId>`，单源资源为 `subscription-source/<src_32hex>`。通用 control-plane/draft 权限不能代替订阅权限；所有订阅动作禁止 BreakGlass 自动提权。

| 动作 | 角色 |
| --- | --- |
| `subscription.read` | Viewer、Operator、Approver、Auditor、Admin，仍需匹配范围 |
| `subscription.source.manage` / `subscription.import` / `subscription.fetch` | Operator、Admin |
| `subscription.admission.decide` / `subscription.source.approve` / `subscription.rollback` | Approver、Admin |

API 前缀为 `/api/v1/subscriptions`：

| 路径 | 方法与含义 |
| --- | --- |
| `/sources` | GET 安全来源元数据；POST 创建本地来源 |
| `/sources/{sourceId}/candidates` | GET 候选摘要；POST base64 正文导入隔离候选 |
| `/sources/{sourceId}/candidates/{candidateId}/nodes` | GET 有界节点安全投影 |
| `/sources/{sourceId}/decisions` | POST 本地接纳或拒绝 |
| `/sources/{sourceId}/rollbacks` | POST 选择曾接纳的本地候选，新建单调 revision |
| `/sources/{sourceId}/approvals` | POST 对受信目录引用作本地批准 |
| `/sources/{sourceId}/fetches` | POST 在当前批准与 CAS 下抓取并隔离导入 |
| `/commands/{commandId}` | GET 不可变历史回执与审计状态；原 owner 或具匹配权限的 Admin/Auditor |

请求正文不接受 actor、tenant/scope、任意 URL、CA、路径或代理参数；动作由路由确定。严格重复键、未知字段、UTF-8、深度、原文和 wire 预算，幂等头只能有一个。列表不一次输出全库节点；每页最多 100，继续页必须绑定源 revision，变化明确冲突，不默默漏项或把旧页拼入新版本。

## 耐久回执与恢复

外部 prepared 证据确认后才允许持久命令与业务动作。命令 ID、完整请求的私有 HMAC、actor、来源/CAS 与实际历史 mutation receipt 绑定；读取历史结果不使用当前 SourceView 假造原始版本。

业务提交后的结果证据失败必须显式 `audit_degraded`；提交是否发生无法确定时必须 `commit_unknown/stateMayHaveChanged=true`。客户端可用安全命令 ID 只读查询，不应自动重试写动作。审计拒绝记录不可用时有显式信号，不能为记录故障放行请求。

重启恢复只根据原始本地业务审计、已保存结果或批准事实补外部结果及 ACK，不重新抓取、解析导入或决策。没有足够业务回执的 prepared 命令保留 unknown，不猜测成功/失败。`OpenStore` 启动时仍会解析重验已有候选，这与恢复阶段不重执行业务是不同范围。

外部审计仍是同宿主的独立耐久 evidence 日志，不是 WORM 或独立企业见证。拒绝审计当前有每个服务实例 4096 次预算，不是跨重启/分布式限流或永久集中归档；预算耗尽或存储故障不能冒称事件已记录。

本轮拒绝审计覆盖认证、权限、写门及应用服务命令尝试，不声称所有 HTTP 格式错误均已形成事件；方法、路径、正文形状等在进入应用服务前被拒绝的情况仍有覆盖缺口。

## 主服务配置与生命周期

| 配置 | 默认与要求 |
| --- | --- |
| `CHENGWANG_SUBSCRIPTIONS_ENABLED` | 默认 false，严格布尔 |
| `CHENGWANG_SUBSCRIPTION_WRITES_ENABLED` | 独立默认 false，不借用 operation/image-trust 写门 |
| `CHENGWANG_SUBSCRIPTION_POLICY_FILE` | 可选绝对规范私有文件；不设置时只可手动本地导入，批准/抓取失败关闭 |
| 固定范围、身份、TLS | 启用时必须完整，配置与目录 scope 必须逐字一致 |

默认禁用不打开任何订阅目录。启用时初始化与恢复先于 Listen；关闭时先排空请求再关闭库存和外部审计。仅在启用订阅时，默认响应超时提高至 30 秒；显式短于 30 秒的配置拒绝启动，原先更长的可信组件超时保持。超时预算不等于能够硬中断内核 I/O，仍须依靠耐久回执描述不确定状态。

## 本轮验收合同与尚未完成项

本轮预先冻结新增 130 个具名测试：服务/存储扩展 44、API 32、受信目录 28、权限 10、配置与真实共享主服务 16。应在 ordinary/race 各实际执行，完整主模块为 2620=2490+130；旧 2490/2403/2391/2320 与上轮 87 项名单均保留，不按前缀豁免。

前两轮父门均明确失败，记录不覆盖：

| 源码 | 原运行 | 实际结果与修正 |
| --- | --- | --- |
| `6bc9d743a7021512027b60d4df6de961df2fef7d` | [39942103352](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39942103352) / job `120375781461` | 默认 vet 拒绝并列常量断言；ordinary 2588 run/pass，32 服务测试未执行，race 未开始。仅拆成两个独立预算断言，未删除约束 |
| `7b6c2891f3900970c0134dcb604936a7a6965494` | [39943748586](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39943748586) / job `120381216288` | ordinary 2620 run、2618 pass、2 fail，race 未开始。修正 Create fixture 的 collection/source 混淆，并保留无效单源 Create 先拒权的断言；DoT deadline 测试改为记录返回瞬间的单调时间并严格比较真实截止，再有界确认 context 通知，不放宽超时要求 |

两轮旧 2490/2403/2391/2320 与原 87 项指纹保持；Fuzz/seed 不计入具名 Test 数。两轮失败的原 jobs/logs API SHA256 分别为 `4de7c9eec150c50441ee6c716c0e36e717a1746dfedc99456d8dac5fb9d557ef`（3377790 字节）及 `28d33b836996a3cb5d58628c78a1c596ebfb0559f198cd2ad58460ae0fe43e9e`（3408947 字节）。

CI 调度保留运行中的验收，不因修正提交自动取消。GitHub concurrency 只保留一个 pending，新 pending 仍可能替换旧 pending，并非无限 FIFO；每轮以精确源码、run/job/attempt 与原工件为准，不将排队或被替换的候选称为通过。

主服务测试使用实际 `RunWith`、真实 TCP/正常 TLS、真实身份文件、私有库存和 evidence；它不是独立 `cmd/server` 子进程。DoT 测试与禁止 private-answer 的 Fetch 反例也不等于已成功获取真实公共 pin 的 HTTPS 200。独立主进程、完整隔离 namespace 的受信来源 Fetch 200 与拒绝矩阵、真实订阅页面双浏览器、自动调度、完整内核验证、容量/浸泡、系统级备份恢复及获批生产灰度仍须继续完成。

整项 `subscription_orchestration` 继续为 `design_only`，不会因候选 API 或局部测试改变为整套已完成。本轮不 SSH、不修改 OpenClash/爱快/DNS/Kuma/ERP、不合并 main、不发布正式镜像、不改生产。
