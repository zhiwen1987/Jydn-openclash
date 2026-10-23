# P2-05 订阅应用：隔离验收记录

验收源码：`f0c23d64f4bc6e8d750f8b588aff18cd83c3eda8`；日期：2026-10-23。本轮本地准入后端与下述有界回归验收通过，四条 CI 同源码。它不代表订阅编排完整、镜像正式发布或生产上线；未完成项继续保留，不以历史提交通过或文档提交代验。

## 实际实现范围

| 范围 | 本轮实现 | 不代表 |
| --- | --- | --- |
| 产品 API | 来源、候选摘要、节点分页、本地接纳/拒绝/回退、批准、抓取、历史命令查询；正常 TLS 与严格请求闭集 | 任意 URL 入口、完整提供者兼容、节点可用或设备发布 |
| 独立 RBAC | 七个订阅动作、角色分工、租户/站点/环境及资源范围；禁止订阅 BreakGlass 提权 | 已接入企业 SSO、多人审批或分布式权限平台 |
| 耐久命令与审计 | prepared 先于业务动作；历史业务回执绑定；提交未知与审计降级；重启只修结果/ACK、不重新抓取或导入 | 原子跨库事务、WORM、独立企业见证或真实断电验收 |
| 受信来源目录 | 私有 Linux 文件、显式 CA、固定 IP DoT；全部有效输入经 scope/source 绑定 HMAC；抓取前后复核批准和 CAS | 已验证公网提供者 HTTP 200、完整网络故障矩阵或自动调度 |
| 主服务组合 | 默认禁用、独立写门、启动前校验及恢复、共享主服务真实 TCP/正常 TLS/身份文件/库存/evidence、请求排空后关闭 | 已完成独立 `cmd/server` 订阅开启链路、容器灰度或生产切换 |

接口与配置细节见[应用合同](P2-SUBSCRIPTION-API.md)。所有订阅结果保持 `LOCAL_SUBSCRIPTION_ADMISSION_ONLY`、`authorization=BLOCKED`、`deviceActionsExecuted=false`。本地接纳不是“已上线”或“已健康”。

## 父门：已独立验收

[运行 39945208483](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39945208483)，job `120386078614`，attempt 1，精确源码为上述 `f0c23d6`。

- ordinary/race 各 2620 个具名 Test，实际 run/pass 各一次，Test fail/skip 为 0。新增 130 项：服务 32、存储扩展 12、API 32、受信目录 28、权限 10、主服务与配置 16。
- 每轮另有 12 个 Fuzz/seed run/pass，不充作具名 Test 或持续模糊测试。42 个 package 中原有无测试 `internal/domain` 的 package skip 单独保留，不把它混称为 Test skip。
- 完整 2620 对名单 SHA256：`06e0e29fbb80a30ce7819be7dda5859cccd8daed8a60060e71174138e51a1b14`；新增 130 对：`8a6406058684acd33b508a276970dcf5f951f4b3e9e332b8d82d813bd48c3736`。
- 旧 2490/2403/2391/2320 与原 87 项名单指纹精确保持。新名单来自 CI 前的固定任务卡，不是从绿色输出重建基线；未删失败项、加 skip 或前缀豁免。
- 子代理与主代理分别重放精确 Git 原四个门脚本；主代理另外从原 API 日志重新提取最后两轮 package cycle，各 10715 个事件对象逐个等于派生 GoJSON。原传输中三处 timestamp 前 BOM 仅在解析传输前缀时处理，原字节未改，未丢 Go 事件。
- 重放结果为 `semanticRunEvents=5240/packages=42`；原 CI 另实际完成 Linux 静态 176 项、11 个 schema 的 Go metaschema 校验及 vet。没有在本机执行 Go 或 Linux root 测试来冒充该证据。

原 jobs/logs API 日志 6023190 字节，SHA256 `d366b18ab692659e14a4099fd1c6583e7e0ddb70b428cbe96d9572fd0cfc7e87`。独立分析报告 SHA256 `53ddab9a27490b28d7846f84bee8e7dfcc4e9f309d49f163dd28aa93eae1d2d8`。这是日志来源，不是 artifact ZIP；此运行没有上传 artifact。

## 最终同源回归

| 检查 | 精确运行 | 当前边界 |
| --- | --- | --- |
| 原生探针/API | [39945208538](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39945208538)，job `120386078611` | success；原 ZIP/backend22 原 checker 经子代理与主代理分别重放，报告逐字等于 CI；真实 Linux 原 24 项及固定 44 unit 实际逐名执行通过 |
| CDP 与 Playwright | [39945208482](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39945208482)，jobs `120386173628` / `120386173833` | 两路径原 ZIP、原 backend22/browser checker 经子代理与主代理分别完整重放，与 CI 报告逐字一致；每路径 18 捕获、8 错误计数全 0、正常 Node/Chrome 退出 0 |
| 镜像绑定/完整候选镜像 | [39945378087](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39945378087)，job `120387454107`，attempt 1，workflow_dispatch | success；原 ZIP/API 摘要匹配，前端 117、子模块 ordinary/race 各 732、旧 Registry 各 3 名单通过独立核验；原 Registry/source/source-TLS 三检查器经子代理与主代理分别重放并逐字等于 CI。其余旧产品完整 verifier 未全部独立重放 |

浏览器 QA 目标仍是已有“代理节点”页：匿名摘要 → 授权明细 → 清令牌/明细 → 匿名重读 → 自然 TTL 撤回 → 0 样本/未评估。Browser plugin not available，使用用户选择的隔离 Chrome/CDP 与固定版本 Playwright；本机不启动实际浏览器。它不是尚未开发的订阅资源页验收。

QA 环境为正常 TLS `https://127.0.0.1:17861/`，1440×1000 与 375×812；固定 `playwright-core 1.64.1`，实际 Chrome `155.0.8059.39`。两份 DER 证书链按捕获时刻验证，TLS bypass=false，不忽略 CA/SAN。页面身份、非空、无框架覆盖层、控制台/请求错误、真实交互和自然 TTL 撤回均通过原 gate。8 张 PNG 完整性已校验；主代理抽看本轮 Playwright fresh 桌面和 CDP expired 移动两张，未对全部截图作人工像素/OCR 检查。长页面截图中的固定导航位于捕获时的滚动位置，不据此声称首屏遮挡已单独验收。

| 原始工件 | ZIP 字节数 / SHA256 | 主代理原 checker 报告 SHA256（逐字等于 CI） |
| --- | --- | --- |
| native `12497484508` | 216443 / `2246d2b8495d7fb37d7b2e163b93bae9b13a39ceecf24a6274f098d76c035135` | `a70f8b1daa7c18803bfbf454844c6b55cde0da6e3742da605b2500c519a6b3ad` |
| CDP `12497862209` | 1684494 / `b0f26b903e5eb1f0b058de0b00c226695c05bac9681045a11ede8b5d6cdc8cfb` | `4a3f57a80e04bb25926b7d5e1f9794d12c6099a7a772a6f0d3d27d18d1157f88` |
| Playwright `12498525934` | 1684991 / `44be3d06a8dfdf970804f06304fd68dccf138f6dc8f70922da02832afd8a5425` | `158e6ffb3ace5f0921a3f969d35d69165eee639ec21bf3d279600af06d6bf780` |

子代理独立核对 native 731、每条浏览器路径 737 个唯一 Git 原 blob，无 CRLF 归一化；两份原 checker 源码文件也由主代理与精确 Git 原字节再比对。源码完整性是本轮捕获绑定，不是独立可重复构建、浏览器渲染公证或公网能力证明。

镜像原 ZIP `12497919268` 为 6369152 字节，SHA256 `261db495d69f31e381ae9a8475e9e556583483aaa28796c57ccf2d0378917de6`；安全解包 1470 唯一普通文件。原 jobs/logs API 2039275 字节，SHA256 `e3bd97d155b0eeee671989665b073f3dd796d664cd17b344b9579a3fe2ff5f37`。关键来源 97 与 checkout 731 两组 before/after 原字节一致，合并 731 个原 Git blob 全部匹配，包含最新 wire 修正。

主代理重新执行精确 Git 原内联前端门，117 实际断言、7 个文件结果及 17 个 suite 计数通过，旧 77/原 33/新 7 名单保持；这仍是 mock 单元测试，不代替上文真实浏览器。子模块两轮完整 732 对名单 SHA256 均为 `47a2e1455240e8a565ac214e463ff59e059e4beaad19c993548d4b6dcc93b24c`，与前阶段精确相同，旧 728/700 保持。

已重放 Registry/source/source-TLS 三个原完整检查器，其报告分别包含 49/75/117 个输入文件摘要关系（不是测试或断言数量）。主代理报告 SHA256 分别为 `2c306e125a94c20697d35fc64b05f7692053fae197a4e4efa579f0ddaa32145b`、`dffc6e4d0f06cf16475ba2a8849d2cd8b862c4af430a921723911f4f4c435ff3`、`ef0ebe8ad25f7e5cccbf909b6a0e4f6292b9b63e7c39bab5f6e381f08dd7753d`，均逐字等于 CI 原 outcome。其余旧 image 打包/私有 archive/Docker 原 inspect 及 lifecycle/crash/state 完整 CLI 本轮未全部重放；仅确认 CI 成功、公开输入摘要与记录闭合，不冒充本机重新执行 Docker 或恢复演练。

## 保留的失败与未执行候选

| 源码/运行 | 实际事实 | 修正或限制 |
| --- | --- | --- |
| `6bc9d74` / 父门 `39942103352` | ordinary 2588 run/pass；32 服务测试因默认 vet 未执行，race 未开始 | 拆分两个预算断言，不删除任何约束 |
| `7b6c289` / 父门 `39943748586` | ordinary 2620 run、2618 pass、2 fail；race 未开始 | 修正 Create fixture 的集合/单源资源混淆；DoT deadline 改为返回瞬间单调时间与真实截止比较，再有界确认通知 |
| `8b0dae8` / 原生 `39944335937` | 三个 HTTPS 精确响应已返回，之后正常 stop 的 5 秒 communicate 超时，cleanup 也超时而要求 emergency kill；整轮失败，backend lab 未运行 | 移除信号处理器内 Event.set，仅记普通终止 flag；原 24 名、3 秒请求、5 秒正常 stop/no-kill 标准保持。新增确定性持锁合成反例；没有原 helper 栈，不能声称唯一归因本次停机超时 |
| `8b0dae8` / 镜像 `39944335909` | 旧 pending 被最新同源待验候选替换，cancelled，0 jobs | 未执行、不是 PASS；没有取消运行中的 `7b6c289` 镜像轮 |

Python [官方信号文档](https://docs.python.org/3/library/signal.html#signals-and-threads)明确警告不要在信号处理器中使用线程锁。该规范及确定性合成反例支持去除重入锁风险，但不能代替失败现场的因果证据。Windows 辅助执行的原 24 项中 8 pass/16 Linux skip 只算辅助检查，真实 Linux 24 项须以最终 CI 原日志为准。

## 尚未完成

- 独立 `cmd/server` 子进程的订阅开启链路；公共 pin 的正常 HTTPS 200 与批准入口贯穿；更完整的拒绝矩阵及实际进程崩溃/断电恢复。
- 真实订阅来源/候选/差异/库存页面及其双浏览器闭环；现有探针页通过不能代替它。
- 自动刷新与调度、完整内核配置校验、节点池/设备发布、真实业务及公网提供者能力、企业容量和长期浸泡。
- 系统级备份恢复、永久集中证据归档、正式 Registry 供应链发布及获批生产备份/灰度/观察。
- 其余旧产品 image/lifecycle/crash/state 完整原 verifier 的独立重放；私有 archive/Docker 原 inspect 不能由当前公开工件补造。
- 同宿主 evidence 不是独立企业见证；拒绝审计不是跨重启/分布式限流，HTTP 格式错误仍有审计覆盖缺口。全套 `subscription_orchestration` 不因本轮局部实现升为完整已完成。

本阶段不 SSH、不改 OpenClash/爱快/DNS/Kuma/ERP、不合并 main、不正式发布镜像、不部署生产。Temp 独立证据与短期 CI artifact 不构成永久备份。总目标及其余缺口继续见[进度台账](PROJECT-PROGRESS-LEDGER.md)。

原始运行、摘要、失败轮及边界的机器可读记录见[本轮证据](evidence/p2-subscription-api-f0c23d6.json)。这些报告随后可单独文档提交；运行验收源码仍是 `f0c23d6`，不得混称为报告提交已构建或已上线。
