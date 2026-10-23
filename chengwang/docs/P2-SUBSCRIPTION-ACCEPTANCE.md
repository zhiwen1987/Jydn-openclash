# P2 订阅准入底座：隔离验收记录

验收源码：`d0e55c6ac7e9528f2c27bd6cbc872fc6e544d3de`；日期：2026-10-23。此记录覆盖订阅核心原型与既有产品回归，不表示产品订阅功能已接入或已上线。后续文档提交不能冒充新的运行源码。

## 实际完成

| 项目 | 已实现及已执行的检查 | 边界 |
| --- | --- | --- |
| 私有模型与身份 | 8 项：范围、闭集预算、HMAC 隔离、私有 JSON/格式化、安全节点视图 | 不认证用户，不赋予 API 权限 |
| 提供者解析 | 26 项：真实 provider YAML、URI/base64 自动识别；严格选项/类型/结构、有界输入、稳定改名重排身份、凭据变更隔离 | 仅明确支持的协议/选项子集；不是完整 Clash 配置、真实节点或内核可用性验证 |
| 私有准入库 | 34 项：独立来源、默认隔离、CAS/幂等、本地接纳/拒绝/回退、重启重验、单 writer、Linux 文件安全及失败封闭 | 故障注入不等于实际断电；本地库存指针不是设备运行版本；本地 hash 链不是外部企业见证 |
| 有界 HTTPS | 18 项：完整 DNS 集合校验、固定 dial、正常 TLS、响应预算、无环境代理/重定向/隐式重试、私有数据不导出 | DNS 合成、私有 dial 映射到实际 loopback TLS；未验公网、实际 namespace DNS 或产品批准入口 |
| 跨组件链路 | 1 项：正常 TLS 获取 → 实际解析 → 两源隔离/本地接纳 → 坏更新保持已接纳版本 → 改名/回退 → 私有文件重启读回 | 不是产品 HTTP API、调度、节点池发布或生产端到端 |

合计新增 **87 项具名测试**。交叉审查中修复了重复密码 key 遮盖类型测试、fixture 私有目录权限、Store/Fetcher 解引用格式化可能暴露私有字段，以及增量门接受过早 package pass 的问题。Store 使用共享私有 core，安全值格式化不复制互斥锁；未放宽文件权限或旧测试门。

## 实际 CI 与独立复核

| 检查 | 精确运行 | 独立结果 |
| --- | --- | --- |
| 主模块 ordinary/race/vet 及旧静态门 | [39934230035](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39934230035)，job `120349700791`，attempt 1 | 原始 jobs/logs API 字节独立读取；两轮各 2490 个 Test 实际 run/pass 一次，新 87 完整、测试级 fail/skip 为 0。旧无测试 domain 包的 package skip 单独保留；每轮 12 个 Fuzz/seed 事件另计，不充当新 Test。精确 Git 三检查器由子代理与主代理分别重放通过 |
| 原生探针/API 回归 | [39934230138](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39934230138)，job `120349701194`，attempt 1 | 原 ZIP 摘要匹配 API；精确 Git 原 checker 重放 22 输入，与 CI 报告逐字一致；710 条源码记录匹配原 Git blob；fresh/restart 6 样本，过期 0 样本/3 unknown，4 次正常退出 |
| CDP 与原生 Playwright 回归 | [39934230107](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39934230107)，jobs `120349778801` / `120349778808`，各 attempt 1 | 两路径各自原 ZIP 摘要、源码绑定、backend22 与 browser 原 checker 完整重放通过，逐字等于 CI。每条 18 捕获、6 实际样本/最新 3 目标 15 层、自然 TTL 撤回、8 错误计数全 0、正常 TLS、Node/Chrome 实际退出 0，无强制清理/guard 干预或所属进程残留 |
| 镜像信任/候选镜像回归 | [39934230001](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39934230001)，job `120349701065`，attempt 1 | success；原 ZIP/API 摘要匹配。实际前端 117 项及旧 77/原 33/新 7 指纹保持；原前端 gate 重放通过，9 项 mutation 严格拒绝。子模块 ordinary/race 各 732 实际 run/pass、测试级 fail/skip 为 0，旧 728/700 与 Registry 3 名单保持。旧产品子 CLI 不据此宣称已全部独立重放；CI 构建/执行候选镜像不代表正式发布或生产 |

完整 2490 Test 名单 SHA256：`1c3d08f5f99f1d34861a6439d8cde3d95422232dc8fa70206e2d0f09ea229dd4`；新 87：`9d5d10f17c264e20f3173320db1dc29e045cc9449d78d46424b255d9bc3ea09a`。旧 2403/2391/2320 及前阶段 71/12 增量指纹保持不变。固定名单是验收合同，不是从当前成功日志重建的替代基线。

## 浏览器 QA 范围

Browser plugin not available；按用户选择复用隔离 CI 的独立 CDP 与固定 `playwright-core 1.64.1`。实际 Chrome `155.0.8059.39`，正常 TLS 地址 `https://127.0.0.1:17861/`，视口 1440×1000 和 375×812；本机未启动实际浏览器或 Go。

流程：进入“代理节点” → 匿名摘要 → 临时授权读取分层明细 → 清除令牌/明细 → 匿名重读 → 自然撤回旧结论 → 过期 0 样本/3 未评估。页面身份、非空内容、无框架错误覆盖层、控制台与网络错误、真实交互、布局与截图完整性均由两路径独立校验。实际证书链两个 DER，经捕获时间的 OpenSSL 校验；不是忽略 TLS 错误。

两路径共 8 张原 PNG 完整解码；主代理检查了本轮 Playwright fresh 桌面与 CDP expired 移动截图，证据层次与过期未评估状态可读，未逐张进行人工像素审查。长页面捕获中的固定导航出现在捕获时滚动位置，不据此声称首屏固定栏遮挡已单独验收。PNG 检查不是 OCR，也不覆盖其他视口、浏览器或整个产品的全部功能页。

## 来源与摘要

主模块原 API 日志：5,773,281 字节，SHA256 `366f45c17534b32b3984def4d9743eba65053d69805a9c3e70f8255e65df051e`，不是 artifact ZIP。独立完整名单报告 517,395 字节，SHA256 `f00f4b5f4479d06adf00fd819d989dae15c5dedcdde267cfcd8d778b68500671`。

| 原 ZIP | 字节数 / SHA256 | 独立重放报告 SHA256 |
| --- | --- | --- |
| 原生后端 `12492694345` | 212167 / `0f4530fad607b64869f7c57650ed53e15d4349e7a0baa47fa3d693a031c5fb87` | `b388515c93401a02fc43fc93a88c387d514491b8888f208a313c232247848fc0` |
| CDP `12492923797` | 1568575 / `e2e2f3488a1f94bee1ae612cebbca82c09ebb55670a24835528d64044f127485` | browser `7a88f42b836b3e44fba973c23cfccbbcb6acc46be58650aa543e0d2889f07f1b` |
| Playwright `12492968215` | 1677189 / `2ac374f5522a35101ad7b1a85bb7f472509dbce2dd3241f369ee027e96b8858d` | browser `7ecd93f3912f6d642af208669d0b060032b69ba197d6ddad2a06a0beeb3fcec9` |
| 镜像绑定 `12494450003` | 6376423 / `75ad1aef278c235440d37c71634e40c4dbe795385491c507af05c801ebe863f1` | 原前端 JSON `486fb541d4963119f902274e58916a11d1aed821e3583bf9a7ee7a9b538126d7` |

两个浏览器包各 63 文件；两条路径各自核对 716 个唯一 Git 原 blob、三处 source 前后与 10 个复制输入，共 2158 记录。原 Vite 隐藏 manifest 保留且绑定，不手补缺失工件。主代理还分别用精确 Git 原浏览器 checker（含后端校验）再次完整重放，两报告摘要与 CI/子代理一致。

镜像绑定原 ZIP 安全解包 1470 文件，checkout/source 两组 before/after 字节相同，合并 710 个独立路径均匹配原 Git blob。已独立重放的旧 Registry CLI 三项名单门不等于 D11 产品 Registry 门。后者及 image 打包/启动、D12 lifecycle、crash、state、source、source-TLS 产品门本次只确认 CI 成功，未逐项独立重放。

机器可读来源、名单指纹与边界见[本轮证据摘要](evidence/p2-subscription-core-d0e55c6.json)，依赖来源另见[固定依赖证据](evidence/p2-subscription-dependency-8c74a3f.json)。CI 工件保留 14 天，Temp 独立复核不是永久备份；摘要/入口不代替原始证据长期集中归档。

## 未完成与下一步

`subscription_orchestration` 继续保持 `design_only`。P2-05 产品 API/独立 RBAC/默认关闭写门、受信来源批准与秘密引用、失败尝试审计/跨库协调均未接线；P2-06 实际订阅资源界面仍未实现，现页面仍占位；P2-07 自动刷新、完整格式与内核校验、运行发布尚未实现。不得从 Go 测试或既有探针浏览器回归推导订阅界面已可用。

1MiB/1024 节点/32 来源/全库 64 候选等预算只是原型边界，未做企业容量或长期浸泡验收。解析进程沙箱、真实公网与节点能力、整套备份恢复/RPO/RTO、正式 Registry 供应链及获批生产灰度仍未完成。下一阶段按[接线约束](P2-SUBSCRIPTION-ADMISSION.md)进入独立权限/API与耐久审计，而非直接启用调度或生产。

本轮未 SSH 或修改路由器、OpenClash、爱快、DNS、Kuma、ERP；未合并 main、未发布正式镜像、未部署生产，设备执行器及生产授权阻断保持。
