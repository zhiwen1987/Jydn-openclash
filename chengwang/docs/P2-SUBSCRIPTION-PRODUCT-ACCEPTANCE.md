# P2-05b 独立订阅产品链路：有界隔离验收

状态：运行源码 `2b0a472dda5fc75290a808d6dc7df18d9df1f128` **已实现并通过隔离 CI 验收**。这不是生产部署、真实公网来源可用、代理节点业务可用或完整订阅编排。生产授权仍为 `BLOCKED`，未执行设备动作。

## 实际完成

从现有 vendor、Go 1.23.12 编译真正的 `cmd/server`，在私有 network/mount/PID namespace 中启动四次独立进程；不用 `RunWith`、`httptest` 或自定义 dial 替代。仅 loopback、无默认路由，`8.8.4.4/32` 只存在于该 namespace。UID/GID 10001、五类 capabilities 全零、NNP=1；低权限进程重新检查身份。没有修改宿主 CA、sysctl 或时钟。

实际正常 TLS API → 身份/RBAC → 私有来源批准 → 固定 IP DoT → 正常 CA/SAN/SNI 的 HTTPS 443 → 解析 → 两来源隔离库存 → 本地接纳 → 重启读回/历史回执的链路已执行。**公网地址 fixture 不等于访问了公共互联网。** 两来源使用相同私有 YAML、各含两条 Trojan 配置，公开节点 ID 集合仍不相交，节点健康仍为 `unknown`，没有连接这些节点验证业务。

| 原始事实 | 本轮结果 | 不能推导的结论 |
| --- | --- | --- |
| 冻结 API 序列 | 46 次、顺序/状态/原始字节均匹配 | 已有真实订阅资源 UI |
| 四次产品进程与一个来源进程 | 实际正常 TERM、wait=0、join、无强杀/所属 session 残留 | 断电、内核 I/O 挂死或分布式恢复已验 |
| 实际来源连接 | 26 连接、18 DNS event、6 HTTP event、102 总 event | 这些计数不是测试数或业务可用率 |
| 负例 | YAML 错误、302、私网 DNS、错误 CA、错误 SAN、超限正文均拒绝且保留两个来源 revision=3/最后有效候选 | 全部真实供应商/协议/格式已验 |
| 重启/重放/策略变更 | 历史回执不变、POST 重放无新 wire、新 key 相同内容 noop；只改私有秘密版本即拒绝旧批准且不拨号；写门 423 | 自动调度、密钥管理平台或设备发布已闭环 |
| 审计与安全投影 | 53 外部事件、24 command、9 approval、6 本地 audit；原链/CP、真实资源 target、paired 稳定字段及回执绑定均匹配 | 私有数据库原字节、系统级备份或 WORM 独立见证已验 |

## 同源码 CI 与独立复核

本轮[产品实验 run 39955687597](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39955687597)，attempt 1：

- producer job `120420840840`：80 个冻结具名辅助测试实际 run/pass、0 skip，其中 wire 24=8 shape＋16 Linux；runner 24 和 checker 32 为纯合成辅助。随后实际采集 46 API/4 epoch，并执行完整原 checker。
- fresh Linux job `120421240997`：在另一工作机下载原公开工件，用同一 Git 源码完整执行 POSIX 文件保管、证书、源码、wire、API、审计和状态校验；与 producer 报告逐字相等。
- 原 product ZIP `12502635850`，110396 字节，SHA256 `394014ad86098004e5d66e96c920d6c46581e4ffa288fa26815be7c724c5630c`；原 fresh ZIP `12503055004`，1612 字节，SHA256 `1850b108b739b7d2abd36d609045d82eef541c991202441a72e2fa5a880d6e6d`。主公开实验目录精确 20 文件，完整 product 包另含 5 个公开辅助报告。
- 原公开源码前后清单逐字相等，744 个 Git 原 blob、32459169 字节逐项匹配；所采集的四项宿主边界前后一致，不声称证明了全宿主所有状态不变。
- 单一集成者及独立子代理分别下载/核对原 ZIP，使用原 Git checker 对原 20 文件作语义重放；root 输出与两份 CI 报告三方逐字一致：2496 字节，SHA256 `29d9695e27f26e1e615e8b423d20e40b9cda6d820d1134caf13f3740898bbc5b`。

Windows 的 FD/path 元数据入口仍严格拒绝，不为本机重放放宽 Linux custody。上述本机重放只在内存中以已核原 ZIP 字节映射替代文件读取，**不是本机完整 POSIX CLI 验证**；完整原门的文件保管证明来自两个真实 Linux job。没有改写原 ZIP、报告、私有状态或验证标准。

同源码[父门 run 39955687580](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39955687580)/job `120420840956`/attempt 1 成功。ordinary/race 各实际 2620 个 Test run/pass、逐对一次、0 Test fail/skip；新 130、旧 2490/2403/2391/2320 及原 87 名单指纹保持。每轮另 12 Fuzz/seed 单列；41 package pass、原 domain 无测试 package skip 保留。原日志 6023437 字节、SHA256 `9ca6e95d2bc5b157804aca46e88644000cd791f05dad33a6ba2ca4267b9bd865`。root 与独立子代理各自重提完整原事件，10715/轮；原 Git 四个门脚本重放 exit=0，semanticRunEvents=5240/packages=42。

本阶段没有修改产品 `cmd`/`internal`/`web` 或旧父门/原生探针/双浏览器工作流。旧探针双浏览器证据仍是既有阶段的证据，不冒充本轮已测试订阅页面。

## 原失败与修正不覆盖

首轮 `2a68973` 的[原失败记录](evidence/p2-subscription-product-attempt-2a68973.json)保留。80 辅助项和实际采集成功不等于整轮通过；原 oversize event 为 `partial/bytes=0`，独立门拒绝，fresh job 未执行。

修正仅让 fixture 先单独发送 headers、body 每次最多 16KiB，只累加成功 `send` 返回；错误不重试，socket 2 秒/关闭 5 秒及原独立正字节门不放宽。原同名辅助测试增加成功 header 后 body SSL 错误、原字节不变、超时异常的反例。新原 oversize 为 `partial/82040`，只代表累计成功返回计数，**不代表物理 wire 量、远端实际接收量或完整正文传输**。

## 未完成与下一阶段

- 真实订阅资源页面仍未实现；下一阶段须接真实 API、授权/写门、分页/冲突、历史回执与失败恢复，明确显示本地接纳不等于发布。按用户选择，同时验收 Chrome/CDP 与固定版本 Playwright，不互相替代。
- 自动调度、完整内核配置与业务节点能力、长时/容量/断电矩阵、完整系统备份恢复、隔离单目标发布/读回/回滚及企业密钥/正式 Registry 仍未完成。
- 未 SSH 或部署到任何局域网设备，未修改 OpenClash/爱快/DNS/Kuma/ERP，未合并 main、发布正式镜像或改变生产。
- 私有库存不公开，`private-readback` 仅可信采集器安全投影；CI build+hash 绑定不是独立可复现构建或恶意 CI root 的远程证明。原工件在线保留 14 天，不是永久集中归档。

整项 `subscription_orchestration` 继续为 `design_only`。后续仍按[完整台账](PROJECT-PROGRESS-LEDGER.md)逐阶段验收，不把本轮子链路替代整套交付。
