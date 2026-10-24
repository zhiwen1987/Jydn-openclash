# 能力页运行失败：证据、诊断与后续验收

2026-10-24。此记录说明已知失败及诊断改进，不把诊断增强记为业务故障已修复。

后续15:49：78v2四份实际原件将首个拒绝收窄到DOCUMENT/r1/EVENT_FINISH_TIME。固定Chromium源码审查后形成[额外时间假设修正候选](P2-CAPABILITY-NETWORK-TIMING-CORRECTION.md)，188项辅助检查通过，尚待真实复测；下述b2和v2开发历史不覆盖。

## 已取得的实际结果

源码 `b2b226d1d57e316ca8b8cc22eccd1f59be1dcffe` 的[浏览器运行40068275370](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40068275370)整体失败。旧订阅场景8个 producer 和8个 fresh 成功；新增能力场景4个 producer 和4个 fresh 失败。父门40068275506与订阅读回40068275429成功，不抵消能力页失败。

四份 `originals/failure.json` 均记录 `UI_RUN`、`driverDiagnostics.stage=NAVIGATE`、`serverExitCode=0`、`controllerExitCode=1`、`forcedSignals=1`、`normalCloseCompleted=false`、`capturedOriginals=[]`。

| 配置／引擎 | 内存capture计数 | 事件计数 | failure.json SHA256 |
| --- | --- | --- | --- |
| default／chrome-cdp | 0 | 15 | 77b868094da231b78b66d5a8a876f3edd3aea281eedd5b75fa103414b8ee1216 |
| default／playwright | 0 | 15 | 4174a0cd6c317ab1857313c1f44ef4ff0beb79bf8637a63f2b1a14b75bb7e81e |
| backend_configured／chrome-cdp | 2 | 17 | 231a8c749fc4724839cf0baca8dc8180424f2f5366a8fe2dbfd0ee1ea2c366ec |
| backend_configured／playwright | 1 | 16 | 7feed1b155e56605cf312f99269892c3a2b2508e4a650e79ffa84bb86d239611 |

原件位于 `D:/CodexData/workspace/capability-ci-index-m5_gnx3f/` 中对应能力场景目录。公开原件仅保留6个文件；没有 captures、DOM、成功driver或截图。capture计数不等于已经取得可重算的capture原字节。

## 目前不能确定的原因

`NAVIGATE` 包含设置视口、导航、文档就绪、等待snapshot、检查网络空闲、字体与帧等待、页面身份、DOM合同和首张截图。现有7字段失败投影无法区分这些步骤，也没有保存首个journal拒绝原因。不能凭运行时长、capture数量或源码猜测确定故障。

源码审计发现新journal要求 `endTimeUs >= headerTimeUs`，旧journal及独立checker只要求各时间不早于start。这是需要检查的一处差异，尚无本次实际触发证据，因此没有据此放宽时间要求。[CDP官方Network定义](https://github.com/ChromeDevTools/devtools-protocol/blob/master/pdl/domains/Network.pdl)可用于核对事件语义，不能代替本次实际事件证据。

## 本地实现的诊断改进，真实运行待验

仅扩展失败投影为明确版本的v2：41个闭合操作枚举、首个脱敏失败类别、匿名请求别名与类型、八类错误计数。缺失观测保留null；不输出异常原文、请求头、原始CDP身份、URL或响应正文。Python端仍先执行秘密栅栏，再做精确字段、类型和范围校验，读取边界保留4096字节、UID10001、0600。

当前187项辅助合同实际通过，旧28场景／79Node名字完整保留，新增8场景／6Node；两次夹具失败与修正保留，未降低成功门。独立代理核过最终源码及根原日志，静态41枚举、21shell块和7Node语法通过。详见[机器记录](evidence/p2-capability-failure-diagnostics-development.json)。这些均不是实际v2浏览器证据。

成功17文件合同、独立成功检查器、正常TLS、隔离与清理要求、八零计数、请求与等待预算均不因诊断需要而放宽。旧v1失败原件保留，后续v2诊断不能倒填成旧运行已经观察到的原因。

## 后续退出条件

1. 保留旧CPU测试名单，增加首个失败定位、并发捕获、未知字段／类型、秘密拒绝反例，按新源码冻结明确名单；取得真实CPU执行日志。
2. 统一提交后，在现有隔离Linux CI取得两配置×两引擎的实际v2失败诊断或成功原件。
3. 依据实际诊断修复确定问题，再运行完整矩阵及独立fresh检查；不把本阶段诊断代码提交当修复完成。
4. 成功后逐图审查桌面／移动截图，完成指定源码原件独立复算与台账更新。

该阶段未运行本地产品、Go构建／测试、npm构建或产品浏览器；未改生产、main、正式镜像或Registry。实际证据总览仍在另一个隔离工作树，源码未编译／测试／推送，未纳入本次运行结果。
