# 能力页采集：纠正额外的时间顺序假设

本页记录候选修正及证据限制；实际浏览器复测尚未完成，不是业务修复成功报告。

## 实际失败收窄到哪里

源码78ffc4e的UI运行40072726996中，旧订阅16任务成功，新能力8任务失败。四份producer公开v2投影的首个拒绝均为 `DOCUMENT / r1 / EVENT_FINISH_TIME / capture_error`，主操作为SNAPSHOT_WAIT，另外七类错误计数为0。四ZIP共144安全成员已保管核验。独立复核见[实际CI跟进](evidence/p2-78ffc4e-ci-followup.json)。

该操作标签同时覆盖时间值转换和完成时间比较；原始时间数值未导出。因此不能把原件描述为“已数值证明end小于header”，也不能断言唯一业务失败原因。私有秘密栅栏没有在Windows重新执行，公开投影复核不代替私有运行证明。

## 官方实现不支持原来的额外比较

按锁定Chrome157.0.8103.6对应固定commit `41520584daa68d0040db7746ae562a0ff82187f6` 审查：导航的[响应通知](https://chromium.googlesource.com/chromium/src/+/41520584daa68d0040db7746ae562a0ff82187f6/content/browser/devtools/devtools_instrumentation.cc#775)调用browser [NetworkHandler::ResponseReceived](https://chromium.googlesource.com/chromium/src/+/41520584daa68d0040db7746ae562a0ff82187f6/content/browser/devtools/protocol/network_handler.cc#3470)，其中响应事件时间取发送通知时的TimeTicks::Now。

加载完成时间则可来自网络服务先前记录的completion_time，经[NavigationBodyLoader](https://chromium.googlesource.com/chromium/src/+/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/platform/loader/fetch/url_loader/navigation_body_loader.cc#573)、[DocumentLoader](https://chromium.googlesource.com/chromium/src/+/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/loader/document_loader.cc#1426)传入[InspectorNetworkAgent::DidFinishLoading](https://chromium.googlesource.com/chromium/src/+/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/inspector/inspector_network_agent.cc#1771)。两者不是相同采样点，不能由事件回调顺序推导完成时间一定晚于响应通知时间。

源码另有renderer响应分支，但它在导航时直接返回；该分支不能作为本次DOCUMENT响应的直接依据。初审的这一范围偏差已纠正，并补齐browser导航主链。

八份固定官方源、实际下载字节及SHA位于 `D:/CodexData/workspace/chromium157-network-time-source-ae20b2091b8049cfbc49fec05d3fb828/`。根代理已独立核对每份文件字节及SHA。

## 候选改动及本地证据

仅将新journal的额外 `end >= header` 改为 `end >= start`，与现有独立checker和旧订阅journal一致。`header >= start`、数值类型与界限、同会话请求身份、事件顺序、FINISH完整性、响应字节／hash、八零计数、普通TLS、等待预算和正常清理要求保留。

保留原85个Node用例名，新增一个“完成时间早于响应通知时间仍可合法”的合成正例；小于请求开始时间、缺失／非有限时间及其他失败反例仍拒绝。该合成时间样本不是原CI时间观察。

根实际执行188项辅助合同通过（16监管＋36场景＋50检查器＋86Node），零跳过；41闭合诊断操作、21shell块、7Node语法检查通过，源字节前后稳定。原78／b2失败不覆盖。候选仍须统一提交、源码绑定CLI、两配置×两引擎真实运行及fresh独立重算；新失败须继续保留并排查。

生产、main、正式镜像／Registry和现网流量未改。实际总览功能仍在独立分支，代码和辅助门通过不等于Go、前端产品测试、HTTP或新总览浏览器已经通过。
