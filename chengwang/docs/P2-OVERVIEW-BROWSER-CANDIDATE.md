# 实际总览：隔离浏览器候选与验收边界

本候选只在开发分支实现和隔离 CI 验收，不修改生产。功能合同见 [总览合同](OVERVIEW-REAL-BROWSER-CONTRACT.md)，本轮机器记录见 [开发证据](evidence/p2-overview-browser-development.json)。没有把分项 CPU 检查当成实际浏览器通过。

## 已实现

固定两种真实后端状态：关闭证据汇总返回预期 503，启用但缺数据的汇总返回实际 200／未知。复用真实 Go 服务和生产前端、固定来源 Chrome、普通 CA 信任以及原生 CDP 和锁定 Playwright；不注入响应、身份或页面状态。合同要求完整桌面／移动操作、三个业务入口、内核往返、刷新及重新进入，并输出八张截图和十九份封闭公开证据文件。新场景由源码固定的 dispatcher 选择，原十二种场景保留。

独立检查器按当前 Git 身份复算请求、响应、DOM、截图字节、进程与退出记录。完整静态导入依赖以及固定监管源必须列入 copiedInputs；不仅检查已列文件是否正确，也拒绝遗漏实际依赖。源码、输入和原件均前后核对，错误记录不覆盖。

## 日志错误不能静默消失

原八类计数保留。所有 `Log.entryAdded` 错误／警告均进入真实计数；安全类、无请求关联、重复、worker、CORS、关闭后及其他请求的错误继续拒绝。仅对 disabled 场景已观察到安全响应头的匿名 overview 503，实际日志 `networkRequestId`、精确 URL 和当前会话请求相符时，记录独立 `LOG_NETWORK_ERROR`。每请求最多一条；缺字段或先于已观察响应头即拒绝。原 consoleErrors 不清零，验收器从事件独立重算资格与剩余错误数，其他控制台错误不能被它抵消。

此例外描述请求关联，不推断浏览器内部原因或缺失正文的隐私安全。依据是固定 Chromium `41520584daa68d0040db7746ae562a0ff82187f6` 的 [LogEntry 字段](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/public/devtools_protocol/domains/Log.pdl)、[请求 ID 导出](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/inspector/inspector_log_agent.cc)、[HTTP 错误日志创建](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/frame/frame_console.cc)及[响应与日志调用顺序](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/loader/resource_load_observer_for_frame.cc)。新场景在两引擎的真实事件顺序仍须 CI 证明。

## 实际检查与剩余工作

统一版本的九份原始测试转录共 236 项通过、零跳过，原能力辅助 188 项以及反馈／导航 42 项回归通过；七份工作流通过固定版本 YAML 解析。五条旧回归工作流从 permissions 起的执行正文与原件完全一致，仅扩展隔离分支与路径触发。辅助脚本曾因 Windows 标准库预载顺序和两套测试数量映射错误拒绝；原失败日志保留，修正辅助脚本后重新核验，产品源未因此修改。

下一出口是包含本源码的真实提交、同提交 SYN CLI、隔离双引擎 producer 与独立 fresh 重放，然后逐图审查。尚未证明新场景实际启动、普通 TLS、Linux 隔离、无残留退出、真实业务可用性、长期稳定或生产上线。最终 CI 的失败原件仍须保存与修复，不能用本地检查数量替代。
