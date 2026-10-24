# 实际总览：隔离浏览器候选与验收边界

本候选只在开发分支实现和隔离 CI 验收，不修改生产。功能合同见 [总览合同](OVERVIEW-REAL-BROWSER-CONTRACT.md)，本轮机器记录见 [开发证据](evidence/p2-overview-browser-development.json)。没有把分项 CPU 检查当成实际浏览器通过。

## 首轮真实失败与定向修正

原候选 `1f5c2ef` 已运行真实 CI：五条前置／旧功能工作流成功，新总览与原 probe-browser 整体失败。总览四份原件分别为 CDP 的 DRIVER_BARRIER、Playwright 的 UI_RUN；均没有成功 checkpoint 或 PNG。八份相关 ZIP、552 个成员已独立保管，旧失败保持原判，不能用本地236项替代。

实际 App 一直挂载 hidden 订阅页，原观察器按节点存在优先，可能把当前总览误认成订阅页。已改为按实际渲染根和所属标题判断，并拒绝多个可见根。新增的同名测试反例在旧代码33过1败，修正后34过，原名单保持；它修复确定的源缺陷，但缺失的原失败DOM不能被补造为唯一原因。

CDP更早启动失败的唯一原因仍未知。新增失败专用诊断，记录29种封闭启动阶段、首个固定fault、初始Target快照的有限数量，以及20种UI阶段和实际进入／完成的固定检查点；未观察值保留null。它不修改启动顺序、协议请求数、等待或退出预算，不把端口就绪是否早于首个页面这个候选原因改写为已确认事实。

诊断只通过独占0600私件写一次；适配器先建立秘密围栏，再按固定身份、字段、枚举、所有者／组、模式、字节稳定性和限额读取。它不导出原始错误、DOM文本、地址、Target ID或argv，不进入成功19公件。阶段表示实际进入的操作，不证明异步错误的因果；早期输入失败、强制终止或存储失败仍可能没有诊断，不能填造默认值。

另四份probe原件的EOF首次拒绝已定位为专用源码清单读取入口漏接已有预算：实际1046／1065项超过默认1024。只有确切browser-build读取启用现有2000上限，其余限制不变，原26项测试通过。修正已单独提交 `c43fae4` 并在固定157分支提交／推送 `c8dad44`；历史原件对新源码身份不符仍拒绝，未绕过。

本次统一稳定源码236项CPU通过，37／25／16／34等分项为其中子集，不重复累计。新同提交CLI、真实四场景／fresh和视觉验收仍待，详见[本次机器记录](evidence/p2-overview-runtime-followup-development.json)。以下保留首版实现及当时范围；旧CPU或CI状态不能自动转为新版本验收结论。

## 已实现

固定两种真实后端状态：关闭证据汇总返回预期 503，启用但缺数据的汇总返回实际 200／未知。复用真实 Go 服务和生产前端、固定来源 Chrome、普通 CA 信任以及原生 CDP 和锁定 Playwright；不注入响应、身份或页面状态。合同要求完整桌面／移动操作、三个业务入口、内核往返、刷新及重新进入，并输出八张截图和十九份封闭公开证据文件。新场景由源码固定的 dispatcher 选择，原十二种场景保留。

独立检查器按当前 Git 身份复算请求、响应、DOM、截图字节、进程与退出记录。完整静态导入依赖以及固定监管源必须列入 copiedInputs；不仅检查已列文件是否正确，也拒绝遗漏实际依赖。源码、输入和原件均前后核对，错误记录不覆盖。

## 日志错误不能静默消失

原八类计数保留。所有 `Log.entryAdded` 错误／警告均进入真实计数；安全类、无请求关联、重复、worker、CORS、关闭后及其他请求的错误继续拒绝。仅对 disabled 场景已观察到安全响应头的匿名 overview 503，实际日志 `networkRequestId`、精确 URL 和当前会话请求相符时，记录独立 `LOG_NETWORK_ERROR`。每请求最多一条；缺字段或先于已观察响应头即拒绝。原 consoleErrors 不清零，验收器从事件独立重算资格与剩余错误数，其他控制台错误不能被它抵消。

此例外描述请求关联，不推断浏览器内部原因或缺失正文的隐私安全。依据是固定 Chromium `41520584daa68d0040db7746ae562a0ff82187f6` 的 [LogEntry 字段](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/public/devtools_protocol/domains/Log.pdl)、[请求 ID 导出](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/inspector/inspector_log_agent.cc)、[HTTP 错误日志创建](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/frame/frame_console.cc)及[响应与日志调用顺序](https://github.com/chromium/chromium/blob/41520584daa68d0040db7746ae562a0ff82187f6/third_party/blink/renderer/core/loader/resource_load_observer_for_frame.cc)。新场景在两引擎的真实事件顺序仍须 CI 证明。

## 实际检查与剩余工作

统一版本的九份原始测试转录共 236 项通过、零跳过，原能力辅助 188 项以及反馈／导航 42 项回归通过；七份工作流通过固定版本 YAML 解析。五条旧回归工作流从 permissions 起的执行正文与原件完全一致，仅扩展隔离分支与路径触发。辅助脚本曾因 Windows 标准库预载顺序和两套测试数量映射错误拒绝；原失败日志保留，修正辅助脚本后重新核验，产品源未因此修改。

下一出口是包含本源码的真实提交、同提交 SYN CLI、隔离双引擎 producer 与独立 fresh 重放，然后逐图审查。尚未证明新场景实际启动、普通 TLS、Linux 隔离、无残留退出、真实业务可用性、长期稳定或生产上线。最终 CI 的失败原件仍须保存与修复，不能用本地检查数量替代。
