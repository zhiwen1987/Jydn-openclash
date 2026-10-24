# 隔离 Chrome157 对照验收

这条路径只用于隔离 Linux CI。它保留原 probe 的产品代码、Playwright1.64.1、Node22.23.3、超时、流式大小限制、原八项零错误门及正常关闭要求。不会更新宿主系统 Chrome，也不部署生产。

原 hosted 工作流继续采集宿主 Chrome 的实际版本；历史155失败原件不能被新结果覆盖。新实验工作流 `chengwang-probe-pinned157.yml` 仅监听指定 `codex/chengwang-probe-pinned157-20261024` 分支 push 和手动触发，producer 与 fresh 都限制到该精确分支引用及这两个事件；不会在 main 或 PR 自动激活，错误引用的手动触发也不运行。它固定调用原场景的 `pinned157` 获取方式，分别运行 CDP、Playwright，再由独立 fresh job 从下载原件重放全部原检查。新 producer 不依赖 hosted 成功，正确分支上 producer 失败仍允许 fresh 尝试读取已有原件；producer 被跳过则 fresh 也跳过。任何真实失败仍使对应 job/工作流失败。

浏览器参数只能是 `hosted` 或 `pinned157`。只有原 push、PR、手动事件的整个 inputs 为 null 或空对象时才默认 hosted；其他事件缺值、显式键值为 null/空串/未知值或额外输入键均拒绝，不允许退回 hosted。参数不是命令或可执行文件路径。兼容依据为官方 runner v2.338.0 的 [缺失上下文处理](https://github.com/actions/runner/blob/v2.338.0/src/Sdk/DTPipelines/Pipelines/ObjectTemplating/PipelineTemplateEvaluator.cs#L419) 及 [ToJson空值/空对象处理](https://github.com/actions/runner/blob/v2.338.0/src/Sdk/DTExpressions2/Expressions2/Sdk/Functions/ToJson.cs#L190)；这是固定源码路径证据，不是本轮 GitHub inputs 值的实测。

固定来源沿用已有 `tools/browser-runtime-candidate/pin.json`：

* Chrome for Testing157.0.8103.6，完整 linux64 分发。
* 源码修订 `41520584daa68d0040db7746ae562a0ff82187f6`。
* ZIP202676171字节，SHA256 `7802b25411aa5b8aa387cc733a45df6eed1aea8cc046fd4e2dec64d5918b1853`。
* 实际 ELF305061192字节，SHA256 `ec4e78d65a5382c2b50aaf28c6a655a624973b3d3c711a2a4ae34369fd9a3444`。

先按原 consume/check 独立核对 ZIP、CRC、展开树、源 Git 字节与收据。`prepare_pinned157.py` 再把完整分发复制到本轮全新 `$RUNNER_TEMP/chengwang-probe-browser-runtime/chrome`，校验逐文件字节、root所有权和无组/其他人写权限。已有目录、链接、越界路径及不同字节均拒绝，不自动覆盖或重试。Git safe.directory 仅通过本次 sudo 命令环境指定当前仓库，不改系统/全局配置。

原 runner 继续使用原 copy、挂载、UID/caps、普通 NSS 信任、真实 TLS、launcher、进程退出和无残留协议。新顶层公件 `pinned157-consumption.json` 和 `pinned157-copy.json` 不进入原 `lab` 闭合集合。独立 `check_pinned157.py` 将消费收据、完整分发复制清单、运行复制的 ELF/Node/Playwright清单、实际进程及 PID 绑定的 CDP 版本相交验证。host155加一份157收据不能通过。

旧 `chromeExecutable.sourceScope=TRUSTED_CI_SYSTEM_TOOL_NOT_INDEPENDENT_SUPPLY_CHAIN` 仅保留为 legacy 信任分类，不能解释为 `/opt/google/chrome` 或 host安装来源。新收据/报告明确 `actualAcquisition=FIXED_CFT_ARCHIVE_NOT_HOST_CHROME`。不伪改旧实际路径、版本或工具链字段。

Fresh 验证重新按同一 SHA 消费浏览器并独立检查，与原收据逐字节比较；它不信 producer 的 passed 标志，也不需要上传202MB浏览器包到旧64MB公件边界。随后实际执行原 backend/browser/status/request-binding/network-lifecycle/browser-identity/EOF检查和新 pin 绑定，每份新报告必须与原报告相同。某一步拒绝不会阻止其余检查尝试，最终失败状态保留。

纯 CPU 模型、语法检查和准备成功不表示浏览器已经通过。新报告也不单独宣称 browser acceptance 或本次取消的唯一因果。Chrome157与锁定1.64.1的真实兼容、完整场景、截图、TLS、关闭和 fresh 重放必须由这轮真实 CI 原件验收。

研究依据是官方 Chromium 修复 [`62473ad0f747e245e514c93e741bb8e168a2a207`](https://github.com/chromium/chromium/commit/62473ad0f747e245e514c93e741bb8e168a2a207)。它修正完成的 Fetch body 被报告为取消的内部重入窗口；与历史现象匹配仍不等于已经获得该请求的内部调用栈证据。
