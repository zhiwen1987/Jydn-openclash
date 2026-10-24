# P2：两个原浏览器失败的独立诊断补充

状态：候选代码与纯CPU合约检查已完成，尚无本候选真实浏览器采集。此工作不是根因修复、生产上线或系统验收。

## 为什么补充

`e6cc0ff` 的订阅UI仅负交接Chrome/CDP失败，最后宽泛checkpoint是NAVIGATE；文档、四个资源和快照的六条匿名GET均200/FINISH，没有POST。该范围包含多步操作，原件没有细分观察，不能猜是点击遮挡、证书、等待或业务回归。

探针CDP仍有failedRequests=1，但绑定请求已有JSON EOF_OK/FINALLY，没有应用CANCEL/ABORT。取消冗余清理已移除，不能继续把全部失败归因于它。原失败与原八零门继续保留。

## 两个相互独立的候选补充

负交接导航采用独立schema，只接受该scenario；不扩旧导航schema。记录viewport、navigate返回、ready、目标唯一、可观察actionability、实际输入确认、匿名DOM及内容检查、证书和TLS阶段。Playwright不伪造CDP鼠标确认。只在失败前读取有界瞬时状态，原异常照常抛出。私有观察0600、独占no-follow、fsync；只投影到原failure.json。成功导出集合与验收要求保持。

新旧正常业务过程、八零计数、TLS、进程退出及无残留要求不变。历史e6原件用新诊断CLI实际得到 `UNAVAILABLE_NOT_ACCEPTANCE`，没有补造历史观测；该命令exit0也不代表UI成功。下一次必须读实际子阶段后才能选择修复。

探针网络旁证仅接收现有CDP被动事件，不新增请求、拦截、重试或等待。最多7个匿名status身份，记录匿名连接、协议、cache／service worker、白名单framing、收包计数、受限失败类别及context变化；不导出URL、IP、任意头、nonce、body或异常文本。固定Chrome源码revision仅是设计参考，实际浏览器仍由原identity门独立读回。

旁证使用独立root预开FD和原有外层隔离，输出到 **evidence顶层**；不向旧lab／backend／browser闭集塞新文件，不扩大旧stderr或binding预算。独立检查器核7身份、原绑定、实际复制源、16个Git源码和执行中helper字节。缺关键事件是incomplete，不造0；`DIAGNOSTIC_COMPLETE`允许保留FAILED并始终 `browserAcceptanceProven=false`。不完整报告归档后exit1，原浏览器门仍保持失败。

## 实际验证范围

根实际执行旧584项纯CPU辅助检查、新负交接57项、新父门18项及新网络48项，共707个不同辅助用例，零skip；不包含新Go／Vitest／浏览器运行。旧辅助脚本里的sourceCommit参数只用于合成报告标签，不能当工作树代码的真实Git／运行证明。

- 旧584原件：`D:/CodexData/workspace/eof-cpu-zwrl8zbm/root-cpu.json`，SHA256 `9ceda22af63c6a48fd967b3d7d8d13deaef48638d3451ab933ac99b1bf0445bd`。
- 新57＋18根记录：`D:/CodexData/workspace/truth-preflight-64cpcorm/result.json`，SHA256 `f8692b37497b9b00d5a19d957def91dab2bb4751d72bfe703d4e736d8608ce43`；该时刻前端门为258预案，随后新增2截止用例改为260，须按最终门再核语法和拒绝不足集合。
- 新网络48的最终工作流原嵌入门已实际执行，`D:/CodexData/workspace/root-network-vskneym5/`保留Node TAP与Python实际开始／成功28个ID。Python完整ID名单摘要为 `1eac936d47080e07e867ec9e1b85baa0955300bde6c5b9f67ca8cb5dfda97e51`；不同于子代理包含重复方法后缀的日志行摘要，二者编码不能混称。

开发过程中曾出现补丁生成工具误解JavaScript replacement中的`$'`，生成了错误driver文本；已在集成前纠正，新增真实driver模块import反例。早期字符串断言不足的过程记录保留，不能只保留最终成功日志。此错误未进入已提交候选或生产。

## 仍未完成

真实新Linux权限／FD／投影采集、Chrome/CDP和Playwright原门、fresh完整重放、原件实际Git绑定、真实UI截止和能力页视觉验收、两个故障根因及行为修复仍待完成。新增诊断CPU通过不能代替这些退出条件。生产、main、正式Registry及原路由／DNS环境未改变。
