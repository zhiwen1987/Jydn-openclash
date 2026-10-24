# P2：正常 EOF 清理优化与独立观测

状态：候选实现及CI接线已完成，584项辅助纯CPU检查通过；新18项前端仅AST／名单已核，尚无新源码真实CI／240项Vitest结果。本阶段只允许开发与隔离验收，不授权生产变更。

## 为什么做

前序 `e4156d64341f5f92eeca9bfa7c8b09066cf69c64` 的订阅与镜像子门成功，但[旧探针40042582518](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40042582518)双引擎原门失败，各 `failedRequests=1`，其余七计数零。原门严格保留，不忽略 canceled 请求。

原 D 证据将唯一失败绑定到约60秒的第五次匿名摘要轮询：HTTP200后出现网络 ABORTED；同一请求亦有 JSON／EOF_OK、取消结果 RESOLVED、FINALLY，无该请求的应用 ABORT、deadline 或卸载取消记录。采集到达顺序不是发生因果，JS与CDP时钟不可混用。现有证据不能证明 `reader.cancel()` 造成历史 NET_FAIL。

固定 [WHATWG 快照337e8e4](https://streams.spec.whatwg.org/commit-snapshots/337e8e4f06b2d9e482d4eae7fb6b6bed58de6445/)和[同提交GitHub源码](https://github.com/whatwg/streams/blob/337e8e4f06b2d9e482d4eae7fb6b6bed58de6445/index.bs)说明：已关闭流的 cancel 直接返回已完成 promise，releaseLock 负责释放 reader。原运行实际 Chrome155.0.8059.39/revision `3ff7ac5a9224be9156d7f8703a06e22890aafd34` 的[流源码](https://github.com/chromium/chromium/blob/3ff7ac5a9224be9156d7f8703a06e22890aafd34/third_party/blink/renderer/core/streams/readable_stream.cc)及[响应体源码](https://github.com/chromium/chromium/blob/3ff7ac5a9224be9156d7f8703a06e22890aafd34/third_party/blink/renderer/core/fetch/body_stream_buffer.cc)只支持“成功读尽后额外cancel冗余”的设计判断，不是浏览器网络故障因果证明。参考157候选pin不能代替实际155运行身份。

## 默认产品路径的实际变化

`web/src/probe-api.ts` 的 read 在流结束、UTF-8解码及JSON解析均成功后，才设置局部 `readComplete`。finally 仅在未完整成功时执行原取消流程；无论成功或失败都释放 reader lock。不加仅测试启用的清理开关，不改fetch路径、认证、响应上限、deadline、卸载、单飞或业务DTO校验。

`EOF` 本身不够：读到EOF后JSON错误、UTF-8 flush错误、或已观察到 signal aborted，仍走原拒绝与取消。头部拒绝、未读尽的大小／解码／读取失败也保留取消。取消 promise 仍不等待，取消异常仍脱敏；完整JSON并不等于DTO有效或业务可用。

## 唯一旧用例的显式语义迁移

旧222项的全部名字保留，但不能声称旧测试断言与源码全部未改。其中一条旧用例 `P1 probe read-only transport observes cancel fulfillment and rejection without awaiting or changing the read result` 曾明确要求成功JSON＋EOF后调用cancel，和新默认清理语义冲突。

本次将该用例输入明确改为 `'{'` 在EOF后JSON解析失败，结果改为format拒绝。原 cancel/release各一次、非await、RESOLVED与REJECTED两种结算、AFTER早于异步结算、原始取消异常不泄露等断言均保留。新增18项独立用例补正常status/details、多chunk／空chunk读尽且无取消，以及头部／大小／UTF-8／JSON／读取错误／abort／恶意取消等路径。不是删除失败测试、放宽旧零错误门或伪造取消成功。

新18项完整名字 sorted LF/no尾换行SHA256：`de7d15a53dbddd3d52558f12b6de317b13ed297cc269f9a171ff706ebdec798f`。当前只完成三个TS文件的AST解析及18声明名单核对，没有运行本机Vitest／tsc／构建。前端真实CI门接成11文件／240项，仍逐项核旧222与新18名单、零skip；240是待验证断言，不是已通过数。

## 补充验收设计

旧v1 status/binding协议、collector、runner、checker与结果枚举保持原样。源码核实原binding门允许每请求0或2条CANCEL；零取消时禁止出现settlement，因此正常成功无需制造 `RESOLVED` 或新 `SKIPPED` 枚举。

独立补充门已实现：读取原件，实际调用两份原CLI重放原browser和request-binding完整门，要求exit0和报告字节一致，再逐身份验证本轮7次匿名成功读取：7 SEND、7唯一绑定、7正常网络结束，每次EOF／EOF_OK(f=true)／FINALLY完整，零ABORT／CANCEL／RESULT／NET_FAIL，原driver八计数仍全零。输入稳定性、16份同Git源码、before/after与执行中helper均绑定；报告在证据树与仓库外独占创建，再归档于顶层，不能扩大旧lab/browser闭集。旧主门失败时新补充门不执行，不以新helper代替原拒绝。

唯一新合同在 `deploy/probe-readback/eof-cleanup-contract.json`，独立检查器 `check_eof_cleanup.py` 和26项反例 `test_check_eof_cleanup.py` 已完成。旧checker/schema/collector/runner未改。新单元测试mock原CLI只属于合成测试，真实辅助门是否通过必须等待实际CI原件。

## 提交前实际检查

根在 `D:/CodexData/workspace/eof-cpu-3005rf15/` 实际运行584项辅助纯CPU检查，保留旧558，新增EOF helper26，零skip；六个旧辅助转录门及31个工作流bash块／前端shell语法检查通过。`root-cpu.json` 8494字节，SHA256 `5f7a75fee0da10e28a89f5fbf836572c8647fc1411b2638563914b0739589301`。全部日志使用D私有临时目录并fsync，不写C临时副本。

新26完整 module.class.method 名单 sorted LF/no尾SHA256 `d8221a96161f7d586432a12043473d9542a6af64f93c6d90167f0ba3848d4060`；CI自定义unittest结果记录器逐次核实际开始与成功ID，不只看总数。根独立AST确认新18声明与摘要，且新240前端门实际拒绝旧222原JSON，未伪造新240通过转录。首次PowerShell包装器引号解析未执行检查，原工具错误保留；改用字面here-string后该负例检查实际通过，不作为产品或CI故障。

独立代理另核唯一旧用例迁移、其余九文件规范LF与e415字节一致、旧九组名单pin保持、成功／失败finally分支无确定阻塞。这些是源码和mock辅助证据，不是类型检查、Vitest、真实浏览器、TLS或取消根因证据。本机未运行Go／npm安装／Vitest／构建／业务服务／浏览器／Docker／netns；用户要求的本机只读任务监控台是单独工具，不属于澄网业务运行。

即使未来真实门通过，也只证明此源码／浏览器／隔离场景下的成功读取清理观测，不证明原故障唯一根因、任意请求正常、长时间稳定、真实互联网、节点业务或生产已修。

GitHub API本次已返回限流，读得core剩余0、reset `2026-10-24T01:37:14Z` 后停止轮询，不换凭据或接口绕过。代码可正常提交开发分支；在恢复读取并取得实际run之前，不声称新CI已开始或成功。

## 退出条件

1. 新18前端用例及旧222名单在真实隔离CI全部通过；唯一迁移用例明确记录。
2. 原探针两引擎正常TLS、业务、进程退出、原八零计数与所有旧诊断门均通过，原失败历史保留。
3. 新辅助门合成反例、真实原件、独立复算及源码绑定通过；不以helper测试代替真实运行。
4. 同源码订阅、父门、旧订阅及镜像等回归完成并按实际范围列出缺口。
5. 所有阶段均保持生产未改、main未合并；正式部署另需授权、备份、回滚与实际读回。
