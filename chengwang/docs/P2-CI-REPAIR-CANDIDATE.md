# P2：实际 CI 故障修正候选

范围：仅开发分支 `codex/chengwang-live-overview-20261024`，基线 `a8e66210b1a3e65c433e16b93cadad68992afce5`。本记录区分旧提交的实际结果、候选源码修正和新提交尚待取得的验收。没有生产部署、main 合并或正式镜像发布。

## 已确认的真实失败

| 原提交／运行 | 已取得的实际证据 | 结论与限制 |
| --- | --- | --- |
| a8e／40076010534 父门 | `OVERVIEW_GO_INCREMENT_GATE=PASS files=2 testsPerFile=2709 addedPairs=39 passingPackagesPerFile=42`；`GO_JSON_GATE=PASS files=2 semanticRunEvents=5418 packages=43 skips=0` | Go 普通／race 实际语义门通过；不表示整个工作流成功 |
| 同一父门 | 远端格式器输出 10 文件清单及差异，6 文件需要格式化；随后 `OVERVIEW_FORMAT=REJECTED` | 真实格式门失败；差异原件保留 |
| 同一父门 | 上传 action 在 host runner.temp 根目录找不到两份 Go JSON 和辅助转录 | 测试写入的目录多一层 `chengwang-m2b-static-gate/`；原始 JSON 没有成功上传，日志不能冒充原始 JSON |
| a8e／40076010522、40076010562 等前端构建 | `OverviewTransport.test.ts(35,104) TS2353`：推断 headers 类型不含 content-length | 前端被编译阻断；345 项前端测试是预期，不能计为通过；浏览器 build 失败不等于浏览器已执行 |
| a8e／40076010521 原生探针 | runner 成功，独立 checker 失败；34 个公开原件已取得并核验 bytes／SHA256／ZIP CRC | 原门离线复放确认 isolation 源清单各 1035 项，先被通用数组 1024 限制拒绝；后续 source_list 本来允许 2000 项 |
| 8e／40075883351 四个能力场景 | 驱动均在移动端 DOM 校验失败；4 份 PNG 已导出，八类传输计数为零 | 被拒绝的 DOM 未导出，不能断言具体失败谓词；不得用传输零错误推导页面验收通过 |
| 同一 UI 工作流的旧 handoff CDP | NAVIGATE 阶段拒绝，forbiddenRequests=1；source 路径收窄至未知 Target 创建 | Target 的原类型及创建阶段未导出，唯一运行根因尚未证实；本候选未修改该逻辑 |

## 候选实际改动

1. 通过 apply_patch 应用原远端格式器的 6 文件差异；全部 10 个受检源文件均与报告 afterBytes／afterSHA256 一致。没有运行本地 Go 或 gofmt。
2. 只改父门上传步骤的 3 个精确路径。保留测试命令、namespace、用户、权限、超时、读门、失败策略及非空上传要求，不增加复制／权限提升／目录通配回退。
3. 测试 helper 的 headers 参数增加 `HeadersInit` 类型。content-length 超限负例及原 11 个用例正文保持；没有放宽产品响应解码器。
4. 原生探针解码器仅对显式 isolation 文件上下文中的顶层 `sourceFilesBefore`／`sourceFilesAfter` 使用既有源码清单上限。默认数组上限、原字节／深度／对象／字符串限制和完整源码路径／排序／哈希语义保留；新增边界反例，旧 32 个方法保留。
5. 内核页增加受限的响应式布局修正：标题和操作换行、网格可收缩、表格在组件内横向滚动、事实文本换行。保留全部行列及原无页面横向溢出验收门；这是针对已确认布局风险的候选，尚未证明它是旧移动 DOM 失败的唯一原因。
6. 实际总览文案明确“汇总时”和“页面不会自动更新”，避免长时间停留时把旧证据理解为当前健康。保留服务端组装时间，不用客户端时钟制造新鲜度；该文案变更没有实现自动刷新或动态 TTL 验收。

## 严格退出条件

- 新提交的远端格式门、Go 普通／race 严格门和原始转录上传均实际通过。
- 新提交的 TypeScript 构建及全部前端精确名单实际执行通过；语法解析不能代替编译或 Vitest。
- 新提交的原生探针 runner 和独立 checker 均通过，源码清单及原件前后稳定；新 checker 重算旧 a8e 证据须单独标明两种源码身份，不能改写 a8e 失败历史。
- 实际 UI 双引擎 producer、fresh checker、桌面及移动 PNG 按指定源码分别验收。handoff 和移动 DOM 失败保留，任何单项成功都不能抵消其他失败。
- 实际证据总览的新双引擎浏览器场景仍待实施；既有能力页／订阅场景不能代证总览请求、状态、刷新、错误恢复及移动交互。
- 整套功能基线、灰度、生产读回、恢复演练及运营闭环仍按项目台账继续执行。此修正候选不构成系统上线声明。
