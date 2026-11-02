# SYS07：严格模型门与非接受性诊断

源码提交 `944f453b86be240896c08eef435134ecd6c80463`，树 `a6f98872ef047eff5a50b529adb7ac73e4e76b68`。9 路径按已备份前像集成，与两个独立切片接受的冻结树完全一致；没有生产变更。

## 本批完成

- 联合 CPU 模型可单独发布来源绑定的有界结果文件：只含四个声明源文件推导的顶层模型 ID、固定 outcome、计数、来源摘要。未知 ID 仅计 UNKNOWN，子测试动态参数、异常文本、traceback、原始输出和凭据不进入公共 JSON。单文件不超过 16 KiB，固定 `accepted=false`、`syntheticOnly=true`，不改变原 CPU 公共目录的单文件约束。
- 严格准入在是否输出诊断文件两条路径都生效。必须保留 wasSuccessful/noskip，且没有 expected/unexpected failure，testsRun 与 AST 一致，started/outcome ID 完整等于声明集合，unknownEventCount 为零，每个必跑模型明确 PASS。旧 unittest expectedFailure 能返回 successful 的边界不再被当作全 PASS。
- 原 83 模型保留，诊断回归及严格门回归使模型数达到 90。当前有界结果 12,570 字节，90 PASS，其余 outcome 和 unknown 为零；原 16 个工作流变异检查保留并增加 4 个。Go 命令次数、300 秒 CPU Go 预算、最终失败门及实际 UID probe 未改变。
- 时间线 schema 升至 v2，增加四个固定文本观察枚举 NONE/TIMEOUT_TEXT/PANIC_TEXT/TIMEOUT_AND_PANIC_TEXT。只在完整 JSON、适用 FSM 和 cap 校验后的语义前缀采样；语义拒绝后不再观察。不复制 Output 或动态数据，不改变 Go 状态、通过条件或因果结论。NONE 不能解释为没有故障；旧 v1 原件仍按其旧 HEAD 源码审查，不伪造缺失字段为 NONE。
- 时间线原 45 个方法保留，新增一项综合回归，共 46；Profile consumer 5 项通过。Foundation 工作流使用 qualified Class.method 摘要，新 46 日志通过原样 heredoc，旧 45 拒绝。Go 689 声明、全部计数上限和时间预算均不减少。

## 集成后实际复核

根会话执行受影响的 224 项 Python 检查：P207 83、joint 90、timeline 46、profile 5，全部通过；结构化 loaded/started/success 与 AST 一致，源码和 clean HEAD/tree 前后不变。实际 source CLI 为 842/21/545/528/38、S92/Q80、foundation 689；joint 853 条契约再次生成后逐字节相同，摘要 `81ec60c1d74a849ca6b16f712580045e4d84dbb87bd5a67193b7002a0465a71a`。

以上都是本地 source/Python 证据，没有运行本地 Go 或真实 Linux namespace，不是新提交 CI 或上线接受。

## 保留的运行结果与未完成

旧精确 8c08 的 P207 528/528 与 31 链已独审有限接受。P207 fresh 只有平台步骤证据，未上传独立 fresh 文件。旧普通 Foundation 和 capacity 的有界时间线各 689 通过，旧 Foundation Race 625 pass/1 open/63 not-started、child exit1；joint CPU 步骤失败，B0/J1/R2 尚未执行。不能把未闭合测试或文本观察认定为根因，不能将旧接受迁移到新 HEAD。

本批实际 GitHub 上传、Linux 下失败模型 ID、Race 文本观察、新 HEAD Go/31 链、真实联合业务及 Linux fresh custody 均待验收。完整企业系统、actualfs 耐久和生产上线仍未完成。

## 证据和恢复

[来源证据索引](evidence/sys07-strict-model-marker-source-20261103.json)。9 个前像保存在 `D:/CodexData/workspace/chengwang-8c08-diagnostics-root-backup-20261103-cd03-v1`。旧候选、首轮失败和创建时 PENDING 不重写，后来的接受通过独立收据补链。开发文件备份不冒充旁路由备份；生产、开发项目 main、Registry、路由器和 DNS 未改。
