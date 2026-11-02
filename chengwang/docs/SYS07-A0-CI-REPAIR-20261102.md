# A0 CI 修复：开发集成，尚未重新验收

基线提交：`9d9c112f6700c128162556410768396df3ded6a8`。

该提交的 P207 Linux CI（run 41473420726）被拒绝：来源模型通过，Go 报告为 361 项通过、130 项未启动；fresh 被跳过。不能据此声称测试全部通过。joint run 41473420944 在 CPU contracts and Go suite 步骤失败，真实 B0/J1/R2 场景未执行。

本次修复仅包含：

- 应用该次 CI 正式产出的 gofmt.patch，涉及四个 sealed_archive Go 文件。
- 将测试同一词法块内第二个 candidatePayloadRaw 声明及其两处使用改名为 candidateGoldenPayloadRaw，消除重复短变量声明。
- 随源码字节更新来源校验值；不放宽原测试数量、权限、失败诊断范围或验收条件。

独立审查结论为 SOURCE_REPAIR_ACCEPT。该结论仅证明源码修改边界，未证明 Go 编译、测试、业务场景或生产可用。官方格式补丁 SHA-256 为 `3748053a406f9953b8805bdd2005092ba59421b4871c8f79f12f6e88ca9e0942`。

原失败报告未提供符合现有白名单的动态编译位置，因此 CI 首条编译或 setup 诊断仍为 UNKNOWN。重复声明是独立源码检查确认的确定性错误，不冒充 CI 原始首条诊断。

随项目保存的证据（均保留原始字节并读回核对）：

- [静态失败诊断](evidence/sys07-a0-ci-static-diagnosis-20261102.json)
- [独立修复审查](evidence/sys07-a0-ci-repair-independent-review-20261102.json)
- [修复候选及前后校验值](evidence/sys07-a0-ci-repair-candidate-20261102.json)
- [官方补丁与三处重命名的精确差异核验](evidence/sys07-a0-ci-repair-exact-diff-audit-20261102.json)

来源校验生成工具 v1 虽通过 10 项安全测试，独立源码审查仍以 OUTPUT_CONTAINMENT_NOT_ENFORCED 拒绝：输出路径没有强制排除 formal、candidate 及其 Git common 目录。未运行该版本的实际生成。原冻结和[拒绝记录](evidence/sys07-a0-pin-tool-v1-rejected-20261102.json)保留，后续版本必须在创建输出前实施路径隔离并补充负向测试。测试通过不替代独立审查。

2026-11-03：v2 修复输出路径隔离后获[工具源码审查接受](evidence/sys07-a0-pin-tool-v2-peer-20261103.json)，但[实际生成被拒绝](evidence/sys07-a0-pin-generation-v2-failed-20261103.json)，exit 1、原因 workflow changed pin scope。未生成 manifest、afterimages 或 patch，四个 gate 未应用。后续只读诊断确认 fixture digest 本来不变，工具却硬要求四项 workflow pin 均变化。v3 应只预期 contract/module/changed-Go 三项变化，并明确要求计算所得 fixture digest 等于原 pin；不可通过改动 fixture 绕过。v3 未经生成与独立输出审查前，不代表校验值更新成功。

v3 实际生成成功，精确四个校验文件通过独立 SOURCE_GATE_ACCEPT 后已集成。正式来源检查通过：830 module、21 fixture、496 source tops、491 required tops、29 changed Go sources、689 foundation tops。fixture digest 未变，旧七个 CTL 诊断来源及十个 checker/model 字节未变。Joint 仍为 841 个来源路径，仅四个 Go 来源行及 contract pin 更新。该结果不证明 Go 执行。

- [生成收据](evidence/sys07-a0-repair-pins-generated-20261103.json)
- [实际输出独立审查](evidence/sys07-a0-repair-pins-actual-peer-20261103.json)
- [集成后正式来源检查](evidence/sys07-a0-repair-root-source-20261103.json)

集成后本地正式模型为 63/63 来源模型、40/40 joint 合成模型通过，[执行收据](evidence/sys07-a0-repair-root-models-20261103.json)包含日志校验值。来源模型使用原固定测试名集合和正式日志验证器；joint producer 实际退出 0 并生成 40 项收据。未在 Windows 执行 Go/gofmt，也不将这些模型结果算作 Linux 或真实业务验收。

下一道门：固定本次提交来源后，在隔离 Linux CI 重跑格式、Go、fresh 和真实业务场景，再核查原 HTTPS 验收链。生产环境、原 main、路由器及 DNS 均未修改；本记录不是上线声明。
