# SYS07 9806 源码阶段、4b 失败更正与待验收边界

当前源码截点为 `980643452dfe9931ff9eb0c3ff45499b217d4bf4`，tree `cee014f61991dfc22038928fed798526bb852aad`，父提交为 `4b326352f84f419f0358eb3ac88a217e1fff1faf`。提交在 root 工作区 clean，但尚未 push。它不继承 `9190` 的运行接受，也不是生产发布记录。

## 4b 原始 257 项结果与更正

父提交 `4b326352` 的真实原始结果不是全绿：257 项中 256 PASS、1 FAIL，且没有运行 Go。唯一失败属于 P207：期望 83、实际成功 82、进程退出 1，缺失模型为 `test_source_contract.ClosedSourceContractModels.test_actual_workflow_independently_pins_the_complete_contract_surface`。joint 104、oracle 18、profile 6、timeline 46 分别通过。

旧 SUMMARY 的 PASS 已作废。调用方没有检查 `validate_receipt` 返回的 `False`，又把期望计数写成实际成功数，因而生成错误汇总。原 SUMMARY 与五组原始回执均保留；CORRECTION 原件位于 `D:/CodexData/workspace/chengwang-4b32-final-v3-root-models-20261103-cd03-v1-CORRECTION.json`，SHA256 为 `1534415c959f5762fcf278c5b140eb53a99d52704ba2dbc194f85b1b82b19101`，明确记录 `result=FAIL`、`testsRerun=false`、`goExecuted=false`。文档不得用后续源码修正倒改这次失败。

## 9806 的最小源码修正

`98064345` 只修改两行、两个文件：把 P207 测试中的 changed-Go 期望从 38 调整为实际 39，并同步 subscription-refresh workflow 的 MODEL SHA。39 相比 38 只新增本轮 Go 测试文件的格式覆盖；545 source tops、528 required tops 与历史 453/448 身份边界不变。

从 `9190` 到 `98064345` 的累计差异为 21 个唯一来源文件：`4b326352` 的 20 个文件，加上本次新进入累计差异的 `test_source_contract.py`。组合冻结、复核与更正身份如下：

- 组合 `FREEZE.json`：`f46886483dfd16b13d04030230e5f7fdcf2a61f019842ff13918a9d21897a3c8`。
- 独立复核 A：`c4d087fde39ca7fde90adf3c6ba207dce5605e1c2b53c9f6b12be08ceb15a107`。
- 独立复核 B：`7bf741d00e3d16aae8da02375e6385f6368d377e843f80da799f775c5c1522a1`。
- 4b root 更正：`1534415c959f5762fcf278c5b140eb53a99d52704ba2dbc194f85b1b82b19101`。

两行修正已获独立 patch-risk 复核，`FINAL.json` 位于 `D:/CodexData/home/state/plugins/codex-security/scans/chengwang-4b32-p207-count-pin-prewrite-20261103-cd03-v1/artifacts-2e8574685705cea4e67f15fd1ddccdf4c65c1f898a922d84be9ba8c96896956a/artifacts/FINAL.json`，SHA256 为 `a1eca2d8c0dc26ac328da1f12866ea37b396cc0d10251975aa46dfc393f5f9a8`；其结论只接受这两行源码修正，不代替全套运行。

## 9806 strict source-model 实际结果

root 在 clean `98064345` / tree `cee014f6`、21 个来源 pin 上重新运行 strict 257，实际 257/257 PASS：P207 83、joint 104、oracle 18、profile 6、timeline 46；五组进程均 exit0，合计 0 fail、0 error、0 skip、0 unknown。没有运行 Go。

- root `SUMMARY.json`：`D:/CodexData/workspace/chengwang-9806-strict-root-models-20261103-cd03-v2/SUMMARY.json`，SHA256 `b759e7f7d54e18c52e0131b8d1fc1e5c5d6530f007e81485c9755a52eb07978c`。
- caller 独立复核：`D:/CodexData/workspace/chengwang-9806-strict-root-models-caller-independent-review-20261103-cd03-v1/FINAL.json`，SHA256 `dbcb5e5224efafcb941c422172bf697eea05291384e55db10047391bb29ba8a8`，结论 `CALLER_ADMISSION_ACCEPT`。
- 输出独立复核：`D:/CodexData/workspace/chengwang-9806-strict-root-models-output-independent-review-20261103-cd03-v1/OUTPUT-FINAL.json`，SHA256 `48469908491c5a31084f1421e06c769341bfaea2ee8aebcf097bf3c479031f4e`，结论 `OUTPUT_ACCEPT_SOURCE_MODELS_ONLY`。

本次接受范围为 `SOURCE_ONLY`。caller 复核证明失败回执、伪造 exit0、短回执、重复/缺失 identity、`successful=false` 和 Boolean `testsRun` 均拒绝；输出复核证明五组集合、计数和退出码精确。它们没有证明 Go、格式、真实 UID/Linux、隔离 CI、性能、业务、整系统或生产接受。

## 组件语义边界

1. C2 的旧命令门拒绝 wrapper 已在源码中修复；这只消除确定的源码冲突，不等于格式、编译或真实 Go 已通过。
2. UID 只增加非权威只读 preflight 与固定 phase/exit 诊断，并修复 trap 对 31、32、17 的状态保存。真实 UID 权限未放宽，实际 UID 故障和根因仍为 `UNKNOWN`。
3. B3 只调整测试 fixture/oracle 的重复准备，不是产品性能逻辑改写。1、2、8 的 full-core、逐字节与 valid-tamper 前置条件保留，真实 256 保留，257 必须拒绝；ordinary/race same-head 成对结果仍为 `UNKNOWN`。
4. oracle 接受必须同时具备真实 Go 执行和 synthetic-data 语义两维，不能以一维替代另一维。
5. bounded-child 只把 `bad` 分类改为确定性注入；没有增加超时、删除其他真实 child 用例，也不保证所有 flakiness 已消失。
6. joint 来源合同仍为 857 路径，joint 模型名称集合仍为 104。P207 changed-Go 为 39，但真实格式与 Go 门尚未执行。

## 仍未完成

- 新 strict source-model 257 已按上述精确原件通过，接受范围仅为 `SOURCE_ONLY`；4b 的 256/1 与旧错误 SUMMARY 仍保留且不改判。
- 本提交尚未运行本地 Go、gofmt、编译、NPM、浏览器、服务、真实 UID、runtime 或生产验收。首次隔离 CI 格式门仍可失败，官方有界格式补丁必须保留。
- 旧 `9190` 的 P207 528、31 安全链和 CPU90 仅属于旧截点。旧 Capacity Go 689 通过同时伴随 full checker 失败，Foundation race 只有部分结果，均不能拼成 `98064345` 接受。
- 私有 JY-CW main `1e14…` 只归档到 `9190`：payload 66995、fresh 115。`4b326352` 与 `98064345` 均未自动补档。
- 产品 main、生产与 Registry 未改动。

机器可读事实见 [9806 阶段证据](evidence/sys07-code4b-source-stage-20261103.json)。
