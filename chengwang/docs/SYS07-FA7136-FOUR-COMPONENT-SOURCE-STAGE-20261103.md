# fa7136 四组件源码阶段与严格模型边界（2026-11-03 当前截点）

一句话结论：formal 当前为 clean `fa7136afd6bbe18b46c7bc1e0b263578f027e12e` / tree `88e924578c432caa0d275c116c41864599655cb6`。18 路径组合的 Slice A 整体风险建议在复核当时是 `hold_for_evidence`（其窄源码切片判断为 `SOURCE_ACCEPT_FOR_CONTROLLED_INTEGRATION`），Slice B 后续建议 `merge / human_review_required`；再后来的 263 项 Python 来源模型输出获独立接受，root 据此将源码提交到开发分支但尚未 push。后续证据和 root 决定不回填或改写 Slice A 当时的 immutable 风险结论，也不等于 Go、gofmt、Linux UID、联合业务、31、新 HEAD CI 或生产接受。

## 当前已核事实

- 四组件为 official-gofmt repair、Capacity Fixture-B Oracle setup-phase、UID bridge v3、capacity current fixture identity。组件 release 原件为 `D:/CodexData/workspace/chengwang-8e5f-four-component-unified-freeze-release-receipt-20261103-cd03-v1/FINAL.json`（2990 bytes，SHA-256 `6c8e7d24b265efa7662bb853f4c0dd53caf91e3eb8a85f958b15a6de16a2e202`）。
- Slice A 的 immutable 风险回执是 `D:/CodexData/home/state/plugins/codex-security/scans/chengwang-8e5f-four-component-unified-source-freeze-20261103-cd03-v1/artifacts-140d9af3a47410f611786edc49c4719a727f78025b7bdeb7aacf9203c6b780b6/artifacts/independent-slice-a/FINAL-PATCH-RISK.json`（13864 bytes，SHA-256 `3401fae450cbd639fd72d8386af779b5961576dc59bd98feffa6940d21ed68cf`）：`recommendation=hold_for_evidence`、`workflowLabel=hold_for_evidence`、`exactHeadChecksPassed=false`。同一复核的配套说明 `D:/CodexData/home/state/plugins/codex-security/scans/chengwang-8e5f-four-component-unified-source-freeze-20261103-cd03-v1/artifacts-140d9af3a47410f611786edc49c4719a727f78025b7bdeb7aacf9203c6b780b6/artifacts/independent-slice-a/FINAL-REVIEW.md`（5006 bytes，SHA-256 `62dcc6a4429db40574fdef193e98e2c936d8dd7c5770285168afdc843c45995a`） 另行明确窄范围 `Slice A source verdict=SOURCE_ACCEPT_FOR_CONTROLLED_INTEGRATION`，但 whole patch 仍须 hold。两者不是矛盾，也不能把窄源码判断写成整体 merge。
- Slice B 的独立回执为 `D:/CodexData/home/state/plugins/codex-security/scans/chengwang-8e5f-four-component-unified-source-freeze-20261103-cd03-v1/artifacts-140d9af3a47410f611786edc49c4719a727f78025b7bdeb7aacf9203c6b780b6/artifacts/four-component-slice-b-independent-review/FINAL-SLICE-B-PATCH-RISK.json`（13384 bytes，SHA-256 `81a7b48020c0dad047632e8fc51247db95230ef2f79321a3f84cbbcaf8cbbb3a`），其状态是 `recommendation=merge`、`workflowLabel=human_review_required`、`exactHeadChecksPassed=true`。Slice B 后续状态、263 模型和 root 开发分支提交都不追溯改变 Slice A 复核当时的结论。
- root 的首次补丁准备明确失败于源码应用前，公开消息仅为 `part failed`，精确子因保持 `UNKNOWN_NOT_CAPTURED`，且 `sourceApplied=false`；原件为 `D:/CodexData/workspace/chengwang-four-component-root-patch-preparation-20261103-cd03-v1.json`（544 bytes，SHA-256 `80963b476a1a281b373a6449ba3d8657a03ad7c5a522f03b140e95001436fc60`）。随后 18 路径被 root 提交为开发提交，`pushed=false`、`productionChanged=false`；原件为 `D:/CodexData/workspace/chengwang-four-component-root-stage-commit-20261103-cd03-v1.json`（382 bytes，SHA-256 `2c11434382b905592c1fbfa7f0a5aea55b9bdd0d4919a45eadc23a74cbd40417`）。
- 当前 profile fixture 身份是 SHA-256 `fab19f1ca714105f5002d31e2e37ca4cdb0296c5133431951ac81a1576056bc4`。它是本组合使用的 current fixture identity，不是历史性能测量，不能据此推导性能变化。
- strict root 的实际输出为 263/263：P207 83、joint 104、oracle 24、profile 6、timeline 46，五组均 exit 0，fail/error/skip/expectedFailure/unexpectedSuccess/unknown 均为 0。汇总原件为 `D:/CodexData/workspace/chengwang-fa7136-strict-root-models-20261103-cd03-v2/SUMMARY.json`（2322 bytes，SHA-256 `02fd776c2a1016b0ba778340364aaa6ee97e11aa77f1d08279d79d35df32bfc0`）。
- 输出独审核了 `trustedPassed=true`、26/26 来源 pin 的 raw Git/SHA 对应、正式库前后 clean 和 HEAD/tree 未变，并保留旧 4b 失败与 binding-v1 拒绝；机器原件为 `D:/CodexData/workspace/chengwang-fa7136-strict-root-models-independent-output-review-20261103-cd03-v1/FINAL.json`（3437 bytes，SHA-256 `c6b9095ce61d875e99a4233184984d90351a4c484efc8df8f9c9a8e03c03e1ec`），配套说明为 `D:/CodexData/workspace/chengwang-fa7136-strict-root-models-independent-output-review-20261103-cd03-v1/FINAL.md`（1594 bytes，SHA-256 `64bac7879f01d1ddf2f8aa414b6974d0a627f1532705d7708ccf9b78c522c2ee`）。它只接受 Python/source-model 输出，不证明 Go 或运行时。

## 保留的失败与修订链

- binding-v1 因从文件名片段而非分组目录推导相对目录，在执行前被拒；原件为 `D:/CodexData/workspace/chengwang-fa7136-strict-root-binding-v1-rejected-20261103-cd03.json`（368 bytes，SHA-256 `2505418803b375ad2e953e261255a93ef6d31ea9a9d23605db5ed190ecb488c5`）。v2 manifest 的 26 来源 union 为 `D:/CodexData/workspace/chengwang-fa7136-strict-root-binding-20261103-cd03-v2/MANIFEST.json`（5472 bytes，SHA-256 `b7bccc9ec490a34ef6fb6a580ac851d907d08b4cf9305f03822e5d20978988bf`）。
- UID bridge v1 因 partial cleanup 对 sealed `0444` 内容检查绕过而 `REVISE`；v2 虽获源码接受，随后仍发现 FSM 终态缺口；v3 才加入真实四终态修复与对应负例覆盖。不能把 v1/v2 的阶段状态覆写成最终接受。
- root 首次 prepare 失败、binding-v1 拒绝、旧 4b 模型失败均继续保留；没有通过删除或改写失败原件制造无失败历史。

## 当前不可越界

- 本 HEAD 的 Go、gofmt、Linux UID、联合业务、31 链和 CI 均未运行或 UNKNOWN；不能复用旧 HEAD 的绿色结果。
- JY-CW `d4035d5e` 的归档只覆盖到历史 `8e5fd014`，不包含 `fa7136`。本候选没有写 JY-CW。
- [SYS01–30 历史事实基线](SYS01-30-FACT-BASELINE-8E5F-20261103.md)是绑定 `8e5f` 的原字节历史材料，不是当前 `fa7136` 验收，也不能缩短 30 包范围。
- 本 docs-authoring 候选尚未写入 formal；这与阶段中 root 已把 18 路径源码提交为开发提交 `fa7136`、且 263 项 Python 来源模型已通过是不同主体、不同动作。docs 尚未集成或 push，产品 main、release、Registry、生产均未改变。执行本记录所用的实际助手模型 SKU 为 `UNKNOWN`，该字段不否定或替代已经逐原件核验的 Python source-model 结果；实际 Go/Linux/业务运行态仍未验证。

机器可核字段和所有证据的绝对路径、字节数、SHA-256 见 [同名 JSON](evidence/sys07-fa7136-four-component-source-stage-20261103.json)。历史 `8e5f` 截点保持为独立冻结记录，不回填后续事实。
