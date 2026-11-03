# 8e5f 归档、Foundation 与待集成源码边界（2026-11-03 历史冻结截点）

一句话结论：这是 `HISTORICAL_FROZEN_CUT`，记录 JY-CW d403 归档读回和 Foundation 安全时间线完成后、UID v2 独立接受前的 `stateAtCheckpoint`；当时产品 formal 仍是 clean `8e5fd014ed3858b25593142dece069b6f1ea7769` / tree `35f812d7cb15a178c7576339e207d40280d966a8`，Foundation workflow 实际首因 UNKNOWN，两组源码候选尚未集成，UID v2 仍待独立复审。后续事实必须写入新 checkpoint，不能回写本截点。

## 已核事实

- JY-CW `d4035d5eb9c413ed195fffc3d5321f5b74244e05` / tree `73cf9cad46694ea9c10e82179dc09545caaf49d7` 已 push 并核远端 ref；fresh partial clone 对 393 个已提交路径逐一读回，缺失、长度不符和 SHA-256 不符均为 0。最终独审接受的是归档与远端读回，不是 Go、Linux UID、业务或生产验收。
- root 全扫回执为 67,380 文件、1,251,282,878 字节、0 failures。最终独审只按 SHA 引用该回执，没有重复执行全扫。
- Foundation run `41550851674` attempt 1 的安全双成员时间线独审通过：ordinary 与 race 均为 689 pass / 0 fail、child exit 0、完整 EOF。容量父 top 的 active span 分别约 0.55 秒和 5.46 秒；它们不是五个 Fixture-B 子 oracle 的逐项证明。
- 同一 Foundation workflow 的结论仍是 failure。安全时间线不能确定首个失败谓词；实际首因保持 `UNKNOWN`。源码只证明 fresh checker 若在成功报告生成前退出，后续 `if-no-files-found:error` 上传会形成次生级联，不能把该上传失败当独立根因。
- 两个 mixed capacity artifact 的声明上传面含 raw stderr、pprof、profile、gofmt 和命令/状态类成员，metadata 不暴露成员 allowlist；安全审查结论是均不得下载或按体积猜内容。本候选没有下载它们。

## 候选与阻断

- 官方 gofmt 的 9 路径候选已获独立源码准入（`merge / human_review_required`），仅可进入后续隔离 CI；尚未集成到 8e5f，未证明候选 HEAD 的 Go/gofmt/runtime。
- Oracle setup-phase 的 5 路径候选也获独立源码准入（`merge / human_review_required`），严格保持诊断与 Oracle 接受分离；尚未集成，真实 Linux namespace、UID 10001、Go 和实际失败 phase 仍 UNKNOWN。
- UID bridge v1 的独立结论为 `REVISE`：partial cleanup 对 sealed `0444` 文件错误跳过内容校验。在本历史截点，v2 已冻结并声明所有 `0444` 都需 exact bytes + SHA-256，但仍待独立复审和 Linux CI，不能称已经修复或接受；后续接受或 v3 FSM 负例不回填本记录。

## 不可越界

- 旧 checkpoint 与历史拒绝记录原样保留；不能把 JY-CW 归档接受、Foundation 的 689-top 时间线或候选源码准入拼接成当前全项目接受。
- SYS01–30／历史 30 包的完整验收仍未证明；本记录不缩短或覆盖旧任务清单。
- 等最终组合身份确定后另写新 checkpoint，再做一次追加集成，避免反复提交触发 CI。
- 主体必须分开：本次 docs-authoring 子任务没有运行 Go、没有新增 artifact 下载、没有写 formal、没有 push 或部署；本阶段较早已授权并完成私有归档仓 `zhiwen1987/JY-CW` 的 main push，也已取得 Foundation 的安全双成员 timeline artifact；两个 mixed capacity artifacts 未下载。
- 在该截点，产品 formal 开发仓、产品 main 分支、Registry 与生产均未变。这里的“产品 main 未变”不包括上条已经明确发生的私有 JY-CW main 归档 push。

机器可核事实见 [同名 JSON](evidence/sys07-8e5f-archive-foundation-pending-20261103.json)。该 JSON 的 `evidence` 列出每份原件的绝对路径、字节数和 SHA-256。
