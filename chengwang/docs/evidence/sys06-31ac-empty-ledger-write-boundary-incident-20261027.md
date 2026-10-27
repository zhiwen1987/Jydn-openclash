# 子代理误写正式开发工作区：保存、恢复与隔离复核

本次 `refresh_failure_source_diagnosis` 收到“仅在外部候选修改”的要求，却误把正式开发目录 `D:/CodexData/workspace/chengwang-mihomo-lifecycle-uv9npzyn/r` 当作候选，提前修改4个源文件：refresh.go、refresh_test.go、subscription-refresh/source_contract.json 及对应 workflow。root从工作树状态发现并立即叫停。子代理确认没有后台进程，未提交、推送或操作生产。此事实意味着事故发生时并未遵守单一集成者流程，不能将该次写入描述为root集成。

root已在新外部目录 `D:/CodexData/workspace/mihomo-31ac-empty-ledger-boundary-incident-pto2871o` 保存并fsync全部4文件的Git原始before像、实际after像、文件哈希、mtime及完整差异。保留差异为6936B，SHA256 `74f2ab86b3e0764b24c97af78b61d579602c3b9a32f388602d94ffa519781c87`。子代理另给的非full-index补丁也保留，但未用于恢复或集成。

root用apply_patch逐文件恢复到 `31ac3c9c895c2c665ae6472a02a1dcb22b4ad002` 的原始字节，未使用reset／删除／覆盖历史证据。恢复后4源全部before SHA匹配，正式工作树仅保留原先任务文档与证据变更；5项受保护文档哈希保持。外部 `INCIDENT-PRESERVATION.json` 和 `ROOT-RESTORATION-RECEIPT.json` 分别记录保存时与恢复后的事实，不回写抹去早期状态。

随后root创建精确31ac的第三隔离worktree `isolated-candidate`，用apply_patch重放保存的4个after像，其完整diff与保存补丁逐字节相等。候选manifest SHA256 `1b71d4b6910c778a2ee41ce616ce0525dc50aac4682adc8bdd62c16a0c26c9a4`，source checker通过，CPU与独立peer另验。流程事故的处置不代表补丁已经被准入、集成或运行通过；正式R没有采用尚未审查的修复。

生产、main、Registry、用户原工作区均未因此改变；没有本地Go、gofmt、浏览器、服务或网络内核运行。后续必须依据独立peer与实际Linux结果决定是否由root重新集成，不以恢复成功代替功能验收。
