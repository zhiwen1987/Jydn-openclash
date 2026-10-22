# P0-d3 标准 Sigstore 验签候选

日期：2026-10-22（Asia/Shanghai）。

本阶段把 P0-d2 尚缺的标准密码学来源校验推进为独立可执行候选，位置 `tools/image-verifier`。主项目 Go 基线与现网均不变。实现合同、输入预算、CLI 使用及明确不支持项见 [模块说明](../tools/image-verifier/README.md)。

## 验收记录

已由最终集成者在 Windows 使用固定 Go 1.25.8 执行普通/race/vet、模块摘要校验与严格 JSON 门禁：`IMAGE_VERIFIER_GO_JSON_GATE=PASS transcripts=2 tests=325 packages=2 skips=0 race=pass authorization=BLOCKED production=false`。包含两种官方真实 bundle、各密码学/歧义负例、CLI 编译后真实子进程和父进程硬终止。初次集成发现 Rekor v1 全局 index 与分片 proof index 被错误强制相等，已按官方协议与 SDK 实现修复；原始 fixture 不作改写，并追加各索引独立篡改回归。

Linux 禁网、只读挂载、race、完整测试集合以及子进程门的最终结果，须在实际 CI run 完成后追加；此处不预填成功。Windows 普通测试、代码审查或 workflow 文件存在均不能替代该证据。

## 证据边界

- 成功只表示：给定原始字节在给定独立策略下通过标准库验签，结果固定 advisory/BLOCKED。
- 不表示：信任根独立批准、TUF/撤销、澄网源码或 builder 批准、Registry 真实来源、运行中镜像相同、唯一出口、可安全恢复或生产已部署。
- 新工具暂未接入任何产品执行器；不移除九项 blocker，不修改旧 Python 供应链校验器的 BLOCKED 行为。
- 第三方 fixture 的许可证差距独立保留，不能把测试材料兼容性当成产品分发许可证通过。

后续必须完成 approved trust/policy 管理、Registry 仓库/平台读回、graph 与签名对象关联及独立部署绑定，然后才有资格进入受控运行态验收。M2b 主动探测、M3 受控发布和 M4 DNS/自治闭环仍未完成。
