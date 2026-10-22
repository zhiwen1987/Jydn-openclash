# P0-d3 标准 Sigstore 验签候选

日期：2026-10-22（Asia/Shanghai）。

本阶段把 P0-d2 尚缺的标准密码学来源校验推进为独立可执行候选，位置 `tools/image-verifier`。主项目 Go 基线与现网均不变。实现合同、输入预算、CLI 使用及明确不支持项见 [模块说明](../tools/image-verifier/README.md)。

## 验收记录

已由最终集成者在 Windows 使用固定 Go 1.25.8 执行普通/race/vet、模块摘要校验与严格 JSON 门禁：`IMAGE_VERIFIER_GO_JSON_GATE=PASS transcripts=2 tests=325 packages=2 skips=0 race=pass authorization=BLOCKED production=false`。包含两种官方真实 bundle、各密码学/歧义负例、CLI 编译后真实子进程和父进程硬终止。初次集成发现 Rekor v1 全局 index 与分片 proof index 被错误强制相等，已按官方协议与 SDK 实现修复；原始 fixture 不作改写，并追加各索引独立篡改回归。

已读回并核实实现提交 `ab5fc8d05e63dd651ea0af14a892d9402421a5ff` 的以下实际 Linux 结果：

| 范围 | 权威记录 | 实际结论 |
| --- | --- | --- |
| 独立标准验签模块 | [run 39738209558 / job 119688829847](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39738209558/job/119688829847) | `success`；Go 1.25.8 linux/amd64；ordinary/race 各 325 个 Test 场景、2 个包、0 skip；vet、模块 verify、23 个门禁拒绝自测通过 |
| 真实离线与权限边界 | 同一任务日志及 artifact `image-verifier-offline-39738209558-1` | 不同 network/mount namespace、无外部接口和路由、IPv4/IPv6 连接失败、非 root、五类 capability 全零、NoNewPrivs=1、源码及 module cache 只读 |
| 原主项目回归 | [run 39738209273 / job 119688829203](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39738209273/job/119688829203) | `success`；主项目 Go 1.23 基线；`GO_JSON_GATE=PASS files=2 semanticRunEvents=4020 packages=36 skips=0`；11 份 schema、既有 Python/真实 Docker/恢复系统调用门通过 |

最终集成者已下载独立验签 artifact，用本地严格门禁重新验证两份 transcript，读回 325 个相同测试集合。19 份模块文件的 before/after manifest 相等，逐份对照上述 Git 提交的原始 blob 摘要一致。不是仅依据 GitHub 绿色图标得出结论。测试包括编译后的 CLI 真实子进程、两类正例、篡改失败及父进程硬终止；不把父进程硬终止当作 SDK 内部可取消证明。

该证据只签署本节列明的仓库候选边界，没有做生产安装、真实镜像准入或恢复切换。Windows 首次并发验收曾出现一个 `strconv` 导入编译失败；后续冻结文件、串行使用同一工具链完成完整普通/race/vet，且独立 Linux 门通过。前次失败不计为通过，其确切环境原因未认定。

## 证据边界

- 成功只表示：给定原始字节在给定独立策略下通过标准库验签，结果固定 advisory/BLOCKED。
- 不表示：信任根独立批准、TUF/撤销、澄网源码或 builder 批准、Registry 真实来源、运行中镜像相同、唯一出口、可安全恢复或生产已部署。
- 新工具暂未接入任何产品执行器；不移除九项 blocker，不修改旧 Python 供应链校验器的 BLOCKED 行为。
- 已补查固定 conformance README 的 Apache 2.0 明确声明，纠正初次只寻找独立 LICENSE 文件的不完整结论；来源和许可证文本已保留，但不能把该窄项核实当成完整产品依赖许可审查。

后续必须完成 approved trust/policy 管理、Registry 仓库/平台读回、graph 与签名对象关联及独立部署绑定，然后才有资格进入受控运行态验收。M2b 主动探测、M3 受控发布和 M4 DNS/自治闭环仍未完成。
