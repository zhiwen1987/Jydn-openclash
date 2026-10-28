# 进源Clash Center：AI 接手入口

更新时间：2026-10-28（Asia/Shanghai）。先阅读本页，再阅读下列交接文件；不要把设计或测试记录解释成已经上线。

1. [当前状态、约束与下一步](docs/handoff/current-state.zh-CN.md)
2. [架构与代码导航](docs/handoff/architecture.zh-CN.md)
3. [操作与恢复、私有资料位置](docs/handoff/operations.zh-CN.md)
4. [工作记录与决策](docs/handoff/work-log.zh-CN.md)
5. [验收账本](docs/handoff/acceptance-ledger-20261028.md)
6. [完整文件索引与 SHA-256](docs/handoff/file-inventory.json)
7. [全部资料索引](docs/handoff/document-index.zh-CN.md)
8. [脱敏历史证据摘要](docs/handoff/evidence-summary.json)
9. [历史运维摘要（Grok/Google/249/252/Lucky/ESXi）](docs/handoff/historical-operations.zh-CN.md)
10. [既有使用与维护手册](docs/system-guide.zh-CN.md)

## 首先确认版本

生产只读核实：`clash-center` 正在运行 `jydn/clash-center:0.2.0`；3101 仍暴露。0.3 功能源码位于 `codex/integrated-control-20261028`，尚未完成最终产物验收，也没有切生产。该分支是开发交接快照，不能作为已验收发行版安装。

用户已允许“功能先加载”：第三家订阅上游 502 不再阻塞功能上线，但其真实解析、双次准入、发布、Clash 加载必须保持待验收。

## 接手检查

```sh
git fetch origin
git switch codex/integrated-control-20261028
git status --short
git log -5 --oneline
```

重新只读核对生产版本、挂载、DNS 内容、provider 地址和 Selector 选择。不要依赖上一聊天的 SSH 会话、工具句柄或智能体状态。GitHub 阅读不能自动获得局域网权限。

公开交接资料已脱敏，不含账号密码、订阅 Token、私钥或数据库。完整业务上下文可以从仓库重建；私有运行数据需由所有者另外授权提供。不能声称仅凭公开仓库即可字节级恢复整个生产环境。

## 可直接粘贴给下一个 AI

> 接手 https://github.com/zhiwen1987/Jydn-openclash 。先读 main 的 AI_HANDOFF.md 和 docs/handoff/project-state.json，再切到 codex/integrated-control-20261028 检查源码。生产目前是 0.2.0，0.3 只是开发快照。请先只读核实现状，按验收账本补齐最终镜像、隔离和回退验证；第三家 502 可作为待恢复缺口，不得伪造通过。不得更改 DNS 内容、原 provider 拉取 URL、业务当前选择或 Windows 应用；生产切换先备份并告知。所有结论都要给实际证据，未经核实不说已上线。

开发源码：[codex/integrated-control-20261028](https://github.com/zhiwen1987/Jydn-openclash/tree/codex/integrated-control-20261028)。

源码快照提交：`e695c6631323948227e1058ce9afa43e45e9fcf9`。机器可读状态见 [project-state.json](docs/handoff/project-state.json)。
