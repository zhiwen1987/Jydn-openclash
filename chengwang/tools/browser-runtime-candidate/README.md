# 已审原字节候选引用：尚未执行

`pin.json` 的 browser SHA 是从真实 acquire/fresh Linux 原件重算读回并由根集成者审阅后固定的，不是猜测的官方摘要。这里特意采用独立的第二提交，不回写第一提交中 `sha256=null` 的获取合同，不篡改其原证据。

这是参考 pin，**目前没有执行 harness 消费它**；不得称为现有浏览器已固定或已经升级。原 `playwright-core@1.64.1`、宿主 Chrome 复制路径与严格回归全部保持不变。alpha 仅是下一阶段隔离候选，不用于生产。

两种 ZIP 必须区分：`originalArtifact.sha256` 是 GitHub 上传工件外壳；`browser.sha256` 才是里面官方 `chrome-linux64.zip` 原字节。fresh 小报告包不包含浏览器。本机没有下载或重算202MB浏览器原 ZIP；重算发生在两个 Linux CI job。本机只复核小报告包、原9 metadata、精确Git5源及原日志的一致性。

下阶段必须先实现只在隔离 CI 下载/核验该实际 SHA 的执行门，再安全有界展开并核对真实 ELF、正常 TLS/权限、运行时 product/revision/protocolVersion。任何变化或来源丢失都失败关闭，不自动换源、换版本、更新 pin 或回落到未固定宿主浏览器。当前 `sourceTagCommit` 是已核源码 tag，不是实际运行 revision；后者继续保持 `null`。

尚须通过 no-store 分块正例、超限/HTTP截断/显式 abort 负例及完整 CDP/PW 原门；最后才是新订阅页真实 E2E。下载、源码包含补丁、某一轮旧回归绿色，都不是本项目取消故障已修复证明。参见[阶段记录](../../docs/P2-BROWSER-IDENTITY-ACQUISITION.md)。
