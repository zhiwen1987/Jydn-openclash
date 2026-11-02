# SYS07：隔离 CI 阻断修复源码截点

代码提交 `8d9707f612e74a465a4a322d1edd1cc770305dde`，代码树 `0f716b46fd6de4bc51e3c7c268288c5a53e18c6d`。两份组合独立复核均接受后，由根会话按已备份的 12 个前像手动集成；正式树与冻结候选逐字节一致。没有生产变更。

## 实际修复

1. 将 385ba 的隔离官方 Go 1.23.12 `gofmt.patch` 精确应用于两个 Go 文件；只改格式，不改变产品语义。
2. CPU 步骤显式捕获 unit、Go、两类投影、fallback 和 publish 的状态，避免继承 Bash errexit 后在记录状态前退出。失败仍保持失败，publish 失败不写 ready；不公开私有 Go 日志。
3. failure reader 绑定实际契约的有序 9 包集合，修复旧的固定 7 包冲突。补充真实契约及报告往返回归，缺包、重排和额外包仍拒绝，528 个必跑 tops 不变。
4. 仅测试夹具增加 finally 清理并断言资源关闭，消除两个临时文件泄漏。保持产品、警告设置、严格日志正则和 Git 替换回归不变。
5. 新增回归使来源模型 82→83，因此同步精确工作流名单、摘要和规范化指纹。四方共享契约统一重生，不能复制某个单独候选的旧 pin。

## 集成后复核

根会话 204 项受影响 Python 方法全部通过：P207 83、joint 83、timeline 38。判定来自结构化 unittest 名单，与源码 AST 精确核对；失败、错误、跳过均为空，运行前后 clean HEAD/tree 和源码摘要一致。没有运行本地 Go。

实际来源检查通过：842 module、21 fixture、545 source tops、528 required tops、38 changed-Go、S92/Q80、foundation 689。实际 joint validator 通过，853 条契约由当前提交再次生成，字节、跟踪文件及 workflow pin 均等于 `c57dfdaa49596896a1b34f283c75a9887c8e5eed4fe472a52291939ce6cc40de`。

## 必须保留的失败与未知项

385ba 的 P207 原件同时显示非空格式补丁与 Go 命令退出 1。曾把退出码误认为 sentinel、称 Go 未调用的推断已纠正：实际工作流控制流及 source-after 记录支持 Go 已调用，但没有测试/失败报告，无法判断具体测试结果或原因。7→9 的 reader 冲突解释诊断器的确定拒绝，不解释 Go 自身的失败。

385ba foundation 的 47/29/38 方法实际通过，但两个测试夹具的 ResourceWarning 打断 verbose 行，原严格 heredoc 在第 19 行拒绝。旧日志和拒绝保留；修订夹具后的受控日志通过同一完整 heredoc，仍不能冒充新 Linux 实跑。

385ba 的独立 31 步 HTTPS 原件已获有限接受；只属于 run41515830933/attempt1/385ba，不能迁移为本修复提交验收，也不代表生产或互联网业务。

最新提交自己的 Linux Go、格式、official selection、source/fresh、联合 B0/J1/R2、foundation/capacity 与 31 链仍待隔离 CI。完整系统、actualfs 耐久、产品 authority/executor、灰度与上线均未完成。

## 证据及恢复边界

[源码修复证据索引](evidence/sys07-ci-blockers-repair-source-20261103.json)。12 个前像备份位于 `D:/CodexData/workspace/chengwang-385ba-root-preintegration-backup-20261103-cd03-v1`，原基线为 385ba；这只是开发文件备份，不是旁路由恢复包。生产/main/Registry/路由器/DNS 未修改。
