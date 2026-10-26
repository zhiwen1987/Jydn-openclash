# SYS-06：配对容量测量操作说明

此分支仅执行隔离测量，不部署产品，不接管局域网流量。代码已经源码复审；真实测量结果需另行读回。

只向 `codex/chengwang-capacity-measure-*` 专用分支推送时启动配对工作流。普通生命周期开发分支不会额外运行它。保留的手动入口受 GitHub 默认分支注册规则限制，本轮使用专用分支 push，无需修改 main、创建 tag 或发布镜像。

AB 与 BA 是两个独立 job。每个 job 在同一 runner 上依次运行两种模式，每次使用新的进程、network／mount／PID namespace 和私有 Go cache。A 使用普通 race 参数；B 使用现有 tagged FULL_CONTRACTS profile 参数。两种模式的参数和环境由原件记录，不能把差值直接归因于 profiler。

Go 的 `-timeout=180s`、256 次实际 history 循环和 2 MiB 上限保持不变。单 leg 外层监督为 270 秒、终止后最多 15 秒强杀；job 的 12 分钟墙钟只给准备、编译、保存和上传留余量，不保证任意外部延迟下都能完成。

每个 artifact 保留两次运行的命令、stdout／stderr、源码前后快照、主机与资源观察、Go 版本、上下文及 comparison.json。读取时核对 exact commit、run／attempt、AB／BA 顺序、源码绑定、原始退出码与 Go 事件。CLI 墙钟、包 Elapsed、容量测试 Elapsed 分开报告。

工作流成功只可能表示测量原件被成功获取和复核。必须分别读取 a.goAccepted 与 b.goAccepted；任一 timeout、skip、未完成或失败不得被报告为 Go 通过。报告中的 productAcceptance、performanceImprovementProven、profileOverheadCausalityProven、identicalSystemLoadProven、production 均为 false。

两次运行仍共享 job cgroup 和主机；没有逐 leg 独立 cgroup，也不能证明负载相同。一次 AB／BA 不证明稳定性能收益。组织级 ruleset 和外部 required workflow 的行为需要实际 CI 观察，不能仅靠本仓库源码推断。

## V3 同轮已验证尾项候选测量

本轮仅测量两个 Go 源文件的窄候选：同一轮完整校验后，当前 V1 REVOKED_UNSTARTED 与最后 history 项逐值完全相等，且无 Source、Execution、Reconciliation 时复用已完成的校验。其他 phase、V2/V3 及跨操作／跨解码缓存全部排除。源审查允许进入 Linux 取证，尚未证明编译、race、180 秒余量或性能收益。原 688 名称、256 次真实循环、2 MiB、race 与 180 秒门均不放宽，测量工作流和读取器逐字节保持。新分支不含独立恢复修复或 stage 诊断；主生命周期工作区保持不变。AB/BA job 成功仍只代表采集与读取成功，必须分别检查四 leg 的 Go 结果。不同 job 的主机／负载相同及因果收益均未证明。
