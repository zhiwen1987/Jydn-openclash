# D12 真实中断子门：失败轮记录

本记录保留未通过的运行，不把前置测试或部分动作通过当作整体验收。生产环境、main、正式镜像发布均未操作。

## 8b07872：Registry 屏障未就绪（2026-10-23）

- 代码 `8b07872d6255ca1031bc8b0cfcf91df6e9ccd5d4`；[绑定运行39847387651 / job120064139154](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39847387651/job/120064139154) 最终 failure。不是取消或超时后推定失败。
- 公开诊断 `product-crash-failure-diagnostic.json`：stage=`reserved`、kind=`message-signature`、phase=`ready-reserved-message-signature`、driverSourceLine=0。READY 至失败约2.175秒，匹配控制端2秒等待窗；该时差不能证明底层原因，也不能证明 helper 已经成功启动。
- 原始 job API 日志1,822,560B，SHA256 `465847d1cd387173a47dc2aa7a32086d9ac8503916ca7a2744f7b28f7fc4818b`。工件12455858682，ZIP4,341,243B，API SHA256 `a2eb16ebfd1aca20d0be821e821797c44ab0600f5f7bcab3981c2a581f49adaa`；14天保留期，不是永久备份。
- 主代理与独立代理分别下载工件。native13（含真实 tmpfs/只读文件别名）、profile6、checker27均具名通过且无跳过；这不能代替真实 Distribution 屏障。8b 已有 `mount --no-canonicalize`，不能把缺少该参数或 tmpfs 不支持当作已确证根因。
- 两个 PREPARED 场景的动作标记和真实内核等待关系存在；动作 JSON 尚未统一导出，完整 outcome 缺失，完整检查器正确拒绝。不能据此验收两个场景的完整证据链，更不能宣称六格完成。
- 新门输出 `D12_PRODUCT_CRASH_CLEANUP=FAIL`：实现把任何紧急 helper/client 回收都计为失败，因此该标记不能区分“需要干预但已回收”和“实际资源残留”。没有成功 cleanup report，不补写或推定成功。外层 D10 自有资源清理为 PASS；它不证明新门的资源全部回收。
- 旧 D12 65关联、D11 49关联独立重放通过，普通/race各700、Registry各3、浏览器40/45/45均通过。666条源码记录（583 checkout、83 child；583唯一路径）before/after字节相同，逐本轮 Git 原 blob 核对一致。
- [父运行39847387924 / job120064140803](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39847387924/job/120064140803) success；普通/race各2320个 Test* 具名 run/pass 一致、零跳过/失败。集合 SHA256 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`。原 API 日志5,447,221B，SHA256 `35668211cbe3569836fd66e940ee14243399fc840ed2b377d445600e684f3c7e`。

处理方向仅为补齐闭集安全诊断：区分启动/等待阶段，输出固定步骤、异常类别、整数行号/errno或既有 helper 错误枚举；不导出异常消息、路径、token、私钥或原始日志。不放宽租约、权限、期限或验收断言；新增诊断后仍须重新取得真实 Linux 运行证据。

诊断改动的本机辅助验证：bash语法检查、25段Python AST（18 heredoc、6字面量`-c`、1 record wrapper）及10个闭集过滤器合成样例通过。样例包含任意secret/路径、未知reason、重复标记、坏编码和超限日志。它们只验证诊断代码形态与不回显原文，**不证明底层启动故障已修复，也不算新的Linux产品验收**。

## a415419：明确 bind alias 命令失败（2026-10-23）

- 代码 `a41541970d57cc45108cc66d541adeb39200db46`；[绑定运行39849854526 / job120072788804](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39849854526/job/120072788804) completed/failure，未取消或原地重试。
- 安全诊断 phase=`wait-holder-ready-blob-reserved-message-signature`；helper `BIND_ALIAS / CalledProcessError / INLINE_STDIN line30 / errno0`，对应 `mount --no-canonicalize --bind /proc/<holder>/fd/<blobfd> <UUIDalias>`。这是实际失败命令；errno0表示没有取得底层 mount errno，不能写成本轮已捕获 EINVAL。控制端的 FileNotFoundError 只是没有 READY 文件，不是根因。
- 工件12457845403，ZIP4,341,237B，SHA256 `353f75af1d34d2e70dc137eb73f860124e43891c652c27ff3a224ae0fc541e60`；job API 原日志1,823,052B，SHA256 `746d48f4f46664c5ecc48a34506f2f44881bfdfbafb31dead714ea52f7d232dd`。主代理及独立代理各取副本，失败诊断没有发布原私有日志。native13/profile6/checker27与旧门继续通过，但新完整outcome和成功cleanup报告仍缺失，整体不验收。
- [父运行39849854656 / job120072789206](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39849854656/job/120072789206) success；普通/race各2320个 Test* run/pass完整一致，无跳过/失败；原日志5,447,548B，SHA256 `3805dd05192c5515f2ac524e61e14010e7b309a18a983cdd47ddf12ce8cd8f69`。

源码解释与实测分开：[Linux v6.8 namespace.c](https://github.com/torvalds/linux/blob/v6.8/fs/namespace.c) 的 `__do_loopback` 检查源mount属于当前namespace；传统 bind 和 `open_detached_copy` 都调用它。因此 host 侧直接对 Registry 的 foreign tmpfs FD 做传统bind，或仅改成 host侧 `open_tree(CLONE)`，均不能作为正确的跨namespace设计。此为源码分析，不冒充本轮实际取得的 mount errno。

下一候选只修测试屏障：保存原私有namespace，暂进入已验证 Registry mount namespace，对持有的精确文件FD克隆 detached mount，再无条件恢复原namespace，在原私有namespace将克隆设为只读并连接到闭集alias。不得修改Registry原mount、复制blob、给helper增权或放宽期限；须新增真正foreign namespace的Linux测试，并重新验收实际镜像，候选设计本身不算通过。

## e3a8a51：安全计数导出权限交接失败（2026-10-23）

- 代码 `e3a8a517e5c548bc3445c2a078867b93d2c916e1`；[绑定运行39852580963 / job120082376127](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39852580963/job/120082376127) completed/failure。工件12458316709，ZIP4,469,917B，SHA256 `81ba12a9e3ea62a639d2530ebaa0f2f1c8981b0d63eafaaef21e27cc3edb4c1a`；原job API日志1,832,067B，SHA256 `55b5628ded2903701d0dd8be159c4ea2c332a2a5688802826863b7356bfd1bf3`。
- 新跨namespace原生回归在本轮真实Linux通过，native14（保留旧13）、profile6、checker27完整具名且零跳过；主代理独立重算native具名集合，其SHA256 `ed707c5088ec1d768ccd7d64aa234132d95655687db615eae25944b041920dba`，测试原文SHA256 `0cd5cdc741754e47bda574aee61272f28f8944c796b072cdb484faca6627f973`，源文件SHA256 `6422344da3bd74ea1b4df95428b91f809e20383a4c1f29848ae406ff3f3fa2d4`。
- 六格62份动作与6份graph已导出，动作链原函数可独立重算通过；各格最终seq10/journal2/audit4，6次计划SIGKILL137、12次产品正常退出0有安全投影。独立代理另外复核8条真实内核租约关系及runtime。**这仍只是本轮已有证据的部分重算，不是完整中断子门验收。**
- 失败位于`safe-evidence-export`：control PermissionError/errno13；`product-crash-observations.json`为0B，成功cleanup/outcome均缺失。控制器以root写`0600 snapshots.private.json`，最终安全计数导出却由非root Python读取，导致权限交接失败。68份动作/graph成功导出以及0B observations共同定位到这个明确调用；不是据此推定产品动作失败。
- 因缺少完整60计数快照的安全投影，不能验收恢复零Registry访问、完整drain关联、精确清理或151条整体关系；完整checker正确拒绝。不补写observations或cleanup，不在旧工件上伪造通过。旧D12/D11门独立重放仍通过。
- [父运行39852580901 / job120082373641](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39852580901/job/120082373641) success，普通/race各2320项具名Test*完整一致、无跳过/失败；原日志5,447,566B，SHA256 `cd07d551ecb80bd13042844fe93fb126626b3f497a868571a1fdcfcfc167713e`。

下一修正仅对固定私有计数文件使用已有root orchestrator做受限读取，增加NOFOLLOW、owner/mode/nlink/size及读前后FD/路径一致检查，再输出固定安全schema；不放宽0600权限、不改产品与测试期限，仍须新Linux/镜像完整验收。
