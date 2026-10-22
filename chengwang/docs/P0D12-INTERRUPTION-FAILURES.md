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
