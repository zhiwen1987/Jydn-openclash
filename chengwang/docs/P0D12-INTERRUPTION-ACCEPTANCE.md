# P0-d12 真实镜像三阶段中断恢复子门验收（2026-10-23）

结论：三阶段 × 两签名的有限子门已在隔离 Linux CI 实际运行，主代理及两名独立子代理分别下载并重算通过。它证明指定在途验证的异常终止、跨库补审计及二次重启幂等，不等于 D12 完整矩阵、正式恢复授权或生产上线。本轮没有修改产品运行逻辑，没有 SSH、生产配置变更、main 合并或正式镜像发行。

## 1. 接受的代码和原始来源

接受代码 `89dfade40f4cf916a6ee3ea6670a581c27338ff3`。后续文档归档提交不是另一份已验运行镜像。

- [绑定运行39854485066 / job120088990361](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39854485066/job/120088990361)：completed/success，attempt1。
- [父运行39854486241 / job120088994194](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39854486241/job/120088994194)：completed/success，head 均为上述代码。
- 工件12459581303，`image-binding-39854485066-1`，367个原工件文件，ZIP4,483,692B；API及独立下载ZIP SHA256均为 `004dade6346569a9098c643ff3e3ca701b985f6365e32092969eb06fb9355c3b`。保留期14天，不是永久备份或WORM。
- 绑定job API原日志1,832,250B，SHA256 `d015bfcf2fdde11d5bc5ac5413dc4da568a50684fdcd45947dd0bdcd1d51d8e4`；父job原日志5,447,046B，SHA256 `be152ebcb1aa433b0023276d1cd32c22fa8fa636b4c0df590083af23668644bb`。使用原API字节，不以`gh run view`包装日志当原文。
- 新检查器独立重算147个本门文件、151条输入摘要关系，canonical结果与CI outcome完全一致；outcome原文件SHA256 `f0b8b375981f3a1a17af1681974ddff5690a75e8d0a8efc08214a01176274d81`。

主代理验收副本：`C:/Users/Administrator/AppData/Local/Temp/chengwang-crash-89-root-ee6bd4c3bd434f6ca1226b2c49a09319`。该临时目录另附主代理下载的两份job日志，不把附加文件计入原工件367项；它不是生产目录或持久备份承诺。

| 身份 | 本轮实际值 |
| --- | --- |
| 产品二进制SHA256 | `3907fd54e49edb78b75e6bcc31467d532f817427a40dbee7f2e6f856758e7134` |
| imageID / config digest | `sha256:74e73bb5d5fcc4eec0717b0957e3da182606fa6a440fad4f3f97dbf6f2e7d60c` |
| Registry manifest digest | `sha256:98925270a0c6547dae633bdd8af675d6aca53d2108b6f8ee2dd9d7c24015294c` |

三种身份不互换。CI实际读取私有镜像graph原字节并与上传及封装内容绑定；验收者下载的是安全投影，没有下载私钥、私有archive或完整graph，不宣称独立builder/SLSA来源证明。

## 2. 六格真实流程

MessageSignature与DSSE各自执行下表三阶段，使用六个独立store、批准、权威和产品容器；全部验证同一真实产品镜像及正常TLS Distribution Registry。无产品fault HTTP/env/config开关，无管理员直接改库来代替真实在途操作。

| 终止边界 | 实际外部屏障 | SIGKILL后离线cut | 首次实际启动恢复 | 最后单独探测原批准 |
| --- | --- | --- | --- | --- |
| PREPARED | 实际events.jsonl的read lease阻塞prepared audit写打开 | seq2、audit0、ledger0、未ACK | seq5、audit2、INTERRUPTED、ACK，未消耗批准 | 200，首次合法消费 |
| RESERVED | 实际Registry config blob的write lease阻塞读打开 | seq4、audit1、RESERVED1、未ACK | seq6、audit2、VERIFICATION_RESERVED_NOT_COMPLETED、ACK，仍保留RESERVED | 400，拒绝重放 |
| CONSUMED | 先卡Registry，安装audit lease后放行Registry，再卡result audit写打开 | seq5、audit1、CONSUMED1、证据摘要已存、未ACK | seq6、audit2、ACK，消费状态及证据摘要不变 | 400，拒绝重放 |

每格同一个容器实际启动三次。首次恢复RecoveryCompleted=1；第二次启动为0，领域序列、journal、ledger及完整audit原字节不变。最终每格seq10/journal2/audit4；PREPARED与CONSUMED最终CONSUMED1，RESERVED仍RESERVED1。

原在途POST各发一次：终止前pending，终止后connection_closed、HTTP status哨兵0、没有响应或成功回执，不重试业务写。CONSUMED审计事实不等于原HTTP成功、送达回执或exactly-once。cut/离线reopen只调用真实truststate/evidence Open，不构造Service提前修复，并核读前后审计原字节不变。

检查器从实际安全事件重算Go事件序列化、纳秒时间、prepared/result哈希链、checkpoint、actor/scope/request/批准/消费绑定及ACK，拒绝纯布尔报告。

## 3. 内核屏障、隔离和请求计数

屏障为Linux F_SETLEASE，不是flock。8条实际holder→waiter关系各有两次稳定内核样本，共16个样本；绑定dev/inode、lock ID、PID/TGID/TID及startTime、实际open syscall/访问模式/路径。SIGIO或BLOCKED标记单独不算证明。最后实际阻塞样本至精确pidfd SIGKILL小于2秒；6次实际退出均137、无OOM、PID0，正常退出不允许借用137。

Registry使用原私有tmpfs、network-none/loopback、只读根、UID/GID10001、cap0、NNP及资源限制。为取得精确blob的只读alias，root测试控制器保存原私有namespace和FD，暂入已验证Registry namespace，仅对已持有文件FD克隆detached mount，再finally恢复原namespace/root/cwd；恢复后设置只读、nosuid/nodev/noexec及private传播，再连接到提前持有的闭集alias FD。不在Registry原namespace安装挂载或改变原mount，不复制blob，不给低权限helper增加capability。真实foreign-namespace第14项回归另外验证原源挂载保持可写、原字节不变、同inode别名、真实读阻塞/释放和FD/子进程回收。

实际计数共60个before/after快照。12个首次恢复/二次启动窗口Registry增量为零，加上四个拒绝probe，共16个明确要求的零请求窗口；不把drain计入这个计数。两个PREPARED末次probe有完整SDK读取；RESERVED/CONSUMED的四个probe均拒绝且不读Registry。原在途请求的零请求、部分读取和完整SDK读取预算分别核对，不把未完成请求当零访问。

解除屏障后先排空旧请求，以连接、目标FD、租约及两次稳定完成计数共同观察，再建立恢复前基线。恢复、二次启动和probe分别计数；不把旧请求尾部归因于恢复重读。

## 4. 精确清理及保留回归

- 12次产品正常停止均exit0；Registry正常停止exit0/noOOM/PID0。新门精确删除7个所属容器，8个helper及6个请求进程分别join/exit0，删除本轮UUID私有树；保留外层产品镜像及Registry fixture镜像供所属外层清理。紧急回收不能冒充正常通过。
- 原始私有计数保持root/0600，由既有root控制器以NOFOLLOW、owner/mode/nlink/size及读前后FD/路径一致检查受限读取；安全projection由普通用户重定向写出。不通过放宽文件权限解决交接问题。外层D10清理也通过。
- native14/profile6/新verifier27全部完整具名通过、零跳过；原前置lease20/feed34/checker13及其cleanup保持通过。Windows仅2形态项通过、12个Linux项跳过的辅助运行不计入这些Linux证明。
- 旧D12 65条关联独立重放通过，当前outcome SHA256 `9ffe231025253588ccfe523d8e83d8bc83c5c0af4ea11bc0d1fec0a206c76ce3`；旧D11 49条关联通过，SHA256 `9f8aad2319004bfbb551d9dc86ef34a02ff940868c3b6e621833b17f4e3c3201`。本轮旧D12来源两类各19次完整响应、0未完整响应，不混用957历史轮的18次。
- 子模块普通/race各700、Registry普通/race各3、浏览器40/45/45均实际保留通过。父普通/race各2320个Test*完整run/pass一致、无跳过/失败，完整名单SHA256均为 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`。
- checkout584 + child83 = 667条源码记录、584个唯一路径；before/after原字节相同，逐本轮Git原blob核对一致。9个新门harness源码摘要另行绑定；不经CRLF归一化后冒充原字节。

三轮失败及各自证据、修正范围见[失败轮记录](P0D12-INTERRUPTION-FAILURES.md)。旧失败工件未补写计数、cleanup或PASS；本轮新工件独立取得完整证明。

## 5. 仍未完成

1. update/verify × 六阶段 × 两签名的全部健康中间态恢复，以及update COMMITTED等其他真实边界；本轮是三个verify边界，不是全矩阵。
2. 审计缺失、键冲突、错误前缀、scope/checkpoint损坏等真实镜像启动拒绝矩阵。
3. 自动刷新多代追赶/缺代/同代分叉/回滚、坏签/过期/CA/SPKI失败、在途取消和撤销竞态的完整真实产品矩阵；本轮使用静态catalogue，不冒充自动刷新与崩溃组合已验。
4. 物理断电、坏盘、整盘回滚、WORM/外部见证、长期soak、正式密钥/IdP/审批、独立builder、多架构、正式发行与生产灰度。
5. 企业全功能、多内核与DNS/业务数据面、九项恢复blocker等既有缺口。

仍 `EPHEMERAL_TEST_ONLY / authorization=BLOCKED / recoveryAuthorized=false / releaseAuthorized=false / production=false / deviceActionsExecuted=false`。不承诺免维护、零bug、全系统完成或任何端到端“多个9”可用率。
