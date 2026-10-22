# D12 真实中断子门实施协议（开发中，未验收）

本文件冻结下一子门的接线，不是验收证明。保持生产/main/正式发行不变，所有 authority 为 EPHEMERAL_TEST_ONLY，authorization=BLOCKED、production=false、deviceActionsExecuted=false。旧 D10/D11/D12 自动刷新门不得缩减。

## 矩阵与证明

两签名 message-signature / dsse × 独立 fresh store 三阶段 prepared / reserved / consumed。目录固定 `/tmp/chengwang-product-lifecycle-<uuid32>/<stage>/<kind>`；复用同一真实产品镜像和正常 TLS Distribution，但每格独立容器、store、批准。无产品 fault HTTP/env/config 开关；外部信号仅用于本轮准确 PID/container。

| 阶段 | 真实外部屏障 | SIGKILL后、产品启动前的状态 | 首次构造恢复 |
| --- | --- | --- | --- |
| prepared | 实际 events.jsonl 的 read lease，prepared audit 写打开阻塞 | seq2 / ledger0 / audit0 / journal PREPARED，outcome与preparedHash空、ACK=false | seq5 / ledger0 / audit2 / INTERRUPTED / ACK |
| reserved | 实际 Distribution config blob data 的 write lease，Registry读打开阻塞 | seq4 / ledger RESERVED1 / audit1 / journal RESERVED，outcome空、preparedHash已绑定、ACK=false | seq6 / RESERVED1 / audit2 / VERIFICATION_RESERVED_NOT_COMPLETED / ACK |
| consumed | 先卡Registry，确认RESERVED，再安装audit read lease，放Registry，卡result audit写打开 | seq5 / ledger CONSUMED1 / audit1 / journal CONSUMED，outcome VERIFICATION_CONSUMED、evidenceSHA已存、ACK=false | seq6 / 原CONSUMED及evidenceSHA不变 / audit2 / ACK |

prepared恢复的audit result为interrupted；reserved为rejected；consumed为verification_consumed。消费事实不是HTTP成功或投递回执。初始freshstore统一seq1/G1/audit0/journal0。恢复禁止重做领域动作/SDK；第二次同容器真实启动必须seq/journal/ledger/完整audit原字节不变、RecoveryCompleted=0、无Registry增量。最后单独探测原请求：prepared可首次成功消费，reserved/consumed必须拒绝重放；每格最终seq10/journal2/audit4，前者与consumed为CONSUMED1，reserved仍RESERVED1。

read lease、write lease都指Linux F_SETLEASE，非flock/F_SETLK。breaking期间F_GETLEASE可能显示兼容目标类型，不据此假装租约已解除。SIGIO不提供可信breaker PID。来源：[Linux leases](https://man7.org/linux/man-pages/man2/F_GETLEASE.2const.html)、[/proc/locks](https://man7.org/linux/man-pages/man5/proc_locks.5.html)、[Distribution filesystem Reader](https://raw.githubusercontent.com/distribution/distribution/v3.1.2/registry/storage/driver/filesystem/driver.go)。

必须核对真实目标dev/inode、holder→waiter内核租约关系、产品/Registry PID/startTime/TGID及其线程阻塞open syscall。只读Status，阻塞期间不调History（其审计锁可能一起等待）。BLOCKED标记不可单独作PASS。所有观测必须先于租约/HTTP期限；产品现有Registry响应头上限10秒不放宽，Registry break→kill或安装audit后release须有单独短截止时间。

Registry保留既有network-none/只读根/cap0/UID10001/私有tmpfs安全profile。root只在helper独立mount namespace中把精确blob文件只读bind到UUID alias，再降权；helper仅O_RDONLY且不改blob。新helper须先有真实Linux syscall测试，包括只读alias、活跃reader拒绝、写租约读阻塞/解除、失败/终止清理。

SIGKILL必须由精确身份检查后对本轮container执行，检查实际exit137/noOOM/PID0；不能放宽正常停止exit0。客户端只发一次原POST，kill前pending，kill后无HTTP200/receipt；禁止重试业务写。SIGKILL后解除屏障，再用实际truststate/evidence Open做离线cut快照，禁止构造product.Service提前修复。该检查不得改领域序列或审计原字节。

释放Registry屏障后排空旧请求（网络活动、目标FD和完成计数共同观察），再建立恢复前基线；不能把尚未完成的请求误报为零访问，或把旧请求尾部记成恢复重读。分别围住首次恢复、第二次启动、最终probe，归档固定schema安全计数；不发布原URL/query/upload UUID/密钥/配置内容。

## 文件/接口协作约定

- 新文件前缀 `product-crash-`，不覆盖此前任何cleanup、outcome或测试日志。
- Go driver `product_crash_d12_linux_test.go`，tags `linux && productregistry && productcrash`，唯一入口 `TestProductCrashD12Fixture`。环境 `CHENGWANG_CRASH_ROOT/KIND/STAGE/COMMIT/IMAGE_ID/ARCHIVE/ACTION`；stage固定三值。JSON schema `chengwang.product-crash-action/v1`。所有POST有O_EXCL意图、不重试；所有safe投影含边界字段。
- 每格动作 `prepare, ready, send, blocked, cut, recovered, reopen-first, idempotent, probe, reopen-final`；consumed格额外 `reserved` 动作。send后台执行直到产品终止；blocked/reserved仅只读Status。cut与reopen使用真实两库但不构造Service；recovered/idempotent用真实API Status+History。精确报告字段由driver/checker两owner对齐并书面通知root，未对齐不能接CI。
- shell `run-product-crash-gate.sh`：独立UUID/Registry/6产品容器；真实inspect/PID1、helper/屏障/信号/流量和清理报告分离；同容器三次启动。所有后台进程需精确回收，正常helperexit0，故障产品137单列；外层总期限独立有界。
- checker `check_product_crash.py` 与 `test_check_product_crash.py`：从原始事件重算prepared/result哈希链、scope/actor/request/ACK；比较cut→恢复→二次启动→probe的领域事实，拒绝纯布尔证明。核同镜像graph、PID/inspect、真实wait关系、客户端无成功及计数/精确清理。固定证据集合及输入摘要关联；safe projection重放不称私有graph下载证明。
- root维护严格外部blob helper及其Linux测试、公共image profile闭集扩展、CI接线与最终合入/验收；各owner只改指定新文件，不提交/推送。source bytes以当前Git原blob绑定，root是唯一集成者。

此子门仍不覆盖其他六阶段边界、update COMMITTED、坏日志/坏盘/物理掉电、正式恢复授权或长期生产soak。完成标准必须由真实Linux/镜像证据证明，不能以本协议或单元测试替代。
