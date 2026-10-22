# D12 预置状态启动恢复/拒绝矩阵协议（有限隔离门已验收）

0633c4b 的实际84格镜像证据及剩余范围见[验收记录](P0D12-STATE-MATRIX-ACCEPTANCE.md)。本协议仍不代表完整D12或生产权限。

本门补齐真实产品镜像 constructor 的预置状态矩阵，不能代替89dfade的实际在途SIGKILL证明。先不动生产、不SSH、不合main/正式发行；原D10/D11/D12自动刷新与三阶段crash门不删减。root唯一集成/提交/推送，各owner只改指定文件。

## 固定范围

- 正常36格：lanes `update / verify-reserved / verify-consumed` × 下表六boundary × `message-signature / dsse`。每格独立store/grant/authority/container，同一产品镜像与正常TLS Registry。早期两boundary三lane持久语义相同，36是显式覆盖行数，不是36种不同DB形状。
- 拒绝48格：三lane × 八fault × 两签名。fault为 `acked-audit-missing / prepared-audit-missing / wrong-prefix / prepared-key-conflict / result-key-conflict / wrong-scope / bad-checkpoint / later-invalid-acked`。每格独立，故全门84case；不把最低14格说成覆盖全部lane。
- 目录闭集 `/tmp/chengwang-product-lifecycle-<uuid32>/state/<lane>/<scenario>/<kind>`；scenario为本协议6boundary或8fault，不接受任意路径。新产物前缀 `product-state-`，旧产物不覆盖。
- 同时最多一个Registry及一个产品容器；每格顺序两次实际启动后删除所属产品，最后Registry正常停止/删除。健康72次正常停止0；拒绝96次自然启动退出1，非超时、非OOM、非137、非runner kill。成功精确删除85容器；无后台feed/lease helper。

| boundary | update seq | reserved seq | consumed seq | audit事件数 | preparedHash | ACK |
| --- | --- | --- | --- | --- | --- | --- |
| after-journal-prepare | 2 | 2 | 2 | 0 | 空 | false |
| after-prepared-audit | 2 | 2 | 2 | 1 | 空 | false |
| before-result-audit | 4 | 4 | 5 | 1 | 已绑定 | false |
| after-journal-outcome | 4 | 5 | 5 | 1 | 已绑定 | false |
| after-result-audit | 4 | 5 | 5 | 2 | 已绑定 | false |
| after-journal-ack | 5 | 6 | 6 | 2 | 已绑定 | true |

基线freshseq1/G1/ledger0。第二个boundary在真实service hook中位于Bind之前，仍seq2。UpdateTracked和Complete已原子存outcome，因此这两lane的before-result与after-outcome可能持久等价，不能伪造额外写。

首次恢复：前两boundary统一seq5/G1/ledger0/PREPARED/INTERRUPTED；后四update为seq5/G2/COMMITTED、reserved为seq6/G1/RESERVED1、consumed为seq6/G1/CONSUMED1且原真实evidenceSHA不变。前五boundaryRecoveryCompleted=1，已ACKboundary为0；第二次启动全部为0，domain/journal/audit/checkpoint原内容不变，均无Registry增量。健康末态均journal1/audit2。

## 预置与负类隔离

driver只通过真实签名材料、truststate/evidence公共事务构造样本，不构造product.Service/不调用product.New，不使用D7 faulthelper、不暴露产品fault HTTP/env/config。

更新使用真实签名cat2与UpdateTracked。reserved使用真实批准BeginTracked。consumed必须完整调用ManagedBindTracked，对正常TLS Registry实际读镜像并执行签名SDK及Complete；禁止直接Complete合成hash。报告真实ManagedResult的公开getter及其原managed evidence投影，并从Go原字段顺序重新核evidenceSHA；预置流量单列，不能记入恢复零窗口。

负类保持bbolt结构有效，目标是产品启动绑定校验；不手工编辑bbolt。除bad-checkpoint外，审计本身须是健康hashchain/checkpoint。

- acked-audit-missing：完整已ACK领域事实配新的健康空audit；缺失真实绑定可重算，领域与消费不得回滚。
- prepared-audit-missing：已绑定prepared hash及领域事实配健康空audit，未ACK；不得重新合成缺失prepared绕过已绑定hash。
- wrong-prefix：先有真实非零audit base，PrepareOperation故意记录一个不同的合法形状base hash；实际prepared/result hash仍精确绑定当前健康audit，其余字段正确，证明前缀矛盾而非泛错误。
- prepared-key-conflict：同opID/key的prepared event仅actor改为固定foreign actor；Bind记录该事件实际hash、领域事实正常，避免额外hash缺失掩盖语义检查。
- result-key-conflict：prepared正确；sealed领域事实后的同result key仅actor改为foreign actor，记录真实事件但不ACK；证明同key异语义被拒。
- wrong-scope：store/journal/audit均正确，运行trust/product配置的site一致改为固定other-site，与原operation scope不符；配置变化在seed前完成且两次失败启动间不再改。
- bad-checkpoint：非空真实audit配固定无效`{}\n` checkpoint，必须保留该损坏原字节，不把重建checkpoint当通过。
- later-invalid-acked：先插入合法未ACK intent（无prepared hash/audit），后插入有正常领域事实但prepared actor冲突、实际hash及ACK均已绑定的第二项。第一项必须位于journal前面；启动拒绝前后两项和audit不变，证明先全量validate而非先修第一项再发现后项。

## 接线与证据约定

- Go新driver `product_state_d12_linux_test.go`，tags `linux && productregistry && productstate`，入口 `TestProductStateD12Fixture`。env `CHENGWANG_STATE_ROOT/LANE/SCENARIO/KIND/COMMIT/IMAGE_ID/ARCHIVE/ACTION`。固定actor `d12-state-admin`、canonical scope为d12-tenant/d12-site/image-trust/storeID/candidate；managementObject=`d12-state-management`。
- actions：每格 `prepare, seed, reopen-first, reopen-second`；健康另 `first-read, second-read`。prepare初始真实材料/空库；seed显式事务/注入完成并关闭全部库；read仅正常TLS实际产品Status+History；reopen真实两库逻辑读回/权威audit原字节，无product.New。负bad-checkpoint不可为采样而修复audit。
- 报告schema `chengwang.product-state-action/v1`，共有sourceCommit/localImageID/kind/lane/scenario/caseKind、boundary=`ADVISORY_PRODUCT_STATE_FIXTURE`、authority=`EPHEMERAL_TEST_ONLY`、authorization=BLOCKED/production=false/deviceActionsExecuted=false。material、完整inspection/journal、实际audit events/bindings、auditLog/checkpoint bytes+SHA、canonical/configured scope及可选真实SDK投影由driver/checker owner对齐后冻结，不能纯布尔证明。
- 独立checker逐实际事件重算Go序列化/hashchain/checkpoint、actor/scope/request/原批准/目录/消费绑定、seed→恢复→二启序列及精确负类差异。offline 的 `trustRecordSHA256` 为只读实际 bbolt logical record 原 bytes 的裸64位SHA256，不导出record内容、token hash或原始catalogue history；负seed→两reopen以及健康首次恢复→第二次启动严格相同，健康seed→首次合法修复允许变化。不要求RW重开后的整个bbolt文件物理bytes恒定。坏checkpoint的权威原bytes则必须恒定。`caseKind` 严格为 `healthy / rejected`。
- 每格Registry窗口固定 `prepare / seed / first / second` 各before/after，共672个快照。prepare上传/读回预算独立，seed仅consumed领域已执行的场景允许真实SDK预算；168个first/second窗口全部零请求，所有窗口间隔不得隐藏请求。负类不运行业务写probe，避免污染恢复零窗口；原D11/crash重放拒绝API门保持。
- 健康每次运行必须真实默认PID1/executable+inspect安全profile、正常TLS读回、正常停止0、离线严格快照；负格两次真实自然退出1/无OOM/PID0、固定安全CLI错误enum、启动/终止时间、同container身份、输入逻辑状态与audit/checkpoint不变。负格快退可能无/proc PID1样本，不冒充已捕获；用实际imageID/defaultentrypoint/封装二进制身份和自然退出/log关联，和健康直接PID1样本区分。
- 负格保留实际有界正常TCP/TLS/API探测次数、固定transport分类/HTTP哨兵、时间范围及最终namespace无API LISTEN。有限探测不称绝对捕获所有瞬时监听；结合被验同源binary的constructor早于Listen源码关系。错误TLS身份不能当服务未就绪的通过依据。
- 原UID/GID10001/cap0/NNP/只读根/精确三挂载/CPU1/256MiB/PIDs128等不放宽；新profile只对本门闭集fault路径允许startup exit1，旧0/137规则和CLI不扩权。
- 精确清理按ID/UUID label逐格记录删除，最后无owned残留、Registry自然停止0；失败紧急清理单列，不能当健康通过。新harness源码/全部证据原bytes摘要绑定当前Git，安全导出不得包含token/私钥/原配置或私有graph。

本门仍不证明真实物理断电/坏盘、全盘回滚、自动刷新崩溃组合、正式恢复权限、生产发布或企业全功能。源码/fixture前置或合成checker通过，不等于84格实际镜像验收。
