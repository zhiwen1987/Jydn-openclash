# P0-d12 真实镜像预置状态启动矩阵验收（2026-10-23）

结论：本门 `implemented+tested isolated-only`。主代理和两名独立子代理分别下载工件，重算结果一致；健康36格与拒绝48格通过。它验证预置持久状态下真实产品镜像的启动恢复/拒绝，不是新增84次真实崩溃或物理断电证明，也不等于D12全部故障组合完成、生产恢复授权或上线。本轮只增加fixture、检查器及测试接线，没有修改产品运行逻辑、SSH、生产配置、main或正式发行。

## 1. 不可混淆的来源和身份

接受代码 `0633c4b6e94cc2c95071bfd195e052a3c173e5b9`，attempt1。

- [绑定运行39860200458 / job120108634673](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39860200458/job/120108634673)：completed/success。
- [父运行39860200452 / job120108635009](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39860200452/job/120108635009)：completed/success，同一完整head。
- 工件12461129314，`image-binding-39860200458-1`，1275个原工件文件；ZIP5,906,572B，SHA256 `d9c27c7b51dab1a30d2b0b3e263004b628439ca55613176ee42a7690ab6f05aa`，三份独立下载与API digest一致。保留14天，不是永久备份或WORM。
- 绑定job原API日志1,947,700B，SHA256 `be540f88b054235e9b9c50182244942e2cb6d650b55cf1d22902bedf1daa7b31`；父job原API日志5,447,257B，SHA256 `4fa489c7c0a2e705c04423e1d783927638665d51a834c57981e9405d81374d22`。未把`gh run view`包装文本当原始日志。
- 新门906个自有报告、909条输入摘要关联独立重放，与原outcome canonical相同；原outcome文件SHA256 `bb7e5371d1483c331139395228bfd92fe1aea8b17411c1a47d316737f4180511`。

| 身份 | 实际值 |
| --- | --- |
| 产品二进制SHA256 | `98878f97b2fde864e01a50d58052dcc68e6f69947563f12ce928d0a1d99ae048` |
| Docker imageID / config digest | `sha256:e76575383c4f15a40865490ac2be3c054dde24b215f008e6d0c6bacefd715867` |
| 私有隔离Registry manifest | `sha256:52b871022ff5cda3bb8a36c61042bb15ceb4ba0b4a29ab5d055bdb6b78750d53` |
| 权限边界 | `EPHEMERAL_TEST_ONLY / authorization=BLOCKED / production=false` |

主代理副本为 `C:/Users/Administrator/AppData/Local/Temp/chengwang-state-0633-root-56a59fda5eab4ae7999594819ab87795/artifact`。原ZIP、API日志及独立replay报告保存在该artifact目录外，不混入1275文件计数；Temp不是长期归档承诺。后续文档提交不是另一个已验运行镜像。

## 2. 实际覆盖与不变性

范围按[固定协议](P0D12-STATE-MATRIX-PROTOCOL.md)：`update / verify-reserved / verify-consumed`三lane，各六健康边界、八拒绝类，再乘两类签名。每格独立store、grant、签名authority及产品容器；早期两边界在三lane中的持久语义重复，36是显式覆盖格数，不是36种独有数据库形状。

- 每格同一容器两次实际启动；健康72次正常SIGTERM退出0。首次恢复为前两边界seq5/G1/无消费、后四update seq5/G2、reserved seq6/G1/RESERVED、consumed seq6/G1/CONSUMED；首五边界恢复计数1，原已ACK边界0；第二次全部0。
- 已消费样本必须经过实际正常TLS Registry读取、签名SDK及ManagedBindTracked/Complete；本轮24次真实seed消费的公开getter、原Go字段顺序evidenceSHA和OCI图公式均独立重算。没有用直接Complete/合成hash冒充SDK消费，seed流量不计作恢复流量。
- 拒绝48格两次自然启动退出1，共96次；无OOM、PID0，不接受timeout、runner kill、137或143替代。原journal/ledger/目录及完整logical record SHA不变，审计JSONL/checkpoint原字节不变，坏checkpoint未重建，消费未回收。
- `later-invalid-acked`每格先有合法待补intent、后有已ACK语义冲突项；拒绝前后两项及审计不变，覆盖先全量校验、不得提前修第一项的性质。
- 健康首次恢复允许必要的Bind/Finish/ACK；二次启动的logical record SHA、领域事实、原SDK evidence、journal及审计/checkpoint不变。record摘要来自Git绑定driver只读真实bbolt记录，不导出原record、token hash或原始catalogue history；已有安全HTTP History DTO仍用于核对。审阅端未下载私有数据库。
- Registry有672份有序累计计数快照；168个首次/第二次启动窗口均零请求，无窗口间隐藏增量。准备上传/读回及24次seed SDK分别按精确descriptor预算核对。
- 拒绝启动保留96份独立自然退出报告、288次实际正常TLS配置探测，本轮均为CONNECTION_REFUSED，并核最终namespace无API LISTEN。快退样本明确`pid1SampleCaptured=false`；不冒充捕获了/proc PID1。有限探测不证明捕获所有瞬时监听，另核同源入口TrustFactory/product.New在Listen之前的源码顺序。

## 3. 隔离、清理和既有回归

保留默认产品入口、真实健康PID1二进制摘要、UID/GID10001、cap0、NNP、只读根、精确三bind、CPU1/256MiB/PIDs128/nofile1024；不放宽旧正常退出0或crash137。新退出1 profile仅作用于闭集state故障路径。Registry独立normal TLS/network-none，产品共享其隔离netns，无host端口或外网路由。

逐格精确删除84个不同产品容器，最后Registry正常SIGTERM退出0并删除，总85个不同所属ID；最多同时2个所属容器，0后台helper，无owned残留，UUID私有树已清理，外层镜像和archive保留至外层门清理。本轮没有租约helper或业务写probe，不替代旧重放API/crash门。

- 新profile8、新verifier32：实际Linux完整具名PASS、0skip；开发期发现synthetic复用旧containerID，修正样本后严格84独立断言保留，没有放宽检查器。
- 原700普通/700 race、Registry普通3/race3及父普通/race各2320 Test*保持；父两轮名单SHA均为 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`，0 Test fail/skip。无测试package的package-level skip不冒充Test skip。
- 浏览器40/45/45项保持，无mock response、TLS绕过或console error；lease20/feed34/preflight checker13及真实foreign-namespace blob/native14保持零skip。
- 旧D11 49关联outcome SHA `8ad0c50270951f4f24d8c086342b0960824f5202dad5c7ac5546ee9f2a9a21b3`；旧D12 65关联 `ecd05c3769e89854b1b62c786cab4b5f6b22d7733131df6fe8b5115d760dec44`；旧crash151关联 `688ca04db81b39eefb8412f194656709647c30ac8630c10b740a2d0002191a6e`，均独立canonical重放通过。原[实际中断门](P0D12-INTERRUPTION-ACCEPTANCE.md)没有删除或改称本门证明。
- checkout591、child85，共676条记录/591唯一路径；before/after原字节一致，逐当前Git原blob核对，没有CRLF归一化或忽略副本差异。新7文件harness不是全部合成测试import的穷尽清单；完整checkout绑定同时保留。

## 4. 未完成与下一门

`actualCrashProvenByThisGate=false / completeCrashMatrixProven=false / physicalPowerLossProven=false / diskFailureRecoveryProven=false / recoveryAuthorized=false / releaseAuthorized=false`。

尚未闭合：自动刷新实际崩溃/在途撤销竞态、来源负矩阵与追代组合、update等全部真实在途中断边界、坏盘/全盘回滚/物理断电、外部见证/WORM、长期soak、正式企业authority/IdP/Registry发行、生产灰度及原[企业功能缺口](SYSTEM-COMPLETION-GAP-AUDIT.md)。下一门优先补实际镜像来源拒绝/追代与撤销时序，再谈生产授权；不以本轮测试解除九项恢复blocker或承诺整体完成率/可用率。
