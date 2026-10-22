# P0-d11 真实产品镜像的隔离 Registry 与受管验签合同

日期：2026-10-23。状态：实施中，**本文不是已验收、已发布或上线的证明**。承接 [D10真实镜像验收](P0D10-IMAGE-RUNTIME-ACCEPTANCE.md)，继续不动生产、不合并main、不向正式Registry发布。

## 必须补上的实际缺口

D10已执行真实产品镜像，但原Registry回归仍使用惰性测试制品。D11必须让同一次构建的真实config/layer字节进入一次性、无外网的Distribution，绑定精确manifest、正常TLS固定来源和真实Sigstore/批准，并由镜像内默认程序执行产品API消费/防重放。不能把旧测试成功或本地imageID直接当成产品镜像来源证明。

## 身份与字节链

1. 复用当次D10构建的imageID和私有Docker save archive，不重建另一份程序。保持实际静态程序SHA、Git revision、8个打包文件和原层diff_id链。
2. 从实际archive受限读取原config与所有层，拒绝超预算、歧义清单、重复/逃逸路径、特殊文件或摘要不匹配。必要时有界解压真实层，构建明确OCI单平台manifest；这是新OCI封装，不冒充Docker daemon原本的Registry manifest。
3. `sha256(raw config)`必须等于本轮本地Docker config imageID；层字节/diff_id必须与实际archive及D10打包报告一致。`sha256(raw OCI manifest)`才是本次隔离Registry reference的manifest digest，两类digest不得互换。
4. 准备器上传后以正常TLS实际回拉manifest/config/所有层，核对与上传原字节相同，独立检查器再重哈希这批私有回拉字节并产生安全摘要证据。准备回拉和后续产品API的消费读回分开计数。原binary、config、layer、Docker archive、签名材料和凭据不作为公开工件上传；主代理独立下载的是安全工件，不冒充另一次远端原字节下载；清理后也不能声称再次读取已删除的原字节。

## 独立运行与权限

- Distribution保持既有固定linux/amd64摘要，实际运行原服务，不加改变产品响应的adapter。它只存在于一次性Docker `none` 网络命名空间，没有host端口或外部默认路由；仅测试准备器可上传。
- 两类签名各有独立Store/Audit与完整产品配置；真实产品镜像共享隔离Registry的网络命名空间，仅使用loopback服务。固定Registry域名/IP/正常CA和叶SPKI，不DNS漂移、不继承环境代理、不关闭TLS。
- 产品仍为默认数字UID/GID10001、只读根、cap=0、NNP、无宿主socket/程序替换，精确私有只读配置与两个RW状态目录，资源限额和停止超时沿用D10。实际PID1、argv和exe摘要必须读回。
- 仅本轮私有image-trust写门开启，以便实际验证/更新；完整产品的发布、Shadow operation和设备执行写门保持关闭。API静态身份需分角色与scope，测试身份不是企业IdP。
- 原D10检查器CLI默认边界不变。独立D11检查器仅显式启用固定UUID `product-registry` namespace并复用全部安全规则，不接受任意路径前缀或通过改写路径绕门。

## 真实密码学、批准与持久生命周期

两类分别执行message-signature与DSSE；使用真实测试PKI、SCT/Rekor证明、精确签名identity/root及独立Ed25519批准/目录签名。测试authority仅存在于隔离验收，**不是正式发布批准者、独立builder attestation或SLSA证明**。不保存签名私钥，预签后续撤销目录即可。

每类签名使用独立的accepted/cross/revoked/spki策略与grant，先准备已有健康Store/Audit，不预先消费实际镜像grant。必须覆盖：

| 时点 | 必须实际观察 |
| --- | --- |
| 首次运行 | 镜像内HTTPS API对真实产品manifest成功绑定，结果仍advisory/BLOCKED，耐久CONSUMED与真实审计ACK存在 |
| 首次拒绝 | 同grant重放、批准签名篡改、同PKI另一真实artifact的交叉bundle均拒绝；后者不能退化为随便填入无效JSON |
| 首次停止后 | 正常退出0，独立重开Store/Audit，核对精确catalog/journal/ledger/hash；失败尝试已RESERVED的grant不能回收 |
| 同容器重启 | 同imageID/同状态再次读取，并在撤销前首先确认已CONSUMED的grant仍拒绝重放，不能只靠后续撤销制造拒绝 |
| 撤销与回滚 | 实际admin API安装有效阈值签名gen2，移除并撤销未使用批准；gen1回滚拒绝，unused grant不能被消费 |
| 来源反证 | 有效签名和批准下，仅Registry SPKI不符时拒绝；不能用签名篡改代替来源固定的检查 |
| 最终停止后 | 再次正常退出与独立重开，代际不倒退，成功消费保留、失败预留保留，审计/journal完整，无额外设备动作 |

产品每进程4次验证/分钟的既有预算不放宽。用明确的首次4次/重启后4次流程，不通过重复重启、等待重试或重置全局预算掩盖失败。预期HTTP状态和安全错误码必须精确；busy/unavailable不是成功拒绝证据。

独立Registry日志只输出固定方法/digest/状态的有界安全计数；区分准备上传和产品不可变读取，不能把seed请求算成产品readback。对于签名/重放/撤销等前置拒绝，核对相应观察区间没有新增Registry HTTP请求。TLS握手拒绝无HTTP日志，不等于独立记录每次握手事件。

## 验收与证据规则

- 原700/2320普通/race、旧真实Registry、D10真实镜像/浏览器/5次优雅停止与4类负启动全部保留。新增带tag fixture独立计数，不能静默缩窄旧测试或以零场景PASS代替真实执行。
- 独立工件门关联原始graph校验、安全API案例投影、实际PID1/运行退出、停后重开状态、Registry访问统计和最终清理，拒绝缺字段、bool伪装int、摘要/源码/镜像不一致、缺案例或危险权限。
- D10报告的local-only/未Registry验证字段保留其阶段含义；D11另出报告，明确“隔离测试Registry种子已上传”和“正式发布未发生”不是同一指标。
- 只清理本轮UUID/标签/精确ID的两个产品容器、Registry及私密材料；外层D10镜像仍归原创建者清理。没有全局prune，不删除或触碰任何生产对象。
- 编译/测试在隔离Linux CI进行。Windows辅助Python结果不能替代Linux原始执行；CI失败保留原原因，修复后重新执行，不删除检查换绿。

## 本阶段仍不代表什么

没有正式Registry发布、独立可信发放/审批/密钥托管、外部builder/source证明、SBOM/漏洞治理、Registry pull后安装灰度、长期soak、物理掉电或坏盘自修证明。自动刷新故障矩阵、整个企业产品UI/网络功能和生产闭环仍需逐项完成。

所有成功均 `authorization=BLOCKED`、`deviceActionsExecuted=false`，九项恢复blocker和原Dockerfile/M2b门不解除。本轮不操作10.88.0.240/.249/.254、爱快、DNS、OpenClash、Kuma、ERP或生产Docker；不提供全项目完成率、免维护、无bug或任何高可用率承诺。
