# P0-d11 真实产品镜像的隔离 Registry 与受管验签合同

日期：2026-10-23。状态：实施中，**本文不是已验收、已发布或上线的证明**。承接 [D10真实镜像验收](P0D10-IMAGE-RUNTIME-ACCEPTANCE.md)，继续不动生产、不合并main、不向正式Registry发布。

## 首轮实际执行记录：未通过

代码 `c6eae18d2f11596373a53e3cd25f1a2c5cd455ca` 的[父回归39817438430](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39817438430)成功，但[绑定39817438467/job119959512324](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39817438467/job/119959512324)失败。主代理与独立代理实际重放确认：父普通/race各2320、子各700、原真实Registry各3保持；新Linux合成门33通过/0skip。D10本轮浏览器及生命周期子检查完成，不代表整轮成功。

D11仅到Registry正常TLS ready、隔离网络读回。`registry-start` 内联Python第10行的容器环境变量有序列表等式失败；原私有inspect按设计未上传，**不能断言只是排序或编造实际Env值**。随后Registry仍在运行而进入紧急清理，D11清理门保持FAIL；外层D10精确清理PASS。D11 prepare、实际API消费/撤销/重启与最终工件门均未执行，不存在49份实际关联证明。

原[工件12441899750](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39817438467/artifacts/12441899750)实际101文件，其中失败诊断明确phase=registry-start、safeStages为空，isolation投影0B不能作为证明。原joblog LF1,773,127B，SHA256 `16d4f3758052f0ccdd7040680e4e70661aae9277a20a5785ef14e3f474fb7622`；父LF5,447,750B，SHA256 `62a033bc6590ff583b45375421b9ff10df964e11d2838ccfd11904b10fa3b096`。父2320完整指纹保持D9/D10的 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`。原始637条源码摘要逐Git blob独立复核，不从本机dirty文件推导。

修复应只把不涉及语义的顺序约束改为**严格唯一环境键值映射**：完整保留固定镜像原值，仅3个明确OTEL键覆盖为none；拒绝重复键、额外键、缺键或任意值变化，不允许任意Env。必须重新执行真实全链，不能拿本轮33项合成测试或父回归替代。

## 第二轮实际执行记录：准备阶段未通过

环境映射修补代码 `65a66b7899d15a86f4ea00d99e706f49851d0114` 的[父39819925451/job119968194598](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39819925451/job/119968194598)已成功；主代理和独立代理对原始普通/race各2320及完整指纹复核一致，父日志LF5,447,546B、SHA256 `b1319149193801c5e866cc94fd1117274dbb92a96d2d4141d9fd8501ca2ad333`。这不能覆盖[绑定39819925371/job119968193542](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39819925371/job/119968193542)的失败。

绑定实际通过原离线回归和旧Registry步骤、新Linux检查器33/33/0skip及D10浏览器45；D11越过严格环境映射、正常TLS、隔离/网络安全投影，但在 `prepare-message-signature-0`、首个 `archive-validated` marker之前失败。安全诊断 `fixtureSourceLine=196` 只是 `t.Helper` 折叠后的 `d11Prepare` 上层入口，**不是具体失败断言或根因**。未形成prepare/graph/实际消费/重启撤销证明，D11紧急清理仍FAIL，外层D10精确清理PASS。

原[工件12444147629](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39819925371/artifacts/12444147629)实际101文件；绑定原joblog LF1,772,694B、SHA256 `84b64a74d2c3e61559a05c48439950d1718f0c430bd1f19c009e0d97e8769982`。本轮不能从已删除的私有归档编造失败细节。下一修补仅增加失败断言的直接源码行与严格枚举JSON分类，不暴露原始错误、私有路径、字段内容或签名材料，不改验收阈值；确认具体原因后才修复。

## 第三轮诊断执行记录：已定位，但仍未通过

仅增强安全诊断的 `1c62d8bea45762eab374042fa51bc14585a2b005`，[父39821171661/job119972526638](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39821171661/job/119972526638)成功；[绑定39821171673/job119972527234](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39821171673/job/119972527234)仍失败。[工件12444497792](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39821171673/artifacts/12444497792)的安全诊断明确 `fixtureAssertionLine=200 / fixtureAssertionContextLine=269 / fixtureJSONRejection=UNKNOWN_FIELD`；精确提交第269行为把Docker-save外围 `manifest.json` 解码到仅含Config/RepoTags/Layers的结构。证实该外围格式存在未建模字段，**未归档具体字段名，不能声称实际读取到了LayerSources**。没有archive-validated或D11业务证明；紧急清理仍不算优雅验收。

绑定原joblog LF1,772,352B、SHA256 `be25556d45ba0a9bd777e480b7900af440667e41bc8e07493226a307078ff698`；父LF5,447,271B、SHA256 `417c93daabd63e87e65e0d8c06df4cc760370ce5c5fd726fd1c9d669e658dfd4`，普通/race各2320完整指纹不变。

修补依据为[Moby v28.0.4外围manifestItem定义](https://github.com/moby/moby/blob/v28.0.4/image/tarexport/tarexport.go)：另含可选Parent/LayerSources，后者的[实际导出代码](https://github.com/moby/moby/blob/v28.0.4/image/tarexport/save.go)可为普通层提供descriptor，并非仅外来层。[Descriptor定义](https://github.com/moby/moby/blob/v28.0.4/vendor/github.com/docker/distribution/blobs.go)也须明确建模。只允许本scratch候选的空Parent；可选LayerSources若出现，必须和真实config diffID/层摘要与长度严格交叉核对，不能从辅助URL取网或赋予信任，未知字段仍拒绝。真正Registry OCI manifest、签名、批准和运行权限均不改变；须新增正反测试并重新跑全链，本文不预告成功。

新增独立 `TestProductRegistryD11DockerSaveMetadata` 的17项合成正反例，以具名PASS和唯一固定marker同时防止空跑；包括双层正确顺序、交换层顺序和缺一条source映射，不并入或缩减原700/Registry3/Python33集合。合成数据不是真实镜像或远端读回。正式执行结果须以修补后的Linux任务及后续全链原始工件为准。

## 第四轮实际执行记录：真实归档通过，清单回读未通过

`433fddab4e75332de558a80c8d02d2c313085c94` 的[父39822733678/job119977955684](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39822733678/job/119977955684)成功，普通/race各2320完整集合不变；父原日志LF5,447,552B、SHA256 `07e76ea5e86d1125e08b7b44c188363b2a0b42fa8c1838fa028803e89ca46270`。[绑定39822733653/job119977955081](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39822733653/job/119977955081)仍失败，但17项元数据具名用例及唯一marker已实际通过，`archive-validated` 证明真实归档/层校验也已越过。

[工件12445906034](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39822733653/artifacts/12445906034)实际102文件；原joblog LF1,776,277B、SHA256 `ab422a7ddcb9f156f5d9e20de547d45879be60e7bc2ccef6c1e6a5292607361d`。诊断 `fixtureAssertionLine=431 / fixtureAssertionContextLine=453` 对应精确提交中的prepare上传后manifest GET联合断言：status200、Docker-Content-Digest相等及原字节相等。前面的blob/manifest PUT201已越过，但本轮并未公开该GET具体状态/头/正文，因此**不能声称已经观测HTTP404**。未到签名/Store/业务API验收。

源码确认该准备器GET未发OCI `Accept`，而[Distribution v3.1.2官方实现](https://github.com/distribution/distribution/blob/v3.1.2/registry/handlers/manifests.go)会在OCI清单未被Accept声明支持时拒绝；这是有源码依据的修补，不代替原始响应证据。仅给固定测试Registry的manifest GET/HEAD补明确OCI Accept，blob/API不继承，并增独立4项无真实取网的请求头合成测试。原HTTP状态/摘要/原字节断言和正常TLS不删除；失败诊断只允许固定状态整数和相等布尔，不暴露响应正文或头值。必须重新完成后续真实回拉与API链后才能验收。

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
