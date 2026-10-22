# P0-d12 自动刷新重复拒绝保护验收（2026-10-23）

结论：本子门 `implemented+tested isolated-only`，不等于完整D12、企业系统闭环或生产上线。代码实际修改产品自动刷新路径；新增28项Linux测试，主代理及独立子代理下载原始工件、日志并分别重算通过。未操作SSH、生产网络/服务、main或正式发行。

## 1. 接受身份与可复核证据

接受运行代码 `ed756d74719891c2fc473b90867dbfda95f37f0c`，attempt1；后续文档提交不是另一个已验镜像。

- [绑定运行39865484513 / job120126497803](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39865484513/job/120126497803)：completed/success。
- [父运行39865484625 / job120126498445](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39865484625/job/120126498445)：completed/success，同一完整head。
- 工件12464218069，`image-binding-39865484513-1`：1275个原工件文件，ZIP5,915,789B；SHA256 `6e09ebea9eebd36ddeffe96aef4b45ae1f00ba1c29196fc7d40a5d290d3bb7d4`，多份独立下载与API digest一致。CI保留14天，不是长期备份/WORM。
- 绑定job原API日志2,005,952B，SHA256 `17733247774c5d62f6396b5861aff84c2313d6b5391faaa203bebd4a855fc66b`；父job原API日志5,447,307B，SHA256 `70260416bad93705502d5cfdcd657f468ed8bd858aa17074b9c367a36a6b1c06`。没有用`gh run view`包装文本代替原日志。

| 身份 | 实际值 |
| --- | --- |
| 产品静态二进制SHA256 | `86898b0e5b08f2dc25e03379e5729ac281201b1494646ecca17406f41ec8d79a` |
| Docker imageID / config digest | `sha256:8c730d1a8ee4282fbd60cab21d7129f784295d26fb953d3893a896d0d304de4b` |
| 隔离Registry manifest digest | `sha256:9cdf3fa462fbf562d1d65d5bb1f4d223365066e429ad610180603408762a407c` |
| 测试授权边界 | `EPHEMERAL_TEST_ONLY / authorization=BLOCKED / production=false` |

主代理副本：`C:/Users/Administrator/AppData/Local/Temp/chengwang-guard-ed756d7-root-34a5b1d21ebf4155a94402371e28c7ef/artifact`。原ZIP、API日志、root-audit-summary及四份独立replay报告在该artifact目录外，不混入1275计数。Temp不承诺永久保存。

## 2. 实际缺陷与产品改动

此前同一坏签/过期候选每次自动重试仍创建新的拒绝操作，单次使sequence+4、journal+1、audit+2；长期重复可耗尽4096操作上限。本轮按[固定协议](P0D12-REFRESH-REJECTION-GUARD.md)修复，不用one-shot来源隐藏问题。

- 每Service固定16槽，只保存当前base generation/catalogue SHA与候选原bytes SHA，进程内有界；base变化清空，重启不继承，不保存原候选或凭据。
- 首次拒绝仍执行原Update、REJECTED审计和ACK；仅完整明确拒绝且前后base未变才保留。普通管理员Update正文与前版本一致，仍逐次审计。
- 每次命中都用新的只读`Store.PreviewUpdate`读取实际数据库、anchor并执行真实签名/转换/当前时间检查；只读db.View不改变持久record/sequence/journal/ledger。可能推进原内存clock high-water，不伪称完全无内存影响。
- 命中仍不合格则返回非nil拒绝，不ConfirmRefresh、不延长LastSuccess/Until；原Fresh按实际TTL自然过期。未来NotBefore变有效、base变化或合法候选仍走原事务重新验证/安装。
- 审计、存储、时钟、取消及不确定结果不能被缓存掩盖；并发自动Apply使用TryLock拒绝排队。额外审计复查不构成跨库原子事务或所有TOCTOU消除。

## 3. 新增28项实际Linux测试

普通及`-race`各728个具名Test*实际run/pass，0 Test* skip/fail；包含原700项及新增Store8/product16/runtime4，无新子测试。新28项精确集合摘要 `6d3e29d503ce0a8de14826ae8443bfc26c87bb0e485604e7445fe52ca84546f0`；完整728摘要 `6557b5f9621b6d691133c2242ab1c35308dfcd376424b43c6a9c2644830d0811`，均按排序Package TAB Test LF编码。

- Store8：合法/非法只读、真实时间窗口重查、base变化、无效context/closed、clock regression、已消费ledger保留、分离返回值不能授权写入。
- product16：重复/不同bytes、16槽驱逐、未来生效、base/newService、并发/持锁Busy、audit/store/context失败、普通管理员审计、Fresh不续期、ledger不变、不确定审计不缓存。
- 新runtime4均为真实`runProduct`服务器/后台worker、正常TLS源与API、停止join后重开两库；是**同进程运行时集成，不是新增四个Docker/独立OS命令进程来源矩阵**：

| 精确测试名（均以TestCandidateD12Refresh开头） | 实际覆盖 |
| --- | --- |
| RepeatedSignedRejectionDoesNotRenew | 先正常确认，再持续坏签；至少3次已完成坏响应，仅一拒绝记录，LastSuccess/Until不变并自然陈旧 |
| FutureCandidateBecomesEligible | 同一未来NotBefore原bytes持续拒绝，真实等待后自动安装G2；不修改宿主时钟 |
| SourceBytesChangeRecovers | 坏A→坏B→坏A分别核对去重，再合法G2恢复 |
| SequentialCatchupAndPartialPrefixRecovers | G1→G3顺序追代；合法G4前缀提交、坏G5只拒绝一次，再合法G5恢复，不回滚/重做前缀 |

源完成计数只计实际write成功，停止中的未完成发送不算成功；prepared/committed audit绑定原candidate SHA，坏候选不被当成committed。测试使用私有临时authority；新runtime4不声称真实Sigstore消费，旧真实SDK镜像门另行保留。

## 4. 原门保留与独立重算

严格测试门仅精确分离新增28项，再将剩余700项送入原7个baseline检查；原33个大写常量及9个受保护函数AST不变，原15个Python测试正文保留。Python具名测试扩为27项、0skip；JSON negative selftest60项通过。原700固定摘要仍为 `b3cd00ab4fd983026e777095b484e2a0e49b05867186a83df234b8a27b7bb999`。Registry普通/race各3项、父普通/race各2320项实际通过，父固定摘要 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8` 不变。

本轮镜像实际重新构建/运行，原证据门由主代理与独立代理分别重放，canonical均与CI outcome逐值相同，全部关联原文件SHA复核：

| 回归门 | 关联数 | 本轮原outcome SHA256 |
| --- | --- | --- |
| D11 Registry/签名/批准/撤销/重放 | 49 | `9a2b5151dc33af0d1327f699de451f3d6db6aaaddbb9545ad8ea6183d42a34f5` |
| D12正常自动刷新/陈旧/恢复/重启 | 65 | `4d6906e12e9aa38a7d354d260e4ae09c9cbc76d0f8c6dfb541e0d61c544f0b90` |
| D12实际三阶段中断 | 151 | `c6808bbc6547ce98989259dc62a0cd9d30a6c72f115c0e6b0bbf7a54042b1f76` |
| D12预置状态启动矩阵 | 909 | `4da914c0732f8b160a02275f5ad50fcee8ce293aa81495d8b10a36970327b50c` |

原浏览器40/45/45、native14、lease20/feed34/checker13、state profile8/verifier32均保持。实际中断仍为6次SIGKILL137/12次正常停止0；预置门仍36健康/48拒绝、168启动/672快照/168零请求窗口、72正常退出0/96自然拒绝1，精确85所属容器删除、Registry正常退出0、无owned残留。没有把预置状态改称真实crash。

checkout597条与子模块source89条，共686条/597唯一文件；各before-after原bytes相同，所有声明SHA逐`git cat-file --batch`对接受head的原始blob匹配，不做CRLF归一化。不是沿用0633的676/591旧计数。

## 5. 明确未完成

- 固定16槽是同进程工作集，不是完整DoS防护：超过16种不同坏候选仍可增长journal，重启后同一坏候选会重新留审计；未做持久去重、无限容量或自动删除审计。
- 新拒绝/追代案例尚未接入真实Docker来源负矩阵。错误CA/SAN/SPKI、真实403/redirect/帧边界、gap/fork/budget/cancel及实际在途撤销竞态仍需独立来源fixture和镜像门；旧200/503 fixture日志为空不能证明TLS拒绝原因。
- 逐代Apply不是整体batch事务，合法前缀可提交；没有宣称失败回滚整批。
- 其他真实中断边界、坏盘/断电/整盘回滚、外部见证/WORM、长期soak、企业IdP/正式authority/Registry发行、灰度及生产读回均未完成。不解除九项恢复blocker，也不承诺可用率或零bug。

下一门保持完整目标：先补可独立观测的adversarial来源fixture，再在真实镜像中验来源拒绝/顺序追代/撤销时序。不得用本子门绿色替代该工作。
