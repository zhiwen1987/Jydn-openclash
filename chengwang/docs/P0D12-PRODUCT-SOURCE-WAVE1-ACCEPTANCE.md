# D12 真实产品来源第一批隔离验收（2026-10-23）

结论：本批 `implemented+tested isolated-only`，不是完整来源故障矩阵、企业系统完成或生产上线。主代理及三名独立子代理分别下载原ZIP/API日志，检查源码并复算。产品运行逻辑未改；本批新增实际镜像验收驱动、独立checker和隔离运行器，没有SSH、生产配置变更、main合并或正式Registry发行。

## 1. 接受代码与原始证据

接受运行代码：`563e51aa855079ad7c0ffd7d830356e3a4cde6a2`，attempt1。后续纯文档归档提交不是另一个已验运行镜像。

- [绑定39877834480 / job120167678960](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39877834480/job/120167678960)与[父39877834614 / job120167678578](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39877834614/job/120167678578)均completed/success、同一完整head，全部步骤成功。
- 工件12469383625，`image-binding-39877834480-1`：1354个原文件；ZIP6,087,348B，SHA256 `e795734960644fa3a33a672b5689644c0137a0cb997fb6e808b2a4f7107f733b`，独立下载与API digest一致。root解包前验证全部entry为有界、唯一、安全平面名称；展开总计14,845,452B。
- 绑定原job日志2,021,177B，SHA256 `b55ae494c9f86cb787fb36d1b400400e541f33dddc1fb0932ebc5f168fac837b`；父原job日志5,447,475B，SHA256 `838946145d862c1e57bac01d4fc86ff3b82a363988749c925ed4751f69b5dd9d`。均直接从jobs API保留原bytes，不以包装日志或绿标记替代。
- 本门原outcome SHA256 `b030ad6c092e3d19d65ddd267d397fde011311c350bc6e8a8a155c6c0abfbcaf`，72个本门工件及75条原输入SHA关联独立重放一致。原来源fixture前置报告SHA256 `7fbb6f7b73e496008cd1ab0c963dcaa72c9c17662ceeedc9456ae1bbf86e5b71`也重放一致；Windows stdout的CRLF与CI的LF只在JSON canonical层比较，所有原ZIP、日志、源文件和原报告摘要保持原bytes，未归一化源字节。

| 实际运行身份 | 值 |
| --- | --- |
| 静态产品二进制SHA256 | `699403e2896effedf8c17a66ed0ccf685c1bad26d239636bda3f8699bdd6a5f1` |
| Docker imageID / config digest | `sha256:6421c0b114923ac967d9317efdd598b4560e6b7075094a96f1d4f8ae3e082e27` |
| 隔离Registry manifest | `sha256:b12ffbe66e085b536a0cec072288ec7a05c193f81da4cad01ed1f1b899141844` |
| 授权边界 | `EPHEMERAL_TEST_ONLY / authorization=BLOCKED / production=false / deviceActionsExecuted=false` |

root副本：`C:/Users/Administrator/AppData/Local/Temp/chengwang-source-wave1-563e51a-root-9c7ecf5fd5444ada90a6dc13ce7343ac/artifact`。原ZIP/API日志和root重放输出位于artifact目录外，不污染1354计数。CI工件保留14天、Windows Temp可被清理，均不是永久备份、WORM或外部见证。

## 2. 六格实际结果

每格独立store/grant/目录根key/批准签名authority/产品容器/来源进程；同一真实产品镜像、默认非测试入口、正常TLS、UID/GID10001、cap0/NNP及只读根文件系统。来源没有主动TCP/TLS/HTTP readiness probe，首次产品启动前的ready、实际PID/profile和空事件日志已核对。

| 流程（各含message-signature和dsse） | 实际行为 | 每格式最终G / sequence / journal / audit / ledger |
| --- | --- | --- |
| http-recovery | 初始403不确认、不写库；原G1确认；403后自然陈旧；原G1重新确认 | `1 / 1 / 0 / 0 / 0` |
| bad-signature | G1确认；坏G2首次完整拒绝，后续重复不追加、不续Fresh；自然陈旧后有效G2恢复 | `2 / 9 / 2 / 4 / 0` |
| prefix-recovery | 实际2.json的有效G2提交；坏G3拒绝、整批不确认；重复不追加，随后有效G3恢复 | `3 / 13 / 3 / 6 / 0` |

六格共67个真实连接、67次成功TLS、67条完整HTTP响应（200×42、403×25）、268条完整connect/tls/http/close事件、18个实际prepare/run/reopen动作。此次没有未完整wire或错误正文部分写；403头完整但正文部分写的允许语义另由合成正反例覆盖，不冒充此次实际触发。

bad-signature各实际发送10次完整坏JSON；prefix各4次完整坏G3。每格首次完整ACK的来源fence后，到deduplicated fence均有3个新的完整坏200，seq、history、LastSuccess与Until不变；自然陈旧观察时间实际为Until+1秒。prefix中G2已提交、G3已拒绝时seq9/journal2、RefreshFresh=false；有效G3后seq13/journal3/audit6。来源发送本身不等于产品接受：独立核对了原候选SHA、实际API代次/hash/ACK、Fresh及离线双库。

独立checker以公开临时anchor及原envelope/payload进行OpenSSL Ed25519验签，坏目录只翻转对应有效签名一个byte、payload不变。另一独立代理另用Node crypto直接核签与源/API/审计时序，不只复用subject checker。实际10条journal、20条完整audit事件按operation ID/trace/scope/hash前缀关联，重算原JSONL及checkpoint字节摘要；不以绑定布尔、相邻二条假设或成功marker代替原事件。logical record SHA是实际Go读库投影，不声称reviewer重构了未导出的私有数据库bytes。

36个Registry计数快照分为6个实际上传/正常TLS回拉窗口、12个运行及离线重开零请求窗口；未隐藏准备流量，也未调用SDK验证消费。6次产品SIGTERM正常exit0、6个source TERM/join0、Registry正常exit0无OOM；7个distinct所属容器精确移除、最多同时创建未移除2个、无所属残留，外层镜像与原归档保留。清理成功报告在实际清理后生成。

## 3. 回归、源码及修正

新profile8项和verifier32项在Linux具名通过、0skip，均标记synthetic-only。旧source fixture24项（8格式/16真实Linux）与checker32、lease20/feed34等保持，不用合成数量代替镜像六格。普通/race各728项实际run/pass、0Test skip/fail，完整名字SHA仍 `6557b5f9621b6d691133c2242ab1c35308dfcd376424b43c6a9c2644830d0811`；原700 SHA仍 `b3cd00ab4fd983026e777095b484e2a0e49b05867186a83df234b8a27b7bb999`，既有新增28精确保留。Registry普通/race各3，父普通/race各2320，父名单SHA仍 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`。浏览器40/45/45及原中断/状态/清理门保留。

| 原门独立重放 | 输入关联 | 此次原outcome SHA256 |
| --- | --- | --- |
| Registry | 49 | `107983536ab021e88cf705d1f95da3171dd24b00949aa5c2bd43f0aa5599c766` |
| lifecycle | 65 | `0db27c813d112dbcea1b408ca6f8f5f6c3d3ea3d3fcd5ebd453824bb65d4b9be` |
| crash | 151 | `959f701e6630f44af6a508f83daf3589f6c1ea68b57d347f90bf788a1b1f4aaa` |
| state | 909 | `77cadf12f9e914b181cac871f06c4a7399ba0b3061e96dc8144ab6450d2c0827` |

checkout612条＋子模块92条＝704记录/612唯一文件，两组before-after原bytes完全一致；每条摘要逐原Git blob复算，不用当前dirty checkout或换行归一化代替。清单原SHA分别 `3e327734abe112e320c6bc731b9567bb58bff5325af3d12531590830f2d3aeaa` 与 `5e0ab5ca80e4c3af92b699859397d092aa139968208b67148c3b62aef1430a8a`。

交叉审查修正了新检查器误继承旧G2上限、旧前置工件命名空间与新门冲突、403错误正文语义、来源send后日志落盘与API先确认的观测竞态，以及提前写清理PASS的问题。保留全部原测试和安全限制。当前首个真实563运行即成功；前阶段真实启动失败仍在[原失败记录](P0D12-SOURCE-FIXTURE-FAILURES.md)，没有倒写。

## 4. 明确未完成

`wave1Only=true`；`reservedRevocationProven/sourceTLSNegativeMatrixProven/sourceRestartMatrixProven/completeSourceFaultMatrixProven/releaseAuthorized=false`。原fixture前置门中的productProven=false仍只描述该前置门，不与本批六格证明混为同一门。

- TLS CA/SAN/SPKI单因产品拒绝及同进程恢复；完整HTTP/帧/hint/gap/fork、真正跨越产品timeout的闭集hold/屏障、Fetch64与Store总history64、两种4MiB预算和取消等仍待证。
- 真实RESERVED期间有效撤销与坏签对照，需要Registry blob内核屏障；最终消费后边界不能用RESERVED证明代替。来源重启/冷确认组合、自动刷新崩溃与其他跨库异常边界、持久去重/完整DoS防护仍缺。本批最大history仅3条，不冒充大于50条分页的实际验收。
- 坏盘、断电、整盘回滚、长期soak、正式authority/企业IdP/审批/Registry发行、企业网络功能、设备执行器和生产灰度仍未闭合。九项恢复blocker不解除，不承诺任何多位数可用率、零bug或整体完成率。

只读补丁风险复核也保留人工审核边界：root编排涉及CI主机权限，隔离测试通过不赋予自动合并或生产部署权限。原CI进行中的hold快照已由真实工件消除待证项；最终结构化结果经技能schema校验为 `merge / human_review_required`，只是代码评估，不是已合并或发布。原commit-range patch214,363B、SHA256 `d456c658680c0f8b075888ddaf4e6433b542a8d121294d07e45160fe089189f4`；最终JSON以插件persistent独立存储的 `artifacts/patch-risk-563e51a.json` 保留，SHA256 `04e8ed77f8c656b3ba74fed3c74244cfac42c438c879ff220ce3e223a0bed472`，不写入被评估的代码树。协议见[第一批范围](P0D12-PRODUCT-SOURCE-WAVE1-PROTOCOL.md)，完整系统差距见[总审计](SYSTEM-COMPLETION-GAP-AUDIT.md)。
