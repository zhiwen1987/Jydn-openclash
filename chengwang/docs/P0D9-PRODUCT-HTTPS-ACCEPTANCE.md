# P0-d9 完整产品候选组合与正常 HTTPS 验收

日期：2026-10-22（Asia/Shanghai）。最终代码 `875db6da9a68c03f3ea0588071925550cfb94fee` 已通过真实隔离验收及原始工件独立复核。下文保留功能候选 `bec75e806e39e8ca4a90124583454eb7932bee97` 和首轮失败记录，最终新增断言与结果单列，不混用不同运行的工具版本或证据。所有工作只在开发分支与隔离 CI，无生产访问/变更，无 main 合并。**通过的是本阶段候选，不是整个系统已上线。**

## 实际完成

- 原主服务组合抽为 Go1.23 `internal/serverruntime`，原 `cmd/server` 薄委托保留全部旧测试包/名称；不提高父 Go 版本，不 import Go1.25 SDK。监听、默认身份/配置/写门保持，停止生命周期强化。
- Go1.25.8 `image-trust-api` 增显式 `-product-config`，在同一个完整产品 `api.New` 接上真实受管后端与共享 Audit，不用 HTTP 代理、伪 backend 或第二份主服务算法。原窄 allowlist `-config` 路径继续保留。
- 固定 control-plane 与 image-trust/storeID 两种 scope 分开检查。Factory 构造恢复先于监听/worker，只借用共享 Audit，成功后的组件/Store 生命周期由 runtime 持有。此 factory 是进程内可信组合，不是不可信插件 sandbox。
- 完整候选只用私有 typed 配置，不读取/修改全局环境，不继承旧发布开关。强制 candidate/TLS，配置/身份/TLS/租户/站点绑定、AuditDir=DataDir/evidence；目录/文件权限及已有状态检查失败关闭。发布/Shadow operations 写入、Mihomo、设备执行均不启用。
- 停止 admission 后取消请求与 worker，等待所有已受理 handler/worker 后再关库。超时明确失败、保留资源，不冒充安全停止；失败进程不能复用。真实完整候选测试覆盖正常 TLS、两 scope、默认锁门、继承环境隔离、实际签名 TLS 源自动刷新、刷新取消、在途 HTTPS handler 持库至 drain。
- 页面继续只服务 D8 安全 trust bundle，不回退原宽松 FileServer 或开放主 App demo。新增正常受信任 Chrome HTTPS 门：测试根只导入私有 HOME 的现代 NSS DB，未修改宿主全局信任、未用证书错误/SPKI 例外或关闭验证。

这里的“完整产品”指**既有基础产品 API 的组合**，不是已经完成多内核、DNS、订阅、自动修复或全部企业功能。签名测试目录的 25 个定义是惰性测试材料，不是已批准生产镜像、节点或业务可用性证据。

## 已完成的功能候选验收：bec75e8

| 层级 | 原始结果 |
| --- | --- |
| 绑定/浏览器/Registry | [run 39795835989 / job 119882790897](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39795835989/job/119882790897)，success，head=bec75e8 |
| 父项目 | [run 39795835974 / job 119882790887](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39795835974/job/119882790887)，success，head=bec75e8 |
| 子模块 Go | ordinary/race 各 700 Test pair、8 包、0 fail/skip，vet 通过；原 669/627/490/379/234 及旧 cmd46/product47 各自保留。cmd128，其余 root61/policy127/product90/refresh64/registry73/catalog89/state68 |
| 子模块完整指纹 | 700 pair SHA256 `b3cd00ab4fd983026e777095b484e2a0e49b05867186a83df234b8a27b7bb999`；cmd128 names SHA256 `21a7ea8e3b507f2af78d46ead04b2d4f9ad38da835d9ffe61d6b4a7466b6242e`；新增 D9 31 pair SHA256 `ad257b3ad1676c525eff4a42c73c125b9ae95a9ad2d6688bc4da02f0a5b43313` |
| 父 Go | ordinary/race 各 2320 run/pass、同一集合；37 个测试包 pass，另唯一允许的 internal/domain 无测试包 skip，共 38 包；0 测试场景 fail/skip。旧 2311/2257/2252 分别保留 |
| 父完整指纹 | 2320 pair SHA256 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`；新增 runtime 9 场景 names SHA256 `9689d928515f0702b68256af5919a33a1ffe6a8ae4dcee391445a15f8dc97104` |
| 前端及检查器 | Vitest 原 5 文件77项、TypeScript/ESLint/Vite build、Node TLS 6项、真实 Linux pidfd guard 11项通过。15 个合成基线/浏览器报告门测试不是实际浏览器证明 |
| 父静态门 | Linux Python160/0skip，suite39+45+19+29+28；13 shell、11 schema 实际 metaschema 通过。Windows 本机门允许的9skip没有拿来替代 Linux 结果 |
| 真 Registry | 无适配 Distribution3.1.2 普通/race 各3测试、两类签名与原 managed/产品API/D7刷新恢复标记保留。144 次不可变 digest GET/HEAD200（GET48/HEAD96）；另健康 GET1。seed POST8/PUT12 不混入只读144计数 |
| 构建 | 实际 trimpath build/--help、Go1.25.8、revision=bec75e8、modified=false，CI 二进制 SHA256 `9b22d15def4444882487dabfeef83234630cccfb7d04d2c7464309654d214353`；只归档元数据，本体未上传或独立重哈希，不是签名产品镜像 |

首轮 `9be382cf56b72102a7d50b06177856ef2f8e7193` 父 [39794461907](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39794461907) 已实际通过，同样2320/D9 9。绑定 [39794461903](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39794461903) 则失败：Vitest 误收 `node:test` 的 `.test.mjs`，6项 Node TAP 成功但 Vitest 无 suite，原77项通过仍不能算整轮成功；Go/浏览器/Registry 未执行。bec 将文件改为显式 Node 入口 `check-trust-browser-tls.mjs`，保留6项且重新验证77项后重跑，不删测试或放宽只读/证书门。

### 真实浏览器 QA

路径：候选 `/trust.html` → 正常受信任 HTTPS → 显式认证 → 真实 Status/history → 搜索/展开/分页/刷新 → viewer403、错误令牌401 → 断开清除；另实际读取父 operations/capabilities。

- Browser plugin not available。沿用既有 Playwright 静态层和预装 Chrome/CDP 完整候选层；无新浏览器依赖。bec 实际 Chrome/156.0.8078.47、Node v22.23.4，不借用首轮或其他 run 的版本。
- 桌面1440×1000、移动375×812、横屏812×375；HTTP38检查/14GET（20011/4012/4031）；HTTPS43检查/16GET（20013/4012/4031）。两份 runtime/CSP/asset/forbidden errors 均0，真实 Noto中文至少7glyph，groupStopped=true。
- 非空、无遮挡、运行时/CSP/资产与真实交互检查通过；独立代理查看8张 PNG，主代理另查看 HTTPS viewer 截图，中文可读、移动无横向溢出、按钮/键盘/reduced-motion保持。桌面全页因滚动条宽1425；两套图高分别1300/6024/2899，移动375×8698。此轮没有独立的 console error/warning 计数或精确 title/URL 断言，缺口由最终875补齐，不能倒记为本轮证据。
- 真实 TLS1.3/AES_128_GCM、DER链2；叶 hash与fixture公证书一致，CA签名/IP SAN/有效期检查。正常信任来自私有 NSS 的 C,,，旧库不存在，不是 `--user-data-dir` 单独隔离，也不是 ignore-certificate-errors。
- 三个独立真实产品端点：不可信链→`ERR_CERT_AUTHORITY_INVALID`，错SAN→`ERR_CERT_COMMON_NAME_INVALID`，过期→`ERR_CERT_DATE_INVALID`。浏览器没有业务挂载/HTTP/API/Authorization；独立服务器实际 handler计数均0，不靠拦截响应或修改fetch。
- 正例与三负例各有实际 Store/Audit，25项签名测试定义、22条journal、44条audit、gen3、ledger0。停止/重开后状态不变；共享审计路径与完整父API实际200，全部临时身份、私钥、配置、NSS/profile清理门通过。
- CI-only Chrome仍显式 `--no-sandbox`，外层 non-root/cap0/NoNewPrivs/loopback-only/只读源码与依赖保留，不声称 Chrome sandbox已开启。此处是本地私有CA，不是公网/企业证书全生命周期。

### 工件与独立读回

- 原绑定附件62文件，无ready/身份/配置/私钥/NSS/profile或二进制本体。主代理独立下载目录：`C:\Users\Administrator\AppData\Local\Temp\chengwang-p0d9-ci-39795835989-a5cc882f4be349d29aa1a5e5e566277e`；另两个代理独立下载，不复用绿色图标作唯一证据。
- 545个checkout条目、74个child条目前后相同；主代理与独立代理逐条以 Git raw blob 核对到 bec，不拿当前dirty worktree或CRLF转换摘要代替。
- 模块389项=386远端+3本地，两个既有replace；386图在线/离线逐字节相同，Sigstore-go1.3.0及Go边界不变，官方两次verify均all modules verified，go.mod/go.sum未变。
- bec父原始joblog5470819B，SHA256 `63c4cc5e11929ceb771071503e7e79eb5be27db5602c3c445e7e646935e82bd1`；主代理另按真实JSON重核首轮父4640run/pass与相同2320指纹。
- bec HTTP报告 SHA256 `d4d3090b59a8f8efa11c035d0eaa2820a432183bafb98982c405812c30b1b932`，HTTPS报告 `bc3082de5dc171af8f2d0dea2d4972f92ab3187cfe0d73bdb428a7abcbe49a0d`。工具实测 libnss3/tools `2:3.98-1ubuntu0.3`，certutil SHA256 `505b13e3087e1abcabec3f1485e0e76b81322667dcae25758341b46bcfc5b62d`。
- 代理曾把附件数量手算为65，实际枚举为62且已更正；不同run的Chrome/Node/NSS版本也按各自原始工件区分，不能混用。

## 最终完整集合与浏览器证明：875db6d

5f4982b 仅修改四个检查器/自测与两份文档，没有更改 Go 或浏览器逻辑。它根据上述实际结果同时锁定旧基线和完整700/2320、新31/9集合；新增删名、同数换名、额外同前缀用例、坏指纹负例。JSON自测增至52负例，15个门测试及Python160/28保持。该轮[绑定39798364520](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39798364520)与[父39798364515](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39798364515)均实际 success。

875db6d 再补浏览器证明，不改产品 Go/React 功能：挂载等待必须同时匹配精确 title `澄网 · 可信策略控制台（候选只读）`、实际 `location.href === ready.url` 与 h1；正例 session 单独统计 console error/warning，只计数、不序列化参数。负 TLS session 保持独立；原38/43检查全部保留，各新增两项 console 零值检查。报告门拒绝字段缺失、非整数、布尔或非零，不能用合成自测替代实际浏览器。

| 最终层级 | 实际结果 |
| --- | --- |
| 精确提交与任务 | 两条run均 head=`875db6da9a68c03f3ea0588071925550cfb94fee`、completed/success：[绑定39799680041](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39799680041)、[父39799679868](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39799679868)。绑定job119896497350查询曾滞后于run，所有step成功；本报告引用run终态，不把查询延迟解释为测试失败或重新执行依据。父job119896500306已success |
| Go与旧集合 | 子ordinary/race各700、8包、D9恰31；父各2320、runtime恰9，37测试包pass+唯一允许domain无测试包skip。上文所有完整指纹及旧基线保持。0测试场景fail/skip、vet通过 |
| 其他门 | 77 Vitest、6 Node、11 pidfd guard、15检查器测试、52 JSON负例；父Linux160 Python/0skip（门28）、13 shell、11 schema实际metaschema通过 |
| 真浏览器 | HTTP40/14 GET（200×11/401×2/403×1）；HTTPS45/16 GET（200×13/401×2/403×1）。两份consoleErrors/consoleWarnings均JSON整数0；runtime/CSP/asset/forbidden均0，真实中文字体7glyph、groupStopped=true |
| HTTPS和真实产品 | TLS1.3/AES_128_GCM、真实链2、私有NSS正常信任，CA签名/IP SAN正确，无TLS bypass；三证书反证精确拒绝且HTTP/API/Bearer0。父operations/capabilities200；journal22/audit44/25项测试定义只读不变，fixture和凭据/私钥/NSS/profile清理标记各恰一次 |
| Registry与构建 | 仍144次不可变GET48+HEAD96全200，另healthGET1；ordinary/race各3真实场景。二进制实际build/help，revision=875、modified=false、Go1.25.8；元数据SHA256 `37f16ffd197eaef7430492af652a5432817d5f95727e5c0884098735954de4be`，仍未上传本体/签名镜像/部署 |
| 源与依赖 | 62原工件，546 checkout+74 child条目前后相同，主代理和独立代理逐条Git原始blob匹配875；386远端在线/离线图逐字节一致，两个既有replace和原go.sum不变 |
| 本轮工具 | 实测Chrome155.0.8059.84、Node22.23.3，libnss3/tools 2:3.98-1ubuntu0.2。不是bec轮Chrome156/Node22.23.4；测试CA每轮独立 |

主代理独立下载：`C:\Users\Administrator\AppData\Local\Temp\chengwang-p0d9-final-875-b942f0194c1f48db8a9e4507c625b404`。HTTP报告SHA256 `388562d5b9f159782361992931924025b68efea0a0aac7802d3059bd011b2db6`；HTTPS报告 `4b8ef9c28dd951b04d8ed32e4bb2bdbdcc9b2a0d020edef51da5115e32df83ec`。绑定原始joblog1760207B、SHA256 `a0bd24bbc456886a0fdcbdd0814ed2e6bac6b393d932a455414f3a0a519bd8b1`；父原始joblog5470418B、SHA256 `9256337dc86115a9ff5befb7842e791afd55bf14fc7050c4a0a3a7a4bf340495`。父日志位于 `C:\Users\Administrator\AppData\Local\Temp\chengwang-p0d9-parent-875-independent-8bcdb7a3802440d9ae393c043f8442b8\parent-job.log`。

### 最终 UI QA 与复核方式

| 检查 | 结果/证据 |
| --- | --- |
| 页面身份 | PASS；精确title、URL、h1等待约束已核对到875原始blob，且本轮真实浏览器流程完成 |
| 非空/框架overlay/遮挡 | PASS；实际有目录与记录，8张PNG由独立代理以original逐张查看，主代理另查看HTTPS断开与viewer；无视觉阻塞 |
| 控制台 | PASS；正例应用console错误0/警告0，独立负证书session不混入；不打印可能含密钥的console参数 |
| 截图/响应式 | PASS；两套各4张：1425×1300断开、1425×6024 auditor、1425×2899 viewer、375×8698 mobile；桌面1440×1000、375×812、横屏812×375实际检查 |
| 交互 | PASS；连接读取→策略分页/搜索/摘要展开→记录详情/分页/手工刷新→viewer403→无效令牌401→断开清空；按钮、键盘focus、reduced-motion实际执行 |

Browser plugin not available，沿用既有Playwright静态层及预装Chrome/CDP真实运行层，无新增浏览器依赖。实际CI运行 `run-linux-ci.sh`→隔离 `run-offline-gate.sh`→原HTTP `run-browser-gate.sh` 与 `run-browser-gate.sh --d9-https`，CDP包括 Page/Runtime/Network及真实DER `Network.getCertificate`，没有关闭证书校验。主代理再以 `check-go-json.py go-test.json go-race.json`、`--mode registry registry-ordinary.json registry-race.json` 重放原始JSON，并独立计算700集合指纹与620条Git blob摘要。上述命令是已执行的验收链说明，不是要求用户在生产执行。

平台仍有GitHub固定版本Action的Node20转Node24弃用警告，不声称整个CI零警告；它与浏览器应用consoleWarnings=0是不同指标。CI-only Chrome `--no-sandbox`、本地私有CA、测试进程及下列未完成项继续明确保留。

## 尚未完成与必须保留的边界

1. 原 `cmd/server` 的默认启动仍无trust backend；新完整候选是显式进程内组合，不是已更新现网。主App全页面/全部企业模块、SSO/IdP/MFA、组织治理仍未完成。
2. 真实浏览器 HTTPS 已填补本地正常信任缺口，但公网/企业CA、证书发放轮换/吊销、域名/LAN、IPv6、Safari/Firefox/全终端矩阵未验收。
3. E2E调用真实runProduct和原完整API，但进程是Go测试可执行文件，不是已安装release binary。实际候选二进制仅build/help；正式容器构建仍因未固定基础镜像而BLOCKED，签名产品镜像/发布/部署/生产灰度读回均未完成。
4. 新完整入口已验证实际签名TLS源更新与取消、真实在途HTTP handler持库到drain。没有新增完整入口的真正SDK/Registry HEAD中途崩溃、物理断电、任意资源耗尽/恶意插件或长期soak证明；旧D7真实SDK/断点与Registry回归不能冒充这些更广证据。
5. 自动恢复仍只补健康两库间审计，不修坏盘/坏checkpoint，不回收grant、不证明HTTP exactly-once。完整TUF、外部单调见证、WORM/副本、长期容量治理、分布式HA与全网络/真实业务能力仍未完成。
6. 所有结果 advisory、authorization=BLOCKED、deviceActionsExecuted=false，九项恢复blocker保留。没有整体完成率/生产运营结论、免维护/无bug或可用率承诺。

本阶段未访问或修改10.88.0.240/.249/.254、爱快、DNS、OpenClash、Kuma、ERP或生产Docker，未合并main。后续生产须另行明确授权、先备份、验证恢复、灰度/读回/观察。本地Temp及Actions保留期不是永久备份。

操作说明：[完整产品候选](PRODUCT-CANDIDATE-OPERATOR-NOTES.md) / [只读可信控制台](TRUST-CONSOLE-OPERATOR-NOTES.md)；范围与技术依据：[实施合同](P0D9-IMPLEMENTATION-CONTRACT.md)。
