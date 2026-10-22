# P0-d10 真实产品候选镜像与隔离运行验收

归档日期：2026-10-23（Asia/Shanghai）。最终验收代码为 `fbe6f0605abb3eb83f541bf62774c08df8a11456`。状态仅为 **implemented+tested isolated-only / PRODUCT_CANDIDATE_IMAGE=BUILT_AND_EXECUTED_ISOLATED**：真实镜像默认入口已经执行，不再只有测试进程或 build/help；但未签名发布、未安装、未接管流量，不代表整个企业系统完成。`authorization=BLOCKED`、`deviceActionsExecuted=false`，九项恢复 blocker 不变。

## 已真实执行的验收

| 层级 | 原始结果与边界 |
| --- | --- |
| 精确提交与任务 | [绑定 run 39808957939 / job 119929674886](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39808957939/job/119929674886)、[父 run 39808957928 / job 119929664827](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39808957928/job/119929664827) 均 head=fbe6f060、completed/success；不是仅排队或单个 step 绿色 |
| 原回归不减少 | 子 ordinary/race 各700 Test pair、8包，所有旧234/379/490/627/669及D9完整集合保留；父各2320 Test pair、37测试包pass，另唯一允许的 domain 无测试包skip；测试场景0 fail/skip，vet通过 |
| 其他原门 | 77 Vitest、6 Node TLS、11 Linux pidfd、15门自测/52 JSON负例；父 Linux Python160/0skip、13 shell、11实际 metaschema通过 |
| 新检查器 | Linux实际18项、0skip；包含合成ELF/上下文/运行投影拒绝反例，不能代替真实镜像运行。Windows本机10pass/8明确POSIX skip仅为辅助，不充作Linux证明 |
| 实际静态程序 | Go1.25.8、linux/amd64、CGO=0、trimpath、revision=fbe6f060、modified=false；28,591,834B，ELF64/ET_EXEC，无PT_INTERP/DT_NEEDED；解析内嵌buildinfo并与外部读回关联 |
| 实际打包/构建 | 独立 `deploy/product-candidate/Dockerfile` 为 `FROM scratch`，构建无网络/无pull/无缓存。白名单上下文9文件=一份Dockerfile+8个镜像文件。实际image save核对config digest、本轮两个layer diff_id、8个文件原字节/所有者/权限；不是仅核对Dockerfile字符串 |
| 真正运行 | 镜像默认 `/app/image-trust-api` 为PID1，程序没有被宿主bind替换；4个实例与可信实例同容器重启共5次运行，5份/proc实际exe摘要与静态程序相同，NSPID=1、UID/GID10001、cap=0、NNP=1 |
| 容器约束 | 10份运行/退出安全投影：只读根、精确3个bind、无host端口/host PID/特权/socket；私有配置树只读，trust/data两个子目录独立可写。内存256MiB、memory+swap总额256MiB（不允许额外swap）、1CPU、PID128、nofile1024、restart=no、stop15秒；等值swap配置语义见[Docker说明](https://docs.docker.com/engine/containers/resource_constraints/#--memory-swap-details) |
| 实际持久生命周期 | 5次SIGTERM/正常退出0；停止4实例后独立重开4组Store/Audit，再重启同一可信容器/同一imageID/状态读回并停止，最后4类启动失败后复核。共3轮四组状态核对：gen3、25测试定义、journal22/audit44、ACK/hash/序列与零消费账本保持；锁已释放，不删库或重建grant |
| 实际重启读回 | 正常Go TLS读取真实status/history、父operations/capabilities；viewer403、错误/匿名401、admin四类写请求423。不是用ready端口可连来代替API正确 |
| 真入口启动反证 | 缺checkpoint、缺TLS私钥、身份权限0644、未知配置字段分别实际退出1、非OOM、不残留running；逐一恢复原输入摘要后再复核状态。失败关闭不等于自动修坏盘 |
| 旧真Registry | Distribution3.1.2、两类签名/受管持久拒重放/API/刷新恢复链保持；ordinary/race各3，144次不可变读取GET48/HEAD96全200，另health GET1。这仍是旧测试制品，不是本轮产品镜像的远端发布验签 |
| 最终清理 | 实际清理标记成功：精确本轮8个容器/本轮imageID、UUID私有材料、已确认退出的浏览器进程/profile；不做全局prune，无生产对象 |

本轮Docker客户端/daemon均28.0.4（API1.48），Chrome155.0.8059.39、Node22.23.3。不得复用旧run工具版本。

### 制品身份，不混用摘要角色

- 实际静态程序SHA256：`6cc3c0f5984cc13282d6fe6e684c8384794625b3294c5fcb12443e97ddac80a4`。
- 本地Docker **config imageID**：`sha256:ed14c159ebb2aa636e3e5781cfdfc3a5478c4d786ab6dceccc0595b8ffd02d6e`。它不是Registry manifest digest，也不是远端仓库身份或签名。
- 镜像仅含程序与7个trust Web文件；二进制0555、Web0444，root-owned，目录0555。无配置、Anchor/身份、TLS私钥、测试程序、工具链、源码或主App演示文件。完整原Vite manifest不改写，SHA256 `bfcd0d86e8360140eca26fb1d0e8189b35e85a7eecacc6626bd1bfb1678a7888`；其中未使用的main条目不代表该页面已打包。
- `product-image-staging.json` 的 `contextPublished=true` 只指本地上下文原子落位；该阶段同时明确 `imageBuilt=false/imageExecuted=false`。实际构建/执行由后续工件证明，不能把这个字段读成Registry发布。
- 镜像实际字节读回发生在CI。原始binary/tar未上传，主代理独立复核的是安全摘要链与源码，不声称重新下载本体并独立重哈希。

## 首轮失败及修复，没有删检查换绿

首轮代码 `5b016ccdaa647c68f7c0f526b6a608e9621a14ba` 的[绑定39806878060/job119922353094](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39806878060/job/119922353094)实际失败；[父39806878064](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39806878064)通过不能覆盖该失败。77个首轮工件证明已构建/校验8文件、4次实际PID1和正常TLS ready，但在 `actual-image-browser` 阶段失败，未到停止/重启/负启动验收。清理另明确报原工作区 `browser-process-guard.py` 对UID10001 Permission denied，私有fixture保留、CLEANUP=FAIL；没有伪称首轮清理完成。私有browser supervisor stderr未归档，不能编造其完整错误。

最终fbe只修CI编排路径：把恰3个Git原字节绑定的verifier/TLS helper/guard复制到本轮私有、root-owned目录，目录0555/文件0444；浏览器使用内核只读mount。实际以UID10001验证读取与Node/Chrome/certutil执行权限。没有放开HOME/工作区全局权限、没有改用root Chrome、没有删TLS/浏览器/清理断言；只输出固定阶段/原因枚举，原始stderr与凭据仍不归档。真实端到端重新运行成功后才接受fbe。

## 真实浏览器验收

目标流程：`/trust.html` → 正常HTTPS → 显式连接 → 读取真实可信状态/历史 → 搜索/分页/摘要与详情 → viewer403/错误令牌401 → 断开清空。另正常HTTPS读取父operations/capabilities。

Browser plugin not available。既有Playwright静态层仅为历史证据；本轮新增真实浏览器验收使用预装Chrome/CDP，没有D10重新运行Playwright的证据，也未增加浏览器依赖。新镜像使用默认产品可执行文件，非Go测试服务器。桌面1440×1000、手机375×812、横屏812×375。

| UI检查 | 最终结果 |
| --- | --- |
| 页面身份 | PASS，实际title/URL/h1精确等待，绑定原verifier而非只检查HTTP200 |
| 非空 | PASS，真实25项签名测试目录、22条操作记录；未连接与未知不显示为健康 |
| overlay/遮挡 | PASS，原始截图无框架错误overlay、阻塞性遮挡；中文可读 |
| console | PASS，三套正例consoleErrors/consoleWarnings均为JSON整数0；runtime/CSP/asset/forbidden均0。不是整个CI没有平台警告 |
| 截图/响应式 | PASS，三套共12张PNG逐张由独立代理original查看；主代理另查看新镜像断开/viewer。每套断开1425×1300、auditor1425×6024、viewer1425×2899、mobile375×8698，无横向溢出 |
| 交互/权限 | PASS，真实分页20+5、搜索重置、摘要展开、记录详情/分页、手工刷新、键盘focus、44px按钮、reduced-motion；403保留获准状态而隐藏历史，401/断开清除观察与内存凭据 |

三套分别为旧HTTP40检查/14GET（200×11/401×2/403×1）、旧HTTPS45/16GET、新镜像HTTPS45/16GET（两者均200×13/401×2/403×1）。新镜像正常TLS1.3/AES_128_GCM、链2、CA签名/IP SAN验证，私有现代NSS的C,,信任、旧库不存在，无SPKI例外/TLS bypass/mock fetch。实际CA指纹 `47d4318fec190389b9f17dfd21355066c67ae711f04b2ca7dc0b7e7dedffe830`，叶指纹 `06e1e2331d4717bb399bf07bc6709014257e0a591bc5ffbe4ee1f571f830b392`。

不受信、错SAN、过期三个实际镜像端点分别被Chrome以AUTHORITY_INVALID/COMMON_NAME_INVALID/DATE_INVALID拒绝，浏览器HTTP/API/Bearer计数0、业务未挂载。**D10没有镜像内服务端独立请求计数器**，outcome明确 `serverNegativeHTTPCountObserved=false`；不能借D9测试进程的观察器声称新镜像服务端也实测0。

关键链为 `run-linux-ci.sh` → 既有 `run-offline-gate.sh`/Registry → `run-product-image-gate.sh`；真实浏览器包括Page/Runtime/Network与 `Network.getCertificate`。Chrome CI仍显式no-sandbox，仅靠外层non-root/cap0/NNP/隔离netns与只读mount，不能声称Chrome sandbox开启。未验证Safari/Firefox或企业/LAN证书链。可另安装Browser插件改善后续交互验收，本轮未安装。

## 独立证据复核与保存位置

最终[工件12438294581](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39808957939/artifacts/12438294581)，名称 `image-binding-39808957939-1`，95文件（ZIP4,063,239B）。主代理独立下载至 `C:\Users\Administrator\AppData\Local\Temp\chengwang-p0d10-final-fbe-b81e7a3da3974a6db80c809d0cb56bdb`，三个子代理另独立下载/复核；没有上传ready、令牌、配置、私钥、NSS/profile、原始inspect、binary或tar。

- 主代理重放实际 `check-go-json.py go-test.json go-race.json` 与 `--mode registry registry-ordinary.json registry-race.json`，并从父真实joblog重新解析普通/race各2320；不是只看绿色图标。
- 553条checkout与76条child清单前后逐字节不变，主代理/独立代理逐项与精确fbe的Git raw blob核对；3个harness摘要同样匹配Git。386远程依赖在线/离线相同，原go.mod/go.sum不变，无新产品依赖。
- 子700 pair SHA256 `b3cd00ab4fd983026e777095b484e2a0e49b05867186a83df234b8a27b7bb999`；父2320 pair SHA256 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`（排序package TAB test并LF结尾），与D9相同。新fixture为 `linux && productimage` tag单独执行，不能混算成原700自动增加。
- 主代理独立核对stage→实际8文件→5次PID1→10运行/退出投影→同容器重启→4负启动→3次重开→outcome，以及三套浏览器报告/12PNG尺寸；没有把合成检查器测试当作真运行。
- 新镜像浏览器报告SHA256 `06a13e7cf7f635e229e36bfab5df12c67700f9be732b7516a72185f08cc0abe6`；outcome SHA256 `23d8715e10dc500f6cf6cd715c2d619f29e760988c78ae8a0ce9f432c26c58f9`。
- 绑定job日志API原字节1,766,803B、SHA256 `6520a1129dc9a7c262eb1e06b726c016e2b0dfb88ce801492079e7340b05c264`；Windows保存CRLF副本1,774,512B、SHA256 `f11c2c61141a00ba59c5375a8723e5b742eb6d89ab3fce6e2bedf750fd82386c`。两者均UTF8 BOM，仅7709行LF/CRLF不同；只在内存规范化后逐字节相等，非测试结果冲突。
- 父日志Windows副本5,470,795B、SHA256 `d70fc59cb2c0cb3d763ec3ec1797a4498bac8e13e81ed5b8ebc85f4da72a41b5`。首轮失败日志CRLF副本1,771,366B、SHA256 `e5fce2638ea8a07b2eaa97d13abbe7bd7a5ca99c99d9ab64632f85f5b9080f11`，失败记录不以最终日志覆盖。

Temp和Actions保留期（14天）不是永久备份或WORM。Git固定保存实现和本报告，不保存私密fixture或原始镜像本体。GitHub平台Action Node20→24弃用警告仍有，不与应用consoleWarnings=0混淆。

## 未完成：不能据此放行生产

1. **产品镜像还没有远端Registry manifest读回、正式签名/批准或来源绑定**。现有Registry测试绑定的是旧惰性制品。下一阶段应先在隔离Registry让本轮真实产品镜像完成精确manifest/config/layer图→正常TLS固定来源→签名/批准/撤销/防回放链，并保留不发布生产边界。
2. 尚无独立builder/source attestation、SBOM/漏洞/许可治理、可重复构建或多架构证明。scratch不自动证明无漏洞或供应链可信。
3. 原 `cmd/server` 默认仍不装配trust backend；旧Dockerfile、M2b/探针浮动基础来源门继续BLOCKED，没有以新scratch路径给旧镜像放行。候选仅为既有基础产品API+trust控制台，并非全部主App/企业模块、订阅/多内核/DNS/业务节点能力。
4. 原700/race/真实Registry客户端是CGO=1；新CGO=0真实程序已验证TLS/API/持久锁与生命周期，但尚未在该镜像进程内完成真实SDK/Registry验证写链与自动刷新故障矩阵。D9其他路径的测试不能替代此缺口。
5. 健康ext4/XFS状态的停止/重开不等于物理断电、坏checkpoint/坏盘自修、全磁盘回滚防护或HTTP exactly-once。没有生产备份恢复/灰度读回、长时间soak、资源耗尽与分布式HA证明。
6. 企业IdP/SSO/MFA、正式可信发放/审批/密钥轮换、公共/企业证书生命周期、LAN/IPv6/多浏览器、独立见证/WORM、长期容量治理与设备执行仍未完成。继续保留全部恢复blocker、M2b/M3/M4与授权限制；不提供全项目完成率、无bug、免维护或99.999999%承诺。

本轮未访问或修改10.88.0.240/.249/.254、爱快、DNS、OpenClash、Kuma、ERP或生产Docker；未合并main，未推送产品镜像。仅推送开发分支源码/文档与运行隔离CI。任何生产步骤仍须另行授权、先备份、验证恢复并灰度/观察。

操作说明：[完整产品候选](PRODUCT-CANDIDATE-OPERATOR-NOTES.md)；范围：[D10实施合同](P0D10-IMAGE-RUNTIME-CONTRACT.md)；历史：[D9验收](P0D9-PRODUCT-HTTPS-ACCEPTANCE.md)。
