# P2：有界CI依赖获取与订阅UI回归

状态：源码 `c7b64c487cb36c9eb5b7240a792cc09950aea337` 的[原CI 40018960129](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/40018960129)已终态 **failure**。两条PW完成安装和真实产品流程，两条CDP在安装240秒期限退出，fresh跳过。**有界退出/失败拦截已实测，依赖获取可用性和整组UI回归仍未闭合**。不是生产变更记录。

## 原始故障及本轮范围

`b68a55e` 原UI run `40013130002` 的三个producer成功，admission/CDP job `120618297320` 在准备阶段超过22分钟上限，fresh跳过。两次npm已结束；61.2MB字体包 `fonts-noto-cjk` 在Azure Ubuntu镜像出现GET→IGN→GET，之后平台取消。该日志证明阻塞位置和平台超时，不证明运营商、镜像服务或其他网络层的唯一根因。[前序原件台账](evidence/p2-probe-request-binding-16ad525.json)不覆盖。

本轮仅改隔离GitHub CI的准备流程：限制等待、失败停止、安装后读回，并补齐原订阅UI矩阵的实际原件验收。不是新增企业业务能力；完整B01–B23、历史偶发取消归因、灰度及生产仍分别保留。

## 最小处理与真实退出条件

1. 保留runner配置的APT签名源、镜像列表和默认验证链，不写 `/etc/apt`，不新建第三方源，不关闭签名或TLS。现有源可含HTTP，本方案**不声称强制全HTTPS或独立包来源公证**。
2. 每条APT命令显式覆盖 `Acquire::Retries=1`、HTTP/HTTPS空闲超时15秒；update严格错误模式any，部分索引失败也拒绝继续。总时长另限update120秒、install240秒，root执行的timeout在TERM后15秒可KILL；只各调用一次，不运行repair、`apt-get upgrade`或重跑浏览器挑绿。`apt-get install`本身仍可能升级所选包及其依赖，本轮日志实际包含libnss3升级，不能称系统所有包完全不变。npm两个安装各限180秒。
3. 真正安装原有两包，不删除中文字体需求。构建前读回两包installed状态/版本、固定certutil文件、Regular/Bold的fontconfig选择、包归属与实际有界文件摘要；APT sources前后只记录路径/长度/摘要并核相同。不输出源配置内容。
4. 日志/结构化报告放在 `reports/dependencies`，独立检查报告放reports同级；不扩写冻结的 `originals` 14文件集合。检查源码绑定helper和合同的Git原blob，保留trusted CI观察边界，不把安全投影当本机独立字体字节验证。
5. 新纯CPU测试只证明闭集命令、超时/错误截断、报告和反例；新CI才证明实际APT、字体读回及四条真实UI流程。四producer+四fresh、API/DOM/审计/正常TLS/PNG/退出/错误计数及旧84+新76门继续严格核原件。

合同：[ci-dependencies-contract.json](../deploy/subscription-ui-browser/ci-dependencies-contract.json)。原job22分钟上限不放宽。只运行隔离CI，未在本机安装包、启动浏览器、服务或Docker；不触碰生产路由、DNS、Kuma和ERP。

## 本机已完成与未证明

准备程序16项、独立检查器10项实际执行通过，0跳过；工作流另外核固定名称摘要和真实run/pass事件，不能用skip凑26。原84及新76订阅UI辅助门保持原样。本机原日志在 `C:/Users/Administrator/AppData/Local/Temp/chengwang-ci-dependency-local-3b999b32dd404957a5db3d27bc5d1627/new26-frozen-unittest-original.log`。

另以完全模拟的子进程、系统包和字体元数据，实际串联准备程序→独立检查器通过，只证明字段及控制流互通，不证明真实APT/字体/Git执行链。独立读入器还实测并处理Windows lstat/fstat ctime差异：各API前后完整稳定性仍核ctime，跨API只比较共享身份字段，不改变原有POSIX门。`executed`仅记录固定阶段调用已尝试；未知退出结果仍是null并FAIL，不当作操作系统执行公证。

前序文档提交f05335b的父门40016485638和旧订阅40016485668已终态success，仅核状态，不冒称该文档提交重做了所有原门。

## 新源码真实CI结果：部分通过，整体失败

四job均为上述源码原run的attempt 1，没有取消、重跑或修改门槛。根端及两独立子代理分别保存原ZIP，按API字节数/摘要、全部CRC及展开字节核对：成功包各35成员，失败包各5成员，共80成员，三方逐字相同。[机器台账](evidence/p2-ci-dependency-acquisition-c7b64c4.json)保存job、artifact与报告摘要。

| 路径 | 原job | UPDATE | INSTALL | 实际后续结果 |
| --- | --- | --- | --- | --- |
| create/CDP | 120638220560 | exit0，5.368s | exit124，240.009s | 独立依赖CLI拒绝；构建/浏览器跳过 |
| admission/CDP | 120638220656 | exit0，7.894s | exit124，240.008s | 独立依赖CLI拒绝；构建/浏览器跳过 |
| create/PW | 120638220761 | exit0，7.985s | exit0，6.761s | 依赖及完整既定创建/回执流程通过 |
| admission/PW | 120638220853 | exit0，9.972s | exit0，7.541s | 依赖及完整既定双来源本地准入流程通过 |

两CDP的失败阶段均为INSTALL：安装原日志停在61.2MB字体包，create出现Get→Ign→Get，admission只观察到Get；没有明确最终网络错误码。两份readback日志为空、packages/fonts为空、certutil为null、readbackComplete为false，不能补写安装成功或浏览器结果。总期限实际返回124，消除了该次无限等待，但**没有证明原下载阻塞根因或下载可用性修复**。fresh job `120640260189` 因前置失败skipped，实际fresh报告0份。

两PW实际读回目标包installed：libnss3-tools `2:3.98-1ubuntu0.3`、fonts-noto-cjk `1:20230817+repack1-3`；Regular 19,484,784B、Bold 20,050,760B，uid/gid0/0、0644，完整SHA见机器台账。四份27项APT配置摘要前后均相同；这不公证配置内容、包可复现来源或独立签名链。四份新26测试原输出均逐名核AST/Git冻结名单、实际ok、Ran16+10、两OK、零skip；26个唯一测试不能按四job累加成104个功能。

根端分别执行两PW完整原产品CLI、旧84/新76原辅助CLI、新依赖完整CLI；产品报告与CI/B代理原字节相同，依赖报告与CI/B/C代理原字节相同。每份产品报告核879个Git源blob；新依赖CLI只绑定helper/合同2个Git blob，不冒充全源码证明。两CDP的原成功检查器根/C均实际exit1且不产PASS报告，这是正确拒绝，不计作安装通过。原件目录：

`C:/Users/Administrator/AppData/Local/Temp/chengwang-ci-dependency-c7b64c4-root-7a6775dcccb946029747dce38cf412bc`

### 有限UI复验记录

目标流程：真实订阅页→创建确认/取消/再创建/回执；另一路为双来源导入→接纳/拒绝/当前版本CAS回退→节点恢复。隔离CI的 `https://127.0.0.1:17891`，真实cmd/server和Web、正常TLS1.3、无mock API；Browser plugin不可用，沿用已批准的CDP/PW隔离CI路径。本轮只有PW成功进入页面。

| 检查项 | 两PW结果 | 边界 |
| --- | --- | --- |
| 页面/非空/错误覆盖层 | 原DOM、API与PNG核对通过 | 仅既定订阅流程 |
| 控制台/网络 | 八错误计数各为0 | 不证明历史偶发问题永久消除 |
| 交互 | create14请求/11步；admission100请求/37步/10命令 | 四角色元数据不等于完整跨角色拒绝矩阵 |
| 截图 | 根与B均实际查看四张原首屏PNG，1440×900与375×900，未见首屏重叠或框架错误覆盖层 | 手机只截首屏、未独立执行完整手机交互；不声称全页或所有视口验收 |
| 生命周期 | 正常关闭、Chrome wait0，无强制退出/所属残留进程 | trusted CI观察，不是独立信号执行公证 |

本轮产品web/internal/cmd/vendor相对b68a55e没有变化，镜像/旧探针workflow未因本轮依赖路径触发，不冒称重新通过。父门 `40018960021` 和旧订阅 `40018960055` 原CI均成功：根核终态；A独立核父门原日志派生JSON（非原tee文件）、ordinary/race各2644实际Test及各12 Fuzz顶层/seed事件、旧基线链，旧订阅两Linux原报告逐字同/20件摘要同。Windows完整旧POSIX custody仍拒绝，未弱化；本轮根未重放该旧门全CLI。

## 上游依据与限制

- [GitHub runner-images固定源码](https://github.com/actions/runner-images/blob/c03600ca998467081ccec9bb9dbf5de6b68e862a/images/ubuntu/scripts/build/configure-apt.sh)已经采用低重试和15秒空闲超时，说明相同URI的高重试可能延迟镜像切换。它是方案参考，不是本项目阻塞同因的证明，也不证明旧runner采用了何值。
- [APT 2.7.14配置读取顺序](https://github.com/Debian/apt/blob/2.7.14/doc/apt.conf.5.xml)说明命令行选项覆盖配置；[HTTP传输定义](https://github.com/Debian/apt/blob/2.7.14/doc/apt-transport-http.1.xml)说明连接/数据空闲超时不等于整条命令总期限。
- [同版本update实现](https://github.com/Debian/apt/blob/2.7.14/apt-pkg/update.cc)与[官方失败传播测试](https://github.com/Debian/apt/blob/2.7.14/test/integration/test-apt-update-failure-propagation)区分默认瞬时错误警告和any严格失败。不能把普通update返回0当作所有索引获取成功。
- [runner-images同一固定提交的源配置](https://github.com/actions/runner-images/blob/c03600ca998467081ccec9bb9dbf5de6b68e862a/images/ubuntu/scripts/build/configure-apt-sources.sh)本就声明Azure→Ubuntu archive→security优先级回退；[APT固定源码](https://github.com/Debian/apt/blob/db797312548f6e7d6d1d1faa9f1e48c1e521d290/apt-pkg/acquire-worker.cc)中同URI重试优先于替代URI，[官方mirror测试](https://github.com/Debian/apt/blob/db797312548f6e7d6d1d1faa9f1e48c1e521d290/test/integration/test-method-mirror)覆盖优先级回退。根通过GitHub API实际读过这些源码；它们是下一补丁的参考，**不是本轮runner配置全文、实际APT版本或当前超时因果的独立证明**。后续获取方案尚在研究，未修改源或导入包缓存。

根另以公开脚本的三行镜像清单重建恰144B，SHA `e0d6b0af979e4662d16357a27ae456cc6f21e26da031540f4df8706ebed1d583` 与四原报告相同，可在trusted-CI投影边界内绑定这份镜像清单；不扩大成APT全部配置或执行版本证明。

下一补丁候选（**仅研究，未实现**）：优先研究在CI私有APT目录调整官方HTTPS候选顺序，保留原发行版/组件/架构/Signed-By，重新验证签名索引及严格总期限；不得继续称有效源完全未变，必须区分宿主未改与私有配置改变。更复杂的一次预取/四job缓存复用暂不优先：[APT固定缓存实现](https://github.com/Debian/apt/blob/db797312548f6e7d6d1d1faa9f1e48c1e521d290/apt-pkg/acquire-item.cc)中已存在同尺寸archive文件的快速路径直接Complete，不能假定缓存重新完整验SHA。该方案若采用，消费者必须按已认证Packages元数据重新核每包SHA/大小，工件自身摘要不足以证明来源。上述均未下载包、改源或执行新runtime；先补实际APT版本及私有配置安全合同，再实现和另起原CI，不重跑本轮挑绿。

即使依赖获取及新矩阵通过，也只关闭本轮CI阻塞和既定UI流程的验收缺口；不保证镜像永不故障，不证明所有字体实际被浏览器选择，不证明公网业务、整套企业产品或生产上线。
