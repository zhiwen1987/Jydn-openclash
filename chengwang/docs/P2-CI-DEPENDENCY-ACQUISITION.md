# P2：有界CI依赖获取与订阅UI回归

状态：实现及新增26项纯CPU检查完成；尚未执行新源码真实CI，不是缺失UI路径已通过，也不是生产变更记录。

## 原始故障及本轮范围

`b68a55e` 原UI run `40013130002` 的三个producer成功，admission/CDP job `120618297320` 在准备阶段超过22分钟上限，fresh跳过。两次npm已结束；61.2MB字体包 `fonts-noto-cjk` 在Azure Ubuntu镜像出现GET→IGN→GET，之后平台取消。该日志证明阻塞位置和平台超时，不证明运营商、镜像服务或其他网络层的唯一根因。[前序原件台账](evidence/p2-probe-request-binding-16ad525.json)不覆盖。

本轮仅改隔离GitHub CI的准备流程：限制等待、失败停止、安装后读回，并补齐原订阅UI矩阵的实际原件验收。不是新增企业业务能力；完整B01–B23、历史偶发取消归因、灰度及生产仍分别保留。

## 最小处理与真实退出条件

1. 保留runner配置的APT签名源、镜像列表和默认验证链，不写 `/etc/apt`，不新建第三方源，不关闭签名或TLS。现有源可含HTTP，本方案**不声称强制全HTTPS或独立包来源公证**。
2. 每条APT命令显式覆盖 `Acquire::Retries=1`、HTTP/HTTPS空闲超时15秒；update严格错误模式any，部分索引失败也拒绝继续。总时长另限update120秒、install240秒，root执行的timeout在TERM后15秒可KILL；只各调用一次，不自动repair/upgrade或重跑浏览器挑绿。npm两个安装各限180秒。
3. 真正安装原有两包，不删除中文字体需求。构建前读回两包installed状态/版本、固定certutil文件、Regular/Bold的fontconfig选择、包归属与实际有界文件摘要；APT sources前后只记录路径/长度/摘要并核相同。不输出源配置内容。
4. 日志/结构化报告放在 `reports/dependencies`，独立检查报告放reports同级；不扩写冻结的 `originals` 14文件集合。检查源码绑定helper和合同的Git原blob，保留trusted CI观察边界，不把安全投影当本机独立字体字节验证。
5. 新纯CPU测试只证明闭集命令、超时/错误截断、报告和反例；新CI才证明实际APT、字体读回及四条真实UI流程。四producer+四fresh、API/DOM/审计/正常TLS/PNG/退出/错误计数及旧84+新76门继续严格核原件。

合同：[ci-dependencies-contract.json](../deploy/subscription-ui-browser/ci-dependencies-contract.json)。原job22分钟上限不放宽。只运行隔离CI，未在本机安装包、启动浏览器、服务或Docker；不触碰生产路由、DNS、Kuma和ERP。

## 本机已完成与未证明

准备程序16项、独立检查器10项实际执行通过，0跳过；工作流另外核固定名称摘要和真实run/pass事件，不能用skip凑26。原84及新76订阅UI辅助门保持原样。本机原日志在 `C:/Users/Administrator/AppData/Local/Temp/chengwang-ci-dependency-local-3b999b32dd404957a5db3d27bc5d1627/new26-frozen-unittest-original.log`。

另以完全模拟的子进程、系统包和字体元数据，实际串联准备程序→独立检查器通过，只证明字段及控制流互通，不证明真实APT/字体/Git执行链。独立读入器还实测并处理Windows lstat/fstat ctime差异：各API前后完整稳定性仍核ctime，跨API只比较共享身份字段，不改变原有POSIX门。`executed`仅记录固定阶段调用已尝试；未知退出结果仍是null并FAIL，不当作操作系统执行公证。

真实安装、超时命令在Linux的执行、实际Regular/Bold包文件读回、四条UI与fresh原件仍必须由新CI验证；此处未预报成功。前序文档提交f05335b的父门40016485638和旧订阅40016485668现已终态success，仅核状态，不冒称该文档提交重做了所有原门。

## 上游依据与限制

- [GitHub runner-images固定源码](https://github.com/actions/runner-images/blob/c03600ca998467081ccec9bb9dbf5de6b68e862a/images/ubuntu/scripts/build/configure-apt.sh)已经采用低重试和15秒空闲超时，说明相同URI的高重试可能延迟镜像切换。它是方案参考，不是本项目阻塞同因的证明，也不证明旧runner采用了何值。
- [APT 2.7.14配置读取顺序](https://github.com/Debian/apt/blob/2.7.14/doc/apt.conf.5.xml)说明命令行选项覆盖配置；[HTTP传输定义](https://github.com/Debian/apt/blob/2.7.14/doc/apt-transport-http.1.xml)说明连接/数据空闲超时不等于整条命令总期限。
- [同版本update实现](https://github.com/Debian/apt/blob/2.7.14/apt-pkg/update.cc)与[官方失败传播测试](https://github.com/Debian/apt/blob/2.7.14/test/integration/test-apt-update-failure-propagation)区分默认瞬时错误警告和any严格失败。不能把普通update返回0当作所有索引获取成功。

即使依赖获取及新矩阵通过，也只关闭本轮CI阻塞和既定UI流程的验收缺口；不保证镜像永不故障，不证明所有字体实际被浏览器选择，不证明公网业务、整套企业产品或生产上线。
