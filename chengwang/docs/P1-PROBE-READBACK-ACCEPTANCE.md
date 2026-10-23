# P1 安全探针读回基础：实际隔离验收

本页保留基础 `2cf4a34` 的验收范围；后续真实 agent→API 的原生后端已通过[700ea9e独立验收](P1-PROBE-NATIVE-BACKEND-ACCEPTANCE.md)，正常 TLS 浏览器全链路仍未完成。当前进度见[项目台账](PROJECT-PROGRESS-LEDGER.md)，下文后续实验计划不能当作最新状态。

状态：`implemented+tested isolated-only`，仅限下列基础接线和原有回归。**真实 probe-agent→DoT/HTTPS→主 API→浏览器的完整闭环仍未完成，未上线**。生产、main、正式 Registry、设备写入均未改。源码提交 `2cf4a34a613bfb39a1caa019ac0f9d44d372faec`；早期失败及取消不计为通过。[实现范围与配置](P1-PROBE-READBACK-IMPLEMENTATION.md)。

## 权威执行

| 执行 | 实际结果 |
| --- | --- |
| [父39891333888](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39891333888)，job120211541665，attempt1 | success；ordinary/race各2391个Test实际run/pass，0 Test skip/fail，旧2320完整保留，新71 exact：reader32/provider19/API10/runtime10。vet为所在成功步骤中的静默命令。 |
| [镜像39891333875](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39891333875)，job120211772460，attempt1 | success；ordinary/race各732，旧728/700全名哈希保留；Registry两轮各3；前端110＝原77＋新33，7文件完整名称校验；原浏览器40/45/45与镜像子门保留。 |
| 本地前端与浏览器 | 110单测、lint/build；1440/375px、键盘、展开、清除、自然TTL和错误态通过，无横向溢出。本轮新probe UI使用明确合成API，不是真实agent网络证据。 |

父旧2320对(package,TestName) SHA256两轮均 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`。子完整732名SHA256 `47a2e1455240e8a565ac214e463ff59e059e4beaad19c993548d4b6dcc93b24c`，剥离exact4保留728 SHA256 `6557b5f9621b6d691133c2242ab1c35308dfcd376424b43c6a9c2644830d0811`；再剥离既有exact28仍为700 SHA256 `b3cd00ab4fd983026e777095b484e2a0e49b05867186a83df234b8a27b7bb999`。Fuzz种子及无测试文件包的package skip不混入这些Test计数。

## 原始证据与重放

- artifact12475268467 / image-binding-39891333875-1，原ZIP6,360,008 bytes / SHA256 `ef93cd7050fd690d7711b6a70fc71cba6b9d46a07f8965f0a9fa81160c8c0e4a`；安全解包1470个无重名平面常规文件，15,586,530 bytes。
- binding原API日志2,038,546 bytes / `ecceecd62379457145ad54bfde294da642295243dca332da26ae0c2326f1ac49`；父原API日志5,581,422 bytes / `816fabc078d3d3fc9103a74d2663211cbdae65ff9d1a8c7c814c360b448fd8a4`。root与独立子代理分别下载、复算，原ZIP/API/metadata与派生报告分离，不归一化原bytes。
- 648 checkout记录＋97子模块记录，648个唯一文件逐git原blob绑定精确2cf提交，前后原清单相同。checkout原清单76,990 bytes / `707b820b3911120f70ca65658735473260ac58f569c66081e3245565ea81c72e`；子清单9,450 bytes / `a75f80e7254ad4536c5865cb52321a432e119ab76acd8acbdd6972809b288907`。范围是此CI的Chengwang/workflow，不是整个OpenClash仓库或生产完整性。
- root及独立子代理分别实际运行六个verifier CLI registry/lifecycle/crash/state/source/source_tls，全部exit0；root重放报告与原outcome逐byte相同。七个原outcome皆该提交/PASS/production=false/authorization=BLOCKED，原1366个证据摘要保留。候选local imageID `sha256:556f1c90b7c745113558e00e1877260468bac8d11a13cbe4b0a4d326451a5977`，不是正式Registry manifest或签名发行；旧镜像门没有启用probe，不能证明新探针链路。
- root证据在本机Temp的 `chengwang-p1-2cf-root-AqcUAu`、`chengwang-p1-2cf-binding-root-4nnbV7`；独立目录 `chengwang-probe-p1-2cf-independent-xnklklzv`、`chengwang-p1-2cf-independent-OBDOL3`。Temp与CI retention不是永久/WORM证据库。

## 失败与剩余边界

8f2a32c父为2391 run/2388 pass/3 fail：两catalog和一runtime测试未显式准备0700近父目录。仅修测试前置后，f443及最终2cf重跑成功，未放宽生产owner/FS/TLS/超时。8f/f443 binding被后续提交取消，不计完整验收。

非Linux unsupported仅实现，本轮未运行Windows Go。协作式取消不等于硬取消坏盘/内核D态。新UI的合成浏览器测试与旧trust实际TLS浏览器回归是不同范围，不能替代真实agent样本、API/浏览器原runID读回、跨服务重启、源tree全程不变。

下一实验必须遵守产品HTTPS443及TTL≤2×interval，拟固定60s/120s而不是无效30s/120s。wire↔run仅为唯一目标/真实时间窗关联；精确ID关联来自原spool EvidenceRef与ledger，不声称服务端收到runID或agent身份签名。新实验辅助代码未实跑前仅为implemented-local-only，不冒充已验闭环。

生产挂载、真实公网/业务能力、设备灰度/回滚、DNS/订阅/多内核与企业运营闭环仍见[完整缺口](SYSTEM-COMPLETION-GAP-AUDIT.md)。本门不解除这些缺口，不承诺高可用率、零bug或整体完成百分比。
