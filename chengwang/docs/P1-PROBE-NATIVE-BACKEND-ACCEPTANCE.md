# P1 真实探针只读后端隔离验收

验收基准：`700ea9ed2f58b267d1530ffcacc0a3f3cdba2dbb`。状态：`implemented+tested isolated-only`，范围固定为 `NATIVE_BACKEND_ONLY`。真实浏览器、公网业务和生产闭环未完成；本轮未改生产、main、正式 Registry 或设备写入。进度见[项目台账](PROJECT-PROGRESS-LEDGER.md)。

## 实际执行与结果

| 执行 | 权威结果 |
| --- | --- |
| [原生 39898532081](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39898532081)，job120234471478，attempt1 | success；真实 agent/server/tagged driver 编译，44 辅助检查和 24 wire 前置检查通过；后端执行、独立 checker、源不变与工件保存均成功 |
| [父门 39898532124](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39898532124)，job120234472032，attempt1 | success；ordinary/race 各 2391 个 Test 实际 run/pass，0 Test skip、0 fail；各 12 个 Fuzz 另验 run/pass，不计入 Test 数 |
| 主代理及独立子代理分别重放 | 各自下载原 ZIP/API 日志，CLI exit0；报告与 CI 原 verification 逐 byte 相同，22 输入 SHA 全匹配；源码逐 Git 原 blob 核对 |

44 辅助检查＝执行器 12＋checker 32，合成正/反例不冒充原生访问。24 wire 前置检查＝8 形状检查＋16 Linux 真实 TLS/拒绝/预算/退出检查，0 skip。两者均保留完整具名名单；wire 名单 SHA256 为 `10cefc1190a296b1d6e199d7e7c6edf9fc5e2b02b5d13c9234e5b956034b8e85`。父门旧 2320 对(package,Test) SHA256 两轮均为 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`，新 tag 未混入普通基线。

## 实际后端链路

- 新私有 net/mount/PID namespace，只有 lo 与封闭的 `8.8.4.4/32`，无外部接口/default route。10001:10001、groups 空、5 类 capability 零、NoNewPrivs=1；正常 TLS，3 套独立 CA；系统根只在 agent 私有挂载中替换。宿主 netns/mountns、sysctl、CA 与源码前后不变。
- 实际 agent 两轮产生 6 个原始 spool 结果；first/final ledger 序列 7/13 联合覆盖 6 个 EvidenceRef/startID/runID 结算，保留原字节，没有 driver 伪造追加。
- 固定 200/403/429 分别读回 available/restricted/rate_limited；12 DoT 查询＋6 HTTPS 响应，18 连接、72 事件。wire 没收到 runID，只能作唯一目标/真实时间窗关联；精确 ID 关联来自持久 spool/ledger。
- fresh 与真实 server 重启后均读回相同 6 样本；等真实所有层最晚 TTL 后，6 expired、0 eligible、0 samples、3 目标 unknown。汇总状态为 partial/evidence_expired，不把它误断为存储损坏，也不要求状态字面值 unknown。
- agent 实际运行 129.163904061 秒，实验 249.968159662 秒；4 个 role 全部正常 TERM/join0，无强制 kill。源状态 snapshotDigest 为 `sha256:b869aa5bb66569a612f146644dc2d375164a66132b5227f9add0337b999c5193`，前后元数据与字节相同。

## 原始证据与复核

artifact12478236023，`probe-readback-native-39898532081-1`，原 ZIP 201,230 bytes，SHA256 `2099388c07edea47c9de23b0160db0ebe502a453287a344615c225c8b970c77b`。安全解包 35 个常规文件、819,909 bytes；其中 22 份 backend 输入与外部独立 verification 分离，私钥/身份/bearer 未导出。

原生 job API 原日志 52,415 bytes，SHA256 `940614091dc58d0e4f67608b48d6f7698d67e7e4dfe67df2b445ca487c59f20e`；父 job API 原日志 5,581,259 bytes，SHA256 `ec5bc36a49796925982264001d5f4c9e9ae59036e90ace846ba578224adfa561`。主代理重放报告 SHA256 `94310635ab278b35354e7febbb2db693e60d915e0508b87f545b47ee1b91a14c`，与 CI 原报告逐 byte 同。

外层 658 记录及 isolation 前后各 662 记录联合 662 个唯一源码文件，共 31,025,621 bytes，逐 Git 原 blob 匹配确切 700ea9e；这是 Chengwang/workflow 范围，不是全部 OpenClash 仓库完整性。构建产物 agent/server 的 SHA 与实际进程 exe 对齐，wire Python SHA 与工具清单对齐；这仍依赖可信 CI 构建，不是独立可复现构建或发行签名。

主代理证据目录：本机 Temp `probe-native-700-root-ph9zXd`、`probe-parent-700-root-On9x1g`。独立目录：`chengwang-probe-700-independent-3949410af53244b2b4ba1739a8bbb217`、`chengwang-parent-700ea9e-b-uyafzxb1`。CI retention 14 天及 Temp 都不是永久集中/WORM 证据库，永久归档与运营闭环仍待实现。

## 能力事实同步后的复验（2fe1231）

`2fe1231de851417e7825b9c8b02083acf1ad08f3` 新增显式 `RuntimeFacts`，保留旧 `Build` 参数及可选观测参数“恰好一个 true 才启用”的语义。`probe_evidence_readback` 默认 blocked，已配置时仅 implemented_local/readOnly；匿名能力清单只检查是否接线，不调用 status/details、不触发磁盘或探测。完整 `active_business_probes` 仍为 design_only，但不再错误声称源码没有 HTTP/TLS/DNS 执行器。配置不等于健康、新鲜或生产可用。

- [父门 39901227879](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39901227879)，job120243028805/attempt1，success。ordinary/race 各实际 2403 Test run/pass，0 Test skip、0 fail；各 12 Fuzz 单独验。新增 4 API＋8 capability 测试名单 SHA256 为 `2daf951da91974d83b2030dfdbd03cbfde528ce9172b429fb0f33e3f3764cc43`；完整 2403 为 `4988f181a389575003152bfd2194485f030506f63859133229019f8d5db4441b`。先精确剥新增 12，强制旧 2391 SHA `5faa2eeda5f6c6db5cbc52dead9bdf3e84d00bf67acd5d25f599a0fce33a4fdc`，再旧 71 和原 2320 门；不以宽泛前缀排除、不重校准旧基线。26 项辅助反例通过不代替真实 Go 执行。
- [原生复验 39901227878](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39901227878)，job120243028830/attempt1，success。仍是 44 辅助、24 wire 和原 22 输入，6 结果/ledger7→13、12 DoT＋6 HTTPS、18连接/72事件、4 role正常 TERM/join0，真实最晚 TTL 后 6 expired/0 samples/3 unknown。agent 129.137679636 秒、实验 249.801247563 秒；状态快照摘要 `sha256:adbcaa970801bb4558f65044231ea3abc00ea6e661ad2da5f302e4f2ed86371e`。
- 原 artifact12479101507，ZIP 202,302 bytes / SHA256 `2ecbe425a6f6d64542130515312f1c1ec182e72a46092a98ee90efb98d190531`；35 个常规文件，原 22 输入与独立报告分离。主代理及独立子代理实际 CLI 重放报告均为 3,585 bytes / `96fad1cc38d285b130084558cf70e4e1d9f4b82b657f31cdbe33d179f391e612`，与 CI 原报告逐 byte 一致。663 外层/667 runtime 记录合并后 667 唯一 Git 原 blob、31,062,685 bytes 均匹配确切源码，无 CRLF 归一化。
- 原生 API 原日志 52,408 bytes / `1a9e244881bad218b9aadb3abb0456879d0681968812893e55a1a7daca902a9c`；父门原日志 5,609,377 bytes / `9fe01e611c2a17f230fd07d78b466ed59c0a86c7a05cce36f89685dda5b6b574`。独立目录为本机 Temp `chengwang-probe-2fe-c-independent-umb6qvko` 与 `chengwang-parent-2fe1231-b-88rvyrwb`；主代理另行解析父门原日志、逐 Git blob 校验并实际重放原生 CLI。
- [候选镜像门 39901227882](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39901227882)，job120243028885/attempt1，终态 success；既有隔离 Registry/产品镜像与来源/恢复回归由原门执行，不能与本阶段新增探针浏览器验收混淆。此复验仍不是正常 TLS 探针浏览器闭环，更不是生产上线；Windows 仅运行 gofmt、Python/Node 辅助检查，无本机 Go build/test/mod、Docker/WSL 或 namespace 实验。

## 失败记录与未完成项

首轮 `a8a5216`/[39897368270](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39897368270) 仍为 failure：真实后端执行成功，但 checker 错误要求已销毁 namespace 的历史 inode 永不复用。仅修 checker/反例及文档，保留并发生命期隔离、PID、argv/exe、权限、阶段顺序和正常退出；startTime 以 tick 非递减判断。原始 ZIP 199,667 bytes / `2ae4d73d4b629973b2317389efb5bcc8c98b8edcf9c1a4ca31fa1cb9adc01234` 未改，修后离线重放通过不改写原 CI 结果。

本门没有正常 TLS 浏览器消费真实样本，没有真实公网/地区/账号/节点能力测试，没有生产挂载、正式镜像发布或设备动作。生命周期依赖受信执行器的有序 join 记录，不是独立退出时间见证；拒绝 API 的原响应体、Python 发行来源与 agent 身份签名未由本门独立证明。Windows 只运行辅助 Python 检查，未运行本机 Go/Docker/WSL。整套系统剩余项见[台账](PROJECT-PROGRESS-LEDGER.md)。
