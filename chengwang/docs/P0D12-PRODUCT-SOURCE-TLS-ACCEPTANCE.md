# D12 初始来源 TLS 故障与同进程恢复：实际验收

状态：`implemented+tested isolated-only`，仅本批六格已验收，未上线。日期：2026-10-23。运行代码为 `b8abe163fdd40f0dffe327c97989cf6f858fb762`；本轮新增测试驱动、检查器、隔离运行器及接线，未改产品刷新/信任库/API 的运行逻辑。根代理单一集成，三名子代理分别实现与交叉核验，无 SSH、生产服务变更、main 合并或正式 Registry 发布。[实施协议](P0D12-PRODUCT-SOURCE-TLS-PROTOCOL.md)。

## 实际证明

| 故障 × 签名格式 | 故障来源的实际观察 | 修正来源后的实际观察 | 正常停止后的真实持久读回 |
| --- | --- | --- | --- |
| CA × message-signature / dsse | 每格 2 条已关闭、非 stopping/timeout 的 TLS 尝试，0 HTTP；API 未确认，LastSuccess/Until 均 0 | 每格 1 次完整原 G1 HTTP 200，原产品进程自动 Fresh | 每格 G1/sequence 1、journal 0、audit 0、ledger 0 |
| SAN × message-signature / dsse | 同上 | 同上 | 同上 |
| SPKI × message-signature / dsse | 同上 | 同上 | 同上 |

六格合计 18 条真实来源连接、60 条原始事件：12 条故障连接与 6 条完整正常响应。每格是“首次刷新遇到故障证书→正常停止并 join 故障来源→启动另一正常来源→同一产品进程恢复”，不是先 Fresh 再出错。两个 phase 的目录、进程、ready 和日志独立，端口均为 5444；切换间隙不算 TLS 拒绝证据，来源无 TCP/TLS/HTTP 就绪探测污染。

公开原始证书由独立 OpenSSL 按两次 API 实际观察时间复算，禁用系统 CA 回落；另一子代理另写 Node X.509/Ed25519 校验，不导入本批 checker。CA 故障保持公钥和 feed SAN，仅更换不受信签发 CA；SAN 故障保持 CA/公钥，仅更换 DNS SAN；SPKI 故障保持正常 CA/feed SAN，仅更换公钥。固定产品 CA/pin/URL、三个实际 PID1 样本的 container/PID/startTime/二进制/两份配置摘要均相同。来源公有证书原字节、实际文件 FD/named 身份投影及私钥派生的公有 SPKI 交叉绑定；不导出私钥，不声称捕获产品自身 PeerCertificates 数组。

本轮故障来源的服务端 TLS 枚举实际均为 `failed`，但它不独立证明 CA/SAN/SPKI 的具体原因；归因来自单因原证书、固定产品配置、真实故障尝试、API 未确认与同进程正常恢复。不能要求未来 SPKI 故障必然在服务端显示 failed，服务端 TLS ok 但客户端拒绝 HTTP 同样可能成立。

每格初始和最终的实际信任逻辑记录 SHA、空审计原日志与 checkpoint 原字节摘要完全相同；只读重开核实没有 journal/audit/grant 预留或消费。24 个实际 driver 动作（六格 × prepare/reject/recover/reopen）各唯一。48 个真实 Registry 计数快照覆盖 6 个精确上传/正常 TLS 原字节读回准备窗口和 18 个零请求窗口，窗口之间无隐藏流量。7 个所属容器精确回收、12 个来源真实 SIGTERM/join exit 0、6 个产品正常 exit 0、Registry exit 0/no OOM/PID 0，最大同时所属容器为 2；私有树回收，保留外层镜像和原归档。

## CI 与原始证据

[绑定 CI 39883622207](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39883622207) / job `120186562390` 与[父 CI 39883621995](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39883621995) / job `120186561748` 均为同一完整提交、attempt 1、success；绑定全部步骤 success。artifact `12472735219`，名称 `image-binding-39883622207-1`。主代理及三名子代理分别下载 API 原 ZIP/日志并独立复算，没有改写原文件、重跑来替换失败或用新结论覆盖旧轮证据。

| 原始对象 | 大小或计数 | SHA256 |
| --- | --- | --- |
| API ZIP，匹配 GitHub metadata digest | 6,368,913 B；1470 个唯一安全平面文件；展开 15,547,657 B | `d3666820025a6784f064184e3c1094c06f2291f8bcea751001852ed65f460892` |
| 绑定 job 原 API 日志 | 2,027,249 B | `d743b7edd0f43e8c6510d7c544c63b98f008da9af428f3ef818db124633ee35f` |
| 父 job 原 API 日志 | 5,447,465 B | `925e29ff553344989da3129807960f16ce396950267c2ef508da90ea3e41ea12` |
| 新 TLS outcome | 114 个自有工件、117 条原输入摘要关系 | `d1385ea4521fd0809c1a0954ceae5757715d54835717e6c045402317eca7c7cf` |
| checkout-before/after 原清单 | 各 619 条、73,670 B，原 bytes 相同 | `3604805e9f9ef69b575229706d4c9e3ac482faead06c7937a29ab6b7d1fff23e` |
| module source-before/after 原清单 | 各 94 条、9,119 B，原 bytes 相同 | `d5b2a9ccc28595877c0630b128be02e69c627bee6c99f7c21039aeba44cb4472` |

713 条源记录合并后 619 个唯一路径，完整集合与该提交 Git 树中的 `chengwang/**` 加 `.github/workflows/chengwang-image-binding.yml` 受检范围一致，94 条 module 记录为其子集；不是整个 OpenClash 仓库的全量文件。每个摘要逐 `git cat-file --batch` 原始 blob bytes 比较，没有 CRLF 归一化。

镜像三个摘要角色严格区分：实际 PID1 二进制 SHA `43dbb7cf1595f2b905dd6a310f08c1cf2ce9e310d1de8b6573d0576252be1830`；本地 imageID/config 为 `sha256:f35bba4babccc37f765bd1aa9408199b3916e0161695b9874e7d6925001737c7`；隔离 Registry manifest 为 `sha256:0b0cdc3265afe28cf9c89c150e47ae0575a570cb2aa8f8e8d06067c137277498`。没有把本地 imageID 当成正式 Registry 来源或发布授权。

主代理原工件及外置重放记录位于 `%TEMP%/chengwang-source-tls-b8abe16-root-8ae1f7189caa4137a466c960bffef79f/`。A/C 独立目录分别为 `%TEMP%/chengwang-tls-b8-independent-ruRAVC/`、`%TEMP%/chengwang-tls-b8-independent-eby40220/`；B 为 `%TEMP%/chengwang-source-tls-b8-07e790b85cc44b19bcffbb20fc39688f/`。GitHub 工件保留 14 天，本地 Temp 也非永久/WORM 证据库。

## 回归与检查器验收

- 实际普通/race 各 728 个 Test run/pass，0 skip/fail；原 700 与完整 728 名字指纹分别为 `b3cd00ab4fd983026e777095b484e2a0e49b05867186a83df234b8a27b7bb999`、`6557b5f9621b6d691133c2242ab1c35308dfcd376424b43c6a9c2644830d0811`。新四 tag driver 不进入这个集合。
- 父普通/race 各 2320 个 Test、各 38 packages，0 Test skip/fail；主代理按每 package 的两次 start cycle 分别复算，指纹均 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`。Registry 普通/race 各 3，原浏览器 40/45/45、lease 20/feed 34 均保留。
- 原 Registry/lifecycle/crash/state/source 五门的 49/65/151/909/75 条关系独立 CLI 重放通过，与原 CI outcome 逐字相同；新增 TLS 117 也逐字相同。来源 fixture 前置仍是 24 个具名项及 32 个合成 checker 项，不冒充完整产品矩阵。
- 新 profile 8 项、新 checker 32 项在实际 Linux 各 0 skip，耗时 0.003s / 8.699s；32 项使用真实 OpenSSL 公共材料验签/证书验证，只有不可变合成输入模板构造缓存，验证结果不缓存。它们是合成检查器反例，不算 40 项产品业务。Windows 辅助执行耗时与 Linux 分开保留；唯一新增 CI verifier 总预算为 120s，没有放宽产品刷新、来源或 TLS 安全限制。

## 仍未完成

本批不证明已确认后的 TLS 故障陈旧/恢复、在线证书轮换、故障来源重启冷确认、完整 HTTP/帧/真实超时/hint/gap/fork/两类 64 与字节预算、实际 RESERVED 期间撤销及消费后独立屏障、长期 soak、正式发行/authority 或生产灰度。九项恢复 blocker 不解除，不能承诺可用率或零 bug。

完整产品还缺主动观测 API/工作台接线、订阅准入及完整可运行配置、设备发布/备份/读回/自动回滚、企业身份/多租户、DNS 数据面、多内核和其他闭环。测试门不能永久替代这些产品能力；下一产品切片见[真实探针只读接入协议（待实施）](P1-PROBE-READBACK-INTEGRATION-PROTOCOL.md)。
