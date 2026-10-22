# P0-d12 真实镜像自动刷新子门验收（2026-10-23）

结论：本子门已在隔离 Linux CI 实际运行并独立复算通过。它补上自动刷新、撤销、来源陈旧/恢复和正常重启的镜像内证据；不是 D12 完整异常恢复矩阵完成，更不是生产上线。没有修改产品运行逻辑、生产配置或设备，没有合并 main。

## 1. 接受的版本和证据

接受代码为 `957271a855fa19991b77ebd5b1d2a8e4200c0aa0`。后续文档归档提交不是另一份已验运行镜像。

- [绑定 CI 39840587359 / job120040237746](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39840587359/job/120040237746)：completed/success。
- [父 CI 39840587362 / job120040240510](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39840587362/job/120040240510)：completed/success；两条运行的 head 均为上述代码。
- GitHub 工件 `12453206957`，`image-binding-39840587359-1`，217个文件；API 返回 ZIP 大小4,297,396B、SHA256 `028f2261f77deea86262592a74124dddaf0b2205a74aff494ee4381ec7aaa561`。保留期14天，不是永久灾备。
- 主代理下载的原始 job API 日志：1,807,887B，SHA256 `5994305dd443022b8f3b5038ad5113b74ca9377cd2b56806ed1c4ab0cebdc4dc`。父 job 原日志：5,447,333B，SHA256 `f5c1eba3c47a07ee8096a71df76b52afa4fd286530fc29f5791b2aa25515946d`。
- 主代理和独立子代理各自下载工件；新 checker 重算64个本门文件、65条输入摘要关联，均与已归档 outcome canonical 内容相同。outcome SHA256：`7aef2361d473f7cbe7739c3c28c0100d6df756ab3d9a03a73b4809f149efc686`。

主代理临时副本：`C:/Users/Administrator/AppData/Local/Temp/chengwang-d12-product-957-eb1ed3ebcb914faaa852441891e5b96e/evidence`。它是开发机验收副本，不是生产目录或持久备份承诺。

实际身份分别为：

| 角色 | 本轮值 |
| --- | --- |
| 产品二进制 SHA256 | `8b46208b7ef958e223e4587fa0588710187b29e5616b74a7b59ac30cb41a2f4e` |
| 本地 imageID / config digest | `sha256:8128ef3d1314994c634ec4f10b5272e355acda79254fd5045574f7d86524a1e9` |
| Registry manifest digest | `sha256:4af861a6fcdd6224b06a6c24bd14a6ce41dbe80664cfa5b5711674b36483d7bc` |

三者不能互换。实际 CI 读取私有 graph 原字节；验收者下载的是安全投影及其关联证据，没有下载私有 archive、签名私钥或完整 graph。本轮仍非独立 builder attestation / SLSA 来源证明。

## 2. 实际执行的产品链

MessageSignature、DSSE 两类签名各18个串行动作，复用本轮真实产品镜像、正常 CA/SAN/IP/SPKI 来源、真实 Distribution Registry 和真实产品 API；不在产品中增加 fault HTTP/env/config 开关，不以直接调用 backend 或管理员 PUT 代替自动刷新。

| 场景 | 实际结果 |
| --- | --- |
| 来源未确认、实际来源503后验证 | 503；不消费、不产生领域操作、不读镜像 |
| 来源自动发布 cat2，撤销 B | 产品自动 actor `image-trust-refresh` 更新到 generation2；B 验证被拒绝 |
| 精确同代 no-op | freshness 真实推进，领域序列、历史和消费记录不变 |
| A 验证及重放 | 首次消费成功，原请求重放被拒绝 |
| 来源持续503 | 等真实 freshness 期限到期后验证503；不修改系统时钟，不放宽产品限制 |
| 恢复同一 cat2 | 经真实来源 GET 重新确认；没有伪造 Confirm |
| 正常停止、重开两库、同容器重启 | cat2、撤销及已消费 A 保留；内存 freshness 归零，未重新确认时拒绝 |
| 重启后重新确认、旧 A / 新 C | 旧 A 仍拒绝；C 首次成功、重放拒绝 |

每种签名首次重开为 seq18 / generation2 / journal4 / audit8 / ledger1；最终为 seq31 / generation2 / journal7 / audit14 / ledger2。检查器从实际 prepared/result 安全事件重算 actor、scope、请求摘要、receipt、哈希链、checkpoint 和 ACK，并要求首次历史及 A 的烧毁记录在最终历史中原样保留。

独立 Registry 计数共有72个 before/after 快照；4个成功验证窗口各有真实镜像读取，30个其他非准备窗口增量为零，准备上传/读回单列。不能把来源 HTTP 请求数当作 Registry 镜像读取数。

本轮两类 source 各18次完整响应，均0次未完整响应；不硬编码轮询总数或跨 epoch 完成顺序。停止前后保存源日志原始前缀 count/SHA，两类签名的停止窗口均没有新增事件。**这不证明本轮实际触发了在途请求取消。** 对窗口内未完整响应的拒绝/独立计数规则有合成测试，但不冒充本轮已发生的产品故障。

## 3. 隔离、清理和回归

- source 私钥、plan、body 和日志位于独立 `root/source/<kind>/feed`；不在产品的三个挂载中。产品仅取得来源 public CA 和固定端点身份。
- 产品实际 PID1 为默认 `/app/image-trust-api`；UID/GID10001、capability 全零、NNP、只读根、精确三挂载、网络仅共享隔离 Registry loopback，资源限制不放宽。
- source 的实际 PID/startTime、祖先、独立 mount namespace、UID/GID/capability、解释器/脚本摘要及六项资源限制经 `/proc` 核对。正常停止用持有的 pidfd 定位，必须 join/exit0，不把紧急回收当正常验收。
- 4次产品正常停止和1次 Registry 正常停止均 exit0；精确清理3容器、2来源进程及本轮 UUID 私有树，保留外层待清理镜像。`product-lifecycle-runtime-cleanup.json` SHA256 `2caba6f480ca7444f3ef9cfe89d134cbd6023d5f2c4348ae0a45a6a517a5ab25`。外层 D10 清理也通过。
- 前置门仍独立保留：lease20/20、feed34/34、checker13/13、零跳过。feed 比605历史轮新增一个真实 Linux 固定端口顺序重绑/活跃监听排他测试；未删除旧33项。前置 cleanup 原始摘要仍为 `3363e8b13e08abee4f08c96eff4db5f3bffde39a60f4873bb29325b9b2a05e05`，未被运行清理覆盖。
- 新 profile5项及新 verifier27项均实际通过、零跳过，属于合成/检查器测试，不是32次产品故障。
- 原 D11 49条关联独立重放通过；其 outcome SHA256 `6e3f227667ee280b12b7ca02b31e11c2df3af71425a7c563bb6192ee663523b5`。原子模块普通/race各700、Registry普通/race各3，浏览器40/45/45检查均保留通过。
- 父普通/race各2320个完整 Test* 名称 run/pass 一致、零测试跳过/失败，集合 SHA256 均为 `fe56888dcace3a596e76409a6c63b83c9f68ef57ef4921d34577c6a11bd112e8`。无测试的 `internal/domain` 包不是被跳过的具名测试。
- checkout574 + child81 = 655条源码记录、574个唯一路径：before/after 原文件完全相同，主代理与独立子代理逐 Git 原 blob 重新核对；不做 CRLF 归一化后冒充原始字节。

原前置报告仍写 `actualProductLifecycleProven=false` 等字段，因为它只证明 fixture prerequisites；新的运行报告单独写 `actualAutomaticRefreshProven=true`。两份报告范围不同，不回写历史结果，也不合并计数。

## 4. 仍未完成

本次只接受自动刷新/正常重启子门，以下仍待真实镜像验收：

1. PREPARED、RESERVED、CONSUMED 等边界的外部屏障、精确异常终止、跨库审计补投递与二次重启幂等；lease fixture 尚未接到这些产品故障边界。
2. update/verify × 六阶段 × 两签名的健康中间态恢复矩阵，以及缺失/冲突/坏前缀/scope/checkpoint 损坏的启动拒绝。
3. 多代追赶、缺代、同代分叉/回滚、坏签/过期来源、来源 CA/SPKI 失败及在途刷新/撤销竞态的真实产品矩阵；不能借用独立 feed 测试冒充产品已验。
4. 物理掉电、坏盘、整盘回滚、WORM/外部见证、长期 soak、企业正式密钥/IdP/审批、正式 Registry 发行、独立 builder/source 证明、多架构和生产灰度。
5. 原完整企业功能、九项恢复 blocker、多内核真实写链、DNS/业务网络数据面等既有缺口。

所有测试 authority 为 `EPHEMERAL_TEST_ONLY`，仍 `authorization=BLOCKED / releaseAuthorized=false / production=false / deviceActionsExecuted=false`。不承诺免维护、零 bug、全系统完成或任何“多个9”的端到端可用率。
