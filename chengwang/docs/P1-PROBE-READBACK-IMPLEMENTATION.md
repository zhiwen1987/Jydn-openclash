# P1 探针证据读回：实现与验收边界

2026-10-23。本批是默认关闭的只读产品切片，不是上线公告。生产、爱快、OpenClash、Kuma、DNS、设备执行器和 main 分支均不在本次变更范围。源协议见 [接入协议](P1-PROBE-READBACK-INTEGRATION-PROTOCOL.md)。

## 已实现

- 新 `probe.ReadStoreSecure` / `ReadCatalogSecure` 是显式 opt-in；旧 reader/writer 不改。Linux 通过持有目录 FD 的 NOFOLLOW/NONBLOCK/CLOEXEC 相对打开、UID/GID/权限/硬链接/前后 inode 与元数据检查拒绝不安全输入；实际数据仅允许 ext4/xfs/tmpfs，非 Linux 不降级到旧 reader。目录接收上限 4096，128 项分批枚举可能扫描到 4224 后拒绝，不能声称精确只扫描 4096。
- 后台单 worker 只读导入、聚合及发布不可变缓存；匿名 `GET /api/v1/probes/status` 不触盘、不列目标、不含身份或路径。`GET /api/v1/probes/details` 先做原有 TLS/身份/scope/ReadResource 检查，最多 256 目标和 200 全局样本，编码预算 1 MiB；不接受任意 query/path/主动刷新参数。
- TTL 同时受缓存年龄、结果和各层证据截止约束。正常到期、时钟回退、读失败均清除旧可用结论；轮询不续原证据 TTL。墙钟恢复需追平高水位并完成一次新的安全读取，不靠页面刷新恢复绿色。
- 工作台保留原导航与 Mihomo 被动层，独立新增“主动探针证据（只读导入）”。摘要不代表业务正常；受保护明细可以按目标展开分层，显示受限/限流/未评估与覆盖不足。令牌仅页面内存，变更/清除/刷新会取消旧请求；样本按完成时间及 runID 选最新，不依赖输入数组顺序。浏览器时钟回退后本页保守锁定未知，重开页面再向服务端读回。
- 所有能力仅 advisory，不触发测速、路由切换、配置修复或设备写入。P1 受控本地摘要不是 agent 签名、独立外部见证或节点整体健康证明。

## 配置说明（仅供后续隔离环境使用，未部署）

原产品服务显式设置以下环境变量；默认全部省略，关闭时其它 probe 字段必须为空/零，否则拒绝启动。启用时必须完整提供：

```text
CHENGWANG_PROBE_READ_ENABLED=true
CHENGWANG_PROBE_CATALOG_FILE=/private/catalog/catalog.json
CHENGWANG_PROBE_SPOOL_DIR=/private/spool
CHENGWANG_PROBE_POLL_INTERVAL=5s
CHENGWANG_PROBE_CACHE_MAX_AGE=30s
```

路径必须绝对且规范；轮询 1–60 秒，缓存年龄不少于轮询且不超过 300 秒。owner 固定为进程实际 UID/GID，不提供绕过开关。spool/segments 为该 owner 的 0700，segment 为 0600 且单硬链接；catalog 为同 owner 0600，或 root:运行组 0640（其近父为 root:运行组 0750）；常规 catalog 近父为同 owner 0700。祖先不允许组/其他写入，仅 root-owned sticky 1777 临时目录例外。不要把 group/world writable 路径或网络/FUSE 卷当受控存储。读取器不创建、不 chmod、不修复输入文件。

独立 image-trust 候选入口只接受 JSON 中显式可选的 `probeRead` 对象：`enabled`、`catalogFile`、`spoolDir`、`pollIntervalSeconds`、`cacheMaxAgeSeconds`；不从宿主环境继承。对象省略时保持原私有配置 JSON 不变。此说明不授权发布/挂载/启动候选。

## 本地证据与 CI 门

本地 Node 25.2.1 / npm 11.6.2；实际安装 React 19.3.1 / Vite 8.3.4，未更新依赖锁。110 个前端单元测试通过（原 77 + 新 33），lint/build 通过。UI/React 技能用于清晰空态、可访问标签、取消与竞态清除、TTL 降级；Browser plugin not available，因此使用现有 Playwright，在 1440×1000 与 375×900 渲染，展开样本、清除令牌、验证无横向溢出/无 pageerror。浏览器输入为明确合成 fixture，不是服务端/真实探针证明；初次未拦截 API 的页面请求失败不计为真实服务可用。

新增 71 个父模块具名 Linux 测试（secure reader 32、provider 19、API 10、runtime 10）；子模块新增 4 个显式配置测试。它们尚待真实 Linux 普通/race/vet 结果，不能从源码存在推断已通过。CI 要求新增 exact 名单，并原样保留 2320/728/700 历史名单与哈希；Python 闭集反例只验证门本身，不替代 Go 执行。

Windows 不运行 Go build/test/mod/download、Docker 或 WSL。仅 gofmt 和本地前端/Python 检查。实际 Linux CI 结果必须另行读回并记录。

首次开发提交 `8f2a32c` 的父 CI `39889973028` 失败，不能计为验收通过：安全 reader 的 32 项已执行 30 pass、2 个 catalog fixture fail，另 runtime 正例未能监听；race/vet 尚未运行。定位为这些新测试用 `t.TempDir()` 后未显式设置 catalog 近父目录 0700，不能假设临时目录天然私有。修正限于测试准备目录的权限前置，保留生产 custody/文件系统/超时/全部断言；下一提交仍需重新跑完整 CI。前端门额外锁定旧传输测试全部 36 个实际名称，保留原 28 名历史哈希，关闭原 8 项只按前缀排除的改名缝隙。

## 尚未完成

1. 新能力的真实 Linux 普通/race/vet 与原始回归读回（提交时待执行）。
2. 真实 probe-agent 经正常 DoT+HTTPS 产生 spool/ledger，再由主 API 经正常 TLS 与浏览器读回原 runID、catalog、各层结果，以及重启和原始 bytes 不变的端到端实验；现有 native 测试只覆盖 reader/runtime，不冒充这个闭环。
3. 真实设备部署、生产挂载/真实外网目标、灰度观察、回滚演练与运营监控。完整系统其它缺口仍见 [能力缺口审计](SYSTEM-COMPLETION-GAP-AUDIT.md)。

取消仅在受控本地文件系统的系统调用之间协作检查；NONBLOCK 防 FIFO 阻塞不等于可以硬取消任意损坏磁盘或内核 D 态。worker 未实际 join 必须报告失败，不可把遗留 goroutine 或强杀当正常退出。任何“零 bug”“100% 完美”或端到端高可用率都不属于本批证明。
