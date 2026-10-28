# 历史运维与变更索引（脱敏交接版）

## 1. 文档边界

本文仅从原工作区 `D:\codex-项目\clash` 的未跟踪历史资料中提取已脱敏的运维事实、路径和验证边界。原工作区未被修改。

必须按以下口径使用：

- 这些记录是 2026-10-23 至 2026-10-28 的时点证据，不是当前在线状态。
- “当时验收通过”只适用于记录中的版本、时间和测试范围；不能推导当前节点、容器、镜像、快照或备份仍存在。
- 容器 `healthy`、匿名 HTTP 状态或单次复测正常不代表真实 App/账号/业务长期可用。
- 历史备份、恢复脚本和快照只能在重新核对目标、散列、所有权和当前差异后使用。
- 本文不收录任何密码、Token、私钥、订阅地址、Cookie 或原始响应。

## 2. Grok App、网页与 Grok Bot

### 2.1 Grok App/网页独立节点池

历史记录显示，2026-10-23 对 `grok.com` 和 `x.ai` 子域实施了 Grok 独立业务组和稳定节点池：

- 候选节点先通过 loopback 隔离核心检测，没有为试节点而切换共享生产组。
- 历史验收中一条媒体线路连续超时，因此未加入稳定池；不应把“有节点名”写成“已验证可用”。
- 当时 Mihomo 语法、规则顺序、其他业务手动选择、容器 ID/重启数和 DNS/Kuma 进行了前后核对。
- 匿名 API `401` 当时只被用作链路可达证据，没有被写成真实登录或对话通过。

主要本地历史资料：

- `monitoring/lan-center/GROK-STABLE-20261023.md`
- `monitoring/grok-failover/严格验收-20261023.md`
- `monitoring/grok-failover/操作与恢复-20261023.md`

### 2.2 Grok 自动故障切换

同日的严格演练记录了一次真实受控切换：

- 仅向主节点的隔离检测通道注入 TCP 失败，没有停止或封锁共享生产节点。
- 历史控制链在约 121 秒内完成主到备切换；撤销注入后，主节点恢复也没有自动抢回。
- 用户当时分别确认 Grok App 和网页可登录并正常收到回复。这是时点业务证据，不是当前保证。
- 记录中保留了切换预算、冷却和人工接管边界；历史操作手册明确禁止通过删状态或改时间绕过安全上限。
- 演练后其他业务做过有限抽样，但记录本身明确没有将“其他生产业务完全无影响”判为全局通过。

### 2.3 Grok Bot 不等于 Grok 网站分流

后续隔离调查确认，Windows Grok Bot 0.75.3 在当时环境中还使用 Cursor/Anysphere 基础设施和云端电脑端点，不只访问 `grok.com`/`x.ai`：

- 当时 Bot 实际命中共享“人工智能 → 新加坡 URLTest”链，没有进入 Grok App/网页独立池。
- 历史证据保留过一次云端电脑连接的代理建连超时；这能证明当时那条链存在故障，不能解释每次刷新失败。
- 额外 HTTP/2 实验曾暴露测试执行器的标准输入阻塞问题；修正后的六次无首包也不足以单独证明 Bot 刷新根因。
- 历史提案是“只为该电脑的 Bot 建受控专用代理入口”，而不是修改 Windows 程序、系统代理或全网 Cursor 分流。该文档明确标为提案，当轮未部署。

主要本地资料：`monitoring/grok-failover/Grok-Bot隔离测试与最小修复方案-20261023.md`。

## 3. Google 单次失败与取证修正

### 3.1 无法事后证明的根因

2026-10-23 的只读调查确认：原验收包装层在远端命令非零退出时只保留异常类，丢失 curl 退出码、CONNECT/目标 HTTP 状态和耗时。同时，早于 11:20 的 OpenClash 日志已不在当时文件中。因此 11:04 那次 Google 失败的精确 DNS/TCP/TLS/代理根因不能事后确证。

当时的旁证显示 Google/gstatic 在其他采样点可正常返回，历史上又存在短时 TLS 异常后恢复的记录。这些都不能覆盖原失败。

### 3.2 当时已生效的取证补强

后续历史变更将 Google 专项监控改为与真实 Google 分流组一致的目标，并增加分层取证：

- 保存 curl 退出码、脱敏 stderr、CONNECT/目标 HTTP 状态、DNS/TCP/TLS/首字节/总耗时、源端口及单调计时。
- 首次失败在复检前落盘；403/429/451 不作快速重试，复检成功不会把首次失败改写成“未发生”。
- 当时隔离回归 31 项通过，真实 TLS 失败和 loopback 拒绝均能保留错误层次。
- 当时做过 Google 三轮和 Google/Grok/百度/ERP 对照复测，并用源端口关联内核日志/真实连接链。
- 历史记录表明，当时运行容器是原镜像加在线文件补丁，不是已重建到新镜像。后续任何 Compose 重建都要重新确认该补强是否已进入当前镜像。

主要本地资料：

- `monitoring/grok-failover/Google只读排查与修复建议-20261023.md`
- `monitoring/lan-center/probe-evidence/操作与验收-20261023.md`

## 4. 249 lan-center 历史

### 4.1 当时统一容器迁移

2026-10-25 的验收记录显示，249 上曾将 Kuma、CoreDNS、探测、节点能力评估和订阅服务合并到 `clash-center` 单容器，当时镜像标记为 `lan-center-unified:20261025-r2`。

当时的边界：

- 未合并 249 上的其他业务容器。
- 旧 Kuma/failover 容器停用保留，作为完整拓扑回退路径；这不证明它们现在仍存在。
- 历史入口保持监控、能力和订阅端口，DNS 保持 TCP/UDP 53。不在本文复制具体管理凭据。
- 切换时使用了自动化冻结、路由写锁等待、独立回退保护，最终验收后才解除冻结/停用发布回退定时器。
- 备份中的 SQLite 在当时做过完整性检查；拓扑回退保留实时数据，整库恢复需另行审批，不能用旧数据库覆盖运行库。

当时未能证明的事项包括：第二订阅的新节点业务能力、完整终端经爱快的来源身份、DNS/规则单一策略源、单容器故障域和长期资源优化。

### 4.2 249 历史证据路径

- `reports/lan-center/unified-20261025/验收说明.md`
- `reports/lan-center/unified-20261025/{build,backup,cutover,accept,inspect,fetch,lab,stage}.json`
- `reports/lan-center/container-rename-20261025/`
- `reports/lan-center/dpanel-20261024/docker-inventory.json`
- `reports/lan-center/system-audit-20261025/`
- `reports/lan-center/重复IP排查-20261026.md`
- `output/handover/openclash-dsh-grok-20261024/09-容器改名补充-20261025.md`

`cutover.json` 在原验收说明中只代表切换初检，不能代替 `accept.json` 的最终接受判定。任何历史 `accepted=true` 也仅对应当时镜像和数据。

## 5. 252 Lucky 与 ESXi 历史

### 5.1 Lucky 3.4.0 重启与业务边界

历史验收显示，252 的 Lucky 在当时已升到 3.4.0 并经过重启后核对：

- 当时 2 个 FRP 实例中的 10 个启用代理运行，3 个停用项仍保持停用。
- 当时原本正常的 7 个反向代理入口通过 HTTP/TLS 检查。
- 一个既有跨网段后端故障被保留为已知问题，没有被统计为通过，也没有为补库而修改其映射。
- 上述数量都是 2026-10-24 的历史读回，不代表当前仍相同。

历史验收回执路径：

- `reports/server252/snapshot-cleanup-20261024-201007/historical-acceptance-receipts/lucky34-reboot-acceptance.json`
- `reports/server252/snapshot-cleanup-20261024-201007/historical-acceptance-receipts/lucky34-production-acceptance.json`
- `reports/server252/snapshot-cleanup-20261024-201007/historical-acceptance-receipts/incident-cleanup-acceptance.json`

第三个回执只说明历史安全事件处理曾有验收记录，不得据此宣称当前 SSH/账号/系统无后门；当前安全状态必须重新只读审计。

### 5.2 ESXi 快照与恢复限制

历史记录把 ESXi 管理节点标识为 `10.88.0.250`，Lucky 虚拟机为 VM 50 / `10.88.0.252`。最后一次历史只读核对使用的快照引用为 `50-snapshot-7`：

- 该快照只包含虚拟磁盘状态，不包含运行内存，创建时未冻结应用文件系统。
- 快照与原虚拟磁盘共用数据存储，是回滚点，不是独立整机备份。
- 当时只核对快照存在、归属和当前引用，没有对生产虚拟机执行实际恢复演练。
- 更早的 `50-snapshot-6`、旧虚拟机副本、来宾机备份和旧恢复脚本在历史清理中已被删除，不能再引用旧手册恢复。
- 两台无关虚拟机曾出现名称字符编码显示差异；当时经归一化核对身份、磁盘拓扑和硬件状态一致，且没有修改这些虚拟机。

主要本地资料：`reports/server252/snapshot-cleanup-20261024-201007/`。

### 5.3 Lucky IP 地址库

2026-10-24 的历史补库记录：

- 当时新增/补齐 9 个条目，7 类格式取得非空查询结果，并对 IPv4/IPv6 样本分别取样。
- 当时 Lucky 进程未因补库重启，主程序散列不变；除 IP 库配置外，业务规则、FRP 和反代配置做了前后比对。
- 初版验收曾把动态流量计数误判成配置差异，因此一度移除新条目；修订后重新补回并依据持久化配置、进程和真实查询复验。
- 普通问题优先用“禁用新条目”做配置级回退，不删文件、不改 FRP/反代；整机快照仅作最后手段。
- 对 CZDB/LKDB 的历史 GitHub 检索未在已检查候选树中找到可直接使用的数据库文件；代码搜索不能覆盖所有 release 附件和历史状态，不能推导“GitHub 任何位置都没有”。缺少官方授权/配套材料的库不应从不明来源补齐。

主要本地资料：`reports/server252/ipdb-fill-20261024/`。

## 6. 历史交接包

`output/handover/openclash-dsh-grok-20261024/` 是一份面向 DSH/Grok Bot 的历史交接包，包含拓扑、节点判断、Docker/DNS 说明、只读清单、变更/回退模板、版本散列及机器交接提示词。

该包自身也明确了下列原则：

- 交接包的历史验收不是接手时的实时状态；接手人必须重新只读核对。
- DSH 和 Grok Bot 按“单一写入者”串行交接，另一方只读；不能同时修改路由、选择或回退点。
- 变更前必须记录当前散列、业务选择、节点/组定义、容器/数据库状态和 DNS 业务边界。
- 只有备份、回退、实际连接链和真实业务验证都成立时，才能把文件或服务存在升级为“已验收”。

历史 ZIP/PDF 只作本地归档。本文没有从其中复制凭据或原始生产信息。

## 7. 禁止直接上传 GitHub 的历史资料

下列文件/目录可能含有凭据索引、生产配置、订阅信息、SSH 材料、数据库、详细网络拓扑或原始 inspect/响应。它们只保留在本地权限受控目录，不得原样提交：

1. `output/handover/OpenClash-Docker-DSH-GrokBot-交接包-*.zip` 及其解压全量内容。
2. `output/handover/openclash-dsh-grok-20261024/06-账号与凭据索引.md`。
3. `output/handover/openclash-dsh-grok-20261024/{02-DSH接手提示词.txt,03-GrokBot接手提示词.txt,evidence-manifest.json,源码与版本快照.json}`；只能在再次脱敏扫描后选择性发布。
4. `reports/lan-center/system-audit-20261025/` 全目录。
5. `reports/lan-center/dpanel-20261024/docker-inventory.json`。
6. `reports/lan-center/unified-20261025/` 和 `reports/lan-center/container-rename-20261025/` 中的 `inspect.json`、`fetch.json`、`backup.json`、`local-before/`、Compose 或完整配置快照。
7. `reports/server252/snapshot-cleanup-20261024-201007/` 中的 `production-before.json`、`production-after.json`、`remote-backup-inventory.json`、`vsphere-*.json`、前端 JS/网页快照和数据存储目录清单。
8. `reports/server252/ipdb-fill-20261024/` 中的原始业务配置、上传记录、下载任务响应和详细运行时 JSON。
9. 任何备份压缩包、SQLite 数据库、`.env`、私钥、`authorized_keys`、`known_hosts`、订阅源、带 query 的 URL 和原始日志。

如需向 GitHub 公开其中的操作方法，应另行生成新的脱敏文档，只保留相对路径、操作语义、错误码和验收边界，不对原文做简单查找替换后直接上传。

## 8. 接手时的重新验证顺序

1. 先只读核对 249、254、252 和 ESXi 的当前身份、时间、镜像/版本、挂载、进程、端口和最近重启。
2. 将“历史记录”和“当前读回”分开保存，不使用历史 PID、镜像 ID、节点名、快照 ID 或容器 ID 作为当前事实。
3. 备份必须重新做存在性、权限、散列、SQLite 完整性及可恢复性核对；ESXi 快照另行标注“非独立备份”。
4. Grok App/网页、Grok Bot、Google、Lucky FRP/反代分别做真实业务验证，不互相代替。
5. 任何写入前先新备份、明确唯一写入者、建立限时回退保护，然后按当前代码和当前生产状态重新执行验收。

## 9. 与当前 0.3 交接的关系

历史资料可以帮助理解为什么当前设计强调 Candidate 隔离、分层取证、稳定 revision、实际读回、单一写入者和可回退部署；但历史 0.2/r2/Grok 脚本的运行状态不能代替当前 0.3 的最终镜像验收。

当前交接应同时阅读：

- `docs/handoff/acceptance-ledger-20261028.md`
- `docs/handoff/current-state.zh-CN.md`
- `docs/handoff/architecture.zh-CN.md`
- `docs/handoff/operations.zh-CN.md`
- `docs/handoff/work-log.zh-CN.md`
- `AI_HANDOFF.md`
