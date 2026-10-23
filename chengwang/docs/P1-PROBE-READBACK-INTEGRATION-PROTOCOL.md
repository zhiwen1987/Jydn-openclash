# 下一产品切片：真实探针只读接入

最新状态：基础接线及原镜像回归见[2cf4a34隔离验收](P1-PROBE-READBACK-ACCEPTANCE.md)；真实 agent→API/重启/自然过期见[700ea9e后端隔离验收](P1-PROBE-NATIVE-BACKEND-ACCEPTANCE.md)。正常 TLS 浏览器读取真实样本仍未完成，未上线。以下“尚无接线”“尚未运行实验”等是原b8abe16设计基线，不能当作当前源码现状；当前进度见[台账](PROJECT-PROGRESS-LEDGER.md)。

状态：基础只读接线已实现于开发分支，Linux/真实探针端到端验收尚未完成；详见 [实现与证据边界](P1-PROBE-READBACK-IMPLEMENTATION.md)。本协议不是已上线声明。2026-10-23 原设计以 `b8abe163fdd40f0dffe327c97989cf6f858fb762` 源码为基线；本批未启动真实探针、配置网络或改生产。它推进真实控制台能力，不替代尚未完成的 TLS/撤销/完整来源与恢复测试。[完整能力缺口](SYSTEM-COMPLETION-GAP-AUDIT.md)。

## 原设计时核实的落点与不足（b8abe16历史基线）

- `internal/probe/reader.go` 的 `ReadStore` 已有只读格式/摘要/目录代次/未来时间/过期/重复 runID 检查；默认允许目录条目上限 4096、总字节预算 64 MiB、单项 64 KiB，最终只返回全局最新最多 200 条。目录按 128 项批次枚举后才检查超限，默认限额的超限检测可能枚举至 4224 项后拒绝，不能把接收上限称为精确扫描步数。`catalog.go` 最多 256 个 target。因此 200 条不是每业务的完整证据，`Healthy=true` 也不等于所有业务已测或可用。
- `aggregate.go` 按 catalog/agent/P1/probe/path 隔离，只给 advisory 结论；2 次连续成功/3 次明确传输失败才越过滞回门槛，403/429 不应被当成正常，过期或未来结果应为 unknown。摘要不是 agent 身份签名，也不是独立外部见证或节点整体健康。
- 当前 reader 的分段读取是 Lstat→os.Open→SameFile，没有 fd-relative NOFOLLOW/NONBLOCK/取消契约；只读目录检查也不验证 owner/mode。静态 symlink 被拒绝不等于恶意同 UID 路径/FIFO 替换已证明有界退出。接入前必须明确 custody；若支持不可信存储，须先实现原生安全读取及对抗反例，不能借接口接线宣称这一边界已解决。
- `internal/serverruntime/runtime.go` 尚无主动 probe spool/catalog 接线；`cmd/server/main.go` 不注入 trust backend。`internal/api/server.go` 的 observation API 仍是 Mihomo 被动观测，`internal/observation/collector.go` 的节点/互联网/业务/DNS 层仍 unknown。snapshot 仍明确 demo，publish 仅版本存储，operations 明确无设备 executor。

## 要交付的产品能力

1. 新只读 probe view 组件与默认 disabled 的独立配置，不覆写被动 Mihomo 观测语义。明确本地受控 spool 的 custody/所有者/权限/目录与文件读取边界，失败关闭，不创建或修复用户 spool。对恶意输入的安全读取、超时/关闭能力必须由原生测试证明，不能假定普通文件读自带可取消语义。
2. 后台单 worker 有界读取、验证及聚合后发布不可变 snapshot；匿名 status 只读固定成本缓存，不触盘、不扫描、不枚举 target，不含 probe/path/catalog ID、URL、文件名或错误原文。有效期受缓存年龄及最早证据到期约束；到期或时钟回退即保守 unknown，不靠重复读取延长 TTL。
3. 受保护 details 先执行现有身份、scope、TLS 和 `ActionReadResource` 检查，再读取脱离内部可变对象的有界安全投影。最多 200 条保留结果，catalog 缺失目标须补 unknown/覆盖标记；不输出 URL/body/header/ReadIssue.File/raw error。端点名、DTO 与错误枚举实施前冻结，不虚构已存在 API。
4. 区分 partial coverage、正常 TTL 过期、读取/限额/格式/摘要/代次拒绝及 clock invalid。`TotalEntries` 包含无效和过期项，不能用它减 Rejected 猜测截断前有效数；若需要精确 truncated，先给 reader 加真实计数。用固定一次 now 贯穿读取/聚合；回拨检测比较 wall UnixNano 高水位，不能仅依赖带 monotonic 的 `time.Time.Before`。
5. 工作台展示真实来源、观测时间、TTL、覆盖不足与未知原因，并区分进程、控制器、DNS/连接/TLS/HTTP/业务证据。配置缺失或权限不足要可解释，不把 demo、“尚未评估”和“访问失败”合并成绿色；不从 P1 单路径结果推断节点整体能力，也不自动切节点。

## 独立验收

后端需覆盖 disabled 零 I/O、匿名固定成本/无 details 调用、身份/跨 scope/明文凭据先拒、snapshot 深拷贝与并发/race、TTL 边界/墙钟回退/未来与过期、2 成功/3 失败及 403/429、catalog/agent/path 隔离、200/256 覆盖不足、受控及恶意 spool 边界、原 bytes 不变和 shutdown worker 退出；公开的 assurance 等级必须与实际证明一致。

实际端到端不得只靠 seed 或 mock API：在新独立自有 UUID/netns 内，真实 probe-agent 经固定正常 DoT 与 HTTPS 目标写入真实 spool/ledger，正常停止后主 API 只读导入，经正常 TLS 请求和浏览器读回原 runID/catalog digest/各层状态；再检查原 spool/ledger bytes 未改。旧 runner 的 127-only 网络证明不能复用为新拓扑证明。

现有地址策略拒绝 loopback/private/documentation IP，HTTPS 目标默认用系统根池，`--dot-ca` 只供 DoT。候选实验需独立设计无外部接口/default route 的 netns、单个合法 GUA /32 及固定 DoT 返回；临时 CA 若使用，只能在该实验私有 mount namespace 做只读信任绑定并核对实际 profile，不改宿主根、不跳过主机名、不放宽产品 IP 规则。上述拓扑、真实 DoT wire helper、进程/出口/请求预算和退出门均尚未实现。

前端必须真实 API/正常 TLS 浏览器验收，覆盖空态、过期、受限、部分覆盖、权限和移动布局；合成反例和真实目标证据分开。生产挂载、真实出站目标、canary 及任何设备写入仍须另行授权，先备份并有回滚。订阅完整配置与实验设备发布闭环是后续产品切片，不因本协议或 TLS 子门通过变为已完成。

## 双路径浏览器验收决定（2026-10-23，未完成）

用户已选择 Chrome/CDP 和 Playwright 两条路径都做；这是两种自动化路径，不是已经完成跨浏览器引擎兼容。当前环境 `Browser plugin not available`，采用普通 Playwright 路径，并保留独立 CDP 的网络/TLS 证据；不得把 CDP 写成已运行 Playwright。

当前新增的共享投影契约只能产出 `CONTRACT_VALIDATED_ONLY`，`runtimeProven=false`、`browserE2EProven=false` 固定不变。独立 CI 工具包锁定 `playwright-core@1.64.1`，与原 `web/package-lock.json` 分离；预检仅证明已安装接口、合成合同和源码不变，不启动浏览器，不属于下面的真实验收。

后续实施按以下退出条件执行，不能用预检或旧浏览器 trust 门代替：

1. **两个独立、有界实验。** 每条路径各自产生真实 agent 的 6 份结果，使用同一候选源码和既有正常 DoT/HTTPS 约定；不把两次完整浏览器串进同一个短新鲜度窗口，也不延长 TTL 掩盖超时。保留原 backend 的 22 输入及 `NATIVE_BACKEND_ONLY` 声明；浏览器原始响应、投影、截图、进程及退出证据放在独立兄弟目录并由新运行态检查器关联。
2. **真实主服务托管真实构建。** 必须用 `cmd/server`、明确只读的 `CHENGWANG_WEB_DIR` 和已核对哈希的构建目录，不能用 Vite、WebFactory 或 mock/fetch 拦截替代。构建与浏览器预热在 agent 前完成；没有修改当前 backend runner 的 14 项 server 环境闭集来假装它已支持静态目录。
3. **普通 TLS 和隔离身份。** 每条路径独立 profile/NSS，验证 CA、叶证书、IP SAN 和实际浏览器 TLS 链；不跳过证书、不改宿主信任，不复用旧 helper 的 `/trust.html`、身份或负端点字段。新实现不得重设 `HOME` 等系统变量；私有 NSS 的发现与 legacy 库隔离仍须在真正运行前验证，当前未完成。
4. **真实交互。** 从主站进入“代理节点”，填写 `#probe-token`，读取受保护明细、展开三个目标，核对真实 catalog、三个最新可见 runID、十五层状态及 HTTP 200/403/429。六条原始 runID 应由浏览器实际收到的公开 API 字节独立关联，不能声称页面显示了全部六条。桌面与 375px 视口检查溢出、控制可达、页面标题、错误覆盖层和 console。
5. **清除与自然撤下。** 点击“清除明细与令牌”，确认输入为空、详情卸载、URL/storage/cookie 不含身份，下一次匿名摘要没有 Authorization；再真实读取并保持同一 API-second/页面。禁止修改 DOM、时钟或用 API 重启故障制造撤样本。页面截止为缓存年龄与最早原层 TTL 的较小值：只有实际截止等于原证据 TTL 才可称 `EVIDENCE_TTL`，否则仅称 `CACHE_OR_EVIDENCE_DEADLINE`。随后等全部原 TTL 过期，实际刷新读回 6 expired、0 samples、3 unknown。
6. **最小公开证据与清理。** 不导出整页 HTML、请求头、输入值、trace/HAR/profile 或 bearer。只允许公开 API 原字节、白名单 DOM/网络投影、截图和哈希引用，且须独立核对原始文件，不靠调用者传入 `true` 自证。每条浏览器进程组均须关联 PID/start ticks、正常关闭/join、精确清理；任一路失败都不得记录双路径通过。

相关上游依据：[Playwright Library](https://playwright.dev/docs/library)、[浏览器版本与安装边界](https://playwright.dev/docs/browsers)、[Playwright 的 CDP 连接边界](https://playwright.dev/docs/api/class-browsertype#browser-type-connect-over-cdp)。本段是已选定的实施合同，不是运行结果或生产授权。
