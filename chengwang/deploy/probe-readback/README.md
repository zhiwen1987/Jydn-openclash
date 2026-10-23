# 真实探针只读链路：隔离实验

本目录属于澄网独立系统，不修改 OpenClash、爱快、DNS、Kuma 或任何生产设备。它不是部署脚本，也不发布 Registry 镜像。

## 分层验收，不能互相替代

1. `test_fixture_probe_wire.py` 检查固定 DoT/HTTPS 对端的真实 TLS、拒绝输入、预算和退出行为。Windows 上只有辅助形状检查，16 项 Linux 测试明确跳过，不能算原生通过。
2. Linux 专用 `probereadbacklab` tag 仅编译一个测试驱动。它准备 catalog/三套独立证书及只读身份，采集真实 writer 的原始字节，调用真实 API；它不直接追加 probe 结果、不打开 ledger writer，不属于普通测试基线。
3. `run_probe_readback.py` 负责新建私有网络、挂载与 PID 命名空间，让真实 `cmd/probe-agent` 生成结果，再启动真实 `cmd/server` 验证 fresh、重启后读回和自然过期。其成功只代表执行器完成，不能代替独立验收。
4. `check_probe_readback.py` 重新核对原始字节、摘要、runID/ledger start 关联、wire 时间窗口、API 投影和内核观测，单独输出检查报告，不覆盖执行器报告。

本阶段明确为 `NATIVE_BACKEND_ONLY`、`browserE2EProven=false`。完整的正常 TLS 浏览器端到端、真实互联网、正式镜像/Registry、设备灰度及生产恢复均未由此证明。基础接线既有验收见 [P1 证据](../../docs/P1-PROBE-READBACK-ACCEPTANCE.md)。新实验是否通过必须查看本次确切 commit 的原始 CI 工件，不能从文件存在或此说明推断。

## 固定实验边界

- 唯一实验目录：`/tmp/chengwang-probe-readback-<32 位小写十六进制>`。准备时必须为空；工具与公开证据在其外，私钥和 bearer 不导出。
- 新 netns 只有 loopback，独立挂载 `8.8.4.4/32`，没有外部网卡或默认路由。这个地址在封闭命名空间内使用，不是访问公共 DNS 或真实互联网的证据。
- 产品规则保持 HTTPS 443、正常证书校验、公网地址限制；不加入测试拨号后门、不使用 `InsecureSkipVerify`。仅在新 netns 将低端口起点设为 0；此 sysctl 的作用域是网络命名空间，宿主值须前后相同。[Linux 官方说明](https://www.kernel.org/doc/html/v6.18/networking/ip-sysctl.html#ip-unprivileged-port-start-integer)
- DoT、目标 HTTPS、管理 API 使用三套独立 CA。目标根只在 agent 私有挂载命名空间绑定到系统根文件；不修改宿主信任库，API 用明确的独立根验证。
- 检测目标固定为 `pass/restricted/limited`，间隔 60 秒、TTL 120 秒；实际回应为 200/403/429。403 是受限、429 是限流，不能显示业务正常。
- 真实 agent 恰好生成两轮、6 个结果后正常停止。先保存序列 7 的第一轮 ledger，再保存序列 13 的最终 ledger，联合验证 6 个原始结算关联；不能假定最终 ledger 保留所有第一轮 start。
- fresh/重启必须落在真实所有结果及各层的最早 expiry 前；expired 等最晚 expiry 后。不能改时钟、延长 TTL 或用理论调度时间代替实测。
- 对端没有收到 runID：只能按唯一目标和实际请求时间窗口关联 wire；持久化精确关联是 spool 的 EvidenceRef 与 ledger 的 StartID/ResultRunID。两者不能混称。

## CI 与证据

新增 workflow `Chengwang Native Probe Readback Lab` 使用固定 Go 1.23.12、父模块现有 vendor、禁用模块下载，编译真实 agent/server 与 tagged driver。对端 24 项原生前置检查和后端链路使用不同的私有 namespace。它不替代现有普通/race、镜像、Registry 或浏览器回归门。

后端工件为 22 个封闭命名文件：6 个驱动报告、6 个原始 API 响应、3 个 wire 文件、2 个源元数据文件、isolation/processes/runtime/cleanup/outcome。独立检查报告位于其外。必须保留失败尝试和原始工件，不能只保存最终 PASS 或手工修补证据。

退出码、正常 TERM 和实际 join 必须同时核实；超时、强制 kill、读取失败或未知状态均失败关闭。进程和文件系统检查是实验可信计算基的一部分，不是对恶意 root 或不可中断内核 I/O 的保证。

## 双浏览器扩展（实现候选，不是运行验收记录）

用户选择同时保留 Chrome/CDP 与原生 Playwright。`run_probe_browser.py` 复用原生实验的真实四个后端角色；默认原生 runner 的 hooks 为空，不改变其原 22 文件协议。扩展使用自己的 `browser-runner` 入口，不把它冒称原 standalone runner。

- 两条路径分别创建新的隔离实验，各自重新采集两轮 6 个结果、验证 API 重启与真实自然过期；不共用浏览器、证据或窄 fresh 时间窗口。
- 在线阶段仅获取锁定依赖和按大小/SHA256 固定的字体；实际编译、辅助检查、agent、API 和浏览器在没有外网出口的命名空间运行。不执行仓库安装 hooks，不访问生产。
- 真正构建现有 React/Vite 页面并通过真实产品 API 提供静态资源。API 使用 P-256 测试证书；DoT/目标证书保持原算法。不关闭证书验证或 CSP。Chrome 的 `--no-sandbox` 仅用于这套外层隔离 CI，不是生产部署建议。
- 浏览器专属挂载覆盖私有 `/etc/passwd` 和 `/etc/group`，配合 `XDG_DATA_HOME` 建立私有 NSS 信任库；不设置 `HOME`、不修改宿主 CA。Playwright 使用原生 `launchPersistentContext`，不是把 CDP 连接换个标签。
- 该专属 mount namespace 内用 tmpfs 覆盖 `/var/tmp`，固定 `TMPDIR=/var/tmp`，避免临时 Unix socket 路径过长；0700/10001:10001、64MiB、nosuid/nodev/noexec，降权前读回实际类型和标志，驱动再次核对所有权。既不修改宿主 `/var/tmp` 内容/权限，也不在宿主清空目录；挂载随 namespace 销毁。此启动修正须由真实运行验证，单元测试不是根因证明。
- 先预热浏览器，再等待 API-second 的真实 fresh 窗口；页面显示实际最新 3 个 runID 和 15 个层级，API 原始字节含 6 个样本。验证清除令牌和明细、匿名摘要、旧结论到期撤回、实际过期后 0 样本/3 个 unknown、桌面和移动端。
- Chrome 的真实等待结果由 `probe_chrome_launcher.py` 保存。关闭命令返回不等于进程退出；正常通过要求 Chrome 和 Node 实际退出 0，且未用强制清理获得绿色结果。
- 公开浏览器输出另在 `browser/`，包括 18 个固定 capture 文件、flow/driver/build/processes 四个记录，以及构建静态资源。令牌、私钥、完整页面 HTML 快照、profile、trace、HAR、storageState 和原始控制台内容不导出。静态构建的公开 `index.html` 不属于页面快照。

采样时最终后端验收摘要尚不存在，因此 capture/flow 始终标为 `API_CAPTURE_UNBOUND`、`runtimeProven=false`，不填占位摘要。完成原 22 输入和清理后，独立 `check_probe_browser.py` 才重新验证后端原字节，并把真实摘要、API、白名单 DOM、PNG、正常 TLS 链、实际静态资源、进程/挂载/参数和正常退出关联到单独的 `chengwang.probe-browser-runtime-gate/v1` 报告。既有纯合同 schema 不会升级成运行证明。

Node fake-driver、PNG 完整性和 Python mock 检查只证明辅助合同，不证明渲染、实际 TLS、真实退出或公网可用。是否通过必须看本提交两条 matrix 的真实结果与独立工件重放；构建来源属于受信 CI 输入，不是独立可复现构建或 Chrome 供应链证明。本扩展仍不授权生产挂载、发布、路由改动或互联网业务可用率承诺。

## 首轮失败与修正边界

`a8a5216` 的[首轮原生 CI](https://github.com/zhiwen1987/Jydn-openclash/actions/runs/39897368270)中，编译、44 项辅助检查、24 项原生 wire 前置检查以及实际 agent/重启/过期执行步骤成功，但独立 checker 拒绝了正常生命周期：已退出的 `api-first` 和随后启动的 `api-second` 复用了同一个 Linux mount namespace inode。历史 inode 数字不保证永远唯一；不能据此认定两个存活进程共用命名空间。

修正只涉及检查器及反例：每个 role 仍须独立于宿主/实验 init；实际并发的 wire/agent 必须分离；PID 唯一、启动顺序、正常 TERM/join 和阶段时序仍需核对。`/proc` 的 startTime 是 tick 而非纳秒，不错误要求两个不同 PID 的顺序启动一定跨过 tick。公开报告明确：退出顺序依赖受信执行器的有序 join 记录，不是独立退出时间见证。新增已退出 namespace 复用及同 tick 启动正例，并保留并发隔离失效、PID 复用、时序倒退和异常退出反例。修后对首轮原字节重放通过，不会把原 CI 的 failure 改称 success；新提交仍必须完整重跑。
