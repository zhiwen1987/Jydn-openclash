# e282 后续研发门与能力事实卡 v2

## 更正与范围

本卡取代但不覆盖冻结 v1。v1 的 G1 将“运行验收尚未发生”误写为“正常模式场景装配尚未实现”；该句已在独立纠错回执中标为拒绝。

本卡只核 committed HEAD `e2829f8b81ea4c31839791983e7893ddb80d4820`。没有运行 Go、浏览器、服务或网络，没有修改 formal。`LIVE-TASKS.md` 只用于剩余范围索引；实现判断来自实际源码、workflow 和 checker。

## 三个后续真实门

### G1：已有 joint 场景的同 HEAD 真实运行与独立验收

状态：`IMPLEMENTED_SOURCE_NOT_RUNTIME_ACCEPTED`，不是“缺最小装配代码”。

已实现：

- workflow 固定 ref、Go 1.23.12、source contract/checker SHA，先跑 CPU/完整 Go，再只构建一次 `cmd/server`（workflow `:24-40, 41-80, 89-100`）。
- `run_joint_control_plane.py` 在正常产品配置中明确设置 subscriptions、双写门、refresh、live overview、Mihomo 只读端点，并设置 `CHENGWANG_MIHOMO_LAB_ENABLED=false`（`:105-110`）。
- B0 建立真实身份/RBAC、两来源、批准、抓取、准入和回执（`:164-180`）；J1 启动 refresh worker，覆盖成功与 503 失败、worker receipt RBAC、overview、Mihomo status/runtime RBAC 和传输负例（`:181-200, 211-227`）；R2 以同一 binary 重启并读回主订阅库和回执（`:201-210`）。
- runner 记录 PID/start ticks、binary SHA、namespace、唯一 listener FD，验证正常 SIGTERM 和端口退出、fixture listeners/threads 清理、三 epoch 同 binary、无残留（`:23-47, 119-145, 228-239`）。
- namespace wrapper 使用独立 mount/net/pid namespace、无默认路由、uid/gid 10001、零 capabilities/no-new-privileges（`ci_namespace.sh:1-53`）。
- 独立 checker 重建 source snapshots、证书、captures、RBAC、refresh DTO/receipts、overview、Mihomo wire、transport negatives、主库重启读回、私密材料不发布，成功才输出 `runtimeAcceptanceProven:true`（checker `:84-250`）；第二 job 下载公开原件并重放 checker，要求 verification 字节相同且 git clean（workflow `:132-153`）。

仍缺验证：当前没有可接受的同 HEAD 场景运行原件；控制事实指出 Go 阶段受阻，因此不能把源实现、40 个 source models 或 workflow 定义写成 E2E 已执行。必须取得真实 scene artifact、原 checker PASS、independent replay 字节相同、source before/after 同 HEAD，且失败记录保留。

源码明确不证明：`contract.outcome` 固定 `deviceActionsExecuted:false`、`lifecycleLabProven:false`、`realBrowserProven:false`、`production:false`、`actualSKUObservation:UNKNOWN`、`authorization:BLOCKED`、`refreshRestartPersistenceProven:false`。因此即便该 lane 后续通过，也仍缺 joint real-browser/DOM 证据和 refresh sidecar 真正启用后的重启恢复场景；它只接受隔离的正常 `cmd/server` 业务 E2E，不是生产或完整系统验收。

发布：无。此门通过后只能得到精确场景的隔离 runtime acceptance。

### G2：sealed archive A1 源取得与文件系统发布

状态：`A0_IMPLEMENTED_SOURCE_A1_NOT_IMPLEMENTED_OR_ACCEPTED`。

已实现：`sealedArchiveV8Input` 的源码合同明确只有 caller-frozen 内存值，且“no path, store handle, clock, random source, selector, or activation authority”（`sealed_archive_a0.go:13-23`）；`sealedArchiveV8Plan` 明确是 pure-memory byte plan，不能推导 filesystem publication、activation、capacity release 或 runtime state（`:60-71`）。A0 已有 build/verify、canonical wire、limits、history 和 tests。

仍缺实现：A1 必须另行拥有受信源取得、dirfd/类型/owner/名字复核、临时和最终对象写入、no-replace 原子发布、文件与目录 fsync、cleanup/失败保留、activation/capacity ownership。这个结论来自 A0 类型和注释的正向边界，不是单凭文件名搜索。

仍缺验证：Linux 实际文件系统、EEXIST/mismatch/orphan、多 crash cut、readback/replay、历史链、峰值临时预算和外部 witness。A0 source/Go 通过不能代 A1。

发布：未激活、未释放容量、未上线。

### G3：把已实现的隔离 Mihomo lifecycle 转成正常产品 authority/executor

状态：`LAB_EXECUTOR_IMPLEMENTED_NORMAL_PRODUCT_AUTHORITY_NOT_IMPLEMENTED_OR_ACCEPTED`。

已实现：不是“完全没有 executor”。`LabBackend` 有 Create/Inspect/Approve/Execute/Revoke（`mihomodeploy/lab_backend.go:20-29`），`LabService` 持有 authority、runtime、store、artifacts、kernel、recovery 等真实隔离生命周期组件（`lab_service.go:21-60`）。

明确边界：`LabBackendBoundary` 是 `OWNED_ISOLATED_MIHOMO_LIFECYCLE_NOT_PRODUCTION_OR_FULL_PAYLOAD_PROOF`（`lab_backend.go:11`）；lab proof 强制 full payload、Internet business、production 全为 false（`api/mihomo_lab.go:87-89`）；lab authority 自称“not an execution permit”（`lab_authority.go:16,31-34,97`）；server 配置还拒绝 lab 与 subscriptions/probe/live overview 同开（`serverruntime/mihomo_lab_runtime.go:49-60`）。

仍缺实现：正常产品模式下由真实企业 authority 驱动的 device publisher/executor bridge，而不是删除 lab 边界。能力注册表仍把普通 Mihomo 设为只读（`capability/registry.go:61-78`），operation control 只记录计划/审批/预检、不执行设备动作（`:108-118`），`router_publish` 仍 design-only（`:253`）。

仍缺验证：正常产品 RBAC/authority、幂等与重放、UNKNOWN 对账、配置和运行态 readback、回滚、崩溃/断网、重启接续、完整 payload 和业务证据、容量浸泡。随后才进入签名发行、授权灰度和生产读回。

发布：无；生产控制仍为 false。

## 企业系统仍未关闭的事实

- source-implemented 但仅本地/隔离：joint B0/J1/R2、A0 pure-memory archive、Mihomo lab lifecycle、本地订阅准入/refresh、静态 Bearer、单机 evidence/operation stores、Mihomo 只读 observation、bounded probe import。它们都各有源码边界，不能合并成企业上线。
- registry 明确 design-only：router publication、subscription orchestration、DNS execution、防泄漏、完整 active business probes、automatic repair、multi-kernel runtime（`registry.go:253-258`）。
- registry 明确企业缺口：单机 evidence 非 WORM/独立副本（`:81-94`）；静态 Bearer 非会话/MFA/SSO/轮换（`:96-105`）；operation 单控制器且无设备动作（`:108-118`）；observation 不测互联网/DNS/业务且不切换/修复（`:121-132`）；probe 无启动/调度 agent API（`:135-146`）；subscription 无完整节点评估/数据面应用/生产验证（`:149-180`）。
- SYS-01–06 的全页面/API/运行态对账、异常矩阵、B01–B23、自动订阅编排、完整配置/DNS/出口一致性、Mihomo 完整故障和生产灰度未关闭。
- SYS-07–19 的 sing-box/Xray、正向代理服务、自建协议、DNS 数据面/防泄漏、完整业务探测和策略池、网关、零信任、多站点、自动修复、AI 受控执行未实现或未验收。
- SYS-20–25 的 IdP/SSO/MFA/多租户治理、统一审计遥测、告警、完整 UI、HA、供应链签名/撤销/正式发行未完成。
- SYS-26–30 的整套恢复、容量/故障/浸泡、授权灰度、生产读回、升级回滚和运营手册未完成；灰度和生产读回仍须明确授权。

无总体百分比；无任何“根本没运行却写绿”的结论。
