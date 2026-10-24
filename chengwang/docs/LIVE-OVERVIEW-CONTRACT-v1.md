# 实际证据总览 v1：冻结接口与验收边界

Go seams:
- ObservationStatusSource interface { Status() observation.Status }
- ProbeStatusSource interface { Status() probeview.Status }
- SnapshotProvider interface { Snapshot(context.Context) (PublicSnapshot, error) }
- Config { Mode string; Observation ObservationStatusSource; Probes ProbeStatusSource; SubscriptionConfigured bool; Now func() time.Time }
- New(Config) (*Provider, error), Validate(PublicSnapshot) error, ErrInvalidProjection sentinel.
- API: func (s *server) overview(w http.ResponseWriter, r *http.Request), root wires options.Overview and exact /api/v1/overview route.
- Constructor has no Status calls. No details, refresh, upstream, inventory backend, storage, goroutines or network/disk capabilities.

All JSON fields REQUIRED; pointer fields encode explicit null, never omitempty.

PublicSnapshot:
 schema: exact chengwang.overview-snapshot/v1
 dataSource: exact live
 generatedAt: assembly time from Now AFTER both sequential Status calls
 mode: actual config mode, no inferred production/health
 readOnly: true
 advisoryOnly: true
 coverage: {state: none|partial, missing: []closed codes}
 observation: ObservationSummary
 probe: ProbeSummary
 subscription: {configured: boolean, inventoryState: protected_not_read, sourceCount: null, nodeCount: null}
 unsupported: {businesses:true,nodePools:true,endToEndDNS:true,deviceInventory:true,trafficTopology:true}

ObservationSummary:
 configured,running,fresh,stale: boolean
 lastAttemptAt,lastSuccessAt: time|null
 consecutiveFailures: int 0..2147483647
 controller,storage,clock: Layer

Layer: {state: unknown|available|degraded|unavailable,reason: closedDerivedCode,observedAt:time|null,expiresAt:time|null}
Closed derived reason codes: not_configured,no_current_evidence,cache_current,evidence_stale,read_failed,worker_stopped,clock_untrusted,storage_unhealthy.
Frozen role/state/reason pairs, independently derived from the actual projector branches: controller available/cache_current, degraded/evidence_stale, unavailable/read_failed, unknown/(not_configured|no_current_evidence|worker_stopped|clock_untrusted); storage available/cache_current, degraded or unavailable/storage_unhealthy, unknown/(not_configured|no_current_evidence); clock available/cache_current, degraded or unavailable/clock_untrusted, unknown/(not_configured|no_current_evidence). An alternate provider must not produce contradictory pairs; exact-key validity alone is insufficient.
Observation source Reason strings are NEVER copied. Node/internet/business/DNS layers are not read into this DTO; unsupported flags explicitly preserve absence of measurements.
Fresh controller requires configured/running/trusted source clock/fresh flag/available state and source time window enclosing assembly time. Stopped worker forces controller unknown and fresh=false even when original TTL remains. Stale records may retain original time pointers but never become fresh by generatedAt.
Storage/clock available describe their own source status only; no business inference.

ProbeSummary:
 configured,running,clockHealthy,storageHealthy:boolean
 state: disabled|pending|unknown|partial|ready
 reason: disabled|not_started|ok|partial_coverage|no_current_evidence|evidence_expired|content_rejected|clock_rollback|stopped|cache_expired|platform_unsupported|limit_rejected|storage_rejected|read_unavailable
 cachedAt,expiresAt:time|null
 coverageState: current|unavailable
 coverage: ProbeCoverage|null
ProbeCoverage TEN exact fields:
 declaredTargets,targetsWithSamples,targetsMissing,retainedSamples,validTotal,expiredTotal,eligibleTotal,rejectedTotal: integer
 truncated,partial:boolean
Counts 0..2147483647; declaredTargets<=256; targetsWithSamples<=declaredTargets; targetsMissing=declaredTargets-targetsWithSamples; retainedSamples<=200 and <=eligibleTotal; expiredTotal<=validTotal; eligibleTotal=validTotal-expiredTotal.
Coverage is null unless source is running, clock/storage healthy, ready|partial, and cachedAt<=generatedAt<expiresAt with cachedAt<expiresAt. Ready is view-ready, never target/business health. Unknown/stopped/expired cached counts are hidden, not coerced to zero. Probe source schema must be chengwang.probe-view-status/v1 and AdvisoryOnly true.

Frozen state/reason pairs, independently checked against current probeview constructors, refresh/build and statusLocked branches: disabled/disabled; pending/not_started; ready/ok; partial/(partial_coverage|no_current_evidence|evidence_expired); unknown/(no_current_evidence|evidence_expired|content_rejected|clock_rollback|stopped|cache_expired|platform_unsupported|limit_rejected|storage_rejected|read_unavailable). In particular evidence_expired and no_current_evidence are valid with either partial or unknown; do not invent a unique mapping. This clarification adds no fields and does not turn view readiness into business health.

Coverage missing order: controller_observation,probe_readback,businesses,node_pools,end_to_end_dns,device_inventory,traffic_topology.
First two appear when respective current source evidence absent. Last five always appear. state=partial if either source has current evidence, else none. Never covered in this slice.

Frozen time rules:
- UTC normalized detached copies; valid Go JSON RFC3339Nano, year0..9999; generatedAt must not be Go zero.
- Optional source Go zero pointers normalize to null (source has a real pre-attempt degraded-storage branch that can create timePointer(zero)). This does not fabricate observed time.
- expiry can be in future but must be later than its paired observed/cached time when both exist.
- Healthy-clock observed/lastAttempt/lastSuccess/cached values later than assembly time reject projection.
- Real clock rollback can legitimately retain future source times; permit these only with observation.clock unavailable or probe.clockHealthy=false, force current controller unknown / probe coverage unavailable. Do not turn clock rollback into fictitious health or indiscriminate503.
- No claim source caches are sampled atomically.

Frozen mode compatibility: valid UTF8 nonempty<=64 bytes, TrimSpace unchanged, reject Unicode control/format (Cc/Cf). Preserve actual custom label (e.g. Shadow/lab.prod), no enum mapping. New endpoint safety subset only, old snapshot unaffected.

HTTP:
exact canonical GET /api/v1/overview; no query including bare?; reject body/transfer/content encoding before provider read.
503 overview_not_configured: nil/typednil provider; no seed fallback.
503 overview_projection_invalid: source/DTO invalid or marshaling/size invalid; fixed Chinese safe error, never raw cause.
504 overview_deadline and408 overview_canceled: ctx errors; checks pre/post both getters and before response.
Validate and Marshal BEFORE200, <=65536 bytes including newline. No per-request background goroutine or hard mutex timeout promise.
All errors fixed {code,message}. Public token presence cannot extend DTO or trigger auth/detail reads.

本文件是已冻结的开发合同，不是实现或上线证据。真实 Go 编译、测试、HTTP、双浏览器与生产验收仍须逐项取得。

## 主集成冻结补充

- 开发基线为b2b226d；仅在codex/chengwang-live-overview-20261024隔离工作树实施。旧snapshot、默认演示路径、编辑器Snapshot和既有capability_truth合同保持；新接口默认关闭。
- Config.LiveOverviewEnabled bool；环境变量CHENGWANG_LIVE_OVERVIEW_ENABLED。复用StrictBoolEnv：未设置、空值、false均关闭，只有true开启；其他值固定错误，不回显输入。overviewConfigFromEnvironment(*Config)只解析，不构造来源或启动worker。根在runtime组装时直接调用overview.New，不再加facade。
- API.Options.Overview类型为overview.SnapshotProvider。注册无method限定的精确/api/v1/overview路由，由新handler显式拒绝HEAD／POST及带query、bare?、body／transfer／content-encoding请求；其他路由保持。
- API聚合软预算500ms，前端总预算5s。Status无context，因此仅做调用前后合作检查，不以遗弃goroutine或新HTTP超时全局设置伪造硬截止保证。
- mode采用候选中的实际UTF8非空、最多64字节、TrimSpace不改变、无Cc／Cf规则，保留Shadow、lab.prod等自定义值，不映射固定枚举。该约束只属于启用的新总览，不改变旧模式处理。
- 公开时间一律UTC及Z后缀、RFC3339Nano、year0..9999；源可选Go零时间规范为null，generatedAt不得为Go零时间。前端按严格UTC日历和补足9位fraction的规范键比较，不能用Date的毫秒精度或Date.now改变来源新鲜度。
- 时钟回拨可保留来源未来时间，必须有对应clock不可信并撤下current；健康时钟下未来观测拒绝。跨来源不宣称原子快照。
- Storage／Clock自己的available只描述该组件自报状态，不用于推导业务、互联网或端到端健康。coverage最后五项始终missing，第一切片永不covered。
- EvidenceOverview named export；可选onStateChange({state:pending|ready|error,mode:string|null})与onNavigate(设备读回|代理节点|订阅与提供者)。每新请求先清当前报告和mode，只有校验成功才ready；卸载不回调，迟到结果／finally必须验证代际及owner，不写全局editor Snapshot或浏览器持久存储。
- 全部字段required，nullable显式null，无omitempty；服务端成功正文含换行最多65536字节且必须Validate／Marshal完成后才200。前端严格exact键和枚举，有界流／fatal UTF8／JSON／DTO通过后只releaseLock，错误才取消且不等待不受控取消结算。
- 首先写有意义的provider／HTTP／config／decoder／reader／组件反例；本地不运行Go、gofmt、npm、Vitest、tsc、Vite、业务服务或产品浏览器。实际构建与运行只用隔离Linux CI；静态检查不冒称通过这些门。
