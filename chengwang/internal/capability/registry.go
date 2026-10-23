package capability

import "time"

type State string

const (
	StateLiveReadOnly     State = "live_readonly"
	StateImplementedLocal State = "implemented_local"
	StateDesignOnly       State = "design_only"
	StateBlocked          State = "blocked"
)

type Item struct {
	ID          string   `json:"id"`
	Domain      string   `json:"domain"`
	Name        string   `json:"name"`
	State       State    `json:"state"`
	ReadOnly    bool     `json:"readOnly"`
	Evidence    []string `json:"evidence"`
	Limitations []string `json:"limitations"`
}

type Report struct {
	GeneratedAt              string `json:"generatedAt"`
	ProductionControlEnabled bool   `json:"productionControlEnabled"`
	OverallState             string `json:"overallState"`
	Capabilities             []Item `json:"capabilities"`
}

// RuntimeFacts describes configured code paths, not their health or freshness.
// A zero value keeps every optional runtime integration disabled.
type RuntimeFacts struct {
	MihomoConfigured           bool
	EvidenceConfigured         bool
	EvidenceValid              bool
	IdentityConfigured         bool
	OperationControlConfigured bool
	ObservationConfigured      bool
	ProbeReadbackConfigured    bool
}

// Build returns the truthful capability inventory for the current foundation.
// It deliberately describes only executable code paths. Product plans and UI
// placeholders remain design_only, and an unconfigured runtime adapter is
// reported as blocked rather than available.
func Build(now time.Time, mihomoConfigured, evidenceConfigured, evidenceValid, identityConfigured, operationControlConfigured bool, observationConfiguredValue ...bool) Report {
	return BuildWithRuntime(now, RuntimeFacts{
		MihomoConfigured:           mihomoConfigured,
		EvidenceConfigured:         evidenceConfigured,
		EvidenceValid:              evidenceValid,
		IdentityConfigured:         identityConfigured,
		OperationControlConfigured: operationControlConfigured,
		ObservationConfigured:      len(observationConfiguredValue) == 1 && observationConfiguredValue[0],
	})
}

// BuildWithRuntime reports explicit configuration facts without accessing a
// reader, starting a worker, or treating a configured integration as healthy.
func BuildWithRuntime(now time.Time, facts RuntimeFacts) Report {
	mihomoState := StateBlocked
	mihomoEvidence := []string{}
	mihomoLimitations := []string{
		"未配置 Mihomo Controller 只读适配器，运行态状态与策略读回不可用",
		"不读取、不修改路由器配置",
	}
	if facts.MihomoConfigured {
		mihomoState = StateLiveReadOnly
		mihomoEvidence = []string{
			"GET /api/v1/kernels/mihomo/status",
			"POST /api/v1/kernels/mihomo/readback",
		}
		mihomoLimitations = []string{
			"仅通过 Controller API 读取运行态并对期望策略执行差异检查",
			"不修改 Mihomo 配置、不重载内核、不写入路由器",
		}
	}

	evidenceState := StateBlocked
	evidencePaths := []string{}
	evidenceLimitations := []string{
		"未配置或未通过完整性验证，单机追加式证据链不可用",
		"不是 WORM 存储且没有独立副本，管理员仍可同时替换日志与本地检查点",
		"尚无真实用户身份，也未对全部 HTTP 请求形成审计事件",
	}
	if facts.EvidenceConfigured {
		evidencePaths = []string{"GET /api/v1/evidence/integrity"}
	}
	if facts.EvidenceConfigured && facts.EvidenceValid {
		evidenceState = StateImplementedLocal
		evidenceLimitations[0] = "仅在本机验证追加日志、哈希链与本地检查点，不代表生产审计闭环"
	}

	identityState := StateBlocked
	identityEvidence := []string{}
	identityLimitations := []string{"未配置本地身份文件，受保护的操作接口不可用"}
	if facts.IdentityConfigured {
		identityState = StateImplementedLocal
		identityEvidence = []string{"受保护的 /api/v1/operations 接口使用严格 Bearer 身份文件"}
		identityLimitations = []string{
			"仅为本地高熵静态 Bearer 凭据哈希，不是密码登录、会话、MFA、SSO 或令牌轮换服务",
			"身份文件变更后需要安全重启进程才能载入",
		}
	}

	operationState := StateBlocked
	operationEvidence := []string{}
	operationLimitations := []string{"身份、耐久操作库、控制服务或证据完整性依赖未全部就绪"}
	if facts.OperationControlConfigured {
		operationState = StateImplementedLocal
		operationEvidence = []string{"GET /api/v1/operations", "POST /api/v1/operations", "POST /api/v1/operations/{id}/transitions"}
		operationLimitations = []string{
			"仅记录本地计划、审批和预检状态，不执行任何设备动作",
			"写入仍受 CHENGWANG_OPERATION_WRITES_ENABLED 独立开关控制",
			"单控制器文件存储，不支持多副本并发协调",
		}
	}

	observationState := StateBlocked
	observationEvidence := []string{}
	observationLimitations := []string{"未配置周期只读观测器，控制器状态只有请求时读取"}
	if facts.ObservationConfigured {
		observationState = StateLiveReadOnly
		observationEvidence = []string{"GET /api/v1/observations/status", "GET /api/v1/observations/mihomo/history"}
		observationLimitations = []string{
			"当前只周期读取 Mihomo Controller 并保留有界摘要历史",
			"不主动测试节点、互联网、DNS 或具体业务；这些层保持 unknown",
			"不切换节点、不重载配置、不执行自动修复",
		}
	}

	probeReadbackState := StateBlocked
	probeReadbackEvidence := []string{}
	probeReadbackLimitations := []string{
		"未配置探测证据只读导入；此能力默认关闭",
		"仅返回后台安全读取形成的有界缓存；status 与 details 不触发探测或请求时读盘",
		"仅为 standalone probe-agent 的本地 advisory 证据读回，不执行设备动作，也没有启动、停止或调度 agent 的 API",
		"不替代完整节点、地区、账号与企业业务评估，不证明公网可达性或生产验证",
	}
	if facts.ProbeReadbackConfigured {
		probeReadbackState = StateImplementedLocal
		probeReadbackEvidence = []string{"GET /api/v1/probes/status", "GET /api/v1/probes/details"}
		probeReadbackLimitations[0] = "仅表示已配置只读导入，不表示证据新鲜、完整、健康或生产验收通过；details 仍受身份与范围授权保护"
	}

	return Report{
		GeneratedAt:              now.UTC().Truncate(time.Second).Format(time.RFC3339),
		ProductionControlEnabled: false,
		OverallState:             "foundation",
		Capabilities: []Item{
			{
				ID: "control_health", Domain: "control", Name: "控制面健康检查",
				State: StateImplementedLocal, ReadOnly: true,
				Evidence:    []string{"GET /api/v1/health"},
				Limitations: []string{"只证明城望控制面进程可响应，不代表互联网、DNS、代理节点或业务可用"},
			},
			{
				ID: "policy_validation", Domain: "policy", Name: "策略草稿校验",
				State: StateImplementedLocal, ReadOnly: true,
				Evidence:    []string{"POST /api/v1/validate"},
				Limitations: []string{"只校验当前领域模型，不证明生成配置可在目标设备上线"},
			},
			{
				ID: "mihomo_compilation", Domain: "policy", Name: "Mihomo 兼容片段编译",
				State: StateImplementedLocal, ReadOnly: true,
				Evidence:    []string{"POST /api/v1/compile/mihomo"},
				Limitations: []string{"只生成可审查兼容片段，尚未合并监听器、DNS、凭据与代理订阅"},
			},
			{
				ID: "local_version_store", Domain: "configuration", Name: "本地策略版本库",
				State: StateImplementedLocal, ReadOnly: false,
				Evidence:    []string{"GET /api/v1/versions", "POST /api/v1/publish"},
				Limitations: []string{"publish 仅写入城望本地版本库且默认锁定，不会发布到路由器或代理内核"},
			},
			{
				ID: "proxy_interface_validation", Domain: "proxy", Name: "代理入口定义与安全校验",
				State: StateImplementedLocal, ReadOnly: true,
				Evidence:    []string{"GET /api/v1/proxy/interfaces", "POST /api/v1/proxy/interfaces/validate"},
				Limitations: []string{"只校验入口模型，不创建监听端口、防火墙规则或代理服务"},
			},
			{
				ID: "mihomo_runtime_readback", Domain: "kernel", Name: "Mihomo 运行态只读与策略读回",
				State: mihomoState, ReadOnly: true,
				Evidence:    mihomoEvidence,
				Limitations: mihomoLimitations,
			},
			{
				ID: "local_evidence_chain", Domain: "audit", Name: "单机追加式证据链",
				State: evidenceState, ReadOnly: false,
				Evidence: evidencePaths, Limitations: evidenceLimitations,
			},
			{
				ID: "real_authentication", Domain: "security", Name: "本地身份认证与范围授权",
				State: identityState, ReadOnly: false,
				Evidence: identityEvidence, Limitations: identityLimitations,
			},
			{
				ID: "durable_operation_control", Domain: "control", Name: "耐久 Shadow 操作控制面",
				State: operationState, ReadOnly: false,
				Evidence: operationEvidence, Limitations: operationLimitations,
			},
			{
				ID: "continuous_passive_observation", Domain: "observability", Name: "Mihomo 持续只读观测",
				State: observationState, ReadOnly: true,
				Evidence: observationEvidence, Limitations: observationLimitations,
			},
			{
				ID: "probe_evidence_readback", Domain: "observability", Name: "探测证据只读导入",
				State: probeReadbackState, ReadOnly: true,
				Evidence: probeReadbackEvidence, Limitations: probeReadbackLimitations,
			},
			designOnly("router_publish", "configuration", "路由器配置写入与发布", "尚无设备写入、配置测试、灰度、热重载和自动回滚闭环"),
			designOnly("subscription_orchestration", "subscription", "订阅识别与编排", "尚无订阅拉取、去重、隔离、转换、健康检查和回退执行链"),
			designOnly("dns_execution", "dns", "DNS 执行与防泄漏", "尚无 DNS 服务进程、解析链路接管、泄漏检测和故障切换执行器"),
			designOnly("active_business_probes", "observability", "主动业务可用性探测", "已有 standalone probe-agent 的有界 HTTP、TLS、DNS 探测与只读证据导入；尚无完整节点、地区、账号与企业业务评估及生产验证闭环"),
			designOnly("automatic_repair", "automation", "自动诊断与修复", "尚无故障决策、抑制、变更、验证和失败回滚执行闭环"),
			designOnly("multi_kernel_runtime", "kernel", "多内核运行与切换", "当前仅有 Mihomo 领域描述和只读适配器，未运行或控制 sing-box、Xray 等内核"),
		},
	}
}

func designOnly(id, domain, name, limitation string) Item {
	return Item{
		ID: id, Domain: domain, Name: name, State: StateDesignOnly, ReadOnly: true,
		Evidence: []string{}, Limitations: []string{limitation},
	}
}
