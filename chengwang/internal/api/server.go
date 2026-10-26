package api

import (
	"context"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authz"
	"chengwang/internal/capability"
	"chengwang/internal/control"
	"chengwang/internal/domain"
	"chengwang/internal/evidence"
	"chengwang/internal/imagetrust"
	"chengwang/internal/mihomodeploy"
	"chengwang/internal/observation"
	"chengwang/internal/operation"
	"chengwang/internal/overview"
	"chengwang/internal/policy"
	"chengwang/internal/proxyiface"
	"chengwang/internal/store"
	"chengwang/internal/subscriptionctl"
)

type Options struct {
	Mode                        string
	AdminToken                  string
	AllowPublish                bool
	Versions                    *store.VersionStore
	Mihomo                      MihomoReader
	Evidence                    EvidenceVerifier
	Authn                       Authenticator
	Operations                  OperationLister
	Control                     *control.Service
	OperationWritesEnabled      bool
	ManagementScope             authz.ResourceScope
	EvidenceMaxAge              time.Duration
	Observation                 ObservationReader
	Overview                    overview.SnapshotProvider
	Probes                      ProbeReader
	ImageTrust                  imagetrust.Backend
	ImageTrustWritesEnabled     bool
	Subscriptions               subscriptionctl.Backend
	SubscriptionWritesEnabled   bool
	MihomoLab                   mihomodeploy.LabBackend
	MihomoLabWritesEnabled      bool
	MihomoRecoveries            mihomodeploy.LabRecoveryBackend
	MihomoRecoveryWritesEnabled bool
}

type MihomoReader interface {
	ReadRuntime(context.Context) (mihomo.RuntimeSnapshot, error)
}

// EvidenceVerifier is deliberately the smallest read-only surface the HTTP
// layer needs. Event contents and append operations are not exposed here.
type EvidenceVerifier interface {
	Verify() (evidence.VerifyReport, error)
	Status() evidence.VerifyReport
}

// Authenticator is intentionally limited to strict HTTP Authorization values.
// Implementations must reject duplicate fields rather than merging them.
type Authenticator interface {
	AuthenticateAuthorizationValues([]string, time.Time) (authz.Principal, error)
}

// OperationLister exposes detached durable operation snapshots. HTTP responses
// convert these snapshots to summaries and never serialize Events.
type OperationLister interface {
	List() ([]operation.Operation, error)
}

// ObservationReader exposes sanitized passive-observation facts. Status is
// safe for an anonymous LAN dashboard; Detail is always management protected.
type ObservationReader interface {
	Status() observation.Status
	Detail(int) observation.Detail
}

type server struct {
	options             Options
	runtime             *runtimeProvider
	evidenceScanGate    chan struct{}
	imageTrustScope     authz.ResourceScope
	subscriptionScope   authz.ResourceScope
	mihomoLabScope      authz.ResourceScope
	mihomoRecoveryScope authz.ResourceScope
}

func New(options Options) http.Handler {
	if options.EvidenceMaxAge <= 0 {
		options.EvidenceMaxAge = 2 * time.Minute
	}
	s := &server{
		options: options, runtime: newRuntimeProvider(options.Mihomo),
		evidenceScanGate: make(chan struct{}, 1),
	}
	if options.ImageTrust != nil {
		s.imageTrustScope = options.ImageTrust.Scope()
	}
	if !nilSubscriptionInterface(options.Subscriptions) {
		s.subscriptionScope = options.Subscriptions.Scope()
	} else {
		s.options.Subscriptions = nil
	}
	if !nilSubscriptionInterface(options.MihomoLab) {
		s.mihomoLabScope = options.MihomoLab.Scope()
	} else {
		s.options.MihomoLab = nil
	}
	if !nilSubscriptionInterface(options.MihomoRecoveries) {
		s.mihomoRecoveryScope = options.MihomoRecoveries.Scope()
	} else {
		s.options.MihomoRecoveries = nil
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v1/health", s.health)
	mux.HandleFunc("GET /api/v1/capabilities", s.capabilities)
	mux.HandleFunc("GET /api/v1/attestation/shadow", s.shadowAttestation)
	mux.HandleFunc("GET /api/v1/observations/status", s.observationStatus)
	mux.HandleFunc("GET /api/v1/observations/mihomo/history", s.observationHistory)
	mux.HandleFunc("/api/v1/probes/status", s.probeStatus)
	mux.HandleFunc("/api/v1/probes/details", s.probeDetails)
	mux.HandleFunc("GET /api/v1/evidence/integrity", s.evidenceIntegrity)
	mux.HandleFunc("GET /api/v1/snapshot", s.snapshot)
	mux.HandleFunc("/api/v1/overview", s.overview)
	mux.HandleFunc("GET /api/v1/versions", s.versions)
	mux.HandleFunc("GET /api/v1/proxy/interfaces", s.proxyInterfaces)
	mux.HandleFunc("POST /api/v1/proxy/interfaces/validate", s.validateProxyInterfaces)
	mux.HandleFunc("POST /api/v1/validate", s.validate)
	mux.HandleFunc("POST /api/v1/compile/mihomo", s.compile)
	mux.HandleFunc("POST /api/v1/publish", s.publish)
	mux.HandleFunc("GET /api/v1/kernels/mihomo/status", s.mihomoStatus)
	mux.HandleFunc("GET /api/v1/kernels/mihomo/runtime", s.mihomoRuntime)
	mux.HandleFunc("POST /api/v1/kernels/mihomo/readback", s.mihomoReadback)
	mux.HandleFunc("GET /api/v1/operations", s.listOperations)
	mux.HandleFunc("POST /api/v1/operations", s.createOperation)
	mux.HandleFunc("POST /api/v1/operations/{id}/transitions", s.transitionOperation)
	mux.HandleFunc("/api/v1/operations", s.operationMethodNotAllowed)
	mux.HandleFunc("/api/v1/operations/{id}/transitions", s.operationMethodNotAllowed)
	mux.HandleFunc("/api/v1/image-trust", s.imageTrustStatus)
	mux.HandleFunc("/api/v1/image-trust/catalogue", s.imageTrustCatalogue)
	mux.HandleFunc("/api/v1/image-trust/verifications", s.imageTrustVerification)
	mux.HandleFunc("/api/v1/image-trust/history", s.imageTrustHistory)
	mux.HandleFunc("/api/v1/subscriptions/sources", s.subscriptionSources)
	mux.HandleFunc("/api/v1/subscriptions/refreshes", s.subscriptionRefreshes)
	mux.HandleFunc("/api/v1/subscriptions/sources/{sourceId}/refresh", s.subscriptionRefresh)
	mux.HandleFunc("/api/v1/subscriptions/access", s.subscriptionAccess)
	mux.HandleFunc("/api/v1/subscriptions/sources/{sourceId}/access", s.subscriptionAccess)
	mux.HandleFunc("/api/v1/subscriptions/sources/{sourceId}/candidates", s.subscriptionCandidates)
	mux.HandleFunc("/api/v1/subscriptions/sources/{sourceId}/candidates/{candidateId}/nodes", s.subscriptionNodes)
	mux.HandleFunc("/api/v1/subscriptions/sources/{sourceId}/decisions", s.subscriptionDecision)
	mux.HandleFunc("/api/v1/subscriptions/sources/{sourceId}/rollbacks", s.subscriptionRollback)
	mux.HandleFunc("/api/v1/subscriptions/sources/{sourceId}/approvals", s.subscriptionApproval)
	mux.HandleFunc("/api/v1/subscriptions/sources/{sourceId}/fetches", s.subscriptionFetch)
	mux.HandleFunc("/api/v1/subscriptions/commands/{commandId}", s.subscriptionReceipt)
	mux.HandleFunc("/api/v1/subscriptions", s.subscriptionUnavailableRoute)
	mux.HandleFunc("/api/v1/subscriptions/", s.subscriptionUnavailableRoute)
	return s.securityHeaders(s.requestID(s.mihomoLabRoutes(mux)))
}

func (s *server) capabilities(w http.ResponseWriter, _ *http.Request) {
	_, evidenceValid := s.verifyEvidence()
	identityConfigured := !nilSubscriptionInterface(s.options.Authn)
	writeJSON(w, http.StatusOK, capability.BuildWithRuntime(time.Now(), capability.RuntimeFacts{
		MihomoConfigured:           s.options.Mihomo != nil,
		EvidenceConfigured:         s.options.Evidence != nil,
		EvidenceValid:              evidenceValid,
		IdentityConfigured:         identityConfigured,
		OperationControlConfigured: identityConfigured && s.options.Operations != nil && s.options.Control != nil && evidenceValid,
		ObservationConfigured:      s.options.Observation != nil,
		// Configuration is not a liveness or business-health assertion. The
		// anonymous inventory must not scan storage or read protected details.
		ProbeReadbackConfigured: s.options.Probes != nil,
		SubscriptionConfigured:  s.options.Subscriptions != nil && subscriptionScopeValid(s.subscriptionScope),
	}))
}

func (s *server) observationStatus(w http.ResponseWriter, _ *http.Request) {
	if s.options.Observation == nil {
		writeJSON(w, http.StatusOK, observation.Status{
			Configured: false, Mode: "disabled",
			Controller:    observation.Layer{State: observation.StateUnknown, Reason: "持续观测未配置"},
			NodeTechnical: observation.Layer{State: observation.StateUnknown, Reason: "节点技术探针未配置"},
			Internet:      observation.Layer{State: observation.StateUnknown, Reason: "互联网探针未配置"},
			Business:      observation.Layer{State: observation.StateUnknown, Reason: "业务探针未配置"},
			DNS:           observation.Layer{State: observation.StateUnknown, Reason: "DNS 探针未配置"},
			Storage:       observation.Layer{State: observation.StateUnknown, Reason: "观测存储未配置"},
			Clock:         observation.Layer{State: observation.StateUnknown, Reason: "观测时钟尚未校验"},
		})
		return
	}
	writeJSON(w, http.StatusOK, s.options.Observation.Status())
}

func (s *server) observationHistory(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.managementPreflight(w, r, authz.ActionReadResource); !ok {
		return
	}
	if s.options.Observation == nil {
		writeError(w, http.StatusServiceUnavailable, "observation_not_configured", "持续观测尚未配置")
		return
	}
	writeJSON(w, http.StatusOK, s.options.Observation.Detail(200))
}

func (s *server) evidenceIntegrity(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.managementPreflight(w, r, authz.ActionReadEvidence); !ok {
		return
	}
	select {
	case s.evidenceScanGate <- struct{}{}:
		defer func() { <-s.evidenceScanGate }()
	default:
		writeError(w, http.StatusTooManyRequests, "evidence_verification_busy", "证据完整性复验正在执行")
		return
	}
	if s.options.Evidence == nil {
		writeError(w, http.StatusServiceUnavailable, "evidence_not_configured", "证据存储尚未配置")
		return
	}
	report, err := s.options.Evidence.Verify()
	valid := err == nil && report.Valid
	if !valid {
		report.Valid = false
		if report.Issue == "" {
			report.Issue = "verification_failed"
		}
		writeJSON(w, http.StatusServiceUnavailable, report)
		return
	}
	writeJSON(w, http.StatusOK, report)
}

func (s *server) proxyInterfaces(w http.ResponseWriter, _ *http.Request) {
	items := seedProxyInterfaces()
	writeJSON(w, http.StatusOK, map[string]any{
		"mode":          s.options.Mode,
		"publishLocked": !s.options.AllowPublish || s.options.AdminToken == "",
		"interfaces":    items,
		"validation":    proxyiface.Validate(items),
	})
}

func (s *server) validateProxyInterfaces(w http.ResponseWriter, r *http.Request) {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var items []domain.ProxyInterface
	if err := decoder.Decode(&items); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "请求格式无效，必须提交代理接口数组")
		return
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_json", "请求只能包含一个 JSON 数组")
		return
	}
	writeJSON(w, http.StatusOK, proxyiface.Validate(items))
}

func (s *server) health(w http.ResponseWriter, _ *http.Request) {
	_, evidenceValid := s.verifyEvidence()
	status := "ok"
	if !evidenceValid {
		status = "degraded"
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"status":                   status,
		"mode":                     s.options.Mode,
		"mihomoReadbackConfigured": s.options.Mihomo != nil,
		"evidenceConfigured":       s.options.Evidence != nil,
		"evidenceIntegrity":        evidenceValid,
	})
}

func (s *server) verifyEvidence() (evidence.VerifyReport, bool) {
	if s.options.Evidence == nil {
		return evidence.VerifyReport{Valid: false, Issue: "not_configured"}, false
	}
	report := s.options.Evidence.Status()
	if !report.Valid {
		report.Valid = false
		if report.Issue == "" {
			report.Issue = "verification_failed"
		}
		return report, false
	}
	if report.VerifiedAt.IsZero() || time.Since(report.VerifiedAt) > s.options.EvidenceMaxAge {
		report.Valid = false
		report.Issue = "verification_stale"
		return report, false
	}
	return report, true
}

func (s *server) snapshot(w http.ResponseWriter, _ *http.Request) {
	current, _ := s.options.Versions.CurrentID()
	snapshot := seedSnapshot(s.options.Mode, current, !s.options.AllowPublish || s.options.AdminToken == "", s.options.Mihomo != nil)
	writeJSON(w, http.StatusOK, snapshot)
}

func (s *server) mihomoStatus(w http.ResponseWriter, r *http.Request) {
	if s.runtime == nil {
		writeError(w, http.StatusServiceUnavailable, "mihomo_not_configured", "尚未配置 Mihomo 只读控制器")
		return
	}
	observation, err := s.runtime.observe(r.Context(), false)
	if err != nil {
		writeMihomoError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"configured": true,
		"reachable":  observation.Reachable,
		"fresh":      observation.Fresh,
		"stale":      observation.Stale,
		"observedAt": observation.LastSuccess,
	})
}

func (s *server) mihomoRuntime(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.managementPreflight(w, r, authz.ActionReadResource); !ok {
		return
	}
	if s.runtime == nil {
		writeError(w, http.StatusServiceUnavailable, "mihomo_not_configured", "尚未配置 Mihomo 只读控制器")
		return
	}
	observation, err := s.runtime.observe(r.Context(), false)
	if err != nil {
		writeMihomoError(w, err)
		return
	}
	if !observation.Fresh {
		w.Header().Set("Warning", `110 - "stale Mihomo runtime snapshot"`)
	}
	writeJSON(w, http.StatusOK, observation.Snapshot)
}

func (s *server) mihomoReadback(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.managementPreflight(w, r, authz.ActionReadResource); !ok {
		return
	}
	if s.runtime == nil {
		writeError(w, http.StatusServiceUnavailable, "mihomo_not_configured", "尚未配置 Mihomo 只读控制器")
		return
	}
	draft, ok := decodeDraft(w, r)
	if !ok {
		return
	}
	validation := policy.Validate(draft)
	if !validation.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, validation)
		return
	}
	observation, err := s.runtime.observe(r.Context(), true)
	if err != nil {
		writeMihomoError(w, err)
		return
	}
	writeJSON(w, http.StatusOK, mihomo.Compare(draft, observation.Snapshot))
}

func (s *server) versions(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.managementPreflight(w, r, authz.ActionReadResource); !ok {
		return
	}
	versions, err := s.options.Versions.List()
	if err != nil {
		writeError(w, http.StatusInternalServerError, "version_store_failed", "读取版本库失败")
		return
	}
	writeJSON(w, http.StatusOK, versions)
}

func (s *server) shadowAttestation(w http.ResponseWriter, r *http.Request) {
	report, evidenceValid := s.verifyEvidence()
	mihomoState := map[string]any{"configured": s.runtime != nil, "reachable": false, "fresh": false}
	if s.runtime != nil {
		if observation, err := s.runtime.observe(r.Context(), false); err == nil {
			mihomoState["reachable"] = observation.Reachable
			mihomoState["fresh"] = observation.Fresh
			mihomoState["stale"] = observation.Stale
			mihomoState["lastSuccessfulAt"] = observation.LastSuccess
		}
	}
	writeJSON(w, http.StatusOK, map[string]any{
		"generatedAt":              time.Now().UTC(),
		"mode":                     s.options.Mode,
		"productionControlEnabled": false,
		"identityConfigured":       s.options.Authn != nil,
		"operationWritesEnabled":   s.options.OperationWritesEnabled,
		"deviceActionsExecuted":    false,
		"evidence": map[string]any{
			"valid": evidenceValid, "verifiedAt": report.VerifiedAt,
		},
		"mihomo": mihomoState,
	})
}

func (s *server) managementPreflight(w http.ResponseWriter, r *http.Request, action authz.Action) (authz.Principal, bool) {
	if len(r.Header.Values("Authorization")) > 0 && !requestTransportSecure(r) {
		writeError(w, http.StatusUpgradeRequired, "secure_transport_required", "管理凭据只允许通过 TLS 或本机回环连接传输")
		return authz.Principal{}, false
	}
	if s.options.Authn == nil || strings.TrimSpace(s.options.ManagementScope.TenantID) == "" {
		writeError(w, http.StatusServiceUnavailable, "diagnostic_auth_not_configured", "安全诊断身份或管理范围尚未配置")
		return authz.Principal{}, false
	}
	principal, err := s.options.Authn.AuthenticateAuthorizationValues(r.Header.Values("Authorization"), time.Now().UTC())
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="chengwang"`)
		writeError(w, http.StatusUnauthorized, "unauthorized", "身份验证失败")
		return authz.Principal{}, false
	}
	decision := authz.Evaluate(authz.Request{Principal: principal, Action: action, Resource: s.options.ManagementScope}, time.Now().UTC())
	if !decision.Allowed {
		writeError(w, http.StatusForbidden, "forbidden", "当前身份无权读取该管理范围")
		return authz.Principal{}, false
	}
	return principal, true
}

func requestTransportSecure(r *http.Request) bool {
	if r.TLS != nil {
		return true
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func (s *server) validate(w http.ResponseWriter, r *http.Request) {
	draft, ok := decodeDraft(w, r)
	if !ok {
		return
	}
	writeJSON(w, http.StatusOK, policy.Validate(draft))
}

func (s *server) compile(w http.ResponseWriter, r *http.Request) {
	draft, ok := decodeDraft(w, r)
	if !ok {
		return
	}
	artifact, err := policy.CompileMihomo(draft)
	if err != nil {
		writeError(w, http.StatusUnprocessableEntity, "validation_failed", "策略未通过校验")
		return
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Content-Disposition", `attachment; filename="chengwang-mihomo.yaml"`)
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(artifact)
}

func (s *server) publish(w http.ResponseWriter, r *http.Request) {
	if !s.options.AllowPublish {
		writeError(w, http.StatusLocked, "publish_disabled", "发布功能尚未启用")
		return
	}
	if len(r.Header.Values("Authorization")) > 0 && !requestTransportSecure(r) {
		writeError(w, http.StatusUpgradeRequired, "secure_transport_required", "管理凭据只允许通过 TLS 或本机回环连接传输")
		return
	}
	if s.options.AdminToken == "" || !bearerValuesMatch(r.Header.Values("Authorization"), s.options.AdminToken) {
		writeError(w, http.StatusUnauthorized, "unauthorized", "管理员身份验证失败")
		return
	}
	draft, ok := decodeDraft(w, r)
	if !ok {
		return
	}
	result := policy.Validate(draft)
	if !result.Valid {
		writeJSON(w, http.StatusUnprocessableEntity, result)
		return
	}
	expected := strings.Trim(r.Header.Get("If-Match"), `"`)
	version, err := s.options.Versions.Publish(draft, "api", expected)
	if err != nil {
		writeError(w, http.StatusConflict, "version_conflict", err.Error())
		return
	}
	writeJSON(w, http.StatusCreated, version)
}

func decodeDraft(w http.ResponseWriter, r *http.Request) (domain.PolicyDraft, bool) {
	defer r.Body.Close()
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	var draft domain.PolicyDraft
	if err := decoder.Decode(&draft); err != nil {
		writeError(w, http.StatusBadRequest, "invalid_json", "请求格式无效")
		return domain.PolicyDraft{}, false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeError(w, http.StatusBadRequest, "invalid_json", "请求只能包含一个 JSON 对象")
		return domain.PolicyDraft{}, false
	}
	return draft, true
}

func bearerMatches(value, token string) bool {
	want := "Bearer " + token
	return len(value) == len(want) && subtle.ConstantTimeCompare([]byte(value), []byte(want)) == 1
}

func bearerValuesMatch(values []string, token string) bool {
	return len(values) == 1 && !strings.Contains(values[0], ",") && bearerMatches(values[0], token)
}

func (s *server) requestID(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestID := fmt.Sprintf("cw-%x", time.Now().UnixNano())
		w.Header().Set("X-Request-ID", requestID)
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), requestIDContextKey{}, requestID)))
	})
}

type requestIDContextKey struct{}

func (s *server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		next.ServeHTTP(w, r)
	})
}

func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}

func writeError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, map[string]string{"code": code, "message": message})
}

func writeMihomoError(w http.ResponseWriter, err error) {
	if errors.Is(err, errRuntimeClock) {
		writeError(w, http.StatusServiceUnavailable, "mihomo_clock_invalid", "系统时钟异常，Mihomo 运行态证据已冻结")
		return
	}
	if errors.Is(err, errRuntimeBusy) {
		w.Header().Set("Retry-After", "5")
		writeError(w, http.StatusTooManyRequests, "mihomo_refresh_busy", "Mihomo 状态刷新受限，请稍后重试")
		return
	}
	if errors.Is(err, context.DeadlineExceeded) {
		writeError(w, http.StatusGatewayTimeout, "mihomo_timeout", "读取 Mihomo 控制器超时")
		return
	}
	var upstream *mihomo.HTTPError
	if errors.As(err, &upstream) && (upstream.StatusCode == http.StatusUnauthorized || upstream.StatusCode == http.StatusForbidden) {
		writeError(w, http.StatusBadGateway, "mihomo_auth_failed", "Mihomo 控制器拒绝了只读请求")
		return
	}
	writeError(w, http.StatusBadGateway, "mihomo_read_failed", "无法读取 Mihomo 控制器状态")
}
