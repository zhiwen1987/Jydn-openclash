package api

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"strconv"
	"strings"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/control"
	"chengwang/internal/operation"
)

const localRecordEffect = "local_record_only"

const (
	defaultOperationLimit = 50
	maxOperationLimit     = 200
	maxOperationBodyBytes = 1 << 20
)

type operationEnvelope struct {
	Effect                string             `json:"effect"`
	DeviceActionsExecuted bool               `json:"deviceActionsExecuted"`
	Operations            []operationSummary `json:"operations,omitempty"`
	Operation             *operationSummary  `json:"operation,omitempty"`
	Created               *bool              `json:"created,omitempty"`
	Applied               *bool              `json:"applied,omitempty"`
	Replayed              *bool              `json:"replayed,omitempty"`
	AuditRecorded         *bool              `json:"auditRecorded,omitempty"`
	Outcome               control.Outcome    `json:"outcome,omitempty"`
	Code                  string             `json:"code,omitempty"`
	Message               string             `json:"message,omitempty"`
}

type operationListEnvelope struct {
	Effect                string             `json:"effect"`
	DeviceActionsExecuted bool               `json:"deviceActionsExecuted"`
	Operations            []operationSummary `json:"operations"`
	Total                 int                `json:"total"`
	Truncated             bool               `json:"truncated"`
}

type operationSummary struct {
	ID              string                    `json:"id"`
	IdentityBinding operation.IdentityBinding `json:"identityBinding"`
	Environment     string                    `json:"environment"`
	Scope           string                    `json:"scope"`
	TargetVersion   string                    `json:"targetVersion"`
	Risk            operation.Risk            `json:"risk"`
	Status          operation.Status          `json:"status"`
	CreatedAt       time.Time                 `json:"createdAt"`
	UpdatedAt       time.Time                 `json:"updatedAt"`
}

type createOperationBody struct {
	Resource      authz.ResourceScope `json:"resource"`
	Risk          authz.Risk          `json:"risk"`
	TargetVersion string              `json:"targetVersion"`
}

type transitionOperationBody struct {
	Resource authz.ResourceScope `json:"resource"`
	To       operation.Status    `json:"to"`
}

func (s *server) operationMethodNotAllowed(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path == "/api/v1/operations" {
		w.Header().Set("Allow", "GET, POST")
	} else {
		w.Header().Set("Allow", "POST")
	}
	writeOperationError(w, http.StatusMethodNotAllowed, "method_not_allowed", "该操作接口不支持此 HTTP 方法")
}

func (s *server) listOperations(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.operationPreflight(w, r, false)
	if !ok {
		return
	}
	limit, validLimit := operationLimit(r)
	if !validLimit {
		writeOperationError(w, http.StatusBadRequest, "invalid_limit", "limit 必须是 1 到 200 之间的整数")
		return
	}
	resource := authz.ResourceScope{
		TenantID: r.URL.Query().Get("tenantId"), SiteID: r.URL.Query().Get("siteId"),
		ObjectType: r.URL.Query().Get("objectType"), ObjectID: r.URL.Query().Get("objectId"),
		Environment: r.URL.Query().Get("environment"),
	}
	if !validResource(resource) {
		writeOperationError(w, http.StatusBadRequest, "invalid_scope", "必须提供有效的 tenantId 与 environment")
		return
	}
	if !authz.Evaluate(authz.Request{Principal: principal, Action: authz.ActionReadResource, Resource: resource}, time.Now().UTC()).Allowed {
		writeOperationError(w, http.StatusForbidden, "forbidden", "无权读取该范围的操作")
		return
	}
	scopeRef, err := control.ScopeReference(resource)
	if err != nil {
		writeOperationError(w, http.StatusBadRequest, "invalid_scope", "操作范围无效")
		return
	}
	items, err := s.options.Operations.List()
	if err != nil {
		writeOperationError(w, http.StatusServiceUnavailable, "operation_store_unavailable", "操作记录暂不可用")
		return
	}
	summaries := make([]operationSummary, 0, min(limit, len(items)))
	total := 0
	for _, item := range items {
		if item.Scope == scopeRef && item.Environment == resource.Environment {
			total++
			if len(summaries) < limit {
				summaries = append(summaries, summarizeOperation(item))
			}
		}
	}
	writeJSON(w, http.StatusOK, operationListEnvelope{
		Effect: localRecordEffect, Operations: summaries, Total: total, Truncated: total > len(summaries),
	})
}

func (s *server) createOperation(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.operationPreflight(w, r, true)
	if !ok {
		return
	}
	if !requireOperationJSON(w, r) {
		return
	}
	var body createOperationBody
	if !decodeOperationBody(w, r, &body) {
		return
	}
	if !validResource(body.Resource) || strings.TrimSpace(body.TargetVersion) == "" {
		writeOperationError(w, http.StatusBadRequest, "invalid_request", "操作范围和目标版本不能为空")
		return
	}
	rawKey, ok := oneHeader(r.Header.Values("Idempotency-Key"))
	key, keyOK := httpIdempotencyKey(rawKey)
	if !ok || !keyOK {
		writeOperationError(w, http.StatusBadRequest, "idempotency_key_required", "必须提供唯一的 Idempotency-Key")
		return
	}
	result, err := s.options.Control.Create(control.CreateRequest{
		Principal: principal, Resource: body.Resource, Risk: body.Risk,
		TargetVersion: body.TargetVersion, IdempotencyKey: key,
	})
	if err != nil {
		writeControlError(w, err, result.Operation)
		return
	}
	summary := summarizeOperation(result.Operation)
	status := http.StatusCreated
	if !result.Created {
		status = http.StatusOK
	}
	writeJSON(w, status, operationEnvelope{
		Effect: localRecordEffect, Operation: &summary, Created: boolPointer(result.Created),
		AuditRecorded: boolPointer(result.AuditRecorded), Outcome: result.Outcome,
	})
}

func (s *server) transitionOperation(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.operationPreflight(w, r, true)
	if !ok {
		return
	}
	if !requireOperationJSON(w, r) {
		return
	}
	var body transitionOperationBody
	if !decodeOperationBody(w, r, &body) {
		return
	}
	if !validResource(body.Resource) {
		writeOperationError(w, http.StatusBadRequest, "invalid_scope", "操作范围无效")
		return
	}
	if !authz.Evaluate(authz.Request{Principal: principal, Action: authz.ActionReadResource, Resource: body.Resource}, time.Now().UTC()).Allowed {
		// Deliberately indistinguishable from a missing operation.
		writeOperationError(w, http.StatusNotFound, "operation_unavailable", "操作不存在或不在授权范围内")
		return
	}
	rawKey, headerOK := oneHeader(r.Header.Values("Idempotency-Key"))
	key, keyOK := httpIdempotencyKey(rawKey)
	if !headerOK || !keyOK {
		writeOperationError(w, http.StatusBadRequest, "idempotency_key_required", "必须提供唯一的 Idempotency-Key")
		return
	}
	id := strings.TrimSpace(r.PathValue("id"))
	current, found, lookupErr := s.visibleOperation(id, body.Resource)
	if lookupErr != nil {
		writeOperationError(w, http.StatusServiceUnavailable, "operation_store_unavailable", "操作记录暂不可用")
		return
	}
	if !found {
		writeOperationError(w, http.StatusNotFound, "operation_unavailable", "操作不存在或不在授权范围内")
		return
	}
	if isExecutorStage(body.To) {
		writeOperationError(w, http.StatusLocked, "executor_not_configured", "尚未配置设备执行器，禁止进入执行阶段")
		return
	}
	if !httpTransitionAllowed(current, body.To) {
		writeOperationError(w, http.StatusUnprocessableEntity, "transition_not_available", "当前风险和状态不允许该本地状态转换")
		return
	}
	result, err := s.options.Control.Transition(control.TransitionRequest{
		Principal: principal, Resource: body.Resource, OperationID: id, To: body.To,
		IdempotencyKey: key,
	})
	if err != nil {
		writeControlError(w, err, result.Operation)
		return
	}
	summary := summarizeOperation(result.Operation)
	writeJSON(w, http.StatusOK, operationEnvelope{
		Effect: localRecordEffect, Operation: &summary, Applied: boolPointer(result.Applied),
		Replayed: boolPointer(result.Replayed), AuditRecorded: boolPointer(result.AuditRecorded), Outcome: result.Outcome,
	})
}

func (s *server) operationPreflight(w http.ResponseWriter, r *http.Request, write bool) (authz.Principal, bool) {
	if s.options.Authn == nil || s.options.Operations == nil || s.options.Control == nil || s.options.Evidence == nil {
		writeOperationError(w, http.StatusServiceUnavailable, "operation_control_not_configured", "本地操作控制面尚未配置")
		return authz.Principal{}, false
	}
	if len(r.Header.Values("Authorization")) > 0 && !requestTransportSecure(r) {
		writeOperationError(w, http.StatusUpgradeRequired, "secure_transport_required", "管理凭据只允许通过 TLS 或本机回环连接传输")
		return authz.Principal{}, false
	}
	principal, err := s.options.Authn.AuthenticateAuthorizationValues(r.Header.Values("Authorization"), time.Now().UTC())
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="chengwang"`)
		writeOperationError(w, http.StatusUnauthorized, "unauthorized", "身份验证失败")
		return authz.Principal{}, false
	}
	if write && !s.options.OperationWritesEnabled {
		writeOperationError(w, http.StatusLocked, "operation_writes_disabled", "本地操作写入开关未启用")
		return authz.Principal{}, false
	}
	// Full verification runs at startup, after appends, in the background, and
	// through the protected single-flight integrity endpoint. HTTP operations
	// consume the bounded cached result so an authenticated but unauthorized
	// caller cannot amplify a full log scan before resource authorization.
	if _, valid := s.verifyEvidence(); !valid {
		writeOperationError(w, http.StatusServiceUnavailable, "evidence_integrity_unavailable", "证据完整性未通过，操作控制面已关闭")
		return authz.Principal{}, false
	}
	return principal, true
}

func (s *server) visibleOperation(id string, resource authz.ResourceScope) (operation.Operation, bool, error) {
	if id == "" {
		return operation.Operation{}, false, nil
	}
	scopeRef, err := control.ScopeReference(resource)
	if err != nil {
		return operation.Operation{}, false, nil
	}
	items, err := s.options.Operations.List()
	if err != nil {
		return operation.Operation{}, false, err
	}
	for _, item := range items {
		if item.ID == id && item.Scope == scopeRef && item.Environment == resource.Environment {
			return item, true, nil
		}
	}
	return operation.Operation{}, false, nil
}

func httpTransitionAllowed(current operation.Operation, to operation.Status) bool {
	switch {
	case current.Status == operation.StatusPlanned && to == operation.StatusAwaitingApproval:
		return current.Risk == operation.RiskHigh || current.Risk == operation.RiskCritical
	case current.Status == operation.StatusPlanned && to == operation.StatusPrechecking:
		return current.Risk == operation.RiskLow || current.Risk == operation.RiskMedium
	case current.Status == operation.StatusAwaitingApproval && to == operation.StatusPrechecking:
		return current.Risk == operation.RiskHigh || current.Risk == operation.RiskCritical
	default:
		return false
	}
}

func isExecutorStage(status operation.Status) bool {
	switch status {
	case operation.StatusExecuting, operation.StatusVerifying, operation.StatusObserving,
		operation.StatusSucceeded, operation.StatusPartial, operation.StatusRolledBack,
		operation.StatusFailed, operation.StatusManualTakeover:
		return true
	default:
		return false
	}
}

func decodeOperationBody(w http.ResponseWriter, r *http.Request, target any) bool {
	defer r.Body.Close()
	payload, err := io.ReadAll(io.LimitReader(r.Body, maxOperationBodyBytes+1))
	if err != nil {
		writeOperationError(w, http.StatusBadRequest, "invalid_json", "无法读取请求正文")
		return false
	}
	if len(payload) > maxOperationBodyBytes {
		writeOperationError(w, http.StatusRequestEntityTooLarge, "request_body_too_large", "请求正文不能超过 1 MiB")
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(payload))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeOperationError(w, http.StatusBadRequest, "invalid_json", "请求格式无效或包含禁止字段")
		return false
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		writeOperationError(w, http.StatusBadRequest, "invalid_json", "请求只能包含一个 JSON 对象")
		return false
	}
	return true
}

func requireOperationJSON(w http.ResponseWriter, r *http.Request) bool {
	mediaType, _, err := mime.ParseMediaType(r.Header.Get("Content-Type"))
	if err != nil || !strings.EqualFold(mediaType, "application/json") {
		writeOperationError(w, http.StatusUnsupportedMediaType, "unsupported_media_type", "Content-Type 必须是 application/json")
		return false
	}
	return true
}

func operationLimit(r *http.Request) (int, bool) {
	values, exists := r.URL.Query()["limit"]
	if !exists {
		return defaultOperationLimit, true
	}
	if len(values) != 1 || values[0] == "" {
		return 0, false
	}
	value, err := strconv.Atoi(values[0])
	if err != nil || value < 1 || value > maxOperationLimit {
		return 0, false
	}
	return value, true
}

func validResource(resource authz.ResourceScope) bool {
	return strings.TrimSpace(resource.TenantID) != "" && resource.TenantID == strings.TrimSpace(resource.TenantID) &&
		strings.TrimSpace(resource.Environment) != "" && resource.Environment == strings.TrimSpace(resource.Environment)
}

func summarizeOperation(item operation.Operation) operationSummary {
	return operationSummary{
		ID: item.ID, IdentityBinding: item.IdentityBinding, Environment: item.Environment,
		Scope: item.Scope, TargetVersion: item.TargetVersion, Risk: item.Risk, Status: item.Status,
		CreatedAt: item.CreatedAt, UpdatedAt: item.UpdatedAt,
	}
}

func writeControlError(w http.ResponseWriter, err error, item operation.Operation) {
	status, code, message := http.StatusInternalServerError, "operation_failed", "本地操作未完成"
	var serviceErr *control.ServiceError
	if errors.As(err, &serviceErr) {
		switch serviceErr.Code {
		case control.CodeAuthorizationDenied, control.CodeScopeMismatch:
			status, code, message = http.StatusForbidden, "forbidden", "操作未获授权"
		case control.CodeInvalidRequest:
			status, code, message = http.StatusBadRequest, "invalid_request", "操作请求无效"
		case control.CodeIdempotencyConflict:
			status, code, message = http.StatusConflict, "idempotency_conflict", "幂等键已用于其他请求"
		case control.CodeNotFound:
			status, code, message = http.StatusNotFound, "operation_unavailable", "操作不存在或不在授权范围内"
		case control.CodeTransitionConflict:
			status, code, message = http.StatusConflict, "transition_conflict", "操作状态已变化或不允许该转换"
		case control.CodeApprovalRequired:
			status, code, message = http.StatusConflict, "approval_required", "操作需要有效的独立审批"
		case control.CodeIdentityUnbound:
			status, code, message = http.StatusConflict, "identity_unbound", "旧操作缺少可靠身份绑定，禁止迁移"
		case control.CodeAuditDegraded:
			status, code, message = http.StatusServiceUnavailable, "audit_degraded", "证据写入异常，操作未确认完成"
		case control.CodeCommitUnknown:
			status, code, message = http.StatusServiceUnavailable, "commit_unknown", "本地持久化结果未知，必须读回后重试"
		case control.CodeOperationStore:
			status, code, message = http.StatusServiceUnavailable, "operation_store_unavailable", "操作记录暂不可用"
		}
	}
	response := operationEnvelope{Effect: localRecordEffect, Code: code, Message: message}
	if item.ID != "" && code != "commit_unknown" {
		summary := summarizeOperation(item)
		response.Operation = &summary
	}
	writeJSON(w, status, response)
}

func writeOperationError(w http.ResponseWriter, status int, code, message string) {
	writeJSON(w, status, operationEnvelope{Effect: localRecordEffect, Code: code, Message: message})
}

func oneHeader(values []string) (string, bool) {
	if len(values) != 1 {
		return "", false
	}
	return values[0], true
}

func httpIdempotencyKey(value string) (string, bool) {
	if value == "" || value != strings.TrimSpace(value) || len(value) > 200 {
		return "", false
	}
	for _, character := range value {
		if character < 0x21 || character > 0x7e || character == ',' {
			return "", false
		}
	}
	digest := sha256.Sum256([]byte(value))
	return "http-" + hex.EncodeToString(digest[:]), true
}

func boolPointer(value bool) *bool { return &value }

var _ Authenticator = (*authn.Store)(nil)
