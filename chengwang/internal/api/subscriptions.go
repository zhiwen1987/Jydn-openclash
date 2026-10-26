package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"reflect"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"chengwang/internal/authz"
	"chengwang/internal/subscription"
	"chengwang/internal/subscriptionctl"
)

const subscriptionMaxWireBytes = 3 << 19

var subscriptionPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var subscriptionKey = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{15,127}$`)
var subscriptionSourceID = regexp.MustCompile(`^src_[a-f0-9]{32}$`)
var subscriptionCandidateID = regexp.MustCompile(`^cand_[a-f0-9]{32}$`)
var subscriptionCommandID = regexp.MustCompile(`^cmd_[a-f0-9]{32}$`)
var subscriptionNodeID = regexp.MustCompile(`^node_[a-f0-9]{32}$`)
var subscriptionDigest = regexp.MustCompile(`^hmac-sha256:[a-f0-9]{64}$`)
var subscriptionHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var subscriptionDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

type subscriptionEnvelope struct {
	Boundary              string               `json:"boundary"`
	Authorization         string               `json:"authorization"`
	DeviceActionsExecuted bool                 `json:"deviceActionsExecuted"`
	StateMayHaveChanged   bool                 `json:"stateMayHaveChanged"`
	Code                  subscriptionctl.Code `json:"code,omitempty"`
	Result                any                  `json:"result,omitempty"`
}

func nilSubscriptionInterface(value any) bool {
	if value == nil {
		return true
	}
	v := reflect.ValueOf(value)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return v.IsNil()
	}
	return false
}

func subscriptionScopeValid(scope authz.ResourceScope) bool {
	return scope.ObjectType == "subscription-store" && subscriptionPart.MatchString(scope.ObjectID) &&
		subscriptionPart.MatchString(scope.TenantID) && subscriptionPart.MatchString(scope.SiteID) && subscriptionPart.MatchString(scope.Environment)
}

func writeSubscription(w http.ResponseWriter, status int, result any, code subscriptionctl.Code, changed bool) {
	value := subscriptionEnvelope{Boundary: subscriptionctl.Boundary, Authorization: "BLOCKED", Result: result, Code: code, StateMayHaveChanged: changed}
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > subscriptionMaxWireBytes {
		status = http.StatusServiceUnavailable
		raw, _ = json.Marshal(subscriptionEnvelope{Boundary: subscriptionctl.Boundary, Authorization: "BLOCKED", Code: subscriptionctl.CodeUnavailable, StateMayHaveChanged: changed})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(raw, '\n'))
}

func writeSubscriptionError(w http.ResponseWriter, status int, code subscriptionctl.Code, changed bool) {
	writeSubscription(w, status, nil, code, changed)
}

func subscriptionStatus(code subscriptionctl.Code) (int, bool) {
	switch code {
	case subscriptionctl.CodeInvalid:
		return http.StatusBadRequest, true
	case subscriptionctl.CodeForbidden:
		return http.StatusForbidden, true
	case subscriptionctl.CodeLocked:
		return http.StatusLocked, true
	case subscriptionctl.CodeConflict, subscriptionctl.CodeApprovalRequired:
		return http.StatusConflict, true
	case subscriptionctl.CodeNotFound:
		return http.StatusNotFound, true
	case subscriptionctl.CodeLimit:
		return http.StatusTooManyRequests, true
	case subscriptionctl.CodeFetchPolicy:
		return http.StatusForbidden, true
	case subscriptionctl.CodeFetchHTTP:
		return http.StatusBadGateway, true
	case subscriptionctl.CodeFetchRateLimited:
		return http.StatusTooManyRequests, true
	case subscriptionctl.CodeUnavailable, subscriptionctl.CodeFetchUnavailable, subscriptionctl.CodeAuditDegraded, subscriptionctl.CodeCommitUnknown, subscriptionctl.CodeCanceled:
		return http.StatusServiceUnavailable, true
	}
	return http.StatusServiceUnavailable, false
}

func writeSubscriptionBackendError(w http.ResponseWriter, err error, attempted bool) {
	code, changed := subscriptionctl.CodeUnavailable, attempted
	var classified *subscriptionctl.Error
	if errors.As(err, &classified) && classified != nil {
		if _, known := subscriptionStatus(classified.Code); known {
			code, changed = classified.Code, classified.StateMayHaveChanged
		}
	}
	if code == subscriptionctl.CodeCommitUnknown {
		changed = true
	}
	status, _ := subscriptionStatus(code)
	writeSubscriptionError(w, status, code, changed)
}

func (s *server) subscriptionDenied(w http.ResponseWriter, r *http.Request, principal authz.Principal, action authz.Action, code subscriptionctl.Code) {
	w.Header().Set("X-Chengwang-Denial-Audit", "unavailable")
	if s.options.Subscriptions != nil && subscriptionScopeValid(s.subscriptionScope) {
		// Only safe classifications/principal facts reach this separate audit
		// method. Denial cannot fall through to inventory or network methods.
		if s.options.Subscriptions.RecordDenied(r.Context(), principal, action, code) == nil {
			w.Header().Set("X-Chengwang-Denial-Audit", "recorded")
		}
	}
}

func (s *server) subscriptionPreflight(w http.ResponseWriter, r *http.Request, action authz.Action, write bool) (authz.Principal, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strictImageTrustBearer(values[0]) {
		s.subscriptionDenied(w, r, authz.Principal{}, action, subscriptionctl.CodeForbidden)
		w.Header().Set("WWW-Authenticate", `Bearer realm="chengwang"`)
		writeSubscriptionError(w, http.StatusUnauthorized, subscriptionctl.CodeForbidden, false)
		return authz.Principal{}, false
	}
	// Subscription ingress is a new TLS-only surface, including loopback.
	// Existing unrelated management routes retain their old compatibility.
	if r.TLS == nil {
		s.subscriptionDenied(w, r, authz.Principal{}, action, subscriptionctl.CodeForbidden)
		writeSubscriptionError(w, http.StatusUpgradeRequired, subscriptionctl.CodeForbidden, false)
		return authz.Principal{}, false
	}
	if nilSubscriptionInterface(s.options.Authn) {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return authz.Principal{}, false
	}
	principal, err := s.options.Authn.AuthenticateAuthorizationValues(values, time.Now().UTC())
	if err != nil {
		s.subscriptionDenied(w, r, authz.Principal{}, action, subscriptionctl.CodeForbidden)
		w.Header().Set("WWW-Authenticate", `Bearer realm="chengwang"`)
		writeSubscriptionError(w, http.StatusUnauthorized, subscriptionctl.CodeForbidden, false)
		return authz.Principal{}, false
	}
	if s.options.Subscriptions == nil || !subscriptionScopeValid(s.subscriptionScope) {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return authz.Principal{}, false
	}
	sourceID := r.PathValue("sourceId")
	if sourceID != "" && !subscriptionSourceID.MatchString(sourceID) {
		writeSubscriptionError(w, http.StatusBadRequest, subscriptionctl.CodeInvalid, false)
		return authz.Principal{}, false
	}
	if !authz.Evaluate(authz.Request{Principal: principal, Action: action, Resource: subscriptionctl.Resource(s.subscriptionScope, sourceID)}, time.Now().UTC()).Allowed {
		s.subscriptionDenied(w, r, principal, action, subscriptionctl.CodeForbidden)
		writeSubscriptionError(w, http.StatusForbidden, subscriptionctl.CodeForbidden, false)
		return authz.Principal{}, false
	}
	if write && !s.options.SubscriptionWritesEnabled {
		s.subscriptionDenied(w, r, principal, action, subscriptionctl.CodeLocked)
		writeSubscriptionError(w, http.StatusLocked, subscriptionctl.CodeLocked, false)
		return authz.Principal{}, false
	}
	if r.Context().Err() != nil {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeCanceled, false)
		return authz.Principal{}, false
	}
	return principal, true
}

func subscriptionRequest(w http.ResponseWriter, r *http.Request, method string, page bool) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeSubscriptionError(w, http.StatusMethodNotAllowed, subscriptionctl.CodeInvalid, false)
		return false
	}
	if r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || r.URL.ForceQuery ||
		(!page && r.URL.RawQuery != "") || len(r.Header.Values("Content-Encoding")) != 0 {
		writeSubscriptionError(w, http.StatusBadRequest, subscriptionctl.CodeInvalid, false)
		return false
	}
	if method == http.MethodGet {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			writeSubscriptionError(w, http.StatusBadRequest, subscriptionctl.CodeInvalid, false)
			return false
		}
		return true
	}
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		writeSubscriptionError(w, http.StatusUnsupportedMediaType, subscriptionctl.CodeInvalid, false)
		return false
	}
	media, parameters, err := mime.ParseMediaType(values[0])
	if err != nil || media != "application/json" || len(parameters) > 1 ||
		(len(parameters) == 1 && !strings.EqualFold(parameters["charset"], "utf-8")) {
		writeSubscriptionError(w, http.StatusUnsupportedMediaType, subscriptionctl.CodeInvalid, false)
		return false
	}
	return true
}

func subscriptionPage(r *http.Request) (subscriptionctl.ListQuery, bool) {
	query := subscriptionctl.ListQuery{Limit: 50}
	seen := map[string]bool{}
	if r.URL.RawQuery == "" {
		return query, true
	}
	for _, field := range strings.Split(r.URL.RawQuery, "&") {
		name, value, found := strings.Cut(field, "=")
		if !found || seen[name] || !subscriptionDecimal.MatchString(value) {
			return query, false
		}
		seen[name] = true
		switch name {
		case "limit", "offset":
			n, err := strconv.ParseUint(value, 10, strconv.IntSize-1)
			if err != nil || name == "limit" && (n < 1 || n > subscriptionctl.MaxPageSize) {
				return query, false
			}
			if name == "limit" {
				query.Limit = int(n)
			} else {
				query.Offset = int(n)
			}
		case "revision":
			n, err := strconv.ParseUint(value, 10, 64)
			if err != nil {
				return query, false
			}
			query.Revision = n
		default:
			return query, false
		}
	}
	return query, true
}

func (s *server) subscriptionSources(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.subscriptionExecute(w, r, subscriptionctl.Create)
		return
	}
	principal, ok := s.subscriptionPreflight(w, r, authz.ActionReadSubscription, false)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		writeSubscriptionError(w, http.StatusMethodNotAllowed, subscriptionctl.CodeInvalid, false)
		return
	}
	if !subscriptionRequest(w, r, http.MethodGet, false) {
		return
	}
	page, err := s.options.Subscriptions.ListSources(r.Context(), principal)
	if err != nil {
		writeSubscriptionBackendError(w, err, false)
		return
	}
	if !s.subscriptionSourcesValid(page) {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return
	}
	writeSubscription(w, http.StatusOK, page, "", false)
}

func (s *server) subscriptionRefreshes(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.subscriptionPreflight(w, r, authz.ActionReadSubscription, false)
	if !ok || !subscriptionRequest(w, r, http.MethodGet, false) {
		return
	}
	reader, ok := s.options.Subscriptions.(subscriptionctl.RefreshReader)
	if !ok {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return
	}
	page, err := reader.ListRefreshes(r.Context(), principal)
	if err != nil {
		writeSubscriptionBackendError(w, err, false)
		return
	}
	if !s.subscriptionRefreshPageValid(page) {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return
	}
	writeSubscription(w, http.StatusOK, page, "", false)
}

func (s *server) subscriptionRefresh(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.subscriptionPreflight(w, r, authz.ActionReadSubscription, false)
	if !ok || !subscriptionRequest(w, r, http.MethodGet, false) {
		return
	}
	sourceID := r.PathValue("sourceId")
	if !subscriptionSourceID.MatchString(sourceID) {
		writeSubscriptionError(w, http.StatusBadRequest, subscriptionctl.CodeInvalid, false)
		return
	}
	reader, ok := s.options.Subscriptions.(subscriptionctl.RefreshReader)
	if !ok {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return
	}
	value, err := reader.ReadRefresh(r.Context(), principal, sourceID)
	if err != nil {
		writeSubscriptionBackendError(w, err, false)
		return
	}
	if !s.subscriptionRefreshValid(value, sourceID) {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return
	}
	writeSubscription(w, http.StatusOK, value, "", false)
}

func (s *server) subscriptionRefreshPageValid(page subscriptionctl.RefreshPage) bool {
	if page.Refreshes == nil || page.Total != len(page.Refreshes) || page.Total > subscription.MaxSources || page.Capacity.CommandsUsed < 0 || page.Capacity.CommandsUsed > page.Capacity.CommandsMax || page.Capacity.CommandsMax != subscription.MaxControlCommands || page.Capacity.CandidatesUsed < 0 || page.Capacity.CandidatesUsed > page.Capacity.CandidatesMax || page.Capacity.CandidatesMax != subscription.MaxCandidates || page.Capacity.DomainAuditUsed < 0 || page.Capacity.DomainAuditUsed > page.Capacity.DomainAuditMax || page.Capacity.DomainAuditMax != subscription.MaxAuditEntries {
		return false
	}
	seen := map[string]bool{}
	for _, value := range page.Refreshes {
		if seen[value.Binding.SourceID] || !s.subscriptionRefreshValid(value, value.Binding.SourceID) {
			return false
		}
		seen[value.Binding.SourceID] = true
	}
	return true
}

func (s *server) subscriptionRefreshValid(value subscription.RefreshView, sourceID string) bool {
	binding := value.Binding
	if binding.SourceID != sourceID || !subscriptionSourceID.MatchString(sourceID) || !subscriptionPart.MatchString(binding.ReferenceID) || !subscriptionCommandID.MatchString(binding.ApprovalID) ||
		binding.PolicyRevision == 0 || binding.ApprovalSourceRevision == 0 || binding.IntervalSeconds < uint64(subscription.MinRefreshInterval/time.Second) || binding.IntervalSeconds > uint64(subscription.MaxRefreshInterval/time.Second) ||
		binding.ApprovalTTLSeconds < uint64(subscription.MinRefreshInterval/time.Second) || binding.ApprovalTTLSeconds > uint64(subscription.MaxApprovalTTL/time.Second) || binding.MaxStaleSeconds < binding.IntervalSeconds || binding.MaxStaleSeconds > uint64(subscription.MaxApprovalTTL/time.Second) ||
		binding.MaxBackoffSeconds < binding.IntervalSeconds || binding.MaxBackoffSeconds > uint64(subscription.MaxRefreshInterval/time.Second) || value.Scope.TenantID != s.subscriptionScope.TenantID || value.Scope.SiteID != s.subscriptionScope.SiteID || value.Scope.Environment != s.subscriptionScope.Environment || !subscriptionDigest.MatchString(value.BindingSeal) || value.BindingGeneration == 0 {
		return false
	}
	switch value.State {
	case subscription.RefreshIdle, subscription.RefreshRunning, subscription.RefreshSucceededNoop, subscription.RefreshCandidateQuarantined, subscription.RefreshFailed, subscription.RefreshBlocked, subscription.RefreshUnknown:
	default:
		return false
	}
	switch value.Failure {
	case subscription.RefreshFailureNone, subscription.RefreshFailureApproval, subscription.RefreshFailurePolicy, subscription.RefreshFailureTransport,
		subscription.RefreshFailureHTTP, subscription.RefreshFailureRate, subscription.RefreshFailureInput, subscription.RefreshFailureLimit,
		subscription.RefreshFailureConflict, subscription.RefreshFailureAudit, subscription.RefreshFailureUnknown, subscription.RefreshFailureCanceled,
		subscription.RefreshFailureForbidden, subscription.RefreshFailureUnavailable, subscription.RefreshFailureClock, subscription.RefreshFailureSequence:
	default:
		return false
	}
	if value.ClockState != subscription.RefreshClockNormal && value.ClockState != subscription.RefreshClockFrozen || value.ClockState == subscription.RefreshClockNormal && value.ClockReason != "" || value.ClockState == subscription.RefreshClockFrozen && value.ClockReason == "" || value.AttemptKey != "" && !subscriptionKey.MatchString(value.AttemptKey) || value.Fence != "" && !subscriptionHash.MatchString(value.Fence) || value.CommandID != "" && !subscriptionCommandID.MatchString(value.CommandID) || value.CandidateID != "" && !subscriptionCandidateID.MatchString(value.CandidateID) || value.CandidateDigest != "" && !subscriptionDigest.MatchString(value.CandidateDigest) {
		return false
	}
	if value.StoragePending != (value.StorageRetryCount > 0) || value.StoragePending != (!value.StorageNextRetryAt.IsZero()) {
		return false
	}
	switch value.State {
	case subscription.RefreshIdle:
		return value.AttemptCount == 0 && value.AttemptSequence == 0 && value.AttemptKey == "" && value.Fence == "" && value.Failure == "" && !value.NextAttemptAt.IsZero() && !value.AuditRecorded && !value.StateMayHaveChanged
	case subscription.RefreshRunning:
		return value.AttemptCount > 0 && value.AttemptSequence > 0 && value.AttemptKey != "" && value.Fence != "" && !value.StartedAt.IsZero() && value.CompletedAt.IsZero() && value.NextAttemptAt.IsZero() && value.Failure == "" && !value.StateMayHaveChanged
	case subscription.RefreshCandidateQuarantined:
		return value.AttemptCount > 0 && value.CommandID != "" && value.CandidateID != "" && value.CandidateDigest != "" && value.ResultRevision > 0 && !value.CompletedAt.IsZero() && value.LastSuccessAt.Equal(value.CompletedAt) && value.FreshUntil.After(value.LastSuccessAt) && value.NextAttemptAt.IsZero() && value.Failure == "" && value.AuditRecorded && !value.StateMayHaveChanged
	case subscription.RefreshSucceededNoop:
		return value.AttemptCount > 0 && value.CommandID != "" && value.CandidateID != "" && value.CandidateDigest != "" && value.ResultRevision > 0 && !value.CompletedAt.IsZero() && value.LastSuccessAt.Equal(value.CompletedAt) && value.FreshUntil.After(value.LastSuccessAt) && value.NextAttemptAt.After(value.CompletedAt) && value.Failure == "" && value.AuditRecorded && !value.StateMayHaveChanged
	case subscription.RefreshFailed:
		return value.AttemptCount > 0 && value.Failure != "" && value.ConsecutiveFailures > 0 && !value.CompletedAt.IsZero() && value.NextAttemptAt.After(value.CompletedAt) && !value.StateMayHaveChanged
	case subscription.RefreshBlocked:
		return (value.AttemptCount > 0 && !value.CompletedAt.IsZero() || value.Failure == subscription.RefreshFailureSequence) && value.Failure != "" && value.NextAttemptAt.IsZero() && !value.StateMayHaveChanged
	case subscription.RefreshUnknown:
		return value.AttemptCount > 0 && value.Failure == subscription.RefreshFailureUnknown && !value.CompletedAt.IsZero() && value.NextAttemptAt.IsZero() && value.StateMayHaveChanged
	}
	return false
}

func (s *server) subscriptionCandidates(w http.ResponseWriter, r *http.Request) {
	if r.Method == http.MethodPost {
		s.subscriptionExecute(w, r, subscriptionctl.Import)
		return
	}
	principal, ok := s.subscriptionPreflight(w, r, authz.ActionReadSubscription, false)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", "GET, POST")
		writeSubscriptionError(w, http.StatusMethodNotAllowed, subscriptionctl.CodeInvalid, false)
		return
	}
	if !subscriptionRequest(w, r, http.MethodGet, true) {
		return
	}
	query, ok := subscriptionPage(r)
	if !ok {
		writeSubscriptionError(w, http.StatusBadRequest, subscriptionctl.CodeInvalid, false)
		return
	}
	page, err := s.options.Subscriptions.ListCandidates(r.Context(), principal, r.PathValue("sourceId"), query)
	if err != nil {
		writeSubscriptionBackendError(w, err, false)
		return
	}
	if !subscriptionCandidatesValid(page, query, r.PathValue("sourceId")) {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return
	}
	writeSubscription(w, http.StatusOK, page, "", false)
}

func (s *server) subscriptionNodes(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.subscriptionPreflight(w, r, authz.ActionReadSubscription, false)
	if !ok || !subscriptionRequest(w, r, http.MethodGet, true) {
		return
	}
	query, ok := subscriptionPage(r)
	if !ok || !subscriptionCandidateID.MatchString(r.PathValue("candidateId")) {
		writeSubscriptionError(w, http.StatusBadRequest, subscriptionctl.CodeInvalid, false)
		return
	}
	page, err := s.options.Subscriptions.ListNodes(r.Context(), principal, r.PathValue("sourceId"), r.PathValue("candidateId"), query)
	if err != nil {
		writeSubscriptionBackendError(w, err, false)
		return
	}
	if !subscriptionNodesValid(page, query) {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return
	}
	writeSubscription(w, http.StatusOK, page, "", false)
}

func (s *server) subscriptionDecision(w http.ResponseWriter, r *http.Request) {
	s.subscriptionExecute(w, r, subscriptionctl.Decide)
}
func (s *server) subscriptionRollback(w http.ResponseWriter, r *http.Request) {
	s.subscriptionExecute(w, r, subscriptionctl.Rollback)
}
func (s *server) subscriptionApproval(w http.ResponseWriter, r *http.Request) {
	s.subscriptionExecute(w, r, subscriptionctl.Approve)
}
func (s *server) subscriptionFetch(w http.ResponseWriter, r *http.Request) {
	s.subscriptionExecute(w, r, subscriptionctl.Fetch)
}

func (s *server) subscriptionExecute(w http.ResponseWriter, r *http.Request, kind subscriptionctl.Kind) {
	principal, ok := s.subscriptionPreflight(w, r, subscriptionctl.ActionFor(kind), true)
	if !ok || !subscriptionRequest(w, r, http.MethodPost, false) {
		return
	}
	keys := r.Header.Values("Idempotency-Key")
	if len(keys) != 1 || !subscriptionKey.MatchString(keys[0]) {
		writeSubscriptionError(w, http.StatusBadRequest, subscriptionctl.CodeInvalid, false)
		return
	}
	command, ok := subscriptionBody(w, r, kind)
	if !ok {
		return
	}
	command.Kind, command.SourceID, command.IdempotencyKey = kind, r.PathValue("sourceId"), keys[0]
	if r.Context().Err() != nil {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeCanceled, false)
		return
	}
	receipt, err := s.options.Subscriptions.Execute(r.Context(), principal, command)
	if err != nil {
		var classified *subscriptionctl.Error
		if errors.As(err, &classified) && classified != nil {
			_, known := subscriptionStatus(classified.Code)
			if known && subscriptionCommandID.MatchString(receipt.CommandID) && receipt.Kind == kind &&
				(command.SourceID == "" || receipt.SourceID == command.SourceID) {
				// This is only a handle for protected, read-only reconciliation.
				// It neither confirms completion nor recommends retrying mutation.
				w.Header().Set("X-Chengwang-Command-ID", receipt.CommandID)
			}
		}
		writeSubscriptionBackendError(w, err, true)
		return
	}
	if !subscriptionReceiptValid(receipt) || receipt.Kind != kind || receipt.Code != "" || !receipt.AuditRecorded || receipt.StateMayHaveChanged ||
		(receipt.State != "committed" && receipt.State != "noop" && receipt.State != "approved") || receipt.CompletedAt.IsZero() ||
		!subscriptionHash.MatchString(receipt.PreparedAuditHash) || !subscriptionHash.MatchString(receipt.ResultAuditHash) ||
		command.SourceID != "" && receipt.SourceID != command.SourceID {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, true)
		return
	}
	writeSubscription(w, http.StatusOK, receipt, "", receipt.StateMayHaveChanged)
}

func (s *server) subscriptionReceipt(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.subscriptionPreflight(w, r, authz.ActionReadSubscription, false)
	if !ok || !subscriptionRequest(w, r, http.MethodGet, false) {
		return
	}
	id := r.PathValue("commandId")
	if !subscriptionCommandID.MatchString(id) {
		writeSubscriptionError(w, http.StatusBadRequest, subscriptionctl.CodeInvalid, false)
		return
	}
	receipt, err := s.options.Subscriptions.ReadReceipt(r.Context(), principal, id)
	if err != nil {
		writeSubscriptionBackendError(w, err, false)
		return
	}
	if !subscriptionReceiptValid(receipt) || receipt.CommandID != id {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return
	}
	writeSubscription(w, http.StatusOK, receipt, "", receipt.StateMayHaveChanged)
}

func (s *server) subscriptionUnavailableRoute(w http.ResponseWriter, r *http.Request) {
	if _, ok := s.subscriptionPreflight(w, r, authz.ActionReadSubscription, false); ok {
		writeSubscriptionError(w, http.StatusNotFound, subscriptionctl.CodeNotFound, false)
	}
}

func subscriptionBody(w http.ResponseWriter, r *http.Request, kind subscriptionctl.Kind) (subscriptionctl.Command, bool) {
	command := subscriptionctl.Command{}
	bad := func() (subscriptionctl.Command, bool) {
		writeSubscriptionError(w, http.StatusBadRequest, subscriptionctl.CodeInvalid, false)
		return command, false
	}
	if r.Body == nil {
		return bad()
	}
	defer r.Body.Close()
	if r.ContentLength > subscriptionMaxWireBytes {
		writeSubscriptionError(w, http.StatusRequestEntityTooLarge, subscriptionctl.CodeLimit, false)
		return command, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, subscriptionMaxWireBytes+1))
	if len(raw) > subscriptionMaxWireBytes {
		writeSubscriptionError(w, http.StatusRequestEntityTooLarge, subscriptionctl.CodeLimit, false)
		return command, false
	}
	if err != nil || r.ContentLength >= 0 && int64(len(raw)) != r.ContentLength || !utf8.Valid(raw) {
		return bad()
	}
	object, ok := subscriptionObject(raw)
	if !ok {
		return bad()
	}
	required := map[subscriptionctl.Kind][]string{
		subscriptionctl.Create: {"label"}, subscriptionctl.Import: {"expectedRevision", "format", "contentBase64"},
		subscriptionctl.Decide:   {"candidateId", "expectedRevision", "expectedDigest", "decision"},
		subscriptionctl.Rollback: {"candidateId", "expectedRevision"},
		subscriptionctl.Approve:  {"referenceId", "policyRevision", "expectedRevision"},
		subscriptionctl.Fetch:    {"approvalId", "policyRevision", "expectedRevision"},
	}[kind]
	if required == nil || !exactImageTrustKeys(object, required...) {
		return bad()
	}
	text := func(name string) string { value, _ := object[name].(string); return value }
	if kind == subscriptionctl.Create {
		command.Label = text("label")
		if !subscriptionLabel(command.Label) {
			return bad()
		}
		return command, true
	}
	command.ExpectedRevision, ok = subscriptionUint(object["expectedRevision"])
	if !ok || command.ExpectedRevision == 0 {
		return bad()
	}
	switch kind {
	case subscriptionctl.Import:
		command.Format = subscription.Format(text("format"))
		if !subscriptionFormat(command.Format, true) {
			return bad()
		}
		encoded := text("contentBase64")
		if len(encoded) == 0 || len(encoded) > base64.StdEncoding.EncodedLen(subscription.MaxInputBytes) {
			return bad()
		}
		command.Content, err = base64.StdEncoding.Strict().DecodeString(encoded)
		if err != nil || len(command.Content) == 0 || len(command.Content) > subscription.MaxInputBytes || base64.StdEncoding.EncodeToString(command.Content) != encoded {
			return bad()
		}
	case subscriptionctl.Decide, subscriptionctl.Rollback:
		command.CandidateID = text("candidateId")
		if !subscriptionCandidateID.MatchString(command.CandidateID) {
			return bad()
		}
		if kind == subscriptionctl.Decide {
			command.ExpectedDigest, command.Decision = text("expectedDigest"), subscription.CandidateState(text("decision"))
			if !subscriptionDigest.MatchString(command.ExpectedDigest) || command.Decision != subscription.CandidateAdmitted && command.Decision != subscription.CandidateRejected {
				return bad()
			}
		}
	case subscriptionctl.Approve, subscriptionctl.Fetch:
		command.PolicyRevision, ok = subscriptionUint(object["policyRevision"])
		if !ok || command.PolicyRevision == 0 {
			return bad()
		}
		if kind == subscriptionctl.Approve {
			command.ReferenceID = text("referenceId")
			if !subscriptionPart.MatchString(command.ReferenceID) {
				return bad()
			}
		} else {
			command.ApprovalID = text("approvalId")
			if !subscriptionCommandID.MatchString(command.ApprovalID) {
				return bad()
			}
		}
	}
	return command, true
}

func subscriptionObject(raw []byte) (map[string]any, bool) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	budget := 0
	var read func(int) (any, bool)
	read = func(depth int) (any, bool) {
		budget++
		if depth > 8 || budget > 4096 {
			return nil, false
		}
		token, err := d.Token()
		if err != nil {
			return nil, false
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				object := map[string]any{}
				for d.More() {
					key, err := d.Token()
					name, valid := key.(string)
					if err != nil || !valid {
						return nil, false
					}
					if _, exists := object[name]; exists {
						return nil, false
					}
					value, valid := read(depth + 1)
					if !valid {
						return nil, false
					}
					object[name] = value
				}
				end, err := d.Token()
				return object, err == nil && end == json.Delim('}')
			case '[':
				array := []any{}
				for d.More() {
					value, valid := read(depth + 1)
					if !valid {
						return nil, false
					}
					array = append(array, value)
				}
				end, err := d.Token()
				return array, err == nil && end == json.Delim(']')
			default:
				return nil, false
			}
		}
		return token, true
	}
	value, ok := read(0)
	if !ok {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	object, ok := value.(map[string]any)
	return object, ok
}

func subscriptionUint(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok || !subscriptionDecimal.MatchString(string(number)) {
		return 0, false
	}
	n, err := strconv.ParseUint(string(number), 10, 64)
	return n, err == nil
}

func subscriptionFormat(value subscription.Format, auto bool) bool {
	return value == subscription.FormatMihomo || value == subscription.FormatURI || value == subscription.FormatBase64URI || auto && value == subscription.FormatAuto
}

func subscriptionLabel(value string) bool {
	if value == "" || len(value) > 128 || !utf8.ValidString(value) || strings.TrimSpace(value) != value {
		return false
	}
	for _, character := range value {
		if !unicode.IsLetter(character) && !unicode.IsDigit(character) && !strings.ContainsRune(" ._-", character) {
			return false
		}
	}
	return true
}

func (s *server) subscriptionSourcesValid(page subscriptionctl.SourcePage) bool {
	if page.Sources == nil || page.Total != len(page.Sources) || page.Total > subscription.MaxSources {
		return false
	}
	seen := map[string]bool{}
	for _, source := range page.Sources {
		if !subscriptionSourceID.MatchString(source.ID) || seen[source.ID] || !subscriptionLabel(source.Label) || source.Revision == 0 || source.UpdatedAt.IsZero() ||
			source.Scope.TenantID != s.subscriptionScope.TenantID || source.Scope.SiteID != s.subscriptionScope.SiteID || source.Scope.Environment != s.subscriptionScope.Environment ||
			(source.AcceptedCandidateID != "" && !subscriptionCandidateID.MatchString(source.AcceptedCandidateID)) ||
			(source.LatestCandidateID != "" && !subscriptionCandidateID.MatchString(source.LatestCandidateID)) {
			return false
		}
		seen[source.ID] = true
	}
	return true
}

func subscriptionPageValid(total, count, maximum int, revision uint64, next *int, query subscriptionctl.ListQuery) bool {
	if total < 0 || total > maximum || count < 0 || count > query.Limit || revision == 0 || query.Revision != 0 && revision != query.Revision {
		return false
	}
	remaining := 0
	if query.Offset < total {
		remaining = total - query.Offset
	}
	if count != min(query.Limit, remaining) {
		return false
	}
	if remaining > count {
		return next != nil && *next == query.Offset+count
	}
	return next == nil
}

func subscriptionCandidatesValid(page subscriptionctl.CandidatePage, query subscriptionctl.ListQuery, sourceID string) bool {
	if page.Candidates == nil || !subscriptionPageValid(page.Total, len(page.Candidates), subscription.MaxCandidates, page.Revision, page.NextOffset, query) {
		return false
	}
	seen := map[string]bool{}
	for _, candidate := range page.Candidates {
		if !subscriptionCandidateID.MatchString(candidate.ID) || seen[candidate.ID] || candidate.SourceID != sourceID || !subscriptionDigest.MatchString(candidate.Digest) ||
			!subscriptionFormat(candidate.Format, false) || candidate.BaseRevision < 2 || candidate.BaseRevision > page.Revision || candidate.CreatedAt.IsZero() ||
			candidate.NodeCount < 1 || candidate.NodeCount > subscription.MaxNodes || candidate.DuplicateCount < 0 || candidate.DuplicateCount > subscription.MaxNodes-candidate.NodeCount ||
			(candidate.State != subscription.CandidateQuarantined && candidate.State != subscription.CandidateAdmitted && candidate.State != subscription.CandidateRejected) {
			return false
		}
		seen[candidate.ID] = true
	}
	return true
}

func subscriptionNodesValid(page subscriptionctl.NodePage, query subscriptionctl.ListQuery) bool {
	if page.Nodes == nil || !subscriptionPageValid(page.Total, len(page.Nodes), subscription.MaxNodes, page.Revision, page.NextOffset, query) {
		return false
	}
	seen := map[string]bool{}
	for _, node := range page.Nodes {
		if !subscriptionNodeID.MatchString(node.ID) || seen[node.ID] || node.Label != "节点-"+node.ID[len(node.ID)-8:] || node.State != "unknown" ||
			!subscriptionProtocol(node.Protocol) {
			return false
		}
		seen[node.ID] = true
	}
	return true
}

func subscriptionProtocol(protocol string) bool {
	switch protocol {
	case "ss", "vmess", "vless", "trojan", "http", "socks5":
		return true
	}
	return false
}

func subscriptionReceiptValid(receipt subscriptionctl.Receipt) bool {
	if !subscriptionCommandID.MatchString(receipt.CommandID) || subscriptionctl.ActionFor(receipt.Kind) == "" || !subscriptionPart.MatchString(receipt.State) ||
		(receipt.SourceID != "" && !subscriptionSourceID.MatchString(receipt.SourceID)) || (receipt.CandidateID != "" && !subscriptionCandidateID.MatchString(receipt.CandidateID)) ||
		(receipt.CandidateDigest != "" && !subscriptionDigest.MatchString(receipt.CandidateDigest)) ||
		(receipt.ReferenceID != "" && !subscriptionPart.MatchString(receipt.ReferenceID)) || (receipt.ApprovalID != "" && !subscriptionCommandID.MatchString(receipt.ApprovalID)) ||
		(receipt.PolicyDigest != "" && !subscriptionDigest.MatchString(receipt.PolicyDigest)) {
		return false
	}
	for _, hash := range []string{receipt.PreparedAuditHash, receipt.ResultAuditHash, receipt.LocalAuditHash} {
		if hash != "" && !subscriptionHash.MatchString(hash) {
			return false
		}
	}
	if receipt.Code != "" {
		_, known := subscriptionStatus(receipt.Code)
		if !known {
			return false
		}
	}
	if receipt.AuditRecorded && (!subscriptionHash.MatchString(receipt.PreparedAuditHash) || !subscriptionHash.MatchString(receipt.ResultAuditHash)) {
		return false
	}
	switch receipt.State {
	case "committed":
		return receipt.Code == "" && receipt.Revision > 0 && subscriptionSourceID.MatchString(receipt.SourceID) && !receipt.CompletedAt.IsZero() && subscriptionHash.MatchString(receipt.LocalAuditHash)
	case "noop", "approved":
		return receipt.Code == "" && receipt.Revision > 0 && subscriptionSourceID.MatchString(receipt.SourceID) && !receipt.CompletedAt.IsZero() && receipt.LocalAuditHash == ""
	case "failed":
		return receipt.Code != "" && !receipt.StateMayHaveChanged && !receipt.CompletedAt.IsZero()
	case "unknown", "prepared":
		return receipt.Code == subscriptionctl.CodeCommitUnknown && receipt.StateMayHaveChanged
	}
	return false
}
