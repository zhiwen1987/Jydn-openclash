package api

import (
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/authz"
	"chengwang/internal/mihomodeploy"
)

const mihomoLabPrefix = "/api/v1/lab/mihomo"
const mihomoLabBodyLimit = 4096
const mihomoLabResponseLimit = 16 << 10

var mihomoLabID = regexp.MustCompile(`^labop_[a-f0-9]{32}$`)
var mihomoLabHash = regexp.MustCompile(`^[a-f0-9]{64}$`)
var mihomoLabPart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)
var mihomoLabUint = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)

type mihomoLabEnvelope struct {
	Boundary            string `json:"boundary"`
	Code                string `json:"code"`
	StateMayHaveChanged bool   `json:"stateMayHaveChanged"`
	Result              any    `json:"result"`
}

func writeMihomoLab(w http.ResponseWriter, status int, code string, changed bool, result any) {
	raw, err := json.Marshal(mihomoLabEnvelope{mihomodeploy.LabBackendBoundary, code, changed, result})
	if err != nil || len(raw)+1 > mihomoLabResponseLimit {
		status = http.StatusServiceUnavailable
		raw, _ = json.Marshal(mihomoLabEnvelope{mihomodeploy.LabBackendBoundary, "mihomo_lab_unavailable", changed, nil})
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_, _ = w.Write(append(raw, '\n'))
}
func mihomoLabError(w http.ResponseWriter, status int, code string, changed bool) {
	writeMihomoLab(w, status, code, changed, nil)
}
func mihomoLabBackendError(w http.ResponseWriter, err error, attempted bool) {
	status, code, changed := http.StatusServiceUnavailable, "mihomo_lab_unavailable", attempted
	var classified *mihomodeploy.LabBackendError
	if errors.As(err, &classified) && classified != nil {
		switch classified.Code {
		case mihomodeploy.LabBackendInvalid:
			status, code = 400, "mihomo_lab_invalid"
		case mihomodeploy.LabBackendUnauthenticated:
			status, code = 401, "mihomo_lab_unauthenticated"
		case mihomodeploy.LabBackendForbidden:
			status, code = 403, "mihomo_lab_forbidden"
		case mihomodeploy.LabBackendNotFound:
			status, code = 404, "mihomo_lab_not_found"
		case mihomodeploy.LabBackendConflict:
			status, code = 409, "mihomo_lab_conflict"
		case mihomodeploy.LabBackendUnavailable, mihomodeploy.LabBackendInternal:
			status, code = 503, "mihomo_lab_unavailable"
		default:
			mihomoLabError(w, status, code, changed)
			return
		}
		changed = classified.StateMayHaveChanged
	}
	if status == 401 {
		w.Header().Set("WWW-Authenticate", `Bearer realm="chengwang"`)
	}
	mihomoLabError(w, status, code, changed)
}
func validMihomoLabScope(v authz.ResourceScope) bool {
	return v.ObjectType == mihomodeploy.LabObjectType && v.Environment == mihomodeploy.LabEnvironment &&
		mihomoLabPart.MatchString(v.TenantID) && mihomoLabPart.MatchString(v.SiteID) && mihomoLabPart.MatchString(v.ObjectID)
}
func validMihomoLabHash(v string) bool {
	return mihomoLabHash.MatchString(v) && v != strings.Repeat("0", 64)
}
func validMihomoLabTime(v time.Time) bool {
	return !v.IsZero() && v.Year() >= 1 && v.Year() <= 9999 && v.Location() == time.UTC
}
func validMihomoLabProof(v mihomodeploy.LabProofView) bool {
	return !v.FullPayloadProven && !v.InternetBusinessProven && !v.Production
}
func validMihomoLabView(v mihomodeploy.LabDeploymentView, id string) bool {
	if v.Schema != mihomodeploy.LabDeploymentViewSchema || v.Boundary != mihomodeploy.LabBackendBoundary ||
		!mihomoLabID.MatchString(v.OperationID) || (id != "" && v.OperationID != id) || v.Revision == 0 || v.HeadGeneration == 0 ||
		!validMihomoLabHash(v.PlanSHA256) || !validMihomoLabHash(v.CandidateRecordSHA256) || !validMihomoLabHash(v.CandidateConfigSHA256) ||
		!validMihomoLabHash(v.PreviousHeadSHA256) || !validMihomoLabHash(v.HeadSHA256) || !validMihomoLabTime(v.ExpiresAt) || !validMihomoLabProof(v.Proof) {
		return false
	}
	switch v.Phase {
	case "PLANNED", "APPROVED", "PREPARED", "UNSENT_REJECTED", "REVOKED":
		if v.HeadAdvanced {
			return false
		}
	case "INTENT_ARMED", "ACKNOWLEDGED", "UNKNOWN", "MANUAL_REQUIRED", "RESPONSE_REJECTED":
		if v.HeadAdvanced || !v.WriteBlocked {
			return false
		}
	case "COMPLETED":
		if !v.HeadAdvanced || v.HeadGeneration < 2 || v.HeadSHA256 == v.PreviousHeadSHA256 {
			return false
		}
	default:
		return false
	}
	if v.Transport != nil {
		t := v.Transport
		if !validMihomoLabTime(t.RecordedAt) || t.Result.StatusCode < 0 || t.Result.StatusCode > 599 {
			return false
		}
		switch t.Result.State {
		case mihomo.ReloadAcknowledged:
			if !t.Result.Dispatched || t.Result.StatusCode != 204 {
				return false
			}
		case mihomo.ReloadRejected:
			if t.Result.Dispatched && (t.Result.StatusCode < 400 || t.Result.StatusCode > 499) {
				return false
			}
			if !t.Result.Dispatched && t.Result.StatusCode != 0 {
				return false
			}
		case mihomo.ReloadUnknown:
			if !t.Result.Dispatched || !v.WriteBlocked || v.HeadAdvanced {
				return false
			}
		default:
			return false
		}
		switch t.Origin {
		case "ADAPTER":
			if t.GateReason != nil {
				return false
			}
		case "SERVICE_GATE":
			if t.GateReason == nil || t.Result.State != mihomo.ReloadRejected || t.Result.Dispatched || t.Result.StatusCode != 0 {
				return false
			}
			switch *t.GateReason {
			case "FINAL_AUTHORIZATION_REJECTED", "OWNED_IDENTITY_REJECTED", "SERVICE_CONTEXT_CANCELLED":
			default:
				return false
			}
		default:
			return false
		}
	}
	// Phase constrains which recorded transport fact may exist. Reopening
	// ARMED may have no result; reopening after ACK retains its original204.
	// UNKNOWN is uncertainty, never an instruction to rewrite that result.
	switch v.Phase {
	case "PLANNED", "APPROVED", "PREPARED", "REVOKED", "INTENT_ARMED":
		if v.Transport != nil {
			return false
		}
	case "ACKNOWLEDGED", "COMPLETED":
		if v.Transport == nil || v.Transport.Origin != "ADAPTER" || v.Transport.Result.State != mihomo.ReloadAcknowledged {
			return false
		}
	case "UNSENT_REJECTED":
		if v.Transport == nil || v.Transport.Result.State != mihomo.ReloadRejected || v.Transport.Result.Dispatched || v.Transport.Result.StatusCode != 0 {
			return false
		}
	case "RESPONSE_REJECTED":
		if v.Transport == nil || v.Transport.Origin != "ADAPTER" || v.Transport.Result.State != mihomo.ReloadRejected || !v.Transport.Result.Dispatched || v.Transport.Result.StatusCode < 400 || v.Transport.Result.StatusCode > 499 {
			return false
		}
	case "UNKNOWN":
		if v.Transport != nil && v.Transport.Origin != "ADAPTER" {
			return false
		}
	case "MANUAL_REQUIRED":
		// Preserve an absent or already validated original fact. The phase
		// checks above always retain its write barrier and forbid head advance.
	}
	if v.Observation != nil {
		o := v.Observation
		if !validMihomoLabHash(o.EvidenceSHA256) || !validMihomoLabTime(o.ObservedAt) ||
			(o.ObservedProjectionSHA256 != nil && !validMihomoLabHash(*o.ObservedProjectionSHA256)) {
			return false
		}
		switch o.Conclusion {
		case mihomo.LabStableNewProjection, mihomo.LabStableOldProjection, mihomo.LabProjectionAmbiguous, mihomo.LabProjectionDrift, mihomo.LabProjectionUnstable:
		default:
			return false
		}
	}
	if v.Phase == "COMPLETED" && (v.Observation == nil || v.Observation.Conclusion != mihomo.LabStableNewProjection || !v.Observation.LocalRouteVerified) {
		return false
	}
	return true
}
func validMihomoLabHead(v mihomodeploy.LabHeadView) bool {
	valid := v.Schema == mihomodeploy.LabHeadViewSchema && v.Boundary == mihomodeploy.LabBackendBoundary && v.Revision > 0 && v.Generation > 0 &&
		validMihomoLabHash(v.HeadSHA256) && validMihomoLabHash(v.ArtifactRecordSHA256) && validMihomoLabHash(v.ConfigSHA256) &&
		validMihomoLabHash(v.VerificationSHA256) && validMihomoLabTime(v.VerifiedAt) && validMihomoLabProof(v.Proof) &&
		(v.ActiveOperationID == nil || mihomoLabID.MatchString(*v.ActiveOperationID))
	if !valid {
		return false
	}
	if v.Generation == 1 {
		return v.PreviousHeadSHA256 == nil
	}
	return v.PreviousHeadSHA256 != nil && validMihomoLabHash(*v.PreviousHeadSHA256) && *v.PreviousHeadSHA256 != v.HeadSHA256
}
func detachedMihomoLabHead(v mihomodeploy.LabHeadView) mihomodeploy.LabHeadView {
	if v.PreviousHeadSHA256 != nil {
		value := *v.PreviousHeadSHA256
		v.PreviousHeadSHA256 = &value
	}
	if v.ActiveOperationID != nil {
		value := *v.ActiveOperationID
		v.ActiveOperationID = &value
	}
	return v
}
func validMihomoLabCandidates(v mihomodeploy.LabCandidateListView) bool {
	if v.Schema != mihomodeploy.LabCandidateListViewSchema || v.Boundary != mihomodeploy.LabBackendBoundary ||
		v.Candidates == nil || len(v.Candidates) != 2 || !validMihomoLabProof(v.Proof) {
		return false
	}
	current := 0
	for i, candidate := range v.Candidates {
		name := "local-a"
		if i == 1 {
			name = "local-b"
		}
		if candidate.Name != name || !validMihomoLabHash(candidate.RecordSHA256) || !validMihomoLabHash(candidate.ConfigSHA256) || !validMihomoLabHash(candidate.SourceSpecSHA256) {
			return false
		}
		if candidate.IsCurrent {
			current++
		}
	}
	currentValid := current == 1
	if v.WriteBlocked {
		currentValid = current == 0
	}
	return currentValid && v.Candidates[0].RecordSHA256 != v.Candidates[1].RecordSHA256 && v.Candidates[0].ConfigSHA256 != v.Candidates[1].ConfigSHA256
}

// Intercept this fixed new prefix before ServeMux's redirect/cleaning logic.
// Unrelated routes still receive their original mux and middleware behavior.
func (s *server) mihomoLabRoutes(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == mihomoRecoveryPrefix || strings.HasPrefix(r.URL.Path, mihomoRecoveryPrefix+"/") {
			s.mihomoRecovery(w, r)
			return
		}
		if r.URL.Path != mihomoLabPrefix && !strings.HasPrefix(r.URL.Path, mihomoLabPrefix+"/") {
			next.ServeHTTP(w, r)
			return
		}
		s.mihomoLab(w, r)
	})
}
func (s *server) mihomoLab(w http.ResponseWriter, r *http.Request) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strictImageTrustBearer(values[0]) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="chengwang"`)
		mihomoLabError(w, 401, "mihomo_lab_unauthenticated", false)
		return
	}
	if !requestTransportSecure(r) {
		mihomoLabError(w, 426, "mihomo_lab_secure_transport_required", false)
		return
	}
	if nilSubscriptionInterface(s.options.MihomoLab) || !validMihomoLabScope(s.mihomoLabScope) {
		mihomoLabError(w, 503, "mihomo_lab_unavailable", false)
		return
	}
	if r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || r.URL.RawQuery != "" || r.URL.ForceQuery ||
		r.URL.Fragment != "" || r.URL.RawFragment != "" || strings.Contains(r.URL.Path, "//") || strings.Contains(r.URL.Path, "/./") || strings.Contains(r.URL.Path, "/../") {
		mihomoLabError(w, 400, "mihomo_lab_invalid", false)
		return
	}
	method, action, id := "", "", ""
	switch r.URL.Path {
	case mihomoLabPrefix + "/head":
		method, action = http.MethodGet, "head"
	case mihomoLabPrefix + "/candidates":
		method, action = http.MethodGet, "candidates"
	case mihomoLabPrefix + "/deployments":
		method, action = http.MethodPost, "create"
	default:
		if strings.HasPrefix(r.URL.Path, mihomoLabPrefix+"/deployments/") {
			parts := strings.Split(strings.TrimPrefix(r.URL.Path, mihomoLabPrefix+"/deployments/"), "/")
			if len(parts) >= 1 {
				id = parts[0]
			}
			if len(parts) == 1 {
				method, action = http.MethodGet, "inspect"
			}
			if len(parts) == 2 {
				switch parts[1] {
				case "approvals":
					method, action = http.MethodPost, "approve"
				case "execute":
					method, action = http.MethodPost, "execute"
				case "revocations":
					method, action = http.MethodPost, "revoke"
				}
			}
		}
	}
	if action == "" {
		mihomoLabError(w, 404, "mihomo_lab_not_found", false)
		return
	}
	if id != "" && !mihomoLabID.MatchString(id) {
		mihomoLabError(w, 400, "mihomo_lab_invalid", false)
		return
	}
	if (action == "inspect" || action == "approve" || action == "execute" || action == "revoke") && id == "" {
		mihomoLabError(w, 400, "mihomo_lab_invalid", false)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		mihomoLabError(w, 405, "mihomo_lab_method_not_allowed", false)
		return
	}
	write := method == http.MethodPost
	if write && !s.options.MihomoLabWritesEnabled {
		mihomoLabError(w, 503, "mihomo_lab_writes_disabled", false)
		return
	}
	if r.Context().Err() != nil {
		mihomoLabError(w, 503, "mihomo_lab_unavailable", false)
		return
	}
	chunked := len(r.TransferEncoding) == 1 && r.TransferEncoding[0] == "chunked" && r.ContentLength == -1
	if (len(r.TransferEncoding) != 0 && (!write || !chunked)) || len(r.Header.Values("Content-Encoding")) != 0 {
		mihomoLabError(w, 400, "mihomo_lab_invalid", false)
		return
	}
	authorization := append([]string(nil), values...)
	if !write {
		if r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody) {
			mihomoLabError(w, 400, "mihomo_lab_invalid", false)
			return
		}
		if action == "candidates" {
			v, err := s.options.MihomoLab.Candidates(r.Context(), authorization)
			if err != nil {
				mihomoLabBackendError(w, err, false)
				return
			}
			if !validMihomoLabCandidates(v) {
				mihomoLabError(w, 503, "mihomo_lab_unavailable", false)
				return
			}
			writeMihomoLab(w, 200, "mihomo_lab_ok", false, v)
			return
		}
		if action == "head" {
			v, err := s.options.MihomoLab.Head(r.Context(), authorization)
			if err != nil {
				mihomoLabBackendError(w, err, false)
				return
			}
			v = detachedMihomoLabHead(v)
			if !validMihomoLabHead(v) {
				mihomoLabError(w, 503, "mihomo_lab_unavailable", false)
				return
			}
			writeMihomoLab(w, 200, "mihomo_lab_ok", false, v)
			return
		}
		v, err := s.options.MihomoLab.Inspect(r.Context(), authorization, id)
		if err != nil {
			mihomoLabBackendError(w, err, false)
			return
		}
		if !validMihomoLabView(v, id) {
			mihomoLabError(w, 503, "mihomo_lab_unavailable", false)
			return
		}
		writeMihomoLab(w, 200, "mihomo_lab_ok", false, v)
		return
	}
	object, ok := readMihomoLabObject(w, r)
	if !ok {
		return
	}
	var v mihomodeploy.LabDeploymentView
	var err error
	expectedHash := ""
	if action == "create" {
		if !exactMihomoLabKeys(object, "candidateRecordSHA256", "ttlSeconds") {
			mihomoLabError(w, 400, "mihomo_lab_invalid", false)
			return
		}
		hash, good := object["candidateRecordSHA256"].(string)
		ttl, number := mihomoLabNumber(object["ttlSeconds"])
		if !good || !validMihomoLabHash(hash) || !number || ttl < 1 || ttl > 300 {
			mihomoLabError(w, 400, "mihomo_lab_invalid", false)
			return
		}
		expectedHash = hash
		v, err = s.options.MihomoLab.Create(r.Context(), authorization, mihomodeploy.LabCreateRequest{CandidateRecordSHA256: hash, TTLSeconds: uint16(ttl)})
	} else {
		keys := []string{"planSHA256", "revision"}
		if action == "revoke" {
			keys = append(keys, "reason")
		}
		if !exactMihomoLabKeys(object, keys...) {
			mihomoLabError(w, 400, "mihomo_lab_invalid", false)
			return
		}
		hash, good := object["planSHA256"].(string)
		revision, number := mihomoLabNumber(object["revision"])
		if !good || !validMihomoLabHash(hash) || !number || revision == 0 {
			mihomoLabError(w, 400, "mihomo_lab_invalid", false)
			return
		}
		expectedHash = hash
		switch action {
		case "approve":
			v, err = s.options.MihomoLab.Approve(r.Context(), authorization, id, mihomodeploy.LabApprovalRequest{PlanSHA256: hash, Revision: revision})
		case "execute":
			v, err = s.options.MihomoLab.Execute(r.Context(), authorization, id, mihomodeploy.LabExecuteRequest{PlanSHA256: hash, Revision: revision})
		case "revoke":
			reason, valid := object["reason"].(string)
			if !valid || (reason != "OPERATOR_REQUESTED" && reason != "SAFETY_STOP") {
				mihomoLabError(w, 400, "mihomo_lab_invalid", false)
				return
			}
			v, err = s.options.MihomoLab.Revoke(r.Context(), authorization, id, mihomodeploy.LabRevokeRequest{PlanSHA256: hash, Revision: revision, Reason: reason})
		}
	}
	if err != nil {
		mihomoLabBackendError(w, err, true)
		return
	}
	bound := (action == "create" && v.CandidateRecordSHA256 == expectedHash) || (action != "create" && v.PlanSHA256 == expectedHash)
	if !bound || !validMihomoLabView(v, id) {
		mihomoLabError(w, 503, "mihomo_lab_unavailable", true)
		return
	}
	status := http.StatusOK
	if action == "create" {
		status = http.StatusCreated
	}
	writeMihomoLab(w, status, "mihomo_lab_ok", true, v)
}

func exactMihomoLabKeys(v map[string]any, keys ...string) bool {
	if len(v) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := v[key]; !ok {
			return false
		}
	}
	return true
}
func mihomoLabNumber(v any) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok || !mihomoLabUint.MatchString(string(n)) {
		return 0, false
	}
	i, err := strconv.ParseUint(string(n), 10, 64)
	return i, err == nil
}
func readMihomoLabObject(w http.ResponseWriter, r *http.Request) (map[string]any, bool) {
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		mihomoLabError(w, 415, "mihomo_lab_content_type", false)
		return nil, false
	}
	media, params, err := mime.ParseMediaType(values[0])
	if err != nil || media != "application/json" || len(params) > 1 || (len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8")) {
		mihomoLabError(w, 415, "mihomo_lab_content_type", false)
		return nil, false
	}
	if r.ContentLength > mihomoLabBodyLimit {
		mihomoLabError(w, 413, "mihomo_lab_body_too_large", false)
		return nil, false
	}
	if r.Body == nil || r.Body == http.NoBody || r.ContentLength < -1 {
		mihomoLabError(w, 400, "mihomo_lab_invalid", false)
		return nil, false
	}
	defer r.Body.Close()
	raw, err := io.ReadAll(io.LimitReader(r.Body, mihomoLabBodyLimit+1))
	if len(raw) > mihomoLabBodyLimit {
		mihomoLabError(w, 413, "mihomo_lab_body_too_large", false)
		return nil, false
	}
	if err != nil || (r.ContentLength >= 0 && int64(len(raw)) != r.ContentLength) || !utf8.Valid(raw) || !mihomoLabJSONStrings(raw) {
		mihomoLabError(w, 400, "mihomo_lab_invalid", false)
		return nil, false
	}
	value, ok := subscriptionObject(raw)
	if !ok {
		mihomoLabError(w, 400, "mihomo_lab_invalid", false)
		return nil, false
	}
	return value, true
}

// encoding/json replaces unmatched UTF16 escapes; reject them before decode.
// Valid surrogate pairs are accepted without normalizing any source bytes.
func mihomoLabJSONStrings(raw []byte) bool {
	hex4 := func(p []byte) (uint16, bool) {
		if len(p) < 4 {
			return 0, false
		}
		var n uint16
		for _, c := range p[:4] {
			n <<= 4
			switch {
			case c >= '0' && c <= '9':
				n |= uint16(c - '0')
			case c >= 'a' && c <= 'f':
				n |= uint16(c - 'a' + 10)
			case c >= 'A' && c <= 'F':
				n |= uint16(c - 'A' + 10)
			default:
				return 0, false
			}
		}
		return n, true
	}
	inside := false
	for i := 0; i < len(raw); i++ {
		c := raw[i]
		if !inside {
			if c == '"' {
				inside = true
			}
			continue
		}
		if c == '"' {
			inside = false
			continue
		}
		if c < 0x20 {
			return false
		}
		if c != '\\' {
			continue
		}
		i++
		if i >= len(raw) {
			return false
		}
		if raw[i] != 'u' {
			if !strings.ContainsRune(`"\/bfnrt`, rune(raw[i])) {
				return false
			}
			continue
		}
		n, ok := hex4(raw[i+1:])
		if !ok {
			return false
		}
		i += 4
		if n >= 0xdc00 && n <= 0xdfff {
			return false
		}
		if n >= 0xd800 && n <= 0xdbff {
			if i+6 >= len(raw) || raw[i+1] != '\\' || raw[i+2] != 'u' {
				return false
			}
			low, good := hex4(raw[i+3:])
			if !good || low < 0xdc00 || low > 0xdfff {
				return false
			}
			i += 6
		}
	}
	return !inside
}
