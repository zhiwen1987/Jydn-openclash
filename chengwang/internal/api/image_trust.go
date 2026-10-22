package api

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"mime"
	"net/http"
	"regexp"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"chengwang/internal/authz"
	"chengwang/internal/imagetrust"
)

type imageTrustErrorResponse struct {
	Boundary              string          `json:"boundary"`
	Authorization         string          `json:"authorization"`
	DeviceActionsExecuted bool            `json:"deviceActionsExecuted"`
	Code                  imagetrust.Code `json:"code"`
	StateMayHaveChanged   bool            `json:"stateMayHaveChanged"`
}

func writeImageTrustError(w http.ResponseWriter, status int, code imagetrust.Code, changed bool) {
	writeJSON(w, status, imageTrustErrorResponse{Boundary: imagetrust.StatusBoundary, Authorization: "BLOCKED", Code: code, StateMayHaveChanged: changed})
}

func (s *server) imageTrustPreflight(w http.ResponseWriter, r *http.Request, action authz.Action, write bool) (authz.Principal, bool) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strictImageTrustBearer(values[0]) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="chengwang"`)
		writeImageTrustError(w, http.StatusUnauthorized, imagetrust.CodeForbidden, false)
		return authz.Principal{}, false
	}
	if !requestTransportSecure(r) {
		writeImageTrustError(w, http.StatusUpgradeRequired, imagetrust.CodeForbidden, false)
		return authz.Principal{}, false
	}
	if s.options.Authn == nil {
		writeImageTrustError(w, http.StatusServiceUnavailable, imagetrust.CodeUnavailable, false)
		return authz.Principal{}, false
	}
	principal, err := s.options.Authn.AuthenticateAuthorizationValues(values, time.Now().UTC())
	if err != nil {
		w.Header().Set("WWW-Authenticate", `Bearer realm="chengwang"`)
		writeImageTrustError(w, http.StatusUnauthorized, imagetrust.CodeForbidden, false)
		return authz.Principal{}, false
	}
	if s.options.ImageTrust == nil || !validImageTrustScope(s.imageTrustScope) {
		writeImageTrustError(w, http.StatusServiceUnavailable, imagetrust.CodeUnavailable, false)
		return authz.Principal{}, false
	}
	if !authz.Evaluate(authz.Request{Principal: principal, Action: action, Resource: s.imageTrustScope}, time.Now().UTC()).Allowed {
		writeImageTrustError(w, http.StatusForbidden, imagetrust.CodeForbidden, false)
		return authz.Principal{}, false
	}
	if write && !s.options.ImageTrustWritesEnabled {
		writeImageTrustError(w, http.StatusLocked, imagetrust.CodeLocked, false)
		return authz.Principal{}, false
	}
	return principal, true
}

func strictImageTrustBearer(value string) bool {
	if len(value) > 4103 || !strings.HasPrefix(value, "Bearer ") || len(value) == 7 {
		return false
	}
	for _, ch := range value[7:] {
		if ch < 0x21 || ch > 0x7e || ch == ',' {
			return false
		}
	}
	return true
}
func validImageTrustScope(scope authz.ResourceScope) bool {
	if scope.ObjectType != "image-trust" || !imageTrustHex(scope.ObjectID, 32) {
		return false
	}
	for _, value := range []string{scope.TenantID, scope.SiteID, scope.Environment} {
		if len(value) == 0 || len(value) > 128 || strings.TrimSpace(value) != value || strings.ContainsFunc(value, unicode.IsControl) {
			return false
		}
	}
	return true
}

func imageTrustRequestShape(w http.ResponseWriter, r *http.Request, method string, jsonBody bool) bool {
	if r.Method != method {
		w.Header().Set("Allow", method)
		writeImageTrustError(w, http.StatusMethodNotAllowed, imagetrust.CodeInvalid, false)
		return false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || len(r.Header.Values("Content-Encoding")) != 0 {
		writeImageTrustError(w, http.StatusBadRequest, imagetrust.CodeInvalid, false)
		return false
	}
	if !jsonBody {
		if r.ContentLength != 0 || len(r.TransferEncoding) != 0 {
			writeImageTrustError(w, http.StatusBadRequest, imagetrust.CodeInvalid, false)
			return false
		}
		return true
	}
	values := r.Header.Values("Content-Type")
	if len(values) != 1 {
		writeImageTrustError(w, http.StatusUnsupportedMediaType, imagetrust.CodeInvalid, false)
		return false
	}
	media, params, err := mime.ParseMediaType(values[0])
	if err != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		writeImageTrustError(w, http.StatusUnsupportedMediaType, imagetrust.CodeInvalid, false)
		return false
	}
	return true
}

func (s *server) imageTrustStatus(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.imageTrustPreflight(w, r, authz.ActionReadImageTrust, false)
	if !ok || !imageTrustRequestShape(w, r, http.MethodGet, false) {
		return
	}
	status, err := s.options.ImageTrust.Status(r.Context(), principal)
	if err != nil {
		writeImageTrustBackendError(w, err, false)
		return
	}
	status.Boundary, status.Authorization, status.DeviceActionsExecuted = imagetrust.StatusBoundary, "BLOCKED", false
	writeJSON(w, http.StatusOK, status)
}
func (s *server) imageTrustCatalogue(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.imageTrustPreflight(w, r, authz.ActionUpdateImageTrust, true)
	if !ok || !imageTrustRequestShape(w, r, http.MethodPut, true) {
		return
	}
	raw, ok := readImageTrustBody(w, r, imagetrust.MaxCatalogueBytes)
	if !ok {
		return
	}
	object, ok := imageTrustJSONObject(raw)
	if !ok || !exactImageTrustKeys(object, "payload", "signatures") || !validImageTrustEnvelope(object) {
		writeImageTrustError(w, http.StatusBadRequest, imagetrust.CodeInvalid, false)
		return
	}
	status, err := s.options.ImageTrust.Update(r.Context(), principal, raw)
	if err != nil {
		writeImageTrustBackendError(w, err, true)
		return
	}
	status.Boundary, status.Authorization, status.DeviceActionsExecuted = imagetrust.StatusBoundary, "BLOCKED", false
	writeJSON(w, http.StatusOK, status)
}
func (s *server) imageTrustVerification(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.imageTrustPreflight(w, r, authz.ActionVerifyImageTrust, true)
	if !ok || !imageTrustRequestShape(w, r, http.MethodPost, true) {
		return
	}
	raw, ok := readImageTrustBody(w, r, imagetrust.MaxVerifyBodyBytes)
	if !ok {
		return
	}
	m, ok := imageTrustJSONObject(raw)
	if !ok || !exactImageTrustKeys(m, "policyId", "approval", "bundle", "trustedRoot") {
		writeImageTrustError(w, http.StatusBadRequest, imagetrust.CodeInvalid, false)
		return
	}
	id, _ := m["policyId"].(string)
	approval, aOK := imageTrustBinary(m["approval"], imagetrust.MaxApprovalBytes)
	bundle, bOK := imageTrustBinary(m["bundle"], imagetrust.MaxBundleBytes)
	root, rOK := imageTrustBinary(m["trustedRoot"], imagetrust.MaxRootBytes)
	if !imageTrustPolicyPattern.MatchString(id) || !aOK || !bOK || !rOK {
		writeImageTrustError(w, http.StatusBadRequest, imagetrust.CodeInvalid, false)
		return
	}
	receipt, err := s.options.ImageTrust.Verify(r.Context(), principal, imagetrust.VerifyRequest{PolicyID: id, Approval: approval, Bundle: bundle, TrustedRoot: root})
	if err != nil {
		writeImageTrustBackendError(w, err, true)
		return
	}
	if !receipt.Verified {
		writeImageTrustError(w, http.StatusServiceUnavailable, imagetrust.CodeUnavailable, true)
		return
	}
	receipt.Boundary, receipt.Authorization, receipt.DeviceActionsExecuted = imagetrust.VerifiedBoundary, "BLOCKED", false
	writeJSON(w, http.StatusOK, receipt)
}

func readImageTrustBody(w http.ResponseWriter, r *http.Request, limit int) ([]byte, bool) {
	if r.Body == nil {
		writeImageTrustError(w, http.StatusBadRequest, imagetrust.CodeInvalid, false)
		return nil, false
	}
	defer r.Body.Close()
	if r.ContentLength > int64(limit) {
		writeImageTrustError(w, http.StatusRequestEntityTooLarge, imagetrust.CodeInvalid, false)
		return nil, false
	}
	raw, err := io.ReadAll(io.LimitReader(r.Body, int64(limit)+1))
	if len(raw) > limit {
		writeImageTrustError(w, http.StatusRequestEntityTooLarge, imagetrust.CodeInvalid, false)
		return nil, false
	}
	if err != nil || len(raw) == 0 {
		writeImageTrustError(w, http.StatusBadRequest, imagetrust.CodeInvalid, false)
		return nil, false
	}
	return raw, true
}

func writeImageTrustBackendError(w http.ResponseWriter, err error, mutationAttempted bool) {
	code, status, changed := imagetrust.CodeUnavailable, http.StatusServiceUnavailable, mutationAttempted
	var classified *imagetrust.Error
	if errors.As(err, &classified) && classified != nil {
		changed = classified.StateMayHaveChanged
		switch classified.Code {
		case imagetrust.CodeInvalid:
			code, status = classified.Code, http.StatusBadRequest
		case imagetrust.CodeForbidden:
			code, status = classified.Code, http.StatusForbidden
		case imagetrust.CodeLocked:
			code, status = classified.Code, http.StatusLocked
		case imagetrust.CodeConflict:
			code, status = classified.Code, http.StatusConflict
		case imagetrust.CodeBusy:
			code, status = classified.Code, http.StatusTooManyRequests
		case imagetrust.CodeAuditDegraded, imagetrust.CodeCanceled, imagetrust.CodeUnavailable:
			code = classified.Code
		}
	}
	writeImageTrustError(w, status, code, changed)
}

var imageTrustPolicyPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func imageTrustHex(value string, size int) bool {
	if len(value) != size {
		return false
	}
	for _, ch := range value {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}
func imageTrustBinary(value any, limit int) ([]byte, bool) {
	s, ok := value.(string)
	if !ok || len(s) == 0 || len(s) > base64.StdEncoding.EncodedLen(limit) {
		return nil, false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	return raw, err == nil && len(raw) > 0 && len(raw) <= limit && base64.StdEncoding.EncodeToString(raw) == s
}
func validImageTrustEnvelope(m map[string]any) bool {
	if _, ok := imageTrustBinary(m["payload"], imagetrust.MaxCatalogueBytes); !ok {
		return false
	}
	signatures, ok := m["signatures"].([]any)
	if !ok || len(signatures) == 0 || len(signatures) > 16 {
		return false
	}
	seen := map[string]bool{}
	for _, value := range signatures {
		sig, ok := value.(map[string]any)
		if !ok || !exactImageTrustKeys(sig, "keyID", "signature") {
			return false
		}
		id, _ := sig["keyID"].(string)
		raw, ok := imageTrustBinary(sig["signature"], 64)
		if !ok || len(raw) != 64 || !imageTrustHex(id, 64) || seen[id] {
			return false
		}
		seen[id] = true
	}
	return true
}
func exactImageTrustKeys(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, ok := m[key]; !ok {
			return false
		}
	}
	return true
}

// This wire profile consists solely of ASCII identifiers and canonical base64.
// Reject escaped aliases, invalid UTF-8, duplicate keys and excessive nesting.
func imageTrustJSONObject(raw []byte) (map[string]any, bool) {
	if !utf8.Valid(raw) || bytes.ContainsRune(raw, '\\') {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, ok := imageTrustJSONValue(d, 0)
	if !ok {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	m, ok := value.(map[string]any)
	return m, ok
}
func imageTrustJSONValue(d *json.Decoder, depth int) (any, bool) {
	if depth > 8 {
		return nil, false
	}
	token, err := d.Token()
	if err != nil {
		return nil, false
	}
	if delim, ok := token.(json.Delim); ok {
		switch delim {
		case '{':
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok {
					return nil, false
				}
				if _, seen := m[name]; seen {
					return nil, false
				}
				value, ok := imageTrustJSONValue(d, depth+1)
				if !ok {
					return nil, false
				}
				m[name] = value
			}
			end, err := d.Token()
			return m, err == nil && end == json.Delim('}')
		case '[':
			a := []any{}
			for d.More() {
				value, ok := imageTrustJSONValue(d, depth+1)
				if !ok {
					return nil, false
				}
				a = append(a, value)
			}
			end, err := d.Token()
			return a, err == nil && end == json.Delim(']')
		default:
			return nil, false
		}
	}
	return token, true
}
