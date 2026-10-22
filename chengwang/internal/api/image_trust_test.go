package api

import (
	"bytes"
	"context"
	"crypto/tls"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"chengwang/internal/authz"
	"chengwang/internal/imagetrust"
)

var imageTrustTestScope = authz.ResourceScope{TenantID: "tenant-a", SiteID: "site-a", ObjectType: "image-trust", ObjectID: strings.Repeat("a", 32), Environment: "isolated"}

type imageTrustTestAuthenticator struct {
	principal authz.Principal
	failed    bool
	calls     int
}

func (a *imageTrustTestAuthenticator) AuthenticateAuthorizationValues(values []string, _ time.Time) (authz.Principal, error) {
	a.calls++
	if a.failed || len(values) != 1 || values[0] != "Bearer image-trust-token" {
		return authz.Principal{}, errors.New("secret authentication reason")
	}
	return a.principal, nil
}

type imageTrustTestBackend struct {
	scope                                             authz.ResourceScope
	scopeCalls, statusCalls, updateCalls, verifyCalls int
	status                                            imagetrust.Status
	receipt                                           imagetrust.Receipt
	err                                               error
	principal                                         authz.Principal
	raw                                               []byte
	request                                           imagetrust.VerifyRequest
}

func (b *imageTrustTestBackend) Scope() authz.ResourceScope { b.scopeCalls++; return b.scope }
func (b *imageTrustTestBackend) Status(_ context.Context, p authz.Principal) (imagetrust.Status, error) {
	b.statusCalls++
	b.principal = p
	return b.status, b.err
}
func (b *imageTrustTestBackend) Update(_ context.Context, p authz.Principal, raw []byte) (imagetrust.Status, error) {
	b.updateCalls++
	b.principal = p
	b.raw = bytes.Clone(raw)
	return b.status, b.err
}
func (b *imageTrustTestBackend) Verify(_ context.Context, p authz.Principal, r imagetrust.VerifyRequest) (imagetrust.Receipt, error) {
	b.verifyCalls++
	b.principal = p
	b.request = r
	return b.receipt, b.err
}
func (b *imageTrustTestBackend) calls() int { return b.statusCalls + b.updateCalls + b.verifyCalls }
func imageTrustTestOptions(role authz.Role) (Options, *imageTrustTestBackend, *imageTrustTestAuthenticator) {
	p := authz.Principal{ID: "principal-a", TenantID: "tenant-a", Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{imageTrustTestScope}, BreakGlassEligible: true}
	a := &imageTrustTestAuthenticator{principal: p}
	b := &imageTrustTestBackend{scope: imageTrustTestScope, status: imagetrust.Status{Healthy: true, Fresh: true, StoreID: imageTrustTestScope.ObjectID, Generation: 1, Authorization: "ALLOWED", DeviceActionsExecuted: true}, receipt: imagetrust.Receipt{Verified: true, Authorization: "ALLOWED", DeviceActionsExecuted: true}}
	return Options{Authn: a, ImageTrust: b, ImageTrustWritesEnabled: true, AdminToken: "legacy-admin-token"}, b, a
}
func imageTrustTestJSON(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
func imageTrustTestCatalogue(t *testing.T) []byte {
	t.Helper()
	// This fixture is wire-valid, not cryptographically approved. Permission
	// tests intentionally mock the backend; real signature acceptance is tested
	// separately in the isolated product integration suite.
	return imageTrustTestJSON(t, map[string]any{"payload": []byte(`{}`), "signatures": []map[string]any{{"keyID": strings.Repeat("b", 64), "signature": make([]byte, 64)}}})
}
func imageTrustTestVerification(t *testing.T) []byte {
	return imageTrustTestJSON(t, imagetrust.VerifyRequest{PolicyID: "business", Approval: []byte("approval"), Bundle: []byte("bundle"), TrustedRoot: []byte("root")})
}
func imageTrustTestRequest(method, path string, body []byte) *http.Request {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = "127.0.0.1:48124"
	r.Header.Set("Authorization", "Bearer image-trust-token")
	if method == http.MethodPost || method == http.MethodPut {
		r.Header.Set("Content-Type", "application/json")
	}
	return r
}
func imageTrustTestServe(t *testing.T, handler http.Handler, r *http.Request, want int) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	handler.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("%s %s status=%d want=%d body=%s", r.Method, r.URL.Path, w.Code, want, w.Body.String())
	}
	if strings.Contains(w.Body.String(), "secret") || strings.Contains(w.Body.String(), "legacy-admin-token") || strings.Contains(w.Body.String(), "image-trust-token") {
		t.Fatal("secret error/body leaked")
	}
	if !strings.Contains(w.Body.String(), `"authorization":"BLOCKED"`) || !strings.Contains(w.Body.String(), `"deviceActionsExecuted":false`) {
		t.Fatal("missing fixed advisory boundary")
	}
	return w
}
func TestImageTrustHTTPRoleMatrix(t *testing.T) {
	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator, authz.RoleApprover, authz.RoleAuditor, authz.RoleAdmin} {
		for _, endpoint := range []struct {
			method, path string
			body         []byte
		}{{http.MethodGet, "/api/v1/image-trust", nil}, {http.MethodPut, "/api/v1/image-trust/catalogue", imageTrustTestCatalogue(t)}, {http.MethodPost, "/api/v1/image-trust/verifications", imageTrustTestVerification(t)}} {
			t.Run(string(role)+"/"+endpoint.method, func(t *testing.T) {
				options, backend, _ := imageTrustTestOptions(role)
				h := New(options)
				allowed := endpoint.method == http.MethodGet || role == authz.RoleAdmin || role == authz.RoleOperator && endpoint.method == http.MethodPost
				want := http.StatusForbidden
				if allowed {
					want = http.StatusOK
				}
				imageTrustTestServe(t, h, imageTrustTestRequest(endpoint.method, endpoint.path, endpoint.body), want)
				calls := 0
				if allowed {
					calls = 1
				}
				if backend.calls() != calls || backend.scopeCalls != 1 {
					t.Fatal("authorization did not precede backend")
				}
				if allowed && backend.principal.ID != "principal-a" {
					t.Fatal("trusted principal not forwarded")
				}
				if allowed && endpoint.method == http.MethodPut && !bytes.Equal(backend.raw, endpoint.body) {
					t.Fatal("signed envelope bytes changed")
				}
				if allowed && endpoint.method == http.MethodPost && (backend.request.PolicyID != "business" || string(backend.request.Approval) != "approval" || string(backend.request.Bundle) != "bundle" || string(backend.request.TrustedRoot) != "root") {
					t.Fatal("request decode mismatch")
				}
			})
		}
	}
}

type imageTrustUnreadBody struct{ reads int }

func (b *imageTrustUnreadBody) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New("secret unread body")
}
func (b *imageTrustUnreadBody) Close() error { return nil }
func TestImageTrustHTTPPreflightDoesNotReadOrCallBackend(t *testing.T) {
	for _, endpoint := range []struct{ method, path string }{{http.MethodGet, "/api/v1/image-trust"}, {http.MethodPut, "/api/v1/image-trust/catalogue"}, {http.MethodPost, "/api/v1/image-trust/verifications"}} {
		for name, tc := range map[string]struct {
			want int
			edit func(*Options, *imageTrustTestBackend, *imageTrustTestAuthenticator, *http.Request)
		}{
			"anonymous": {401, func(_ *Options, _ *imageTrustTestBackend, _ *imageTrustTestAuthenticator, r *http.Request) {
				r.Header.Del("Authorization")
			}},
			"duplicate_auth": {401, func(_ *Options, _ *imageTrustTestBackend, _ *imageTrustTestAuthenticator, r *http.Request) {
				r.Header.Add("Authorization", "Bearer image-trust-token")
			}},
			"merged_auth": {401, func(_ *Options, _ *imageTrustTestBackend, _ *imageTrustTestAuthenticator, r *http.Request) {
				r.Header.Set("Authorization", "Bearer image-trust-token, Bearer image-trust-token")
			}},
			"basic": {401, func(_ *Options, _ *imageTrustTestBackend, _ *imageTrustTestAuthenticator, r *http.Request) {
				r.Header.Set("Authorization", "Basic image-trust-token")
			}},
			"space_token": {401, func(_ *Options, _ *imageTrustTestBackend, _ *imageTrustTestAuthenticator, r *http.Request) {
				r.Header.Set("Authorization", "Bearer image trust token")
			}},
			"legacy_admin": {401, func(_ *Options, _ *imageTrustTestBackend, _ *imageTrustTestAuthenticator, r *http.Request) {
				r.Header.Set("Authorization", "Bearer legacy-admin-token")
			}},
			"cookie_only": {401, func(_ *Options, _ *imageTrustTestBackend, _ *imageTrustTestAuthenticator, r *http.Request) {
				r.Header.Del("Authorization")
				r.AddCookie(&http.Cookie{Name: "Authorization", Value: "image-trust-token"})
			}},
			"untrusted_forwarded": {426, func(_ *Options, _ *imageTrustTestBackend, _ *imageTrustTestAuthenticator, r *http.Request) {
				r.RemoteAddr = "10.88.0.20:1234"
				r.Header.Set("X-Forwarded-Proto", "https")
				r.Header.Set("X-Forwarded-For", "127.0.0.1")
			}},
			"auth_failure": {401, func(_ *Options, _ *imageTrustTestBackend, a *imageTrustTestAuthenticator, _ *http.Request) {
				a.failed = true
			}},
			"missing_authn": {503, func(o *Options, _ *imageTrustTestBackend, _ *imageTrustTestAuthenticator, _ *http.Request) {
				o.Authn = nil
			}},
			"missing_backend": {503, func(o *Options, _ *imageTrustTestBackend, _ *imageTrustTestAuthenticator, _ *http.Request) {
				o.ImageTrust = nil
			}},
			"tenant": {403, func(_ *Options, _ *imageTrustTestBackend, a *imageTrustTestAuthenticator, _ *http.Request) {
				a.principal.TenantID = "other"
			}},
			"site": {403, func(_ *Options, _ *imageTrustTestBackend, a *imageTrustTestAuthenticator, _ *http.Request) {
				a.principal.AllowedScopes[0].SiteID = "other"
			}},
			"object_type": {403, func(_ *Options, _ *imageTrustTestBackend, a *imageTrustTestAuthenticator, _ *http.Request) {
				a.principal.AllowedScopes[0].ObjectType = "router"
			}},
			"object_id": {403, func(_ *Options, _ *imageTrustTestBackend, a *imageTrustTestAuthenticator, _ *http.Request) {
				a.principal.AllowedScopes[0].ObjectID = "other"
			}},
			"environment": {403, func(_ *Options, _ *imageTrustTestBackend, a *imageTrustTestAuthenticator, _ *http.Request) {
				a.principal.AllowedScopes[0].Environment = "production"
			}},
			"unknown_role": {403, func(_ *Options, _ *imageTrustTestBackend, a *imageTrustTestAuthenticator, _ *http.Request) {
				a.principal.Roles = append(a.principal.Roles, "owner")
			}},
			"invalid_scope": {503, func(_ *Options, b *imageTrustTestBackend, _ *imageTrustTestAuthenticator, _ *http.Request) {
				b.scope.ObjectID = ""
			}},
		} {
			t.Run(endpoint.method+"/"+name, func(t *testing.T) {
				options, backend, a := imageTrustTestOptions(authz.RoleAdmin)
				r := imageTrustTestRequest(endpoint.method, endpoint.path, nil)
				spy := &imageTrustUnreadBody{}
				r.Body = spy
				tc.edit(&options, backend, a, r)
				h := New(options)
				imageTrustTestServe(t, h, r, tc.want)
				if backend.calls() != 0 || spy.reads != 0 {
					t.Fatal("denied request touched body/backend")
				}
			})
		}
	}
}
func TestImageTrustHTTPWritesLockedAndMethodsProtected(t *testing.T) {
	for _, endpoint := range []struct{ method, path string }{{http.MethodPut, "/api/v1/image-trust/catalogue"}, {http.MethodPost, "/api/v1/image-trust/verifications"}} {
		t.Run(endpoint.method+"_locked", func(t *testing.T) {
			o, b, _ := imageTrustTestOptions(authz.RoleAdmin)
			o.ImageTrustWritesEnabled = false
			r := imageTrustTestRequest(endpoint.method, endpoint.path, nil)
			spy := &imageTrustUnreadBody{}
			r.Body = spy
			imageTrustTestServe(t, New(o), r, 423)
			if b.calls() != 0 || spy.reads != 0 {
				t.Fatal("locked request reached state/body")
			}
		})
	}
	for _, path := range []string{"/api/v1/image-trust", "/api/v1/image-trust/catalogue", "/api/v1/image-trust/verifications"} {
		for _, method := range []string{http.MethodDelete, http.MethodHead, http.MethodPatch} {
			t.Run(path+"/"+method, func(t *testing.T) {
				o, b, _ := imageTrustTestOptions(authz.RoleAdmin)
				h := New(o)
				r := imageTrustTestRequest(method, path, nil)
				r.Header.Del("Authorization")
				imageTrustTestServe(t, h, r, 401)
				r = imageTrustTestRequest(method, path, nil)
				imageTrustTestServe(t, h, r, 405)
				if b.calls() != 0 {
					t.Fatal("wrong method reached backend")
				}
			})
		}
	}
}
func TestImageTrustHTTPBadJSONNeverCallsBackend(t *testing.T) {
	valid := imageTrustTestVerification(t)
	for name, raw := range map[string][]byte{
		"unknown_principal":   append([]byte(`{"principal":{},`), valid[1:]...),
		"unknown_scope":       append([]byte(`{"scope":{},`), valid[1:]...),
		"unknown_anchor":      append([]byte(`{"anchor":{},`), valid[1:]...),
		"unknown_registry_ca": append([]byte(`{"registryCA":"secret",`), valid[1:]...),
		"unknown_nonce":       append([]byte(`{"nonce":"caller",`), valid[1:]...),
		"break_glass":         append([]byte(`{"breakGlass":{},`), valid[1:]...),
		"duplicate":           append([]byte(`{"policyId":"other",`), valid[1:]...),
		"case_alias":          bytes.Replace(valid, []byte(`"policyId"`), []byte(`"PolicyId"`), 1),
		"escaped_alias":       bytes.Replace(valid, []byte(`"policyId"`), []byte(`"policy\u0049d"`), 1),
		"trailing":            append(bytes.Clone(valid), []byte(` {}`)...),
		"invalid_utf8":        append(bytes.Clone(valid), 0xff),
		"depth":               []byte(`{"x":[[[[[[[[[[[0]]]]]]]]]]]}`),
		"empty_approval":      imageTrustTestJSON(t, map[string]any{"policyId": "business", "approval": "", "bundle": "YQ==", "trustedRoot": "Yg=="}),
		"noncanonical_base64": imageTrustTestJSON(t, map[string]any{"policyId": "business", "approval": "YR==", "bundle": "YQ==", "trustedRoot": "Yg=="}),
		"unpadded_base64":     imageTrustTestJSON(t, map[string]any{"policyId": "business", "approval": "YQ", "bundle": "YQ==", "trustedRoot": "Yg=="}),
		"wrong_type":          []byte(`{"policyId":true,"approval":"YQ==","bundle":"YQ==","trustedRoot":"Yg=="}`),
		"unknown_policy":      bytes.Replace(valid, []byte(`"business"`), []byte(`"../business"`), 1),
	} {
		t.Run(name, func(t *testing.T) {
			o, b, _ := imageTrustTestOptions(authz.RoleAdmin)
			imageTrustTestServe(t, New(o), imageTrustTestRequest(http.MethodPost, "/api/v1/image-trust/verifications", raw), 400)
			if b.calls() != 0 {
				t.Fatal("malformed request reached backend")
			}
		})
	}
	for name, raw := range map[string][]byte{
		"unknown_envelope":     []byte(`{"payload":"e30=","signatures":[],"anchor":{}}`),
		"duplicate_payload":    []byte(`{"payload":"e30=","payload":"e30=","signatures":[]}`),
		"no_signatures":        []byte(`{"payload":"e30=","signatures":[]}`),
		"signature_unknown":    []byte(`{"payload":"e30=","signatures":[{"keyID":"x","signature":"YQ==","status":"approved"}]}`),
		"signature_case_alias": bytes.Replace(imageTrustTestCatalogue(t), []byte(`"keyID"`), []byte(`"keyId"`), 1),
		"signature_duplicate":  bytes.Replace(imageTrustTestCatalogue(t), []byte(`"keyID":`), []byte(`"keyID":"x","keyID":`), 1),
		"bad_signature_base64": bytes.Replace(imageTrustTestCatalogue(t), []byte(base64.StdEncoding.EncodeToString(make([]byte, 64))), []byte("YQ=="), 1),
	} {
		t.Run("catalogue_"+name, func(t *testing.T) {
			o, b, _ := imageTrustTestOptions(authz.RoleAdmin)
			imageTrustTestServe(t, New(o), imageTrustTestRequest(http.MethodPut, "/api/v1/image-trust/catalogue", raw), 400)
			if b.calls() != 0 {
				t.Fatal("malformed envelope reached backend")
			}
		})
	}
}
func TestImageTrustHTTPRequestBudgetsAndHeaders(t *testing.T) {
	for _, endpoint := range []struct {
		method, path string
		raw          []byte
	}{{http.MethodPost, "/api/v1/image-trust/verifications", imageTrustTestVerification(t)}, {http.MethodPut, "/api/v1/image-trust/catalogue", imageTrustTestCatalogue(t)}} {
		for name, tc := range map[string]struct {
			code   int
			mutate func(*http.Request)
		}{
			"query":             {400, func(r *http.Request) { r.URL.RawQuery = "scope=other" }},
			"bare_query":        {400, func(r *http.Request) { r.URL.ForceQuery = true }},
			"encoding":          {400, func(r *http.Request) { r.Header.Set("Content-Encoding", "gzip") }},
			"missing_type":      {415, func(r *http.Request) { r.Header.Del("Content-Type") }},
			"wrong_type":        {415, func(r *http.Request) { r.Header.Set("Content-Type", "text/plain") }},
			"duplicate_type":    {415, func(r *http.Request) { r.Header.Add("Content-Type", "application/json") }},
			"bad_charset":       {415, func(r *http.Request) { r.Header.Set("Content-Type", "application/json; charset=latin1") }},
			"unknown_parameter": {415, func(r *http.Request) { r.Header.Set("Content-Type", "application/json; profile=trusted") }},
		} {
			t.Run(endpoint.method+"/"+name, func(t *testing.T) {
				o, b, _ := imageTrustTestOptions(authz.RoleAdmin)
				r := imageTrustTestRequest(endpoint.method, endpoint.path, endpoint.raw)
				tc.mutate(r)
				spy := &imageTrustUnreadBody{}
				r.Body = spy
				imageTrustTestServe(t, New(o), r, tc.code)
				if b.calls() != 0 || spy.reads != 0 {
					t.Fatal("header/query rejection read body or backend")
				}
			})
		}
	}
	for name, tc := range map[string]struct {
		method, path string
		limit        int
	}{"catalogue": {http.MethodPut, "/api/v1/image-trust/catalogue", imagetrust.MaxCatalogueBytes}, "verification": {http.MethodPost, "/api/v1/image-trust/verifications", imagetrust.MaxVerifyBodyBytes}} {
		t.Run(name, func(t *testing.T) {
			o, b, _ := imageTrustTestOptions(authz.RoleAdmin)
			for _, unknownLength := range []bool{false, true} {
				r := imageTrustTestRequest(tc.method, tc.path, bytes.Repeat([]byte(" "), tc.limit+1))
				if unknownLength {
					r.ContentLength = -1
				}
				imageTrustTestServe(t, New(o), r, 413)
			}
			if b.calls() != 0 {
				t.Fatal("oversized body reached backend")
			}
		})
	}
	for _, field := range []string{"approval", "bundle", "trustedRoot"} {
		t.Run("decoded_"+field, func(t *testing.T) {
			limit := imagetrust.MaxBundleBytes
			if field == "approval" {
				limit = imagetrust.MaxApprovalBytes
			}
			if field == "trustedRoot" {
				limit = imagetrust.MaxRootBytes
			}
			body := map[string]any{"policyId": "business", "approval": []byte("a"), "bundle": []byte("b"), "trustedRoot": []byte("c")}
			body[field] = make([]byte, limit+1)
			o, b, _ := imageTrustTestOptions(authz.RoleAdmin)
			imageTrustTestServe(t, New(o), imageTrustTestRequest(http.MethodPost, "/api/v1/image-trust/verifications", imageTrustTestJSON(t, body)), 400)
			if b.calls() != 0 {
				t.Fatal("decoded over-budget reached backend")
			}
		})
	}
}
func TestImageTrustHTTPBackendErrorsAreSafeAndBlocked(t *testing.T) {
	for name, tc := range map[string]struct {
		err     error
		status  int
		changed bool
	}{
		"unclassified":     {errors.New("secret registry token and raw configuration"), 503, true},
		"invalid":          {&imagetrust.Error{Code: imagetrust.CodeInvalid}, 400, false},
		"forbidden":        {&imagetrust.Error{Code: imagetrust.CodeForbidden}, 403, false},
		"locked":           {&imagetrust.Error{Code: imagetrust.CodeLocked}, 423, false},
		"replay":           {&imagetrust.Error{Code: imagetrust.CodeConflict}, 409, false},
		"busy":             {&imagetrust.Error{Code: imagetrust.CodeBusy}, 429, false},
		"audit_unknown":    {&imagetrust.Error{Code: imagetrust.CodeAuditDegraded, StateMayHaveChanged: true}, 503, true},
		"canceled_unknown": {&imagetrust.Error{Code: imagetrust.CodeCanceled, StateMayHaveChanged: true}, 503, true},
		"unknown_code":     {&imagetrust.Error{Code: "secret rawbody", StateMayHaveChanged: true}, 503, true},
	} {
		t.Run(name, func(t *testing.T) {
			o, b, _ := imageTrustTestOptions(authz.RoleAdmin)
			b.err = tc.err
			w := imageTrustTestServe(t, New(o), imageTrustTestRequest(http.MethodPost, "/api/v1/image-trust/verifications", imageTrustTestVerification(t)), tc.status)
			var parsed imageTrustErrorResponse
			if err := json.Unmarshal(w.Body.Bytes(), &parsed); err != nil {
				t.Fatal(err)
			}
			if parsed.StateMayHaveChanged != tc.changed || b.calls() != 1 {
				t.Fatal("ambiguous state flag lost")
			}
		})
	}
}
func TestImageTrustHTTPFixedConfigurationAndTLSSucceed(t *testing.T) {
	o, b, _ := imageTrustTestOptions(authz.RoleAdmin)
	h := New(o)
	b.scope = authz.ResourceScope{TenantID: "untrusted-change"}
	r := imageTrustTestRequest(http.MethodGet, "/api/v1/image-trust", nil)
	r.RemoteAddr = "10.88.0.20:1234"
	r.TLS = &tls.ConnectionState{}
	imageTrustTestServe(t, h, r, 200)
	if b.scopeCalls != 1 || b.statusCalls != 1 {
		t.Fatal("request read mutable scope getter")
	}
	// Plain HTTP at a non-loopback peer is never made trusted by headers.
	r = imageTrustTestRequest(http.MethodGet, "/api/v1/image-trust", nil)
	r.RemoteAddr = "10.88.0.20:1234"
	r.Header.Set("Forwarded", "proto=https;for=127.0.0.1")
	imageTrustTestServe(t, h, r, 426)
	if b.statusCalls != 1 {
		t.Fatal("untrusted transport reached backend")
	}
}

var _ imagetrust.Backend = (*imageTrustTestBackend)(nil)
var _ io.ReadCloser = (*imageTrustUnreadBody)(nil)
