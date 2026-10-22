package api

import (
	"context"
	"encoding/json"
	"net/http"
	"testing"

	"chengwang/internal/authz"
	"chengwang/internal/imagetrust"
)

type imageTrustD8HistoryBackend struct {
	*imageTrustTestBackend
	historyCalls int
	query        imagetrust.HistoryRequest
	history      imagetrust.History
	historyErr   error
}

func (b *imageTrustD8HistoryBackend) History(_ context.Context, p authz.Principal, q imagetrust.HistoryRequest) (imagetrust.History, error) {
	b.historyCalls++
	b.principal = p
	b.query = q
	return b.history, b.historyErr
}
func imageTrustD8Options(role authz.Role) (Options, *imageTrustD8HistoryBackend, *imageTrustTestAuthenticator) {
	o, b, a := imageTrustTestOptions(role)
	h := &imageTrustD8HistoryBackend{imageTrustTestBackend: b, history: imagetrust.History{Authorization: "ALLOWED", DeviceActionsExecuted: true, ObservedAtUnix: 123, Sequence: 7, Entries: []imagetrust.HistoryEntry{}}}
	o.ImageTrust = h
	return o, h, a
}

func TestImageTrustHistoryD8OptionalBackendAndRoleMatrix(t *testing.T) {
	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator, authz.RoleApprover, authz.RoleAuditor, authz.RoleAdmin} {
		t.Run(string(role), func(t *testing.T) {
			o, b, _ := imageTrustD8Options(role)
			want := http.StatusForbidden
			if role == authz.RoleAuditor || role == authz.RoleAdmin {
				want = http.StatusOK
			}
			w := imageTrustTestServe(t, New(o), imageTrustTestRequest(http.MethodGet, "/api/v1/image-trust/history", nil), want)
			if want == http.StatusOK {
				var history imagetrust.History
				if json.Unmarshal(w.Body.Bytes(), &history) != nil || history.Boundary != imagetrust.HistoryBoundary || history.Authorization != "BLOCKED" || history.DeviceActionsExecuted {
					t.Fatal("history escaped advisory boundary")
				}
				if b.historyCalls != 1 || b.query.Limit != 20 || b.principal.ID != "principal-a" {
					t.Fatal("history principal/default query mismatch")
				}
			} else if b.historyCalls != 0 {
				t.Fatal("history RBAC reached backend")
			}
		})
	}
	o, b, _ := imageTrustTestOptions(authz.RoleAdmin)
	imageTrustTestServe(t, New(o), imageTrustTestRequest(http.MethodGet, "/api/v1/image-trust/history", nil), http.StatusServiceUnavailable)
	if b.calls() != 0 {
		t.Fatal("old optional backend acquired history capability")
	}
	o.ImageTrust = nil
	imageTrustTestServe(t, New(o), imageTrustTestRequest(http.MethodGet, "/api/v1/image-trust/history", nil), http.StatusServiceUnavailable)
}

func TestImageTrustHistoryD8CanonicalQueryAndNoBodyReads(t *testing.T) {
	for _, tc := range []struct {
		name, query   string
		valid         bool
		limit, offset int
		sequence      uint64
	}{
		{"default", "", true, 20, 0, 0}, {"minimum", "limit=1&offset=0&sequence=0", true, 1, 0, 0}, {"maximum", "limit=50&offset=4096&sequence=18446744073709551615", true, 50, 4096, ^uint64(0)},
		{"actor-injection", "actorId=attacker", false, 0, 0, 0}, {"scope-injection", "scope=other", false, 0, 0, 0}, {"unknown", "page=1", false, 0, 0, 0}, {"duplicate", "limit=1&limit=2", false, 0, 0, 0}, {"case-alias", "Limit=1", false, 0, 0, 0}, {"escaped-alias", "%6cimit=1", false, 0, 0, 0}, {"escaped-digit", "limit=%31", false, 0, 0, 0}, {"leading-zero", "limit=01", false, 0, 0, 0}, {"zero", "limit=0", false, 0, 0, 0}, {"large-limit", "limit=51", false, 0, 0, 0}, {"large-offset", "offset=4097", false, 0, 0, 0}, {"negative", "offset=-1", false, 0, 0, 0}, {"plus", "limit=+1", false, 0, 0, 0}, {"empty", "limit=", false, 0, 0, 0}, {"missing-equals", "limit", false, 0, 0, 0}, {"trailing-separator", "limit=1&", false, 0, 0, 0}, {"semicolon", "limit=1;offset=0", false, 0, 0, 0}, {"exponent", "sequence=1e3", false, 0, 0, 0}, {"overflow", "sequence=18446744073709551616", false, 0, 0, 0},
	} {
		t.Run(tc.name, func(t *testing.T) {
			o, b, _ := imageTrustD8Options(authz.RoleAuditor)
			r := imageTrustTestRequest(http.MethodGet, "/api/v1/image-trust/history", nil)
			r.URL.RawQuery = tc.query
			spy := &imageTrustUnreadBody{}
			r.Body = spy
			want := http.StatusBadRequest
			if tc.valid {
				want = http.StatusOK
			}
			imageTrustTestServe(t, New(o), r, want)
			if spy.reads != 0 {
				t.Fatal("history read request body")
			}
			if tc.valid {
				if b.historyCalls != 1 || b.query.Limit != tc.limit || b.query.Offset != tc.offset || b.query.Sequence != tc.sequence {
					t.Fatal("history query mismatch")
				}
			} else if b.historyCalls != 0 {
				t.Fatal("invalid query reached backend")
			}
		})
	}
	for _, kind := range []string{"body", "chunked", "encoding", "bare-query", "wrong-method"} {
		t.Run(kind, func(t *testing.T) {
			o, b, _ := imageTrustD8Options(authz.RoleAdmin)
			r := imageTrustTestRequest(http.MethodGet, "/api/v1/image-trust/history", nil)
			spy := &imageTrustUnreadBody{}
			r.Body = spy
			want := http.StatusBadRequest
			switch kind {
			case "body":
				r.ContentLength = 1
			case "chunked":
				r.TransferEncoding = []string{"chunked"}
			case "encoding":
				r.Header.Set("Content-Encoding", "identity")
			case "bare-query":
				r.URL.ForceQuery = true
			case "wrong-method":
				r.Method = http.MethodPost
				want = http.StatusMethodNotAllowed
			}
			imageTrustTestServe(t, New(o), r, want)
			if b.historyCalls != 0 || spy.reads != 0 {
				t.Fatal("shape rejection read body/backend")
			}
		})
	}
}

func TestImageTrustHistoryD8AuthenticationScopeAndTransportPrecedeQuery(t *testing.T) {
	for _, kind := range []string{"anonymous", "duplicate-auth", "plain-remote", "wrong-scope", "missing-authn", "forbidden-role"} {
		t.Run(kind, func(t *testing.T) {
			o, b, a := imageTrustD8Options(authz.RoleAuditor)
			r := imageTrustTestRequest(http.MethodGet, "/api/v1/image-trust/history", nil)
			r.URL.RawQuery = "actorId=attacker"
			want := http.StatusUnauthorized
			switch kind {
			case "anonymous":
				r.Header.Del("Authorization")
			case "duplicate-auth":
				r.Header.Add("Authorization", "Bearer image-trust-token")
			case "plain-remote":
				r.RemoteAddr = "10.88.0.20:1111"
				r.Header.Set("X-Forwarded-Proto", "https")
				want = http.StatusUpgradeRequired
			case "wrong-scope":
				a.principal.AllowedScopes[0].SiteID = "other"
				want = http.StatusForbidden
			case "missing-authn":
				o.Authn = nil
				want = http.StatusServiceUnavailable
			case "forbidden-role":
				a.principal.Roles = []authz.Role{authz.RoleViewer}
				want = http.StatusForbidden
			}
			imageTrustTestServe(t, New(o), r, want)
			if b.historyCalls != 0 {
				t.Fatal("preflight rejection touched history")
			}
		})
	}
}

func TestImageTrustHistoryD8SnapshotConflictDoesNotClaimMutation(t *testing.T) {
	o, b, _ := imageTrustD8Options(authz.RoleAdmin)
	b.historyErr = &imagetrust.Error{Code: imagetrust.CodeConflict}
	r := imageTrustTestRequest(http.MethodGet, "/api/v1/image-trust/history?sequence=7", nil)
	w := imageTrustTestServe(t, New(o), r, http.StatusConflict)
	var result imageTrustErrorResponse
	if json.Unmarshal(w.Body.Bytes(), &result) != nil || result.StateMayHaveChanged {
		t.Fatal("read conflict claimed mutation")
	}
}
