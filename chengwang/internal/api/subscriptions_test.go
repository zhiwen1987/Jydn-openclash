package api

// HTTP contract tests use the real router/policy and an instrumented backend.
// Only the last test loads the real credential store. These are not the
// separate runtime's real-TLS, durable-service or Internet acceptance proof.
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
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/subscription"
	"chengwang/internal/subscriptionctl"
)

var subscriptionAPIScope = authz.ResourceScope{TenantID: "tenant-a", SiteID: "site-a", ObjectType: "subscription-store", ObjectID: "local", Environment: "isolated"}
var subscriptionAPISource = "src_" + strings.Repeat("a", 32)
var subscriptionAPICandidate = "cand_" + strings.Repeat("b", 32)
var subscriptionAPICommand = "cmd_" + strings.Repeat("c", 32)
var subscriptionAPIDigest = "hmac-sha256:" + strings.Repeat("d", 64)

const subscriptionAPIToken = "subscription-test-token"
const subscriptionAPISecret = "private-api-sentinel"

type subscriptionAPIAuth struct {
	principal authz.Principal
	calls     int
	fail      bool
}

func (a *subscriptionAPIAuth) AuthenticateAuthorizationValues(values []string, _ time.Time) (authz.Principal, error) {
	a.calls++
	if a.fail || len(values) != 1 || values[0] != "Bearer "+subscriptionAPIToken {
		return authz.Principal{}, errors.New(subscriptionAPISecret)
	}
	return a.principal, nil
}

type subscriptionAPISpy struct {
	scope                                              authz.ResourceScope
	scopeCalls, sourceCalls, candidateCalls, nodeCalls int
	executeCalls, receiptCalls, deniedCalls            int
	sources                                            subscriptionctl.SourcePage
	candidates                                         subscriptionctl.CandidatePage
	nodes                                              subscriptionctl.NodePage
	receipt                                            subscriptionctl.Receipt
	lastPrincipal                                      authz.Principal
	lastCommand                                        subscriptionctl.Command
	lastQuery                                          subscriptionctl.ListQuery
	lastSource, lastCandidate, lastReceipt             string
	err, deniedErr                                     error
	fixedReceipt                                       bool
}

func (b *subscriptionAPISpy) Scope() authz.ResourceScope { b.scopeCalls++; return b.scope }
func (b *subscriptionAPISpy) ListSources(_ context.Context, p authz.Principal) (subscriptionctl.SourcePage, error) {
	b.sourceCalls++
	b.lastPrincipal = p
	return b.sources, b.err
}
func (b *subscriptionAPISpy) ListCandidates(_ context.Context, p authz.Principal, source string, q subscriptionctl.ListQuery) (subscriptionctl.CandidatePage, error) {
	b.candidateCalls++
	b.lastPrincipal, b.lastSource, b.lastQuery = p, source, q
	return b.candidates, b.err
}
func (b *subscriptionAPISpy) ListNodes(_ context.Context, p authz.Principal, source, candidate string, q subscriptionctl.ListQuery) (subscriptionctl.NodePage, error) {
	b.nodeCalls++
	b.lastPrincipal, b.lastSource, b.lastCandidate, b.lastQuery = p, source, candidate, q
	return b.nodes, b.err
}
func (b *subscriptionAPISpy) Execute(_ context.Context, p authz.Principal, command subscriptionctl.Command) (subscriptionctl.Receipt, error) {
	b.executeCalls++
	b.lastPrincipal, b.lastCommand = p, command
	b.lastCommand.Content = bytes.Clone(command.Content)
	result := b.receipt
	if !b.fixedReceipt {
		result.Kind = command.Kind
		if command.SourceID != "" {
			result.SourceID = command.SourceID
		}
		if command.Kind == subscriptionctl.Approve {
			result.State, result.LocalAuditHash = "approved", ""
		}
	}
	return result, b.err
}
func (b *subscriptionAPISpy) ReadReceipt(_ context.Context, p authz.Principal, id string) (subscriptionctl.Receipt, error) {
	b.receiptCalls++
	b.lastPrincipal, b.lastReceipt = p, id
	return b.receipt, b.err
}
func (b *subscriptionAPISpy) RecordDenied(_ context.Context, _ authz.Principal, _ authz.Action, _ subscriptionctl.Code) error {
	b.deniedCalls++
	return b.deniedErr
}
func (b *subscriptionAPISpy) privateCalls() int {
	return b.sourceCalls + b.candidateCalls + b.nodeCalls + b.executeCalls + b.receiptCalls
}

func subscriptionAPIFixture(role authz.Role) (Options, *subscriptionAPISpy, *subscriptionAPIAuth) {
	when := time.Date(2026, 10, 23, 8, 0, 0, 0, time.UTC)
	scope := subscription.Scope{TenantID: subscriptionAPIScope.TenantID, SiteID: subscriptionAPIScope.SiteID, Environment: subscriptionAPIScope.Environment}
	source := subscription.SourceView{ID: subscriptionAPISource, Scope: scope, Label: "来源甲", Revision: 2, LatestCandidateID: subscriptionAPICandidate, UpdatedAt: when}
	nodeID := "node_" + strings.Repeat("e", 32)
	b := &subscriptionAPISpy{scope: subscriptionAPIScope,
		sources:    subscriptionctl.SourcePage{Sources: []subscription.SourceView{source}, Total: 1},
		candidates: subscriptionctl.CandidatePage{Candidates: []subscriptionctl.CandidateSummary{{ID: subscriptionAPICandidate, SourceID: subscriptionAPISource, Digest: subscriptionAPIDigest, Format: subscription.FormatMihomo, State: subscription.CandidateQuarantined, BaseRevision: 2, NodeCount: 1, CreatedAt: when}}, Total: 1, Revision: 2},
		nodes:      subscriptionctl.NodePage{Nodes: []subscription.NodeView{{ID: nodeID, Label: "节点-eeeeeeee", Protocol: "trojan", CredentialConfigured: true, State: "unknown"}}, Total: 1, Revision: 2},
		receipt:    subscriptionctl.Receipt{CommandID: subscriptionAPICommand, Kind: subscriptionctl.Create, SourceID: subscriptionAPISource, Revision: 2, State: "committed", AuditRecorded: true, PreparedAuditHash: strings.Repeat("a", 64), ResultAuditHash: strings.Repeat("b", 64), LocalAuditHash: strings.Repeat("c", 64), CompletedAt: when},
	}
	principal := authz.Principal{ID: "principal-a", TenantID: scope.TenantID, Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{{TenantID: scope.TenantID, SiteID: scope.SiteID, Environment: scope.Environment}}, BreakGlassEligible: true}
	a := &subscriptionAPIAuth{principal: principal}
	return Options{Authn: a, Subscriptions: b, SubscriptionWritesEnabled: true, AdminToken: "legacy-admin-sentinel"}, b, a
}

func subscriptionAPIJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal("fixture JSON")
	}
	return raw
}
func subscriptionAPIPath(suffix string) string {
	return "/api/v1/subscriptions/sources/" + subscriptionAPISource + suffix
}
func subscriptionAPIRequest(method, path string, body []byte) *http.Request {
	r := httptest.NewRequest(method, path, bytes.NewReader(body))
	r.RemoteAddr = "10.23.0.7:1234"
	r.TLS = &tls.ConnectionState{}
	r.Header.Set("Authorization", "Bearer "+subscriptionAPIToken)
	if method == http.MethodPost {
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("Idempotency-Key", "subscription-key-0001")
	}
	return r
}
func subscriptionAPIServe(t *testing.T, h http.Handler, r *http.Request, want int) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if w.Code != want {
		t.Fatalf("subscription response status=%d want=%d", w.Code, want)
	}
	for _, secret := range []string{subscriptionAPISecret, subscriptionAPIToken, "legacy-admin-sentinel", "PRIVATE KEY", "Bearer "} {
		if strings.Contains(w.Body.String(), secret) {
			t.Fatal("private material escaped HTTP")
		}
	}
	var envelope map[string]any
	if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || envelope["boundary"] != subscriptionctl.Boundary || envelope["authorization"] != "BLOCKED" || envelope["deviceActionsExecuted"] != false {
		t.Fatal("missing fixed local-only envelope")
	}
	if _, ok := envelope["stateMayHaveChanged"].(bool); !ok {
		t.Fatal("missing explicit uncertainty")
	}
	if w.Header().Get("Cache-Control") != "no-store" {
		t.Fatal("private subscription response cacheable")
	}
	return w
}
func subscriptionAPIBody(t *testing.T, kind subscriptionctl.Kind) []byte {
	t.Helper()
	switch kind {
	case subscriptionctl.Create:
		return subscriptionAPIJSON(t, map[string]any{"label": "来源甲"})
	case subscriptionctl.Import:
		return subscriptionAPIJSON(t, map[string]any{"expectedRevision": 2, "format": subscription.FormatAuto, "contentBase64": base64.StdEncoding.EncodeToString([]byte("proxies: []\n"))})
	case subscriptionctl.Decide:
		return subscriptionAPIJSON(t, map[string]any{"candidateId": subscriptionAPICandidate, "expectedRevision": 2, "expectedDigest": subscriptionAPIDigest, "decision": "admitted_local"})
	case subscriptionctl.Rollback:
		return subscriptionAPIJSON(t, map[string]any{"candidateId": subscriptionAPICandidate, "expectedRevision": 2})
	case subscriptionctl.Approve:
		return subscriptionAPIJSON(t, map[string]any{"referenceId": "source-reference", "policyRevision": 1, "expectedRevision": 2})
	case subscriptionctl.Fetch:
		return subscriptionAPIJSON(t, map[string]any{"approvalId": subscriptionAPICommand, "policyRevision": 1, "expectedRevision": 2})
	}
	t.Fatal("unknown fixture command")
	return nil
}
func subscriptionAPIRoute(kind subscriptionctl.Kind) string {
	switch kind {
	case subscriptionctl.Create:
		return "/api/v1/subscriptions/sources"
	case subscriptionctl.Import:
		return subscriptionAPIPath("/candidates")
	case subscriptionctl.Decide:
		return subscriptionAPIPath("/decisions")
	case subscriptionctl.Rollback:
		return subscriptionAPIPath("/rollbacks")
	case subscriptionctl.Approve:
		return subscriptionAPIPath("/approvals")
	case subscriptionctl.Fetch:
		return subscriptionAPIPath("/fetches")
	}
	return ""
}

type subscriptionAPIUnread struct{ reads int }

func (b *subscriptionAPIUnread) Read([]byte) (int, error) {
	b.reads++
	return 0, errors.New(subscriptionAPISecret)
}
func (*subscriptionAPIUnread) Close() error { return nil }

func TestSubscriptionAPIProtectedRoutesRequireStrictBearer(t *testing.T) {
	for _, values := range [][]string{nil, {""}, {"bearer x"}, {"Bearer "}, {"Bearer x,y"}, {"Bearer a", "Bearer b"}, {"Bearer a b"}, {"Bearer " + strings.Repeat("x", 4097)}, {"Bearer wrong"}} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		r := subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/sources", nil)
		r.Header.Del("Authorization")
		for _, value := range values {
			r.Header.Add("Authorization", value)
		}
		w := subscriptionAPIServe(t, New(o), r, 401)
		if w.Header().Get("X-Chengwang-Denial-Audit") != "recorded" {
			t.Fatal("successful denial audit was not signaled")
		}
		if b.privateCalls() != 0 || b.deniedCalls != 1 {
			t.Fatal("denied request touched private backend")
		}
	}
}
func TestSubscriptionAPILegacyAdminCannotAuthenticate(t *testing.T) {
	for _, header := range []string{"Bearer legacy-admin-sentinel", "legacy-admin-sentinel"} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		r := subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), subscriptionAPIBody(t, subscriptionctl.Create))
		r.Header.Set("Authorization", header)
		subscriptionAPIServe(t, New(o), r, 401)
		if b.privateCalls() != 0 {
			t.Fatal("legacy admin gained subscription permission")
		}
	}
}
func TestSubscriptionAPIPlaintextRequiresSecureTransport(t *testing.T) {
	for _, remote := range []string{"10.23.0.7:1234", "127.0.0.1:1234", "[::1]:1234"} {
		o, b, a := subscriptionAPIFixture(authz.RoleAdmin)
		r := subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/sources", nil)
		r.TLS = nil
		r.RemoteAddr = remote
		subscriptionAPIServe(t, New(o), r, http.StatusUpgradeRequired)
		if b.privateCalls() != 0 || a.calls != 0 {
			t.Fatal("plaintext reached authentication or inventory")
		}
	}
}
func TestSubscriptionAPIScopeCacheCPUOnly(t *testing.T) {
	o, b, _ := subscriptionAPIFixture(authz.RoleViewer)
	h := New(o)
	w := httptest.NewRecorder()
	h.ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/api/v1/capabilities", nil))
	if w.Code != 200 || b.scopeCalls != 1 || b.privateCalls() != 0 {
		t.Fatal("anonymous capabilities read subscription state")
	}
	for i := 0; i < 3; i++ {
		subscriptionAPIServe(t, h, subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/sources", nil), 200)
	}
	if b.scopeCalls != 1 || b.sourceCalls != 3 {
		t.Fatal("scope getter was not cached")
	}
}
func TestSubscriptionAPIBackendUnavailableAndTypedNil(t *testing.T) {
	for i := 0; i < 5; i++ {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		switch i {
		case 0:
			o.Subscriptions = nil
		case 1:
			var absent *subscriptionAPISpy
			o.Subscriptions = absent
		case 2:
			b.scope.ObjectType = "control-plane"
		case 3:
			o.Authn = nil
		case 4:
			var absent *subscriptionAPIAuth
			o.Authn = absent
		}
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/sources", nil), 503)
		if b.privateCalls() != 0 {
			t.Fatal("unconfigured backend was read")
		}
	}
}
func TestSubscriptionAPIRolesHaveIndependentActions(t *testing.T) {
	for _, role := range []authz.Role{authz.RoleViewer, authz.RoleOperator, authz.RoleApprover, authz.RoleAuditor, authz.RoleAdmin} {
		for _, kind := range []subscriptionctl.Kind{subscriptionctl.Create, subscriptionctl.Import, subscriptionctl.Decide, subscriptionctl.Rollback, subscriptionctl.Approve, subscriptionctl.Fetch} {
			o, b, _ := subscriptionAPIFixture(role)
			allowed := role == authz.RoleAdmin || role == authz.RoleOperator && (kind == subscriptionctl.Create || kind == subscriptionctl.Import || kind == subscriptionctl.Fetch) || role == authz.RoleApprover && (kind == subscriptionctl.Decide || kind == subscriptionctl.Rollback || kind == subscriptionctl.Approve)
			want := 403
			if allowed {
				want = 200
			}
			subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(kind), subscriptionAPIBody(t, kind)), want)
			if (b.executeCalls == 1) != allowed {
				t.Fatal("role permissions were aliased")
			}
		}
		o, _, _ := subscriptionAPIFixture(role)
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/sources", nil), 200)
	}
}
func TestSubscriptionAPICrossTenantSiteEnvironmentDeniedBeforePrivateRead(t *testing.T) {
	for _, field := range []string{"tenant", "site", "environment"} {
		o, b, a := subscriptionAPIFixture(authz.RoleAdmin)
		switch field {
		case "tenant":
			a.principal.TenantID = "other"
		case "site":
			a.principal.AllowedScopes[0].SiteID = "other"
		case "environment":
			a.principal.AllowedScopes[0].Environment = "other"
		}
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, subscriptionAPIPath("/candidates"), nil), 403)
		if b.privateCalls() != 0 {
			t.Fatal("cross-scope denial read inventory")
		}
	}
}
func TestSubscriptionAPISourceGrantCannotListOrCreateCollection(t *testing.T) {
	o, b, a := subscriptionAPIFixture(authz.RoleAdmin)
	a.principal.AllowedScopes = []authz.ResourceScope{subscriptionctl.Resource(subscriptionAPIScope, subscriptionAPISource)}
	h := New(o)
	subscriptionAPIServe(t, h, subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/sources", nil), 403)
	subscriptionAPIServe(t, h, subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), subscriptionAPIBody(t, subscriptionctl.Create)), 403)
	if b.privateCalls() != 0 {
		t.Fatal("source grant escaped to collection")
	}
	subscriptionAPIServe(t, h, subscriptionAPIRequest(http.MethodGet, subscriptionAPIPath("/candidates"), nil), 200)
	if b.candidateCalls != 1 {
		t.Fatal("exact source grant was not honored")
	}
}
func TestSubscriptionAPIWritesDisabledBeforeBodyRead(t *testing.T) {
	for _, kind := range []subscriptionctl.Kind{subscriptionctl.Create, subscriptionctl.Import, subscriptionctl.Decide, subscriptionctl.Rollback, subscriptionctl.Approve, subscriptionctl.Fetch} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		o.SubscriptionWritesEnabled = false
		body := &subscriptionAPIUnread{}
		r := subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(kind), nil)
		r.Body = body
		r.ContentLength = 10
		subscriptionAPIServe(t, New(o), r, 423)
		if b.privateCalls() != 0 || body.reads != 0 || b.deniedCalls != 1 {
			t.Fatal("closed write gate consumed private input")
		}
	}
}
func TestSubscriptionAPIDeniedAuditFailureDoesNotOpenPrivatePath(t *testing.T) {
	o, b, _ := subscriptionAPIFixture(authz.RoleViewer)
	b.deniedErr = errors.New(subscriptionAPISecret)
	body := &subscriptionAPIUnread{}
	r := subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Fetch), nil)
	r.Body = body
	r.ContentLength = 10
	w := subscriptionAPIServe(t, New(o), r, 403)
	if w.Header().Get("X-Chengwang-Denial-Audit") != "unavailable" {
		t.Fatal("failed denial audit was reported as recorded")
	}
	if b.deniedCalls != 1 || b.privateCalls() != 0 || body.reads != 0 {
		t.Fatal("denial audit failure opened a private fallback")
	}
}
func TestSubscriptionAPIContextCancellationDoesNotCallBackend(t *testing.T) {
	for _, method := range []string{http.MethodGet, http.MethodPost} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		body := &subscriptionAPIUnread{}
		r := subscriptionAPIRequest(method, "/api/v1/subscriptions/sources", nil)
		if method == http.MethodPost {
			r.Body = body
			r.ContentLength = 10
		}
		ctx, cancel := context.WithCancel(r.Context())
		cancel()
		r = r.WithContext(ctx)
		subscriptionAPIServe(t, New(o), r, 503)
		if b.privateCalls() != 0 || body.reads != 0 {
			t.Fatal("canceled request proceeded")
		}
	}
}
func TestSubscriptionAPIMethodsClosedAcrossRoutes(t *testing.T) {
	for _, path := range []string{"/api/v1/subscriptions/sources", subscriptionAPIPath("/candidates"), subscriptionAPIPath("/candidates/" + subscriptionAPICandidate + "/nodes"), subscriptionAPIPath("/decisions"), subscriptionAPIPath("/rollbacks"), subscriptionAPIPath("/approvals"), subscriptionAPIPath("/fetches"), "/api/v1/subscriptions/commands/" + subscriptionAPICommand} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		body := &subscriptionAPIUnread{}
		r := subscriptionAPIRequest(http.MethodPut, path, nil)
		r.Body = body
		r.ContentLength = 10
		w := subscriptionAPIServe(t, New(o), r, 405)
		if w.Header().Get("Allow") == "" || b.privateCalls() != 0 || body.reads != 0 {
			t.Fatal("method mismatch consumed private data")
		}
	}
}
func TestSubscriptionAPIQueryIsClosedAndCanonical(t *testing.T) {
	for _, query := range []string{"limit=0", "limit=101", "limit=01", "limit=+1", "limit=%31", "limit=1&limit=2", "offset=-1", "offset=1.0", "offset=9223372036854775808", "revision=18446744073709551616", "tenantId=other", "limit=1;offset=0", "limit=1&", "revision=1e2"} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, subscriptionAPIPath("/candidates?")+query, nil), 400)
		if b.privateCalls() != 0 {
			t.Fatal("invalid page query reached backend")
		}
	}
	o, b, _ := subscriptionAPIFixture(authz.RoleViewer)
	subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, subscriptionAPIPath("/candidates?limit=1&offset=0&revision=2"), nil), 200)
	if b.lastQuery != (subscriptionctl.ListQuery{Limit: 1, Revision: 2}) {
		t.Fatal("canonical page query changed")
	}
	for _, path := range []string{"/api/v1/subscriptions/sources?limit=1", subscriptionAPIPath("/candidates?"), "/api/v1/subscriptions/commands/" + subscriptionAPICommand + "?offset=0"} {
		o, b, _ := subscriptionAPIFixture(authz.RoleViewer)
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, path, nil), 400)
		if b.privateCalls() != 0 {
			t.Fatal("query bypass")
		}
	}
}
func TestSubscriptionAPIRequestEncodingAndContentTypeClosed(t *testing.T) {
	for i := 0; i < 6; i++ {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		r := subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), subscriptionAPIBody(t, subscriptionctl.Create))
		want := 415
		switch i {
		case 0:
			r.Header.Del("Content-Type")
		case 1:
			r.Header.Set("Content-Type", "text/plain")
		case 2:
			r.Header.Add("Content-Type", "application/json")
		case 3:
			r.Header.Set("Content-Type", "application/json; charset=ascii")
		case 4:
			r.Header.Set("Content-Type", "application/json; extra=value")
		case 5:
			r.Header.Set("Content-Encoding", "identity")
			want = 400
		}
		subscriptionAPIServe(t, New(o), r, want)
		if b.privateCalls() != 0 {
			t.Fatal("unsupported encoding reached backend")
		}
	}
}
func TestSubscriptionAPIBodyBudgetAndTruncation(t *testing.T) {
	for i := 0; i < 4; i++ {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		r := subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), subscriptionAPIBody(t, subscriptionctl.Create))
		want := 413
		switch i {
		case 0:
			r.ContentLength = subscriptionMaxWireBytes + 1
		case 1:
			r.Body = io.NopCloser(strings.NewReader(strings.Repeat("x", subscriptionMaxWireBytes+1)))
			r.ContentLength = -1
		case 2:
			r.Body = &subscriptionAPIUnread{}
			r.ContentLength = -1
			want = 400
		case 3:
			r.ContentLength++
			want = 400
		}
		subscriptionAPIServe(t, New(o), r, want)
		if b.privateCalls() != 0 {
			t.Fatal("invalid body budget reached backend")
		}
	}
}
func TestSubscriptionAPIJSONDuplicateUnknownAndTrailingRejected(t *testing.T) {
	for _, body := range []string{`{"label":"one","label":"two"}`, `{"label":"one","\u006cabel":"two"}`, `{"label":"one","actor":"admin"}`, `{"label":"one","kind":"fetch"}`, `{"label":"one","tenantId":"other"}`, `{"label":"one","url":"https://example/"}`, `{"label":"one","Label":"two"}`, `{"label":"one"}{}`, `[]`, `null`} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), []byte(body)), 400)
		if b.privateCalls() != 0 {
			t.Fatal("nonclosed JSON reached backend")
		}
	}
}
func TestSubscriptionAPIJSONUTF8DepthAndScalarTypesRejected(t *testing.T) {
	for _, body := range [][]byte{[]byte("{\"label\":\"\xff\"}"), []byte(`{"label":42}`), []byte(`{"label":null}`), []byte(`{"label":true}`), []byte(`{"label":"\u000a"}`), []byte(`{"label":` + strings.Repeat("[", 10) + `"deep"` + strings.Repeat("]", 10) + `}`)} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), body), 400)
		if b.privateCalls() != 0 {
			t.Fatal("invalid JSON type reached backend")
		}
	}
	for _, revision := range []string{`"2"`, `true`, `2.0`, `2e0`, `-1`, `0`, `18446744073709551616`} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		raw := []byte(`{"candidateId":"` + subscriptionAPICandidate + `","expectedRevision":` + revision + `}`)
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Rollback), raw), 400)
		if b.privateCalls() != 0 {
			t.Fatal("revision coerced")
		}
	}
}
func TestSubscriptionAPICreateUnicodeLabelAndRouteOwnedKind(t *testing.T) {
	o, b, _ := subscriptionAPIFixture(authz.RoleOperator)
	subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), subscriptionAPIBody(t, subscriptionctl.Create)), 200)
	if b.lastCommand.Kind != subscriptionctl.Create || b.lastCommand.Label != "来源甲" || b.lastCommand.SourceID != "" || b.lastPrincipal.ID != "principal-a" {
		t.Fatal("authenticated command mapping failed")
	}
}
func TestSubscriptionAPIImportCanonicalBase64PreservesPrivateBytes(t *testing.T) {
	o, b, _ := subscriptionAPIFixture(authz.RoleOperator)
	content := []byte("proxies:\n  - name: 中文私有名称\n    password: " + subscriptionAPISecret + "\n")
	raw := subscriptionAPIJSON(t, map[string]any{"expectedRevision": 2, "format": subscription.FormatMihomo, "contentBase64": base64.StdEncoding.EncodeToString(content)})
	subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Import), raw), 200)
	if !bytes.Equal(b.lastCommand.Content, content) || b.lastCommand.Kind != subscriptionctl.Import || b.lastCommand.SourceID != subscriptionAPISource || b.lastCommand.Format != subscription.FormatMihomo {
		t.Fatal("original private content was reencoded or misbound")
	}
}
func TestSubscriptionAPIImportFormatsAndRawBudgetClosed(t *testing.T) {
	for _, format := range []subscription.Format{subscription.FormatAuto, subscription.FormatMihomo, subscription.FormatURI, subscription.FormatBase64URI} {
		o, b, _ := subscriptionAPIFixture(authz.RoleOperator)
		raw := subscriptionAPIJSON(t, map[string]any{"expectedRevision": 2, "format": format, "contentBase64": base64.StdEncoding.EncodeToString([]byte("private"))})
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Import), raw), 200)
		if b.lastCommand.Format != format {
			t.Fatal("format changed")
		}
	}
	for _, encoded := range []string{"", "%%%", "YQ", "YR==", "YQ==\n", base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), subscription.MaxInputBytes+1))} {
		o, b, _ := subscriptionAPIFixture(authz.RoleOperator)
		raw := subscriptionAPIJSON(t, map[string]any{"expectedRevision": 2, "format": "auto", "contentBase64": encoded})
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Import), raw), 400)
		if b.privateCalls() != 0 {
			t.Fatal("invalid raw representation reached service")
		}
	}
	o, b, _ := subscriptionAPIFixture(authz.RoleOperator)
	raw := subscriptionAPIJSON(t, map[string]any{"expectedRevision": 2, "format": "auto", "contentBase64": base64.StdEncoding.EncodeToString(bytes.Repeat([]byte("x"), subscription.MaxInputBytes))})
	subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Import), raw), 200)
	if len(b.lastCommand.Content) != subscription.MaxInputBytes {
		t.Fatal("raw boundary not preserved")
	}
	for _, format := range []string{"", "yaml", "full-clash"} {
		o, b, _ := subscriptionAPIFixture(authz.RoleOperator)
		raw := subscriptionAPIJSON(t, map[string]any{"expectedRevision": 2, "format": format, "contentBase64": "eA=="})
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Import), raw), 400)
		if b.privateCalls() != 0 {
			t.Fatal("unknown format accepted")
		}
	}
}
func TestSubscriptionAPIDecisionOnlyLocalStatesAndCAS(t *testing.T) {
	for _, decision := range []string{"admitted_local", "rejected"} {
		o, b, _ := subscriptionAPIFixture(authz.RoleApprover)
		raw := subscriptionAPIJSON(t, map[string]any{"candidateId": subscriptionAPICandidate, "expectedRevision": 2, "expectedDigest": subscriptionAPIDigest, "decision": decision})
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Decide), raw), 200)
		if b.lastCommand.Decision != subscription.CandidateState(decision) || b.lastCommand.ExpectedRevision != 2 || b.lastCommand.ExpectedDigest != subscriptionAPIDigest {
			t.Fatal("local decision mapping")
		}
	}
	for _, decision := range []string{"quarantined", "published", "healthy", ""} {
		o, b, _ := subscriptionAPIFixture(authz.RoleApprover)
		raw := subscriptionAPIJSON(t, map[string]any{"candidateId": subscriptionAPICandidate, "expectedRevision": 2, "expectedDigest": subscriptionAPIDigest, "decision": decision})
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Decide), raw), 400)
		if b.privateCalls() != 0 {
			t.Fatal("decision gained runtime authority")
		}
	}
}
func TestSubscriptionAPIRollbackApprovalAndFetchCommandsAreClosed(t *testing.T) {
	for _, kind := range []subscriptionctl.Kind{subscriptionctl.Rollback, subscriptionctl.Approve, subscriptionctl.Fetch} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(kind), subscriptionAPIBody(t, kind)), 200)
		if b.lastCommand.Kind != kind || b.lastCommand.ExpectedRevision != 2 {
			t.Fatal("route command mismatch")
		}
		if kind == subscriptionctl.Approve && (b.lastCommand.ReferenceID != "source-reference" || b.lastCommand.PolicyRevision != 1) {
			t.Fatal("approval binding")
		}
		if kind == subscriptionctl.Fetch && (b.lastCommand.ApprovalID != subscriptionAPICommand || b.lastCommand.PolicyRevision != 1) {
			t.Fatal("fetch binding")
		}
		var object map[string]any
		_ = json.Unmarshal(subscriptionAPIBody(t, kind), &object)
		object["url"] = "https://" + subscriptionAPISecret + ".example/"
		o, b, _ = subscriptionAPIFixture(authz.RoleAdmin)
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(kind), subscriptionAPIJSON(t, object)), 400)
		if b.privateCalls() != 0 {
			t.Fatal("client URL accepted")
		}
	}
}
func TestSubscriptionAPIIdempotencyHeaderIsUniqueAndBounded(t *testing.T) {
	for _, values := range [][]string{nil, {""}, {strings.Repeat("a", 15)}, {strings.Repeat("a", 129)}, {"same-key-00000001", "same-key-00000001"}, {"key-with-a-comma,0001"}, {"key with spaces 0001"}, {"/private/key/00001"}} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		r := subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), subscriptionAPIBody(t, subscriptionctl.Create))
		r.Header.Del("Idempotency-Key")
		for _, v := range values {
			r.Header.Add("Idempotency-Key", v)
		}
		subscriptionAPIServe(t, New(o), r, 400)
		if b.privateCalls() != 0 {
			t.Fatal("invalid key consumed command")
		}
	}
	for _, size := range []int{16, 128} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		r := subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), subscriptionAPIBody(t, subscriptionctl.Create))
		r.Header.Set("Idempotency-Key", strings.Repeat("a", size))
		subscriptionAPIServe(t, New(o), r, 200)
		if b.lastCommand.IdempotencyKey != strings.Repeat("a", size) {
			t.Fatal("key was silently normalized")
		}
	}
}
func TestSubscriptionAPISourceAndCandidatePathsRejectAliases(t *testing.T) {
	for _, path := range []string{strings.Replace(subscriptionAPIPath("/candidates"), "src_", "SRC_", 1), strings.Replace(subscriptionAPIPath("/candidates"), "src_", "%73rc_", 1), subscriptionAPIPath("/candidates/cand_BAD/nodes"), "/api/v1/subscriptions/commands/cmd_BAD"} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, path, nil), 400)
		if b.privateCalls() != 0 {
			t.Fatal("noncanonical path reached private inventory")
		}
	}
	o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
	subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/not-a-route", nil), 404)
	if b.privateCalls() != 0 {
		t.Fatal("unknown route reached backend")
	}
}
func TestSubscriptionAPISourcePageSafeBoundary(t *testing.T) {
	o, b, _ := subscriptionAPIFixture(authz.RoleViewer)
	w := subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/sources", nil), 200)
	if b.sourceCalls != 1 || strings.Contains(w.Body.String(), "nodes") || strings.Contains(w.Body.String(), "contentBase64") || strings.Contains(w.Body.String(), "url") {
		t.Fatal("source page was not safe metadata")
	}
	var value struct{ Result subscriptionctl.SourcePage }
	if json.Unmarshal(w.Body.Bytes(), &value) != nil || value.Result.Total != 1 || value.Result.Sources[0].ID != subscriptionAPISource {
		t.Fatal("source page shape")
	}
}
func TestSubscriptionAPICandidateSummariesNeverExposeNodes(t *testing.T) {
	o, b, _ := subscriptionAPIFixture(authz.RoleViewer)
	w := subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, subscriptionAPIPath("/candidates"), nil), 200)
	if b.candidateCalls != 1 || strings.Contains(w.Body.String(), `"nodes"`) || strings.Contains(w.Body.String(), "canonicalConfig") || strings.Contains(w.Body.String(), "privateName") {
		t.Fatal("candidate list exposed private node material")
	}
}
func TestSubscriptionAPINodePagesBoundedAndRevisionFenced(t *testing.T) {
	o, b, _ := subscriptionAPIFixture(authz.RoleViewer)
	subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, subscriptionAPIPath("/candidates/"+subscriptionAPICandidate+"/nodes?limit=1&revision=2"), nil), 200)
	if b.lastQuery.Limit != 1 || b.lastQuery.Revision != 2 || b.lastSource != subscriptionAPISource || b.lastCandidate != subscriptionAPICandidate {
		t.Fatal("node page not scope/revision bound")
	}
	o, b, _ = subscriptionAPIFixture(authz.RoleViewer)
	b.err = &subscriptionctl.Error{Code: subscriptionctl.CodeConflict}
	subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, subscriptionAPIPath("/candidates/"+subscriptionAPICandidate+"/nodes?revision=3"), nil), 409)
	o, b, _ = subscriptionAPIFixture(authz.RoleViewer)
	b.nodes.Revision = 3
	subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, subscriptionAPIPath("/candidates/"+subscriptionAPICandidate+"/nodes?revision=2"), nil), 503)
}
func TestSubscriptionAPIReceiptRoutesAreProtectedAndSafe(t *testing.T) {
	o, b, _ := subscriptionAPIFixture(authz.RoleViewer)
	subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/commands/"+subscriptionAPICommand, nil), 200)
	if b.receiptCalls != 1 || b.lastReceipt != subscriptionAPICommand {
		t.Fatal("receipt not bound")
	}
	o, b, _ = subscriptionAPIFixture(authz.RoleViewer)
	b.receipt.State = "unknown"
	b.receipt.Code = subscriptionctl.CodeCommitUnknown
	b.receipt.StateMayHaveChanged = true
	b.receipt.LocalAuditHash = ""
	w := subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/commands/"+subscriptionAPICommand, nil), 200)
	if !strings.Contains(w.Body.String(), `"stateMayHaveChanged":true`) {
		t.Fatal("unknown receipt presented as no change")
	}
	o, b, _ = subscriptionAPIFixture(authz.RoleViewer)
	b.err = &subscriptionctl.Error{Code: subscriptionctl.CodeNotFound}
	subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/commands/"+subscriptionAPICommand, nil), 404)
}
func TestSubscriptionAPIBackendErrorsAreClosedAndStateExplicit(t *testing.T) {
	for _, item := range []struct {
		code   subscriptionctl.Code
		status int
	}{{subscriptionctl.CodeInvalid, 400}, {subscriptionctl.CodeForbidden, 403}, {subscriptionctl.CodeLocked, 423}, {subscriptionctl.CodeConflict, 409}, {subscriptionctl.CodeNotFound, 404}, {subscriptionctl.CodeAuditDegraded, 503}, {subscriptionctl.CodeCommitUnknown, 503}, {subscriptionctl.CodeCanceled, 503}, {subscriptionctl.CodeApprovalRequired, 409}, {subscriptionctl.CodeLimit, 429}, {subscriptionctl.CodeUnavailable, 503}} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		b.err = &subscriptionctl.Error{Code: item.code}
		w := subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), subscriptionAPIBody(t, subscriptionctl.Create)), item.status)
		var envelope subscriptionEnvelope
		if json.Unmarshal(w.Body.Bytes(), &envelope) != nil || envelope.Code != item.code || envelope.StateMayHaveChanged != (item.code == subscriptionctl.CodeCommitUnknown) {
			t.Fatal("classification/uncertainty changed")
		}
		if w.Header().Get("X-Chengwang-Command-ID") != subscriptionAPICommand {
			t.Fatal("safe classified error lost its read-only receipt handle")
		}
	}
}
func TestSubscriptionAPIUnknownBackendErrorsSuppressRawSecrets(t *testing.T) {
	for _, err := range []error{errors.New(subscriptionAPISecret + " /private/path?token=hidden"), &subscriptionctl.Error{Code: subscriptionctl.Code(subscriptionAPISecret)}} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		b.err = err
		w := subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), subscriptionAPIBody(t, subscriptionctl.Create)), 503)
		if !strings.Contains(w.Body.String(), `"stateMayHaveChanged":true`) {
			t.Fatal("unknown mutation error falsely promised no change")
		}
		if w.Header().Get("X-Chengwang-Command-ID") != "" {
			t.Fatal("unclassified failure exposed a receipt handle")
		}
	}
	o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
	b.err = &subscriptionctl.Error{Code: subscriptionctl.CodeAuditDegraded, StateMayHaveChanged: true}
	b.receipt.CommandID = subscriptionAPISecret
	w := subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Create), subscriptionAPIBody(t, subscriptionctl.Create)), 503)
	if w.Header().Get("X-Chengwang-Command-ID") != "" {
		t.Fatal("malformed receipt handle was exported")
	}
	for _, wrongSource := range []bool{false, true} {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		b.err = &subscriptionctl.Error{Code: subscriptionctl.CodeAuditDegraded, StateMayHaveChanged: true}
		b.fixedReceipt = true
		if wrongSource {
			b.receipt.Kind = subscriptionctl.Fetch
			b.receipt.SourceID = "src_" + strings.Repeat("f", 32)
		}
		w := subscriptionAPIServe(t, New(o), subscriptionAPIRequest(http.MethodPost, subscriptionAPIRoute(subscriptionctl.Fetch), subscriptionAPIBody(t, subscriptionctl.Fetch)), 503)
		if w.Header().Get("X-Chengwang-Command-ID") != "" {
			t.Fatal("route-unbound receipt handle was exported")
		}
	}
}
func TestSubscriptionAPIInvalidBackendProjectionFailsClosed(t *testing.T) {
	for i := 0; i < 7; i++ {
		o, b, _ := subscriptionAPIFixture(authz.RoleAdmin)
		path := "/api/v1/subscriptions/sources"
		method := http.MethodGet
		var raw []byte
		switch i {
		case 0:
			b.sources.Sources = nil
		case 1:
			b.sources.Sources[0].Scope.TenantID = "foreign"
		case 2:
			path = subscriptionAPIPath("/candidates")
			b.candidates.Candidates[0].CreatedAt = time.Time{}
		case 3:
			path = subscriptionAPIPath("/candidates/" + subscriptionAPICandidate + "/nodes")
			b.nodes.Nodes[0].State = "available"
		case 4:
			path = subscriptionAPIPath("/candidates/" + subscriptionAPICandidate + "/nodes")
			b.nodes.Nodes[0].Protocol = "ss|vmess"
		case 5:
			method = http.MethodPost
			raw = subscriptionAPIBody(t, subscriptionctl.Create)
			b.receipt.AuditRecorded = false
		case 6:
			b.sources.Sources[0].UpdatedAt = time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)
		}
		subscriptionAPIServe(t, New(o), subscriptionAPIRequest(method, path, raw), 503)
	}
}
func TestSubscriptionAPIActualIdentityStoreAuthentication(t *testing.T) {
	o, b, a := subscriptionAPIFixture(authz.RoleViewer)
	token, digest, err := authn.GenerateToken(32)
	if err != nil {
		t.Fatal("generate private fixture identity")
	}
	dir := t.TempDir()
	if os.Chmod(dir, 0700) != nil {
		t.Fatal("private credential fixture directory")
	}
	path := filepath.Join(dir, "identities.json")
	raw := subscriptionAPIJSON(t, authn.File{Version: 1, Identities: []authn.Identity{{TokenID: "subscription-fixture", TokenHash: digest, Principal: a.principal}}})
	if os.WriteFile(path, raw, 0600) != nil {
		t.Fatal("write private identity fixture")
	}
	identity, err := authn.Open(path)
	if err != nil {
		t.Fatal("load actual identity store")
	}
	o.Authn = identity
	h := New(o)
	r := subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/sources", nil)
	r.Header.Set("Authorization", "Bearer "+token)
	subscriptionAPIServe(t, h, r, 200)
	r = subscriptionAPIRequest(http.MethodGet, "/api/v1/subscriptions/sources", nil)
	r.Header.Set("Authorization", "Bearer "+base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{9}, 32)))
	subscriptionAPIServe(t, h, r, 401)
	if b.sourceCalls != 1 || b.lastPrincipal.ID != a.principal.ID {
		t.Fatal("actual authentication not enforced")
	}
}

var _ subscriptionctl.Backend = (*subscriptionAPISpy)(nil)
