package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"
	"time"

	"chengwang/internal/authz"
	"chengwang/internal/subscription"
	"chengwang/internal/subscriptionctl"
)

type accessAPISpy struct {
	*subscriptionAPISpy
	view             *subscriptionctl.AccessView
	accessCalls      int
	lastAccessSource string
	accessErr        error
}

func (b *accessAPISpy) Access(_ context.Context, p authz.Principal, id string) (subscriptionctl.AccessView, error) {
	b.accessCalls++
	b.lastAccessSource = id
	b.lastPrincipal = p
	if b.accessErr != nil {
		return subscriptionctl.AccessView{}, b.accessErr
	}
	if b.view != nil {
		return *b.view, nil
	}
	resource := subscriptionctl.Resource(b.scope, id)
	view := subscriptionctl.AccessView{Scope: subscription.Scope{TenantID: b.scope.TenantID, SiteID: b.scope.SiteID, Environment: b.scope.Environment}, Resource: subscriptionctl.AccessResource{Type: resource.ObjectType, ID: resource.ObjectID}, WritesEnabled: true, Actions: []authz.Action{}, PolicyState: "ready", References: []subscriptionctl.PolicyReference{{ReferenceID: "source-reference", Revision: 1}}}
	for _, action := range []authz.Action{authz.ActionReadSubscription, authz.ActionManageSubscriptionSource, authz.ActionImportSubscription, authz.ActionDecideSubscription, authz.ActionApproveSubscriptionSource, authz.ActionFetchSubscription, authz.ActionRollbackSubscription} {
		if authz.Evaluate(authz.Request{Principal: p, Action: action, Resource: resource}, time.Now().UTC()).Allowed {
			view.Actions = append(view.Actions, action)
		}
	}
	return view, nil
}
func accessAPIFixture(role authz.Role) (Options, *accessAPISpy, *subscriptionAPIAuth) {
	options, base, auth := subscriptionAPIFixture(role)
	spy := &accessAPISpy{subscriptionAPISpy: base}
	options.Subscriptions = spy
	return options, spy, auth
}
func accessAPIResult(t *testing.T, w *httptest.ResponseRecorder) subscriptionctl.AccessView {
	t.Helper()
	var body struct {
		Result subscriptionctl.AccessView `json:"result"`
	}
	if json.Unmarshal(w.Body.Bytes(), &body) != nil {
		t.Fatal("invalid access result")
	}
	return body.Result
}
func accessAPIRequest(path string) *http.Request {
	return subscriptionAPIRequest(http.MethodGet, path, nil)
}

const accessAPICollection = "/api/v1/subscriptions/access"

func accessAPIPrivateUntouched(t *testing.T, b *accessAPISpy) {
	t.Helper()
	if b.privateCalls() != 0 {
		t.Fatal("access touched private inventory or mutation")
	}
}

func TestSubscriptionAccessAPIRequiresStrictBearer(t *testing.T) {
	for _, values := range [][]string{nil, {"Bearer legacy-admin-sentinel"}, {"Bearer " + subscriptionAPIToken, "Bearer " + subscriptionAPIToken}, {"bearer " + subscriptionAPIToken}, {"Bearer " + subscriptionAPIToken + ",other"}} {
		options, b, _ := accessAPIFixture(authz.RoleAdmin)
		r := accessAPIRequest(accessAPICollection)
		r.Header.Del("Authorization")
		for _, value := range values {
			r.Header.Add("Authorization", value)
		}
		subscriptionAPIServe(t, New(options), r, http.StatusUnauthorized)
		if b.accessCalls != 0 {
			t.Fatal("anonymous metadata exposed")
		}
		accessAPIPrivateUntouched(t, b)
	}
}
func TestSubscriptionAccessAPIRequiresTLSIncludingLoopback(t *testing.T) {
	for _, addr := range []string{"127.0.0.1:17861", "10.23.0.7:1234"} {
		options, b, a := accessAPIFixture(authz.RoleAdmin)
		r := accessAPIRequest(accessAPICollection)
		r.RemoteAddr = addr
		r.TLS = nil
		subscriptionAPIServe(t, New(options), r, http.StatusUpgradeRequired)
		if a.calls != 0 || b.accessCalls != 0 {
			t.Fatal("plaintext Bearer authenticated or metadata read")
		}
		accessAPIPrivateUntouched(t, b)
	}
}
func TestSubscriptionAccessAPIIndependentReadScope(t *testing.T) {
	for _, scope := range []authz.ResourceScope{{TenantID: "foreign", SiteID: "site-a", Environment: "isolated"}, {TenantID: "tenant-a", SiteID: "foreign", Environment: "isolated"}, {TenantID: "tenant-a", SiteID: "site-a", Environment: "production"}} {
		options, b, a := accessAPIFixture(authz.RoleAdmin)
		a.principal.AllowedScopes = []authz.ResourceScope{scope}
		subscriptionAPIServe(t, New(options), accessAPIRequest(subscriptionAPIPath("/access")), http.StatusForbidden)
		if b.accessCalls != 0 {
			t.Fatal("foreign resource metadata read")
		}
		accessAPIPrivateUntouched(t, b)
	}
	options, b, a := accessAPIFixture(authz.RoleOperator)
	a.principal.AllowedScopes = []authz.ResourceScope{subscriptionctl.Resource(subscriptionAPIScope, subscriptionAPISource)}
	h := New(options)
	subscriptionAPIServe(t, h, accessAPIRequest(accessAPICollection), http.StatusForbidden)
	subscriptionAPIServe(t, h, accessAPIRequest(subscriptionAPIPath("/access")), http.StatusOK)
	if b.accessCalls != 1 || b.lastAccessSource != subscriptionAPISource {
		t.Fatal("source-only grant broadened")
	}
	accessAPIPrivateUntouched(t, b)
}
func TestSubscriptionAccessAPIGetShapeClosedBeforeMetadata(t *testing.T) {
	for _, mutate := range []func(*http.Request){
		func(r *http.Request) { r.Method = http.MethodPost }, func(r *http.Request) { r.Method = http.MethodHead },
		func(r *http.Request) { r.URL.RawQuery = "limit=1" }, func(r *http.Request) { r.URL.ForceQuery = true },
		func(r *http.Request) { r.Header.Set("Content-Encoding", "identity") }, func(r *http.Request) { r.ContentLength = 1 },
		func(r *http.Request) { r.TransferEncoding = []string{"chunked"} }, func(r *http.Request) { r.URL.RawPath = "/api/v1/subscriptions/%61ccess" },
	} {
		options, b, _ := accessAPIFixture(authz.RoleAdmin)
		r := accessAPIRequest(accessAPICollection)
		mutate(r)
		want := http.StatusBadRequest
		if r.Method != http.MethodGet {
			want = http.StatusMethodNotAllowed
		}
		w := subscriptionAPIServe(t, New(options), r, want)
		if want == http.StatusMethodNotAllowed && w.Header().Get("Allow") != "GET" {
			t.Fatal("missing GET method contract")
		}
		if b.accessCalls != 0 {
			t.Fatal("malformed request read metadata")
		}
		accessAPIPrivateUntouched(t, b)
	}
	options, b, _ := accessAPIFixture(authz.RoleAdmin)
	subscriptionAPIServe(t, New(options), accessAPIRequest("/api/v1/subscriptions/sources/src_bad/access"), http.StatusBadRequest)
	if b.accessCalls != 0 {
		t.Fatal("invalid source reached backend")
	}
}
func TestSubscriptionAccessAPIUnavailableAndTypedNil(t *testing.T) {
	for _, backend := range []subscriptionctl.Backend{nil, (*accessAPISpy)(nil)} {
		options, _, _ := accessAPIFixture(authz.RoleAdmin)
		options.Subscriptions = backend
		subscriptionAPIServe(t, New(options), accessAPIRequest(accessAPICollection), http.StatusServiceUnavailable)
	}
	options, b, _ := accessAPIFixture(authz.RoleAdmin)
	options.Authn = (*subscriptionAPIAuth)(nil)
	subscriptionAPIServe(t, New(options), accessAPIRequest(accessAPICollection), http.StatusServiceUnavailable)
	if b.accessCalls != 0 {
		t.Fatal("typed nil authn reached metadata")
	}
	options, b, _ = accessAPIFixture(authz.RoleAdmin)
	b.scope = authz.ResourceScope{}
	subscriptionAPIServe(t, New(options), accessAPIRequest(accessAPICollection), http.StatusServiceUnavailable)
	if b.accessCalls != 0 {
		t.Fatal("invalid trusted scope reached metadata")
	}
}
func TestSubscriptionAccessAPIOptionalBackendPreservesLegacyInterface(t *testing.T) {
	options, b, _ := subscriptionAPIFixture(authz.RoleViewer)
	h := New(options)
	subscriptionAPIServe(t, h, accessAPIRequest(accessAPICollection), http.StatusServiceUnavailable)
	if b.privateCalls() != 0 {
		t.Fatal("optional fallback touched inventory")
	}
	subscriptionAPIServe(t, h, accessAPIRequest("/api/v1/subscriptions/sources"), http.StatusOK)
	if b.sourceCalls != 1 {
		t.Fatal("legacy Backend required interface changed")
	}
}
func TestSubscriptionAccessAPICollectionActionsCannotGrantSource(t *testing.T) {
	options, b, a := accessAPIFixture(authz.RoleAdmin)
	w := subscriptionAPIServe(t, New(options), accessAPIRequest(accessAPICollection), http.StatusOK)
	v := accessAPIResult(t, w)
	if !reflect.DeepEqual(v.Actions, []authz.Action{authz.ActionReadSubscription, authz.ActionManageSubscriptionSource}) {
		t.Fatal("collection granted source actions")
	}
	v.Actions = append(v.Actions, authz.ActionImportSubscription)
	b.view = &v
	subscriptionAPIServe(t, New(options), accessAPIRequest(accessAPICollection), http.StatusServiceUnavailable)
	b.view = nil
	a.principal.AllowedScopes = []authz.ResourceScope{subscriptionAPIScope}
	before := b.accessCalls
	subscriptionAPIServe(t, New(options), accessAPIRequest(subscriptionAPIPath("/access")), http.StatusForbidden)
	if b.accessCalls != before {
		t.Fatal("collection-only grant expanded to source")
	}
	accessAPIPrivateUntouched(t, b)
}
func TestSubscriptionAccessAPISourceActionsMatchCurrentPrincipal(t *testing.T) {
	for _, row := range []struct {
		role    authz.Role
		actions []authz.Action
	}{
		{authz.RoleViewer, []authz.Action{authz.ActionReadSubscription}},
		{authz.RoleAuditor, []authz.Action{authz.ActionReadSubscription}},
		{authz.RoleOperator, []authz.Action{authz.ActionReadSubscription, authz.ActionImportSubscription, authz.ActionFetchSubscription}},
		{authz.RoleApprover, []authz.Action{authz.ActionReadSubscription, authz.ActionDecideSubscription, authz.ActionApproveSubscriptionSource, authz.ActionRollbackSubscription}},
	} {
		options, b, _ := accessAPIFixture(row.role)
		w := subscriptionAPIServe(t, New(options), accessAPIRequest(subscriptionAPIPath("/access")), http.StatusOK)
		if !reflect.DeepEqual(accessAPIResult(t, w).Actions, row.actions) {
			t.Fatal("source permissions incorrect")
		}
		accessAPIPrivateUntouched(t, b)
	}
}
func TestSubscriptionAccessAPIEffectiveWriteGateIntersection(t *testing.T) {
	for _, serviceEnabled := range []bool{false, true} {
		for _, apiEnabled := range []bool{false, true} {
			options, b, a := accessAPIFixture(authz.RoleOperator)
			view, err := b.Access(context.Background(), a.principal, subscriptionAPISource)
			if err != nil {
				t.Fatal("fixture access")
			}
			b.accessCalls = 0
			view.WritesEnabled = serviceEnabled
			b.view = &view
			options.SubscriptionWritesEnabled = apiEnabled
			w := subscriptionAPIServe(t, New(options), accessAPIRequest(subscriptionAPIPath("/access")), http.StatusOK)
			result := accessAPIResult(t, w)
			if result.WritesEnabled != (serviceEnabled && apiEnabled) || !reflect.DeepEqual(result.Actions, view.Actions) {
				t.Fatal("effective gate is not intersection")
			}
			accessAPIPrivateUntouched(t, b)
		}
	}
}
func TestSubscriptionAccessAPIRejectsUnsafeMetadata(t *testing.T) {
	for _, mutate := range []func(*subscriptionctl.AccessView){
		func(v *subscriptionctl.AccessView) { v.Scope.TenantID = "foreign" }, func(v *subscriptionctl.AccessView) { v.Scope.SiteID = "foreign" }, func(v *subscriptionctl.AccessView) { v.Scope.Environment = "foreign" },
		func(v *subscriptionctl.AccessView) { v.Resource.Type = "secret-url" }, func(v *subscriptionctl.AccessView) { v.Resource.ID = subscriptionAPISource },
		func(v *subscriptionctl.AccessView) { v.Actions = nil }, func(v *subscriptionctl.AccessView) { v.Actions = append(v.Actions, authz.ActionFetchSubscription) },
		func(v *subscriptionctl.AccessView) {
			v.Actions = []authz.Action{authz.ActionManageSubscriptionSource, authz.ActionReadSubscription}
		},
		func(v *subscriptionctl.AccessView) {
			v.Actions = []authz.Action{authz.ActionReadSubscription, authz.ActionReadSubscription}
		},
	} {
		options, b, a := accessAPIFixture(authz.RoleAdmin)
		view, err := b.Access(context.Background(), a.principal, "")
		if err != nil {
			t.Fatal("fixture access")
		}
		mutate(&view)
		b.view = &view
		subscriptionAPIServe(t, New(options), accessAPIRequest(accessAPICollection), http.StatusServiceUnavailable)
		accessAPIPrivateUntouched(t, b)
	}
}
func TestSubscriptionAccessAPIReferencesAndPolicyStateClosed(t *testing.T) {
	for _, mutate := range []func(*subscriptionctl.AccessView){
		func(v *subscriptionctl.AccessView) { v.PolicyState = "secret-url" }, func(v *subscriptionctl.AccessView) { v.References = nil }, func(v *subscriptionctl.AccessView) { v.References = []subscriptionctl.PolicyReference{} },
		func(v *subscriptionctl.AccessView) { v.References[0].Revision = 0 }, func(v *subscriptionctl.AccessView) { v.References[0].ReferenceID = "https://private-url/token" },
		func(v *subscriptionctl.AccessView) { v.References = append(v.References, v.References[0]) }, func(v *subscriptionctl.AccessView) {
			v.References = append(v.References, subscriptionctl.PolicyReference{ReferenceID: "a", Revision: 1})
		},
		func(v *subscriptionctl.AccessView) {
			v.References = make([]subscriptionctl.PolicyReference, subscriptionctl.MaxPolicyReferences+1)
		}, func(v *subscriptionctl.AccessView) { v.PolicyState = "not_configured" }, func(v *subscriptionctl.AccessView) { v.PolicyState = "unavailable" },
	} {
		options, b, a := accessAPIFixture(authz.RoleViewer)
		view, err := b.Access(context.Background(), a.principal, "")
		if err != nil {
			t.Fatal("fixture access")
		}
		mutate(&view)
		b.view = &view
		subscriptionAPIServe(t, New(options), accessAPIRequest(accessAPICollection), http.StatusServiceUnavailable)
		accessAPIPrivateUntouched(t, b)
	}
	for _, state := range []string{"not_configured", "unavailable"} {
		options, b, a := accessAPIFixture(authz.RoleViewer)
		view, _ := b.Access(context.Background(), a.principal, "")
		view.PolicyState = state
		view.References = []subscriptionctl.PolicyReference{}
		b.view = &view
		w := subscriptionAPIServe(t, New(options), accessAPIRequest(accessAPICollection), http.StatusOK)
		if accessAPIResult(t, w).PolicyState != state {
			t.Fatal("safe policy state unavailable")
		}
	}
}
func TestSubscriptionAccessAPISafeEnvelopeAndNoPrivateCalls(t *testing.T) {
	options, b, _ := accessAPIFixture(authz.RoleViewer)
	w := subscriptionAPIServe(t, New(options), accessAPIRequest(accessAPICollection), http.StatusOK)
	var body map[string]json.RawMessage
	if json.Unmarshal(w.Body.Bytes(), &body) != nil || len(body) != 5 {
		t.Fatal("access envelope shape")
	}
	var result map[string]json.RawMessage
	if json.Unmarshal(body["result"], &result) != nil || len(result) != 6 {
		t.Fatal("access result fields")
	}
	for _, key := range []string{"scope", "resource", "writesEnabled", "actions", "policyState", "references"} {
		if _, ok := result[key]; !ok {
			t.Fatal("access public field missing")
		}
	}
	if string(body["stateMayHaveChanged"]) != "false" {
		t.Fatal("read implied mutation")
	}
	accessAPIPrivateUntouched(t, b)
	b.accessErr = errors.New(subscriptionAPISecret)
	w = subscriptionAPIServe(t, New(options), accessAPIRequest(accessAPICollection), http.StatusServiceUnavailable)
	if strings.Contains(w.Body.String(), subscriptionAPISecret) || strings.Contains(w.Body.String(), "result") {
		t.Fatal("raw backend failure exposed")
	}
	b.accessErr = &subscriptionctl.Error{Code: subscriptionctl.CodeForbidden}
	subscriptionAPIServe(t, New(options), accessAPIRequest(accessAPICollection), http.StatusForbidden)
	accessAPIPrivateUntouched(t, b)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	before := b.accessCalls
	r := accessAPIRequest(accessAPICollection).WithContext(ctx)
	subscriptionAPIServe(t, New(options), r, http.StatusServiceUnavailable)
	if b.accessCalls != before {
		t.Fatal("canceled request read metadata")
	}
}
