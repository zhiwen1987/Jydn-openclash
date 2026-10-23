package subscriptionctl

import (
	"context"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"chengwang/internal/authz"
	"chengwang/internal/subscription"
)

type accessCtlManualPolicy struct{}

func (*accessCtlManualPolicy) Describe(string) (PolicyDescriptor, error) {
	panic("private Describe must not run")
}
func (*accessCtlManualPolicy) Fetch(context.Context, subscription.Scope, string, string) (subscription.FetchResult, error) {
	panic("network Fetch must not run")
}

type accessCtlPolicy struct {
	accessCtlManualPolicy
	entries []PolicyReference
	err     error
	calls   int
	cancel  context.CancelFunc
}

func (p *accessCtlPolicy) References() ([]PolicyReference, error) {
	p.calls++
	if p.cancel != nil {
		p.cancel()
	}
	return p.entries, p.err
}
func accessCtlFixture(role authz.Role) (*Service, authz.Principal) {
	scope := authz.ResourceScope{TenantID: "tenant-a", SiteID: "site-a", Environment: "isolated", ObjectType: "subscription-store", ObjectID: "local"}
	// A deliberately unopened Store: any attempted private inventory I/O would
	// fail. Access must depend only on validated configuration and authz.
	s := &Service{serviceCore: &serviceCore{config: Config{Scope: scope, Store: &subscription.Store{}, WritesEnabled: true}}}
	p := authz.Principal{ID: "access-reader", TenantID: scope.TenantID, Roles: []authz.Role{role}, AllowedScopes: []authz.ResourceScope{{TenantID: scope.TenantID, SiteID: scope.SiteID, Environment: scope.Environment}}, BreakGlassEligible: true}
	return s, p
}
func accessCtlGet(t *testing.T, s *Service, p authz.Principal, id string) AccessView {
	t.Helper()
	v, err := s.Access(context.Background(), p, id)
	if err != nil {
		t.Fatal("access metadata rejected")
	}
	return v
}
func accessCtlCode(t *testing.T, err error, want Code) {
	t.Helper()
	var e *Error
	if !errors.As(err, &e) || e.Code != want || e.StateMayHaveChanged {
		t.Fatal("unsafe access error classification")
	}
}

func TestSubscriptionAccessServiceScopeAndResource(t *testing.T) {
	s, p := accessCtlFixture(authz.RoleAdmin)
	v := accessCtlGet(t, s, p, "")
	if v.Resource != (AccessResource{Type: "subscription-store", ID: "local"}) || v.Scope != (subscription.Scope{TenantID: "tenant-a", SiteID: "site-a", Environment: "isolated"}) {
		t.Fatal("collection scope changed")
	}
	id := "src_" + strings.Repeat("a", 32)
	v = accessCtlGet(t, s, p, id)
	if v.Resource != (AccessResource{Type: "subscription-source", ID: id}) {
		t.Fatal("source scope changed")
	}
	_, err := s.Access(context.Background(), p, "src_bad")
	accessCtlCode(t, err, CodeForbidden)
}
func TestSubscriptionAccessServiceRoleActionsAreResourceSpecific(t *testing.T) {
	id := "src_" + strings.Repeat("a", 32)
	for _, row := range []struct {
		role               authz.Role
		collection, source []authz.Action
	}{
		{authz.RoleViewer, []authz.Action{authz.ActionReadSubscription}, []authz.Action{authz.ActionReadSubscription}},
		{authz.RoleAuditor, []authz.Action{authz.ActionReadSubscription}, []authz.Action{authz.ActionReadSubscription}},
		{authz.RoleOperator, []authz.Action{authz.ActionReadSubscription, authz.ActionManageSubscriptionSource}, []authz.Action{authz.ActionReadSubscription, authz.ActionImportSubscription, authz.ActionFetchSubscription}},
		{authz.RoleApprover, []authz.Action{authz.ActionReadSubscription}, []authz.Action{authz.ActionReadSubscription, authz.ActionDecideSubscription, authz.ActionApproveSubscriptionSource, authz.ActionRollbackSubscription}},
		{authz.RoleAdmin, []authz.Action{authz.ActionReadSubscription, authz.ActionManageSubscriptionSource}, []authz.Action{authz.ActionReadSubscription, authz.ActionImportSubscription, authz.ActionDecideSubscription, authz.ActionApproveSubscriptionSource, authz.ActionFetchSubscription, authz.ActionRollbackSubscription}},
	} {
		s, p := accessCtlFixture(row.role)
		if !reflect.DeepEqual(accessCtlGet(t, s, p, "").Actions, row.collection) || !reflect.DeepEqual(accessCtlGet(t, s, p, id).Actions, row.source) {
			t.Fatal("resource-specific role actions changed")
		}
	}
}
func TestSubscriptionAccessServiceWriteGateDoesNotRewritePermissions(t *testing.T) {
	s, p := accessCtlFixture(authz.RoleAdmin)
	enabled := accessCtlGet(t, s, p, "")
	s.config.WritesEnabled = false
	disabled := accessCtlGet(t, s, p, "")
	if !enabled.WritesEnabled || disabled.WritesEnabled || !reflect.DeepEqual(enabled.Actions, disabled.Actions) {
		t.Fatal("write gate conflated with permission")
	}
}
func TestSubscriptionAccessServicePoliciesNotConfigured(t *testing.T) {
	s, p := accessCtlFixture(authz.RoleViewer)
	for _, policy := range []PolicyProvider{nil, (*accessCtlPolicy)(nil), (*accessCtlManualPolicy)(nil)} {
		s.config.Policies = policy
		v := accessCtlGet(t, s, p, "")
		if v.PolicyState != "not_configured" || v.References == nil || len(v.References) != 0 {
			t.Fatal("nil policies falsely ready")
		}
	}
}
func TestSubscriptionAccessServicePoliciesUnsupportedOrUnavailable(t *testing.T) {
	s, p := accessCtlFixture(authz.RoleViewer)
	for _, policy := range []PolicyProvider{&accessCtlManualPolicy{}, &accessCtlPolicy{err: errors.New("secret-url-token")}, &accessCtlPolicy{entries: []PolicyReference{}}, &accessCtlPolicy{entries: []PolicyReference{{ReferenceID: "duplicate", Revision: 1}, {ReferenceID: "duplicate", Revision: 2}}}, &accessCtlPolicy{entries: []PolicyReference{{ReferenceID: "https://secret", Revision: 1}}}, &accessCtlPolicy{entries: []PolicyReference{{ReferenceID: "valid", Revision: 0}}}} {
		s.config.Policies = policy
		v := accessCtlGet(t, s, p, "")
		if v.PolicyState != "unavailable" || v.References == nil || len(v.References) != 0 {
			t.Fatal("unavailable directory exposed metadata")
		}
		raw, _ := json.Marshal(v)
		if strings.Contains(string(raw), "secret") {
			t.Fatal("private policy leaked")
		}
	}
}
func TestSubscriptionAccessServiceReferencesBoundedSortedAndDetached(t *testing.T) {
	s, p := accessCtlFixture(authz.RoleViewer)
	provider := &accessCtlPolicy{entries: []PolicyReference{{ReferenceID: "z", Revision: 2}, {ReferenceID: "a", Revision: 1}}}
	s.config.Policies = provider
	v := accessCtlGet(t, s, p, "")
	if v.PolicyState != "ready" || v.References[0].ReferenceID != "a" || provider.entries[0].ReferenceID != "z" {
		t.Fatal("directory not sorted or caller mutated")
	}
	v.References[0].ReferenceID = "changed"
	v.Actions[0] = "changed"
	again := accessCtlGet(t, s, p, "")
	if again.References[0].ReferenceID != "a" || again.Actions[0] != authz.ActionReadSubscription {
		t.Fatal("metadata aliases provider")
	}
	provider.entries = make([]PolicyReference, MaxPolicyReferences+1)
	if accessCtlGet(t, s, p, "").PolicyState != "unavailable" {
		t.Fatal("directory budget ignored")
	}
}
func TestSubscriptionAccessServiceAuthorizationPrecedesMetadata(t *testing.T) {
	s, p := accessCtlFixture(authz.RoleAdmin)
	provider := &accessCtlPolicy{entries: []PolicyReference{{ReferenceID: "a", Revision: 1}}}
	s.config.Policies = provider
	p.AllowedScopes = []authz.ResourceScope{{TenantID: "foreign"}}
	_, err := s.Access(context.Background(), p, "")
	accessCtlCode(t, err, CodeForbidden)
	if provider.calls != 0 {
		t.Fatal("denied request enumerated policies")
	}
	_, p = accessCtlFixture(authz.RoleAdmin)
	p.AllowedScopes = []authz.ResourceScope{Resource(s.config.Scope, "src_"+strings.Repeat("a", 32))}
	_, err = s.Access(context.Background(), p, "")
	accessCtlCode(t, err, CodeForbidden)
	if provider.calls != 0 {
		t.Fatal("source grant leaked collection metadata")
	}
}
func TestSubscriptionAccessServiceNoPrivateIOAndCanceledContexts(t *testing.T) {
	s, p := accessCtlFixture(authz.RoleViewer)
	provider := &accessCtlPolicy{entries: []PolicyReference{{ReferenceID: "a", Revision: 1}}}
	s.config.Policies = provider
	_ = accessCtlGet(t, s, p, "")
	if provider.calls != 1 {
		t.Fatal("CPU directory not consulted")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err := s.Access(ctx, p, "")
	accessCtlCode(t, err, CodeCanceled)
	if provider.calls != 1 {
		t.Fatal("canceled request read directory")
	}
	ctx, cancel = context.WithCancel(context.Background())
	provider.cancel = cancel
	_, err = s.Access(ctx, p, "")
	accessCtlCode(t, err, CodeCanceled)
	_, err = s.Access(nil, p, "")
	accessCtlCode(t, err, CodeCanceled)
	var absent *Service
	_, err = absent.Access(context.Background(), p, "")
	accessCtlCode(t, err, CodeUnavailable)
	_, err = (&Service{}).Access(context.Background(), p, "")
	accessCtlCode(t, err, CodeUnavailable)
}
