package api

import (
	"net/http"
	"time"

	"chengwang/internal/authz"
	"chengwang/internal/subscriptionctl"
)

func subscriptionAccessActions() [7]authz.Action {
	return [7]authz.Action{authz.ActionReadSubscription, authz.ActionManageSubscriptionSource,
		authz.ActionImportSubscription, authz.ActionDecideSubscription, authz.ActionApproveSubscriptionSource,
		authz.ActionFetchSubscription, authz.ActionRollbackSubscription}
}

// This second validation boundary does not trust an optional backend's view
// to confer permissions. It independently evaluates the actual route resource.
func subscriptionAccessValid(view subscriptionctl.AccessView, principal authz.Principal, scope authz.ResourceScope, sourceID string) bool {
	resource := subscriptionctl.Resource(scope, sourceID)
	if view.Scope.TenantID != scope.TenantID || view.Scope.SiteID != scope.SiteID || view.Scope.Environment != scope.Environment ||
		view.Resource.Type != resource.ObjectType || view.Resource.ID != resource.ObjectID || view.Actions == nil || view.References == nil {
		return false
	}
	expected := []authz.Action{}
	now := time.Now().UTC()
	for _, action := range subscriptionAccessActions() {
		if authz.Evaluate(authz.Request{Principal: principal, Action: action, Resource: resource}, now).Allowed {
			expected = append(expected, action)
		}
	}
	if len(view.Actions) != len(expected) {
		return false
	}
	for i, action := range expected {
		if view.Actions[i] != action {
			return false
		}
	}
	switch view.PolicyState {
	case "ready":
		if len(view.References) == 0 || len(view.References) > subscriptionctl.MaxPolicyReferences {
			return false
		}
	case "not_configured", "unavailable":
		if len(view.References) != 0 {
			return false
		}
	default:
		return false
	}
	for i, entry := range view.References {
		if !subscriptionPart.MatchString(entry.ReferenceID) || entry.Revision == 0 || i > 0 && view.References[i-1].ReferenceID >= entry.ReferenceID {
			return false
		}
	}
	return true
}

func (s *server) subscriptionAccess(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.subscriptionPreflight(w, r, authz.ActionReadSubscription, false)
	if !ok {
		return
	}
	if !subscriptionRequest(w, r, http.MethodGet, false) {
		return
	}
	reader, ok := s.options.Subscriptions.(subscriptionctl.AccessReader)
	if !ok || nilSubscriptionInterface(reader) {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return
	}
	sourceID := r.PathValue("sourceId")
	view, err := reader.Access(r.Context(), principal, sourceID)
	if err != nil {
		writeSubscriptionBackendError(w, err, false)
		return
	}
	if r.Context().Err() != nil || !subscriptionAccessValid(view, principal, s.subscriptionScope, sourceID) {
		writeSubscriptionError(w, http.StatusServiceUnavailable, subscriptionctl.CodeUnavailable, false)
		return
	}
	view.WritesEnabled = view.WritesEnabled && s.options.SubscriptionWritesEnabled
	writeSubscription(w, http.StatusOK, view, "", false)
}
