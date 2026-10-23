package subscriptionctl

import (
	"context"
	"sort"
	"time"

	"chengwang/internal/authz"
	"chengwang/internal/subscription"
)

const MaxPolicyReferences = subscription.MaxSources

// PolicyReference is an intentionally small, public policy-directory entry.
// It is not an approval, a policy digest, or permission to fetch a URL.
type PolicyReference struct {
	ReferenceID string `json:"referenceId"`
	Revision    uint64 `json:"revision"`
}

// PolicyReferenceReader is optional: existing manual-reference providers need
// not expose a directory. Implementations must use immutable CPU-only metadata.
type PolicyReferenceReader interface {
	References() ([]PolicyReference, error)
}

// AccessReader preserves the required Backend contract for existing adapters.
type AccessReader interface {
	Access(context.Context, authz.Principal, string) (AccessView, error)
}

type AccessResource struct {
	Type string `json:"type"`
	ID   string `json:"id"`
}

type AccessView struct {
	Scope         subscription.Scope `json:"scope"`
	Resource      AccessResource     `json:"resource"`
	WritesEnabled bool               `json:"writesEnabled"`
	Actions       []authz.Action     `json:"actions"`
	PolicyState   string             `json:"policyState"`
	References    []PolicyReference  `json:"references"`
}

func accessActions() [7]authz.Action {
	return [7]authz.Action{authz.ActionReadSubscription, authz.ActionManageSubscriptionSource,
		authz.ActionImportSubscription, authz.ActionDecideSubscription, authz.ActionApproveSubscriptionSource,
		authz.ActionFetchSubscription, authz.ActionRollbackSubscription}
}

// Access is advisory permission metadata, not source existence or inventory
// health. It never opens the Store, describes a private policy, or fetches it.
// Every mutation must still perform its normal authorization and write gates.
func (s *Service) Access(ctx context.Context, principal authz.Principal, sourceID string) (AccessView, error) {
	if err := s.authorize(ctx, principal, authz.ActionReadSubscription, sourceID); err != nil {
		return AccessView{}, err
	}
	scope := s.config.Scope
	if !ctlPart.MatchString(scope.TenantID) || !ctlPart.MatchString(scope.SiteID) || !ctlPart.MatchString(scope.Environment) ||
		scope.ObjectType != "subscription-store" || !ctlPart.MatchString(scope.ObjectID) || sourceID != "" && !ctlSource.MatchString(sourceID) {
		return AccessView{}, ctlError(CodeUnavailable, false)
	}
	resource := Resource(scope, sourceID)
	result := AccessView{Scope: subscription.Scope{TenantID: scope.TenantID, SiteID: scope.SiteID, Environment: scope.Environment},
		Resource: AccessResource{Type: resource.ObjectType, ID: resource.ObjectID}, WritesEnabled: s.config.WritesEnabled,
		Actions: []authz.Action{}, PolicyState: "not_configured", References: []PolicyReference{}}
	now := time.Now().UTC()
	for _, action := range accessActions() {
		if authz.Evaluate(authz.Request{Principal: principal, Action: action, Resource: resource}, now).Allowed {
			result.Actions = append(result.Actions, action)
		}
	}
	if !ctlNil(s.config.Policies) {
		result.PolicyState = "unavailable"
		reader, ok := s.config.Policies.(PolicyReferenceReader)
		if ok && !ctlNil(reader) {
			entries, err := reader.References()
			if err == nil && len(entries) > 0 && len(entries) <= MaxPolicyReferences {
				copyEntries := append([]PolicyReference(nil), entries...)
				sort.Slice(copyEntries, func(i, j int) bool { return copyEntries[i].ReferenceID < copyEntries[j].ReferenceID })
				valid := true
				for i, entry := range copyEntries {
					if !ctlPart.MatchString(entry.ReferenceID) || entry.Revision == 0 || i > 0 && copyEntries[i-1].ReferenceID == entry.ReferenceID {
						valid = false
						break
					}
				}
				if valid {
					result.PolicyState, result.References = "ready", copyEntries
				}
			}
		}
	}
	if ctlCanceled(ctx) {
		return AccessView{}, ctlError(CodeCanceled, false)
	}
	return result, nil
}

var _ AccessReader = (*Service)(nil)
