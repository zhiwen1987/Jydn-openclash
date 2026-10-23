package authz

import "regexp"

var subscriptionScopePart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
var subscriptionSourceID = regexp.MustCompile(`^src_[a-f0-9]{32}$`)

func subscriptionAction(action Action) bool {
	switch action {
	case ActionReadSubscription, ActionManageSubscriptionSource, ActionImportSubscription,
		ActionDecideSubscription, ActionApproveSubscriptionSource, ActionFetchSubscription, ActionRollbackSubscription:
		return true
	default:
		return false
	}
}

func subscriptionResource(action Action, resource ResourceScope) bool {
	if !subscriptionScopePart.MatchString(resource.TenantID) || !subscriptionScopePart.MatchString(resource.SiteID) || !subscriptionScopePart.MatchString(resource.Environment) {
		return false
	}
	if action == ActionManageSubscriptionSource {
		return resource.ObjectType == "subscription-store" && subscriptionScopePart.MatchString(resource.ObjectID)
	}
	if action == ActionReadSubscription && resource.ObjectType == "subscription-store" {
		return subscriptionScopePart.MatchString(resource.ObjectID)
	}
	return resource.ObjectType == "subscription-source" && subscriptionSourceID.MatchString(resource.ObjectID)
}
