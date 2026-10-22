package trustcatalog

// Summary is public metadata for an already authenticated catalogue. It is not
// a capability and cannot be passed back to Replay, Advance, or Resolve. Public
// keys, signed payload bytes and signature envelopes are deliberately absent.
type Summary struct {
	StoreID              string            `json:"storeID"`
	Generation           uint64            `json:"generation"`
	SHA256               string            `json:"sha256"`
	NotBeforeUnix        int64             `json:"notBeforeUnix"`
	NotAfterUnix         int64             `json:"notAfterUnix"`
	RootKeyCount         int               `json:"rootKeyCount"`
	RootThreshold        int               `json:"rootThreshold"`
	ApproverCount        int               `json:"approverCount"`
	Grants               []Grant           `json:"grants"`
	PolicyFloors         map[string]uint64 `json:"policyFloors"`
	RevokedKeyCount      int               `json:"revokedKeyCount"`
	RevokedApprovalCount int               `json:"revokedApprovalCount"`
	RevokedManifestCount int               `json:"revokedManifestCount"`
}

func (c Catalogue) Summary() Summary {
	if !c.verified {
		return Summary{}
	}
	floors := make(map[string]uint64, len(c.document.PolicyFloors))
	for k, v := range c.document.PolicyFloors {
		floors[k] = v
	}
	grants := append([]Grant{}, c.document.Grants...)
	return Summary{StoreID: c.document.StoreID, Generation: c.document.Generation, SHA256: c.digest, NotBeforeUnix: c.document.NotBeforeUnix, NotAfterUnix: c.document.NotAfterUnix, RootKeyCount: len(c.document.RootKeys), RootThreshold: c.document.Threshold, ApproverCount: len(c.document.Approvers), Grants: grants, PolicyFloors: floors, RevokedKeyCount: len(c.document.RevokedKeys), RevokedApprovalCount: len(c.document.RevokedApprovals), RevokedManifestCount: len(c.document.RevokedManifests)}
}
