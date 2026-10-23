package subscriptionpolicy

import (
	"sort"

	"chengwang/internal/subscriptionctl"
)

// References reads only the immutable in-memory directory. No descriptor,
// URL, resolver, trust root, credential version or digest crosses this view.
func (c *Catalog) References() ([]subscriptionctl.PolicyReference, error) {
	if c == nil || c.core == nil || len(c.core.sources) == 0 || len(c.core.sources) > subscriptionctl.MaxPolicyReferences {
		return nil, ErrUnavailable
	}
	entries := make([]subscriptionctl.PolicyReference, 0, len(c.core.sources))
	seen := make(map[string]bool, len(c.core.sources))
	for key, value := range c.core.sources {
		id := value.config.ReferenceID
		if key != id || !partPattern.MatchString(id) || value.config.Revision == 0 || seen[id] {
			return nil, ErrUnavailable
		}
		seen[id] = true
		entries = append(entries, subscriptionctl.PolicyReference{ReferenceID: id, Revision: value.config.Revision})
	}
	sort.Slice(entries, func(i, j int) bool { return entries[i].ReferenceID < entries[j].ReferenceID })
	return entries, nil
}

var _ subscriptionctl.PolicyReferenceReader = (*Catalog)(nil)
