package imagetrust

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestImageTrustD8HistoryProjectionHasNoRawAuthority(t *testing.T) {
	raw, err := json.Marshal(History{Boundary: HistoryBoundary, Authorization: "BLOCKED", Entries: []HistoryEntry{{OperationID: "op", ActorID: "actor", Kind: "verify", State: "RESERVED"}}})
	if err != nil {
		t.Fatal(err)
	}
	pageKeys := []string{"boundary", "authorization", "deviceActionsExecuted", "observedAtUnix", "sequence", "total", "offset", "limit", "entries"}
	var page map[string]json.RawMessage
	if json.Unmarshal(raw, &page) != nil || len(page) != len(pageKeys) {
		t.Fatal("history page wire fields drifted")
	}
	for _, key := range pageKeys {
		if _, ok := page[key]; !ok {
			t.Fatalf("missing history field %s", key)
		}
	}
	for _, excluded := range []string{"payload", "publicKey", "token", "scopeSHA256", "outcomeData", "bundle", "trustedRoot"} {
		if strings.Contains(string(raw), excluded) {
			t.Fatal("raw authority material added to history DTO")
		}
	}
	entryKeys := []string{"operationId", "actorId", "kind", "state", "outcome", "acknowledged", "policyId", "grantId", "generation", "catalogueSHA256", "preparedAuditHash", "resultAuditHash", "preparedAtUnix", "resultAtUnix"}
	entryRaw, err := json.Marshal(HistoryEntry{})
	if err != nil {
		t.Fatal(err)
	}
	var entry map[string]json.RawMessage
	if json.Unmarshal(entryRaw, &entry) != nil || len(entry) != len(entryKeys) {
		t.Fatal("history entry field drift")
	}
	for _, key := range entryKeys {
		if _, ok := entry[key]; !ok {
			t.Fatalf("missing history entry field %s", key)
		}
	}
}
