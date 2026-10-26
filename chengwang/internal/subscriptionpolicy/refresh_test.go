//go:build linux

package subscriptionpolicy

import (
	"bytes"
	"strings"
	"testing"
)

func TestRefreshBindingDoesNotChangeApprovedFetchMaterial(t *testing.T) {
	base := policyConfig(t)
	baseCatalog := policyParsed(t, base)
	baseMaterial := policyDescriptor(t, baseCatalog, policyReference)
	config := base
	policyEntry(config)["refresh"] = map[string]any{
		"sourceId": "src_" + strings.Repeat("a", 32), "approvalId": "cmd_" + strings.Repeat("b", 32),
		"approvalSourceRevision": uint64(3), "intervalSeconds": uint64(60), "approvalTtlSeconds": uint64(600),
		"maxStaleSeconds": uint64(300), "maxBackoffSeconds": uint64(600),
	}
	catalog := policyParsed(t, config)
	if !bytes.Equal(baseMaterial, policyDescriptor(t, catalog, policyReference)) {
		t.Fatal("scheduler binding changed approved network policy material")
	}
	bindings, err := catalog.RefreshBindings()
	if err != nil || len(bindings) != 1 || bindings[0].ReferenceID != policyReference || bindings[0].PolicyRevision != 1 || bindings[0].ApprovalSourceRevision != 3 {
		t.Fatal("safe refresh binding projection mismatch")
	}
}

func TestRefreshBindingRejectsUnboundedOrDuplicateSource(t *testing.T) {
	config := policyConfig(t)
	entry := policyEntry(config)
	entry["refresh"] = map[string]any{
		"sourceId": "src_" + strings.Repeat("a", 32), "approvalId": "cmd_" + strings.Repeat("b", 32),
		"approvalSourceRevision": uint64(1), "intervalSeconds": uint64(1), "approvalTtlSeconds": uint64(600),
		"maxStaleSeconds": uint64(300), "maxBackoffSeconds": uint64(600),
	}
	policyInvalid(t, policyBytes(t, config))

	config = policyConfig(t)
	entry = policyEntry(config)
	entry["refresh"] = map[string]any{
		"sourceId": "src_" + strings.Repeat("a", 32), "approvalId": "cmd_" + strings.Repeat("b", 32),
		"approvalSourceRevision": uint64(1), "intervalSeconds": uint64(60), "approvalTtlSeconds": uint64(600),
		"maxStaleSeconds": uint64(300), "maxBackoffSeconds": uint64(600),
	}
	duplicate := make(map[string]any, len(entry))
	for key, value := range entry {
		duplicate[key] = value
	}
	duplicate["referenceId"] = "enterprise-b"
	config["sources"] = append(config["sources"].([]any), duplicate)
	catalog := policyParsed(t, config)
	if bindings, err := catalog.RefreshBindings(); err == nil || bindings != nil {
		t.Fatal("duplicate refresh source accepted")
	}
}
