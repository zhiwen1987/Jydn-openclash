package subscription

import (
	"bytes"
	"encoding/json"
	"fmt"
	"strings"
	"testing"
)

func TestSubscriptionCoreLimitsAreClosed(t *testing.T) {
	if MaxInputBytes != 1<<20 || MaxNodes != 1024 || MaxSources != 32 || MaxCandidates != 64 || MaxStoreBytes != 16<<20 || MaxScalarBytes != 4096 || MaxDepth != 16 || MaxSyntaxNodes != 32768 || MaxAuditEntries != 4096 {
		t.Fatal("reviewed subscription budgets changed")
	}
}

func TestSubscriptionCoreScopesRejectAmbiguousValues(t *testing.T) {
	base := Scope{TenantID: "tenant-a", SiteID: "site-a", Environment: "lab"}
	if !validScope(base) {
		t.Fatal("valid scope rejected")
	}
	for _, value := range []string{"", " ", "tenant\x00other", "../tenant", "tenant/other", "tenant@host", strings.Repeat("a", 65)} {
		for index := 0; index < 3; index++ {
			changed := base
			switch index {
			case 0:
				changed.TenantID = value
			case 1:
				changed.SiteID = value
			case 2:
				changed.Environment = value
			}
			if validScope(changed) {
				t.Fatal("ambiguous scope admitted")
			}
		}
	}
	if scopeKey(base) == scopeKey(Scope{TenantID: "tenant-b", SiteID: "site-a", Environment: "lab"}) {
		t.Fatal("scope identity collision")
	}
}

func TestSubscriptionCoreSourceIDsAreOpaque(t *testing.T) {
	if !validSource("src_" + strings.Repeat("a", 32)) {
		t.Fatal("opaque ID rejected")
	}
	for _, value := range []string{"", "airport-name", "https://provider.invalid/token", "src_" + strings.Repeat("a", 31), "src_" + strings.Repeat("A", 32), "src_" + strings.Repeat("a", 33)} {
		if validSource(value) {
			t.Fatal("noncanonical source ID admitted")
		}
	}
}

func TestSubscriptionCoreIdempotencyBounds(t *testing.T) {
	for _, size := range []int{16, 64, 128} {
		if !validIdempotency(strings.Repeat("a", size)) {
			t.Fatal("bounded idempotency key rejected")
		}
	}
	for _, value := range []string{"", strings.Repeat("a", 15), strings.Repeat("a", 129), strings.Repeat("a", 16) + " ", "aaaaaaaaaaaaaaaa/secret", "aaaaaaaaaaaaaaa\x00a"} {
		if validIdempotency(value) {
			t.Fatal("ambiguous idempotency key admitted")
		}
	}
	if !validActor("operator-1") || validActor("operator/secret") {
		t.Fatal("actor validation changed")
	}
}

func TestSubscriptionCoreKeyedIdentityIsolation(t *testing.T) {
	key := bytes.Repeat([]byte{1}, 32)
	digest := keyedDigest(key, []byte("scope-a"), []byte("source-a"), []byte("private-credential"))
	if len(digest) != 64 || digest != keyedDigest(key, []byte("scope-a"), []byte("source-a"), []byte("private-credential")) {
		t.Fatal("identity is not stable")
	}
	for _, other := range []string{
		keyedDigest(bytes.Repeat([]byte{2}, 32), []byte("scope-a"), []byte("source-a"), []byte("private-credential")),
		keyedDigest(key, []byte("scope-b"), []byte("source-a"), []byte("private-credential")),
		keyedDigest(key, []byte("scope-a"), []byte("source-b"), []byte("private-credential")),
		keyedDigest(key, []byte("scope-a"), []byte("source-a"), []byte("rotated-credential")),
	} {
		if other == digest {
			t.Fatal("identity crossed private boundary")
		}
	}
	if keyedDigest(key, []byte("a"), []byte("bc")) == keyedDigest(key, []byte("ab"), []byte("c")) {
		t.Fatal("field framing collision")
	}
}

func TestSubscriptionCoreJSONDoesNotExposePrivateIngress(t *testing.T) {
	secret := "private-sentinel-do-not-export"
	values := []any{
		ParseInput{Content: []byte(secret), IdentityKey: []byte(secret)},
		ImportRequest{Content: []byte(secret)},
		ParsedNode{PrivateName: secret, Config: json.RawMessage(`{"password":"` + secret + `"}`)},
		Parsed{Nodes: []ParsedNode{{PrivateName: secret, Config: json.RawMessage(`{"password":"` + secret + `"}`)}}},
	}
	for _, value := range values {
		raw, err := json.Marshal(value)
		if err != nil || bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte("cHJpdmF0ZS1zZW50aW5lbC1kby1ub3QtZXhwb3J0")) {
			t.Fatal("private adapter content exported")
		}
		if strings.Contains(fmt.Sprintf("%v %+v %#v", value, value, value), secret) {
			t.Fatal("private adapter content formatted")
		}
	}
}

func TestSubscriptionCoreNodeViewIsDetachedUnknown(t *testing.T) {
	node := ParsedNode{ID: "node_" + strings.Repeat("a", 64), Protocol: "trojan", PrivateName: "secret-provider-label", Config: json.RawMessage(`{"password":"secret"}`), CredentialConfigured: true}
	view := nodeView(node)
	raw, err := json.Marshal(view)
	if err != nil || strings.Contains(string(raw), "secret") || view.State != "unknown" || view.Label != "节点-aaaaaaaa" || !view.CredentialConfigured || view.Protocol != "trojan" {
		t.Fatal("node view exposed private data or invented health")
	}
	node.Config[0] = '['
	if view.State != "unknown" {
		t.Fatal("node view aliased private state")
	}
}

func TestSubscriptionCoreFailureRedaction(t *testing.T) {
	for _, code := range []Code{CodeInputInvalid, CodeInputLimit, CodeFormatUnsupported, CodeProtocolUnsupported, CodeEmpty, CodeConflict, CodeScopeDenied, CodeNotFound, CodeStoreUnsafe, CodeStoreLocked, CodeStoreClosed, CodeStoreLimit, CodeCommitUncertain, CodeFetchPolicy, CodeFetchUnavailable, CodeFetchHTTP, CodeFetchRateLimited} {
		err := fail(code)
		if err.Error() != string(code) || !strings.HasPrefix(err.Error(), "subscription_") {
			t.Fatal("failure retained unexpected information")
		}
	}
}
