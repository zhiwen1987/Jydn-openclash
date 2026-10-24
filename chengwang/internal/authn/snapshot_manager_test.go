package authn

import (
	"bytes"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
	"testing"
	"time"
)

func TestSnapshotReferenceFormattingAndJSONAreMetadataOnly(t *testing.T) {
	ref := SnapshotRef{core: &snapshotRefCore{manager: [32]byte{11}, epoch: [32]byte{22}, generation: 7}}
	copyValue := ref
	for _, value := range []any{ref, &ref, copyValue, &copyValue} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q", "%f"} {
			if got := fmt.Sprintf(format, value); got != snapshotRefLabel {
				t.Fatal("reference debug representation is not the fixed safe label")
			}
		}
		for _, format := range []string{"%p", "%#p", "%T", "%w"} {
			got := fmt.Sprintf(format, value)
			for _, forbidden := range []string{"epoch", "generation", "owner", fmt.Sprint(ref.core.manager), fmt.Sprint(ref.core.epoch), hex.EncodeToString(ref.core.manager[:]), hex.EncodeToString(ref.core.epoch[:]), base64.StdEncoding.EncodeToString(ref.core.epoch[:])} {
				if strings.Contains(got, forbidden) {
					t.Fatal("special format verb expanded reference internals")
				}
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `{"scope":"MEMORY_AUTHN_SNAPSHOT_REFERENCE_NOT_AUTHORIZATION"}` {
			t.Fatal("reference JSON exposed internal state")
		}
	}
	var nilRef *SnapshotRef
	if fmt.Sprintf("%#v", nilRef) != "<nil>" {
		t.Fatal("nil reference formatting unsafe")
	}
	for _, format := range []string{"%d", "%x", "%q", "%s"} {
		if fmt.Sprintf(format, nilRef) != "<nil>" {
			t.Fatal("typed-nil reference ordinary format is not safe")
		}
	}
	if raw, err := json.Marshal(nilRef); err != nil || string(raw) != "null" {
		t.Fatal("nil reference JSON unsafe")
	}
}

func TestSnapshotReferenceJSONCannotRestoreAuthority(t *testing.T) {
	for _, raw := range []string{`{}`, `null`, `{"manager":"x","epoch":"y","generation":1}`} {
		ref := SnapshotRef{core: &snapshotRefCore{manager: [32]byte{1}, epoch: [32]byte{2}, generation: 9}}
		if err := json.Unmarshal([]byte(raw), &ref); !errors.Is(err, ErrSnapshotStale) || ref != (SnapshotRef{}) {
			t.Fatal("JSON could preserve or create a reference")
		}
	}
	var nilRef *SnapshotRef
	if !errors.Is(nilRef.UnmarshalJSON(nil), ErrSnapshotStale) {
		t.Fatal("nil JSON receiver must reject")
	}
}

func TestSnapshotManagerFormattingAndJSONDoNotExposeCore(t *testing.T) {
	manager := SnapshotManager{core: &snapshotManagerCore{path: "private-credential-path", manager: [32]byte{77}, epoch: [32]byte{88}, generation: 123}}
	copyValue := manager
	for _, value := range []any{manager, &manager, copyValue, &copyValue} {
		for _, format := range []string{"%v", "%+v", "%#v", "%s", "%d", "%x", "%X", "%q", "%f"} {
			if got := fmt.Sprintf(format, value); got != snapshotManagerLabel {
				t.Fatal("manager representation did not remain fixed metadata")
			}
		}
		for _, format := range []string{"%p", "%#p", "%T", "%w"} {
			got := fmt.Sprintf(format, value)
			for _, forbidden := range []string{"private-credential-path", "epoch", "generation", fmt.Sprint(manager.core.manager), fmt.Sprint(manager.core.epoch), hex.EncodeToString(manager.core.manager[:]), hex.EncodeToString(manager.core.epoch[:]), base64.StdEncoding.EncodeToString(manager.core.epoch[:])} {
				if strings.Contains(got, forbidden) {
					t.Fatal("special format verb expanded manager internals")
				}
			}
		}
		raw, err := json.Marshal(value)
		if err != nil || string(raw) != `{"scope":"MEMORY_AUTHN_FRESHNESS_NOT_AUTHORIZATION"}` {
			t.Fatal("manager JSON exposed core state")
		}
	}
	var managerNil *SnapshotManager
	if fmt.Sprintf("%#v", managerNil) != "<nil>" {
		t.Fatal("nil manager formatting unsafe")
	}
	for _, format := range []string{"%d", "%x", "%q", "%s"} {
		if fmt.Sprintf(format, managerNil) != "<nil>" {
			t.Fatal("typed-nil manager ordinary format is not safe")
		}
	}
	if raw, err := json.Marshal(managerNil); err != nil || string(raw) != "null" {
		t.Fatal("nil manager JSON unsafe")
	}
}

func TestSnapshotManagerNilAndZeroFailClosed(t *testing.T) {
	for _, manager := range []*SnapshotManager{nil, {}} {
		if _, ref, err := manager.AuthenticateAuthorization("Bearer anything", time.Now()); !errors.Is(err, ErrSnapshotUnavailable) || ref != (SnapshotRef{}) {
			t.Fatal("nil/zero manager authenticated")
		}
		if _, err := manager.CurrentPrincipal(SnapshotRef{}, "actor", time.Now()); !errors.Is(err, ErrSnapshotUnavailable) {
			t.Fatal("nil/zero manager queried an identity")
		}
		if !errors.Is(manager.Close(), ErrSnapshotUnavailable) {
			t.Fatal("nil/zero manager unexpectedly closed a live core")
		}
	}
}

func TestSnapshotManagerUnsupportedPlatformHasNoFallback(t *testing.T) {
	if !snapshotPlatformSupported() {
		if manager, err := OpenSnapshotManager("not-even-a-path", time.Time{}); manager != nil || !errors.Is(err, ErrSnapshotUnsupported) {
			t.Fatal("unsupported platform did not fail before file access")
		}
		return
	}
	if manager, err := OpenSnapshotManager("not-even-a-path", time.Time{}); manager != nil || !errors.Is(err, ErrSnapshotClock) {
		t.Fatal("invalid trusted time was accepted")
	}
}

func TestSharedCredentialParserRejectsDuplicateKeysAtEveryDepth(t *testing.T) {
	_, hash := testToken('j')
	valid, err := json.Marshal(File{Version: 1, Identities: []Identity{testIdentity("id", hash, "principal")}})
	if err != nil {
		t.Fatal(err)
	}
	cases := [][]byte{
		[]byte(`{"version":1,"version":1,"identities":[]}`),
		[]byte(`{"version":1,"ver\u0073ion":1,"identities":[]}`),
		[]byte(`{"version":1,"Version":1,"identities":[]}`),
		[]byte(`{"Version":1,"identities":[]}`),
		[]byte(`{"verSion":1,"identities":[]}`),
		[]byte(`{"ver\u017fion":1,"identities":[]}`),
		bytes.Replace(valid, []byte(`"roles"`), []byte(`"role\u017f"`), 1),
		bytes.Replace(valid, []byte(`"principal"`), []byte(`"Principal"`), 1),
		bytes.Replace(valid, []byte(`"tokenHash"`), []byte(`"TokenHash"`), 1),
		bytes.Replace(valid, []byte(`"tokenId":"id"`), []byte(`"tokenId":"id","tokenId":"id"`), 1),
		bytes.Replace(valid, []byte(`"id":"principal"`), []byte(`"id":"principal","id":"principal"`), 1),
		bytes.Replace(valid, []byte(`"tenantId":"tenant-1"`), []byte(`"tenantId":"tenant-1","tenantId":"tenant-1"`), 1),
	}
	for _, raw := range cases {
		if _, err := parseCredentialPayload(raw); err == nil {
			t.Fatal("ambiguous duplicate credential JSON accepted")
		}
	}
	if _, err := parseCredentialPayload(valid); err != nil {
		t.Fatal("unambiguous original credential schema rejected")
	}
}

func TestSharedCredentialParserRetainsIdentityAndUnknownFieldValidation(t *testing.T) {
	_, hash := testToken('k')
	identity := testIdentity("one", hash, "principal")
	for _, config := range []File{
		{Version: 1, Identities: []Identity{identity, withPrincipal(identity, "another")}},
		{Version: 1, Identities: []Identity{identity, withToken(identity, "another", testHash("another-token"))}},
		{Version: 1, Identities: []Identity{identity, withTokenAndPrincipal(identity, "another", "another")}},
	} {
		raw, err := json.Marshal(config)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := parseCredentialPayload(raw); err == nil {
			t.Fatal("duplicate token/principal identity accepted by shared parser")
		}
	}
	for _, raw := range []string{`{"version":1,"identities":[],"extra":true}`, `{"version":1,"identities":[]} {}`, `{"version":2,"identities":[]}`} {
		if _, err := parseCredentialPayload([]byte(raw)); err == nil {
			t.Fatal("invalid schema accepted")
		}
	}
}

func TestSharedCredentialParserBoundsBytesUTF8AndDepth(t *testing.T) {
	for _, raw := range [][]byte{nil, bytes.Repeat([]byte(" "), maxFileBytes+1), {0xff}, []byte(strings.Repeat("[", 26)+"0"+strings.Repeat("]", 26))} {
		if _, err := parseCredentialPayload(raw); err == nil {
			t.Fatal("invalid or unbounded credential bytes accepted")
		}
	}
}

func TestLegacyImmutableOpenDoesNotBecomeRefreshingStore(t *testing.T) {
	token, hash := testToken('m')
	config := File{Version: 1, Identities: []Identity{testIdentity("legacy", hash, "legacy-principal")}}
	path := writeStore(t, config)
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	config.Identities[0].Disabled = true
	raw, _ := json.Marshal(config)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if principal, err := store.AuthenticateAuthorization("Bearer "+token, time.Now()); err != nil || principal.ID != "legacy-principal" {
		t.Fatal("legacy immutable API behavior changed")
	}
	current, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = current.AuthenticateAuthorization("Bearer "+token, time.Now())
	assertCode(t, err, CodeIdentityDisabled)
}
