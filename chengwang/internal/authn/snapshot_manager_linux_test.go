//go:build linux

package authn

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/authz"
)

func snapshotFixture(t *testing.T) (*SnapshotManager, string, string, File, time.Time) {
	t.Helper()
	now := time.Date(2026, 10, 25, 1, 0, 0, 0, time.UTC)
	token, hash := testToken('s')
	config := File{Version: 1, Identities: []Identity{testIdentity("snapshot-token", hash, "snapshot-principal")}}
	path := writeStore(t, config)
	manager, err := OpenSnapshotManager(path, now)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close() })
	return manager, path, token, config, now
}

func replaceSnapshotFile(t *testing.T, path string, raw []byte) {
	t.Helper()
	temp, err := os.CreateTemp(filepath.Dir(path), ".replace-")
	if err != nil {
		t.Fatal(err)
	}
	name := temp.Name()
	t.Cleanup(func() { _ = os.Remove(name) })
	if err := temp.Chmod(0600); err != nil {
		t.Fatal(err)
	}
	if _, err := temp.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := temp.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(name, path); err != nil {
		t.Fatal(err)
	}
}

func snapshotAuthenticate(t *testing.T, manager *SnapshotManager, token string, now time.Time) SnapshotRef {
	t.Helper()
	_, ref, err := manager.AuthenticateAuthorization("Bearer "+token, now)
	if err != nil {
		t.Fatal(err)
	}
	return ref
}

func TestSnapshotManagerTrustedPrincipalRevalidatesRevocationWithoutToken(t *testing.T) {
	manager, path, _, config, now := snapshotFixture(t)
	principal, ref, err := manager.TrustedPrincipal("snapshot-principal", now)
	if err != nil || principal.ID != "snapshot-principal" || ref == (SnapshotRef{}) { t.Fatal("trusted source resolve failed") }
	config.Identities[0].Disabled = true
	raw, err := json.Marshal(config); if err != nil { t.Fatal(err) }
	replaceSnapshotFile(t, path, append(raw, '\n'))
	if _, err = manager.CurrentPrincipal(ref, principal.ID, now.Add(time.Second)); !errors.Is(err, ErrSnapshotStale) { t.Fatal("post-fetch style revocation did not invalidate source-issued reference") }
	if _, _, err = manager.TrustedPrincipal(principal.ID, now.Add(2*time.Second)); err == nil { t.Fatal("disabled identity resolved after replacement") }
}

func TestSnapshotManagerStableBytesKeepReferenceAndRereadEveryTime(t *testing.T) {
	manager, path, token, _, now := snapshotFixture(t)
	ref := snapshotAuthenticate(t, manager, token, now)
	reads := 0
	reader := manager.core.read
	manager.core.read = func(path string) (credentialSnapshot, error) { reads++; return reader(path) }
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	replaceSnapshotFile(t, path, raw)
	current := snapshotAuthenticate(t, manager, token, now.Add(time.Second))
	if current != ref {
		t.Fatal("stable identical replacement bytes changed snapshot reference")
	}
	if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now.Add(2*time.Second)); err != nil || reads != 2 {
		t.Fatal("each operation must actually reread the file")
	}
}

func TestSnapshotManagerChangedBytesInvalidateEvenSemanticallyEqualFile(t *testing.T) {
	manager, path, token, _, now := snapshotFixture(t)
	ref := snapshotAuthenticate(t, manager, token, now)
	raw, _ := os.ReadFile(path)
	replaceSnapshotFile(t, path, append(raw, '\n'))
	if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotStale) {
		t.Fatal("changed raw credential bytes retained approval epoch")
	}
	current := snapshotAuthenticate(t, manager, token, now)
	if current == ref {
		t.Fatal("changed credential sample reused old reference")
	}
	replaceSnapshotFile(t, path, raw)
	if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotStale) {
		t.Fatal("returning old raw bytes revived an old reference")
	}
}

func TestSnapshotManagerReloadedDisabledIdentityInvalidatesApproval(t *testing.T) {
	manager, path, token, config, now := snapshotFixture(t)
	ref := snapshotAuthenticate(t, manager, token, now)
	guardToken, guardHash := testToken('g')
	config.Identities[0].Disabled = true
	config.Identities = append(config.Identities, testIdentity("guard-token", guardHash, "guard-principal"))
	raw, _ := json.Marshal(config)
	replaceSnapshotFile(t, path, raw)
	if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotStale) {
		t.Fatal("old approval reference survived credential change")
	}
	_, returned, err := manager.AuthenticateAuthorization("Bearer "+token, now)
	assertCode(t, err, CodeIdentityDisabled)
	if returned != (SnapshotRef{}) {
		t.Fatal("denied authentication returned reference")
	}
	current := snapshotAuthenticate(t, manager, guardToken, now)
	_, err = manager.CurrentPrincipal(current, "snapshot-principal", now)
	assertCode(t, err, CodeIdentityDisabled)
}

func TestSnapshotManagerCurrentPrincipalChecksTimeAndDeepCopies(t *testing.T) {
	manager, path, token, config, now := snapshotFixture(t)
	expires := now.Add(time.Minute)
	config.Identities[0].ExpiresAt = &expires
	raw, _ := json.Marshal(config)
	replaceSnapshotFile(t, path, raw)
	principal, ref, err := manager.AuthenticateAuthorization("Bearer "+token, now)
	if err != nil {
		t.Fatal(err)
	}
	principal.Roles[0] = authz.RoleAdmin
	principal.AllowedScopes[0].TenantID = "other-tenant"
	current, err := manager.CurrentPrincipal(ref, "snapshot-principal", now)
	if err != nil || current.Roles[0] != authz.RoleViewer || current.AllowedScopes[0].TenantID != "tenant-1" {
		t.Fatal("authenticate result mutated manager snapshot")
	}
	current.Roles[0] = authz.RoleAdmin
	current.AllowedScopes[0].TenantID = "other-tenant"
	current, err = manager.CurrentPrincipal(ref, "snapshot-principal", now)
	if err != nil || current.Roles[0] != authz.RoleViewer || current.AllowedScopes[0].TenantID != "tenant-1" {
		t.Fatal("current-principal result mutated manager snapshot")
	}
	_, err = manager.CurrentPrincipal(ref, "snapshot-principal", expires)
	assertCode(t, err, CodeIdentityExpired)
	if _, err := manager.CurrentPrincipal(ref, "missing", expires); err == nil {
		t.Fatal("missing principal was accepted")
	}
}

func TestSnapshotManagerNotBeforeIdentityCannotBeQueriedEarly(t *testing.T) {
	manager, path, token, config, now := snapshotFixture(t)
	second, secondHash := testToken('u')
	notBefore := now.Add(time.Minute)
	identity := testIdentity("future-token", secondHash, "future-principal")
	identity.NotBefore = &notBefore
	config.Identities = append(config.Identities, identity)
	raw, _ := json.Marshal(config)
	replaceSnapshotFile(t, path, raw)
	ref := snapshotAuthenticate(t, manager, token, now)
	_, err := manager.CurrentPrincipal(ref, "future-principal", now)
	assertCode(t, err, CodeIdentityNotActive)
	_, _, err = manager.AuthenticateAuthorization("Bearer "+second, now)
	assertCode(t, err, CodeIdentityNotActive)
	if principal, err := manager.CurrentPrincipal(ref, "future-principal", notBefore); err != nil || principal.ID != "future-principal" {
		t.Fatal("current reference did not check actual activity at supplied time")
	}
}

func TestSnapshotManagerPermissionFailureAndRecoveryNeverRevivesReference(t *testing.T) {
	manager, path, token, _, now := snapshotFixture(t)
	ref := snapshotAuthenticate(t, manager, token, now)
	for _, name := range []string{path, filepath.Dir(path)} {
		mode := os.FileMode(0640)
		original := os.FileMode(0600)
		if name != path {
			mode, original = 0750, 0700
		}
		if err := os.Chmod(name, mode); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotUnavailable) {
			t.Fatal("unsafe credential mode retained current snapshot")
		}
		if err := os.Chmod(name, original); err != nil {
			t.Fatal(err)
		}
		if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotStale) {
			t.Fatal("restored permission revived old reference")
		}
		ref = snapshotAuthenticate(t, manager, token, now)
	}
}

func TestSnapshotManagerMissingAndMalformedFileDiscardSnapshot(t *testing.T) {
	manager, path, token, config, now := snapshotFixture(t)
	original, _ := os.ReadFile(path)
	duplicateIdentity, _ := json.Marshal(File{Version: 1, Identities: []Identity{config.Identities[0], config.Identities[0]}})
	for _, bad := range [][]byte{nil, []byte(`{"version":1,"version":1,"identities":[]}`), []byte(`{"version":1,"identities":[],"token":"private-value"}`), duplicateIdentity, {0xff}} {
		ref := snapshotAuthenticate(t, manager, token, now)
		if bad == nil {
			if err := os.Remove(path); err != nil {
				t.Fatal(err)
			}
		} else {
			replaceSnapshotFile(t, path, bad)
		}
		if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotUnavailable) {
			t.Fatal("missing/malformed sample reused an old store")
		}
		replaceSnapshotFile(t, path, original)
		if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotStale) {
			t.Fatal("old bytes restored an old approval epoch")
		}
	}
}

func TestSnapshotManagerClockRollbackAndInvalidTimeInvalidateReference(t *testing.T) {
	manager, _, token, _, now := snapshotFixture(t)
	for _, invalid := range []time.Time{now.Add(-time.Second), {}, time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)} {
		ref := snapshotAuthenticate(t, manager, token, now)
		if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", invalid); !errors.Is(err, ErrSnapshotClock) {
			t.Fatal("invalid or rolled-back trusted clock accepted")
		}
		if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotStale) {
			t.Fatal("clock recovery revived old approval epoch")
		}
	}
}

func TestSnapshotManagerRepeatedRandomCannotReviveInvalidatedEpoch(t *testing.T) {
	manager, path, token, _, now := snapshotFixture(t)
	ref := snapshotAuthenticate(t, manager, token, now)
	original, _ := os.ReadFile(path)
	replaceSnapshotFile(t, path, []byte("bad"))
	if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotUnavailable) {
		t.Fatal("bad sample accepted")
	}
	replaceSnapshotFile(t, path, original)
	// Deterministic repeated nonce models even a random collision. Generation
	// is never reset by invalidate and independently prevents resurrection.
	manager.core.random = bytes.NewReader(ref.core.epoch[:])
	current := snapshotAuthenticate(t, manager, token, now)
	if current.core.epoch != ref.core.epoch || current.core.generation <= ref.core.generation {
		t.Fatal("repeated nonce regression fixture did not exercise generation fence")
	}
	if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotStale) {
		t.Fatal("repeated random nonce revived old reference")
	}
	if _, err := manager.CurrentPrincipal(current, "snapshot-principal", now); err != nil {
		t.Fatal("new generation reference failed")
	}
}

func TestSnapshotManagerGenerationExhaustionAndEntropyFailureFailClosed(t *testing.T) {
	manager, path, token, _, now := snapshotFixture(t)
	ref := snapshotAuthenticate(t, manager, token, now)
	original, _ := os.ReadFile(path)
	manager.core.random = bytes.NewReader(nil)
	replaceSnapshotFile(t, path, append(bytes.Clone(original), '\n'))
	if _, _, err := manager.AuthenticateAuthorization("Bearer "+token, now); !errors.Is(err, ErrSnapshotUnavailable) || manager.core.store != nil {
		t.Fatal("entropy failure retained usable snapshot")
	}
	manager.core.random = bytes.NewReader(bytes.Repeat([]byte{37}, 32))
	replaceSnapshotFile(t, path, original)
	current := snapshotAuthenticate(t, manager, token, now)
	if current == ref {
		t.Fatal("entropy recovery reused old reference")
	}
	manager.core.generation = ^uint64(0)
	replaceSnapshotFile(t, path, append(bytes.Clone(original), '\n'))
	if _, _, err := manager.AuthenticateAuthorization("Bearer "+token, now); !errors.Is(err, ErrSnapshotUnavailable) || manager.core.store != nil {
		t.Fatal("generation overflow accepted or retained store")
	}
	replaceSnapshotFile(t, path, original)
	if _, err := manager.CurrentPrincipal(current, "snapshot-principal", now); !errors.Is(err, ErrSnapshotUnavailable) {
		t.Fatal("exhausted generation became reusable")
	}
}

func TestSnapshotReferencesAreManagerBoundAndClosedCopiesRemainClosed(t *testing.T) {
	manager, path, token, _, now := snapshotFixture(t)
	ref := snapshotAuthenticate(t, manager, token, now)
	other, err := OpenSnapshotManager(path, now)
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close()
	if _, err := other.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotStale) {
		t.Fatal("reference transferred to another manager")
	}
	if _, err := manager.CurrentPrincipal(SnapshotRef{}, "snapshot-principal", now); !errors.Is(err, ErrSnapshotStale) {
		t.Fatal("zero reference accepted")
	}
	copyValue := *manager
	if err := copyValue.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotClosed) {
		t.Fatal("copied manager close did not invalidate shared core")
	}
	if err := manager.Close(); err != nil {
		t.Fatal("close should be idempotent")
	}
}

func TestSnapshotManagerDuplicateHeadersCannotReturnReference(t *testing.T) {
	manager, _, token, _, now := snapshotFixture(t)
	reads := 0
	reader := manager.core.read
	manager.core.read = func(path string) (credentialSnapshot, error) { reads++; return reader(path) }
	for _, headers := range [][]string{nil, {"Bearer " + token, "Bearer " + token}, {"Basic " + token}} {
		if principal, ref, err := manager.AuthenticateAuthorizationValues(headers, now); err == nil || principal.ID != "" || ref != (SnapshotRef{}) {
			t.Fatal("denied authentication supplied principal or ref")
		}
	}
	if reads != 3 {
		t.Fatal("authentication denied before mandatory fresh read")
	}
}

func TestSnapshotManagerConcurrentReadersOnlyReceiveDetachedPrincipals(t *testing.T) {
	manager, _, token, _, now := snapshotFixture(t)
	ref := snapshotAuthenticate(t, manager, token, now)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			principal, current, err := manager.AuthenticateAuthorization("Bearer "+token, now)
			if err != nil || current != ref {
				t.Error("concurrent authentication failed")
				return
			}
			principal.Roles[0] = authz.RoleAdmin
			principal.AllowedScopes[0].TenantID = "mutated"
		}()
	}
	wg.Wait()
	principal, err := manager.CurrentPrincipal(ref, "snapshot-principal", now)
	if err != nil || principal.Roles[0] != authz.RoleViewer || principal.AllowedScopes[0].TenantID != "tenant-1" {
		t.Fatal("concurrent caller mutated shared identity data")
	}
}

func TestSnapshotManagerReadErrorsAreFixedAndDoNotExposeInputs(t *testing.T) {
	manager, path, token, config, now := snapshotFixture(t)
	ref := snapshotAuthenticate(t, manager, token, now)
	manager.core.read = func(string) (credentialSnapshot, error) {
		return credentialSnapshot{}, fmt.Errorf("raw secret %s hash %s path %s", token, config.Identities[0].TokenHash, path)
	}
	_, err := manager.CurrentPrincipal(ref, "snapshot-principal", now)
	if err != ErrSnapshotUnavailable || err.Error() != "credential snapshot unavailable" {
		t.Fatal("raw filesystem/parser error escaped")
	}
	if manager.core.store != nil || manager.core.epoch != [32]byte{} {
		t.Fatal("failed read kept usable identity epoch")
	}
}

func TestCredentialStableReadRejectsReplacementDuringRead(t *testing.T) {
	_, path, _, config, _ := snapshotFixture(t)
	config.Identities[0].Disabled = true
	raw, _ := json.Marshal(config)
	if _, err := readCredentialSnapshot(path, true, func() { replaceSnapshotFile(t, path, raw) }); err == nil {
		t.Fatal("replacement after reading old descriptor was accepted")
	}
}

func TestCredentialStableReadRejectsParentDirectoryReplacement(t *testing.T) {
	_, path, _, _, _ := snapshotFixture(t)
	raw, _ := os.ReadFile(path)
	dir := filepath.Dir(path)
	moved := dir + "-moved"
	t.Cleanup(func() { _ = os.RemoveAll(moved) })
	if _, err := readCredentialSnapshot(path, true, func() {
		if err := os.Rename(dir, moved); err != nil {
			t.Fatal(err)
		}
		if err := os.Mkdir(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, raw, 0600); err != nil {
			t.Fatal(err)
		}
	}); err == nil {
		t.Fatal("same-byte file under replacement parent accepted")
	}
}

func TestCredentialStableReadRejectsModeChangeAndHardlinks(t *testing.T) {
	manager, path, token, _, now := snapshotFixture(t)
	if _, err := readCredentialSnapshot(path, true, func() {
		if err := os.Chmod(path, 0640); err != nil {
			t.Fatal(err)
		}
	}); err == nil {
		t.Fatal("mode changed during read was accepted")
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	ref := snapshotAuthenticate(t, manager, token, now)
	link := path + "-hardlink"
	if err := os.Link(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotUnavailable) {
		t.Fatal("hardlinked credential file accepted")
	}
	if err := os.Remove(link); err != nil {
		t.Fatal(err)
	}
	if _, err := manager.CurrentPrincipal(ref, "snapshot-principal", now); !errors.Is(err, ErrSnapshotStale) {
		t.Fatal("removing hardlink revived invalidated reference")
	}
}

func TestCredentialStableReadRejectsSymlinksAndNonregularFiles(t *testing.T) {
	_, path, _, _, now := snapshotFixture(t)
	link := path + "-symlink"
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if manager, err := OpenSnapshotManager(link, now); manager != nil || !errors.Is(err, ErrSnapshotUnavailable) {
		t.Fatal("symlink credential accepted")
	}
	fifo := path + "-fifo"
	if err := syscall.Mkfifo(fifo, 0600); err != nil {
		t.Fatal(err)
	}
	if _, err := readCredentialSnapshot(fifo, true, nil); err == nil {
		t.Fatal("nonregular credential accepted")
	}
	opened, err := openCredentialFile(fifo, true)
	if err != nil {
		t.Fatal(err)
	}
	defer opened.Close()
	if info, err := opened.Stat(); err != nil || info.Mode().IsRegular() {
		t.Fatal("nonblocking FIFO regression fixture invalid")
	}
}

type snapshotStatInfo struct {
	os.FileInfo
	stat syscall.Stat_t
}

func (info snapshotStatInfo) Sys() any { return &info.stat }

func TestCredentialMetadataRejectsForeignOwnerAndCapturesChangeTime(t *testing.T) {
	_, path, _, _, _ := snapshotFixture(t)
	info, err := os.Lstat(path)
	if err != nil {
		t.Fatal(err)
	}
	stat := *info.Sys().(*syscall.Stat_t)
	foreign := stat
	foreign.Uid++
	if _, err := credentialMetadata(snapshotStatInfo{FileInfo: info, stat: foreign}, true, false); err == nil {
		t.Fatal("foreign file owner accepted")
	}
	meta, err := credentialMetadata(info, true, false)
	if err != nil {
		t.Fatal(err)
	}
	changed := stat
	changed.Ctim.Nsec++
	other, err := credentialMetadata(snapshotStatInfo{FileInfo: info, stat: changed}, true, false)
	if err != nil || credentialFileStable(info, info, meta, other) {
		t.Fatal("change time ignored by stable sample")
	}
}

func TestSnapshotManagerRejectsUntrustedStartupPathAndBoundsFile(t *testing.T) {
	_, path, _, _, now := snapshotFixture(t)
	for _, invalid := range []string{"", "relative.json", " " + path, filepath.Dir(path) + "/./identities.json"} {
		if manager, err := OpenSnapshotManager(invalid, now); manager != nil || !errors.Is(err, ErrSnapshotUnavailable) {
			t.Fatal("untrusted noncanonical startup path accepted")
		}
	}
	replaceSnapshotFile(t, path, bytes.Repeat([]byte(" "), maxFileBytes+1))
	if manager, err := OpenSnapshotManager(path, now); manager != nil || !errors.Is(err, ErrSnapshotUnavailable) {
		t.Fatal("oversized credential source accepted")
	}
}

func TestSnapshotManagerCurrentLookupDoesNotGrantRBAC(t *testing.T) {
	manager, _, token, _, now := snapshotFixture(t)
	ref := snapshotAuthenticate(t, manager, token, now)
	principal, err := manager.CurrentPrincipal(ref, "snapshot-principal", now)
	if err != nil {
		t.Fatal(err)
	}
	decision := authz.Evaluate(authz.Request{Principal: principal, Action: authz.ActionExecuteOperation, Risk: authz.RiskCritical,
		Resource: authz.ResourceScope{TenantID: "tenant-1", Environment: "isolated-lab"}, InitiatorID: "initiator", ApprovedByID: "approver"}, now)
	if decision.Allowed {
		t.Fatal("active principal query bypassed RBAC")
	}
}
