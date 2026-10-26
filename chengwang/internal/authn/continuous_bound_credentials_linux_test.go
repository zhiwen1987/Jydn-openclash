//go:build linux && chengwang_mihomo_service && chengwang_mihomo_recovery_native && chengwang_mihomo_recovery_continuous_fault && !chengwang_mihomo_faults && !chengwang_mihomo_completion_native

package authn

import (
	"bytes"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/authz"
)

var continuousRecoveryTestRoles = [...]authz.Role{
	authz.RoleViewer, authz.RoleOperator, authz.RoleApprover, authz.RoleAuditor, authz.RoleAdmin,
}

func continuousRecoveryTestToken(index int) string {
	return base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{byte(index + 1)}, 32))
}

func continuousRecoveryTestFile(t *testing.T, edit func(*ContinuousRecoveryBoundCredentialFile)) (string, []byte, map[authz.Role]string, time.Time) {
	t.Helper()
	file := ContinuousRecoveryBoundCredentialFile{Schema: ContinuousRecoveryCredentialSchema}
	tokens := make(map[authz.Role]string, len(continuousRecoveryTestRoles))
	for index, role := range continuousRecoveryTestRoles {
		token := continuousRecoveryTestToken(index)
		digest := sha256.Sum256([]byte(token))
		credential, err := NewContinuousRecoveryBoundCredential(role, hex.EncodeToString(digest[:]))
		if err != nil {
			t.Fatal(err)
		}
		file.Credentials = append(file.Credentials, credential)
		tokens[role] = token
	}
	if edit != nil {
		edit(&file)
	}
	raw, err := json.Marshal(file)
	if err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "credentials.json")
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(path, 0600); err != nil {
		t.Fatal(err)
	}
	dirInfo, dirErr := os.Stat(dir)
	fileInfo, fileErr := os.Stat(path)
	if dirErr != nil || fileErr != nil || dirInfo.Mode().Perm() != 0700 || fileInfo.Mode().Perm() != 0600 {
		t.Fatal("bound credential fixture permissions were not exact")
	}
	return path, raw, tokens, time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
}

func TestContinuousRecoveryBoundCredentialsV2MODEL(t *testing.T) {
	t.Run("one stable snapshot seeds API store and freshness manager", func(t *testing.T) {
		path, _, tokens, now := continuousRecoveryTestFile(t, nil)
		bundle, err := OpenContinuousRecoveryCredentialBundle(path, now)
		if err != nil || bundle == nil {
			t.Fatal("bound credential bundle did not open")
		}
		scope, err := bundle.Scope()
		if err != nil || scope != continuousRecoveryCredentialScope() {
			t.Fatal("source scope was not detached and exact")
		}
		copied := *bundle
		store, manager, err := bundle.Consume()
		if err != nil || store == nil || manager == nil || manager.core == nil || manager.core.store != store || manager.core.digest == [sha256.Size]byte{} {
			t.Fatal("API store and manager did not share the initial snapshot")
		}
		if _, _, err := copied.Consume(); !errors.Is(err, ErrSnapshotUnavailable) {
			t.Fatal("copied bundle consumed twice")
		}
		for _, row := range continuousRecoveryBindings() {
			principal, err := store.AuthenticateAuthorization("Bearer "+tokens[row.role], now)
			if err != nil || principal.ID != row.principalID || len(principal.Roles) != 1 || principal.Roles[0] != row.role || len(principal.AllowedScopes) != 1 || principal.AllowedScopes[0] != scope {
				t.Fatal("immutable API authentication did not use the exact source row")
			}
			fresh, ref, err := manager.AuthenticateAuthorization("Bearer "+tokens[row.role], now)
			if err != nil || fresh.ID != principal.ID || ref.core == nil {
				t.Fatal("fresh authentication did not use the seeded source row")
			}
			current, err := manager.CurrentPrincipal(ref, principal.ID, now)
			if err != nil || current.ID != principal.ID || current.Roles[0] != row.role {
				t.Fatal("fresh reference did not remain source bound")
			}
		}
		viewer, err := store.AuthenticateAuthorization("Bearer "+tokens[authz.RoleViewer], now)
		decision := authz.Evaluate(authz.Request{Principal: viewer, Action: authz.ActionReadResource, Resource: scope}, now)
		if err != nil || !decision.Allowed {
			t.Fatal("real bearer hash authentication did not reach ordinary RBAC")
		}
		if err := manager.Close(); err != nil {
			t.Fatal("manager close failed")
		}
	})

	t.Run("source binding rows are returned by value", func(t *testing.T) {
		mutated := continuousRecoveryBindings()
		mutated[0].tokenID = "foreign-token"
		mutated[0].selector = "foreign-selector"
		mutated[0].principalID = "foreign-principal"
		mutated[0].role = authz.RoleAdmin
		fresh := continuousRecoveryBindings()
		if fresh[0].tokenID != "continuous-credential-01" || fresh[0].selector != "binding-01" ||
			fresh[0].principalID != "continuous-principal-viewer" || fresh[0].role != authz.RoleViewer {
			t.Fatal("returned binding mutation changed the source table")
		}
	})

	t.Run("schema exact-five pair and field failures reject", func(t *testing.T) {
		path, raw, _, now := continuousRecoveryTestFile(t, nil)
		_ = path
		var valid ContinuousRecoveryBoundCredentialFile
		if json.Unmarshal(raw, &valid) != nil {
			t.Fatal("fixture decode failed")
		}
		cases := map[string][]byte{}
		legacy, _ := json.Marshal(File{Version: FileVersion})
		cases["legacy-v1"] = legacy
		unknown := valid
		unknown.Schema = "chengwang.mihomo-continuous-recovery-bound-credentials/v3"
		cases["unknown-schema"], _ = json.Marshal(unknown)
		missing := valid
		missing.Credentials = append([]ContinuousRecoveryBoundCredential(nil), valid.Credentials[:4]...)
		cases["missing"], _ = json.Marshal(missing)
		extra := valid
		extra.Credentials = append(append([]ContinuousRecoveryBoundCredential(nil), valid.Credentials...), valid.Credentials[0])
		cases["extra"], _ = json.Marshal(extra)
		duplicateHash := valid
		duplicateHash.Credentials = append([]ContinuousRecoveryBoundCredential(nil), valid.Credentials...)
		duplicateHash.Credentials[1].TokenHash = duplicateHash.Credentials[0].TokenHash
		cases["duplicate-hash"], _ = json.Marshal(duplicateHash)
		duplicateID := valid
		duplicateID.Credentials = append([]ContinuousRecoveryBoundCredential(nil), valid.Credentials...)
		duplicateID.Credentials[1].TokenID = duplicateID.Credentials[0].TokenID
		duplicateID.Credentials[1].Binding = duplicateID.Credentials[0].Binding
		cases["duplicate-token-id"], _ = json.Marshal(duplicateID)
		swapped := valid
		swapped.Credentials = append([]ContinuousRecoveryBoundCredential(nil), valid.Credentials...)
		swapped.Credentials[0].Binding, swapped.Credentials[4].Binding = swapped.Credentials[4].Binding, swapped.Credentials[0].Binding
		cases["swapped-selector"], _ = json.Marshal(swapped)
		cases["unknown-field"] = bytes.Replace(raw, []byte(`"binding":"binding-01"`), []byte(`"binding":"binding-01","principal":{"roles":["admin"]}`), 1)
		cases["duplicate-key"] = bytes.Replace(raw, []byte(`"schema":`), []byte(`"schema":"duplicate","schema":`), 1)
		cases["disabled-null"] = bytes.Replace(raw, []byte(`"binding":"binding-01"`), []byte(`"binding":"binding-01","disabled":null`), 1)
		cases["disabled-string"] = bytes.Replace(raw, []byte(`"binding":"binding-01"`), []byte(`"binding":"binding-01","disabled":"false"`), 1)
		cases["not-before-null"] = bytes.Replace(raw, []byte(`"binding":"binding-01"`), []byte(`"binding":"binding-01","notBefore":null`), 1)
		cases["not-before-bool"] = bytes.Replace(raw, []byte(`"binding":"binding-01"`), []byte(`"binding":"binding-01","notBefore":false`), 1)
		cases["expires-at-null"] = bytes.Replace(raw, []byte(`"binding":"binding-01"`), []byte(`"binding":"binding-01","expiresAt":null`), 1)
		cases["expires-at-number"] = bytes.Replace(raw, []byte(`"binding":"binding-01"`), []byte(`"binding":"binding-01","expiresAt":0`), 1)
		for name, candidate := range cases {
			t.Run(name, func(t *testing.T) {
				if _, err := parseContinuousRecoveryCredentialPayload(candidate); err == nil {
					t.Fatal("invalid bound credential file accepted")
				}
			})
		}
		bindings := continuousRecoveryBindings()
		for index := range valid.Credentials {
			for wrong := range bindings {
				if wrong == index {
					continue
				}
				candidate := valid
				candidate.Credentials = append([]ContinuousRecoveryBoundCredential(nil), valid.Credentials...)
				candidate.Credentials[index].Binding = bindings[wrong].selector
				raw, marshalErr := json.Marshal(candidate)
				if marshalErr != nil {
					t.Fatal("wrong-pair fixture encode failed")
				}
				if _, err := parseContinuousRecoveryCredentialPayload(raw); err == nil {
					t.Fatal("wrong tokenID-selector pair accepted")
				}
			}
		}
		if bundle, err := OpenContinuousRecoveryCredentialBundle(path, now); err != nil || bundle == nil {
			t.Fatal("valid control rejected")
		} else if err := bundle.Close(); err != nil {
			t.Fatal("unconsumed bundle did not close")
		}
	})

	t.Run("trusted-file hash reassignment remains subject to the fixed row role", func(t *testing.T) {
		path, _, tokens, now := continuousRecoveryTestFile(t, func(file *ContinuousRecoveryBoundCredentialFile) {
			file.Credentials[0].TokenHash, file.Credentials[4].TokenHash = file.Credentials[4].TokenHash, file.Credentials[0].TokenHash
		})
		bundle, err := OpenContinuousRecoveryCredentialBundle(path, now)
		if err != nil {
			t.Fatal("hash-swap fixture did not open")
		}
		store, manager, err := bundle.Consume()
		if err != nil {
			t.Fatal("hash-swap fixture did not consume")
		}
		principal, err := store.AuthenticateAuthorization("Bearer "+tokens[authz.RoleAdmin], now)
		if err != nil || len(principal.Roles) != 1 || principal.Roles[0] != authz.RoleViewer {
			t.Fatal("hash swap fixture did not preserve row-bound authorization")
		}
		decision := authz.Evaluate(authz.Request{Principal: principal, Action: authz.ActionCreateOperation,
			Resource: continuousRecoveryCredentialScope(), Risk: authz.RiskHigh}, now)
		if decision.Allowed {
			t.Fatal("swapped admin token satisfied the fixed admin request mapping")
		}
		_ = manager.Close()
	})

	t.Run("activity windows and duplicate hashes fail closed", func(t *testing.T) {
		now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
		cases := []struct {
			name string
			edit func(*ContinuousRecoveryBoundCredential)
			code ErrorCode
		}{
			{name: "disabled", edit: func(v *ContinuousRecoveryBoundCredential) { v.Disabled = true }, code: CodeIdentityDisabled},
			{name: "future", edit: func(v *ContinuousRecoveryBoundCredential) { at := now.Add(time.Minute); v.NotBefore = &at }, code: CodeIdentityNotActive},
			{name: "expired", edit: func(v *ContinuousRecoveryBoundCredential) { at := now; v.ExpiresAt = &at }, code: CodeIdentityExpired},
		}
		for _, tc := range cases {
			t.Run(tc.name, func(t *testing.T) {
				path, _, tokens, _ := continuousRecoveryTestFile(t, func(file *ContinuousRecoveryBoundCredentialFile) { tc.edit(&file.Credentials[0]) })
				bundle, err := OpenContinuousRecoveryCredentialBundle(path, now)
				if err != nil {
					t.Fatal("activity fixture did not open")
				}
				store, manager, err := bundle.Consume()
				if err != nil {
					t.Fatal("activity fixture did not consume")
				}
				_, authErr := store.AuthenticateAuthorization("Bearer "+tokens[authz.RoleViewer], now)
				if code, ok := CodeOf(authErr); !ok || code != tc.code {
					t.Fatal("immutable activity gate mismatch")
				}
				_, _, authErr = manager.AuthenticateAuthorization("Bearer "+tokens[authz.RoleViewer], now)
				if code, ok := CodeOf(authErr); !ok || code != tc.code {
					t.Fatal("fresh activity gate mismatch")
				}
				_ = manager.Close()
			})
		}
	})

	t.Run("atomic replacement invalidates and reverted bytes do not revive refs", func(t *testing.T) {
		path, original, tokens, now := continuousRecoveryTestFile(t, nil)
		bundle, err := OpenContinuousRecoveryCredentialBundle(path, now)
		if err != nil {
			t.Fatal("replacement fixture did not open")
		}
		_, manager, err := bundle.Consume()
		if err != nil {
			t.Fatal("replacement fixture did not consume")
		}
		principal, ref, err := manager.AuthenticateAuthorization("Bearer "+tokens[authz.RoleViewer], now)
		if err != nil {
			t.Fatal("initial reference unavailable")
		}
		var replacement ContinuousRecoveryBoundCredentialFile
		if json.Unmarshal(original, &replacement) != nil {
			t.Fatal("replacement fixture decode failed")
		}
		newToken := base64.RawURLEncoding.EncodeToString(bytes.Repeat([]byte{99}, 32))
		newDigest := sha256.Sum256([]byte(newToken))
		replacement.Credentials[0].TokenHash = hex.EncodeToString(newDigest[:])
		replacementRaw, _ := json.Marshal(replacement)
		replaceSnapshotFile(t, path, replacementRaw)
		if _, err := manager.CurrentPrincipal(ref, principal.ID, now); !errors.Is(err, ErrSnapshotStale) {
			t.Fatal("atomic replacement retained the old reference")
		}
		_, replacementRef, err := manager.AuthenticateAuthorization("Bearer "+newToken, now)
		if err != nil || replacementRef.core == nil || replacementRef.core == ref.core {
			t.Fatal("replacement did not create a fresh epoch")
		}
		replaceSnapshotFile(t, path, original)
		if _, err := manager.CurrentPrincipal(ref, principal.ID, now); !errors.Is(err, ErrSnapshotStale) {
			t.Fatal("restored old bytes revived the first reference")
		}
		if _, err := manager.CurrentPrincipal(replacementRef, principal.ID, now); !errors.Is(err, ErrSnapshotStale) {
			t.Fatal("restored old bytes revived the replacement reference")
		}
		_ = manager.Close()
	})

	t.Run("strict filesystem custody is shared by the v2 parser", func(t *testing.T) {
		path, raw, _, now := continuousRecoveryTestFile(t, nil)
		dir := filepath.Dir(path)
		if err := os.Chmod(dir, 0755); err != nil {
			t.Fatal(err)
		}
		if bundle, err := OpenContinuousRecoveryCredentialBundle(path, now); bundle != nil || !errors.Is(err, ErrSnapshotUnavailable) {
			t.Fatal("non-private bound credential directory accepted")
		}
		if err := os.Chmod(dir, 0700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(path, 0644); err != nil {
			t.Fatal(err)
		}
		if bundle, err := OpenContinuousRecoveryCredentialBundle(path, now); bundle != nil || !errors.Is(err, ErrSnapshotUnavailable) {
			t.Fatal("non-private bound credential file accepted")
		}
		if err := os.Chmod(path, 0600); err != nil {
			t.Fatal(err)
		}
		link := path + "-link"
		if err := os.Symlink(path, link); err != nil {
			t.Fatal(err)
		}
		if bundle, err := OpenContinuousRecoveryCredentialBundle(link, now); bundle != nil || !errors.Is(err, ErrSnapshotUnavailable) {
			t.Fatal("symlink bound credential accepted")
		}
		hardlink := path + "-hardlink"
		if err := os.Link(path, hardlink); err != nil {
			t.Fatal(err)
		}
		if bundle, err := OpenContinuousRecoveryCredentialBundle(path, now); bundle != nil || !errors.Is(err, ErrSnapshotUnavailable) {
			t.Fatal("hardlinked bound credential accepted")
		}
		if err := os.Remove(hardlink); err != nil {
			t.Fatal(err)
		}
		fifo := path + "-fifo"
		if err := syscall.Mkfifo(fifo, 0600); err != nil {
			t.Fatal(err)
		}
		if bundle, err := OpenContinuousRecoveryCredentialBundle(fifo, now); bundle != nil || !errors.Is(err, ErrSnapshotUnavailable) {
			t.Fatal("FIFO bound credential accepted")
		}
		moved := dir + "-moved"
		t.Cleanup(func() { _ = os.RemoveAll(moved) })
		if _, err := readCredentialSnapshotWithParser(path, true, func() {
			if err := os.Rename(dir, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(dir, 0700); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, raw, 0600); err != nil {
				t.Fatal(err)
			}
		}, parseContinuousRecoveryCredentialPayload); err == nil {
			t.Fatal("replacement parent accepted for v2")
		}
	})

	t.Run("errors remain static and do not expose credential material", func(t *testing.T) {
		path, _, tokens, now := continuousRecoveryTestFile(t, nil)
		bundle, err := OpenContinuousRecoveryCredentialBundle(path, now)
		if err != nil {
			t.Fatal("error fixture did not open")
		}
		_, manager, err := bundle.Consume()
		if err != nil {
			t.Fatal("error fixture did not consume")
		}
		secret := tokens[authz.RoleViewer]
		principal, ref, err := manager.AuthenticateAuthorization("Bearer "+secret, now)
		if err != nil {
			t.Fatal("error fixture initial reference unavailable")
		}
		reader := manager.core.read
		manager.core.read = func(string) (credentialSnapshot, error) { return credentialSnapshot{}, errors.New("private " + secret) }
		_, _, err = manager.AuthenticateAuthorization("Bearer "+secret, now)
		if !errors.Is(err, ErrSnapshotUnavailable) || strings.Contains(err.Error(), secret) {
			t.Fatal("private reader error escaped")
		}
		manager.core.read = reader
		if _, err := manager.CurrentPrincipal(ref, principal.ID, now); !errors.Is(err, ErrSnapshotStale) {
			t.Fatal("restored v2 reader revived a reference invalidated by read failure")
		}
	})
}
