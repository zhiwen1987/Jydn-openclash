//go:build linux && chengwang_mihomo_service && chengwang_mihomo_recovery_native && chengwang_mihomo_recovery_continuous_fault && !chengwang_mihomo_faults && !chengwang_mihomo_completion_native

package serverruntime

import (
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/mihomodeploy"
)

func continuousRecoveryBoundCredentialMODELFile(t *testing.T, schema string) map[authz.Role]string {
	t.Helper()
	root := filepath.Dir(MihomoLabIdentityFile)
	if err := os.RemoveAll(root); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(root, 0700); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(root) })
	file := authn.ContinuousRecoveryBoundCredentialFile{Schema: schema}
	tokens := make(map[authz.Role]string, 5)
	roles := []authz.Role{authz.RoleViewer, authz.RoleOperator, authz.RoleApprover, authz.RoleAuditor, authz.RoleAdmin}
	for index, role := range roles {
		token := base64.RawURLEncoding.EncodeToString(make([]byte, 32+index))
		digest := sha256.Sum256([]byte(token))
		credential, err := authn.NewContinuousRecoveryBoundCredential(role, hex.EncodeToString(digest[:]))
		if err != nil {
			t.Fatal(err)
		}
		file.Credentials = append(file.Credentials, credential)
		tokens[role] = token
	}
	raw, err := json.Marshal(file)
	if err != nil || os.WriteFile(MihomoLabIdentityFile, raw, 0600) != nil {
		t.Fatal("bound credential MODEL file")
	}
	return tokens
}

func continuousRecoveryBoundCredentialMODELConfig() Config {
	return Config{MihomoLabEnabled: true, IdentitiesFile: MihomoLabIdentityFile,
		TenantID: "sub-tenant", SiteID: "sub-site", ManagementObjectID: "local", Mode: mihomodeploy.LabEnvironment}
}

func TestContinuousRecoveryBoundCredentialsSourceArmMODEL(t *testing.T) {
	now := time.Date(2026, 10, 26, 0, 0, 0, 0, time.UTC)
	tokens := continuousRecoveryBoundCredentialMODELFile(t, authn.ContinuousRecoveryCredentialSchema)
	c := continuousRecoveryBoundCredentialMODELConfig()

	t.Run("unarmed exact build retains legacy selection", func(t *testing.T) {
		issuer := &labContinuousRecoveryHarnessIssuer{}
		store, manager, selected, err := claimLabContinuousRecoveryCredentialsFrom(issuer, c, now)
		if err != nil || selected || store != nil || manager != nil {
			t.Fatal("unarmed exact build selected bound credentials")
		}
	})

	t.Run("one source arm claims one exact bundle", func(t *testing.T) {
		issuer := &labContinuousRecoveryHarnessIssuer{armed: true, result: make(chan labContinuousRecoveryHarnessResult, 1)}
		store, manager, selected, err := claimLabContinuousRecoveryCredentialsFrom(issuer, c, now)
		if err != nil || !selected || store == nil || manager == nil || issuer.credentialStore != store || issuer.credentialManager != manager {
			t.Fatal("source arm did not claim the exact bundle")
		}
		principal, err := store.AuthenticateAuthorization("Bearer "+tokens[authz.RoleViewer], now)
		if err != nil || len(principal.Roles) != 1 || principal.Roles[0] != authz.RoleViewer || len(principal.AllowedScopes) != 1 || principal.AllowedScopes[0] != (authz.ResourceScope{TenantID: c.TenantID, SiteID: c.SiteID, ObjectType: mihomodeploy.LabObjectType, ObjectID: c.ManagementObjectID, Environment: mihomodeploy.LabEnvironment}) {
			t.Fatal("claimed API store was not source bound")
		}
		if _, _, selected, err := claimLabContinuousRecoveryCredentialsFrom(issuer, c, now); !selected || !errors.Is(err, errLabContinuousRecoveryHarness) {
			t.Fatal("claimed issuer was reusable")
		}
		if err := manager.Close(); err != nil {
			t.Fatal("claimed manager did not close")
		}
	})

	t.Run("foreign scope path and schema fail without fallback", func(t *testing.T) {
		foreign := c
		foreign.TenantID = "foreign-tenant"
		foreignMode := c
		foreignMode.Mode = "shadow"
		disabled := c
		disabled.MihomoLabEnabled = false
		for name, candidate := range map[string]Config{
			"disabled":      disabled,
			"foreign-scope": foreign,
			"foreign-mode":  foreignMode,
			"foreign-path": func() Config {
				value := c
				value.IdentitiesFile = filepath.Join(filepath.Dir(MihomoLabIdentityFile), "other.json")
				return value
			}(),
		} {
			t.Run(name, func(t *testing.T) {
				issuer := &labContinuousRecoveryHarnessIssuer{armed: true, result: make(chan labContinuousRecoveryHarnessResult, 1)}
				store, manager, selected, err := claimLabContinuousRecoveryCredentialsFrom(issuer, candidate, now)
				if !selected || err == nil || store != nil || manager != nil {
					t.Fatal("foreign armed credential input did not fail closed")
				}
			})
		}
		continuousRecoveryBoundCredentialMODELFile(t, "chengwang.mihomo-continuous-recovery-bound-credentials/v3")
		issuer := &labContinuousRecoveryHarnessIssuer{armed: true, result: make(chan labContinuousRecoveryHarnessResult, 1)}
		if store, manager, selected, err := claimLabContinuousRecoveryCredentialsFrom(issuer, c, now); !selected || err == nil || store != nil || manager != nil {
			t.Fatal("unknown schema fell back to legacy identity parsing")
		}
	})

	t.Run("RunWith closes claimed manager on pre-transfer TLS failure and cannot rearm", func(t *testing.T) {
		tokens = continuousRecoveryBoundCredentialMODELFile(t, authn.ContinuousRecoveryCredentialSchema)
		if _, err := armLabContinuousRecoveryHarness(); err != nil {
			t.Fatal("first process arm failed")
		}
		failed := c
		failed.Addr = "127.0.0.1:0"
		failed.DataDir = t.TempDir()
		failed.TLSCertFile = filepath.Join(t.TempDir(), "certificate.pem")
		listenerCalled := false
		err := RunWith(Options{Context: context.Background(), Config: &failed, ShutdownTimeout: time.Second,
			Listen: func(_, _ string) (net.Listener, error) {
				listenerCalled = true
				t.Fatal("listener was invoked before the TLS failure")
				return nil, errors.New("listener must not be invoked")
			}})
		if err == nil || !strings.Contains(err.Error(), "initialize TLS") {
			t.Fatal("pre-transfer TLS failure was accepted")
		}
		if listenerCalled {
			t.Fatal("pre-transfer TLS failure reached the listener")
		}
		manager := processLabContinuousRecoveryHarness.credentialManager
		if manager == nil {
			t.Fatal("RunWith did not retain the claimed manager for ownership verification")
		}
		if _, _, err := manager.AuthenticateAuthorization("Bearer "+tokens[authz.RoleViewer], now); !errors.Is(err, authn.ErrSnapshotClosed) {
			t.Fatal("pre-transfer failure did not close the claimed manager")
		}
		if _, err := armLabContinuousRecoveryHarness(); !errors.Is(err, errLabContinuousRecoveryHarness) {
			t.Fatal("process source arm rearmed")
		}
	})
}
