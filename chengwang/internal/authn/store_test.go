package authn

import (
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"chengwang/internal/authz"
)

func TestAuthenticateAuthorizationAndRestart(t *testing.T) {
	now := time.Date(2026, 10, 18, 7, 0, 0, 0, time.UTC)
	firstToken, firstHash := testToken('a')
	secondToken, secondHash := testToken('b')
	path := writeStore(t, File{Version: FileVersion, Identities: []Identity{
		testIdentity("token-1", firstHash, "operator-1"),
		testIdentity("token-2", secondHash, "auditor-1"),
	}})

	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	principal, err := store.AuthenticateAuthorization("Bearer "+secondToken, now)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != "auditor-1" || principal.TenantID != "tenant-1" {
		t.Fatalf("unexpected principal: %+v", principal)
	}
	principal.Roles[0] = authz.RoleAdmin

	// Reopening simulates process restart and must preserve the same identity.
	restarted, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	principal, err = restarted.AuthenticateAuthorization("bearer "+firstToken, now)
	if err != nil {
		t.Fatal(err)
	}
	if principal.ID != "operator-1" || principal.Roles[0] != authz.RoleViewer {
		t.Fatalf("unexpected principal after restart: %+v", principal)
	}
}

func TestAuthenticateAuthorizationLifecycle(t *testing.T) {
	now := time.Date(2026, 10, 18, 7, 0, 0, 0, time.UTC)
	cases := []struct {
		name string
		edit func(*Identity)
		code ErrorCode
	}{
		{"disabled", func(identity *Identity) { identity.Disabled = true }, CodeIdentityDisabled},
		{"not active", func(identity *Identity) { value := now.Add(time.Minute); identity.NotBefore = &value }, CodeIdentityNotActive},
		{"expired", func(identity *Identity) { value := now; identity.ExpiresAt = &value }, CodeIdentityExpired},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			token, hash := testToken('c')
			identity := testIdentity("token-life", hash, "principal-life")
			tc.edit(&identity)
			store := openTestStore(t, File{Version: FileVersion, Identities: []Identity{identity}})
			_, err := store.AuthenticateAuthorization("Bearer "+token, now)
			assertCode(t, err, tc.code)
		})
	}
}

func TestAuthorizationHeaderFailures(t *testing.T) {
	token, hash := testToken('d')
	store := openTestStore(t, File{Version: FileVersion, Identities: []Identity{testIdentity("token-header", hash, "principal-header")}})
	now := time.Now()
	cases := []struct {
		name, header string
		code         ErrorCode
	}{
		{"missing", "", CodeAuthorizationMissing},
		{"leading space", " Bearer " + token, CodeAuthorizationMalformed},
		{"trailing space", "Bearer " + token + " ", CodeAuthorizationMalformed},
		{"double space", "Bearer  " + token, CodeAuthorizationMalformed},
		{"tab", "Bearer\t" + token, CodeAuthorizationMalformed},
		{"multiple comma", "Bearer " + token + ", Bearer " + token, CodeAuthorizationMalformed},
		{"multiple newline", "Bearer " + token + "\nBearer " + token, CodeAuthorizationMalformed},
		{"wrong scheme", "Basic " + token, CodeSchemeUnsupported},
		{"too short", "Bearer YWJj", CodeAuthorizationMalformed},
		{"invalid base64", "Bearer " + strings.Repeat("!", 43), CodeAuthorizationMalformed},
		{"unknown", "Bearer " + base64Token('e'), CodeTokenInvalid},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := store.AuthenticateAuthorization(tc.header, now)
			assertCode(t, err, tc.code)
			if strings.Contains(err.Error(), token) || (tc.header != "" && strings.Contains(err.Error(), tc.header)) {
				t.Fatal("authentication error leaked authorization material")
			}
		})
	}
}

func TestAuthorizationHeaderValuesRejectDuplicates(t *testing.T) {
	token, hash := testToken('v')
	store := openTestStore(t, File{Version: FileVersion, Identities: []Identity{testIdentity("token-values", hash, "principal-values")}})
	if _, err := store.AuthenticateAuthorizationValues(nil, time.Now()); err == nil {
		t.Fatal("expected missing Authorization rejection")
	} else {
		assertCode(t, err, CodeAuthorizationMissing)
	}
	if _, err := store.AuthenticateAuthorizationValues([]string{"Bearer " + token, "Bearer " + token}, time.Now()); err == nil {
		t.Fatal("expected duplicate Authorization rejection")
	} else {
		assertCode(t, err, CodeAuthorizationMalformed)
	}
	if principal, err := store.AuthenticateAuthorizationValues([]string{"Bearer " + token}, time.Now()); err != nil || principal.ID != "principal-values" {
		t.Fatalf("single Authorization value should authenticate: principal=%+v err=%v", principal, err)
	}
}

func TestOpenRejectsMalformedAndDuplicateFiles(t *testing.T) {
	_, hash := testToken('f')
	base := testIdentity("token-1", hash, "principal-1")
	cases := []struct {
		name string
		body any
	}{
		{"unknown top field", map[string]any{"version": 1, "identities": []Identity{base}, "extra": true}},
		{"unknown nested field", json.RawMessage(`{"version":1,"identities":[{"tokenId":"one","tokenHash":"` + hash + `","principal":{"id":"p","tenantId":"tenant-1","roles":["viewer"],"allowedScopes":[{"tenantId":"tenant-1"}],"unknown":true}}]}`)},
		{"duplicate principal", File{Version: 1, Identities: []Identity{base, withToken(base, "token-2", testHash("other"))}}},
		{"duplicate token id", File{Version: 1, Identities: []Identity{base, withPrincipal(base, "principal-2")}}},
		{"duplicate hash", File{Version: 1, Identities: []Identity{base, withTokenAndPrincipal(base, "token-2", "principal-2")}}},
		{"uppercase hash", File{Version: 1, Identities: []Identity{withHash(base, strings.ToUpper(hash))}}},
		{"bad version", File{Version: 2, Identities: []Identity{base}}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var data []byte
			if raw, ok := tc.body.(json.RawMessage); ok {
				data = raw
			} else {
				data, _ = json.Marshal(tc.body)
			}
			path := writeRawStore(t, data)
			if _, err := Open(path); err == nil {
				t.Fatal("expected Open to reject credential file")
			}
		})
	}
}

func TestOpenRejectsPermissionsAndSymlink(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows FileMode does not expose ACL equivalence")
	}
	_, hash := testToken('g')
	config := File{Version: 1, Identities: []Identity{testIdentity("token-perm", hash, "principal-perm")}}
	data, _ := json.Marshal(config)

	t.Run("directory", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "identities.json")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "0700") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("file", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		path := filepath.Join(dir, "identities.json")
		if err := os.WriteFile(path, data, 0o644); err != nil {
			t.Fatal(err)
		}
		if _, err := Open(path); err == nil || !strings.Contains(err.Error(), "0600") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
	t.Run("symlink", func(t *testing.T) {
		dir := t.TempDir()
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(dir, "target.json")
		if err := os.WriteFile(target, data, 0o600); err != nil {
			t.Fatal(err)
		}
		link := filepath.Join(dir, "identities.json")
		if err := os.Symlink(target, link); err != nil {
			t.Skipf("symlink unavailable: %v", err)
		}
		if _, err := Open(link); err == nil || !strings.Contains(err.Error(), "symbolic") {
			t.Fatalf("unexpected error: %v", err)
		}
	})
}

func TestGenerateToken(t *testing.T) {
	if _, _, err := GenerateToken(31); err == nil {
		t.Fatal("expected minimum entropy rejection")
	}
	plaintext, hash, err := GenerateToken(32)
	if err != nil {
		t.Fatal(err)
	}
	if plaintext == "" || len(hash) != 64 || strings.Contains(plaintext, "=") {
		t.Fatalf("unexpected token material: token length=%d hash length=%d", len(plaintext), len(hash))
	}
	digest := sha256.Sum256([]byte(plaintext))
	if hash != hex.EncodeToString(digest[:]) {
		t.Fatal("generated token hash mismatch")
	}
	second, _, err := GenerateToken(32)
	if err != nil || second == plaintext {
		t.Fatal("tokens must be independently random")
	}
}

func openTestStore(t *testing.T, config File) *Store {
	t.Helper()
	store, err := Open(writeStore(t, config))
	if err != nil {
		t.Fatal(err)
	}
	return store
}

func writeStore(t *testing.T, config File) string {
	t.Helper()
	data, err := json.Marshal(config)
	if err != nil {
		t.Fatal(err)
	}
	return writeRawStore(t, data)
}

func writeRawStore(t *testing.T, data []byte) string {
	t.Helper()
	dir := t.TempDir()
	if runtime.GOOS != "windows" {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	path := filepath.Join(dir, "identities.json")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" {
		if err := os.Chmod(path, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return path
}

func testIdentity(tokenID, hash, principalID string) Identity {
	return Identity{
		TokenID: tokenID, TokenHash: hash,
		Principal: authz.Principal{
			ID: principalID, TenantID: "tenant-1", Roles: []authz.Role{authz.RoleViewer},
			AllowedScopes: []authz.ResourceScope{{TenantID: "tenant-1"}},
		},
	}
}

func testToken(fill byte) (string, string) {
	token := base64Token(fill)
	return token, testHash(token)
}

func base64Token(fill byte) string {
	return base64.RawURLEncoding.EncodeToString([]byte(strings.Repeat(string(fill), 32)))
}

func testHash(token string) string {
	digest := sha256.Sum256([]byte(token))
	return hex.EncodeToString(digest[:])
}

func withToken(identity Identity, tokenID, hash string) Identity {
	identity.TokenID, identity.TokenHash = tokenID, hash
	return identity
}
func withPrincipal(identity Identity, id string) Identity {
	identity.Principal.ID = id
	return identity
}
func withTokenAndPrincipal(identity Identity, tokenID, principalID string) Identity {
	identity.TokenID, identity.Principal.ID = tokenID, principalID
	return identity
}
func withHash(identity Identity, hash string) Identity { identity.TokenHash = hash; return identity }

func assertCode(t *testing.T, err error, want ErrorCode) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected authentication error %s", want)
	}
	got, ok := CodeOf(err)
	if !ok || got != want {
		t.Fatalf("got code %q (%v), want %q", got, err, want)
	}
	var authErr *AuthenticationError
	if !errors.As(err, &authErr) {
		t.Fatal("expected AuthenticationError")
	}
}
