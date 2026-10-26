//go:build linux && chengwang_mihomo_service && chengwang_mihomo_recovery_native && chengwang_mihomo_recovery_continuous_fault && !chengwang_mihomo_faults && !chengwang_mihomo_completion_native

package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"chengwang/internal/authz"
)

const ContinuousRecoveryCredentialSchema = "chengwang.mihomo-continuous-recovery-bound-credentials/v2"
const continuousRecoveryCredentialBundleLabel = "authn.ContinuousRecoveryCredentialBundle(isolated_source_bound_not_authorization)"

// ContinuousRecoveryBoundCredential contains credential facts only. The
// closed Binding value selects a source-owned row; it never supplies a role,
// principal, tenant, site, object or environment.
type ContinuousRecoveryBoundCredential struct {
	TokenID   string     `json:"tokenId"`
	TokenHash string     `json:"tokenHash"`
	Binding   string     `json:"binding"`
	Disabled  bool       `json:"disabled,omitempty"`
	NotBefore *time.Time `json:"notBefore,omitempty"`
	ExpiresAt *time.Time `json:"expiresAt,omitempty"`
}

type ContinuousRecoveryBoundCredentialFile struct {
	Schema      string                              `json:"schema"`
	Credentials []ContinuousRecoveryBoundCredential `json:"credentials"`
}

type continuousRecoveryBinding struct {
	tokenID, selector, principalID string
	role                           authz.Role
}

func continuousRecoveryBindings() [5]continuousRecoveryBinding {
	return [5]continuousRecoveryBinding{
		{tokenID: "continuous-credential-01", selector: "binding-01", principalID: "continuous-principal-viewer", role: authz.RoleViewer},
		{tokenID: "continuous-credential-02", selector: "binding-02", principalID: "continuous-principal-operator", role: authz.RoleOperator},
		{tokenID: "continuous-credential-03", selector: "binding-03", principalID: "continuous-principal-approver", role: authz.RoleApprover},
		{tokenID: "continuous-credential-04", selector: "binding-04", principalID: "continuous-principal-auditor", role: authz.RoleAuditor},
		{tokenID: "continuous-credential-05", selector: "binding-05", principalID: "continuous-principal-admin", role: authz.RoleAdmin},
	}
}

func continuousRecoveryCredentialScope() authz.ResourceScope {
	return authz.ResourceScope{TenantID: "sub-tenant", SiteID: "sub-site", ObjectType: "mihomo-lab", ObjectID: "local", Environment: "isolated-lab"}
}

// NewContinuousRecoveryBoundCredential selects one exact source row without
// serializing its role or principal. This function exists only in the exact
// isolated build and does not write a file or mint bearer material.
func NewContinuousRecoveryBoundCredential(role authz.Role, tokenHash string) (ContinuousRecoveryBoundCredential, error) {
	for _, row := range continuousRecoveryBindings() {
		if row.role == role {
			return ContinuousRecoveryBoundCredential{TokenID: row.tokenID, TokenHash: tokenHash, Binding: row.selector}, nil
		}
	}
	return ContinuousRecoveryBoundCredential{}, errors.New("continuous recovery credential role rejected")
}

type ContinuousRecoveryCredentialBundle struct {
	core *continuousRecoveryCredentialBundleCore
}

type continuousRecoveryCredentialBundleCore struct {
	mu       sync.Mutex
	identity *continuousRecoveryCredentialBundleCore
	store    *Store
	manager  *SnapshotManager
	used     bool
}

func (ContinuousRecoveryCredentialBundle) String() string   { return continuousRecoveryCredentialBundleLabel }
func (ContinuousRecoveryCredentialBundle) GoString() string { return continuousRecoveryCredentialBundleLabel }
func (ContinuousRecoveryCredentialBundle) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"ISOLATED_SOURCE_BOUND_CREDENTIAL_BUNDLE_NOT_AUTHORIZATION"}`), nil
}
func (*ContinuousRecoveryCredentialBundle) UnmarshalJSON([]byte) error { return ErrSnapshotUnavailable }
func (ContinuousRecoveryCredentialBundle) Format(state fmt.State, _ rune) {
	_, _ = io.WriteString(state, continuousRecoveryCredentialBundleLabel)
}

// Scope returns a detached source constant. No credential-file field can
// supply or modify any member.
func (bundle *ContinuousRecoveryCredentialBundle) Scope() (authz.ResourceScope, error) {
	if bundle == nil || bundle.core == nil {
		return authz.ResourceScope{}, ErrSnapshotUnavailable
	}
	core := bundle.core
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.identity != core || core.used || core.store == nil || core.manager == nil {
		return authz.ResourceScope{}, ErrSnapshotUnavailable
	}
	return continuousRecoveryCredentialScope(), nil
}

// Consume transfers the sole manager close obligation to the caller and
// returns the exact Store seeded into that manager. Copied or replayed bundle
// wrappers cannot consume twice.
func (bundle *ContinuousRecoveryCredentialBundle) Consume() (*Store, *SnapshotManager, error) {
	if bundle == nil || bundle.core == nil {
		return nil, nil, ErrSnapshotUnavailable
	}
	core := bundle.core
	core.mu.Lock()
	defer core.mu.Unlock()
	if core.identity != core || core.used || core.store == nil || core.manager == nil || core.manager.core == nil || core.manager.core.store != core.store {
		return nil, nil, ErrSnapshotUnavailable
	}
	core.used = true
	return core.store, core.manager, nil
}

// Close rejects an unconsumed bundle and closes its sole manager. Once
// consumed, the runtime is the unique close owner and this method fails.
func (bundle *ContinuousRecoveryCredentialBundle) Close() error {
	if bundle == nil || bundle.core == nil {
		return ErrSnapshotUnavailable
	}
	core := bundle.core
	core.mu.Lock()
	if core.identity != core || core.used || core.manager == nil {
		core.mu.Unlock()
		return ErrSnapshotUnavailable
	}
	core.used = true
	manager := core.manager
	core.mu.Unlock()
	return manager.Close()
}

// OpenContinuousRecoveryCredentialBundle performs one strict stable read.
// The immutable API Store and the freshness manager initially share that exact
// parsed Store and raw-file digest. Later manager refreshes use only the same
// v2 decoder and retain the ordinary epoch/stale-reference behavior.
func OpenContinuousRecoveryCredentialBundle(path string, now time.Time) (*ContinuousRecoveryCredentialBundle, error) {
	if !snapshotPlatformSupported() || !snapshotTime(now) || path == "" || strings.TrimSpace(path) != path || !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return nil, ErrSnapshotUnavailable
	}
	initial, err := readCredentialSnapshotWithParser(path, true, nil, parseContinuousRecoveryCredentialPayload)
	if err != nil || initial.store == nil {
		return nil, ErrSnapshotUnavailable
	}
	pending := true
	reader := func(candidate string) (credentialSnapshot, error) {
		if pending {
			pending = false
			return initial, nil
		}
		return readCredentialSnapshotWithParser(candidate, true, nil, parseContinuousRecoveryCredentialPayload)
	}
	managerCore := &snapshotManagerCore{path: path, random: rand.Reader, read: reader}
	if _, err := io.ReadFull(managerCore.random, managerCore.manager[:]); err != nil || managerCore.manager == [32]byte{} {
		return nil, ErrSnapshotUnavailable
	}
	if err := managerCore.refresh(now); err != nil || pending || managerCore.store != initial.store || managerCore.digest != initial.digest {
		managerCore.invalidate()
		return nil, ErrSnapshotUnavailable
	}
	manager := &SnapshotManager{core: managerCore}
	core := &continuousRecoveryCredentialBundleCore{store: initial.store, manager: manager}
	core.identity = core
	return &ContinuousRecoveryCredentialBundle{core: core}, nil
}

func parseContinuousRecoveryCredentialPayload(payload []byte) (*Store, error) {
	if len(payload) < 1 || len(payload) > maxFileBytes || !utf8.Valid(payload) {
		return nil, errors.New("continuous recovery credential payload is invalid")
	}
	if err := rejectCredentialDuplicateKeysWithSet(payload, map[string]bool{
		"schema": true, "credentials": true, "tokenId": true, "tokenHash": true,
		"binding": true, "disabled": true, "notBefore": true, "expiresAt": true,
	}); err != nil {
		return nil, err
	}
	var shapes struct {
		Credentials []map[string]json.RawMessage `json:"credentials"`
	}
	shapeDecoder := json.NewDecoder(strings.NewReader(string(payload)))
	if err := shapeDecoder.Decode(&shapes); err != nil || ensureJSONEOF(shapeDecoder) != nil {
		return nil, errors.New("continuous recovery credential file rejected")
	}
	for _, shape := range shapes.Credentials {
		if raw, present := shape["disabled"]; present && string(raw) != "true" && string(raw) != "false" {
			return nil, errors.New("continuous recovery credential activity rejected")
		}
		for _, name := range []string{"notBefore", "expiresAt"} {
			raw, present := shape[name]
			if !present {
				continue
			}
			if len(raw) < 2 || raw[0] != '"' || raw[len(raw)-1] != '"' {
				return nil, errors.New("continuous recovery credential activity rejected")
			}
			var value time.Time
			if err := json.Unmarshal(raw, &value); err != nil {
				return nil, errors.New("continuous recovery credential activity rejected")
			}
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var file ContinuousRecoveryBoundCredentialFile
	if err := decoder.Decode(&file); err != nil {
		return nil, errors.New("continuous recovery credential file rejected")
	}
	bindings := continuousRecoveryBindings()
	if ensureJSONEOF(decoder) != nil || file.Schema != ContinuousRecoveryCredentialSchema || len(file.Credentials) != len(bindings) || len(shapes.Credentials) != len(file.Credentials) {
		return nil, errors.New("continuous recovery credential file rejected")
	}

	scope := continuousRecoveryCredentialScope()
	rows := make(map[string]continuousRecoveryBinding, len(bindings))
	for _, row := range bindings {
		rows[row.tokenID] = row
	}
	seen := make(map[string]bool, len(bindings))
	hashes := make(map[string]bool, len(bindings))
	store := &Store{identities: make([]storedIdentity, 0, len(bindings))}
	for _, credential := range file.Credentials {
		row, ok := rows[credential.TokenID]
		if !ok || seen[credential.TokenID] || credential.Binding != row.selector || hashes[credential.TokenHash] {
			return nil, errors.New("continuous recovery credential binding rejected")
		}
		identity := Identity{TokenID: credential.TokenID, TokenHash: credential.TokenHash,
			Principal: authz.Principal{ID: row.principalID, TenantID: scope.TenantID, Roles: []authz.Role{row.role}, AllowedScopes: []authz.ResourceScope{scope}},
			Disabled: credential.Disabled, NotBefore: credential.NotBefore, ExpiresAt: credential.ExpiresAt}
		if err := validateIdentity(identity); err != nil {
			return nil, errors.New("continuous recovery credential record rejected")
		}
		digestBytes, err := hex.DecodeString(identity.TokenHash)
		if err != nil || len(digestBytes) != sha256.Size {
			return nil, errors.New("continuous recovery credential record rejected")
		}
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		if identity.NotBefore != nil {
			value := identity.NotBefore.UTC()
			identity.NotBefore = &value
		}
		if identity.ExpiresAt != nil {
			value := identity.ExpiresAt.UTC()
			identity.ExpiresAt = &value
		}
		identity.Principal = clonePrincipal(identity.Principal)
		store.identities = append(store.identities, storedIdentity{record: identity, hash: digest})
		seen[credential.TokenID], hashes[credential.TokenHash] = true, true
	}
	if len(seen) != len(bindings) {
		return nil, errors.New("continuous recovery credential bindings incomplete")
	}
	return store, nil
}
