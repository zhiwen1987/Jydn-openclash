// Package authn authenticates high-entropy, static bearer credentials from a
// strictly validated local file.
//
// The credential file contains SHA-256 token hashes only. It is intentionally
// not a password database, JWT issuer, token rotation service, MFA system, or
// SSO integration. Callers are responsible for securely delivering the
// one-time plaintext returned by GenerateToken and for replacing the file
// atomically when identities change.
package authn

import (
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"time"
	"unicode"
	"unicode/utf8"

	"chengwang/internal/authz"
)

const (
	// FileVersion is the only credential-file schema accepted by this package.
	FileVersion   = 1
	minTokenBytes = 32
	maxTokenBytes = 384
	maxFileBytes  = 1 << 20
	maxIdentities = 10_000
)

var safeIdentifier = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:@/-]*$`)

// ErrorCode is a stable machine-readable authentication result. Errors never
// include a bearer token, its digest, or the supplied Authorization header.
type ErrorCode string

const (
	CodeAuthorizationMissing   ErrorCode = "authorization_missing"
	CodeAuthorizationMalformed ErrorCode = "authorization_malformed"
	CodeSchemeUnsupported      ErrorCode = "authorization_scheme_unsupported"
	CodeTokenInvalid           ErrorCode = "token_invalid"
	CodeIdentityDisabled       ErrorCode = "identity_disabled"
	CodeIdentityNotActive      ErrorCode = "identity_not_active"
	CodeIdentityExpired        ErrorCode = "identity_expired"
)

// AuthenticationError represents a denied credential without retaining any
// secret input. Code is safe to persist in the evidence log.
type AuthenticationError struct {
	Code ErrorCode
}

func (e *AuthenticationError) Error() string {
	return "authentication denied: " + string(e.Code)
}

// CodeOf extracts a stable authentication error code.
func CodeOf(err error) (ErrorCode, bool) {
	var authErr *AuthenticationError
	if errors.As(err, &authErr) {
		return authErr.Code, true
	}
	return "", false
}

// File is the on-disk credential schema. Unknown JSON fields are rejected at
// every nesting level by Open.
type File struct {
	Version    int        `json:"version"`
	Identities []Identity `json:"identities"`
}

// Identity binds one opaque token identifier and digest to an authorization
// principal. TokenHash must be a lowercase SHA-256 hexadecimal digest.
type Identity struct {
	TokenID   string          `json:"tokenId"`
	TokenHash string          `json:"tokenHash"`
	Principal authz.Principal `json:"principal"`
	Disabled  bool            `json:"disabled,omitempty"`
	NotBefore *time.Time      `json:"notBefore,omitempty"`
	ExpiresAt *time.Time      `json:"expiresAt,omitempty"`
}

type storedIdentity struct {
	record Identity
	hash   [sha256.Size]byte
}

// Store is an immutable in-memory snapshot. Reopen the file after an atomic
// credential-file replacement; Open never mutates the credential file.
type Store struct {
	identities []storedIdentity
}

// Open validates and loads an existing credential file. On POSIX systems the
// containing directory must be exactly 0700 and the regular file exactly
// 0600. Symbolic links in any existing path component are rejected.
func Open(path string) (*Store, error) {
	snapshot, err := readCredentialSnapshot(path, false, nil)
	if err != nil {
		return nil, err
	}
	return snapshot.store, nil
}

type credentialOSState struct {
	uid, gid, links     uint64
	ctimeSec, ctimeNsec int64
}

type credentialPathState struct {
	path string
	info os.FileInfo
	os   credentialOSState
}

type credentialSnapshot struct {
	store  *Store
	digest [sha256.Size]byte
}

type credentialPayloadParser func([]byte) (*Store, error)

// The optional hook is private and only supports deterministic filesystem-race
// tests. Product callers never supply callbacks. The digest stays in memory.
func readCredentialSnapshot(path string, strict bool, afterRead func()) (credentialSnapshot, error) {
	return readCredentialSnapshotWithParser(path, strict, afterRead, parseCredentialPayload)
}

func readCredentialSnapshotWithParser(path string, strict bool, afterRead func(), parser credentialPayloadParser) (credentialSnapshot, error) {
	if parser == nil {
		return credentialSnapshot{}, errors.New("credential parser is required")
	}
	if strings.TrimSpace(path) == "" {
		return credentialSnapshot{}, errors.New("credential file path is required")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return credentialSnapshot{}, fmt.Errorf("resolve credential file path: %w", err)
	}
	chain, err := credentialPathSnapshot(absPath, strict)
	if err != nil {
		return credentialSnapshot{}, err
	}

	dir := filepath.Dir(absPath)
	dirInfo, err := os.Lstat(dir)
	if err != nil {
		return credentialSnapshot{}, fmt.Errorf("inspect credential directory: %w", err)
	}
	if !dirInfo.IsDir() {
		return credentialSnapshot{}, errors.New("credential directory is not a directory")
	}
	if err := requirePermissions("credential directory", dirInfo, 0o700); err != nil {
		return credentialSnapshot{}, err
	}

	info, err := os.Lstat(absPath)
	if err != nil {
		return credentialSnapshot{}, fmt.Errorf("inspect credential file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return credentialSnapshot{}, errors.New("credential file is not a regular file")
	}
	if err := requirePermissions("credential file", info, 0o600); err != nil {
		return credentialSnapshot{}, err
	}
	if info.Size() < 1 || info.Size() > maxFileBytes {
		return credentialSnapshot{}, errors.New("credential file size is invalid")
	}
	beforeOS, err := credentialMetadata(info, strict, false)
	if err != nil {
		return credentialSnapshot{}, err
	}

	file, err := openCredentialFile(absPath, strict)
	if err != nil {
		return credentialSnapshot{}, fmt.Errorf("open credential file: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return credentialSnapshot{}, fmt.Errorf("inspect opened credential file: %w", err)
	}
	openedOS, err := credentialMetadata(openedInfo, strict, false)
	if err != nil || !credentialFileStable(info, openedInfo, beforeOS, openedOS) {
		return credentialSnapshot{}, errors.New("credential file changed while opening")
	}
	if err := requirePermissions("credential file", openedInfo, 0o600); err != nil {
		return credentialSnapshot{}, err
	}

	payload, err := io.ReadAll(io.LimitReader(file, maxFileBytes+1))
	if err != nil {
		return credentialSnapshot{}, fmt.Errorf("read credential file: %w", err)
	}
	if len(payload) > maxFileBytes {
		return credentialSnapshot{}, fmt.Errorf("credential file exceeds %d bytes", maxFileBytes)
	}
	if afterRead != nil {
		afterRead()
	}
	finalInfo, statErr := file.Stat()
	if statErr != nil {
		return credentialSnapshot{}, errors.New("credential file final inspection failed")
	}
	finalOS, metaErr := credentialMetadata(finalInfo, strict, false)
	if metaErr != nil || !credentialFileStable(openedInfo, finalInfo, openedOS, finalOS) || int64(len(payload)) != finalInfo.Size() {
		return credentialSnapshot{}, errors.New("credential file changed while reading")
	}
	if err := verifyCredentialPath(chain, absPath, finalInfo, finalOS, strict); err != nil {
		return credentialSnapshot{}, err
	}
	if err := file.Close(); err != nil {
		return credentialSnapshot{}, errors.New("credential file close failed")
	}
	store, err := parser(payload)
	if err != nil {
		return credentialSnapshot{}, err
	}
	// Parsing is bounded CPU, but an atomic replacement during that interval
	// still invalidates this sample. This remains a point-in-time observation.
	if err := verifyCredentialPath(chain, absPath, finalInfo, finalOS, strict); err != nil {
		return credentialSnapshot{}, err
	}
	return credentialSnapshot{store: store, digest: sha256.Sum256(payload)}, nil
}

func credentialFileStable(a, b os.FileInfo, x, y credentialOSState) bool {
	return os.SameFile(a, b) && a.Mode() == b.Mode() && a.Size() == b.Size() && a.ModTime().Equal(b.ModTime()) && x == y
}

func credentialPathSnapshot(path string, strict bool) ([]credentialPathState, error) {
	var reversed []string
	for current := path; ; current = filepath.Dir(current) {
		reversed = append(reversed, current)
		if filepath.Dir(current) == current {
			break
		}
	}
	chain := make([]credentialPathState, 0, len(reversed))
	for i := len(reversed) - 1; i >= 0; i-- {
		name := reversed[i]
		info, err := os.Lstat(name)
		if err != nil {
			return nil, errors.New("credential path inspection failed")
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return nil, errors.New("credential symbolic links are not allowed")
		}
		if i > 0 && !info.IsDir() {
			return nil, errors.New("credential path directory rejected")
		}
		meta, err := credentialMetadata(info, strict, i > 0)
		if err != nil {
			return nil, err
		}
		chain = append(chain, credentialPathState{path: name, info: info, os: meta})
	}
	return chain, nil
}

func verifyCredentialPath(chain []credentialPathState, path string, fileInfo os.FileInfo, fileOS credentialOSState, strict bool) error {
	current, err := credentialPathSnapshot(path, strict)
	if err != nil || len(current) != len(chain) {
		return errors.New("credential path changed while reading")
	}
	for i, before := range chain {
		after := current[i]
		// Directory entry counts/mtime can change due to unrelated siblings.
		// Bind their identity, owner and mode; bind ALL file metadata below.
		if !os.SameFile(before.info, after.info) || before.info.Mode() != after.info.Mode() || before.os.uid != after.os.uid || before.os.gid != after.os.gid {
			return errors.New("credential directory or file identity changed")
		}
	}
	last := current[len(current)-1]
	if !credentialFileStable(fileInfo, last.info, fileOS, last.os) {
		return errors.New("credential file no longer matches its path")
	}
	return nil
}

func parseCredentialPayload(payload []byte) (*Store, error) {
	if len(payload) < 1 || len(payload) > maxFileBytes || !utf8.Valid(payload) {
		return nil, errors.New("credential payload is invalid")
	}
	if err := rejectCredentialDuplicateKeys(payload); err != nil {
		return nil, err
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.DisallowUnknownFields()
	var config File
	if err := decoder.Decode(&config); err != nil {
		return nil, fmt.Errorf("decode credential file: %w", err)
	}
	if err := ensureJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("decode credential file: %w", err)
	}
	if config.Version != FileVersion {
		return nil, fmt.Errorf("unsupported credential file version %d", config.Version)
	}
	if len(config.Identities) > maxIdentities {
		return nil, fmt.Errorf("credential file exceeds %d identities", maxIdentities)
	}

	store := &Store{identities: make([]storedIdentity, 0, len(config.Identities))}
	principalIDs := make(map[string]struct{}, len(config.Identities))
	tokenIDs := make(map[string]struct{}, len(config.Identities))
	tokenHashes := make(map[string]struct{}, len(config.Identities))
	for index, identity := range config.Identities {
		if err := validateIdentity(identity); err != nil {
			return nil, fmt.Errorf("identity %d: %w", index, err)
		}
		if _, exists := principalIDs[identity.Principal.ID]; exists {
			return nil, fmt.Errorf("identity %d: duplicate principal id", index)
		}
		if _, exists := tokenIDs[identity.TokenID]; exists {
			return nil, fmt.Errorf("identity %d: duplicate token id", index)
		}
		if _, exists := tokenHashes[identity.TokenHash]; exists {
			return nil, fmt.Errorf("identity %d: duplicate token hash", index)
		}
		principalIDs[identity.Principal.ID] = struct{}{}
		tokenIDs[identity.TokenID] = struct{}{}
		tokenHashes[identity.TokenHash] = struct{}{}

		digestBytes, _ := hex.DecodeString(identity.TokenHash)
		var digest [sha256.Size]byte
		copy(digest[:], digestBytes)
		identity.Principal = clonePrincipal(identity.Principal)
		if identity.NotBefore != nil {
			timestamp := identity.NotBefore.UTC()
			identity.NotBefore = &timestamp
		}
		if identity.ExpiresAt != nil {
			timestamp := identity.ExpiresAt.UTC()
			identity.ExpiresAt = &timestamp
		}
		store.identities = append(store.identities, storedIdentity{record: identity, hash: digest})
	}
	return store, nil
}

func rejectCredentialDuplicateKeys(payload []byte) error {
	return rejectCredentialDuplicateKeysWithSet(payload, map[string]bool{
		"version": true, "identities": true, "tokenId": true, "tokenHash": true,
		"principal": true, "disabled": true, "notBefore": true, "expiresAt": true,
		"id": true, "tenantId": true, "roles": true, "allowedScopes": true,
		"breakGlassEligible": true, "siteId": true, "environment": true,
		"objectType": true, "objectId": true,
	})
}

func rejectCredentialDuplicateKeysWithSet(payload []byte, canonicalKeys map[string]bool) error {
	if len(canonicalKeys) == 0 {
		return errors.New("credential JSON key policy is unavailable")
	}
	decoder := json.NewDecoder(strings.NewReader(string(payload)))
	decoder.UseNumber()
	var value func(int) error
	value = func(depth int) error {
		if depth > 24 {
			return errors.New("credential JSON nesting exceeds limit")
		}
		token, err := decoder.Token()
		if err != nil {
			return errors.New("credential JSON is invalid")
		}
		opening, ok := token.(json.Delim)
		if !ok {
			return nil
		}
		if opening != '{' && opening != '[' {
			return errors.New("credential JSON is invalid")
		}
		seen := make(map[string]bool)
		for decoder.More() {
			if opening == '{' {
				key, err := decoder.Token()
				name, ok := key.(string)
				// An exact tag allowlist rejects even a SINGLE noncanonical
				// spelling. Nested placement/types remain the typed decoder's job.
				if err != nil || !ok || !canonicalKeys[name] || seen[name] {
					return errors.New("credential JSON contains duplicate or invalid keys")
				}
				seen[name] = true
			}
			if err := value(depth + 1); err != nil {
				return err
			}
		}
		closing, err := decoder.Token()
		if err != nil || (opening == '{' && closing != json.Delim('}')) || (opening == '[' && closing != json.Delim(']')) {
			return errors.New("credential JSON is invalid")
		}
		return nil
	}
	if err := value(0); err != nil {
		return err
	}
	return ensureJSONEOF(decoder)
}

// AuthenticateAuthorization authenticates exactly one strict Bearer value.
// Hash comparison is constant-time for every loaded identity. The returned
// Principal is a defensive copy and is ready for authz.Evaluate.
func (s *Store) AuthenticateAuthorization(header string, now time.Time) (authz.Principal, error) {
	token, code := parseAuthorization(header)
	if code != "" {
		return authz.Principal{}, denied(code)
	}
	if s == nil {
		return authz.Principal{}, denied(CodeTokenInvalid)
	}
	digest := sha256.Sum256([]byte(token))
	matched := -1
	for index := range s.identities {
		equal := subtle.ConstantTimeCompare(digest[:], s.identities[index].hash[:])
		if equal == 1 {
			matched = index
		}
	}
	if matched < 0 {
		return authz.Principal{}, denied(CodeTokenInvalid)
	}
	record := s.identities[matched].record
	if record.Disabled {
		return authz.Principal{}, denied(CodeIdentityDisabled)
	}
	now = now.UTC()
	if record.NotBefore != nil && now.Before(*record.NotBefore) {
		return authz.Principal{}, denied(CodeIdentityNotActive)
	}
	if record.ExpiresAt != nil && !now.Before(*record.ExpiresAt) {
		return authz.Principal{}, denied(CodeIdentityExpired)
	}
	return clonePrincipal(record.Principal), nil
}

// AuthenticateAuthorizationValues is the HTTP-facing variant. It rejects
// duplicate Authorization fields before delegating to the single-value
// parser; callers should pass request.Header.Values("Authorization") rather
// than request.Header.Get("Authorization").
func (s *Store) AuthenticateAuthorizationValues(headers []string, now time.Time) (authz.Principal, error) {
	if len(headers) == 0 {
		return authz.Principal{}, denied(CodeAuthorizationMissing)
	}
	if len(headers) != 1 {
		return authz.Principal{}, denied(CodeAuthorizationMalformed)
	}
	return s.AuthenticateAuthorization(headers[0], now)
}

// resolvePrincipal is package-private because Store is an immutable snapshot.
// Only SnapshotManager may expose a freshly reread id-based trusted-service
// lookup; HTTP callers must authenticate a bearer value.
func (s *Store) resolvePrincipal(id string, now time.Time) (authz.Principal, error) {
	if s == nil || validateIdentifier("principal.id", id, 128) != nil { return authz.Principal{}, denied(CodeTokenInvalid) }
	for _, identity := range s.identities {
		record := identity.record
		if record.Principal.ID != id { continue }
		if record.Disabled { return authz.Principal{}, denied(CodeIdentityDisabled) }
		if record.NotBefore != nil && now.Before(*record.NotBefore) { return authz.Principal{}, denied(CodeIdentityNotActive) }
		if record.ExpiresAt != nil && !now.Before(*record.ExpiresAt) { return authz.Principal{}, denied(CodeIdentityExpired) }
		return clonePrincipal(record.Principal), nil
	}
	return authz.Principal{}, denied(CodeTokenInvalid)
}

// GenerateToken creates an opaque base64url bearer token using crypto/rand
// and returns its plaintext once together with the lowercase SHA-256 digest
// suitable for Identity.TokenHash. It performs no file or production write.
func GenerateToken(randomBytes int) (plaintext string, tokenHash string, err error) {
	if randomBytes < minTokenBytes {
		return "", "", fmt.Errorf("token entropy must be at least %d bytes", minTokenBytes)
	}
	if randomBytes > maxTokenBytes {
		return "", "", fmt.Errorf("token entropy must not exceed %d bytes", maxTokenBytes)
	}
	material := make([]byte, randomBytes)
	if _, err := rand.Read(material); err != nil {
		return "", "", fmt.Errorf("generate bearer token: %w", err)
	}
	plaintext = base64.RawURLEncoding.EncodeToString(material)
	digest := sha256.Sum256([]byte(plaintext))
	return plaintext, hex.EncodeToString(digest[:]), nil
}

func parseAuthorization(header string) (string, ErrorCode) {
	if header == "" {
		return "", CodeAuthorizationMissing
	}
	if strings.TrimSpace(header) != header || strings.ContainsAny(header, "\r\n\t,") {
		return "", CodeAuthorizationMalformed
	}
	separator := strings.IndexByte(header, ' ')
	if separator <= 0 || separator == len(header)-1 || strings.IndexByte(header[separator+1:], ' ') >= 0 {
		return "", CodeAuthorizationMalformed
	}
	if !strings.EqualFold(header[:separator], "Bearer") {
		return "", CodeSchemeUnsupported
	}
	token := header[separator+1:]
	if len(token) > base64.RawURLEncoding.EncodedLen(maxTokenBytes) {
		return "", CodeAuthorizationMalformed
	}
	decoded, err := base64.RawURLEncoding.DecodeString(token)
	if err != nil || len(decoded) < minTokenBytes || len(decoded) > maxTokenBytes {
		return "", CodeAuthorizationMalformed
	}
	return token, ""
}

func denied(code ErrorCode) error { return &AuthenticationError{Code: code} }

func validateIdentity(identity Identity) error {
	if err := validateIdentifier("tokenId", identity.TokenID, 128); err != nil {
		return err
	}
	if len(identity.TokenHash) != sha256.Size*2 || identity.TokenHash != strings.ToLower(identity.TokenHash) {
		return errors.New("tokenHash must be a lowercase SHA-256 hexadecimal digest")
	}
	if _, err := hex.DecodeString(identity.TokenHash); err != nil {
		return errors.New("tokenHash must be a lowercase SHA-256 hexadecimal digest")
	}
	if err := validatePrincipal(identity.Principal); err != nil {
		return err
	}
	if identity.NotBefore != nil && identity.NotBefore.IsZero() {
		return errors.New("notBefore must not be zero")
	}
	if identity.ExpiresAt != nil && identity.ExpiresAt.IsZero() {
		return errors.New("expiresAt must not be zero")
	}
	if identity.NotBefore != nil && identity.ExpiresAt != nil && !identity.ExpiresAt.After(*identity.NotBefore) {
		return errors.New("expiresAt must be after notBefore")
	}
	return nil
}

func validatePrincipal(principal authz.Principal) error {
	if err := validateIdentifier("principal.id", principal.ID, 128); err != nil {
		return err
	}
	if err := validateIdentifier("principal.tenantId", principal.TenantID, 128); err != nil {
		return err
	}
	if len(principal.Roles) == 0 {
		return errors.New("principal.roles is required")
	}
	roleSeen := make(map[authz.Role]struct{}, len(principal.Roles))
	for _, role := range principal.Roles {
		switch role {
		case authz.RoleViewer, authz.RoleOperator, authz.RoleApprover, authz.RoleAuditor, authz.RoleAdmin, authz.RoleSubscriptionRefresher:
		default:
			return fmt.Errorf("principal.roles contains unknown role %q", role)
		}
		if _, exists := roleSeen[role]; exists {
			return fmt.Errorf("principal.roles contains duplicate role %q", role)
		}
		roleSeen[role] = struct{}{}
	}
	if len(principal.AllowedScopes) == 0 {
		return errors.New("principal.allowedScopes is required")
	}
	for index, scope := range principal.AllowedScopes {
		if scope.TenantID != principal.TenantID {
			return fmt.Errorf("principal.allowedScopes[%d].tenantId must equal principal.tenantId", index)
		}
		for name, value := range map[string]string{
			"siteId": scope.SiteID, "objectType": scope.ObjectType,
			"objectId": scope.ObjectID, "environment": scope.Environment,
		} {
			if value != "" {
				if err := validateIdentifier("principal.allowedScopes."+name, value, 128); err != nil {
					return err
				}
			}
		}
	}
	return nil
}

func validateIdentifier(name, value string, max int) error {
	if value == "" || len(value) > max || strings.TrimSpace(value) != value || hasControl(value) || !safeIdentifier.MatchString(value) {
		return fmt.Errorf("%s is invalid", name)
	}
	return nil
}

func hasControl(value string) bool {
	for _, r := range value {
		if unicode.IsControl(r) {
			return true
		}
	}
	return false
}

func clonePrincipal(principal authz.Principal) authz.Principal {
	principal.Roles = append([]authz.Role(nil), principal.Roles...)
	principal.AllowedScopes = append([]authz.ResourceScope(nil), principal.AllowedScopes...)
	return principal
}

func ensureJSONEOF(decoder *json.Decoder) error {
	var extra any
	err := decoder.Decode(&extra)
	if errors.Is(err, io.EOF) {
		return nil
	}
	if err == nil {
		return errors.New("multiple JSON values")
	}
	return err
}

func requirePermissions(name string, info os.FileInfo, expected os.FileMode) error {
	// Windows ACLs are not represented by FileMode.Perm. Production Linux
	// deployments enforce the exact POSIX modes below; Windows callers must
	// apply an equivalent ACL outside this package.
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm() != expected || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("%s permissions must be %04o, got %04o", name, expected, info.Mode().Perm())
	}
	return nil
}
