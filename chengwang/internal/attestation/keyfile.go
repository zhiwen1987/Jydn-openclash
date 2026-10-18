package attestation

import (
	"crypto/ed25519"
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

const (
	PrivateKeyFileVersion = 1
	PublicKeyFileVersion  = 1
	maxPrivateKeyFileSize = 4096

	MaterialSeed       = "seed"
	MaterialPrivateKey = "private_key"
)

type privateKeyFile struct {
	Version      int    `json:"version"`
	Algorithm    string `json:"algorithm"`
	Encoding     string `json:"encoding"`
	MaterialType string `json:"materialType"`
	Material     string `json:"material"`
}

// LoadPrivateKey reads exactly one explicit JSON seed/private-key format.
// Errors never include the file contents or decoded key material.
func LoadPrivateKey(path string) (*Signer, error) {
	if strings.TrimSpace(path) == "" {
		return nil, errors.New("private key file path is required")
	}
	absPath, err := filepath.Abs(path)
	if err != nil {
		return nil, fmt.Errorf("resolve private key file path: %w", err)
	}
	if err := rejectKeySymlinkComponents(absPath); err != nil {
		return nil, err
	}
	dirInfo, err := os.Lstat(filepath.Dir(absPath))
	if err != nil {
		return nil, fmt.Errorf("inspect private key directory: %w", err)
	}
	if !dirInfo.IsDir() {
		return nil, errors.New("private key directory is not a directory")
	}
	if err := requireKeyPermissions("private key directory", dirInfo, 0o700); err != nil {
		return nil, err
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return nil, fmt.Errorf("inspect private key file: %w", err)
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("private key file is not a regular file")
	}
	if err := requireKeyPermissions("private key file", info, 0o600); err != nil {
		return nil, err
	}
	if info.Size() > maxPrivateKeyFileSize {
		return nil, fmt.Errorf("private key file exceeds %d bytes", maxPrivateKeyFileSize)
	}

	file, err := os.Open(absPath)
	if err != nil {
		return nil, fmt.Errorf("open private key file: %w", err)
	}
	defer file.Close()
	openedInfo, err := file.Stat()
	if err != nil {
		return nil, fmt.Errorf("inspect opened private key file: %w", err)
	}
	if !openedInfo.Mode().IsRegular() || !os.SameFile(info, openedInfo) {
		return nil, errors.New("private key file changed while opening")
	}
	if err := requireKeyPermissions("private key file", openedInfo, 0o600); err != nil {
		return nil, err
	}
	body, err := io.ReadAll(io.LimitReader(file, maxPrivateKeyFileSize+1))
	if err != nil {
		return nil, fmt.Errorf("read private key file: %w", err)
	}
	if len(body) > maxPrivateKeyFileSize {
		return nil, fmt.Errorf("private key file exceeds %d bytes", maxPrivateKeyFileSize)
	}

	decoder := json.NewDecoder(strings.NewReader(string(body)))
	decoder.DisallowUnknownFields()
	var document privateKeyFile
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("decode private key file: invalid strict JSON")
	}
	if err := ensureKeyJSONEOF(decoder); err != nil {
		return nil, errors.New("decode private key file: invalid strict JSON")
	}
	if document.Version != PrivateKeyFileVersion || document.Algorithm != Algorithm || document.Encoding != Encoding {
		return nil, errors.New("private key file metadata is unsupported")
	}

	var expectedSize int
	switch document.MaterialType {
	case MaterialSeed:
		expectedSize = ed25519.SeedSize
	case MaterialPrivateKey:
		expectedSize = ed25519.PrivateKeySize
	default:
		return nil, errors.New("private key materialType must be seed or private_key")
	}
	material, err := decodeCanonicalBase64("private key material", document.Material, expectedSize, expectedSize)
	if err != nil {
		return nil, errors.New("private key material is invalid")
	}
	defer clear(material)

	var privateKey ed25519.PrivateKey
	if document.MaterialType == MaterialSeed {
		privateKey = ed25519.NewKeyFromSeed(material)
	} else {
		privateKey = append(ed25519.PrivateKey(nil), material...)
		derived := ed25519.NewKeyFromSeed(privateKey.Seed())
		if subtle.ConstantTimeCompare(privateKey, derived) != 1 {
			clear(privateKey)
			return nil, errors.New("private key material is internally inconsistent")
		}
	}
	signer, err := NewSigner(privateKey)
	clear(privateKey)
	if err != nil {
		return nil, errors.New("private key material is invalid")
	}
	return signer, nil
}

// ParsePublicKey accepts the public-only export schema and validates that its
// declared fingerprint matches the decoded key. It never chooses an algorithm
// based on the document's algorithm field.
func ParsePublicKey(data []byte) (ed25519.PublicKey, error) {
	if len(data) == 0 || len(data) > maxPrivateKeyFileSize {
		return nil, errors.New("public key document size is invalid")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	var document PublicKeyDocument
	if err := decoder.Decode(&document); err != nil {
		return nil, errors.New("decode public key document: invalid strict JSON")
	}
	if err := ensureKeyJSONEOF(decoder); err != nil {
		return nil, errors.New("decode public key document: invalid strict JSON")
	}
	if document.Version != PublicKeyFileVersion || document.Algorithm != Algorithm || document.Encoding != Encoding {
		return nil, errors.New("public key document metadata is unsupported")
	}
	material, err := decodeCanonicalBase64("public key material", document.PublicKey, ed25519.PublicKeySize, ed25519.PublicKeySize)
	if err != nil {
		return nil, err
	}
	publicKey := append(ed25519.PublicKey(nil), material...)
	if subtle.ConstantTimeCompare([]byte(document.KeyID), []byte(keyID(publicKey))) != 1 {
		return nil, errors.New("public key document fingerprint mismatch")
	}
	return publicKey, nil
}

func ensureKeyJSONEOF(decoder *json.Decoder) error {
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

func rejectKeySymlinkComponents(path string) error {
	volume := filepath.VolumeName(path)
	remainder := strings.TrimLeft(strings.TrimPrefix(path, volume), string(os.PathSeparator))
	current := volume + string(os.PathSeparator)
	if volume == "" {
		current = string(os.PathSeparator)
	}
	for _, part := range strings.Split(remainder, string(os.PathSeparator)) {
		if part == "" {
			continue
		}
		current = filepath.Join(current, part)
		info, err := os.Lstat(current)
		if err != nil {
			return fmt.Errorf("inspect private key path: %w", err)
		}
		if info.Mode()&os.ModeSymlink != 0 {
			return errors.New("private key path must not contain symbolic links")
		}
	}
	return nil
}

func requireKeyPermissions(name string, info os.FileInfo, expected os.FileMode) error {
	// FileMode cannot express Windows ACLs. The exact POSIX boundary applies on
	// production Unix; Windows deployments need an equivalent external ACL.
	if runtime.GOOS == "windows" {
		return nil
	}
	if info.Mode().Perm() != expected || info.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) != 0 {
		return fmt.Errorf("%s permissions must be %04o, got %04o", name, expected, info.Mode().Perm())
	}
	return nil
}
