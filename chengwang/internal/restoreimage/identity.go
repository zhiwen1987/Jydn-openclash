// Package restoreimage associates local OCI bytes with a local Docker runtime
// observation. Independent signatures, Registry readback, and deployment
// authorization belong to later gates; this package grants none of them.
package restoreimage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net/netip"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	ContentBoundary  = "ADVISORY_LOCAL_OCI_BYTES_BOUND"
	maximumJSONBytes = 1 << 20
	maximumLayers    = 128
	ociManifest      = "application/vnd.oci.image.manifest.v1+json"
	dockerManifest   = "application/vnd.docker.distribution.manifest.v2+json"
	ociConfig        = "application/vnd.oci.image.config.v1+json"
	dockerConfig     = "application/vnd.docker.container.image.v1+json"
)

var (
	ErrInvalid     = errors.New("local OCI identity is invalid")
	digestPattern  = regexp.MustCompile(`^sha256:[0-9a-f]{64}$`)
	repositoryPart = regexp.MustCompile(`^[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*$`)
	hostLabel      = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]*[a-z0-9])?$`)
)

// Expected is an explicit local expectation, not an authenticated policy.
// Reference must name a single-platform manifest by digest, never a tag/index.
type Expected struct {
	Reference, OS, Architecture, Variant string
}

// ValidateExpected checks only canonical reference syntax and the supported
// platform set. It performs no IO and authenticates neither policy nor source.
func ValidateExpected(expected Expected) bool {
	_, ok := referenceDigest(expected.Reference)
	return ok && validPlatform(expected.OS, expected.Architecture, expected.Variant)
}

// Content holds only validated public identities. It retains no config bytes,
// environment, labels, history, annotations, or registry credentials.
type Content struct {
	boundary, reference, manifestDigest, configDigest string
	os, architecture, variant                         string
	layerCount                                        int
}

func (c Content) Boundary() string       { return c.boundary }
func (c Content) Reference() string      { return c.reference }
func (c Content) ManifestDigest() string { return c.manifestDigest }
func (c Content) ConfigDigest() string   { return c.configDigest }
func (c Content) OS() string             { return c.os }
func (c Content) Architecture() string   { return c.architecture }
func (c Content) Variant() string        { return c.variant }
func (c Content) LayerCount() int        { return c.layerCount }

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        descriptor        `json:"config"`
	Layers        []descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

// ValidateLocal hashes original bytes, then checks manifest/config identity and
// declared platform. It does not fetch Registry objects or read layer content.
// In particular, matching bytes do not authenticate the Reference's repository.
func ValidateLocal(expected Expected, manifestRaw, configRaw []byte) (Content, error) {
	if !ValidateExpected(expected) {
		return Content{}, ErrInvalid
	}
	wantDigest, _ := referenceDigest(expected.Reference)
	if !strictJSON(manifestRaw) || !strictJSON(configRaw) || hash(manifestRaw) != wantDigest {
		return Content{}, ErrInvalid
	}
	var image manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.DisallowUnknownFields()
	// encoding/json matches struct keys case-insensitively. Check exact names
	// separately before decoding so aliases cannot enter the trusted projection.
	if !objectKeys(manifestRaw, []string{"schemaVersion", "mediaType", "config", "layers"}, []string{"annotations"}) ||
		decoder.Decode(&image) != nil || image.SchemaVersion != 2 ||
		(image.MediaType != ociManifest && image.MediaType != dockerManifest) ||
		len(image.Layers) == 0 || len(image.Layers) > maximumLayers {
		return Content{}, ErrInvalid
	}
	var manifestFields map[string]json.RawMessage
	if json.Unmarshal(manifestRaw, &manifestFields) != nil || !descriptorKeys(manifestFields["config"]) {
		return Content{}, ErrInvalid
	}
	var layerFields []json.RawMessage
	if json.Unmarshal(manifestFields["layers"], &layerFields) != nil {
		return Content{}, ErrInvalid
	}
	config := image.Config
	if !validDescriptor(config) || config.Size != int64(len(configRaw)) || config.Digest != hash(configRaw) ||
		(image.MediaType == ociManifest && config.MediaType != ociConfig) ||
		(image.MediaType == dockerManifest && config.MediaType != dockerConfig) {
		return Content{}, ErrInvalid
	}
	for i, layer := range image.Layers {
		if !descriptorKeys(layerFields[i]) || !validDescriptor(layer) || !validLayerType(image.MediaType, layer.MediaType) {
			return Content{}, ErrInvalid
		}
	}
	if !objectKeys(configRaw, []string{"architecture", "os", "rootfs"},
		[]string{"variant", "created", "author", "config", "history"}) {
		return Content{}, ErrInvalid
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(configRaw, &fields) != nil {
		return Content{}, ErrInvalid
	}
	var osName, architecture, variant string
	if json.Unmarshal(fields["os"], &osName) != nil || json.Unmarshal(fields["architecture"], &architecture) != nil {
		return Content{}, ErrInvalid
	}
	if raw, exists := fields["variant"]; exists {
		if bytes.Equal(bytes.TrimSpace(raw), []byte("null")) || json.Unmarshal(raw, &variant) != nil {
			return Content{}, ErrInvalid
		}
	}
	if osName != expected.OS || architecture != expected.Architecture || variant != expected.Variant ||
		!objectKeys(fields["rootfs"], []string{"type", "diff_ids"}, nil) {
		return Content{}, ErrInvalid
	}
	var rootfs struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	}
	if json.Unmarshal(fields["rootfs"], &rootfs) != nil || rootfs.Type != "layers" || len(rootfs.DiffIDs) != len(image.Layers) {
		return Content{}, ErrInvalid
	}
	for _, diffID := range rootfs.DiffIDs {
		if !digestPattern.MatchString(diffID) {
			return Content{}, ErrInvalid
		}
	}
	if raw, exists := fields["config"]; exists && !isJSONObject(raw) {
		return Content{}, ErrInvalid
	}
	if raw, exists := fields["history"]; exists {
		var history []json.RawMessage
		if len(raw) == 0 || bytes.TrimSpace(raw)[0] != '[' || json.Unmarshal(raw, &history) != nil {
			return Content{}, ErrInvalid
		}
		for _, item := range history {
			if !isJSONObject(item) {
				return Content{}, ErrInvalid
			}
		}
	}
	return Content{
		boundary: ContentBoundary, reference: expected.Reference,
		manifestDigest: wantDigest, configDigest: config.Digest,
		os: osName, architecture: architecture, variant: variant, layerCount: len(image.Layers),
	}, nil
}

func hash(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func validPlatform(osName, architecture, variant string) bool {
	return osName == "linux" && ((architecture == "amd64" && variant == "") ||
		(architecture == "arm64" && (variant == "" || variant == "v8")))
}

func referenceDigest(reference string) (string, bool) {
	if len(reference) > 512 || strings.Count(reference, "@") != 1 {
		return "", false
	}
	parts := strings.SplitN(reference, "@", 2)
	if !digestPattern.MatchString(parts[1]) {
		return "", false
	}
	path := strings.Split(parts[0], "/")
	if len(path) < 2 || len(parts[0]) > 255 {
		return "", false
	}
	host := path[0]
	if host != strings.ToLower(host) || (!strings.ContainsAny(host, ".:") && host != "localhost") {
		return "", false
	}
	u, err := url.Parse("https://" + host)
	if err != nil || u.Host != host || u.Hostname() == "" || u.User != nil || u.Path != "" || u.RawQuery != "" || u.Fragment != "" {
		return "", false
	}
	if port := u.Port(); port != "" {
		value, err := strconv.ParseUint(port, 10, 16)
		if err != nil || value == 0 || strconv.FormatUint(value, 10) != port {
			return "", false
		}
	} else if strings.HasSuffix(host, ":") {
		return "", false
	}
	hostname := u.Hostname()
	if address, err := netip.ParseAddr(hostname); err == nil {
		if address.String() != hostname || address.Zone() != "" || address.Is4In6() || address.IsUnspecified() || address.IsMulticast() || address.Is6() && !strings.HasPrefix(host, "[") || address.Is4() && strings.HasPrefix(host, "[") {
			return "", false
		}
	} else {
		if len(hostname) > 253 || strings.ContainsAny(hostname, ":[]%") {
			return "", false
		}
		for _, label := range strings.Split(hostname, ".") {
			if len(label) > 63 || !hostLabel.MatchString(label) {
				return "", false
			}
		}
	}
	for _, part := range path[1:] {
		if !repositoryPart.MatchString(part) {
			return "", false
		}
	}
	return parts[1], true
}

func validDescriptor(d descriptor) bool {
	return digestPattern.MatchString(d.Digest) && d.Size > 0 && d.Size <= 512<<20
}

func validLayerType(parent, layer string) bool {
	if parent == dockerManifest {
		return layer == "application/vnd.docker.image.rootfs.diff.tar.gzip"
	}
	return layer == "application/vnd.oci.image.layer.v1.tar" || layer == "application/vnd.oci.image.layer.v1.tar+gzip"
}

func descriptorKeys(raw []byte) bool {
	return objectKeys(raw, []string{"mediaType", "digest", "size"}, []string{"annotations"})
}

func isJSONObject(raw []byte) bool {
	raw = bytes.TrimSpace(raw)
	return len(raw) > 1 && raw[0] == '{'
}

func objectKeys(raw []byte, required, optional []string) bool {
	if !isJSONObject(raw) {
		return false
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(raw, &fields) != nil {
		return false
	}
	allowed := make(map[string]bool, len(required)+len(optional))
	for _, key := range required {
		allowed[key] = true
		if _, exists := fields[key]; !exists {
			return false
		}
	}
	for _, key := range optional {
		allowed[key] = true
	}
	for key, value := range fields {
		if !allowed[key] || bytes.Equal(bytes.TrimSpace(value), []byte("null")) {
			return false
		}
	}
	return true
}

// Scan the entire JSON tree before interpreting fields. This rejects duplicate
// keys even in opaque config/history metadata that is never exposed.
func strictJSON(raw []byte) bool {
	if len(raw) == 0 || len(raw) > maximumJSONBytes || !utf8.Valid(raw) || !isJSONObject(raw) {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	nodes := 0
	if !scan(decoder, 0, &nodes) {
		return false
	}
	_, err := decoder.Token()
	return err == io.EOF
}

func scan(decoder *json.Decoder, depth int, nodes *int) bool {
	*nodes = *nodes + 1
	if depth > 32 || *nodes > 32768 {
		return false
	}
	token, err := decoder.Token()
	if err != nil {
		return false
	}
	delimiter, structured := token.(json.Delim)
	if !structured {
		return true
	}
	if delimiter != '{' && delimiter != '[' {
		return false
	}
	seen := make(map[string]bool)
	for decoder.More() {
		if delimiter == '{' {
			token, err := decoder.Token()
			key, ok := token.(string)
			if err != nil || !ok || seen[key] {
				return false
			}
			seen[key] = true
		}
		if !scan(decoder, depth+1, nodes) {
			return false
		}
	}
	end, err := decoder.Token()
	return err == nil && ((delimiter == '{' && end == json.Delim('}')) || (delimiter == '[' && end == json.Delim(']')))
}
