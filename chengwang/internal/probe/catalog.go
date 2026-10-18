package probe

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

const (
	MaxCatalogBytes    = 256 << 10
	MaxCatalogPaths    = 16
	MaxCatalogTargets  = 256
	MaxAllowedCNAMEs   = 16
	MaxMarkerBytes     = 256
	MaxResponseBytes   = 64 << 10
	MinIntervalSeconds = 30
	MaxIntervalSeconds = 3600
	MinTimeoutSeconds  = 1
	MaxTimeoutSeconds  = 10
	MinTTLSeconds      = 30
	MaxTTLSeconds      = 7200
)

var (
	idPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	revisionPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	hostLabel       = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
)

// ParseCatalog decodes one bounded JSON document. Unknown fields and duplicate
// object keys are rejected so catalog typos cannot silently weaken policy.
func ParseCatalog(r io.Reader) (Catalog, error) {
	if r == nil {
		return Catalog{}, errors.New("catalog reader is nil")
	}
	raw, err := io.ReadAll(io.LimitReader(r, MaxCatalogBytes+1))
	if err != nil {
		return Catalog{}, fmt.Errorf("read catalog: %w", err)
	}
	if len(raw) > MaxCatalogBytes {
		return Catalog{}, fmt.Errorf("catalog exceeds %d bytes", MaxCatalogBytes)
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return Catalog{}, err
	}

	var catalog Catalog
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&catalog); err != nil {
		return Catalog{}, fmt.Errorf("decode catalog: %w", err)
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return Catalog{}, errors.New("catalog contains more than one JSON value")
		}
		return Catalog{}, fmt.Errorf("decode trailing catalog data: %w", err)
	}

	canonical, err := canonicalCatalog(catalog)
	if err != nil {
		return Catalog{}, err
	}
	digest, err := digestCanonical(canonical)
	if err != nil {
		return Catalog{}, err
	}
	canonical.Digest = digest
	return canonical, nil
}

func ParseCatalogBytes(raw []byte) (Catalog, error) {
	return ParseCatalog(bytes.NewReader(raw))
}

// ValidateCatalog validates without changing the caller's slices.
func ValidateCatalog(catalog Catalog) error {
	_, err := canonicalCatalog(catalog)
	return err
}

// DigestCatalog returns a stable SHA-256 digest. Ordering of paths, probes and
// expected status codes does not affect the digest.
func DigestCatalog(catalog Catalog) (string, error) {
	canonical, err := canonicalCatalog(catalog)
	if err != nil {
		return "", err
	}
	return digestCanonical(canonical)
}

func canonicalCatalog(catalog Catalog) (Catalog, error) {
	if catalog.Schema != CatalogSchemaV1 {
		return Catalog{}, fmt.Errorf("schema must be %q", CatalogSchemaV1)
	}
	if !revisionPattern.MatchString(catalog.Revision) {
		return Catalog{}, errors.New("revision must be 1-64 safe characters")
	}
	if !idPattern.MatchString(catalog.Agent.ID) {
		return Catalog{}, errors.New("agent.id must be a lowercase stable identifier")
	}
	if catalog.Agent.Independence != IndependenceP1 {
		return Catalog{}, errors.New("agent.independence must be P1 for M2b-0")
	}
	if !catalog.Agent.AdvisoryOnly {
		return Catalog{}, errors.New("agent.advisoryOnly must be true")
	}
	if len(catalog.Paths) == 0 || len(catalog.Paths) > MaxCatalogPaths {
		return Catalog{}, fmt.Errorf("paths must contain 1-%d entries", MaxCatalogPaths)
	}
	if len(catalog.Probes) == 0 || len(catalog.Probes) > MaxCatalogTargets {
		return Catalog{}, fmt.Errorf("probes must contain 1-%d entries", MaxCatalogTargets)
	}

	canonical := catalog
	canonical.Digest = ""
	canonical.Paths = append([]Path(nil), catalog.Paths...)
	canonical.Probes = append([]Target(nil), catalog.Probes...)

	pathIDs := make(map[string]struct{}, len(canonical.Paths))
	for i := range canonical.Paths {
		path := canonical.Paths[i]
		if !idPattern.MatchString(path.ID) {
			return Catalog{}, fmt.Errorf("paths[%d].id must be a lowercase stable identifier", i)
		}
		if path.Kind != PathKindDirect {
			return Catalog{}, fmt.Errorf("paths[%d].kind must be %q", i, PathKindDirect)
		}
		if _, duplicate := pathIDs[path.ID]; duplicate {
			return Catalog{}, fmt.Errorf("duplicate path id %q", path.ID)
		}
		pathIDs[path.ID] = struct{}{}
	}

	probeIDs := make(map[string]struct{}, len(canonical.Probes))
	for i := range canonical.Probes {
		probe := canonical.Probes[i]
		if err := ValidateTarget(probe); err != nil {
			return Catalog{}, fmt.Errorf("probes[%d]: %w", i, err)
		}
		if _, duplicate := probeIDs[probe.ID]; duplicate {
			return Catalog{}, fmt.Errorf("duplicate probe id %q", probe.ID)
		}
		probeIDs[probe.ID] = struct{}{}
		if _, exists := pathIDs[probe.PathID]; !exists {
			return Catalog{}, fmt.Errorf("probes[%d].pathId %q is not declared", i, probe.PathID)
		}
		probe.ExpectedStatus = append([]int(nil), probe.ExpectedStatus...)
		probe.AllowedCNAMEs = append([]string(nil), probe.AllowedCNAMEs...)
		sort.Ints(probe.ExpectedStatus)
		sort.Strings(probe.AllowedCNAMEs)
		canonical.Probes[i] = probe
	}

	sort.Slice(canonical.Paths, func(i, j int) bool { return canonical.Paths[i].ID < canonical.Paths[j].ID })
	sort.Slice(canonical.Probes, func(i, j int) bool { return canonical.Probes[i].ID < canonical.Probes[j].ID })
	return canonical, nil
}

func ValidateTarget(target Target) error {
	if !idPattern.MatchString(target.ID) {
		return errors.New("id must be a lowercase stable identifier")
	}
	if !idPattern.MatchString(target.PathID) {
		return errors.New("pathId must be a lowercase stable identifier")
	}
	if target.Kind != ProbeHTTPS {
		return errors.New("kind must be https")
	}
	if err := validateExactHost(target.Host); err != nil {
		return fmt.Errorf("host: %w", err)
	}
	if len(target.AllowedCNAMEs) > MaxAllowedCNAMEs {
		return fmt.Errorf("allowedCNAMEs must contain at most %d entries", MaxAllowedCNAMEs)
	}
	seenCNAME := make(map[string]struct{}, len(target.AllowedCNAMEs))
	for _, cname := range target.AllowedCNAMEs {
		if err := validateExactHost(cname); err != nil {
			return fmt.Errorf("allowedCNAMEs: %w", err)
		}
		if cname == target.Host {
			return errors.New("allowedCNAMEs must not repeat host")
		}
		if _, duplicate := seenCNAME[cname]; duplicate {
			return fmt.Errorf("allowedCNAMEs contains duplicate %q", cname)
		}
		seenCNAME[cname] = struct{}{}
	}
	if target.Port != 443 {
		return errors.New("v1 HTTPS probes require port 443")
	}
	if err := validateRequestPath(target.RequestPath); err != nil {
		return fmt.Errorf("requestPath: %w", err)
	}
	if target.Method != "GET" {
		return errors.New("method must be GET")
	}
	if len(target.ExpectedStatus) == 0 || len(target.ExpectedStatus) > 16 {
		return errors.New("expectedStatus must contain 1-16 entries")
	}
	seenStatus := make(map[int]struct{}, len(target.ExpectedStatus))
	for _, status := range target.ExpectedStatus {
		if status < 200 || status > 599 {
			return fmt.Errorf("expectedStatus contains invalid status %d", status)
		}
		if _, duplicate := seenStatus[status]; duplicate {
			return fmt.Errorf("expectedStatus contains duplicate status %d", status)
		}
		seenStatus[status] = struct{}{}
	}
	if !utf8.ValidString(target.RequiredMarker) || len(target.RequiredMarker) > MaxMarkerBytes {
		return fmt.Errorf("requiredMarker must be valid UTF-8 and at most %d bytes", MaxMarkerBytes)
	}
	if strings.IndexFunc(target.RequiredMarker, func(r rune) bool { return r < 0x20 && r != '\t' }) >= 0 {
		return errors.New("requiredMarker contains a control character")
	}
	if target.IntervalSeconds < MinIntervalSeconds || target.IntervalSeconds > MaxIntervalSeconds {
		return fmt.Errorf("intervalSeconds must be between %d and %d", MinIntervalSeconds, MaxIntervalSeconds)
	}
	if target.TimeoutSeconds < MinTimeoutSeconds || target.TimeoutSeconds > MaxTimeoutSeconds {
		return fmt.Errorf("timeoutSeconds must be between %d and %d", MinTimeoutSeconds, MaxTimeoutSeconds)
	}
	if target.TTLSeconds < MinTTLSeconds || target.TTLSeconds > MaxTTLSeconds || target.TTLSeconds < target.IntervalSeconds || target.TTLSeconds > 2*target.IntervalSeconds {
		return fmt.Errorf("ttlSeconds must be between intervalSeconds and twice intervalSeconds, within %d-%d", MinTTLSeconds, MaxTTLSeconds)
	}
	if target.MaxBodyBytes < 1 || target.MaxBodyBytes > MaxResponseBytes {
		return fmt.Errorf("maxBodyBytes must be between 1 and %d", MaxResponseBytes)
	}
	return nil
}

func validateExactHost(host string) error {
	if host == "" || len(host) > 253 {
		return errors.New("must be 1-253 characters")
	}
	if host != strings.ToLower(host) || strings.HasSuffix(host, ".") {
		return errors.New("must be canonical lowercase without a trailing dot")
	}
	if strings.ContainsAny(host, "*:/@[]\\%") || strings.ContainsAny(host, "\r\n\t ") {
		return errors.New("must be an exact DNS hostname")
	}
	if net.ParseIP(host) != nil {
		return errors.New("IP literals are not allowed")
	}
	labels := strings.Split(host, ".")
	if len(labels) < 2 {
		return errors.New("must contain at least two DNS labels")
	}
	for _, label := range labels {
		if !hostLabel.MatchString(label) {
			return errors.New("contains an invalid DNS label")
		}
	}
	return nil
}

func validateRequestPath(path string) error {
	if path == "" || len(path) > 1024 || !strings.HasPrefix(path, "/") || strings.HasPrefix(path, "//") {
		return errors.New("must be an absolute path of 1-1024 bytes")
	}
	if strings.Contains(path, "\\") || strings.ContainsAny(path, "\r\n\x00") {
		return errors.New("contains a prohibited character")
	}
	parsed, err := url.ParseRequestURI(path)
	if err != nil {
		return fmt.Errorf("invalid URI path: %w", err)
	}
	if parsed.IsAbs() || parsed.Host != "" || parsed.User != nil || parsed.Fragment != "" {
		return errors.New("must not contain scheme, host, userinfo, or fragment")
	}
	if parsed.RawQuery != "" {
		return errors.New("query parameters are not allowed in v1 probe paths")
	}
	return nil
}

func digestCanonical(catalog Catalog) (string, error) {
	catalog.Digest = ""
	raw, err := json.Marshal(catalog)
	if err != nil {
		return "", fmt.Errorf("marshal canonical catalog: %w", err)
	}
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:]), nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeJSONValue(decoder); err != nil {
		return fmt.Errorf("validate catalog JSON: %w", err)
	}
	if token, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("validate catalog JSON: unexpected token %v", token)
		}
		return fmt.Errorf("validate catalog JSON: %w", err)
	}
	return nil
}

func consumeJSONValue(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, isDelimiter := token.(json.Delim)
	if !isDelimiter {
		return nil
	}
	switch delimiter {
	case '{':
		seen := make(map[string]struct{})
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return fmt.Errorf("duplicate object key %q", key)
			}
			seen[key] = struct{}{}
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim('}') {
			return errors.New("object is not terminated")
		}
	case '[':
		for decoder.More() {
			if err := consumeJSONValue(decoder); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil {
			return err
		}
		if end != json.Delim(']') {
			return errors.New("array is not terminated")
		}
	default:
		return fmt.Errorf("unexpected delimiter %q", delimiter)
	}
	return nil
}
