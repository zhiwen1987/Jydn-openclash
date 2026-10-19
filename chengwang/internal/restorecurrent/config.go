package restorecurrent

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"path"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

type configurationContents struct {
	env      []byte
	catalog  []byte
	ca       []byte
	policy   []byte
	identity []byte
}

type validatedEnvironment struct{ projectName string }

var (
	releasePattern = regexp.MustCompile(`^[a-z0-9][a-z0-9._-]{0,63}$`)
	hashPattern    = regexp.MustCompile(`^[0-9a-f]{64}$`)
	hostPattern    = regexp.MustCompile(`^[A-Za-z0-9](?:[A-Za-z0-9.-]{0,251}[A-Za-z0-9])?$`)
)

var allowedEnvironmentKeys = []string{
	"M2B_PROBE_RELEASE_ID", "M2B_PROBE_PROJECT_NAME", "M2B_PROBE_CANDIDATE_ROOT",
	"M2B_PROBE_CATALOG_FILE", "M2B_PROBE_DOT_CA_FILE", "M2B_PROBE_EGRESS_POLICY_FILE",
	"M2B_PROBE_SPOOL_DIR", "M2B_PROBE_LEDGER_DIR", "M2B_PROBE_DOT_UPSTREAM",
	"M2B_PROBE_DOT_SERVER_NAME", "M2B_PROBE_CATALOG_SHA256", "M2B_PROBE_DOT_CA_SHA256",
	"M2B_PROBE_EGRESS_POLICY_SHA256", "M2B_PROBE_ACTIVE_APPROVAL",
}

func validateConfiguration(contents configurationContents, candidateRoot, instance string) (validatedEnvironment, error) {
	values, err := parseEnvironment(contents.env)
	if err != nil {
		return validatedEnvironment{}, err
	}
	expectedPaths := map[string]string{
		"M2B_PROBE_CANDIDATE_ROOT":     candidateRoot,
		"M2B_PROBE_CATALOG_FILE":       path.Join(candidateRoot, "config/catalog.json"),
		"M2B_PROBE_DOT_CA_FILE":        path.Join(candidateRoot, "config/dot-ca.pem"),
		"M2B_PROBE_EGRESS_POLICY_FILE": path.Join(candidateRoot, "config/egress-policy.json"),
		"M2B_PROBE_SPOOL_DIR":          path.Join(candidateRoot, "probe-state/probe-spool"),
		"M2B_PROBE_LEDGER_DIR":         path.Join(candidateRoot, "probe-state/probe-ledger"),
	}
	for key, expected := range expectedPaths {
		if values[key] != expected {
			return validatedEnvironment{}, errors.Join(ErrInvalid, fmt.Errorf("candidate environment path mismatch for %s", key))
		}
	}
	for key, raw := range map[string][]byte{
		"M2B_PROBE_CATALOG_SHA256":       contents.catalog,
		"M2B_PROBE_DOT_CA_SHA256":        contents.ca,
		"M2B_PROBE_EGRESS_POLICY_SHA256": contents.policy,
	} {
		if !hashPattern.MatchString(values[key]) || values[key] != rawHexDigest(raw) {
			return validatedEnvironment{}, errors.Join(ErrInvalid, fmt.Errorf("candidate environment digest mismatch for %s", key))
		}
	}
	if values["M2B_PROBE_ACTIVE_APPROVAL"] != "approved-candidate-only" {
		return validatedEnvironment{}, errors.Join(ErrInvalid, errors.New("candidate approval phrase is invalid"))
	}
	release := values["M2B_PROBE_RELEASE_ID"]
	if !releasePattern.MatchString(release) || containsBlockedToken(release) {
		return validatedEnvironment{}, errors.Join(ErrInvalid, errors.New("candidate release identifier is invalid"))
	}
	rootHash := sha256.Sum256([]byte(candidateRoot))
	expectedProject := "chengwang-m2b-probe-" + instance + "-" + hex.EncodeToString(rootHash[:])[:12] + "-candidate"
	if values["M2B_PROBE_PROJECT_NAME"] != expectedProject {
		return validatedEnvironment{}, errors.Join(ErrInvalid, errors.New("candidate project name is not derived from the fixed root"))
	}
	if err := validateDoT(values); err != nil {
		return validatedEnvironment{}, err
	}
	if err := validateCA(contents.ca); err != nil {
		return validatedEnvironment{}, err
	}
	if err := validatePolicy(contents.policy); err != nil {
		return validatedEnvironment{}, err
	}
	return validatedEnvironment{projectName: expectedProject}, nil
}

func parseEnvironment(raw []byte) (map[string]string, error) {
	if len(raw) == 0 || len(raw) > 32<<10 || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return nil, errors.Join(ErrInvalid, errors.New("candidate environment encoding or size is invalid"))
	}
	allowed := make(map[string]struct{}, len(allowedEnvironmentKeys))
	for _, key := range allowedEnvironmentKeys {
		allowed[key] = struct{}{}
	}
	values := make(map[string]string, len(allowed))
	lines := strings.Split(strings.ReplaceAll(string(raw), "\r\n", "\n"), "\n")
	for number, rawLine := range lines {
		line := strings.TrimSpace(rawLine)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		key, value, found := strings.Cut(line, "=")
		if !found || key == "" || value == "" || key != strings.TrimSpace(key) || value != strings.TrimSpace(value) {
			return nil, errors.Join(ErrInvalid, fmt.Errorf("candidate environment line %d is malformed", number+1))
		}
		if _, ok := allowed[key]; !ok {
			return nil, errors.Join(ErrInvalid, errors.New("candidate environment contains an unknown key"))
		}
		if _, duplicate := values[key]; duplicate {
			return nil, errors.Join(ErrInvalid, errors.New("candidate environment contains a duplicate key"))
		}
		values[key] = value
	}
	if len(values) != len(allowed) {
		return nil, errors.Join(ErrInvalid, errors.New("candidate environment key set is incomplete"))
	}
	return values, nil
}

func validateDoT(values map[string]string) error {
	host, portText, err := splitHostPort(values["M2B_PROBE_DOT_UPSTREAM"])
	if err != nil {
		return errors.Join(ErrInvalid, errors.New("candidate DoT upstream is invalid"))
	}
	address, err := netip.ParseAddr(host)
	port, portErr := strconv.Atoi(portText)
	if err != nil || portErr != nil || port != 853 || !address.IsValid() || address.IsUnspecified() || address.IsLoopback() || address.IsLinkLocalUnicast() || address.IsMulticast() || isDocumentationAddress(address) {
		return errors.Join(ErrInvalid, errors.New("candidate DoT upstream is not an approved unicast endpoint"))
	}
	name := strings.ToLower(values["M2B_PROBE_DOT_SERVER_NAME"])
	if !hostPattern.MatchString(name) || strings.HasSuffix(name, ".invalid") || containsBlockedToken(name) {
		return errors.Join(ErrInvalid, errors.New("candidate DoT server name is invalid"))
	}
	return nil
}

func splitHostPort(value string) (string, string, error) {
	if strings.HasPrefix(value, "[") {
		end := strings.LastIndex(value, "]:")
		if end <= 1 {
			return "", "", errors.New("invalid bracketed address")
		}
		return value[1:end], value[end+2:], nil
	}
	index := strings.LastIndexByte(value, ':')
	if index <= 0 || strings.Contains(value[:index], ":") {
		return "", "", errors.New("invalid address")
	}
	return value[:index], value[index+1:], nil
}

func isDocumentationAddress(address netip.Addr) bool {
	for _, prefix := range []string{"192.0.2.0/24", "198.51.100.0/24", "203.0.113.0/24", "2001:db8::/32"} {
		block := netip.MustParsePrefix(prefix)
		if block.Contains(address) {
			return true
		}
	}
	return false
}

func validateCA(raw []byte) error {
	if len(raw) == 0 || len(raw) > 1<<20 || !utf8.Valid(raw) || !bytes.Contains(raw, []byte("-----BEGIN CERTIFICATE-----")) || !bytes.Contains(raw, []byte("-----END CERTIFICATE-----")) || containsBlockedToken(strings.ToLower(string(raw))) {
		return errors.Join(ErrInvalid, errors.New("candidate DoT CA bundle is invalid"))
	}
	return nil
}

func validatePolicy(raw []byte) error {
	if len(raw) == 0 || len(raw) > 256<<10 {
		return errors.Join(ErrInvalid, errors.New("candidate egress policy size is invalid"))
	}
	if err := rejectDuplicateJSONKeys(raw); err != nil {
		return errors.Join(ErrInvalid, errors.New("candidate egress policy JSON is invalid"))
	}
	var policy struct {
		Schema   string `json:"schema"`
		Approval struct {
			Status string `json:"status"`
		} `json:"approval"`
		Enforcement struct {
			State           string `json:"state"`
			RuntimeEvidence string `json:"runtimeEvidence"`
		} `json:"enforcement"`
	}
	if err := json.Unmarshal(raw, &policy); err != nil || policy.Schema != "chengwang.probe-egress-policy/v1" || policy.Approval.Status != "approved" || policy.Enforcement.State != "enforced" || policy.Enforcement.RuntimeEvidence == "" || policy.Enforcement.RuntimeEvidence == "not-collected" {
		return errors.Join(ErrInvalid, errors.New("candidate egress policy approval or enforcement is invalid"))
	}
	return nil
}

func rejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := scanJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON token")
		}
		return err
	}
	return nil
}

func scanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
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
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := scanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func rawHexDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return hex.EncodeToString(sum[:])
}

func containsBlockedToken(value string) bool {
	lower := strings.ToLower(value)
	return strings.Contains(lower, "placeholder") || strings.Contains(lower, "replace-with") || strings.Contains(lower, "latest") || strings.Contains(lower, "local")
}
