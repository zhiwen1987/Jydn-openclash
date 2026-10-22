package trustcatalog

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"io"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// All profile strings are ASCII identifiers, digests, schema or base64. Escape
// sequences have no legitimate use in this narrow wire profile. Rejecting them
// also prevents escaped-key aliases and invalid-surrogate replacement by JSON.
func strict(raw []byte) (map[string]any, bool) {
	if len(raw) == 0 || len(raw) > MaxEnvelopeBytes || !utf8.Valid(raw) || bytes.ContainsRune(raw, '\\') {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, ok := readValue(d, 0)
	if !ok {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	m, ok := value.(map[string]any)
	return m, ok
}
func readValue(d *json.Decoder, depth int) (any, bool) {
	if depth > 8 {
		return nil, false
	}
	t, err := d.Token()
	if err != nil {
		return nil, false
	}
	if delim, ok := t.(json.Delim); ok {
		switch delim {
		case '{':
			m := make(map[string]any)
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok {
					return nil, false
				}
				if _, exists := m[name]; exists {
					return nil, false
				}
				value, ok := readValue(d, depth+1)
				if !ok {
					return nil, false
				}
				m[name] = value
			}
			close, err := d.Token()
			return m, err == nil && close == json.Delim('}')
		case '[':
			a := make([]any, 0)
			for d.More() {
				v, ok := readValue(d, depth+1)
				if !ok {
					return nil, false
				}
				a = append(a, v)
			}
			close, err := d.Token()
			return a, err == nil && close == json.Delim(']')
		default:
			return nil, false
		}
	}
	return t, true
}
func exact(m map[string]any, keys ...string) bool {
	if len(m) != len(keys) {
		return false
	}
	for _, key := range keys {
		if _, exists := m[key]; !exists {
			return false
		}
	}
	return true
}
func stringValue(v any) string { s, _ := v.(string); return s }
func hexValue(s string, size int) bool {
	if len(s) != size {
		return false
	}
	for _, ch := range s {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}
func digestValue(s string) bool {
	return strings.HasPrefix(s, "sha256:") && hexValue(strings.TrimPrefix(s, "sha256:"), 64)
}

var identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)

func uintValue(v any) (uint64, bool) {
	n, ok := v.(json.Number)
	if !ok {
		return 0, false
	}
	u, err := strconv.ParseUint(string(n), 10, 64)
	return u, err == nil && strconv.FormatUint(u, 10) == string(n)
}
func unixValue(v any) (int64, bool) {
	u, ok := uintValue(v)
	return int64(u), ok && u > 0 && u <= 253402300799
}
func binaryValue(v any, limit int) ([]byte, bool) {
	s, ok := v.(string)
	if !ok || len(s) == 0 || len(s) > base64.StdEncoding.EncodedLen(limit) {
		return nil, false
	}
	raw, err := base64.StdEncoding.Strict().DecodeString(s)
	return raw, err == nil && len(raw) > 0 && len(raw) <= limit && base64.StdEncoding.EncodeToString(raw) == s
}
func validKeys(keys []Key, threshold, limit int) bool {
	if len(keys) < 1 || len(keys) > limit || threshold < 1 || threshold > len(keys) {
		return false
	}
	seen := make(map[string]bool)
	for _, key := range keys {
		if key.ID == "" || key.ID != KeyID(key.PublicKey) || seen[key.ID] {
			return false
		}
		seen[key.ID] = true
	}
	return true
}
func parseKeys(v any, limit int) ([]Key, bool) {
	a, ok := v.([]any)
	if !ok || len(a) > limit {
		return nil, false
	}
	keys := make([]Key, 0, len(a))
	for _, value := range a {
		m, ok := value.(map[string]any)
		if !ok || !exact(m, "id", "publicKey") {
			return nil, false
		}
		public, ok := binaryValue(m["publicKey"], ed25519.PublicKeySize)
		if !ok || len(public) != ed25519.PublicKeySize {
			return nil, false
		}
		key := Key{ID: stringValue(m["id"]), PublicKey: public}
		if key.ID != KeyID(public) {
			return nil, false
		}
		keys = append(keys, key)
	}
	if len(keys) > 0 && !validKeys(keys, 1, limit) {
		return nil, false
	}
	return keys, true
}
func parseList(v any, valid func(string) bool) ([]string, bool) {
	a, ok := v.([]any)
	if !ok || len(a) > 4096 {
		return nil, false
	}
	result := make([]string, 0, len(a))
	seen := make(map[string]bool, len(a))
	for _, value := range a {
		s := stringValue(value)
		if !valid(s) || seen[s] {
			return nil, false
		}
		seen[s] = true
		result = append(result, s)
	}
	return result, true
}

func parse(raw []byte) (Document, []authenticatedSignature, error) {
	var zero Document
	envelope, ok := strict(raw)
	if !ok || !exact(envelope, "payload", "signatures") {
		return zero, nil, ErrInvalid
	}
	payload, ok := binaryValue(envelope["payload"], MaxEnvelopeBytes)
	if !ok {
		return zero, nil, ErrInvalid
	}
	m, ok := strict(payload)
	if !ok {
		return zero, nil, ErrInvalid
	}
	d, ok := parseDocument(m)
	if !ok {
		return zero, nil, ErrInvalid
	}
	sigValues, ok := envelope["signatures"].([]any)
	if !ok || len(sigValues) < 1 || len(sigValues) > 16 {
		return zero, nil, ErrInvalid
	}
	message := make([]byte, 0, len(signingDomain)+len(payload))
	message = append(message, signingDomain...)
	message = append(message, payload...)
	signatures := make([]authenticatedSignature, 0, len(sigValues))
	seen := make(map[string]bool)
	for _, value := range sigValues {
		s, ok := value.(map[string]any)
		if !ok || !exact(s, "keyID", "signature") {
			return zero, nil, ErrInvalid
		}
		id := stringValue(s["keyID"])
		b, ok := binaryValue(s["signature"], ed25519.SignatureSize)
		if !ok || len(b) != ed25519.SignatureSize || !hexValue(id, 64) || seen[id] {
			return zero, nil, ErrInvalid
		}
		seen[id] = true
		signatures = append(signatures, authenticatedSignature{keyID: id, publicPayload: message, signature: b})
	}
	return d, signatures, nil
}

func parseDocument(m map[string]any) (Document, bool) {
	var d Document
	if !exact(m, "schema", "storeID", "generation", "notBeforeUnix", "notAfterUnix", "rootKeys", "threshold", "approvers", "grants", "policyFloors", "revokedKeys", "revokedApprovals", "revokedManifests") {
		return d, false
	}
	d.Schema, d.StoreID = stringValue(m["schema"]), stringValue(m["storeID"])
	if d.Schema != Schema || !hexValue(d.StoreID, 32) {
		return Document{}, false
	}
	var ok bool
	if d.Generation, ok = uintValue(m["generation"]); !ok || d.Generation == 0 {
		return Document{}, false
	}
	if d.NotBeforeUnix, ok = unixValue(m["notBeforeUnix"]); !ok {
		return Document{}, false
	}
	if d.NotAfterUnix, ok = unixValue(m["notAfterUnix"]); !ok || d.NotAfterUnix <= d.NotBeforeUnix || d.NotAfterUnix-d.NotBeforeUnix > 86400 {
		return Document{}, false
	}
	if d.RootKeys, ok = parseKeys(m["rootKeys"], 8); !ok {
		return Document{}, false
	}
	threshold, ok := uintValue(m["threshold"])
	if !ok || threshold > 8 {
		return Document{}, false
	}
	d.Threshold = int(threshold)
	if !validKeys(d.RootKeys, d.Threshold, 8) {
		return Document{}, false
	}
	if d.Approvers, ok = parseKeys(m["approvers"], 64); !ok {
		return Document{}, false
	}
	if d.RevokedKeys, ok = parseList(m["revokedKeys"], func(s string) bool { return hexValue(s, 64) }); !ok {
		return Document{}, false
	}
	if d.RevokedApprovals, ok = parseList(m["revokedApprovals"], digestValue); !ok {
		return Document{}, false
	}
	if d.RevokedManifests, ok = parseList(m["revokedManifests"], digestValue); !ok {
		return Document{}, false
	}
	floors, ok := m["policyFloors"].(map[string]any)
	if !ok || len(floors) > 512 {
		return Document{}, false
	}
	d.PolicyFloors = make(map[string]uint64, len(floors))
	for id, raw := range floors {
		u, ok := uintValue(raw)
		if !ok || u == 0 || !identifierPattern.MatchString(id) {
			return Document{}, false
		}
		d.PolicyFloors[id] = u
	}
	grants, ok := m["grants"].([]any)
	if !ok || len(grants) > 256 {
		return Document{}, false
	}
	d.Grants = make([]Grant, 0, len(grants))
	ids, policies, approvers, revokedKeys, revokedApprovals, revokedManifests := map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}, map[string]bool{}
	for _, key := range d.Approvers {
		approvers[key.ID] = true
	}
	for _, id := range d.RevokedKeys {
		revokedKeys[id] = true
	}
	for _, hash := range d.RevokedApprovals {
		revokedApprovals[hash] = true
	}
	for _, hash := range d.RevokedManifests {
		revokedManifests[hash] = true
	}
	for _, key := range d.RootKeys {
		if revokedKeys[key.ID] {
			return Document{}, false
		}
	}
	for _, raw := range grants {
		m, ok := raw.(map[string]any)
		if !ok || !exact(m, "id", "policyID", "approvalSHA256", "approverKeyID", "manifestSHA256", "revision") {
			return Document{}, false
		}
		g := Grant{ID: stringValue(m["id"]), PolicyID: stringValue(m["policyID"]), ApprovalSHA256: stringValue(m["approvalSHA256"]), ApproverKeyID: stringValue(m["approverKeyID"]), ManifestSHA256: stringValue(m["manifestSHA256"])}
		if g.Revision, ok = uintValue(m["revision"]); !ok || g.Revision == 0 {
			return Document{}, false
		}
		if !hexValue(g.ID, 32) || !identifierPattern.MatchString(g.PolicyID) || !digestValue(g.ApprovalSHA256) || !hexValue(g.ApproverKeyID, 64) || !digestValue(g.ManifestSHA256) || ids[g.ID] || policies[g.PolicyID] || !approvers[g.ApproverKeyID] || d.PolicyFloors[g.PolicyID] != g.Revision || revokedKeys[g.ApproverKeyID] || revokedApprovals[g.ApprovalSHA256] || revokedManifests[g.ManifestSHA256] {
			return Document{}, false
		}
		ids[g.ID], policies[g.PolicyID] = true, true
		d.Grants = append(d.Grants, g)
	}
	return d, true
}
