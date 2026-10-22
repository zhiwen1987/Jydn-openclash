package refresh

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"strconv"
	"unicode/utf8"
)

func generationHint(raw []byte) (uint64, bool) {
	m, ok := object(raw)
	if !ok || !exact(m, "payload", "signatures") {
		return 0, false
	}
	payload, ok := binary(m["payload"], MaxCatalogueBytes)
	if !ok {
		return 0, false
	}
	sigs, ok := m["signatures"].([]any)
	if !ok || len(sigs) == 0 || len(sigs) > 16 {
		return 0, false
	}
	seen := map[string]bool{}
	for _, value := range sigs {
		sig, ok := value.(map[string]any)
		if !ok || !exact(sig, "keyID", "signature") {
			return 0, false
		}
		id, _ := sig["keyID"].(string)
		b, ok := binary(sig["signature"], 64)
		if !ok || len(b) != 64 || !hexValid(id, 64) || seen[id] {
			return 0, false
		}
		seen[id] = true
	}
	doc, ok := object(payload)
	if !ok {
		return 0, false
	}
	number, ok := doc["generation"].(json.Number)
	if !ok {
		return 0, false
	}
	value, err := strconv.ParseUint(string(number), 10, 64)
	return value, err == nil && value > 0 && strconv.FormatUint(value, 10) == string(number)
}
func object(raw []byte) (map[string]any, bool) {
	if len(raw) == 0 || len(raw) > MaxCatalogueBytes || !utf8.Valid(raw) || bytes.ContainsRune(raw, '\\') {
		return nil, false
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	value, ok := jsonValue(d, 0)
	if !ok {
		return nil, false
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, false
	}
	m, ok := value.(map[string]any)
	return m, ok
}
func jsonValue(d *json.Decoder, depth int) (any, bool) {
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
			m := map[string]any{}
			for d.More() {
				key, err := d.Token()
				name, ok := key.(string)
				if err != nil || !ok {
					return nil, false
				}
				if _, exists := m[name]; exists {
					return nil, false
				}
				value, ok := jsonValue(d, depth+1)
				if !ok {
					return nil, false
				}
				m[name] = value
			}
			end, err := d.Token()
			return m, err == nil && end == json.Delim('}')
		case '[':
			a := []any{}
			for d.More() {
				v, ok := jsonValue(d, depth+1)
				if !ok {
					return nil, false
				}
				a = append(a, v)
			}
			end, err := d.Token()
			return a, err == nil && end == json.Delim(']')
		default:
			return nil, false
		}
	}
	return t, true
}
func binary(value any, limit int) ([]byte, bool) {
	s, ok := value.(string)
	if !ok || len(s) == 0 || len(s) > base64.StdEncoding.EncodedLen(limit) {
		return nil, false
	}
	b, err := base64.StdEncoding.Strict().DecodeString(s)
	return b, err == nil && len(b) > 0 && len(b) <= limit && base64.StdEncoding.EncodeToString(b) == s
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
