package verifier

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"google.golang.org/protobuf/reflect/protoreflect"
)

// Parsing budgets apply independently to the bundle, trust root, Rekor body,
// and signed DSSE payload. No re-encoding is used for cryptographic input.
const maxJSONDepth = 32
const maxJSONNodes = 8192

func strictJSON(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	nodes := 0
	v, err := jsonValue(d, 0, &nodes)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err := d.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	m, ok := v.(map[string]any)
	if !ok {
		return nil, ErrInvalid
	}
	return m, nil
}

func jsonValue(d *json.Decoder, depth int, nodes *int) (any, error) {
	(*nodes)++
	if depth > maxJSONDepth || *nodes > maxJSONNodes {
		return nil, ErrInvalid
	}
	t, err := d.Token()
	if err != nil || t == nil {
		return nil, ErrInvalid
	}
	switch v := t.(type) {
	case json.Delim:
		switch v {
		case '{':
			m := make(map[string]any)
			for d.More() {
				k, err := d.Token()
				key, ok := k.(string)
				if err != nil || !ok || strings.ContainsRune(key, utf8.RuneError) {
					return nil, ErrInvalid
				}
				if _, exists := m[key]; exists {
					return nil, ErrInvalid
				}
				value, err := jsonValue(d, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				m[key] = value
			}
			end, err := d.Token()
			if err != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return m, nil
		case '[':
			a := make([]any, 0)
			for d.More() {
				value, err := jsonValue(d, depth+1, nodes)
				if err != nil {
					return nil, err
				}
				a = append(a, value)
			}
			end, err := d.Token()
			if err != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return a, nil
		default:
			return nil, ErrInvalid
		}
	case string:
		if strings.ContainsRune(v, utf8.RuneError) {
			return nil, ErrInvalid
		}
		return v, nil
	case json.Number, bool:
		return v, nil
	default:
		return nil, ErrInvalid
	}
}

// ProtoJSON accepts proto field names as aliases. Our wire contract accepts
// only canonical JSON names; this also refuses case and snake_case aliases.
func canonicalProtoObject(m map[string]any, desc protoreflect.MessageDescriptor) bool {
	for name, value := range m {
		f := desc.Fields().ByJSONName(name)
		if f == nil || f.JSONName() != name {
			return false
		}
		if f.IsMap() {
			entries, ok := value.(map[string]any)
			if !ok {
				return false
			}
			for _, entry := range entries {
				if !canonicalProtoValue(entry, f.MapValue()) {
					return false
				}
			}
		} else if f.IsList() {
			list, ok := value.([]any)
			if !ok {
				return false
			}
			for _, entry := range list {
				if !canonicalProtoValue(entry, f) {
					return false
				}
			}
		} else if !canonicalProtoValue(value, f) {
			return false
		}
	}
	return true
}

func canonicalProtoValue(v any, f protoreflect.FieldDescriptor) bool {
	if f.Kind() != protoreflect.MessageKind {
		return true // protojson performs scalar type/range validation afterwards.
	}
	if f.Message().FullName() == "google.protobuf.Timestamp" {
		_, ok := v.(string)
		return ok
	}
	m, ok := v.(map[string]any)
	return ok && canonicalProtoObject(m, f.Message())
}

func object(v any) map[string]any {
	m, _ := v.(map[string]any)
	return m
}

func textValue(v any) string {
	s, _ := v.(string)
	return s
}

func onlyKeys(m map[string]any, keys ...string) bool {
	if m == nil {
		return false
	}
	for name := range m {
		found := false
		for _, key := range keys {
			if key == name {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}
	return true
}
