package policy

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"
)

const maxJSONDepth = 8
const maxJSONNodes = 256

func strictObject(raw []byte) (map[string]any, error) {
	if len(raw) == 0 || len(raw) > MaxPolicyBytes || !utf8.Valid(raw) {
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
	token, err := d.Token()
	if err != nil || token == nil {
		return nil, ErrInvalid
	}
	switch value := token.(type) {
	case json.Delim:
		switch value {
		case '{':
			m := map[string]any{}
			for d.More() {
				keyToken, err := d.Token()
				key, ok := keyToken.(string)
				if err != nil || !ok || strings.ContainsRune(key, utf8.RuneError) {
					return nil, ErrInvalid
				}
				if _, exists := m[key]; exists {
					return nil, ErrInvalid
				}
				v, err := jsonValue(d, depth+1, nodes)
				if err != nil {
					return nil, ErrInvalid
				}
				m[key] = v
			}
			if end, err := d.Token(); err != nil || end != json.Delim('}') {
				return nil, ErrInvalid
			}
			return m, nil
		case '[':
			a := []any{}
			for d.More() {
				v, err := jsonValue(d, depth+1, nodes)
				if err != nil {
					return nil, ErrInvalid
				}
				a = append(a, v)
			}
			if end, err := d.Token(); err != nil || end != json.Delim(']') {
				return nil, ErrInvalid
			}
			return a, nil
		default:
			return nil, ErrInvalid
		}
	case string:
		if strings.ContainsRune(value, utf8.RuneError) {
			return nil, ErrInvalid
		}
		return value, nil
	case json.Number, bool:
		return value, nil
	default:
		return nil, ErrInvalid
	}
}
