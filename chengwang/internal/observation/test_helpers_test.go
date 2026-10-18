package observation

import (
	"encoding/json"
	"strings"
	"testing"
)

func mustMarshal(t *testing.T, value any) []byte {
	t.Helper()
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func contains(value, fragment string) bool { return strings.Contains(value, fragment) }
