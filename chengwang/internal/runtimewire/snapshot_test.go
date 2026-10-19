package runtimewire

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestSnapshotWireSchemaIsVersionedAndSecretFree(t *testing.T) {
	value := Snapshot{
		Schema: SchemaV1, ProjectName: "project", ServiceName: "probe-agent",
		Container: Container{ID: strings.Repeat("a", 64), ImageID: "sha256:" + strings.Repeat("b", 64)},
		Image:     Image{ID: "sha256:" + strings.Repeat("b", 64)},
		Network:   Network{ID: strings.Repeat("c", 64)},
	}
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), `"schema":"`+SchemaV1+`"`) {
		t.Fatal("wire schema identifier is missing")
	}
	for _, forbidden := range []string{"environment", "healthLog", "mountSource", "labels", "dockerError"} {
		if strings.Contains(string(raw), forbidden) {
			t.Fatalf("wire contract exposes forbidden field %q", forbidden)
		}
	}
}
