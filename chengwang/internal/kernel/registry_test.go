package kernel

import "testing"

type stubAdapter struct{ descriptor Descriptor }

func (s stubAdapter) Descriptor() Descriptor             { return s.descriptor }
func (stubAdapter) Validate([]byte) error                { return nil }
func (stubAdapter) Compile(value []byte) ([]byte, error) { return value, nil }

func TestRegistryRejectsDuplicateAdapters(t *testing.T) {
	registry := NewRegistry()
	adapter := stubAdapter{descriptor: Descriptor{ID: "mihomo", DisplayName: "Mihomo", ConfigFormat: "yaml"}}
	if err := registry.Register(adapter); err != nil {
		t.Fatal(err)
	}
	if err := registry.Register(adapter); err == nil {
		t.Fatal("expected duplicate registration to fail")
	}
}

func TestKnownCapabilitiesHaveNoDuplicates(t *testing.T) {
	seen := map[string]struct{}{}
	for _, capability := range KnownCapabilities() {
		if _, exists := seen[capability]; exists {
			t.Fatalf("duplicate capability %q", capability)
		}
		seen[capability] = struct{}{}
	}
}
