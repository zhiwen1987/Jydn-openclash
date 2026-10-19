package restoreimage

import (
	"strings"
	"testing"
)

func TestValidateLocalBoundsOpaqueInputWork(t *testing.T) {
	for _, target := range []string{"manifest", "config"} {
		t.Run(target+"-over-one-mebibyte", func(t *testing.T) {
			expected, manifest, config := testFixture(t, false, "amd64", "", 1)
			if target == "manifest" {
				object := testObject(t, manifest)
				object["annotations"] = map[string]string{"oversized": strings.Repeat("x", 1<<20)}
				manifest = testJSON(t, object)
				expected = testBindManifest(expected, manifest)
			} else {
				object := testObject(t, config)
				object["config"] = map[string]any{"Env": []string{strings.Repeat("x", 1<<20)}}
				config = testJSON(t, object)
				expected, manifest = testBindConfig(t, expected, manifest, config)
			}
			testInvalid(t, expected, manifest, config)
		})
	}
	t.Run("opaque-config-node-budget", func(t *testing.T) {
		expected, manifest, config := testFixture(t, false, "amd64", "", 1)
		object := testObject(t, config)
		object["config"] = map[string]any{"Env": make([]string, 32768)}
		config = testJSON(t, object)
		if len(config) >= 1<<20 {
			t.Fatal("fixture hits byte limit instead of node budget")
		}
		expected, manifest = testBindConfig(t, expected, manifest, config)
		testInvalid(t, expected, manifest, config)
	})
}

func TestValidateLocalDescriptorIntegerAndReferenceBounds(t *testing.T) {
	for _, size := range []string{"9223372036854775808", "536870913", "1e2", "1.0"} {
		t.Run("invalid-size-"+size, func(t *testing.T) {
			expected, manifest, config := testFixture(t, false, "amd64", "", 1)
			manifest = []byte(strings.Replace(string(manifest), `"size":1}`, `"size":`+size+`}`, 1))
			expected = testBindManifest(expected, manifest)
			testInvalid(t, expected, manifest, config)
		})
	}
	for _, host := range []string{"registry.example:0", "registry.example:65536", "registry.example:05000", "registry.example:-1", ".example.test", "example.test.", "-registry.test", "registry-.test", strings.Repeat("x", 64) + ".test"} {
		t.Run("invalid-host-"+host, func(t *testing.T) {
			expected, manifest, config := testFixture(t, false, "amd64", "", 1)
			expected.Reference = host + "/team/probe@" + testSHA(manifest)
			testInvalid(t, expected, manifest, config)
		})
	}
}
