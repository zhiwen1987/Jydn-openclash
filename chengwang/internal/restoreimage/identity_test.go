package restoreimage

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

const (
	testOCIManifest    = "application/vnd.oci.image.manifest.v1+json"
	testOCIConfig      = "application/vnd.oci.image.config.v1+json"
	testOCILayer       = "application/vnd.oci.image.layer.v1.tar+gzip"
	testDockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
	testDockerConfig   = "application/vnd.docker.container.image.v1+json"
	testDockerLayer    = "application/vnd.docker.image.rootfs.diff.tar.gzip"
)

func testSHA(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func testJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func testFixture(t *testing.T, docker bool, arch, variant string, layers int) (Expected, []byte, []byte) {
	t.Helper()
	diffIDs := make([]string, layers)
	descriptors := make([]any, layers)
	manifestType, configType, layerType := testOCIManifest, testOCIConfig, testOCILayer
	if docker {
		manifestType, configType, layerType = testDockerManifest, testDockerConfig, testDockerLayer
	}
	for index := range diffIDs {
		diffIDs[index] = testSHA([]byte(fmt.Sprintf("uncompressed-%d", index)))
		descriptors[index] = map[string]any{"mediaType": layerType, "digest": testSHA([]byte(fmt.Sprintf("compressed-%d", index))), "size": index + 1}
	}
	config := map[string]any{"os": "linux", "architecture": arch, "rootfs": map[string]any{"type": "layers", "diff_ids": diffIDs}}
	if variant != "" {
		config["variant"] = variant
	}
	configRaw := testJSON(t, config)
	manifest := map[string]any{
		"schemaVersion": 2, "mediaType": manifestType,
		"config": map[string]any{"mediaType": configType, "digest": testSHA(configRaw), "size": len(configRaw)},
		"layers": descriptors,
	}
	manifestRaw := testJSON(t, manifest)
	return Expected{Reference: "registry.example.test/team/probe@" + testSHA(manifestRaw), OS: "linux", Architecture: arch, Variant: variant}, manifestRaw, configRaw
}

func testObject(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var result map[string]any
	if err := json.Unmarshal(raw, &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func testBindManifest(expected Expected, manifest []byte) Expected {
	expected.Reference = "registry.example.test/team/probe@" + testSHA(manifest)
	return expected
}

func testBindConfig(t *testing.T, expected Expected, manifest, config []byte) (Expected, []byte) {
	t.Helper()
	value := testObject(t, manifest)
	descriptor := value["config"].(map[string]any)
	descriptor["digest"] = testSHA(config)
	descriptor["size"] = len(config)
	manifest = testJSON(t, value)
	return testBindManifest(expected, manifest), manifest
}

func testInvalid(t *testing.T, expected Expected, manifest, config []byte) {
	t.Helper()
	content, err := ValidateLocal(expected, manifest, config)
	if !errors.Is(err, ErrInvalid) {
		t.Fatalf("expected ErrInvalid, got content=%#v error=%v", content, err)
	}
	if !reflect.DeepEqual(content, Content{}) {
		t.Fatal("failed validation returned nonzero content")
	}
}

func TestValidateLocalBindsRawOCIAndDockerBytes(t *testing.T) {
	for _, tc := range []struct {
		name, arch, variant string
		docker              bool
		layers              int
	}{
		{"oci-amd64", "amd64", "", false, 1},
		{"docker-amd64", "amd64", "", true, 2},
		{"oci-arm64", "arm64", "", false, 2},
		{"oci-arm64-v8", "arm64", "v8", false, 2},
		{"maximum-layers", "amd64", "", false, 128},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected, manifest, config := testFixture(t, tc.docker, tc.arch, tc.variant, tc.layers)
			content, err := ValidateLocal(expected, manifest, config)
			if err != nil {
				t.Fatal(err)
			}
			if content.Reference() != expected.Reference || content.ManifestDigest() != testSHA(manifest) ||
				content.ConfigDigest() != testSHA(config) || content.OS() != expected.OS ||
				content.Architecture() != tc.arch || content.Variant() != tc.variant || content.LayerCount() != tc.layers ||
				content.Boundary() != ContentBoundary || ContentBoundary != "ADVISORY_LOCAL_OCI_BYTES_BOUND" {
				t.Fatalf("content identity mismatch: %#v", content)
			}
			// Input ownership must not escape into an apparently verified result.
			manifest[0], config[0] = '!', '!'
			if content.Reference() != expected.Reference || content.Boundary() != ContentBoundary {
				t.Fatal("caller mutation changed verified identity")
			}
		})
	}
}

func TestValidateLocalRequiresExactRawByteDigests(t *testing.T) {
	expected, manifest, config := testFixture(t, false, "amd64", "", 1)
	t.Run("manifest-whitespace-invalidates-old-reference", func(t *testing.T) {
		testInvalid(t, expected, append([]byte(" \n"), manifest...), config)
	})
	t.Run("manifest-whitespace-has-distinct-valid-identity", func(t *testing.T) {
		changed := append([]byte(" \n"), manifest...)
		updated := testBindManifest(expected, changed)
		content, err := ValidateLocal(updated, changed, config)
		if err != nil || content.ManifestDigest() == testSHA(manifest) {
			t.Fatalf("raw manifest identity was canonicalized: %v", err)
		}
	})
	t.Run("config-whitespace-invalidates-old-descriptor", func(t *testing.T) {
		testInvalid(t, expected, manifest, append([]byte(" \n"), config...))
	})
	t.Run("same-config-semantics-have-distinct-identity", func(t *testing.T) {
		changed := append([]byte(" \n"), config...)
		updated, updatedManifest := testBindConfig(t, expected, manifest, changed)
		content, err := ValidateLocal(updated, updatedManifest, changed)
		if err != nil || content.ConfigDigest() == testSHA(config) || content.ManifestDigest() == testSHA(manifest) {
			t.Fatalf("raw config identity was canonicalized: %v", err)
		}
	})
	t.Run("config-id-is-not-manifest-digest", func(t *testing.T) {
		changed := expected
		changed.Reference = "registry.example.test/team/probe@" + testSHA(config)
		testInvalid(t, changed, manifest, config)
	})
	t.Run("manifest-id-is-not-config-digest", func(t *testing.T) {
		value := testObject(t, manifest)
		value["config"].(map[string]any)["digest"] = testSHA(manifest)
		changed := testJSON(t, value)
		testInvalid(t, testBindManifest(expected, changed), changed, config)
	})
}

func TestValidateLocalRejectsInvalidManifestSemantics(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"schema-version", func(v map[string]any) { v["schemaVersion"] = 1 }},
		{"schema-version-fraction", func(v map[string]any) { v["schemaVersion"] = 2.5 }},
		{"schema-version-null", func(v map[string]any) { v["schemaVersion"] = nil }},
		{"manifest-unknown-field", func(v map[string]any) { v["unexpected"] = true }},
		{"index-media-type", func(v map[string]any) { v["mediaType"] = "application/vnd.oci.image.index.v1+json" }},
		{"artifact-type", func(v map[string]any) { v["artifactType"] = "application/secret" }},
		{"config-null", func(v map[string]any) { v["config"] = nil }},
		{"config-wrong-media-type", func(v map[string]any) { v["config"].(map[string]any)["mediaType"] = testOCILayer }},
		{"config-size-zero", func(v map[string]any) { v["config"].(map[string]any)["size"] = 0 }},
		{"config-size-negative", func(v map[string]any) { v["config"].(map[string]any)["size"] = -1 }},
		{"config-size-mismatch", func(v map[string]any) { v["config"].(map[string]any)["size"] = 1 }},
		{"config-size-fraction", func(v map[string]any) { v["config"].(map[string]any)["size"] = 1.5 }},
		{"config-url", func(v map[string]any) { v["config"].(map[string]any)["urls"] = []string{"https://example.test/secret"} }},
		{"config-inline-data", func(v map[string]any) { v["config"].(map[string]any)["data"] = "c2VjcmV0" }},
		{"layers-empty", func(v map[string]any) { v["layers"] = []any{} }},
		{"layers-null", func(v map[string]any) { v["layers"] = nil }},
		{"layer-null", func(v map[string]any) { v["layers"].([]any)[0] = nil }},
		{"layer-size-zero", func(v map[string]any) { v["layers"].([]any)[0].(map[string]any)["size"] = 0 }},
		{"layer-size-negative", func(v map[string]any) { v["layers"].([]any)[0].(map[string]any)["size"] = -1 }},
		{"layer-size-fraction", func(v map[string]any) { v["layers"].([]any)[0].(map[string]any)["size"] = 0.5 }},
		{"layer-unknown-field", func(v map[string]any) { v["layers"].([]any)[0].(map[string]any)["unknown"] = "secret" }},
		{"layer-url", func(v map[string]any) {
			v["layers"].([]any)[0].(map[string]any)["urls"] = []string{"https://example.test/secret"}
		}},
		{"layer-wrong-media-type", func(v map[string]any) { v["layers"].([]any)[0].(map[string]any)["mediaType"] = testOCIConfig }},
		{"layer-short-digest", func(v map[string]any) { v["layers"].([]any)[0].(map[string]any)["digest"] = "sha256:ab" }},
		{"layer-uppercase-digest", func(v map[string]any) {
			v["layers"].([]any)[0].(map[string]any)["digest"] = "sha256:" + strings.Repeat("A", 64)
		}},
		{"layer-sha512", func(v map[string]any) {
			v["layers"].([]any)[0].(map[string]any)["digest"] = "sha512:" + strings.Repeat("a", 128)
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected, manifest, config := testFixture(t, false, "amd64", "", 1)
			value := testObject(t, manifest)
			tc.mutate(value)
			manifest = testJSON(t, value)
			testInvalid(t, testBindManifest(expected, manifest), manifest, config)
		})
	}
	t.Run("layer-count-exceeded", func(t *testing.T) {
		expected, manifest, config := testFixture(t, false, "amd64", "", 129)
		testInvalid(t, expected, manifest, config)
	})
}

func TestValidateLocalRejectsInvalidConfigAndPlatform(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(map[string]any)
	}{
		{"os", func(v map[string]any) { v["os"] = "windows" }},
		{"architecture", func(v map[string]any) { v["architecture"] = "386" }},
		{"missing-os", func(v map[string]any) { delete(v, "os") }},
		{"missing-architecture", func(v map[string]any) { delete(v, "architecture") }},
		{"amd64-variant", func(v map[string]any) { v["variant"] = "v8" }},
		{"rootfs-null", func(v map[string]any) { v["rootfs"] = nil }},
		{"rootfs-type", func(v map[string]any) { v["rootfs"].(map[string]any)["type"] = "other" }},
		{"rootfs-diff-id-count", func(v map[string]any) { v["rootfs"].(map[string]any)["diff_ids"] = []string{} }},
		{"rootfs-diff-id-short", func(v map[string]any) { v["rootfs"].(map[string]any)["diff_ids"] = []string{"sha256:ab"} }},
		{"rootfs-diff-id-uppercase", func(v map[string]any) {
			v["rootfs"].(map[string]any)["diff_ids"] = []string{"sha256:" + strings.Repeat("A", 64)}
		}},
		{"rootfs-diff-id-null", func(v map[string]any) { v["rootfs"].(map[string]any)["diff_ids"] = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected, manifest, config := testFixture(t, false, "amd64", "", 1)
			value := testObject(t, config)
			tc.mutate(value)
			config = testJSON(t, value)
			expected, manifest = testBindConfig(t, expected, manifest, config)
			testInvalid(t, expected, manifest, config)
		})
	}
	for _, field := range []string{"os", "architecture", "variant"} {
		t.Run("expected-"+field+"-mismatch", func(t *testing.T) {
			expected, manifest, config := testFixture(t, false, "arm64", "v8", 1)
			switch field {
			case "os":
				expected.OS = "windows"
			case "architecture":
				expected.Architecture = "amd64"
			case "variant":
				expected.Variant = ""
			}
			testInvalid(t, expected, manifest, config)
		})
	}
	t.Run("arm64-invalid-variant", func(t *testing.T) {
		expected, manifest, config := testFixture(t, false, "arm64", "v7", 1)
		testInvalid(t, expected, manifest, config)
	})
}

func TestValidateLocalRejectsAmbiguousJSON(t *testing.T) {
	for _, target := range []string{"manifest", "config"} {
		for _, shape := range []string{"empty", "null", "trailing-object", "trailing-null", "duplicate-root", "case-alias", "duplicate-nested", "invalid-utf8", "deep"} {
			t.Run(target+"-"+shape, func(t *testing.T) {
				expected, manifest, config := testFixture(t, false, "amd64", "", 1)
				raw := manifest
				if target == "config" {
					raw = config
				}
				switch shape {
				case "empty":
					raw = nil
				case "null":
					raw = []byte("null")
				case "trailing-object":
					raw = append(raw, []byte(" {}")...)
				case "trailing-null":
					raw = append(raw, []byte(" null")...)
				case "duplicate-root":
					field := `"schemaVersion":2,`
					if target == "config" {
						field = `"os":"linux",`
					}
					raw = append([]byte("{"+field), raw[1:]...)
				case "case-alias":
					old, replacement := `"schemaVersion"`, `"SchemaVersion"`
					if target == "config" {
						old, replacement = `"os"`, `"OS"`
					}
					raw = bytes.Replace(raw, []byte(old), []byte(replacement), 1)
				case "duplicate-nested":
					if target == "config" {
						raw = bytes.Replace(raw, []byte(`"rootfs":{`), []byte(`"rootfs":{"type":"layers",`), 1)
					} else {
						raw = bytes.Replace(raw, []byte(`"config":{`), []byte(`"config":{"size":1,`), 1)
					}
				case "invalid-utf8":
					raw = append([]byte("{\"invalid"+string([]byte{0xff})+"\":0,"), raw[1:]...)
				case "deep":
					raw = append([]byte(`{"nested":`+strings.Repeat("[", 33)+"0"+strings.Repeat("]", 33)+","), raw[1:]...)
				}
				if target == "config" {
					config = raw
					expected, manifest = testBindConfig(t, expected, manifest, config)
				} else {
					manifest = raw
					expected = testBindManifest(expected, manifest)
				}
				testInvalid(t, expected, manifest, config)
			})
		}
	}
}

func TestValidateLocalRequiresExplicitSafeRegistryReference(t *testing.T) {
	expected, manifest, config := testFixture(t, false, "amd64", "", 1)
	digest := testSHA(manifest)
	for _, prefix := range []string{"localhost/probe@", "localhost:5000/team/probe@", "registry.example.test:5443/team/probe@"} {
		t.Run("accepted-"+prefix, func(t *testing.T) {
			changed := expected
			changed.Reference = prefix + digest
			if _, err := ValidateLocal(changed, manifest, config); err != nil {
				t.Fatal(err)
			}
		})
	}
	for _, reference := range []string{
		"", "probe@" + digest, "team/probe@" + digest, "registry.example.test/team/probe:latest", "registry.example.test/team/probe:tag@" + digest,
		"https://registry.example.test/team/probe@" + digest, "user:secret@registry.example.test/team/probe@" + digest,
		"registry.example.test/team/probe@" + digest + "?token=secret", "registry.example.test/team/probe@" + digest + "#fragment",
		" registry.example.test/team/probe@" + digest, "registry.example.test/team/probe@" + digest + "\n",
		"REGISTRY.example.test/team/probe@" + digest, "registry.example.test/Team/probe@" + digest,
		"registry.example.test/team/../probe@" + digest, "registry.example.test//probe@" + digest,
		"registry.example.test/team/%70robe@" + digest, "registry.example.test/team/probe@sha256:ab",
		"registry.example.test/team/probe@sha256:" + strings.Repeat("A", 64),
	} {
		t.Run("rejected-"+reference, func(t *testing.T) {
			changed := expected
			changed.Reference = reference
			testInvalid(t, changed, manifest, config)
		})
	}
}

func TestContentHasNoAuthorizationOrRawConfigSurface(t *testing.T) {
	expected, manifest, config := testFixture(t, false, "amd64", "", 1)
	secret := "TEST-CONFIG-ENV-SECRET-never-return"
	configValue := testObject(t, config)
	configValue["config"] = map[string]any{"Env": []string{"TOKEN=" + secret}, "Cmd": []string{"probe"}}
	config = testJSON(t, configValue)
	expected, manifest = testBindConfig(t, expected, manifest, config)
	content, err := ValidateLocal(expected, manifest, config)
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{"Reference": true, "ManifestDigest": true, "ConfigDigest": true, "OS": true, "Architecture": true, "Variant": true, "LayerCount": true, "Boundary": true}
	typeOf := reflect.TypeOf(content)
	for i := 0; i < typeOf.NumMethod(); i++ {
		if !allowed[typeOf.Method(i).Name] {
			t.Fatalf("unexpected public Content capability: %s", typeOf.Method(i).Name)
		}
	}
	for i := 0; i < typeOf.NumField(); i++ {
		if typeOf.Field(i).IsExported() {
			t.Fatalf("Content exposes mutable field: %s", typeOf.Field(i).Name)
		}
	}
	raw, err := json.Marshal(content)
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != "{}" {
		t.Fatalf("Content unexpectedly serializes internals: %s", raw)
	}
	if strings.Contains(fmt.Sprintf("%#v", content), secret) {
		t.Fatal("Content retained secret config bytes")
	}
	badConfig := []byte(`{"config":{"Env":["TOKEN=` + secret + `"]},"os":"windows"}`)
	updated, updatedManifest := testBindConfig(t, expected, manifest, badConfig)
	_, err = ValidateLocal(updated, updatedManifest, badConfig)
	if !errors.Is(err, ErrInvalid) || strings.Contains(fmt.Sprint(err), secret) {
		t.Fatalf("invalid configuration error leaked input: %v", err)
	}
}

func TestValidateLocalAcceptsBoundAnnotationsWithoutExposingThem(t *testing.T) {
	expected, manifest, config := testFixture(t, false, "amd64", "", 1)
	value := testObject(t, manifest)
	secret := "ANNOTATION-PRIVATE-never-return"
	value["annotations"] = map[string]string{"org.example.private": secret}
	value["config"].(map[string]any)["annotations"] = map[string]string{"org.example.private": secret}
	value["layers"].([]any)[0].(map[string]any)["annotations"] = map[string]string{"org.example.private": secret}
	manifest = testJSON(t, value)
	content, err := ValidateLocal(testBindManifest(expected, manifest), manifest, config)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(fmt.Sprintf("%#v", content), secret) {
		t.Fatal("Content retained raw annotations")
	}
}
