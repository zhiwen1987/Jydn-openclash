package restoreimage

import (
	"context"
	"strings"
	"testing"
)

func TestCanonicalReferencesBindBothContentAndLayers(t *testing.T) {
	fixture := graphTestBuild(t, false, graphTestRaw("canonical reference byte fixture"))
	for _, tc := range []struct{ name, repository string }{
		{"ipv6", "[2001:db8::1]/team/app"},
		{"ipv6-port", "[2001:db8::1]:5443/team/app"},
		{"ipv6-loopback", "[::1]:5443/team/app"},
		{"ipv4", "10.88.0.240:5443/team/app"},
		{"double-underscore", "registry.example.test/team__one/app__two"},
		{"consecutive-hyphens", "registry.example.test/team---one/app--two"},
		{"mixed-separators", "registry.example.test/team__one/app.two---three_four"},
		{"single-label-port", "registry:5443/team/app"},
		{"localhost", "localhost/team/app"},
		{"maximum-name", "registry.test/" + strings.Repeat("a", 255-len("registry.test/"))},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected := fixture.expected
			expected.Reference = tc.repository + "@" + graphTestDigest(fixture.manifest)
			if !ValidateExpected(expected) {
				t.Fatal("canonical reference rejected before byte validation")
			}
			content, err := ValidateLocal(expected, fixture.manifest, fixture.config)
			if err != nil || content.Reference() != expected.Reference {
				t.Fatal("canonical reference did not bind content", err)
			}
			graph, err := ValidateLocalLayers(context.Background(), expected, fixture.manifest, fixture.config, fixture.blobs)
			if err != nil || graph.Content().Reference() != expected.Reference || graph.Content().ManifestDigest() != graphTestDigest(fixture.manifest) || graph.Boundary() != LayerGraphBoundary {
				t.Fatal("canonical reference did not bind actual layer bytes", err)
			}
		})
	}
}

func TestCanonicalReferenceRejectionsAreShared(t *testing.T) {
	fixture := graphTestBuild(t, false, graphTestRaw("reference rejection fixture"))
	for _, tc := range []struct{ name, repository string }{
		{"implicit-registry", "team/app"},
		{"ipv6-unbracketed", "2001:db8::1/team/app"},
		{"ipv6-zone", "[fe80::1%25eth0]/team/app"},
		{"ipv6-mapped", "[::ffff:10.88.0.240]/team/app"},
		{"ipv6-unspecified", "[::]/team/app"},
		{"ipv6-multicast", "[ff02::1]/team/app"},
		{"ipv6-expanded-alias", "[2001:db8:0:0:0:0:0:1]/team/app"},
		{"ipv6-uppercase-alias", "[2001:DB8::1]/team/app"},
		{"ipv6-bracket-suffix", "[2001:db8::1]evil/team/app"},
		{"ipv4-bracket-alias", "[10.88.0.240]/team/app"},
		{"ipv4-unspecified", "0.0.0.0/team/app"},
		{"ipv4-multicast", "224.0.0.1/team/app"},
		{"port-leading-zero", "registry.test:05443/team/app"},
		{"port-zero", "registry.test:0/team/app"},
		{"port-overflow", "registry.test:65536/team/app"},
		{"port-empty", "registry.test:/team/app"},
		{"ipv6-port-empty", "[2001:db8::1]:/team/app"},
		{"scheme", "https://registry.test/team/app"},
		{"credentials", "user:secret@registry.test/team/app"},
		{"tag", "registry.test/team/app:latest"},
		{"traversal", "registry.test/team/../app"},
		{"empty-component", "registry.test/team//app"},
		{"escaped-component", "registry.test/team/%61pp"},
		{"query", "registry.test/team/app?secret=hidden"},
		{"fragment", "registry.test/team/app#hidden"},
		{"trailing-host-dot", "registry.test./team/app"},
		{"uppercase-host", "Registry.test/team/app"},
		{"uppercase-path", "registry.test/team/App"},
		{"triple-underscore", "registry.test/team/app___one"},
		{"double-dot", "registry.test/team/app..one"},
		{"separator-prefix", "registry.test/team/__app"},
		{"separator-suffix", "registry.test/team/app--"},
		{"name-overflow", "registry.test/" + strings.Repeat("a", 256-len("registry.test/"))},
		{"reference-overflow", "registry.test/" + strings.Repeat("a", 513)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected := fixture.expected
			expected.Reference = tc.repository + "@" + graphTestDigest(fixture.manifest)
			if ValidateExpected(expected) {
				t.Fatal("invalid canonical expectation accepted")
			}
			testInvalid(t, expected, fixture.manifest, fixture.config)
			graph, err := ValidateLocalLayers(context.Background(), expected, fixture.manifest, fixture.config, fixture.blobs)
			graphTestReject(t, graph, err)
		})
	}
}

func TestValidateExpectedUsesSupportedPlatformContract(t *testing.T) {
	for _, tc := range []struct {
		name, os, architecture, variant string
		valid                           bool
	}{
		{"linux-amd64", "linux", "amd64", "", true},
		{"linux-arm64", "linux", "arm64", "", true},
		{"linux-arm64-v8", "linux", "arm64", "v8", true},
		{"windows", "windows", "amd64", "", false},
		{"386", "linux", "386", "", false},
		{"amd64-variant", "linux", "amd64", "v8", false},
		{"arm64-v7", "linux", "arm64", "v7", false},
		{"empty", "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			expected := Expected{Reference: "registry.test/team/app@sha256:" + strings.Repeat("a", 64), OS: tc.os, Architecture: tc.architecture, Variant: tc.variant}
			if ValidateExpected(expected) != tc.valid {
				t.Fatal("expected validation diverged from local platform support")
			}
		})
	}
}
