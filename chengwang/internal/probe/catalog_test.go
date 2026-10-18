package probe

import (
	"encoding/json"
	"strings"
	"testing"
)

func validCatalog() Catalog {
	return Catalog{
		Schema:   CatalogSchemaV1,
		Revision: "2026-10-18.1",
		Agent: AgentSpec{
			ID:           "probe-agent-1",
			Independence: IndependenceP1,
			AdvisoryOnly: true,
		},
		Paths: []Path{{ID: "direct-primary", Kind: PathKindDirect}},
		Probes: []Target{{
			ID:              "business-home",
			PathID:          "direct-primary",
			Kind:            ProbeHTTPS,
			Host:            "service.example.com",
			Port:            443,
			RequestPath:     "/health",
			Method:          "GET",
			ExpectedStatus:  []int{204, 200},
			RequiredMarker:  "ready",
			IntervalSeconds: 300,
			TimeoutSeconds:  8,
			TTLSeconds:      600,
			MaxBodyBytes:    4096,
		}},
	}
}

func mustCatalogJSON(t *testing.T, catalog Catalog) []byte {
	t.Helper()
	raw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func TestParseCatalogStrictAndCanonical(t *testing.T) {
	parsed, err := ParseCatalogBytes(mustCatalogJSON(t, validCatalog()))
	if err != nil {
		t.Fatalf("ParseCatalogBytes() error = %v", err)
	}
	if !strings.HasPrefix(parsed.Digest, "sha256:") || len(parsed.Digest) != len("sha256:")+64 {
		t.Fatalf("unexpected digest %q", parsed.Digest)
	}
	if got := parsed.Probes[0].ExpectedStatus; got[0] != 200 || got[1] != 204 {
		t.Fatalf("expected status was not canonicalized: %v", got)
	}

	unknown := strings.Replace(string(mustCatalogJSON(t, validCatalog())), `"revision":`, `"unknown":true,"revision":`, 1)
	if _, err := ParseCatalogBytes([]byte(unknown)); err == nil || !strings.Contains(err.Error(), "unknown field") {
		t.Fatalf("unknown field error = %v", err)
	}

	duplicate := strings.Replace(string(mustCatalogJSON(t, validCatalog())), `"schema":`, `"schema":"duplicate","schema":`, 1)
	if _, err := ParseCatalogBytes([]byte(duplicate)); err == nil || !strings.Contains(err.Error(), "duplicate object key") {
		t.Fatalf("duplicate key error = %v", err)
	}

	trailing := append(mustCatalogJSON(t, validCatalog()), []byte(` {}`)...)
	if _, err := ParseCatalogBytes(trailing); err == nil {
		t.Fatal("multiple JSON values were accepted")
	}

	oversized := []byte(`{"padding":"` + strings.Repeat("x", MaxCatalogBytes) + `"}`)
	if _, err := ParseCatalogBytes(oversized); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized catalog error = %v", err)
	}
}

func TestDigestCatalogStableAcrossOrdering(t *testing.T) {
	first := validCatalog()
	first.Probes[0].AllowedCNAMEs = []string{"z.cdn.example.com", "a.cdn.example.com"}
	first.Paths = append(first.Paths, Path{ID: "a-path", Kind: PathKindDirect})
	secondProbe := first.Probes[0]
	secondProbe.ID = "another-probe"
	secondProbe.PathID = "a-path"
	first.Probes = append(first.Probes, secondProbe)

	second := first
	second.Paths = []Path{first.Paths[1], first.Paths[0]}
	second.Probes = []Target{first.Probes[1], first.Probes[0]}
	second.Probes[1].ExpectedStatus = []int{200, 204}
	second.Probes[1].AllowedCNAMEs = []string{"a.cdn.example.com", "z.cdn.example.com"}

	firstDigest, err := DigestCatalog(first)
	if err != nil {
		t.Fatal(err)
	}
	secondDigest, err := DigestCatalog(second)
	if err != nil {
		t.Fatal(err)
	}
	if firstDigest != secondDigest {
		t.Fatalf("semantic ordering changed digest: %s != %s", firstDigest, secondDigest)
	}
	if _, err := ParseCatalogBytes(append([]byte("\n\t"), append(mustCatalogJSON(t, first), '\n')...)); err != nil {
		t.Fatalf("insignificant whitespace was rejected: %v", err)
	}
}

func TestValidateCatalogBoundsAndRelationships(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Catalog)
		want   string
	}{
		{"schema", func(c *Catalog) { c.Schema = "v2" }, "schema"},
		{"revision", func(c *Catalog) { c.Revision = "bad revision" }, "revision"},
		{"agent id", func(c *Catalog) { c.Agent.ID = "Agent" }, "agent.id"},
		{"independence", func(c *Catalog) { c.Agent.Independence = IndependenceP0 }, "P1"},
		{"advisory only", func(c *Catalog) { c.Agent.AdvisoryOnly = false }, "advisoryOnly"},
		{"no paths", func(c *Catalog) { c.Paths = nil }, "paths"},
		{"duplicate paths", func(c *Catalog) { c.Paths = append(c.Paths, c.Paths[0]) }, "duplicate path"},
		{"path kind", func(c *Catalog) { c.Paths[0].Kind = "proxy-url" }, "kind"},
		{"no probes", func(c *Catalog) { c.Probes = nil }, "probes"},
		{"duplicate probes", func(c *Catalog) { c.Probes = append(c.Probes, c.Probes[0]) }, "duplicate probe"},
		{"missing path", func(c *Catalog) { c.Probes[0].PathID = "missing" }, "not declared"},
		{"too many paths", func(c *Catalog) {
			c.Paths = make([]Path, MaxCatalogPaths+1)
		}, "paths"},
		{"too many probes", func(c *Catalog) {
			c.Probes = make([]Target, MaxCatalogTargets+1)
		}, "probes"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			catalog := validCatalog()
			test.mutate(&catalog)
			if err := ValidateCatalog(catalog); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("ValidateCatalog() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestValidateTargetRejectsUnsafeOrProgrammableInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*Target)
	}{
		{"wildcard host", func(p *Target) { p.Host = "*.example.com" }},
		{"IP literal", func(p *Target) { p.Host = "8.8.8.8" }},
		{"wildcard CNAME", func(p *Target) { p.AllowedCNAMEs = []string{"*.example.com"} }},
		{"duplicate CNAME", func(p *Target) { p.AllowedCNAMEs = []string{"cdn.example.com", "cdn.example.com"} }},
		{"host repeated as CNAME", func(p *Target) { p.AllowedCNAMEs = []string{p.Host} }},
		{"URL userinfo", func(p *Target) { p.Host = "user@example.com" }},
		{"URL host", func(p *Target) { p.Host = "https://example.com" }},
		{"uppercase host", func(p *Target) { p.Host = "Example.com" }},
		{"implicit port", func(p *Target) { p.Port = 0 }},
		{"non-HTTPS port", func(p *Target) { p.Port = 8443 }},
		{"non HTTPS", func(p *Target) { p.Kind = "tcp" }},
		{"absolute URL path", func(p *Target) { p.RequestPath = "https://evil.example/" }},
		{"query parameter", func(p *Target) { p.RequestPath = "/health?token=secret" }},
		{"scheme relative path", func(p *Target) { p.RequestPath = "//evil.example/" }},
		{"path injection", func(p *Target) { p.RequestPath = "/ok\r\nX-Test: yes" }},
		{"arbitrary method", func(p *Target) { p.Method = "POST" }},
		{"empty expected", func(p *Target) { p.ExpectedStatus = nil }},
		{"duplicate expected", func(p *Target) { p.ExpectedStatus = []int{200, 200} }},
		{"invalid expected", func(p *Target) { p.ExpectedStatus = []int{199} }},
		{"control marker", func(p *Target) { p.RequiredMarker = "ok\x00" }},
		{"long marker", func(p *Target) { p.RequiredMarker = strings.Repeat("x", MaxMarkerBytes+1) }},
		{"short interval", func(p *Target) { p.IntervalSeconds = MinIntervalSeconds - 1 }},
		{"long interval", func(p *Target) { p.IntervalSeconds = MaxIntervalSeconds + 1 }},
		{"short timeout", func(p *Target) { p.TimeoutSeconds = MinTimeoutSeconds - 1 }},
		{"long timeout", func(p *Target) { p.TimeoutSeconds = MaxTimeoutSeconds + 1 }},
		{"short TTL", func(p *Target) { p.TTLSeconds = MinTTLSeconds - 1 }},
		{"long TTL", func(p *Target) { p.TTLSeconds = MaxTTLSeconds + 1 }},
		{"TTL shorter than interval", func(p *Target) { p.TTLSeconds = p.IntervalSeconds - 1 }},
		{"zero body budget", func(p *Target) { p.MaxBodyBytes = 0 }},
		{"large body budget", func(p *Target) { p.MaxBodyBytes = MaxResponseBytes + 1 }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			target := validCatalog().Probes[0]
			test.mutate(&target)
			if err := ValidateTarget(target); err == nil {
				t.Fatal("ValidateTarget() accepted unsafe target")
			}
		})
	}
}

func TestUnknownProgrammableProbeFieldsAreRejected(t *testing.T) {
	raw := string(mustCatalogJSON(t, validCatalog()))
	for _, field := range []string{`"headers":{"Authorization":"secret"}`, `"body":"payload"`, `"script":"run()"`, `"url":"https://example.com"`} {
		withField := strings.Replace(raw, `"id":"business-home"`, `"id":"business-home",`+field, 1)
		if _, err := ParseCatalogBytes([]byte(withField)); err == nil || !strings.Contains(err.Error(), "unknown field") {
			t.Fatalf("field %s error = %v", field, err)
		}
	}
}
