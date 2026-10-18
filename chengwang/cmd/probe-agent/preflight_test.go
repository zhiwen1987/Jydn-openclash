package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"chengwang/internal/probe"
)

type preflightFixture struct {
	now        time.Time
	catalog    probe.Catalog
	policy     probeEgressPolicy
	config     preflightConfig
	arguments  []string
	policyPath string
}

func TestPreflightAcceptsExactReadOnlyContracts(t *testing.T) {
	fixture := newPreflightFixture(t)
	before := snapshotPreflightFiles(t, fixture.config)
	var output bytes.Buffer
	if err := runPreflightCommand(fixture.arguments, &output, func() time.Time { return fixture.now }); err != nil {
		t.Fatalf("runPreflightCommand() error = %v", err)
	}
	if output.Len() != 0 {
		t.Fatalf("successful preflight emitted output: %q", output.String())
	}
	executeArguments := append([]string{"preflight"}, fixture.arguments...)
	if err := execute(context.Background(), executeArguments, &output); err != nil {
		t.Fatalf("execute(preflight) error = %v", err)
	}
	after := snapshotPreflightFiles(t, fixture.config)
	for path, content := range before {
		if !bytes.Equal(content, after[path]) {
			t.Fatalf("preflight modified an input file")
		}
	}
}

func TestPreflightArgumentsAreStrict(t *testing.T) {
	fixture := newPreflightFixture(t)
	tests := []struct {
		name string
		args []string
		want string
	}{
		{"missing", fixture.arguments[2:], "--catalog is required"},
		{"duplicate", append(append([]string{}, fixture.arguments...), "--catalog", fixture.config.catalogPath), "duplicate"},
		{"positional", append(append([]string{}, fixture.arguments...), "unexpected"), "only named --flag"},
		{"unknown", append(append([]string{}, fixture.arguments...), "--unknown", "value"), "flag provided but not defined"},
		{"uppercase digest", replaceArgument(fixture.arguments, "--expected-catalog-sha256", strings.ToUpper(fixture.config.expectedCatalogSHA)), "lowercase"},
		{"DoT wrong port", replaceArgument(fixture.arguments, "--dot-upstream", "1.1.1.1:443"), "port 853"},
		{"DoT hostname", replaceArgument(fixture.arguments, "--dot-upstream", "resolver.example.com:853"), "fixed IP"},
		{"DoT private", replaceArgument(fixture.arguments, "--dot-upstream", "10.0.0.1:853"), "public IP"},
		{"DoT documentation", replaceArgument(fixture.arguments, "--dot-upstream", "192.0.2.1:853"), "public IP"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			err := runPreflightCommand(test.args, nil, func() time.Time { return fixture.now })
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("runPreflightCommand() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestPreflightRejectsFileDigestAndCAFailures(t *testing.T) {
	fixture := newPreflightFixture(t)
	wrong := strings.Repeat("0", 64)
	for _, test := range []struct {
		name   string
		mutate func(*preflightConfig)
		want   string
	}{
		{"catalog digest", func(value *preflightConfig) { value.expectedCatalogSHA = wrong }, "catalog SHA-256 mismatch"},
		{"CA digest", func(value *preflightConfig) { value.expectedDoTCASHA = wrong }, "DoT CA SHA-256 mismatch"},
		{"policy digest", func(value *preflightConfig) { value.expectedEgressSHA = wrong }, "egress policy SHA-256 mismatch"},
	} {
		t.Run(test.name, func(t *testing.T) {
			value := fixture.config
			test.mutate(&value)
			if err := executePreflight(value, fixture.now); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("executePreflight() error = %v, want containing %q", err, test.want)
			}
		})
	}

	t.Run("invalid CA", func(t *testing.T) {
		value := fixture.config
		invalidPath := filepath.Join(t.TempDir(), "invalid-ca.pem")
		raw := []byte("not a certificate")
		if err := os.WriteFile(invalidPath, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		value.doTCAPath = invalidPath
		value.expectedDoTCASHA = rawSHA256(raw)
		if err := executePreflight(value, fixture.now); err == nil || !strings.Contains(err.Error(), "DoT CA validation failed") {
			t.Fatalf("executePreflight() error = %v", err)
		}
	})

	t.Run("same file", func(t *testing.T) {
		value := fixture.config
		value.egressPolicyPath = value.catalogPath
		if err := executePreflight(value, fixture.now); err == nil || !strings.Contains(err.Error(), "distinct files") {
			t.Fatalf("executePreflight() error = %v", err)
		}
	})

	t.Run("symbolic link", func(t *testing.T) {
		link := filepath.Join(t.TempDir(), "catalog-link.json")
		if err := os.Symlink(fixture.config.catalogPath, link); err != nil {
			t.Skipf("symbolic links unavailable: %v", err)
		}
		value := fixture.config
		value.catalogPath = link
		if err := executePreflight(value, fixture.now); err == nil || !strings.Contains(err.Error(), "non-symlink regular") {
			t.Fatalf("executePreflight() error = %v", err)
		}
	})
}

func TestPreflightPolicyJSONIsStrictAndBounded(t *testing.T) {
	fixture := newPreflightFixture(t)
	raw, err := json.Marshal(fixture.policy)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name string
		raw  []byte
		want string
	}{
		{"unknown top-level", append(append([]byte(nil), bytes.TrimSuffix(raw, []byte("}"))...), []byte(`,"credential":"secret"}`)...), "unknown field"},
		{"duplicate", append(append([]byte(nil), bytes.TrimSuffix(raw, []byte("}"))...), []byte(`,"schema":"chengwang.probe-egress-policy/v1"}`)...), "duplicate"},
		{"trailing", append(append([]byte(nil), raw...), []byte("\n{}")...), "trailing"},
		{"unknown destination URL", replaceJSONOnce(t, raw, `"kind":"fixed-dot"`, `"kind":"fixed-dot","url":"https://user:password@example.com"`), "unknown field"},
		{"oversized", bytes.Repeat([]byte{'x'}, int(maximumEgressPolicyBytes+1)), "size limit"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := parseProbeEgressPolicy(test.raw); err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("parseProbeEgressPolicy() error = %v, want containing %q", err, test.want)
			}
		})
	}
}

func TestPreflightPolicyRequiresApprovalEnforcementAndExactDestinations(t *testing.T) {
	fixture := newPreflightFixture(t)
	valid := fixture.policy
	tests := []struct {
		name   string
		mutate func(*probeEgressPolicy)
		want   string
	}{
		{"schema", func(policy *probeEgressPolicy) { policy.Schema = "chengwang.probe-egress-policy/v2" }, "schema"},
		{"revision", func(policy *probeEgressPolicy) { policy.Revision = "bad revision" }, "revision"},
		{"approval status", func(policy *probeEgressPolicy) { policy.Approval.Status = "unapproved" }, "not approved"},
		{"approval owner empty", func(policy *probeEgressPolicy) { policy.Approval.Owner = "" }, "owner"},
		{"approval owner control", func(policy *probeEgressPolicy) { policy.Approval.Owner = "owner\nsecond" }, "owner"},
		{"approval time zero", func(policy *probeEgressPolicy) { policy.Approval.ApprovedAt = time.Time{} }, "approval time"},
		{"approval time future", func(policy *probeEgressPolicy) { policy.Approval.ApprovedAt = fixture.now.Add(time.Nanosecond) }, "future"},
		{"enforcement state", func(policy *probeEgressPolicy) { policy.Enforcement.DesiredState = "blocked" }, "desired egress contract"},
		{"enforcement mode", func(policy *probeEgressPolicy) { policy.Enforcement.ExpectedMode = "deny-all" }, "desired egress contract"},
		{"evidence absent", func(policy *probeEgressPolicy) { policy.Enforcement.AttestationRef = "" }, "attestation reference"},
		{"evidence unrestricted", func(policy *probeEgressPolicy) { policy.Enforcement.AttestationRef = "not-collected" }, "attestation reference"},
		{"empty destinations", func(policy *probeEgressPolicy) { policy.AllowedDestinations = nil }, "allowed destinations"},
		{"destination schema", func(policy *probeEgressPolicy) { policy.AllowedDestinations[0].Schema = "unversioned" }, "destination 0 schema"},
		{"destination kind", func(policy *probeEgressPolicy) { policy.AllowedDestinations[0].Kind = "url" }, "kind"},
		{"private DoT", func(policy *probeEgressPolicy) { policy.AllowedDestinations[0].Endpoint = "10.0.0.1:853" }, "not public"},
		{"DoT wrong port", func(policy *probeEgressPolicy) { policy.AllowedDestinations[0].Endpoint = "1.1.1.1:443" }, "invalid fixed DoT"},
		{"DoT URL", func(policy *probeEgressPolicy) { policy.AllowedDestinations[0].Endpoint = "https://1.1.1.1:853" }, "invalid fixed DoT"},
		{"DoT credentials", func(policy *probeEgressPolicy) { policy.AllowedDestinations[0].Endpoint = "user:password@1.1.1.1:853" }, "invalid fixed DoT"},
		{"DoT mismatch", func(policy *probeEgressPolicy) { policy.AllowedDestinations[0].Endpoint = "8.8.8.8:853" }, "does not match"},
		{"DoT SNI mismatch", func(policy *probeEgressPolicy) { policy.AllowedDestinations[0].ServerName = "other.example.com" }, "does not match"},
		{"DoT mixed fields", func(policy *probeEgressPolicy) { policy.AllowedDestinations[0].ProbeID = "canary" }, "mixes"},
		{"target digest", func(policy *probeEgressPolicy) {
			policy.AllowedDestinations[1].CatalogDigest = "sha256:" + strings.Repeat("0", 64)
		}, "digest"},
		{"target unknown", func(policy *probeEgressPolicy) { policy.AllowedDestinations[1].ProbeID = "unknown" }, "approved catalog probe"},
		{"target mixed fields", func(policy *probeEgressPolicy) { policy.AllowedDestinations[1].Endpoint = "1.1.1.1:443" }, "mixes"},
		{"note control", func(policy *probeEgressPolicy) { policy.Notes = []string{"bad\nnote"} }, "note"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			policy := cloneEgressPolicy(t, valid)
			test.mutate(&policy)
			err := validateProbeEgressPolicy(policy, fixture.catalog, fixture.config.doTUpstream, fixture.config.doTServerName, fixture.now)
			if err == nil || !strings.Contains(err.Error(), test.want) {
				t.Fatalf("validateProbeEgressPolicy() error = %v, want containing %q", err, test.want)
			}
		})
	}

	t.Run("content digest is not a stable evidence id", func(t *testing.T) {
		policy := cloneEgressPolicy(t, valid)
		policy.Enforcement.AttestationRef = "sha256:" + strings.Repeat("a", 64)
		if err := validateProbeEgressPolicy(policy, fixture.catalog, fixture.config.doTUpstream, fixture.config.doTServerName, fixture.now); err == nil {
			t.Fatal("SHA-256 runtime evidence unexpectedly accepted")
		}
	})
}

func newPreflightFixture(t *testing.T) preflightFixture {
	t.Helper()
	directory := t.TempDir()
	now := time.Now().UTC().Truncate(time.Second)
	catalog := commandTestCatalog(t)
	catalogRaw, err := json.Marshal(catalog)
	if err != nil {
		t.Fatal(err)
	}
	catalogPath := filepath.Join(directory, "catalog.json")
	if err := os.WriteFile(catalogPath, catalogRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	caRaw := testCertificatePEM(t)
	caPath := filepath.Join(directory, "dot-ca.pem")
	if err := os.WriteFile(caPath, caRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	upstream := netip.MustParseAddrPort("1.1.1.1:853")
	serverName := "resolver.example.com"
	policy := probeEgressPolicy{
		Schema: probeEgressPolicySchema, Revision: "candidate-20261018-v1",
		Approval:    probeEgressApproval{Status: "approved", Owner: "network-approver", ApprovedAt: now.Add(-time.Minute)},
		Enforcement: administrativeEgressExpectation{DesiredState: "enforced", ExpectedMode: "default-deny", AttestationRef: "evidence:nft-counter-20261018"},
		AllowedDestinations: []probeEgressDestination{
			{Schema: probeEgressDestinationSchema, Kind: egressDestinationFixedDoT, Endpoint: upstream.String(), ServerName: serverName},
			{Schema: probeEgressDestinationSchema, Kind: egressDestinationCatalogProbe, ProbeID: catalog.Probes[0].ID, CatalogDigest: catalog.Digest},
		},
		Notes: []string{"Local fixture with no network activity."},
	}
	policyRaw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	policyPath := filepath.Join(directory, "egress-policy.json")
	if err := os.WriteFile(policyPath, policyRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	value := preflightConfig{
		catalogPath: catalogPath, doTCAPath: caPath, egressPolicyPath: policyPath,
		doTUpstream: upstream, doTServerName: serverName,
		expectedCatalogSHA: rawSHA256(catalogRaw), expectedDoTCASHA: rawSHA256(caRaw), expectedEgressSHA: rawSHA256(policyRaw),
	}
	arguments := []string{
		"--catalog", value.catalogPath, "--dot-ca", value.doTCAPath,
		"--egress-policy", value.egressPolicyPath, "--dot-upstream", value.doTUpstream.String(),
		"--dot-server-name", value.doTServerName,
		"--expected-catalog-sha256", value.expectedCatalogSHA,
		"--expected-dot-ca-sha256", value.expectedDoTCASHA,
		"--expected-egress-policy-sha256", value.expectedEgressSHA,
	}
	return preflightFixture{now: now, catalog: catalog, policy: policy, config: value, arguments: arguments, policyPath: policyPath}
}

func rawSHA256(raw []byte) string {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:])
}

func cloneEgressPolicy(t *testing.T, policy probeEgressPolicy) probeEgressPolicy {
	t.Helper()
	raw, err := json.Marshal(policy)
	if err != nil {
		t.Fatal(err)
	}
	var clone probeEgressPolicy
	if err := json.Unmarshal(raw, &clone); err != nil {
		t.Fatal(err)
	}
	return clone
}

func replaceJSONOnce(t *testing.T, raw []byte, old, replacement string) []byte {
	t.Helper()
	updated := strings.Replace(string(raw), old, replacement, 1)
	if updated == string(raw) {
		t.Fatalf("JSON fixture does not contain %q", old)
	}
	return []byte(updated)
}

func snapshotPreflightFiles(t *testing.T, value preflightConfig) map[string][]byte {
	t.Helper()
	result := make(map[string][]byte)
	for _, path := range []string{value.catalogPath, value.doTCAPath, value.egressPolicyPath} {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		result[path] = raw
	}
	return result
}
