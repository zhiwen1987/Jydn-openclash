package restorecurrent

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"reflect"
	"sort"
	"strings"
	"testing"

	"chengwang/internal/probe"
)

func TestAdvisoryObservationBlockersAreExactStableAndImmutable(t *testing.T) {
	want := []BlockerCode{
		BlockerCandidateIDAttestationMissing,
		BlockerComposeRenderedAttestationMissing,
		BlockerComposeSourceAttestationMissing,
		BlockerExternalTimeAnchorMissing,
		BlockerImageIdentityAttestationMissing,
		BlockerLiveContainerIdentityNotObserved,
		BlockerLiveQuiesceNotAuthorized,
		BlockerProbeStatePathBindingUnproven,
		BlockerStateWriterQuiesceUnproven,
	}
	actual := append([]BlockerCode(nil), mandatoryBlockers...)
	sort.Slice(actual, func(i, j int) bool { return actual[i] < actual[j] })
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("blockers changed: got=%v want=%v", actual, want)
	}
	observation := Observation{blockers: actual}
	copy := observation.Blockers()
	copy[0] = "MUTATED"
	if observation.Blockers()[0] != want[0] {
		t.Fatal("caller mutated the observation blocker set")
	}
}

func TestIdentityBoundBlockersKeepExternalAttestationGap(t *testing.T) {
	want := []BlockerCode{
		BlockerCandidateIDAttestationMissing,
		BlockerComposeRenderedAttestationMissing,
		BlockerComposeSourceAttestationMissing,
		BlockerExternalTimeAnchorMissing,
		BlockerImageIdentityAttestationMissing,
		BlockerLiveContainerIdentityNotObserved,
		BlockerLiveQuiesceNotAuthorized,
		BlockerProbeStatePathBindingUnproven,
		BlockerStateWriterQuiesceUnproven,
	}
	actual := sortedBlockersForTest(mandatoryBlockers)
	if !reflect.DeepEqual(actual, want) {
		t.Fatalf("local identity removed a trust blocker: got=%v want=%v", actual, want)
	}
}

func sortedBlockersForTest(source []BlockerCode) []BlockerCode {
	value := append([]BlockerCode(nil), source...)
	sort.Slice(value, func(i, j int) bool { return value[i] < value[j] })
	return value
}

func TestOpenAdvisoryRejectsEveryUnsafeCandidatePathBeforeCollection(t *testing.T) {
	for _, candidate := range []string{"", "relative", "/", "/tmp/site", "/var/lib/chengwang-m2b-candidate", "/var/lib/chengwang-m2b-candidate/a/b", "/var/lib/chengwang-m2b-candidate/UPPER", "/var/lib/chengwang-m2b-candidate/site/"} {
		if _, err := OpenAdvisory(candidate); !errors.Is(err, ErrInvalid) {
			t.Fatalf("OpenAdvisory(%q) error=%v, want ErrInvalid", candidate, err)
		}
	}
}

func TestNilZeroClosedAndCopiedHandlesFailClosed(t *testing.T) {
	var nilHandle *Handle
	if _, err := nilHandle.Observation(); !errors.Is(err, ErrClosed) || !errors.Is(nilHandle.Verify(), ErrClosed) || nilHandle.Close() != nil {
		t.Fatal("nil handle did not fail closed")
	}
	zero := &Handle{}
	if _, err := zero.Observation(); !errors.Is(err, ErrClosed) || !errors.Is(zero.Verify(), ErrClosed) || zero.Close() != nil {
		t.Fatal("zero handle did not fail closed")
	}
	shared := &handleControl{closed: true}
	first, second := &Handle{control: shared}, &Handle{control: shared}
	if first.Close() != nil || second.Close() != nil {
		t.Fatal("copied handles were not idempotent")
	}
}

func TestValidateConfigurationAcceptsOnlyExactFixedBindings(t *testing.T) {
	root := "/var/lib/chengwang-m2b-candidate/site1"
	contents := validConfigurationContents(t, root)
	value, err := validateConfiguration(contents, root, "site1")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(value.projectName, "chengwang-m2b-probe-site1-") || !strings.HasSuffix(value.projectName, "-candidate") {
		t.Fatalf("unexpected project name %q", value.projectName)
	}
	if _, err := parseTestCatalog(contents.catalog); err != nil {
		t.Fatal(err)
	}

	mutations := map[string]func(*configurationContents){
		"env binding": func(c *configurationContents) {
			c.env = bytesReplace(c.env, root+"/config/catalog.json", root+"/config/other.json")
		},
		"catalog bytes": func(c *configurationContents) { c.catalog = append(append([]byte(nil), c.catalog...), ' ') },
		"ca bytes":      func(c *configurationContents) { c.ca = append(append([]byte(nil), c.ca...), '\n') },
		"policy bytes":  func(c *configurationContents) { c.policy = append(append([]byte(nil), c.policy...), '\n') },
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			copy := cloneContents(contents)
			mutate(&copy)
			if _, err := validateConfiguration(copy, root, "site1"); !errors.Is(err, ErrInvalid) {
				t.Fatalf("error=%v, want ErrInvalid", err)
			}
		})
	}
}

func TestCandidateIdentityBindsRootNonceProjectAndGeneration(t *testing.T) {
	root := "/var/lib/chengwang-m2b-candidate/site1"
	contents := validConfigurationContents(t, root)
	environment, err := validateConfiguration(contents, root, "site1")
	if err != nil {
		t.Fatal(err)
	}
	identity, err := parseCandidateIdentity(contents.identity, root, "site1", environment.projectName)
	if err != nil {
		t.Fatal(err)
	}
	if identity.CandidateID != deriveCandidateID(root, identity.GenesisNonce) || identity.IdentityGeneration != 1 {
		t.Fatalf("identity is not deterministically bound: %#v", identity)
	}
	sentinel := "SECRET_CANARY_identity"
	mutations := map[string]func([]byte) []byte{
		"root": func(raw []byte) []byte {
			return bytesReplace(raw, root, root+"-other")
		},
		"project": func(raw []byte) []byte {
			return bytesReplace(raw, environment.projectName, environment.projectName+"-other")
		},
		"generation": func(raw []byte) []byte {
			return bytesReplace(raw, `"identityGeneration":1`, `"identityGeneration":2`)
		},
		"unknown": func(raw []byte) []byte {
			return bytesReplace(raw, "}", `,"unknown":"`+sentinel+`"}`)
		},
		"duplicate_key": func(raw []byte) []byte {
			return bytesReplace(raw, "}", `,"schema":"`+sentinel+`"}`)
		},
		"trailing_token": func(raw []byte) []byte {
			return append(raw, []byte(` "`+sentinel+`"`)...)
		},
		"wrong_type": func(raw []byte) []byte {
			return bytesReplace(raw, `"identityGeneration":1`, `"identityGeneration":"`+sentinel+`"`)
		},
		"wrong_schema": func(raw []byte) []byte {
			return bytesReplace(raw, candidateIdentitySchemaV1, "chengwang.m2b-candidate-identity/v2")
		},
		"wrong_candidate_id": func(raw []byte) []byte {
			return bytesReplace(raw, identity.CandidateID, "candidate-ffffffffffffffffffffffffffffffff")
		},
		"wrong_instance": func(raw []byte) []byte {
			return bytesReplace(raw, `"instance":"site1"`, `"instance":"site2"`)
		},
		"wrong_service": func(raw []byte) []byte {
			return bytesReplace(raw, `"serviceName":"`+serviceName+`"`, `"serviceName":"other"`)
		},
		"wrong_state_mount_target": func(raw []byte) []byte {
			return bytesReplace(raw, `"stateMountTarget":"`+stateMountTarget+`"`, `"stateMountTarget":"/other"`)
		},
		"invalid_nonce": func(raw []byte) []byte {
			return bytesReplace(raw, identity.GenesisNonce, strings.Repeat("g", 64))
		},
		"all_zero_nonce": func(raw []byte) []byte {
			return bytesReplace(raw, identity.GenesisNonce, strings.Repeat("0", 64))
		},
	}
	for name, mutate := range mutations {
		t.Run(name, func(t *testing.T) {
			raw := append([]byte(nil), contents.identity...)
			raw = mutate(raw)
			_, err := parseCandidateIdentity(raw, root, "site1", environment.projectName)
			if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), sentinel) {
				t.Fatalf("unsafe identity was not rejected safely: %v", err)
			}
		})
	}
}

func TestEnvironmentParserRejectsUnknownDuplicateMissingAndSecretValues(t *testing.T) {
	root := "/var/lib/chengwang-m2b-candidate/site1"
	valid := validConfigurationContents(t, root)
	sentinel := "SECRET_CANARY_91d67d"
	cases := [][]byte{
		append(append([]byte(nil), valid.env...), []byte("UNKNOWN="+sentinel+"\n")...),
		append(append([]byte(nil), valid.env...), []byte(sentinel+"=x\n")...),
		append(append([]byte(nil), valid.env...), []byte("M2B_PROBE_RELEASE_ID="+sentinel+"\n")...),
		[]byte("M2B_PROBE_RELEASE_ID=" + sentinel + "\n"),
	}
	for _, raw := range cases {
		_, err := parseEnvironment(raw)
		if !errors.Is(err, ErrInvalid) {
			t.Fatalf("error=%v, want ErrInvalid", err)
		}
		if strings.Contains(err.Error(), sentinel) {
			t.Fatal("environment error leaked a secret value")
		}
	}
}

func TestPolicyRejectsDuplicateKeysAndUnapprovedClaims(t *testing.T) {
	for _, raw := range [][]byte{
		[]byte(`{"schema":"chengwang.probe-egress-policy/v1","schema":"chengwang.probe-egress-policy/v1","approval":{"status":"approved"},"enforcement":{"state":"enforced","runtimeEvidence":"receipt"}}`),
		[]byte(`{"schema":"chengwang.probe-egress-policy/v1","approval":{"status":"unapproved"},"enforcement":{"state":"enforced","runtimeEvidence":"receipt"}}`),
		[]byte(`{"schema":"chengwang.probe-egress-policy/v1","approval":{"status":"approved"},"enforcement":{"state":"blocked","runtimeEvidence":"receipt"}}`),
	} {
		if err := validatePolicy(raw); !errors.Is(err, ErrInvalid) {
			t.Fatalf("error=%v, want ErrInvalid", err)
		}
	}
}

func TestConfigurationErrorsNeverExposeRawSecretCanary(t *testing.T) {
	root := "/var/lib/chengwang-m2b-candidate/site1"
	contents := validConfigurationContents(t, root)
	sentinel := "SECRET_CANARY_bfa402"
	contents.ca = []byte(sentinel)
	_, err := validateConfiguration(contents, root, "site1")
	if err == nil || strings.Contains(err.Error(), sentinel) {
		t.Fatalf("secret-safe rejection failed: %v", err)
	}
}

func TestCatalogAndPolicyErrorsNeverExposeUntrustedTokens(t *testing.T) {
	sentinel := "SECRET_CANARY_38c911"
	for name, run := range map[string]func() error{
		"catalog trailing token": func() error {
			_, err := parseCandidateCatalog([]byte(`{"schema":"chengwang.probe-catalog/v1"} "` + sentinel + `"`))
			return err
		},
		"catalog unknown key": func() error {
			_, err := parseCandidateCatalog([]byte(`{"schema":"chengwang.probe-catalog/v1","` + sentinel + `":"x"}`))
			return err
		},
		"policy trailing token": func() error {
			return validatePolicy([]byte(`{"schema":"chengwang.probe-egress-policy/v1"} "` + sentinel + `"`))
		},
		"policy duplicate key": func() error {
			return validatePolicy([]byte(`{"schema":"chengwang.probe-egress-policy/v1","` + sentinel + `":1,"` + sentinel + `":2}`))
		},
	} {
		t.Run(name, func(t *testing.T) {
			err := run()
			if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), sentinel) {
				t.Fatalf("untrusted token was not rejected safely: %v", err)
			}
		})
	}
}

func TestDigestUsesPrefixedRawSHA256(t *testing.T) {
	raw := []byte("exact raw bytes\r\n")
	sum := sha256.Sum256(raw)
	want := "sha256:" + hex.EncodeToString(sum[:])
	if got := digest(raw); got != want {
		t.Fatalf("digest=%q want=%q", got, want)
	}
}

func validConfigurationContents(t *testing.T, root string) configurationContents {
	t.Helper()
	catalog := []byte(`{"schema":"chengwang.probe-catalog/v1","revision":"r1","agent":{"id":"observer","independence":"P1","advisoryOnly":true},"paths":[{"id":"direct","kind":"direct"}],"probes":[{"id":"example","pathId":"direct","kind":"https","host":"example.com","port":443,"requestPath":"/","method":"GET","expectedStatus":[200],"intervalSeconds":30,"timeoutSeconds":5,"ttlSeconds":60,"maxBodyBytes":1024}]}`)
	ca := []byte("-----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n")
	policy := []byte(`{"schema":"chengwang.probe-egress-policy/v1","revision":"r1","approval":{"status":"approved","owner":"ops","approvedAt":"2026-10-19T00:00:00Z"},"enforcement":{"state":"enforced","mode":"allowlist","runtimeEvidence":"receipt-1"},"allowedDestinations":[],"notes":[]}`)
	rootHash := sha256.Sum256([]byte(root))
	project := "chengwang-m2b-probe-" + strings.TrimPrefix(root, "/var/lib/chengwang-m2b-candidate/") + "-" + hex.EncodeToString(rootHash[:])[:12] + "-candidate"
	values := map[string]string{
		"M2B_PROBE_RELEASE_ID": "release-20261019", "M2B_PROBE_PROJECT_NAME": project,
		"M2B_PROBE_CANDIDATE_ROOT": root, "M2B_PROBE_CATALOG_FILE": root + "/config/catalog.json",
		"M2B_PROBE_DOT_CA_FILE": root + "/config/dot-ca.pem", "M2B_PROBE_EGRESS_POLICY_FILE": root + "/config/egress-policy.json",
		"M2B_PROBE_SPOOL_DIR": root + "/probe-state/probe-spool", "M2B_PROBE_LEDGER_DIR": root + "/probe-state/probe-ledger",
		"M2B_PROBE_DOT_UPSTREAM": "1.1.1.1:853", "M2B_PROBE_DOT_SERVER_NAME": "cloudflare-dns.com",
		"M2B_PROBE_CATALOG_SHA256": rawHexDigest(catalog), "M2B_PROBE_DOT_CA_SHA256": rawHexDigest(ca),
		"M2B_PROBE_EGRESS_POLICY_SHA256": rawHexDigest(policy), "M2B_PROBE_ACTIVE_APPROVAL": "approved-candidate-only",
	}
	var builder strings.Builder
	for _, key := range allowedEnvironmentKeys {
		builder.WriteString(key + "=" + values[key] + "\n")
	}
	nonce := strings.Repeat("1", 64)
	candidateID := deriveCandidateID(root, nonce)
	instance := root[strings.LastIndex(root, "/")+1:]
	identity := []byte(`{"schema":"` + candidateIdentitySchemaV1 + `","candidateId":"` + candidateID + `","instance":"` + instance + `","candidateRoot":"` + root + `","projectName":"` + project + `","serviceName":"` + serviceName + `","stateMountTarget":"` + stateMountTarget + `","identityGeneration":1,"genesisNonce":"` + nonce + `"}`)
	return configurationContents{env: []byte(builder.String()), catalog: catalog, ca: ca, policy: policy, identity: identity}
}

func parseTestCatalog(raw []byte) (string, error) {
	// Keep this helper local so the test proves the exact fixture is accepted by
	// the same public parser used by OpenAdvisory without exposing its contents.
	value, err := probe.ParseCatalogBytes(raw)
	if err != nil {
		return "", err
	}
	return value.Digest, nil
}

func cloneContents(value configurationContents) configurationContents {
	return configurationContents{
		env: append([]byte(nil), value.env...), catalog: append([]byte(nil), value.catalog...),
		ca: append([]byte(nil), value.ca...), policy: append([]byte(nil), value.policy...),
		identity: append([]byte(nil), value.identity...),
	}
}

func bytesReplace(raw []byte, old, replacement string) []byte {
	return []byte(strings.Replace(string(raw), old, replacement, 1))
}
