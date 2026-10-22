package verifier_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"testing"
	"time"

	verifier "chengwang-image-verifier"
)

const (
	artifactDigest = "sha256:a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf"
	rootDigest     = "sha256:4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c"
	logID          = "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d"
	issuer         = "https://token.actions.githubusercontent.com"
	san            = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"
)

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile("testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func digest(raw []byte) string {
	h := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(h[:])
}

func expected(kind verifier.Kind) verifier.Expected {
	e := verifier.Expected{ArtifactSHA256: artifactDigest, TrustedRootSHA256: rootDigest,
		LogID: logID, Issuer: issuer, SAN: san, Kind: kind}
	if kind == verifier.KindDSSE {
		e.SubjectName = "a.txt"
		e.PredicateType = "https://slsa.dev/provenance/v1"
	}
	return e
}

func bundleName(kind verifier.Kind) string {
	if kind == verifier.KindDSSE {
		return "dsse.sigstore.json"
	}
	return "message.sigstore.json"
}

func requireFailure(t *testing.T, ctx context.Context, e verifier.Expected, b, r []byte, want error) {
	t.Helper()
	got, err := verifier.Verify(ctx, e, b, r)
	if !errors.Is(err, want) {
		t.Fatalf("error = %v, want %v", err, want)
	}
	if want == verifier.ErrInvalid && err != verifier.ErrInvalid {
		t.Fatalf("invalid result leaked variable error: %v", err)
	}
	if !reflect.DeepEqual(got, verifier.Result{}) {
		t.Fatal("failure returned nonzero Result")
	}
	if got.Verified() || got.ArtifactSHA256() != "" || got.BundleSHA256() != "" || got.TrustedRootSHA256() != "" {
		t.Fatal("failure exposed a successful verification claim")
	}
}

func verifySuccess(t *testing.T, kind verifier.Kind) {
	t.Helper()
	b, r := fixture(t, bundleName(kind)), fixture(t, "trusted-root.json")
	e := expected(kind)
	result, err := verifier.Verify(context.Background(), e, b, r)
	if err != nil {
		t.Fatalf("official fixture rejected: %v", err)
	}
	if !result.Verified() {
		t.Fatal("successful verification not marked verified")
	}
	if result.Boundary() != "ADVISORY_SIGSTORE_BUNDLE_VERIFIED" || result.Authorization() != "BLOCKED" {
		t.Fatalf("unexpected trust boundary or authorization: %q / %q", result.Boundary(), result.Authorization())
	}
	if result.ArtifactSHA256() != artifactDigest || result.BundleSHA256() != digest(b) || result.TrustedRootSHA256() != rootDigest {
		t.Fatal("successful result does not bind the original artifact, bundle, and root")
	}
}

func TestVerifyMessageBundle(t *testing.T) { verifySuccess(t, verifier.KindMessageSignature) }
func TestVerifyDSSEBundle(t *testing.T)    { verifySuccess(t, verifier.KindDSSE) }

func TestOfficialFixtureBytes(t *testing.T) {
	for _, tc := range []struct {
		name, sha string
		length    int
	}{
		{"artifact.txt", artifactDigest, 109},
		{"message.sigstore.json", "sha256:82382358bdf586d1a184820ac0d0ff06eb737f459fe03baebbbd2c76e80b54a9", 10054},
		{"dsse.sigstore.json", "sha256:0b205ad5900e2f8009cb97a1e97c38e7759a64e4356ac97797bf3cbf7d7551c7", 11737},
		{"trusted-root.json", rootDigest, 7014},
	} {
		t.Run(tc.name, func(t *testing.T) {
			raw := fixture(t, tc.name)
			if len(raw) != tc.length || digest(raw) != tc.sha {
				t.Fatal("official raw fixture bytes changed")
			}
		})
	}
}

func object(t *testing.T, raw []byte) map[string]any {
	t.Helper()
	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatal(err)
	}
	return obj
}

func marshal(t *testing.T, obj any) []byte {
	t.Helper()
	b, err := json.Marshal(obj)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func mapAt(obj map[string]any, keys ...string) map[string]any {
	for _, key := range keys {
		obj = obj[key].(map[string]any)
	}
	return obj
}

func entry(obj map[string]any) map[string]any {
	return mapAt(obj, "verificationMaterial")["tlogEntries"].([]any)[0].(map[string]any)
}

func flipBase64(t *testing.T, value string) string {
	t.Helper()
	b, err := base64.StdEncoding.DecodeString(value)
	if err != nil || len(b) == 0 {
		t.Fatalf("bad fixture base64: %v", err)
	}
	b[len(b)-1] ^= 1
	return base64.StdEncoding.EncodeToString(b)
}

func TestRejectCryptographicTampering(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			for _, name := range []string{"signature", "artifact", "certificate", "issuer", "san", "set", "sct", "checkpoint", "proof", "log", "canonicalized_body", "missing_set", "missing_proof", "missing_checkpoint", "empty_tlog", "root"} {
				t.Run(name, func(t *testing.T) {
					b, r := fixture(t, bundleName(kind)), fixture(t, "trusted-root.json")
					e, obj := expected(kind), object(t, b)
					switch name {
					case "signature":
						if kind == verifier.KindDSSE {
							s := mapAt(obj, "dsseEnvelope")["signatures"].([]any)[0].(map[string]any)
							s["sig"] = flipBase64(t, s["sig"].(string))
						} else {
							s := mapAt(obj, "messageSignature")
							s["signature"] = flipBase64(t, s["signature"].(string))
						}
					case "artifact":
						e.ArtifactSHA256 = "sha256:" + strings.Repeat("1", 64)
					case "issuer":
						e.Issuer = "https://token.actions.githubusercontent.com.attacker.invalid"
					case "san":
						e.SAN += "/attacker"
					case "certificate":
						c := mapAt(obj, "verificationMaterial", "certificate")
						c["rawBytes"] = flipBase64(t, c["rawBytes"].(string))
					case "set":
						s := mapAt(entry(obj), "inclusionPromise")
						s["signedEntryTimestamp"] = flipBase64(t, s["signedEntryTimestamp"].(string))
					case "sct":
						// Replace the trusted CT key with a different valid official CT key;
						// the leaf certificate and Fulcio roots remain unchanged.
						root := object(t, r)
						logs := root["ctlogs"].([]any)
						mapAt(logs[1].(map[string]any), "publicKey")["rawBytes"] = mapAt(logs[0].(map[string]any), "publicKey")["rawBytes"]
						r = marshal(t, root)
						e.TrustedRootSHA256 = digest(r)
					case "checkpoint":
						c := mapAt(entry(obj), "inclusionProof", "checkpoint")
						env := c["envelope"].(string)
						idx := strings.LastIndex(strings.TrimSpace(env), " ")
						c["envelope"] = env[:idx+1] + flipBase64(t, strings.TrimSpace(env[idx+1:])) + "\n"
					case "proof":
						p := mapAt(entry(obj), "inclusionProof")
						hashes := p["hashes"].([]any)
						hashes[0] = flipBase64(t, hashes[0].(string))
					case "log":
						e.LogID = strings.Repeat("1", 64)
					case "canonicalized_body":
						entry(obj)["canonicalizedBody"] = flipBase64(t, entry(obj)["canonicalizedBody"].(string))
					case "missing_set":
						delete(entry(obj), "inclusionPromise")
					case "missing_proof":
						delete(entry(obj), "inclusionProof")
					case "missing_checkpoint":
						delete(mapAt(entry(obj), "inclusionProof"), "checkpoint")
					case "empty_tlog":
						mapAt(obj, "verificationMaterial")["tlogEntries"] = []any{}
					case "root":
						root := object(t, r)
						root["certificateAuthorities"] = []any{}
						r = marshal(t, root)
						e.TrustedRootSHA256 = digest(r)
					}
					if name != "sct" && name != "root" {
						b = marshal(t, obj)
					}
					requireFailure(t, context.Background(), e, b, r, verifier.ErrInvalid)
				})
			}
		})
	}
}

func TestRejectPolicyMismatch(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			for _, name := range []string{"empty_artifact", "bare_artifact", "uppercase_artifact", "wrong_artifact_algorithm", "short_artifact", "empty_root", "wrong_root", "uppercase_root", "empty_log", "uppercase_log", "short_log", "empty_issuer", "empty_san", "regex_issuer", "regex_san", "wrong_kind", "unknown_kind", "empty_kind", "wrong_subject", "wrong_predicate"} {
				t.Run(name, func(t *testing.T) {
					e := expected(kind)
					switch name {
					case "empty_artifact":
						e.ArtifactSHA256 = ""
					case "bare_artifact":
						e.ArtifactSHA256 = strings.TrimPrefix(e.ArtifactSHA256, "sha256:")
					case "uppercase_artifact":
						e.ArtifactSHA256 = strings.ToUpper(e.ArtifactSHA256)
					case "wrong_artifact_algorithm":
						e.ArtifactSHA256 = "sha512:" + strings.Repeat("0", 128)
					case "short_artifact":
						e.ArtifactSHA256 = "sha256:00"
					case "empty_root":
						e.TrustedRootSHA256 = ""
					case "wrong_root":
						e.TrustedRootSHA256 = "sha256:" + strings.Repeat("0", 64)
					case "uppercase_root":
						e.TrustedRootSHA256 = strings.ToUpper(e.TrustedRootSHA256)
					case "empty_log":
						e.LogID = ""
					case "uppercase_log":
						e.LogID = strings.ToUpper(e.LogID)
					case "short_log":
						e.LogID = "00"
					case "empty_issuer":
						e.Issuer = ""
					case "empty_san":
						e.SAN = ""
					case "regex_issuer":
						e.Issuer = "https://.*"
					case "regex_san":
						e.SAN = ".*"
					case "wrong_kind":
						if kind == verifier.KindDSSE {
							e.Kind = verifier.KindMessageSignature
							e.SubjectName = ""
							e.PredicateType = ""
						} else {
							e.Kind = verifier.KindDSSE
							e.SubjectName = "a.txt"
							e.PredicateType = "https://slsa.dev/provenance/v1"
						}
					case "unknown_kind":
						e.Kind = verifier.Kind("unknown")
					case "empty_kind":
						e.Kind = ""
					case "wrong_subject":
						e.SubjectName = "wrong-artifact"
					case "wrong_predicate":
						e.PredicateType = "https://attacker.invalid/predicate"
					}
					requireFailure(t, context.Background(), e, fixture(t, bundleName(kind)), fixture(t, "trusted-root.json"), verifier.ErrInvalid)
				})
			}
		})
	}
}

func TestRejectJSONAmbiguity(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			for _, name := range []string{"bundle_empty", "bundle_null", "bundle_array", "bundle_truncated", "bundle_trailing", "bundle_unknown", "bundle_nested_unknown", "bundle_duplicate", "bundle_alias", "bundle_media_alias", "bundle_bom", "bundle_oversize", "root_empty", "root_null", "root_array", "root_truncated", "root_trailing", "root_unknown", "root_nested_unknown", "root_duplicate", "root_alias", "root_oversize", "both_signature_types", "unknown_version", "legacy_version"} {
				t.Run(name, func(t *testing.T) {
					b, r := fixture(t, bundleName(kind)), fixture(t, "trusted-root.json")
					e := expected(kind)
					obj := object(t, b)
					switch name {
					case "bundle_empty":
						b = nil
					case "bundle_null":
						b = []byte("null")
					case "bundle_array":
						b = []byte("[]")
					case "bundle_truncated":
						b = b[:len(b)/2]
					case "bundle_trailing":
						b = append(b, []byte(" {}")...)
					case "bundle_unknown":
						obj["unrecognized"] = true
						b = marshal(t, obj)
					case "bundle_nested_unknown":
						mapAt(obj, "verificationMaterial", "certificate")["unrecognized"] = true
						b = marshal(t, obj)
					case "bundle_duplicate":
						b = append([]byte(`{"mediaType":"application/vnd.dev.sigstore.bundle.v0.3+json",`), b[1:]...)
					case "bundle_alias":
						c := mapAt(obj, "verificationMaterial", "certificate")
						c["raw_bytes"] = c["rawBytes"]
						delete(c, "rawBytes")
						b = marshal(t, obj)
					case "bundle_media_alias":
						obj["media_type"] = obj["mediaType"]
						delete(obj, "mediaType")
						b = marshal(t, obj)
					case "bundle_bom":
						b = append([]byte{0xef, 0xbb, 0xbf}, b...)
					case "bundle_oversize":
						b = append(b, bytes.Repeat([]byte(" "), verifier.MaxBundleBytes)...)
					case "root_empty":
						r = nil
					case "root_null":
						r = []byte("null")
					case "root_array":
						r = []byte("[]")
					case "root_truncated":
						r = r[:len(r)/2]
					case "root_trailing":
						r = append(r, []byte(" {}")...)
					case "root_unknown":
						root := object(t, r)
						root["unrecognized"] = true
						r = marshal(t, root)
					case "root_nested_unknown":
						root := object(t, r)
						root["ctlogs"].([]any)[0].(map[string]any)["unrecognized"] = true
						r = marshal(t, root)
					case "root_duplicate":
						r = append([]byte(`{"mediaType":"application/vnd.dev.sigstore.trustedroot+json;version=0.1",`), r[1:]...)
					case "root_alias":
						root := object(t, r)
						root["media_type"] = root["mediaType"]
						delete(root, "mediaType")
						r = marshal(t, root)
					case "root_oversize":
						r = append(r, bytes.Repeat([]byte(" "), verifier.MaxRootBytes)...)
					case "both_signature_types":
						other := object(t, fixture(t, "message.sigstore.json"))
						if kind == verifier.KindDSSE {
							obj["messageSignature"] = other["messageSignature"]
						} else {
							obj["dsseEnvelope"] = object(t, fixture(t, "dsse.sigstore.json"))["dsseEnvelope"]
						}
						b = marshal(t, obj)
					case "unknown_version":
						obj["mediaType"] = "application/vnd.dev.sigstore.bundle.v0.4+json"
						b = marshal(t, obj)
					case "legacy_version":
						obj["mediaType"] = "application/vnd.dev.sigstore.bundle+json;version=0.1"
						b = marshal(t, obj)
					}
					if strings.HasPrefix(name, "root_") {
						e.TrustedRootSHA256 = digest(r)
					}
					requireFailure(t, context.Background(), e, b, r, verifier.ErrInvalid)
				})
			}
		})
	}
}

func TestRejectMalformedDSSEStatements(t *testing.T) {
	for _, name := range []string{"payload_type", "payload_base64", "statement_type", "duplicate_subject", "empty_subject", "wrong_subject", "wrong_digest", "extra_digest", "predicate_type", "unknown_statement_field", "duplicate_statement_field", "trailing_statement", "two_signatures", "zero_signatures", "missing_subject_policy", "missing_predicate_policy"} {
		t.Run(name, func(t *testing.T) {
			b, r := fixture(t, "dsse.sigstore.json"), fixture(t, "trusted-root.json")
			e, obj := expected(verifier.KindDSSE), object(t, b)
			env := mapAt(obj, "dsseEnvelope")
			raw, err := base64.StdEncoding.DecodeString(env["payload"].(string))
			if err != nil {
				t.Fatal(err)
			}
			stmt := object(t, raw)
			mutatedStatement := true
			switch name {
			case "payload_type":
				env["payloadType"] = "application/json"
				mutatedStatement = false
			case "payload_base64":
				env["payload"] = "!invalid!"
				mutatedStatement = false
			case "statement_type":
				stmt["_type"] = "https://in-toto.io/Statement/v0.1"
			case "duplicate_subject":
				stmt["subject"] = append(stmt["subject"].([]any), stmt["subject"].([]any)[0])
			case "empty_subject":
				stmt["subject"] = []any{}
			case "wrong_subject":
				stmt["subject"].([]any)[0].(map[string]any)["name"] = "wrong"
			case "wrong_digest":
				mapAt(stmt["subject"].([]any)[0].(map[string]any), "digest")["sha256"] = strings.Repeat("0", 64)
			case "extra_digest":
				mapAt(stmt["subject"].([]any)[0].(map[string]any), "digest")["sha512"] = strings.Repeat("0", 128)
			case "predicate_type":
				stmt["predicateType"] = "https://attacker.invalid/provenance"
			case "unknown_statement_field":
				stmt["unrecognized"] = true
			case "duplicate_statement_field":
				raw = append([]byte(`{"_type":"https://in-toto.io/Statement/v1",`), raw[1:]...)
				mutatedStatement = false
				env["payload"] = base64.StdEncoding.EncodeToString(raw)
			case "trailing_statement":
				env["payload"] = base64.StdEncoding.EncodeToString(append(raw, []byte(" {}")...))
				mutatedStatement = false
			case "two_signatures":
				env["signatures"] = append(env["signatures"].([]any), env["signatures"].([]any)[0])
				mutatedStatement = false
			case "zero_signatures":
				env["signatures"] = []any{}
				mutatedStatement = false
			case "missing_subject_policy":
				e.SubjectName = ""
				mutatedStatement = false
			case "missing_predicate_policy":
				e.PredicateType = ""
				mutatedStatement = false
			}
			if mutatedStatement {
				env["payload"] = base64.StdEncoding.EncodeToString(marshal(t, stmt))
			}
			requireFailure(t, context.Background(), e, marshal(t, obj), r, verifier.ErrInvalid)
		})
	}
}

func TestCancellationAndDeadline(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			t.Run("canceled", func(t *testing.T) {
				ctx, cancel := context.WithCancel(context.Background())
				cancel()
				requireFailure(t, ctx, expected(kind), fixture(t, bundleName(kind)), fixture(t, "trusted-root.json"), context.Canceled)
			})
			t.Run("deadline", func(t *testing.T) {
				ctx, cancel := context.WithDeadline(context.Background(), time.Now().Add(-time.Second))
				defer cancel()
				requireFailure(t, ctx, expected(kind), fixture(t, bundleName(kind)), fixture(t, "trusted-root.json"), context.DeadlineExceeded)
			})
		})
	}
}

func TestZeroResultHasNoVerificationAuthority(t *testing.T) {
	var result verifier.Result
	if result.Verified() || result.Authorization() != "BLOCKED" || result.ArtifactSHA256() != "" || result.BundleSHA256() != "" || result.TrustedRootSHA256() != "" {
		t.Fatal("zero result gained verification or authorization authority")
	}
}

func TestRekorGlobalAndShardIndexes(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			b, r := fixture(t, bundleName(kind)), fixture(t, "trusted-root.json")
			obj := object(t, b)
			global, err := strconv.ParseInt(entry(obj)["logIndex"].(string), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			shard, err := strconv.ParseInt(mapAt(entry(obj), "inclusionProof")["logIndex"].(string), 10, 64)
			if err != nil {
				t.Fatal(err)
			}
			if global == shard || shard <= 0 {
				t.Fatal("fixture no longer exercises distinct global and shard-local indexes")
			}
			t.Run("distinct_original_indexes_verify", func(t *testing.T) { verifySuccess(t, kind) })
			t.Run("tampered_global_index", func(t *testing.T) {
				modified := object(t, b)
				entry(modified)["logIndex"] = strconv.FormatInt(global+1, 10)
				requireFailure(t, context.Background(), expected(kind), marshal(t, modified), r, verifier.ErrInvalid)
			})
			t.Run("tampered_shard_index_in_bounds", func(t *testing.T) {
				modified := object(t, b)
				// Stay inside the original tree to require proof verification, rather
				// than merely fail an index >= tree-size range check.
				mapAt(entry(modified), "inclusionProof")["logIndex"] = strconv.FormatInt(shard-1, 10)
				requireFailure(t, context.Background(), expected(kind), marshal(t, modified), r, verifier.ErrInvalid)
			})
		})
	}
}

func TestExactByteLimits(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			for _, target := range []string{"bundle", "root", "both"} {
				t.Run(target, func(t *testing.T) {
					b, r := fixture(t, bundleName(kind)), fixture(t, "trusted-root.json")
					if target != "root" {
						b = append(b, bytes.Repeat([]byte(" "), verifier.MaxBundleBytes-len(b))...)
					}
					if target != "bundle" {
						r = append(r, bytes.Repeat([]byte(" "), verifier.MaxRootBytes-len(r))...)
					}
					e := expected(kind)
					e.TrustedRootSHA256 = digest(r)
					result, err := verifier.Verify(context.Background(), e, b, r)
					if err != nil || !result.Verified() || result.BundleSHA256() != digest(b) || result.TrustedRootSHA256() != digest(r) || result.Authorization() != "BLOCKED" {
						t.Fatalf("valid official materials padded to inclusive byte limit failed: %v", err)
					}
					if target != "root" {
						requireFailure(t, context.Background(), e, append(bytes.Clone(b), ' '), r, verifier.ErrInvalid)
					}
					if target != "bundle" {
						tooLarge := append(bytes.Clone(r), ' ')
						e.TrustedRootSHA256 = digest(tooLarge)
						requireFailure(t, context.Background(), e, b, tooLarge, verifier.ErrInvalid)
					}
				})
			}
		})
	}
}

func TestRejectProofMixingAndEntryBudgets(t *testing.T) {
	for _, kind := range []verifier.Kind{verifier.KindMessageSignature, verifier.KindDSSE} {
		t.Run(string(kind), func(t *testing.T) {
			for _, name := range []string{"other_entry_proof", "other_entry_set", "other_entry_body", "duplicate_entry", "proof_negative_index", "global_negative_index", "proof_index_outside_tree", "tree_size_zero", "proof_root_short", "proof_hash_short", "proof_hashes_64", "proof_no_hashes", "checkpoint_oversize", "set_oversize", "body_oversize", "certificate_oversize", "signature_oversize", "unexpected_timestamp_material", "proof_unknown_field", "entry_unknown_field", "checkpoint_unknown_field", "body_unknown_field", "entry_integer_overflow", "log_id_short"} {
				t.Run(name, func(t *testing.T) {
					b, r := fixture(t, bundleName(kind)), fixture(t, "trusted-root.json")
					obj := object(t, b)
					current := entry(obj)
					proof := mapAt(current, "inclusionProof")
					otherKind := verifier.KindDSSE
					if kind == verifier.KindDSSE {
						otherKind = verifier.KindMessageSignature
					}
					other := entry(object(t, fixture(t, bundleName(otherKind))))
					switch name {
					case "other_entry_proof":
						current["inclusionProof"] = other["inclusionProof"]
					case "other_entry_set":
						current["inclusionPromise"] = other["inclusionPromise"]
					case "other_entry_body":
						current["canonicalizedBody"] = other["canonicalizedBody"]
					case "duplicate_entry":
						mapAt(obj, "verificationMaterial")["tlogEntries"] = []any{current, current}
					case "proof_negative_index":
						proof["logIndex"] = "-1"
					case "global_negative_index":
						current["logIndex"] = "-1"
					case "proof_index_outside_tree":
						proof["logIndex"] = proof["treeSize"]
					case "tree_size_zero":
						proof["treeSize"] = "0"
					case "proof_root_short":
						proof["rootHash"] = base64.StdEncoding.EncodeToString(make([]byte, 31))
					case "proof_hash_short":
						proof["hashes"].([]any)[0] = base64.StdEncoding.EncodeToString(make([]byte, 31))
					case "proof_hashes_64":
						hashes := make([]any, 64)
						for i := range hashes {
							hashes[i] = base64.StdEncoding.EncodeToString(make([]byte, 32))
						}
						proof["hashes"] = hashes
					case "proof_no_hashes":
						proof["hashes"] = []any{}
					case "checkpoint_oversize":
						mapAt(proof, "checkpoint")["envelope"] = strings.Repeat("x", 16385)
					case "set_oversize":
						mapAt(current, "inclusionPromise")["signedEntryTimestamp"] = base64.StdEncoding.EncodeToString(make([]byte, 16385))
					case "body_oversize":
						current["canonicalizedBody"] = base64.StdEncoding.EncodeToString(bytes.Repeat([]byte(" "), (256<<10)+1))
					case "certificate_oversize":
						mapAt(obj, "verificationMaterial", "certificate")["rawBytes"] = base64.StdEncoding.EncodeToString(make([]byte, 16385))
					case "signature_oversize":
						if kind == verifier.KindDSSE {
							mapAt(obj, "dsseEnvelope")["signatures"].([]any)[0].(map[string]any)["sig"] = base64.StdEncoding.EncodeToString(make([]byte, 16385))
						} else {
							mapAt(obj, "messageSignature")["signature"] = base64.StdEncoding.EncodeToString(make([]byte, 16385))
						}
					case "unexpected_timestamp_material":
						mapAt(obj, "verificationMaterial")["timestampVerificationData"] = map[string]any{"rfc3161Timestamps": []any{}}
					case "proof_unknown_field":
						proof["unrecognized"] = true
					case "entry_unknown_field":
						current["unrecognized"] = true
					case "checkpoint_unknown_field":
						mapAt(proof, "checkpoint")["unrecognized"] = true
					case "body_unknown_field":
						raw, _ := base64.StdEncoding.DecodeString(current["canonicalizedBody"].(string))
						body := object(t, raw)
						body["unrecognized"] = true
						current["canonicalizedBody"] = base64.StdEncoding.EncodeToString(marshal(t, body))
					case "entry_integer_overflow":
						current["logIndex"] = "9223372036854775808"
					case "log_id_short":
						mapAt(current, "logId")["keyId"] = base64.StdEncoding.EncodeToString(make([]byte, 31))
					}
					requireFailure(t, context.Background(), expected(kind), marshal(t, obj), r, verifier.ErrInvalid)
				})
			}
		})
	}
}

func TestRejectRootBudgetsAndDuplicateLogIDs(t *testing.T) {
	for _, name := range []string{"duplicate_rekor_id", "duplicate_ct_id", "rekor_logs_9", "ct_logs_9", "certificate_authorities_9", "timestamp_authorities_9", "cert_chain_9", "certificate_oversize", "public_key_oversize", "rekor_unknown_field", "ct_unknown_field", "certificate_unknown_field", "root_nested_duplicate", "root_escaped_duplicate"} {
		t.Run(name, func(t *testing.T) {
			r := fixture(t, "trusted-root.json")
			obj := object(t, r)
			switch name {
			case "duplicate_rekor_id":
				logs := obj["tlogs"].([]any)
				obj["tlogs"] = append(logs, logs[0])
			case "duplicate_ct_id":
				logs := obj["ctlogs"].([]any)
				obj["ctlogs"] = append(logs, logs[0])
			case "rekor_logs_9", "ct_logs_9":
				key := "tlogs"
				if name == "ct_logs_9" {
					key = "ctlogs"
				}
				original := obj[key].([]any)[0]
				logs := make([]any, 9)
				for i := range logs {
					item := object(t, marshal(t, original))
					id := make([]byte, 32)
					id[31] = byte(i)
					mapAt(item, "logId")["keyId"] = base64.StdEncoding.EncodeToString(id)
					logs[i] = item
				}
				obj[key] = logs
			case "certificate_authorities_9", "timestamp_authorities_9":
				authorities := make([]any, 9)
				for i := range authorities {
					authorities[i] = obj["certificateAuthorities"].([]any)[0]
				}
				key := "certificateAuthorities"
				if name == "timestamp_authorities_9" {
					key = "timestampAuthorities"
				}
				obj[key] = authorities
			case "cert_chain_9":
				chain := mapAt(obj["certificateAuthorities"].([]any)[0].(map[string]any), "certChain")
				certs := make([]any, 9)
				for i := range certs {
					certs[i] = chain["certificates"].([]any)[0]
				}
				chain["certificates"] = certs
			case "certificate_oversize":
				mapAt(obj["certificateAuthorities"].([]any)[0].(map[string]any), "certChain")["certificates"].([]any)[0].(map[string]any)["rawBytes"] = base64.StdEncoding.EncodeToString(make([]byte, 16385))
			case "public_key_oversize":
				mapAt(obj["tlogs"].([]any)[0].(map[string]any), "publicKey")["rawBytes"] = base64.StdEncoding.EncodeToString(make([]byte, 16385))
			case "rekor_unknown_field":
				obj["tlogs"].([]any)[0].(map[string]any)["unrecognized"] = true
			case "ct_unknown_field":
				obj["ctlogs"].([]any)[0].(map[string]any)["unrecognized"] = true
			case "certificate_unknown_field":
				mapAt(obj["certificateAuthorities"].([]any)[0].(map[string]any), "certChain")["certificates"].([]any)[0].(map[string]any)["unrecognized"] = true
			case "root_nested_duplicate":
				r = bytes.Replace(r, []byte(`"rawBytes":`), []byte(`"rawBytes":"AA==","rawBytes":`), 1)
			case "root_escaped_duplicate":
				r = append([]byte(`{"media\u0054ype":"application/vnd.dev.sigstore.trustedroot+json;version=0.1",`), r[1:]...)
			}
			if name != "root_nested_duplicate" && name != "root_escaped_duplicate" {
				r = marshal(t, obj)
			}
			e := expected(verifier.KindMessageSignature)
			e.TrustedRootSHA256 = digest(r)
			requireFailure(t, context.Background(), e, fixture(t, "message.sigstore.json"), r, verifier.ErrInvalid)
		})
	}
}

func TestRejectJSONResourceExhaustion(t *testing.T) {
	for _, target := range []string{"bundle", "root", "rekor_body", "dsse_payload"} {
		t.Run(target, func(t *testing.T) {
			for _, budget := range []string{"depth", "nodes", "invalid_utf8", "lone_surrogate", "escaped_duplicate"} {
				t.Run(budget, func(t *testing.T) {
					var bad []byte
					switch budget {
					case "depth":
						bad = []byte(`{"nested":` + strings.Repeat(`{"x":`, 40) + `true` + strings.Repeat(`}`, 40) + `}`)
					case "nodes":
						bad = []byte(`{"nodes":[` + strings.Repeat(`true,`, 9000) + `true]}`)
					case "invalid_utf8":
						bad = []byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}
					case "lone_surrogate":
						bad = []byte(`{"x":"\ud800"}`)
					case "escaped_duplicate":
						bad = []byte(`{"same":true,"s\u0061me":false}`)
					}
					kind := verifier.KindMessageSignature
					if target == "dsse_payload" {
						kind = verifier.KindDSSE
					}
					b, r := fixture(t, bundleName(kind)), fixture(t, "trusted-root.json")
					e := expected(kind)
					switch target {
					case "bundle":
						b = bad
					case "root":
						r = bad
						e.TrustedRootSHA256 = digest(r)
					case "rekor_body":
						obj := object(t, b)
						entry(obj)["canonicalizedBody"] = base64.StdEncoding.EncodeToString(bad)
						b = marshal(t, obj)
					case "dsse_payload":
						obj := object(t, b)
						mapAt(obj, "dsseEnvelope")["payload"] = base64.StdEncoding.EncodeToString(bad)
						b = marshal(t, obj)
					}
					requireFailure(t, context.Background(), e, b, r, verifier.ErrInvalid)
				})
			}
		})
	}
}
