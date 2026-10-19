package restorecurrent

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"path"
	"reflect"
	"sort"
	"strconv"
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

func TestLocalReleaseBindsExactBytesSemanticsAndKeepsAllBlockers(t *testing.T) {
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
	digests, err := validateLocalRelease(contents, environment, identity)
	if err != nil {
		t.Fatal(err)
	}
	if digests.ComposeSourceSHA256 != digest(contents.composeSource) || digests.ComposeRenderedSHA256 != digest(contents.composeJSON) ||
		digests.LocalBindingSHA256 != digest(contents.composeBinding) || !strings.HasPrefix(digests.RenderedSemanticSHA256, "sha256:") {
		t.Fatalf("local release digests are incomplete: %#v", digests)
	}
	if !reflect.DeepEqual(sortedBlockersForTest(mandatoryBlockers), []BlockerCode{
		BlockerCandidateIDAttestationMissing, BlockerComposeRenderedAttestationMissing, BlockerComposeSourceAttestationMissing,
		BlockerExternalTimeAnchorMissing, BlockerImageIdentityAttestationMissing, BlockerLiveContainerIdentityNotObserved,
		BlockerLiveQuiesceNotAuthorized, BlockerProbeStatePathBindingUnproven, BlockerStateWriterQuiesceUnproven,
	}) {
		t.Fatal("local release binding changed the trust blocker set")
	}
}

func TestLocalReleaseRejectsBindingAndRenderedDriftWithoutLeakingTokens(t *testing.T) {
	root := "/var/lib/chengwang-m2b-candidate/site1"
	base := validConfigurationContents(t, root)
	sentinel := "SECRET_CANARY_release"
	cases := map[string]func(*configurationContents){
		"source_guard_role": func(c *configurationContents) {
			c.composeSource = []byte("candidate-guard\n" + sentinel)
		},
		"rendered_extra_service": func(c *configurationContents) {
			c.composeJSON = bytesReplace(c.composeJSON, `"services":{"probe-agent":`, `"services":{"extra":{},"probe-agent":`)
		},
		"rendered_privileged": func(c *configurationContents) {
			c.composeJSON = bytesReplace(c.composeJSON, `"privileged":false`, `"privileged":true`)
		},
		"rendered_mount_mode": func(c *configurationContents) {
			c.composeJSON = bytesReplace(c.composeJSON, `"read_only":true`, `"read_only":false`)
		},
		"binding_duplicate": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, `"schema":"`+localReleaseBindingSchemaV1+`"`, `"schema":"`+localReleaseBindingSchemaV1+`","schema":"`+sentinel+`"`)
		},
		"binding_trailing": func(c *configurationContents) {
			c.composeBinding = append(c.composeBinding, []byte(` "`+sentinel+`"`)...)
		},
		"binding_unknown": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, "}", `,"unknown":"`+sentinel+`"}`)
		},
		"binding_wrong_type": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, `"sourceSizeBytes":`+strconv.Itoa(len(c.composeSource)), `"sourceSizeBytes":"`+sentinel+`"`)
		},
		"binding_identity": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, digest(c.identity), "sha256:"+strings.Repeat("f", 64))
		},
		"binding_project": func(c *configurationContents) {
			binding, err := parseLocalReleaseBinding(c.composeBinding)
			if err != nil {
				t.Fatal(err)
			}
			c.composeBinding = bytesReplace(c.composeBinding, `"projectName":"`+binding.ProjectName+`"`, `"projectName":"`+sentinel+`"`)
		},
		"binding_profile": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, `"profile":"`+activeProbeProfile+`"`, `"profile":"`+sentinel+`"`)
		},
		"binding_release": func(c *configurationContents) {
			binding, err := parseLocalReleaseBinding(c.composeBinding)
			if err != nil {
				t.Fatal(err)
			}
			c.composeBinding = bytesReplace(c.composeBinding, `"releaseId":"`+binding.ReleaseID+`"`, `"releaseId":"`+sentinel+`"`)
		},
		"binding_source_size": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, `"sourceSizeBytes":`+strconv.Itoa(len(c.composeSource)), `"sourceSizeBytes":1`)
		},
		"binding_rendered_size": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, `"renderedSizeBytes":`+strconv.Itoa(len(c.composeJSON)), `"renderedSizeBytes":1`)
		},
		"binding_env_digest": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, digest(c.env), "sha256:"+strings.Repeat("c", 64))
		},
		"binding_semantic_digest": func(c *configurationContents) {
			binding, err := parseLocalReleaseBinding(c.composeBinding)
			if err != nil {
				t.Fatal(err)
			}
			c.composeBinding = bytesReplace(c.composeBinding, binding.RenderedSemanticSHA256, "sha256:"+strings.Repeat("b", 64))
		},
		"binding_source_digest": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, digest(c.composeSource), "sha256:"+strings.Repeat("e", 64))
		},
		"binding_rendered_digest": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, digest(c.composeJSON), "sha256:"+strings.Repeat("d", 64))
		},
		"binding_renderer_claim": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, `"name":"docker-compose-v2"`, `"name":"`+sentinel+`"`)
		},
		"binding_renderer_version": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, `"version":"v2.40.3"`, `"version":"`+sentinel+`"`)
		},
		"binding_renderer_binary": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, "sha256:"+strings.Repeat("a", 64), "sha256:"+strings.Repeat("0", 64))
		},
		"binding_renderer_invocation": func(c *configurationContents) {
			c.composeBinding = bytesReplace(c.composeBinding, `"invocationContract":"chengwang.compose-render-invocation/v1"`, `"invocationContract":"`+sentinel+`"`)
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			contents := cloneContents(base)
			mutate(&contents)
			environment, err := validateConfiguration(contents, root, "site1")
			if err != nil {
				t.Fatal(err)
			}
			identity, err := parseCandidateIdentity(contents.identity, root, "site1", environment.projectName)
			if err != nil {
				t.Fatal(err)
			}
			_, err = validateLocalRelease(contents, environment, identity)
			if !errors.Is(err, ErrInvalid) || strings.Contains(err.Error(), sentinel) {
				t.Fatalf("unsafe local release was not rejected safely: %v", err)
			}
		})
	}
}

func TestLocalReleaseAcceptsAbsoluteExternalBuildContextClaim(t *testing.T) {
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
	externalContext := "/srv/chengwang-source"
	contents.composeJSON = mutateRenderedCompose(t, contents.composeJSON, func(value map[string]any) {
		renderedService(value)["build"].(map[string]any)["context"] = externalContext
	})
	semantic, err := validateRenderedCompose(contents.composeJSON, environment, externalContext)
	if err != nil {
		t.Fatalf("coordinated fixture should be internally self-consistent: %v", err)
	}
	binding, err := parseLocalReleaseBinding(contents.composeBinding)
	if err != nil {
		t.Fatal(err)
	}
	binding.BuildContext = externalContext
	binding.RenderedSizeBytes = uint64(len(contents.composeJSON))
	binding.RenderedSHA256 = releaseDigest(contents.composeJSON)
	binding.RenderedSemanticSHA256 = semantic
	contents.composeBinding, err = json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateLocalRelease(contents, environment, identity); err != nil {
		t.Fatalf("real lifecycle repository build context claim was rejected: %v", err)
	}
}

func TestLocalReleaseRejectsMalformedBuildContextClaims(t *testing.T) {
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
	for name, invalid := range map[string]string{
		"relative": "repository", "root": "/", "unclean": "/srv/../tmp/source", "backslash": "/srv/bad\\source",
		"newline": "/srv/bad\nsource", "nul": "/srv/bad\x00source",
	} {
		t.Run(name, func(t *testing.T) {
			candidate := contents
			binding, parseErr := parseLocalReleaseBinding(candidate.composeBinding)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			binding.BuildContext = invalid
			candidate.composeBinding, parseErr = json.Marshal(binding)
			if parseErr != nil {
				t.Fatal(parseErr)
			}
			if _, validateErr := validateLocalRelease(candidate, environment, identity); !errors.Is(validateErr, ErrInvalid) {
				t.Fatalf("malformed build context was accepted: %v", validateErr)
			} else if strings.Contains(validateErr.Error(), invalid) {
				t.Fatal("build-context rejection leaked the untrusted path")
			}
		})
	}
}

func TestRenderedComposeRejectsEverySecurityProjectionDrift(t *testing.T) {
	root := "/var/lib/chengwang-m2b-candidate/site1"
	contents := validConfigurationContents(t, root)
	environment, err := validateConfiguration(contents, root, "site1")
	if err != nil {
		t.Fatal(err)
	}
	buildContext := root + "/repository"
	cases := map[string]func(map[string]any){
		"extra_service": func(value map[string]any) {
			value["services"].(map[string]any)["extra"] = map[string]any{}
		},
		"privileged": func(value map[string]any) {
			renderedService(value)["privileged"] = true
		},
		"privileged_null": func(value map[string]any) {
			renderedService(value)["privileged"] = nil
		},
		"build_context": func(value map[string]any) {
			renderedService(value)["build"].(map[string]any)["context"] = root + "/other"
		},
		"network_name": func(value map[string]any) {
			value["networks"].(map[string]any)["m2b_probe_quarantine"].(map[string]any)["name"] = "other"
		},
		"network_attachment": func(value map[string]any) {
			renderedService(value)["networks"].(map[string]any)["m2b_probe_quarantine"] = map[string]any{"aliases": []any{"bypass"}}
		},
		"duplicate_tmpfs": func(value map[string]any) {
			item := "/tmp:size=4m,mode=1777,nosuid,nodev,noexec"
			renderedService(value)["tmpfs"] = []any{item, item}
		},
		"proxy_environment": func(value map[string]any) {
			renderedService(value)["environment"].(map[string]any)["HTTPS_PROXY"] = "http://127.0.0.1:8080"
		},
		"mount_mode": func(value map[string]any) {
			renderedService(value)["volumes"].([]any)[0].(map[string]any)["read_only"] = false
		},
		"user":       func(value map[string]any) { renderedService(value)["user"] = "0:0" },
		"profile":    func(value map[string]any) { renderedService(value)["profiles"] = []any{"other"} },
		"read_only":  func(value map[string]any) { renderedService(value)["read_only"] = false },
		"init":       func(value map[string]any) { renderedService(value)["init"] = false },
		"stdin_open": func(value map[string]any) { renderedService(value)["stdin_open"] = true },
		"tty":        func(value map[string]any) { renderedService(value)["tty"] = true },
		"stdin_open_null": func(value map[string]any) {
			renderedService(value)["stdin_open"] = nil
		},
		"tty_null": func(value map[string]any) {
			renderedService(value)["tty"] = nil
		},
		"unknown_service_field": func(value map[string]any) {
			renderedService(value)["unknown"] = false
		},
		"missing_required_field": func(value map[string]any) {
			delete(renderedService(value), "read_only")
		},
		"restart":      func(value map[string]any) { renderedService(value)["restart"] = "always" },
		"stop_signal":  func(value map[string]any) { renderedService(value)["stop_signal"] = "SIGKILL" },
		"stop_grace":   func(value map[string]any) { renderedService(value)["stop_grace_period"] = "1s" },
		"cap_drop":     func(value map[string]any) { renderedService(value)["cap_drop"] = []any{"NET_ADMIN"} },
		"security_opt": func(value map[string]any) { renderedService(value)["security_opt"] = []any{} },
		"image":        func(value map[string]any) { renderedService(value)["image"] = "untrusted:latest" },
		"dockerfile": func(value map[string]any) {
			renderedService(value)["build"].(map[string]any)["dockerfile"] = "Dockerfile"
		},
		"entrypoint": func(value map[string]any) { renderedService(value)["entrypoint"] = []any{"/bin/sh"} },
		"command":    func(value map[string]any) { renderedService(value)["command"] = []any{"sleep", "infinity"} },
		"environment_value": func(value map[string]any) {
			renderedService(value)["environment"].(map[string]any)["M2B_PROBE_DOT_UPSTREAM"] = "8.8.8.8:853"
		},
		"cpus":        func(value map[string]any) { renderedService(value)["cpus"] = "2" },
		"memory":      func(value map[string]any) { renderedService(value)["mem_limit"] = "268435456" },
		"reservation": func(value map[string]any) { renderedService(value)["mem_reservation"] = "134217728" },
		"pids":        func(value map[string]any) { renderedService(value)["pids_limit"] = "1024" },
		"nofile": func(value map[string]any) {
			renderedService(value)["ulimits"].(map[string]any)["nofile"].(map[string]any)["soft"] = 1024
		},
		"mount_source": func(value map[string]any) {
			renderedService(value)["volumes"].([]any)[0].(map[string]any)["source"] = "/tmp/untrusted"
		},
		"mount_target": func(value map[string]any) {
			renderedService(value)["volumes"].([]any)[0].(map[string]any)["target"] = "/tmp/untrusted"
		},
		"mount_type": func(value map[string]any) {
			renderedService(value)["volumes"].([]any)[0].(map[string]any)["type"] = "volume"
		},
		"mount_create_host_path": func(value map[string]any) {
			renderedService(value)["volumes"].([]any)[0].(map[string]any)["bind"].(map[string]any)["create_host_path"] = true
		},
		"network_internal": func(value map[string]any) {
			value["networks"].(map[string]any)["m2b_probe_quarantine"].(map[string]any)["internal"] = false
		},
		"network_driver": func(value map[string]any) {
			value["networks"].(map[string]any)["m2b_probe_quarantine"].(map[string]any)["driver"] = "host"
		},
		"network_attachable": func(value map[string]any) {
			value["networks"].(map[string]any)["m2b_probe_quarantine"].(map[string]any)["attachable"] = true
		},
		"network_external": func(value map[string]any) {
			value["networks"].(map[string]any)["m2b_probe_quarantine"].(map[string]any)["external"] = true
		},
		"network_icc": func(value map[string]any) {
			value["networks"].(map[string]any)["m2b_probe_quarantine"].(map[string]any)["driver_opts"].(map[string]any)["com.docker.network.bridge.enable_icc"] = "true"
		},
		"healthcheck": func(value map[string]any) {
			renderedService(value)["healthcheck"].(map[string]any)["retries"] = 1
		},
		"logging": func(value map[string]any) {
			renderedService(value)["logging"].(map[string]any)["options"].(map[string]any)["max-size"] = "100m"
		},
		"identity_label": func(value map[string]any) {
			renderedService(value)["labels"].(map[string]any)["com.jydn.chengwang.advisory-only"] = "false"
		},
		"tmpfs_parameter": func(value map[string]any) {
			renderedService(value)["tmpfs"].([]any)[0] = "/tmp:size=4m,mode=0777"
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			raw := mutateRenderedCompose(t, contents.composeJSON, mutate)
			if _, err := validateRenderedCompose(raw, environment, buildContext); !errors.Is(err, ErrInvalid) {
				t.Fatalf("semantic drift was accepted: %v", err)
			}
		})
	}
}

func TestRenderedSemanticDigestNormalizesAcceptedRepresentations(t *testing.T) {
	root := "/var/lib/chengwang-m2b-candidate/site1"
	contents := validConfigurationContents(t, root)
	environment, err := validateConfiguration(contents, root, "site1")
	if err != nil {
		t.Fatal(err)
	}
	buildContext := root + "/repository"
	want, err := validateRenderedCompose(contents.composeJSON, environment, buildContext)
	if err != nil {
		t.Fatal(err)
	}
	variant := mutateRenderedCompose(t, contents.composeJSON, func(value map[string]any) {
		service := renderedService(value)
		delete(service, "privileged")
		delete(service, "stdin_open")
		delete(service, "tty")
		service["build"].(map[string]any)["dockerfile"] = path.Join(buildContext, "deploy/m2b-candidate/Dockerfile.probe-agent")
		service["cpus"] = "0.25"
		service["mem_limit"] = "100663296"
		health := service["healthcheck"].(map[string]any)
		health["interval"] = int64(10_000_000_000)
		health["timeout"] = int64(3_000_000_000)
		health["start_period"] = int64(5_000_000_000)
		tmpfs := service["tmpfs"].([]any)
		service["tmpfs"] = []any{tmpfs[1], tmpfs[0]}
	})
	got, err := validateRenderedCompose(variant, environment, buildContext)
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("equivalent rendered representations changed semantic digest: got=%s want=%s", got, want)
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
	contents := configurationContents{env: []byte(builder.String()), catalog: catalog, ca: ca, policy: policy, identity: identity}
	contents.composeSource = append([]byte(nil), approvedProbeComposeSource...)
	contents.composeJSON = validRenderedComposeJSON(t, root, project, values)
	buildContext := root + "/repository"
	semantic, err := validateRenderedCompose(contents.composeJSON, validatedEnvironment{projectName: project, releaseID: values["M2B_PROBE_RELEASE_ID"], values: values}, buildContext)
	if err != nil {
		t.Fatal(err)
	}
	binding := localReleaseBinding{
		Schema: localReleaseBindingSchemaV1, CandidateID: candidateID, IdentityGeneration: 1,
		CandidateIdentitySHA256: digest(identity), ProjectName: project, ServiceName: serviceName,
		ComposeRole: activeProbeComposeRole, Profile: activeProbeProfile, ReleaseID: values["M2B_PROBE_RELEASE_ID"],
		SourceOrigin: composeSourceOrigin, ProjectDirectoryContract: composeProjectContract, BuildContext: buildContext,
		SourceFileName: "compose-source.yaml", SourceSizeBytes: uint64(len(contents.composeSource)), SourceSHA256: digest(contents.composeSource),
		ProbeEnvSHA256: digest(contents.env), RenderedFileName: "compose-rendered.json", RenderedSizeBytes: uint64(len(contents.composeJSON)),
		RenderedSHA256: digest(contents.composeJSON), RenderedSemanticSchema: renderedProjectionSchemaV1, RenderedSemanticSHA256: semantic,
		RendererClaim: rendererClaim{Name: "docker-compose-v2", Version: "v2.40.3", BinarySHA256: "sha256:" + strings.Repeat("a", 64), InvocationContract: "chengwang.compose-render-invocation/v1"},
	}
	contents.composeBinding, err = json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	return contents
}

func validRenderedComposeJSON(t *testing.T, root, project string, values map[string]string) []byte {
	t.Helper()
	volumes := []any{
		map[string]any{"type": "bind", "source": values["M2B_PROBE_CATALOG_FILE"], "target": "/run/chengwang-probe/catalog.json", "read_only": true, "bind": map[string]any{"create_host_path": false}},
		map[string]any{"type": "bind", "source": values["M2B_PROBE_DOT_CA_FILE"], "target": "/run/chengwang-probe/dot-ca.pem", "read_only": true, "bind": map[string]any{"create_host_path": false}},
		map[string]any{"type": "bind", "source": values["M2B_PROBE_EGRESS_POLICY_FILE"], "target": "/run/chengwang-probe/egress-policy.json", "read_only": true, "bind": map[string]any{"create_host_path": false}},
		map[string]any{"type": "bind", "source": values["M2B_PROBE_SPOOL_DIR"], "target": "/var/lib/chengwang-probe/results", "read_only": false, "bind": map[string]any{"create_host_path": false}},
		map[string]any{"type": "bind", "source": values["M2B_PROBE_LEDGER_DIR"], "target": "/var/lib/chengwang-probe/ledger", "read_only": false, "bind": map[string]any{"create_host_path": false}},
	}
	environment := map[string]any{
		"TZ": "UTC", "M2B_PROBE_ACTIVE_APPROVAL": "approved-candidate-only", "M2B_PROBE_DOT_UPSTREAM": values["M2B_PROBE_DOT_UPSTREAM"],
		"M2B_PROBE_DOT_SERVER_NAME": values["M2B_PROBE_DOT_SERVER_NAME"], "M2B_PROBE_EXPECTED_CATALOG_SHA256": values["M2B_PROBE_CATALOG_SHA256"],
		"M2B_PROBE_EXPECTED_DOT_CA_SHA256": values["M2B_PROBE_DOT_CA_SHA256"], "M2B_PROBE_EXPECTED_EGRESS_POLICY_SHA256": values["M2B_PROBE_EGRESS_POLICY_SHA256"],
	}
	command := []string{"/app/probe-agent", "--catalog", "/run/chengwang-probe/catalog.json", "--spool-dir", "/var/lib/chengwang-probe/results", "--ledger-dir", "/var/lib/chengwang-probe/ledger", "--dot-upstream", values["M2B_PROBE_DOT_UPSTREAM"], "--dot-server-name", values["M2B_PROBE_DOT_SERVER_NAME"], "--dot-ca", "/run/chengwang-probe/dot-ca.pem", "--health-file", "/run/m2b-probe-health/health.json", "--resolver-timeout", "5s", "--runner-timeout", "10s", "--concurrency", "2", "--queue-size", "256", "--starts-per-minute", "20"}
	service := map[string]any{
		"build":    map[string]any{"context": root + "/repository", "dockerfile": "deploy/m2b-candidate/Dockerfile.probe-agent"},
		"cap_drop": []string{"ALL"}, "command": command, "cpus": 0.25, "entrypoint": []string{"/app/probe-agent-entrypoint.sh"}, "environment": environment,
		"healthcheck": map[string]any{"test": []string{"CMD", "/app/probe-agent", "health", "--health-file", "/run/m2b-probe-health/health.json", "--catalog", "/run/chengwang-probe/catalog.json", "--max-age", "20s"}, "interval": "10s", "timeout": "3s", "start_period": "5s", "retries": 3},
		"image":       "chengwang-m2b-probe-agent:" + values["M2B_PROBE_RELEASE_ID"], "init": true,
		"labels":    map[string]any{"com.jydn.chengwang.component": "m2b-probe-agent-candidate", "com.jydn.chengwang.active-probes": "true", "com.jydn.chengwang.advisory-only": "true", "com.jydn.chengwang.egress-approved": "false"},
		"logging":   map[string]any{"driver": "json-file", "options": map[string]any{"max-file": "2", "max-size": "1m"}},
		"mem_limit": 100663296, "mem_reservation": 50331648, "networks": map[string]any{"m2b_probe_quarantine": nil}, "pids_limit": 64,
		"privileged": false, "profiles": []string{activeProbeProfile}, "read_only": true, "restart": "no", "security_opt": []string{"no-new-privileges:true"},
		"stdin_open": false, "stop_grace_period": "20s", "stop_signal": "SIGTERM",
		"tmpfs": []string{"/tmp:size=4m,mode=1777,nosuid,nodev,noexec", "/run/m2b-probe-health:size=1m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec"},
		"tty":   false, "ulimits": map[string]any{"nofile": map[string]any{"soft": 256, "hard": 256}}, "user": "10001:10001", "volumes": volumes,
	}
	rootValue := map[string]any{
		"name": project, "services": map[string]any{serviceName: service},
		"networks": map[string]any{"m2b_probe_quarantine": map[string]any{"name": project + "_m2b_probe_quarantine", "driver": "bridge", "driver_opts": map[string]any{"com.docker.network.bridge.enable_icc": "false"}, "attachable": false, "internal": true, "external": false}},
	}
	raw, err := json.Marshal(rootValue)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func mutateRenderedCompose(t *testing.T, raw []byte, mutate func(map[string]any)) []byte {
	t.Helper()
	var value map[string]any
	decoder := json.NewDecoder(strings.NewReader(string(raw)))
	decoder.UseNumber()
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	mutate(value)
	result, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func renderedService(value map[string]any) map[string]any {
	return value["services"].(map[string]any)[serviceName].(map[string]any)
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
		identity:      append([]byte(nil), value.identity...),
		composeSource: append([]byte(nil), value.composeSource...), composeJSON: append([]byte(nil), value.composeJSON...),
		composeBinding: append([]byte(nil), value.composeBinding...),
	}
}

func bytesReplace(raw []byte, old, replacement string) []byte {
	return []byte(strings.Replace(string(raw), old, replacement, 1))
}
