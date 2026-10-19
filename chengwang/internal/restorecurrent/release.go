package restorecurrent

import (
	"bytes"
	"crypto/sha256"
	_ "embed"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"path"
	"regexp"
	"strings"
	"unicode/utf8"
)

const (
	localReleaseBindingSchemaV1 = "chengwang.m2b-compose-local-binding/v1"
	renderedProjectionSchemaV1  = "chengwang.m2b-probe-compose-projection/v1"
	activeProbeProfile          = "active-probe-candidate"
	activeProbeComposeRole      = "ACTIVE_PROBE_AGENT"
	composeSourceOrigin         = "repository-evidence-copy:chengwang/deploy/m2b-candidate/compose.probe-agent.yaml"
	composeProjectContract      = "repository-project-directory:chengwang/deploy/m2b-candidate/v1"
)

var rendererVersionPattern = regexp.MustCompile(`^v[0-9]+\.[0-9]+\.[0-9]+(?:[-+][A-Za-z0-9._-]+)?$`)
var releaseHashPattern = regexp.MustCompile(`^[0-9a-f]{64}$`)

//go:embed compose_probe_agent.snapshot.yaml
var approvedProbeComposeSource string

type localReleaseBinding struct {
	Schema                   string        `json:"schema"`
	CandidateID              string        `json:"candidateId"`
	IdentityGeneration       uint64        `json:"identityGeneration"`
	CandidateIdentitySHA256  string        `json:"candidateIdentitySha256"`
	ProjectName              string        `json:"projectName"`
	ServiceName              string        `json:"serviceName"`
	ComposeRole              string        `json:"composeRole"`
	Profile                  string        `json:"profile"`
	ReleaseID                string        `json:"releaseId"`
	SourceOrigin             string        `json:"sourceOrigin"`
	ProjectDirectoryContract string        `json:"projectDirectoryContract"`
	BuildContext             string        `json:"buildContext"`
	SourceFileName           string        `json:"sourceFileName"`
	SourceSizeBytes          uint64        `json:"sourceSizeBytes"`
	SourceSHA256             string        `json:"sourceSha256"`
	ProbeEnvSHA256           string        `json:"probeEnvSha256"`
	RenderedFileName         string        `json:"renderedFileName"`
	RenderedSizeBytes        uint64        `json:"renderedSizeBytes"`
	RenderedSHA256           string        `json:"renderedSha256"`
	RenderedSemanticSchema   string        `json:"renderedSemanticSchema"`
	RenderedSemanticSHA256   string        `json:"renderedSemanticSha256"`
	RendererClaim            rendererClaim `json:"rendererClaim"`
}

type rendererClaim struct {
	Name               string `json:"name"`
	Version            string `json:"version"`
	BinarySHA256       string `json:"binarySha256"`
	InvocationContract string `json:"invocationContract"`
}

func validateLocalRelease(contents configurationContents, env validatedEnvironment, identity candidateIdentity) (LocalReleaseDigests, error) {
	binding, err := parseLocalReleaseBinding(contents.composeBinding)
	if err != nil {
		return LocalReleaseDigests{}, err
	}
	if err := validateComposeSourceEvidence(contents.composeSource); err != nil {
		return LocalReleaseDigests{}, err
	}
	if err := validateBuildContextClaim(binding.BuildContext); err != nil {
		return LocalReleaseDigests{}, err
	}
	semanticDigest, err := validateRenderedCompose(contents.composeJSON, env, binding.BuildContext)
	if err != nil {
		return LocalReleaseDigests{}, err
	}
	if binding.Schema != localReleaseBindingSchemaV1 || binding.CandidateID != identity.CandidateID ||
		binding.IdentityGeneration != identity.IdentityGeneration || binding.CandidateIdentitySHA256 != releaseDigest(contents.identity) ||
		binding.ProjectName != env.projectName || binding.ServiceName != serviceName ||
		binding.ComposeRole != activeProbeComposeRole || binding.Profile != activeProbeProfile ||
		binding.ReleaseID != env.releaseID || binding.SourceOrigin != composeSourceOrigin ||
		binding.ProjectDirectoryContract != composeProjectContract || binding.SourceFileName != "compose-source.yaml" ||
		binding.RenderedFileName != "compose-rendered.json" || binding.RenderedSemanticSchema != renderedProjectionSchemaV1 ||
		binding.SourceSizeBytes != uint64(len(contents.composeSource)) || binding.RenderedSizeBytes != uint64(len(contents.composeJSON)) ||
		binding.SourceSHA256 != releaseDigest(contents.composeSource) || binding.ProbeEnvSHA256 != releaseDigest(contents.env) ||
		binding.RenderedSHA256 != releaseDigest(contents.composeJSON) || binding.RenderedSemanticSHA256 != semanticDigest {
		return LocalReleaseDigests{}, errors.Join(ErrInvalid, errors.New("local release binding is inconsistent"))
	}
	claim := binding.RendererClaim
	if claim.Name != "docker-compose-v2" || !rendererVersionPattern.MatchString(claim.Version) ||
		!isNonzeroDigest(claim.BinarySHA256) || claim.InvocationContract != "chengwang.compose-render-invocation/v1" {
		return LocalReleaseDigests{}, errors.Join(ErrInvalid, errors.New("renderer claim is invalid"))
	}
	return LocalReleaseDigests{
		ComposeSourceSHA256: releaseDigest(contents.composeSource), ComposeRenderedSHA256: releaseDigest(contents.composeJSON),
		RenderedSemanticSHA256: semanticDigest, LocalBindingSHA256: releaseDigest(contents.composeBinding),
	}, nil
}

func parseLocalReleaseBinding(raw []byte) (localReleaseBinding, error) {
	if len(raw) == 0 || len(raw) > 32<<10 || releaseRejectDuplicateJSONKeys(raw) != nil {
		return localReleaseBinding{}, errors.Join(ErrInvalid, errors.New("local release binding JSON is invalid"))
	}
	var root map[string]json.RawMessage
	if err := json.Unmarshal(raw, &root); err != nil || !exactKeys(root, []string{
		"schema", "candidateId", "identityGeneration", "candidateIdentitySha256", "projectName", "serviceName",
		"composeRole", "profile", "releaseId", "sourceOrigin", "projectDirectoryContract", "buildContext", "sourceFileName",
		"sourceSizeBytes", "sourceSha256", "probeEnvSha256", "renderedFileName", "renderedSizeBytes",
		"renderedSha256", "renderedSemanticSchema", "renderedSemanticSha256", "rendererClaim",
	}) {
		return localReleaseBinding{}, errors.Join(ErrInvalid, errors.New("local release binding field set is invalid"))
	}
	var claimKeys map[string]json.RawMessage
	if err := json.Unmarshal(root["rendererClaim"], &claimKeys); err != nil || !exactKeys(claimKeys, []string{"name", "version", "binarySha256", "invocationContract"}) {
		return localReleaseBinding{}, errors.Join(ErrInvalid, errors.New("renderer claim field set is invalid"))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var value localReleaseBinding
	if err := decoder.Decode(&value); err != nil {
		return localReleaseBinding{}, errors.Join(ErrInvalid, errors.New("local release binding value types are invalid"))
	}
	return value, nil
}

func exactKeys(value map[string]json.RawMessage, wanted []string) bool {
	if len(value) != len(wanted) {
		return false
	}
	for _, key := range wanted {
		if _, ok := value[key]; !ok {
			return false
		}
	}
	return true
}

func isNonzeroDigest(value string) bool {
	return strings.HasPrefix(value, "sha256:") && len(value) == 71 && releaseHashPattern.MatchString(strings.TrimPrefix(value, "sha256:")) && value != "sha256:"+strings.Repeat("0", 64)
}

func validateComposeSourceEvidence(raw []byte) error {
	if len(raw) == 0 || len(raw) > 256<<10 || !utf8.Valid(raw) || bytes.IndexByte(raw, 0) >= 0 {
		return errors.Join(ErrInvalid, errors.New("Compose source evidence encoding or size is invalid"))
	}
	if !bytes.Equal(raw, []byte(approvedProbeComposeSource)) {
		return errors.Join(ErrInvalid, errors.New("Compose source evidence differs from the reviewed source snapshot"))
	}
	return nil
}

func validateBuildContextClaim(value string) error {
	if len(value) < 2 || len(value) > 4096 || !utf8.Valid([]byte(value)) || !path.IsAbs(value) ||
		path.Clean(value) != value || strings.ContainsAny(value, "\\\x00\r\n\t") {
		return errors.Join(ErrInvalid, errors.New("local release build context claim is invalid"))
	}
	return nil
}

func validateRenderedCompose(raw []byte, env validatedEnvironment, buildContext string) (string, error) {
	if len(raw) == 0 || len(raw) > 1<<20 || releaseRejectDuplicateJSONKeys(raw) != nil {
		return "", errors.Join(ErrInvalid, errors.New("rendered Compose JSON is invalid"))
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil || !exactAnyKeys(root, "name", "networks", "services") {
		return "", errors.Join(ErrInvalid, errors.New("rendered Compose top-level contract is invalid"))
	}
	if value, ok := root["name"].(string); !ok || value != env.projectName {
		return "", errors.Join(ErrInvalid, errors.New("rendered Compose project is invalid"))
	}
	services, ok := root["services"].(map[string]any)
	if !ok || !exactAnyKeys(services, serviceName) {
		return "", errors.Join(ErrInvalid, errors.New("rendered Compose service set is invalid"))
	}
	service, ok := services[serviceName].(map[string]any)
	if !ok || !exactAnyKeys(service,
		"build", "cap_drop", "command", "cpus", "entrypoint", "environment", "healthcheck", "image", "init", "labels",
		"logging", "mem_limit", "mem_reservation", "networks", "pids_limit", "privileged", "profiles", "read_only", "restart",
		"security_opt", "stdin_open", "stop_grace_period", "stop_signal", "tmpfs", "tty", "ulimits", "user", "volumes",
	) {
		return "", errors.Join(ErrInvalid, errors.New("rendered Compose service field set is invalid"))
	}
	if !equalStrings(service["profiles"], []string{activeProbeProfile}) || stringValue(service["image"]) != "chengwang-m2b-probe-agent:"+env.releaseID ||
		stringValue(service["user"]) != "10001:10001" || !boolValue(service["read_only"], true) || !boolValue(service["privileged"], false) ||
		!boolValue(service["init"], true) || !boolValue(service["stdin_open"], false) || !boolValue(service["tty"], false) ||
		stringValue(service["restart"]) != "no" || stringValue(service["stop_signal"]) != "SIGTERM" || !durationValue(service["stop_grace_period"], "20s", 20_000_000_000) {
		return "", errors.Join(ErrInvalid, errors.New("rendered Compose process isolation is invalid"))
	}
	if !equalStrings(service["cap_drop"], []string{"ALL"}) || !equalStrings(service["security_opt"], []string{"no-new-privileges:true"}) ||
		!numberValue(service["cpus"], "0.25") || !numberValue(service["mem_limit"], "100663296") ||
		!numberValue(service["mem_reservation"], "50331648") || !numberValue(service["pids_limit"], "64") {
		return "", errors.Join(ErrInvalid, errors.New("rendered Compose security or resource contract is invalid"))
	}
	if err := validateRenderedBuild(service["build"], buildContext); err != nil {
		return "", err
	}
	if err := validateRenderedEnvironment(service["environment"], env); err != nil {
		return "", err
	}
	if err := validateRenderedCommand(service); err != nil {
		return "", err
	}
	if err := validateRenderedMounts(service["volumes"], env); err != nil {
		return "", err
	}
	if err := validateRenderedNetwork(root["networks"], service["networks"], env.projectName); err != nil {
		return "", err
	}
	if err := validateRenderedAuxiliary(service); err != nil {
		return "", err
	}
	canonical, err := json.Marshal(renderedSemanticProjection(env, buildContext))
	if err != nil {
		return "", errors.Join(ErrInvalid, errors.New("rendered Compose projection is not canonicalizable"))
	}
	return releaseDigest(append([]byte(renderedProjectionSchemaV1+"\x00"), canonical...)), nil
}

func releaseDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func releaseRejectDuplicateJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := releaseScanJSONValue(decoder, 0); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("unexpected trailing JSON token")
		}
		return err
	}
	return nil
}

func releaseScanJSONValue(decoder *json.Decoder, depth int) error {
	if depth > 16 {
		return errors.New("JSON nesting is too deep")
	}
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	delimiter, compound := token.(json.Delim)
	if !compound {
		return nil
	}
	switch delimiter {
	case '{':
		seen := map[string]struct{}{}
		for decoder.More() {
			keyToken, err := decoder.Token()
			if err != nil {
				return err
			}
			key, ok := keyToken.(string)
			if !ok {
				return errors.New("object key is not a string")
			}
			if _, duplicate := seen[key]; duplicate {
				return errors.New("duplicate object key")
			}
			seen[key] = struct{}{}
			if err := releaseScanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return errors.New("object is not closed")
		}
	case '[':
		for decoder.More() {
			if err := releaseScanJSONValue(decoder, depth+1); err != nil {
				return err
			}
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return errors.New("array is not closed")
		}
	default:
		return errors.New("unexpected JSON delimiter")
	}
	return nil
}

func validateRenderedBuild(raw any, buildContext string) error {
	value, ok := raw.(map[string]any)
	dockerfile := stringValue(value["dockerfile"])
	expectedDockerfile := "deploy/m2b-candidate/Dockerfile.probe-agent"
	dockerfileValid := dockerfile == expectedDockerfile ||
		(path.IsAbs(dockerfile) && path.Clean(dockerfile) == path.Join(buildContext, expectedDockerfile))
	if !ok || !exactAnyKeys(value, "context", "dockerfile") || !dockerfileValid || stringValue(value["context"]) != buildContext {
		return errors.Join(ErrInvalid, errors.New("rendered Compose build contract is invalid"))
	}
	return nil
}

func validateRenderedEnvironment(raw any, env validatedEnvironment) error {
	value, ok := raw.(map[string]any)
	wanted := map[string]string{
		"TZ": "UTC", "M2B_PROBE_ACTIVE_APPROVAL": "approved-candidate-only",
		"M2B_PROBE_DOT_UPSTREAM": env.values["M2B_PROBE_DOT_UPSTREAM"], "M2B_PROBE_DOT_SERVER_NAME": env.values["M2B_PROBE_DOT_SERVER_NAME"],
		"M2B_PROBE_EXPECTED_CATALOG_SHA256":       env.values["M2B_PROBE_CATALOG_SHA256"],
		"M2B_PROBE_EXPECTED_DOT_CA_SHA256":        env.values["M2B_PROBE_DOT_CA_SHA256"],
		"M2B_PROBE_EXPECTED_EGRESS_POLICY_SHA256": env.values["M2B_PROBE_EGRESS_POLICY_SHA256"],
	}
	if !ok || len(value) != len(wanted) {
		return errors.Join(ErrInvalid, errors.New("rendered Compose environment field set is invalid"))
	}
	for key, expected := range wanted {
		if stringValue(value[key]) != expected {
			return errors.Join(ErrInvalid, errors.New("rendered Compose environment binding is invalid"))
		}
	}
	return nil
}

func validateRenderedCommand(service map[string]any) error {
	if !equalStrings(service["entrypoint"], []string{"/app/probe-agent-entrypoint.sh"}) {
		return errors.Join(ErrInvalid, errors.New("rendered Compose entrypoint is invalid"))
	}
	environment := service["environment"].(map[string]any)
	wanted := []string{
		"/app/probe-agent", "--catalog", "/run/chengwang-probe/catalog.json", "--spool-dir", "/var/lib/chengwang-probe/results",
		"--ledger-dir", "/var/lib/chengwang-probe/ledger", "--dot-upstream", stringValue(environment["M2B_PROBE_DOT_UPSTREAM"]),
		"--dot-server-name", stringValue(environment["M2B_PROBE_DOT_SERVER_NAME"]), "--dot-ca", "/run/chengwang-probe/dot-ca.pem",
		"--health-file", "/run/m2b-probe-health/health.json", "--resolver-timeout", "5s", "--runner-timeout", "10s",
		"--concurrency", "2", "--queue-size", "256", "--starts-per-minute", "20",
	}
	if !equalStrings(service["command"], wanted) {
		return errors.Join(ErrInvalid, errors.New("rendered Compose command is invalid"))
	}
	return nil
}

func validateRenderedMounts(raw any, env validatedEnvironment) error {
	values, ok := raw.([]any)
	if !ok || len(values) != 5 {
		return errors.Join(ErrInvalid, errors.New("rendered Compose mount set is invalid"))
	}
	wanted := map[string]struct {
		source   string
		readOnly bool
	}{
		"/run/chengwang-probe/catalog.json":       {env.values["M2B_PROBE_CATALOG_FILE"], true},
		"/run/chengwang-probe/dot-ca.pem":         {env.values["M2B_PROBE_DOT_CA_FILE"], true},
		"/run/chengwang-probe/egress-policy.json": {env.values["M2B_PROBE_EGRESS_POLICY_FILE"], true},
		"/var/lib/chengwang-probe/results":        {env.values["M2B_PROBE_SPOOL_DIR"], false},
		"/var/lib/chengwang-probe/ledger":         {env.values["M2B_PROBE_LEDGER_DIR"], false},
	}
	seen := map[string]bool{}
	for _, rawMount := range values {
		mount, ok := rawMount.(map[string]any)
		if !ok || !exactAnyKeys(mount, "bind", "read_only", "source", "target", "type") {
			return errors.Join(ErrInvalid, errors.New("rendered Compose mount shape is invalid"))
		}
		target := stringValue(mount["target"])
		expected, ok := wanted[target]
		bind, bindOK := mount["bind"].(map[string]any)
		if !ok || seen[target] || stringValue(mount["type"]) != "bind" || stringValue(mount["source"]) != expected.source ||
			!boolValue(mount["read_only"], expected.readOnly) || !bindOK || !exactAnyKeys(bind, "create_host_path") || !boolValue(bind["create_host_path"], false) {
			return errors.Join(ErrInvalid, errors.New("rendered Compose mount binding is invalid"))
		}
		seen[target] = true
	}
	return nil
}

func validateRenderedNetwork(rawNetworks, rawServiceNetworks any, projectName string) error {
	networks, ok := rawNetworks.(map[string]any)
	if !ok || !exactAnyKeys(networks, "m2b_probe_quarantine") {
		return errors.Join(ErrInvalid, errors.New("rendered Compose network set is invalid"))
	}
	network, ok := networks["m2b_probe_quarantine"].(map[string]any)
	if !ok || !allowedAnyKeys(network, "name", "driver", "driver_opts", "attachable", "internal", "external") ||
		stringValue(network["name"]) != projectName+"_m2b_probe_quarantine" || stringValue(network["driver"]) != "bridge" ||
		!boolValue(network["attachable"], false) || !boolValue(network["internal"], true) {
		return errors.Join(ErrInvalid, errors.New("rendered Compose quarantine network is invalid"))
	}
	if external, exists := network["external"]; exists && !boolValue(external, false) {
		return errors.Join(ErrInvalid, errors.New("rendered Compose network cannot be external"))
	}
	opts, ok := network["driver_opts"].(map[string]any)
	if !ok || !exactAnyKeys(opts, "com.docker.network.bridge.enable_icc") || stringValue(opts["com.docker.network.bridge.enable_icc"]) != "false" {
		return errors.Join(ErrInvalid, errors.New("rendered Compose network driver options are invalid"))
	}
	serviceNetworks, ok := rawServiceNetworks.(map[string]any)
	if !ok || !exactAnyKeys(serviceNetworks, "m2b_probe_quarantine") {
		return errors.Join(ErrInvalid, errors.New("rendered Compose service network binding is invalid"))
	}
	attachment := serviceNetworks["m2b_probe_quarantine"]
	if attachment != nil {
		value, ok := attachment.(map[string]any)
		if !ok || len(value) != 0 {
			return errors.Join(ErrInvalid, errors.New("rendered Compose service network attachment is invalid"))
		}
	}
	return nil
}

func validateRenderedAuxiliary(service map[string]any) error {
	labels, ok := service["labels"].(map[string]any)
	wantedLabels := map[string]string{
		"com.jydn.chengwang.component": "m2b-probe-agent-candidate", "com.jydn.chengwang.active-probes": "true",
		"com.jydn.chengwang.advisory-only": "true", "com.jydn.chengwang.egress-approved": "false",
	}
	if !ok || len(labels) != len(wantedLabels) {
		return errors.Join(ErrInvalid, errors.New("rendered Compose label set is invalid"))
	}
	for key, expected := range wantedLabels {
		if stringValue(labels[key]) != expected {
			return errors.Join(ErrInvalid, errors.New("rendered Compose identity label is invalid"))
		}
	}
	logging, ok := service["logging"].(map[string]any)
	options, optionsOK := logging["options"].(map[string]any)
	if !ok || !optionsOK || !exactAnyKeys(logging, "driver", "options") || stringValue(logging["driver"]) != "json-file" ||
		!exactAnyKeys(options, "max-file", "max-size") || stringValue(options["max-file"]) != "2" || stringValue(options["max-size"]) != "1m" {
		return errors.Join(ErrInvalid, errors.New("rendered Compose logging contract is invalid"))
	}
	health, ok := service["healthcheck"].(map[string]any)
	wantedHealth := []string{"CMD", "/app/probe-agent", "health", "--health-file", "/run/m2b-probe-health/health.json", "--catalog", "/run/chengwang-probe/catalog.json", "--max-age", "20s"}
	if !ok || !exactAnyKeys(health, "interval", "retries", "start_period", "test", "timeout") || !equalStrings(health["test"], wantedHealth) ||
		!durationValue(health["interval"], "10s", 10_000_000_000) || !durationValue(health["timeout"], "3s", 3_000_000_000) ||
		!durationValue(health["start_period"], "5s", 5_000_000_000) || !numberValue(health["retries"], "3") {
		return errors.Join(ErrInvalid, errors.New("rendered Compose health contract is invalid"))
	}
	ulimits, ok := service["ulimits"].(map[string]any)
	nofile, nofileOK := ulimits["nofile"].(map[string]any)
	if !ok || !nofileOK || !exactAnyKeys(ulimits, "nofile") || !exactAnyKeys(nofile, "hard", "soft") || !numberValue(nofile["hard"], "256") || !numberValue(nofile["soft"], "256") {
		return errors.Join(ErrInvalid, errors.New("rendered Compose nofile contract is invalid"))
	}
	tmpfs, ok := service["tmpfs"].([]any)
	if !ok || len(tmpfs) != 2 || !stringSliceSet(tmpfs, []string{
		"/tmp:size=4m,mode=1777,nosuid,nodev,noexec",
		"/run/m2b-probe-health:size=1m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec",
	}) {
		return errors.Join(ErrInvalid, errors.New("rendered Compose tmpfs contract is invalid"))
	}
	return nil
}

func renderedSemanticProjection(env validatedEnvironment, buildContext string) map[string]any {
	environment := map[string]string{
		"TZ": "UTC", "M2B_PROBE_ACTIVE_APPROVAL": "approved-candidate-only",
		"M2B_PROBE_DOT_UPSTREAM": env.values["M2B_PROBE_DOT_UPSTREAM"], "M2B_PROBE_DOT_SERVER_NAME": env.values["M2B_PROBE_DOT_SERVER_NAME"],
		"M2B_PROBE_EXPECTED_CATALOG_SHA256":       env.values["M2B_PROBE_CATALOG_SHA256"],
		"M2B_PROBE_EXPECTED_DOT_CA_SHA256":        env.values["M2B_PROBE_DOT_CA_SHA256"],
		"M2B_PROBE_EXPECTED_EGRESS_POLICY_SHA256": env.values["M2B_PROBE_EGRESS_POLICY_SHA256"],
	}
	command := []string{
		"/app/probe-agent", "--catalog", "/run/chengwang-probe/catalog.json", "--spool-dir", "/var/lib/chengwang-probe/results",
		"--ledger-dir", "/var/lib/chengwang-probe/ledger", "--dot-upstream", env.values["M2B_PROBE_DOT_UPSTREAM"],
		"--dot-server-name", env.values["M2B_PROBE_DOT_SERVER_NAME"], "--dot-ca", "/run/chengwang-probe/dot-ca.pem",
		"--health-file", "/run/m2b-probe-health/health.json", "--resolver-timeout", "5s", "--runner-timeout", "10s",
		"--concurrency", "2", "--queue-size", "256", "--starts-per-minute", "20",
	}
	mounts := []map[string]any{
		{"target": "/run/chengwang-probe/catalog.json", "source": env.values["M2B_PROBE_CATALOG_FILE"], "readOnly": true},
		{"target": "/run/chengwang-probe/dot-ca.pem", "source": env.values["M2B_PROBE_DOT_CA_FILE"], "readOnly": true},
		{"target": "/run/chengwang-probe/egress-policy.json", "source": env.values["M2B_PROBE_EGRESS_POLICY_FILE"], "readOnly": true},
		{"target": "/var/lib/chengwang-probe/results", "source": env.values["M2B_PROBE_SPOOL_DIR"], "readOnly": false},
		{"target": "/var/lib/chengwang-probe/ledger", "source": env.values["M2B_PROBE_LEDGER_DIR"], "readOnly": false},
	}
	return map[string]any{
		"schema": renderedProjectionSchemaV1, "projectName": env.projectName, "serviceName": serviceName,
		"profile": activeProbeProfile, "image": "chengwang-m2b-probe-agent:" + env.releaseID,
		"build": map[string]string{"context": buildContext, "dockerfile": "deploy/m2b-candidate/Dockerfile.probe-agent"},
		"process": map[string]any{
			"user": "10001:10001", "entrypoint": []string{"/app/probe-agent-entrypoint.sh"}, "command": command,
			"init": true, "restart": "no", "stopSignal": "SIGTERM", "stopGraceNanoseconds": int64(20_000_000_000),
			"stdinOpen": false, "tty": false,
		},
		"security":    map[string]any{"readOnly": true, "privileged": false, "capDrop": []string{"ALL"}, "securityOpt": []string{"no-new-privileges:true"}},
		"resources":   map[string]any{"cpus": "0.25", "memoryBytes": int64(100663296), "reservationBytes": int64(50331648), "pidsLimit": int64(64), "nofileSoft": int64(256), "nofileHard": int64(256)},
		"environment": environment, "mounts": mounts,
		"tmpfs": []string{
			"/run/m2b-probe-health:size=1m,mode=0700,uid=10001,gid=10001,nosuid,nodev,noexec",
			"/tmp:size=4m,mode=1777,nosuid,nodev,noexec",
		},
		"network": map[string]any{"key": "m2b_probe_quarantine", "name": env.projectName + "_m2b_probe_quarantine", "driver": "bridge", "internal": true, "attachable": false, "external": false, "icc": "false", "serviceAttachment": "empty"},
		"health":  map[string]any{"test": []string{"CMD", "/app/probe-agent", "health", "--health-file", "/run/m2b-probe-health/health.json", "--catalog", "/run/chengwang-probe/catalog.json", "--max-age", "20s"}, "intervalNanoseconds": int64(10_000_000_000), "timeoutNanoseconds": int64(3_000_000_000), "startPeriodNanoseconds": int64(5_000_000_000), "retries": int64(3)},
		"logging": map[string]string{"driver": "json-file", "maxFile": "2", "maxSize": "1m"},
		"labels": map[string]string{
			"com.jydn.chengwang.component": "m2b-probe-agent-candidate", "com.jydn.chengwang.active-probes": "true",
			"com.jydn.chengwang.advisory-only": "true", "com.jydn.chengwang.egress-approved": "false",
		},
	}
}

func exactAnyKeys(value map[string]any, keys ...string) bool {
	return len(value) == len(keys) && allowedAnyKeys(value, keys...)
}

func allowedAnyKeys(value map[string]any, keys ...string) bool {
	allowed := make(map[string]struct{}, len(keys))
	for _, key := range keys {
		allowed[key] = struct{}{}
	}
	for key := range value {
		if _, ok := allowed[key]; !ok {
			return false
		}
	}
	return true
}

func stringValue(raw any) string {
	value, _ := raw.(string)
	return value
}

func boolValue(raw any, expected bool) bool {
	value, ok := raw.(bool)
	return ok && value == expected
}

func equalStrings(raw any, expected []string) bool {
	values, ok := raw.([]any)
	if !ok || len(values) != len(expected) {
		return false
	}
	for index, expectedValue := range expected {
		if stringValue(values[index]) != expectedValue {
			return false
		}
	}
	return true
}

func numberValue(raw any, expected string) bool {
	switch value := raw.(type) {
	case json.Number:
		return value.String() == expected
	case string:
		return value == expected
	default:
		return false
	}
}

func durationValue(raw any, text string, nanoseconds int64) bool {
	return stringValue(raw) == text || numberValue(raw, fmt.Sprint(nanoseconds))
}

func stringSliceSet(raw []any, expected []string) bool {
	if len(raw) != len(expected) {
		return false
	}
	wanted := make(map[string]bool, len(expected))
	for _, value := range expected {
		wanted[value] = true
	}
	seen := make(map[string]bool, len(expected))
	for _, value := range raw {
		item := stringValue(value)
		if !wanted[item] || seen[item] {
			return false
		}
		seen[item] = true
	}
	return len(seen) == len(wanted)
}
