//go:build composecli

package restorecurrent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"testing"
	"time"
)

func TestComposeCLIRenderedOutputMatchesLocalReleaseContract(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Fatal("Compose CLI compatibility gate is Linux-only")
	}
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository root")
	}
	repositoryRoot := filepath.Clean(filepath.Join(filepath.Dir(currentFile), "..", ".."))
	projectDirectory := filepath.Join(repositoryRoot, "deploy", "m2b-candidate")
	composeFile := filepath.Join(projectDirectory, "compose.probe-agent.yaml")

	candidateRoot := "/var/lib/chengwang-m2b-candidate/composecompat"
	contents := validConfigurationContents(t, candidateRoot)
	environment, err := validateConfiguration(contents, candidateRoot, "composecompat")
	if err != nil {
		t.Fatal(err)
	}
	envFile := filepath.Join(t.TempDir(), "probe.env")
	if err := os.WriteFile(envFile, contents.env, 0o600); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	command := exec.CommandContext(
		ctx,
		"docker", "compose", "--env-file", envFile,
		"--project-name", environment.projectName,
		"--project-directory", projectDirectory,
		"-f", composeFile,
		"--profile", activeProbeProfile,
		"config", "--format", "json",
	)
	for _, variable := range os.Environ() {
		if !strings.HasPrefix(variable, "COMPOSE_") {
			command.Env = append(command.Env, variable)
		}
	}
	command.Env = append(command.Env, "COMPOSE_IGNORE_ORPHANS=1")
	rendered, err := command.CombinedOutput()
	if err != nil {
		t.Fatalf("docker compose config failed: %v: %s", err, strings.TrimSpace(string(rendered)))
	}
	contents.composeJSON = rendered
	buildContext := filepath.ToSlash(repositoryRoot)
	semanticDigest, err := validateRenderedCompose(rendered, environment, buildContext)
	if err != nil {
		t.Fatalf("actual Docker Compose v2 output violates the local release contract: %v; safe_shape=%s", err, renderedComposeKeyShape(rendered, environment))
	}
	binding, err := parseLocalReleaseBinding(contents.composeBinding)
	if err != nil {
		t.Fatal(err)
	}
	binding.BuildContext = buildContext
	binding.RenderedSizeBytes = uint64(len(rendered))
	binding.RenderedSHA256 = releaseDigest(rendered)
	binding.RenderedSemanticSHA256 = semanticDigest
	contents.composeBinding, err = json.Marshal(binding)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := parseCandidateIdentity(contents.identity, candidateRoot, "composecompat", environment.projectName)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := validateLocalRelease(contents, environment, identity); err != nil {
		t.Fatalf("actual Docker Compose v2 release bundle was rejected: %v", err)
	}
}

func renderedComposeKeyShape(raw []byte, environment validatedEnvironment) string {
	var root map[string]any
	if err := json.Unmarshal(raw, &root); err != nil {
		return "unparseable-json"
	}
	parts := []string{"root=" + strings.Join(sortedMapKeys(root), ",")}
	services, ok := root["services"].(map[string]any)
	if !ok {
		return strings.Join(parts, ";")
	}
	parts = append(parts, "services="+strings.Join(sortedMapKeys(services), ","))
	service, ok := services[serviceName].(map[string]any)
	if !ok {
		return strings.Join(parts, ";")
	}
	parts = append(parts, "service="+strings.Join(sortedMapKeys(service), ","))
	if build, ok := service["build"].(map[string]any); ok {
		parts = append(parts, "build="+strings.Join(sortedMapKeys(build), ","))
	}
	if healthcheck, ok := service["healthcheck"].(map[string]any); ok {
		parts = append(parts, "healthcheck="+strings.Join(sortedMapKeys(healthcheck), ","))
	}
	if logging, ok := service["logging"].(map[string]any); ok {
		parts = append(parts, "logging="+strings.Join(sortedMapKeys(logging), ","))
	}
	if volumes, ok := service["volumes"].([]any); ok {
		wanted := map[string]struct {
			source   string
			readOnly bool
		}{
			"/run/chengwang-probe/catalog.json":       {environment.values["M2B_PROBE_CATALOG_FILE"], true},
			"/run/chengwang-probe/dot-ca.pem":         {environment.values["M2B_PROBE_DOT_CA_FILE"], true},
			"/run/chengwang-probe/egress-policy.json": {environment.values["M2B_PROBE_EGRESS_POLICY_FILE"], true},
			"/var/lib/chengwang-probe/results":        {environment.values["M2B_PROBE_SPOOL_DIR"], false},
			"/var/lib/chengwang-probe/ledger":         {environment.values["M2B_PROBE_LEDGER_DIR"], false},
		}
		for index, rawMount := range volumes {
			mount, mountOK := rawMount.(map[string]any)
			if !mountOK {
				parts = append(parts, fmt.Sprintf("mount%d=not-object", index))
				continue
			}
			target := stringValue(mount["target"])
			expected, known := wanted[target]
			bind, bindOK := mount["bind"].(map[string]any)
			parts = append(parts, fmt.Sprintf(
				"mount%d=keys[%s],bindKeys[%s],known[%t],typeBind[%t],sourceMatch[%t],readOnlyMatch[%t],createHostPathFalse[%t]",
				index, strings.Join(sortedMapKeys(mount), ","), strings.Join(sortedMapKeys(bind), ","), known,
				stringValue(mount["type"]) == "bind", known && stringValue(mount["source"]) == expected.source,
				known && boolValue(mount["read_only"], expected.readOnly), bindOK && boolValue(bind["create_host_path"], false),
			))
		}
	}
	if networks, ok := root["networks"].(map[string]any); ok {
		parts = append(parts, "networks="+strings.Join(sortedMapKeys(networks), ","))
		if network, ok := networks["m2b_probe_quarantine"].(map[string]any); ok {
			driverOptions, driverOptionsOK := network["driver_opts"].(map[string]any)
			ipam, ipamOK := network["ipam"].(map[string]any)
			parts = append(parts, fmt.Sprintf(
				"network=keys[%s],nameMatch[%t],driverBridge[%t],attachableFalse[%t],internalTrue[%t],externalFalse[%t],driverOptions[%t],driverOptionKeys[%s],iccFalse[%t],ipamObject[%t],ipamKeys[%s]",
				strings.Join(sortedMapKeys(network), ","), stringValue(network["name"]) == environment.projectName+"_m2b_probe_quarantine",
				stringValue(network["driver"]) == "bridge", omittedOrFalse(network, "attachable"), boolValue(network["internal"], true),
				omittedOrFalse(network, "external"), driverOptionsOK, strings.Join(sortedMapKeys(driverOptions), ","),
				driverOptionsOK && stringValue(driverOptions["com.docker.network.bridge.enable_icc"]) == "false", ipamOK, strings.Join(sortedMapKeys(ipam), ","),
			))
		}
	}
	if serviceNetworks, ok := service["networks"].(map[string]any); ok {
		attachment, exists := serviceNetworks["m2b_probe_quarantine"]
		attachmentObject, attachmentObjectOK := attachment.(map[string]any)
		parts = append(parts, fmt.Sprintf(
			"serviceNetworks=keys[%s],attachmentExists[%t],attachmentNil[%t],attachmentObject[%t],attachmentKeys[%s]",
			strings.Join(sortedMapKeys(serviceNetworks), ","), exists, attachment == nil, attachmentObjectOK, strings.Join(sortedMapKeys(attachmentObject), ","),
		))
	}
	return strings.Join(parts, ";")
}

func sortedMapKeys(value map[string]any) []string {
	keys := make([]string, 0, len(value))
	for key := range value {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}
