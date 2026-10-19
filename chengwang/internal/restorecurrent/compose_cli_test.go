//go:build composecli

package restorecurrent

import (
	"context"
	"encoding/json"
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
		t.Fatalf("actual Docker Compose v2 output violates the local release contract: %v; safe_shape=%s", err, renderedComposeKeyShape(rendered))
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

func renderedComposeKeyShape(raw []byte) string {
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
