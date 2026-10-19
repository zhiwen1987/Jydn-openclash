package restoreruntime

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestObserverProductionSourcesForbidDockerWriteCapabilities(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate source directory")
	}
	root := filepath.Dir(source)
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	forbidden := []string{
		"/var/run/docker.sock", "/run/docker.sock", "os/exec", "docker/client", "DOCKER_HOST", "DOCKER_CONTEXT",
		"ProxyFromEnvironment", "http.MethodPost", "http.MethodPut", "http.MethodPatch", "http.MethodDelete",
	}
	productionFiles := 0
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		productionFiles++
		raw, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		for _, token := range forbidden {
			if strings.Contains(string(raw), token) {
				t.Fatalf("production observer source %s contains forbidden capability %q", entry.Name(), token)
			}
		}
	}
	if productionFiles < 3 {
		t.Fatalf("unexpected production source count: %d", productionFiles)
	}
}
