package main

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProxyCommandKeepsFixedPrivilegeBoundary(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate command source")
	}
	root := filepath.Dir(source)
	linuxSource, err := os.ReadFile(filepath.Join(root, "main_linux.go"))
	if err != nil {
		t.Fatal(err)
	}
	text := string(linuxSource)
	required := []string{
		`frontendDirectory = "/run/chengwang-runtime-observer"`,
		`frontendSocket    = "/run/chengwang-runtime-observer/readonly.sock"`,
		`observerGroup     = "chengwang-runtime-observer"`,
		"dockerreadonlyproxy.NewCollector()",
		"dockerreadonlyproxy.NewServer(collector)",
	}
	for _, token := range required {
		if !strings.Contains(text, token) {
			t.Fatalf("fixed command contract is missing %q", token)
		}
	}
	forbidden := []string{"flag.", "os.Getenv", "os.LookupEnv", "os/exec", "docker.sock"}
	for _, token := range forbidden {
		if strings.Contains(text, token) {
			t.Fatalf("command contains caller-controlled or direct Docker capability %q", token)
		}
	}
}
