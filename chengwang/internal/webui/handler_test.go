package webui

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestNewRequiresIndex(t *testing.T) {
	if _, err := New(t.TempDir(), http.NotFoundHandler()); err == nil {
		t.Fatal("expected missing index error")
	}
}

func TestHandlerServesAPIAssetsAndSPAFallback(t *testing.T) {
	root := t.TempDir()
	if err := os.Mkdir(filepath.Join(root, "assets"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("<main>console</main>"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "assets", "app.js"), []byte("console.log('ok')"), 0o644); err != nil {
		t.Fatal(err)
	}
	api := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTeapot)
	})
	handler, err := New(root, api)
	if err != nil {
		t.Fatal(err)
	}

	apiResponse := request(t, handler, http.MethodGet, "/api/v1/health")
	if apiResponse.Code != http.StatusTeapot {
		t.Fatalf("api status = %d, want %d", apiResponse.Code, http.StatusTeapot)
	}

	assetResponse := request(t, handler, http.MethodGet, "/assets/app.js")
	if assetResponse.Code != http.StatusOK || !strings.Contains(assetResponse.Body.String(), "console.log") {
		t.Fatalf("asset response = %d %q", assetResponse.Code, assetResponse.Body.String())
	}
	if got := assetResponse.Header().Get("Cache-Control"); !strings.Contains(got, "immutable") {
		t.Fatalf("asset cache-control = %q", got)
	}

	spaResponse := request(t, handler, http.MethodGet, "/device-readback")
	if spaResponse.Code != http.StatusOK || !strings.Contains(spaResponse.Body.String(), "console") {
		t.Fatalf("spa response = %d %q", spaResponse.Code, spaResponse.Body.String())
	}
	if got := spaResponse.Header().Get("Content-Security-Policy"); !strings.Contains(got, "default-src 'self'") {
		t.Fatalf("content-security-policy = %q", got)
	}
}

func TestHandlerRejectsStaticWrites(t *testing.T) {
	root := t.TempDir()
	if err := os.WriteFile(filepath.Join(root, "index.html"), []byte("ok"), 0o644); err != nil {
		t.Fatal(err)
	}
	handler, err := New(root, http.NotFoundHandler())
	if err != nil {
		t.Fatal(err)
	}
	response := request(t, handler, http.MethodPost, "/")
	if response.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want %d", response.Code, http.StatusMethodNotAllowed)
	}
}

func request(t *testing.T, handler http.Handler, method, target string) *httptest.ResponseRecorder {
	t.Helper()
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, httptest.NewRequest(method, target, nil))
	return response
}
