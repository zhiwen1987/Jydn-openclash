//go:build linux

package main

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func candidateD8Web(t *testing.T) (string, map[string]webManifestEntry) {
	t.Helper()
	directory := t.TempDir()
	if os.Chmod(directory, 0700) != nil || os.Mkdir(filepath.Join(directory, ".vite"), 0755) != nil || os.Mkdir(filepath.Join(directory, "assets"), 0755) != nil {
		t.Fatal("create isolated built web fixture")
	}
	manifest := map[string]webManifestEntry{
		"trust.html": {File: "assets/trust.js", Src: "trust.html", IsEntry: true, Imports: []string{"_shared.js"}, CSS: []string{"assets/trust.css"}},
		"_shared.js": {File: "assets/shared.js", Assets: []string{"assets/glyph.svg", "assets/font.woff2"}},
		"index.html": {File: "assets/unrelated.js", Src: "index.html", IsEntry: true},
	}
	for name, raw := range map[string]string{
		"trust.html":          "<!doctype html><html><head><link rel=\"stylesheet\" href=\"/assets/trust.css\"></head><body><div id=\"root\"></div><script type=\"module\" src=\"/assets/trust.js\"></script></body></html>",
		"assets/trust.js":     "import './shared.js'; document.body.dataset.loaded='true';",
		"assets/shared.js":    "export const publicValue=true;",
		"assets/trust.css":    "body{color:#123}",
		"assets/glyph.svg":    "<svg xmlns=\"http://www.w3.org/2000/svg\"></svg>",
		"assets/font.woff2":   "isolated-font-fixture",
		"assets/unrelated.js": "not reachable from trust.html",
		"unrelated.json":      "must never be served",
	} {
		candidatePrivateFile(t, filepath.Join(directory, filepath.FromSlash(name)), []byte(raw))
	}
	candidatePrivateFile(t, filepath.Join(directory, ".vite", "manifest.json"), candidateJSON(t, manifest))
	return directory, manifest
}

func TestCandidateD8WebManifestLoadsOnlyReachableImmutableResources(t *testing.T) {
	directory, _ := candidateD8Web(t)
	bundle, err := loadWebBundle(directory)
	if err != nil || bundle == nil || len(bundle.resources) != 6 {
		t.Fatal("valid bounded Vite reachability graph rejected")
	}
	if disabled, err := loadWebBundle(""); err != nil || disabled != nil {
		t.Fatal("default enabled public web serving")
	}
	// Serving uses the already validated bytes, not a later mutable file read.
	old := bytes.Clone(bundle.resources["/assets/trust.js"].bytes)
	candidatePrivateFile(t, filepath.Join(directory, "assets", "trust.js"), []byte("changed after load"))
	for path, expectedType := range map[string]string{"/trust.html": "text/html; charset=utf-8", "/assets/trust.js": "text/javascript; charset=utf-8", "/assets/trust.css": "text/css; charset=utf-8", "/assets/glyph.svg": "image/svg+xml", "/assets/font.woff2": "font/woff2"} {
		request := httptest.NewRequest(http.MethodGet, path, nil)
		response := httptest.NewRecorder()
		if !bundle.serve(response, request) || response.Code != http.StatusOK || response.Header().Get("Content-Type") != expectedType || response.Header().Get("Cache-Control") != "no-store" || response.Header().Get("X-Content-Type-Options") != "nosniff" || response.Header().Get("X-Frame-Options") != "DENY" {
			t.Fatal("invalid public resource response")
		}
		csp := response.Header().Get("Content-Security-Policy")
		if !strings.Contains(csp, "script-src 'self'") || strings.Contains(csp, "unsafe-inline") || !strings.Contains(csp, "frame-ancestors 'none'") {
			t.Fatal("static CSP weakened")
		}
		if path == "/assets/trust.js" && !bytes.Equal(response.Body.Bytes(), old) {
			t.Fatal("resource changed after safe preload")
		}
	}
	for _, path := range []string{"/", "/index.html", "/.vite/manifest.json", "/assets/", "/assets/unrelated.js", "/unrelated.json", "/api/v1/versions", "/assets/trust.js?token=excluded", "/assets/%74rust.js"} {
		if bundle.serve(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil)) {
			t.Fatal("unreferenced or noncanonical route served", path)
		}
	}
	head := httptest.NewRecorder()
	if !bundle.serve(head, httptest.NewRequest(http.MethodHead, "/trust.html", nil)) || head.Code != 200 || head.Body.Len() != 0 || head.Header().Get("Content-Length") == "" {
		t.Fatal("HEAD served a body or lacked resource size")
	}
	method := httptest.NewRecorder()
	if !bundle.serve(method, httptest.NewRequest(http.MethodPost, "/trust.html", nil)) || method.Code != 405 {
		t.Fatal("static write method accepted")
	}
}

func TestCandidateD8WebLoaderRejectsUnsafeBuilds(t *testing.T) {
	for _, kind := range []string{"relative", "root", "directory-symlink", "assets-symlink", "manifest-symlink", "file-symlink", "hardlink", "directory-mode", "file-mode", "executable", "directory-asset", "unsupported-extension", "traversal", "missing-asset", "missing-entry", "unknown-field", "case-alias", "escaped-alias", "deep-graph", "too-many-assets", "oversized-asset", "oversized-html", "total-budget", "external-html", "missing-manifest"} {
		t.Run(kind, func(t *testing.T) {
			directory, manifest := candidateD8Web(t)
			target := directory
			asset := filepath.Join(directory, "assets", "trust.js")
			manifestPath := filepath.Join(directory, ".vite", "manifest.json")
			switch kind {
			case "relative":
				target = "relative-web-dir"
			case "root":
				target = "/"
			case "directory-symlink":
				target = filepath.Join(t.TempDir(), "linked-web")
				if os.Symlink(directory, target) != nil {
					t.Fatal("create directory symlink fixture")
				}
			case "assets-symlink":
				path := filepath.Join(directory, "assets")
				if os.Rename(path, path+"-retained") != nil || os.Symlink(path+"-retained", path) != nil {
					t.Fatal("create assets symlink fixture")
				}
			case "manifest-symlink", "file-symlink":
				path := asset
				if kind == "manifest-symlink" {
					path = manifestPath
				}
				if os.Rename(path, path+".retained") != nil || os.Symlink(path+".retained", path) != nil {
					t.Fatal("create file symlink fixture")
				}
			case "hardlink":
				if os.Link(asset, asset+".linked") != nil {
					t.Fatal("create hardlink fixture")
				}
			case "directory-mode":
				if os.Chmod(directory, 0770) != nil {
					t.Fatal("change directory fixture mode")
				}
			case "file-mode":
				if os.Chmod(asset, 0660) != nil {
					t.Fatal("change file fixture mode")
				}
			case "executable":
				if os.Chmod(asset, 0700) != nil {
					t.Fatal("change executable fixture mode")
				}
			case "directory-asset":
				if os.Remove(asset) != nil || os.Mkdir(asset, 0700) != nil {
					t.Fatal("create nonregular fixture")
				}
			case "unsupported-extension", "traversal", "missing-asset":
				entry := manifest["trust.html"]
				entry.File = map[string]string{"unsupported-extension": "assets/config.json", "traversal": "assets/../../private.js", "missing-asset": "assets/missing.js"}[kind]
				manifest["trust.html"] = entry
			case "missing-entry":
				delete(manifest, "trust.html")
			case "deep-graph":
				for i := 0; i < 18; i++ {
					entry := webManifestEntry{File: "assets/shared.js", Imports: []string{"depth-" + strconv.Itoa(i+1)}}
					manifest["depth-"+strconv.Itoa(i)] = entry
				}
				entry := manifest["trust.html"]
				entry.Imports = []string{"depth-0"}
				manifest["trust.html"] = entry
			case "too-many-assets", "total-budget":
				entry := manifest["trust.html"]
				count, size := webMaxAssets+1, 1
				if kind == "total-budget" {
					count, size = 5, webMaxAssetBytes
				}
				for i := 0; i < count; i++ {
					name := "assets/extra-" + strconv.Itoa(i) + ".js"
					candidatePrivateFile(t, filepath.Join(directory, filepath.FromSlash(name)), bytes.Repeat([]byte("x"), size))
					entry.Assets = append(entry.Assets, name)
				}
				manifest["trust.html"] = entry
			case "oversized-asset":
				candidatePrivateFile(t, asset, bytes.Repeat([]byte("x"), webMaxAssetBytes+1))
			case "oversized-html":
				candidatePrivateFile(t, filepath.Join(directory, "trust.html"), bytes.Repeat([]byte("x"), (256<<10)+1))
			case "external-html":
				candidatePrivateFile(t, filepath.Join(directory, "trust.html"), []byte(`<script src="https://excluded.invalid/remote.js"></script>`))
			}
			if kind != "manifest-symlink" {
				raw := candidateJSON(t, manifest)
				switch kind {
				case "unknown-field":
					raw = bytes.Replace(raw, []byte(`"isEntry":true`), []byte(`"isEntry":true,"bootstrap":true`), 1)
				case "case-alias":
					raw = bytes.Replace(raw, []byte(`"file":`), []byte(`"File":`), 1)
				case "escaped-alias":
					raw = bytes.Replace(raw, []byte(`"file":`), []byte(`"\u0066ile":`), 1)
				}
				candidatePrivateFile(t, manifestPath, raw)
			}
			if kind == "missing-manifest" && os.Remove(manifestPath) != nil {
				t.Fatal("remove isolated manifest")
			}
			if bundle, err := loadWebBundle(target); err != errConfiguration || bundle != nil {
				t.Fatal("unsafe compiled web directory accepted")
			}
		})
	}
}

func TestCandidateD8StaticRoutesUseRealCandidateAndHistory(t *testing.T) {
	directory, _ := candidateD8Web(t)
	f := newCandidateFixture(t, true)
	f.config.WebDir = directory
	candidateD7Write(t, f)
	address, stop := candidateD7Start(t, f)
	defer stop()
	transport := &http.Transport{Proxy: nil}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport}
	for _, item := range []struct {
		path, token string
		code        int
	}{
		{"/trust.html", "", 200}, {"/assets/trust.js", "", 200},
		{"/api/v1/image-trust/history", "", 401}, {"/api/v1/image-trust/history", f.token, 200},
		{"/api/v1/versions", f.token, 404}, {"/api/v1/publish", f.token, 404},
		{"/index.html", "", 404}, {"/.vite/manifest.json", "", 404}, {"/assets/unrelated.js", "", 404},
	} {
		request, _ := http.NewRequest(http.MethodGet, "http://"+address+item.path, nil)
		if item.token != "" {
			request.Header.Set("Authorization", "Bearer "+item.token)
		}
		response, err := client.Do(request)
		if err != nil {
			t.Fatal("real candidate request failed")
		}
		raw, readErr := io.ReadAll(io.LimitReader(response.Body, 1<<20))
		_ = response.Body.Close()
		if readErr != nil || response.StatusCode != item.code || response.Header.Get("Cache-Control") != "no-store" || bytes.Contains(raw, []byte(f.token)) {
			t.Fatal("real candidate static/API routing or redaction failed", item.path)
		}
		if item.code == 404 && !json.Valid(raw) {
			t.Fatal("unknown route fell back to HTML")
		}
	}
}
