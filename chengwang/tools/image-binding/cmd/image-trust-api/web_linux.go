//go:build linux

package main

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const webMaxAssetBytes = 2 << 20
const webMaxTotalBytes = 8 << 20
const webMaxAssets = 64

type webResource struct {
	contentType string
	bytes       []byte
}
type webBundle struct{ resources map[string]webResource }
type webManifestEntry struct {
	File           string   `json:"file"`
	Src            string   `json:"src"`
	Name           string   `json:"name"`
	Names          []string `json:"names"`
	IsEntry        bool     `json:"isEntry"`
	IsDynamicEntry bool     `json:"isDynamicEntry"`
	Imports        []string `json:"imports"`
	DynamicImports []string `json:"dynamicImports"`
	CSS            []string `json:"css"`
	Assets         []string `json:"assets"`
}

// The public page contains no trusted identity. Its same-origin data requests
// still pass the actual API's bearer/RBAC checks. No inline script/style,
// external origin, framing, cache or directory browsing is enabled here.
func candidateSecurityHeaders(w http.ResponseWriter) {
	w.Header().Set("Content-Security-Policy", "default-src 'none'; script-src 'self'; style-src 'self'; connect-src 'self'; img-src 'self'; font-src 'self'; base-uri 'none'; object-src 'none'; frame-ancestors 'none'; form-action 'self'")
	w.Header().Set("Cache-Control", "no-store")
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("X-Frame-Options", "DENY")
	w.Header().Set("Referrer-Policy", "no-referrer")
}

func (b *webBundle) serve(w http.ResponseWriter, r *http.Request) bool {
	if b == nil || r.URL.RawPath != "" || r.URL.RawQuery != "" || r.URL.ForceQuery {
		return false
	}
	resource, ok := b.resources[r.URL.Path]
	if !ok {
		return false
	}
	candidateSecurityHeaders(w)
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		w.Header().Set("Allow", "GET, HEAD")
		w.WriteHeader(http.StatusMethodNotAllowed)
		return true
	}
	w.Header().Set("Content-Type", resource.contentType)
	w.Header().Set("Content-Length", strconv.Itoa(len(resource.bytes)))
	w.WriteHeader(http.StatusOK)
	if r.Method == http.MethodGet {
		_, _ = w.Write(resource.bytes)
	}
	return true
}

func webAssetType(name string) (string, bool) {
	if !strings.HasPrefix(name, "assets/") || !webFilename(strings.TrimPrefix(name, "assets/")) {
		return "", false
	}
	switch filepath.Ext(name) {
	case ".js":
		return "text/javascript; charset=utf-8", true
	case ".css":
		return "text/css; charset=utf-8", true
	case ".svg":
		return "image/svg+xml", true
	case ".woff2":
		return "font/woff2", true
	}
	return "", false
}

func webFilename(name string) bool {
	if len(name) == 0 || len(name) > 160 || name[0] == '.' {
		return false
	}
	for _, ch := range name {
		if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
			return false
		}
	}
	return true
}

func loadWebBundle(directory string) (*webBundle, error) {
	if directory == "" {
		return nil, nil
	}
	root, err := openWebDirectory(directory)
	if err != nil {
		return nil, errConfiguration
	}
	defer unix.Close(root)
	manifestRaw, err := readWebFile(root, ".vite/manifest.json", 256<<10)
	if err != nil {
		return nil, errConfiguration
	}
	var manifest map[string]webManifestEntry
	if strictDecode(manifestRaw, &manifest) != nil || len(manifest) == 0 || len(manifest) > 256 {
		return nil, errConfiguration
	}
	entry, ok := manifest["trust.html"]
	if !ok || !entry.IsEntry || entry.Src != "trust.html" {
		return nil, errConfiguration
	}
	page, err := readWebFile(root, "trust.html", 256<<10)
	if err != nil {
		return nil, errConfiguration
	}
	bundle := &webBundle{resources: map[string]webResource{"/trust.html": {contentType: "text/html; charset=utf-8", bytes: page}}}
	total := len(page)
	add := func(name string) error {
		contentType, ok := webAssetType(name)
		if !ok {
			return errConfiguration
		}
		if _, exists := bundle.resources["/"+name]; exists {
			return nil
		}
		if len(bundle.resources)-1 >= webMaxAssets {
			return errConfiguration
		}
		raw, err := readWebFile(root, name, webMaxAssetBytes)
		if err != nil || len(raw) > webMaxTotalBytes-total {
			return errConfiguration
		}
		total += len(raw)
		bundle.resources["/"+name] = webResource{contentType: contentType, bytes: raw}
		return nil
	}
	seen := map[string]bool{}
	var visit func(string, int) error
	visit = func(key string, depth int) error {
		if len(key) == 0 || len(key) > 256 || depth > 16 {
			return errConfiguration
		}
		if seen[key] {
			return nil
		}
		seen[key] = true
		entry, found := manifest[key]
		if !found || add(entry.File) != nil {
			return errConfiguration
		}
		for _, name := range append(append([]string{}, entry.CSS...), entry.Assets...) {
			if err := add(name); err != nil {
				return err
			}
		}
		for _, dependency := range append(append([]string{}, entry.Imports...), entry.DynamicImports...) {
			if err := visit(dependency, depth+1); err != nil {
				return err
			}
		}
		return nil
	}
	if visit("trust.html", 0) != nil {
		return nil, errConfiguration
	}
	// Validate every HTML source/link reference against the already bounded
	// Vite reachability graph. Do not guess JavaScript dependencies with regex.
	for _, match := range regexp.MustCompile(`(?i)(?:src|href)\s*=\s*["']([^"']+)["']`).FindAllSubmatch(page, -1) {
		name := strings.TrimPrefix(string(match[1]), "/")
		if _, ok := bundle.resources["/"+name]; !ok || name == "trust.html" {
			return nil, errConfiguration
		}
	}
	return bundle, nil
}

func openWebDirectory(directory string) (int, error) {
	if !filepath.IsAbs(directory) || filepath.Clean(directory) != directory || directory == "/" || strings.ContainsAny(directory, "\\\x00") {
		return -1, errConfiguration
	}
	fd, err := unix.Open("/", unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
	if err != nil {
		return -1, errConfiguration
	}
	parts := strings.Split(strings.TrimPrefix(directory, "/"), "/")
	for i, part := range parts {
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		_ = unix.Close(fd)
		if err != nil {
			return -1, errConfiguration
		}
		fd = next
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 && !(i < len(parts)-1 && stat.Uid == 0 && stat.Mode&unix.S_ISVTX != 0) {
			_ = unix.Close(fd)
			return -1, errConfiguration
		}
	}
	return fd, nil
}

func readWebFile(root int, name string, limit int64) ([]byte, error) {
	parts := strings.Split(name, "/")
	fd, err := unix.Dup(root)
	if err != nil {
		return nil, errConfiguration
	}
	defer func() { _ = unix.Close(fd) }()
	for _, part := range parts[:len(parts)-1] {
		if part != ".vite" && !webFilename(part) || part == "." || part == ".." {
			return nil, errConfiguration
		}
		next, err := unix.Openat(fd, part, unix.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC|unix.O_NOFOLLOW, 0)
		if err != nil {
			return nil, errConfiguration
		}
		_ = unix.Close(fd)
		fd = next
		var stat unix.Stat_t
		if unix.Fstat(fd, &stat) != nil || stat.Uid != 0 && stat.Uid != uint32(os.Geteuid()) || stat.Mode&0022 != 0 {
			return nil, errConfiguration
		}
	}
	if !webFilename(parts[len(parts)-1]) {
		return nil, errConfiguration
	}
	fileFD, err := unix.Openat(fd, parts[len(parts)-1], unix.O_RDONLY|unix.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return nil, errConfiguration
	}
	file := os.NewFile(uintptr(fileFD), "candidate-built-web-resource")
	defer file.Close()
	var before, after unix.Stat_t
	if unix.Fstat(fileFD, &before) != nil || before.Mode&unix.S_IFMT != unix.S_IFREG || before.Mode&0022 != 0 || before.Mode&0111 != 0 || before.Nlink != 1 || before.Uid != 0 && before.Uid != uint32(os.Geteuid()) || before.Size <= 0 || before.Size > limit {
		return nil, errConfiguration
	}
	raw, err := io.ReadAll(io.LimitReader(file, limit+1))
	if err != nil || int64(len(raw)) != before.Size || unix.Fstat(fileFD, &after) != nil || before.Dev != after.Dev || before.Ino != after.Ino || before.Size != after.Size || before.Mtim != after.Mtim || before.Ctim != after.Ctim {
		return nil, errConfiguration
	}
	return raw, nil
}
