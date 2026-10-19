package restoreimage

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// This scanner is intentionally separate from production logic. It checks all
// production files, including inactive platform/build-tag files, so capability
// changes require review rather than depending on the CI host's build target.
func checkImageProductionSource(name string, source []byte) error {
	file, err := parser.ParseFile(token.NewFileSet(), name, source, parser.ParseComments|parser.AllErrors)
	if err != nil {
		return fmt.Errorf("invalid production Go source: %s", name)
	}
	if file.Name.Name != "restoreimage" {
		return fmt.Errorf("unexpected production package: %s", name)
	}
	allowed := map[string]bool{
		"compress/gzip": true, "context": true,
		"bytes": true, "crypto/sha256": true, "encoding/hex": true,
		"encoding/json": true, "errors": true, "io": true, "regexp": true,
		"strconv": true, "strings": true, "unicode/utf8": true, "sort": true,
		"chengwang/internal/restorecurrent": true,
		"chengwang/internal/restoreruntime": true,
	}
	parentSelectors := map[string]map[string]bool{
		"restorecurrent": {
			"BlockerCode":                              true,
			"BlockerCandidateIDAttestationMissing":     true,
			"BlockerComposeSourceAttestationMissing":   true,
			"BlockerComposeRenderedAttestationMissing": true,
			"BlockerImageIdentityAttestationMissing":   true,
			"BlockerLiveContainerIdentityNotObserved":  true,
			"BlockerLiveQuiesceNotAuthorized":          true,
			"BlockerStateWriterQuiesceUnproven":        true,
			"BlockerProbeStatePathBindingUnproven":     true,
			"BlockerExternalTimeAnchorMissing":         true,
		},
		"restoreruntime": {
			"Observation": true, "ObservationSchemaV1": true, "ObservationBoundary": true,
		},
	}
	importedParents := map[string]bool{}
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !allowed[path] {
			return fmt.Errorf("unreviewed production import in %s", name)
		}
		// Reject aliases as well as dot/blank imports; the exact package names
		// make restricted parent selector checks explicit and auditable.
		if spec.Name != nil {
			return fmt.Errorf("production import alias is forbidden in %s", name)
		}
		if path == "chengwang/internal/restorecurrent" {
			importedParents["restorecurrent"] = true
		}
		if path == "chengwang/internal/restoreruntime" {
			importedParents["restoreruntime"] = true
		}
	}
	for _, group := range file.Comments {
		for _, comment := range group.List {
			for _, directive := range []string{"go:linkname", "go:embed", "go:cgo_", "go:wasmimport", "go:wasmexport", "//extern"} {
				if strings.Contains(comment.Text, directive) {
					return fmt.Errorf("native or external compiler directive forbidden in %s", name)
				}
			}
		}
	}
	var violation error
	ast.Inspect(file, func(node ast.Node) bool {
		if violation != nil {
			return false
		}
		switch node := node.(type) {
		case *ast.Ident:
			// Builtin print/println bypass the import boundary and can emit raw
			// inputs. Conservatively reserve both names throughout production.
			if node.Name == "print" || node.Name == "println" {
				violation = fmt.Errorf("builtin output capability forbidden in %s", name)
			}
		case *ast.FuncDecl:
			if node.Name.Name == "init" || node.Body == nil {
				violation = fmt.Errorf("implicit initializer or external function forbidden in %s", name)
			}
		case *ast.SelectorExpr:
			parent, ok := node.X.(*ast.Ident)
			if ok && importedParents[parent.Name] && !parentSelectors[parent.Name][node.Sel.Name] {
				violation = fmt.Errorf("unreviewed parent selector %s.%s in %s", parent.Name, node.Sel.Name, name)
			}
		}
		return violation == nil
	})
	return violation
}

func checkImageProductionDirectory(root string) error {
	entries, err := os.ReadDir(root)
	if err != nil {
		return err
	}
	productionFiles := 0
	nativeExtensions := map[string]bool{
		".s": true, ".syso": true, ".c": true, ".h": true, ".cc": true,
		".cpp": true, ".cxx": true, ".hpp": true, ".hh": true, ".hxx": true,
		".m": true, ".mm": true, ".f": true, ".f90": true, ".for": true,
		".o": true, ".obj": true, ".a": true, ".lib": true, ".so": true,
		".dll": true, ".dylib": true, ".wasm": true, ".swig": true, ".swigcxx": true,
	}
	for _, entry := range entries {
		if entry.IsDir() {
			continue
		}
		if entry.Type()&os.ModeSymlink != 0 {
			return fmt.Errorf("source symlink forbidden: %s", entry.Name())
		}
		if nativeExtensions[strings.ToLower(filepath.Ext(entry.Name()))] {
			return fmt.Errorf("native source attachment forbidden: %s", entry.Name())
		}
		if !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		productionFiles++
		raw, err := os.ReadFile(filepath.Join(root, entry.Name()))
		if err != nil {
			return err
		}
		if err := checkImageProductionSource(entry.Name(), raw); err != nil {
			return err
		}
	}
	if productionFiles == 0 {
		return fmt.Errorf("production Go source set is empty")
	}
	return nil
}

func TestProductionSourcesKeepPureByteAndParentTypeBoundary(t *testing.T) {
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate production source directory")
	}
	if err := checkImageProductionDirectory(filepath.Dir(source)); err != nil {
		t.Fatal(err)
	}
}

func TestProductionSourceScannerRejectsCapabilityChanges(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"file-access", `package restoreimage; import "os"; var _ = os.ReadFile`},
		{"file-access-alias", `package restoreimage; import b "os"; var _ = b.ReadFile`},
		{"network", `package restoreimage; import "net"; var _ = net.Dial`},
		{"http", `package restoreimage; import "net/http"; var _ = http.Get`},
		{"exec", `package restoreimage; import "os/exec"; var _ = exec.Command`},
		{"unsafe", `package restoreimage; import "unsafe"; var _ unsafe.Pointer`},
		{"cgo", `package restoreimage; import "C"`},
		{"embed", `package restoreimage; import "embed"; var _ embed.FS`},
		{"unreviewed-dependency", `package restoreimage; import "chengwang/internal/restorecoordinator"; var _ = restorecoordinator.Open`},
		{"blank-import", `package restoreimage; import _ "bytes"`},
		{"dot-import", `package restoreimage; import . "bytes"; var _ = NewReader`},
		{"approved-import-alias", `package restoreimage; import b "bytes"; var _ = b.NewReader`},
		{"parent-alias-call", `package restoreimage; import b "chengwang/internal/restoreruntime"; var _ = b.Capture`},
		{"runtime-call", `package restoreimage; import "chengwang/internal/restoreruntime"; func f(){ restoreruntime.Capture(nil,nil) }`},
		{"runtime-function-value", `package restoreimage; import "chengwang/internal/restoreruntime"; var f = restoreruntime.Capture`},
		{"current-open-call", `package restoreimage; import "chengwang/internal/restorecurrent"; var _ = restorecurrent.OpenLocalRelease`},
		{"parent-unreviewed-type", `package restoreimage; import "chengwang/internal/restorecurrent"; var _ restorecurrent.Handle`},
		{"parent-unreviewed-blocker", `package restoreimage; import "chengwang/internal/restorecurrent"; var _ = restorecurrent.BlockerFuture`},
		{"init", `package restoreimage; func init(){}`},
		{"builtin-print", `package restoreimage; func f(){ print("secret") }`},
		{"builtin-println", `package restoreimage; func f(){ println("secret") }`},
		{"builtin-print-function-value", `package restoreimage; var output = print`},
		{"builtin-println-function-value", `package restoreimage; var output = println`},
		{"variable-initializer-output", `package restoreimage; var output = func() int { println("secret"); return 0 }()`},
		{"external-function", "package restoreimage\nfunc external()"},
		{"linkname", "package restoreimage\n//go:linkname f os.ReadFile\nfunc f(){}"},
		{"embed-directive", "package restoreimage\n//go:embed secret.txt\nvar x string"},
		{"cgo-directive", "package restoreimage\n//go:cgo_import_dynamic f f\nfunc f(){}"},
		{"wasmimport", "package restoreimage\n//go:wasmimport env f\nfunc f(){}"},
		{"wrong-package", `package replacement`},
		{"invalid-go", `package restoreimage; import (`},
		{"inactive-platform-file", "//go:build unknownplatform\n\npackage restoreimage\nimport \"os\""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkImageProductionSource("synthetic.go", []byte(tc.source)); err == nil {
				t.Fatal("forbidden source accepted")
			}
		})
	}
}

func TestProductionSourceScannerAcceptsReviewedPureCode(t *testing.T) {
	for _, tc := range []struct{ name, source string }{
		{"single-import", `package restoreimage; import "bytes"; var _ = bytes.NewReader`},
		{"parent-types-and-constants", `package restoreimage; import ("chengwang/internal/restorecurrent"; "chengwang/internal/restoreruntime"); var _ restoreruntime.Observation; var _ restorecurrent.BlockerCode; const _ = restoreruntime.ObservationSchemaV1; const _ = restoreruntime.ObservationBoundary; const _ = restorecurrent.BlockerExternalTimeAnchorMissing`},
		{"getter-on-observation", `package restoreimage; import "chengwang/internal/restoreruntime"; func f(value restoreruntime.Observation) string { return value.ImageID() }`},
		{"ordinary-comment", "package restoreimage\n// This package parses bytes without IO.\nfunc f(){}"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := checkImageProductionSource("synthetic.go", []byte(tc.source)); err != nil {
				t.Fatal(err)
			}
		})
	}
}

func TestProductionSourceScannerRejectsNativeAttachments(t *testing.T) {
	for _, extension := range []string{".s", ".S", ".syso", ".c", ".h", ".cc", ".cpp", ".CXX", ".hpp", ".m", ".mm", ".f", ".f90", ".o", ".obj", ".a", ".lib", ".so", ".dll", ".dylib", ".wasm", ".swig", ".swigcxx"} {
		t.Run(extension, func(t *testing.T) {
			root := t.TempDir()
			if err := os.WriteFile(filepath.Join(root, "pure.go"), []byte("package restoreimage"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(root, "attachment"+extension), []byte("native"), 0600); err != nil {
				t.Fatal(err)
			}
			if err := checkImageProductionDirectory(root); err == nil {
				t.Fatal("native attachment accepted")
			}
		})
	}
}
