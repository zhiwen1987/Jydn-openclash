package evidence

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
)

func TestArchiveExistingProductionSourceHasNoMutationPrimitive(t *testing.T) {
	path := "archive_existing_linux.go"
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), path, raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	forbiddenCalls := map[string]bool{
		"Chmod": true, "Chown": true, "Create": true, "CreateTemp": true,
		"Fchmod": true, "Fchown": true, "Lchown": true, "Mkdir": true,
		"MkdirAll": true, "Mkdirat": true, "Remove": true, "RemoveAll": true,
		"Rename": true, "Renameat": true, "Truncate": true, "Unlinkat": true,
		"WriteFile": true,
	}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		name := ""
		switch fun := call.Fun.(type) {
		case *ast.Ident:
			name = fun.Name
		case *ast.SelectorExpr:
			name = fun.Sel.Name
		}
		if forbiddenCalls[name] {
			t.Errorf("production existing-only source calls forbidden mutation primitive %s", name)
		}
		return true
	})
	forbiddenIdentifiers := map[string]bool{"O_CREAT": true, "O_TRUNC": true, "O_APPEND": true, "O_WRONLY": true}
	ast.Inspect(file, func(node ast.Node) bool {
		if ident, ok := node.(*ast.Ident); ok && forbiddenIdentifiers[ident.Name] {
			t.Errorf("production existing-only source contains forbidden flag %s", ident.Name)
		}
		return true
	})
}

func TestArchiveExistingLinuxOpenAndStreamingPolicy(t *testing.T) {
	raw, err := os.ReadFile("archive_existing_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	required := []string{
		"archiveOpenAt(leaf, lockFilename, syscall.O_RDWR)",
		"archiveOpenAt(leaf, logFilename, syscall.O_RDONLY|syscall.O_NONBLOCK)",
		"archiveOpenAt(leaf, checkpointFilename, syscall.O_RDONLY|syscall.O_NONBLOCK)",
		"archiveOpenAt(directory, name, syscall.O_RDONLY|syscall.O_NONBLOCK)",
		"io.LimitReader(file, before.Size+1)",
	}
	for _, fragment := range required {
		if !strings.Contains(source, fragment) {
			t.Errorf("required existing-only source fragment missing: %s", fragment)
		}
	}
	if strings.Contains(source, "io.ReadAll") {
		t.Error("WAL source must remain streaming")
	}
}

func TestArchiveExistingEventLimitProofPolicy(t *testing.T) {
	raw, err := os.ReadFile("archive_existing_linux.go")
	if err != nil {
		t.Fatal(err)
	}
	source := string(raw)
	required := []string{
		"archiveValidateLogEvent(event, head, eventIDs, idempotency, count < limits.MaxEvents)",
		"if count == limits.MaxEvents",
		"if limits.MaxEvents == math.MaxUint64",
		"proofOrdinal := limits.MaxEvents + 1",
		"archiveProofWindowStable(directory, file, checkpointFile, before, cp)",
		"stableCheckpoint.Count < proofOrdinal",
		"stableCheckpoint.Count == proofOrdinal && stableCheckpoint.LastHash != nextHead",
		"cpBefore.hash != cpAfter.hash",
		"!bytes.Equal(cpBefore.raw, cpAfter.raw)",
		"cpBefore.value != cpAfter.value",
	}
	for _, fragment := range required {
		if !strings.Contains(source, fragment) {
			t.Errorf("required event-limit proof fragment missing: %s", fragment)
		}
	}
	forbidden := []string{
		"if cp.value.Count > limits.MaxEvents",
		"eventIDs[event.ID] = struct{}{} // proof",
	}
	for _, fragment := range forbidden {
		if strings.Contains(source, fragment) {
			t.Errorf("forbidden event-limit shortcut present: %s", fragment)
		}
	}
}

func TestArchiveAnchorAndFormattingMethodsHaveNoCalls(t *testing.T) {
	raw, err := os.ReadFile("archive_existing.go")
	if err != nil {
		t.Fatal(err)
	}
	file, err := parser.ParseFile(token.NewFileSet(), "archive_existing.go", raw, 0)
	if err != nil {
		t.Fatal(err)
	}
	required := map[string]bool{"Anchor": false, "String": false, "GoString": false}
	for _, declaration := range file.Decls {
		function, ok := declaration.(*ast.FuncDecl)
		if !ok || function.Recv == nil {
			continue
		}
		if _, ok := required[function.Name.Name]; !ok {
			continue
		}
		required[function.Name.Name] = true
		ast.Inspect(function.Body, func(node ast.Node) bool {
			if _, ok := node.(*ast.CallExpr); ok {
				t.Errorf("%s must not perform calls, I/O, locking, or lazy work", function.Name.Name)
			}
			return true
		})
	}
	for name, found := range required {
		if !found {
			t.Errorf("required no-call method not found: %s", name)
		}
	}
}

func TestArchiveExistingAPINotCalledByProductionYet(t *testing.T) {
	root := filepath.Clean("../..")
	allowedFutureCaller := filepath.ToSlash("internal/subscription/archive_source_evidence.go")
	reviewedAPIOwners := map[string]bool{
		filepath.ToSlash("internal/evidence/archive_existing.go"):             true,
		filepath.ToSlash("internal/evidence/archive_existing_linux.go"):       true,
		filepath.ToSlash("internal/evidence/archive_existing_unsupported.go"): true,
	}
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if entry.IsDir() || filepath.Ext(path) != ".go" || strings.HasSuffix(path, "_test.go") {
			return nil
		}
		relative, err := filepath.Rel(root, path)
		if err != nil {
			return err
		}
		relative = filepath.ToSlash(relative)
		if reviewedAPIOwners[relative] {
			return nil
		}
		raw, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		for _, violation := range archiveCallerPolicyViolations(relative, raw, allowedFutureCaller) {
			t.Errorf("%s: %s", relative, violation)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
}

func TestArchiveExistingCallerPolicyRejectsReceiverAndHandleEscape(t *testing.T) {
	allowed := filepath.ToSlash("internal/subscription/archive_source_evidence.go")
	fixtures := []struct {
		name     string
		path     string
		source   string
		fragment string
	}{
		{
			name: "unauthorized receiver call",
			path: "internal/subscription/not_the_adapter.go",
			source: `package subscription
import "chengwang/internal/evidence"
func f() { h, _ := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); _ = h.Anchor() }
`,
			fragment: "outside exact future adapter",
		},
		{
			name: "handle return",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() any { h, _ := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); return h }
`,
			fragment: "handle escape or unsupported use",
		},
		{
			name: "handle transfer",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() { h, _ := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); consume(h) }
`,
			fragment: "handle escape or unsupported use",
		},
		{
			name: "method value escape",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() { h, _ := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); closeLater := h.Close; _ = closeLater }
`,
			fragment: "handle escape or unsupported use",
		},
		{
			name: "closure capture",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() { h, _ := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); later := func() { _ = h.Revalidate() }; _ = later }
`,
			fragment: "handle closure or goroutine use is forbidden",
		},
		{
			name: "open outside direct assignment",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() (*evidence.ExistingArchiveSnapshot, error) { return evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}) }
`,
			fragment: "Open reference must be the direct callee",
		},
		{
			name: "parenthesized Open callee",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() any { h, _ := (evidence.OpenExistingArchiveSnapshot)("", evidence.ArchiveExistingReadLimits{}); return h }
`,
			fragment: "Open reference must be the direct callee",
		},
		{
			name: "local Open function alias",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() any { open := evidence.OpenExistingArchiveSnapshot; h, _ := open("", evidence.ArchiveExistingReadLimits{}); return h }
`,
			fragment: "Open reference must be the direct callee",
		},
		{
			name: "package Open function alias",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
var open = evidence.OpenExistingArchiveSnapshot
func f() any { h, _ := open("", evidence.ArchiveExistingReadLimits{}); return h }
`,
			fragment: "Open reference must be the direct callee",
		},
		{
			name: "callback-valued Open",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() { consume(evidence.OpenExistingArchiveSnapshot) }
`,
			fragment: "Open reference must be the direct callee",
		},
		{
			name: "cross-file Open alias declaration",
			path: "internal/subscription/archive_source_alias.go",
			source: `package subscription
import "chengwang/internal/evidence"
var openArchive = evidence.OpenExistingArchiveSnapshot
`,
			fragment: "outside exact future adapter",
		},
		{
			name: "method expression on exported handle type",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
var closeArchive = (*evidence.ExistingArchiveSnapshot).Close
`,
			fragment: "explicit handle type is forbidden",
		},
		{
			name: "new evidence package owner leak",
			path: "internal/evidence/leak.go",
			source: `package evidence
func Leak() any { h, _ := OpenExistingArchiveSnapshot("", ArchiveExistingReadLimits{}); return h }
`,
			fragment: "outside exact future adapter",
		},
		{
			name: "cross-file package global ordinary assignment",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() { var err error; escaped, err = evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); _ = err }
`,
			fragment: "Open must use a fresh function-local short declaration",
		},
		{
			name: "same-file package global ordinary assignment",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
var escaped any
func f() { var err error; escaped, err = evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); _ = err }
`,
			fragment: "Open must use a fresh function-local short declaration",
		},
		{
			name: "named result is not fresh",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() (h any, err error) { h, localErr := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); return h, localErr }
`,
			fragment: "Open handle may not shadow a parameter or named result",
		},
		{
			name: "package global shadow is forbidden",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
var h any
func f() { h, err := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); _, _ = h, err }
`,
			fragment: "Open handle may not shadow a file-scope binding",
		},
		{
			name: "preexisting local is not fresh",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() { var h any; h, err := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); _, _ = h, err }
`,
			fragment: "Open handle must be a newly declared function-local object",
		},
		{
			name: "handle alias",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() { h, _ := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); alias := h; _ = alias }
`,
			fragment: "handle escape or unsupported use",
		},
		{
			name: "handle interface conversion",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() { h, _ := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); var escaped any = h; _ = escaped }
`,
			fragment: "handle escape or unsupported use",
		},
		{
			name: "handle callback",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() { h, _ := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); callback(func() { _ = h.Anchor() }) }
`,
			fragment: "handle closure or goroutine use is forbidden",
		},
		{
			name: "handle goroutine",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() { h, _ := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); go h.Close() }
`,
			fragment: "handle closure or goroutine use is forbidden",
		},
		{
			name: "non-direct receiver",
			path: allowed,
			source: `package subscription
import "chengwang/internal/evidence"
func f() { h, _ := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{}); _ = (h).Anchor() }
`,
			fragment: "handle method requires direct identifier receiver",
		},
	}
	for _, fixture := range fixtures {
		t.Run(fixture.name, func(t *testing.T) {
			violations := archiveCallerPolicyViolations(filepath.ToSlash(fixture.path), []byte(fixture.source), allowed)
			if !archiveViolationContains(violations, fixture.fragment) {
				t.Fatalf("missing %q violation: %v", fixture.fragment, violations)
			}
		})
	}
	accepted := `package subscription
import "chengwang/internal/evidence"
func f() error {
	h, err := evidence.OpenExistingArchiveSnapshot("", evidence.ArchiveExistingReadLimits{MaxLogBytes: 1, MaxEvents: 1})
	if err != nil { return err }
	{
		h := "unrelated shadow"
		_ = h
	}
	_ = h.Anchor()
	if err := h.Revalidate(); err != nil { return err }
	return h.Close()
}
`
	if violations := archiveCallerPolicyViolations(allowed, []byte(accepted), allowed); len(violations) != 0 {
		t.Fatalf("exact adapter local lifecycle was rejected: %v", violations)
	}
}

func archiveCallerPolicyViolations(relative string, raw []byte, allowed string) []string {
	// Mode 0 intentionally keeps the parser's file-local object resolution.
	// The policy admits only a token.DEFINE identifier whose ast.Object is
	// created by that exact AssignStmt; unresolved or cross-file bindings never
	// become handles. Uses are tracked by object identity, not spelling.
	file, err := parser.ParseFile(token.NewFileSet(), relative, raw, 0)
	if err != nil {
		return []string{"parse failure: " + err.Error()}
	}
	guardedSymbols := map[string]bool{
		"OpenExistingArchiveSnapshot": true,
		"Anchor":                      true,
		"Revalidate":                  true,
		"Close":                       true,
		"ExistingArchiveSnapshot":     true,
		"ArchiveExistingReadLimits":   true,
		"ErrArchiveExistingLimit":     true,
		"ArchivePosixIdentity":        true,
		"ArchiveDirectoryAnchor":      true,
		"ArchiveFileAnchor":           true,
		"ArchiveEvidenceAnchor":       true,
	}
	guardedPackageSymbols := map[string]bool{
		"OpenExistingArchiveSnapshot": true,
		"ExistingArchiveSnapshot":     true,
		"ArchiveExistingReadLimits":   true,
		"ErrArchiveExistingLimit":     true,
		"ArchivePosixIdentity":        true,
		"ArchiveDirectoryAnchor":      true,
		"ArchiveFileAnchor":           true,
		"ArchiveEvidenceAnchor":       true,
	}
	allowedMethods := map[string]bool{"Anchor": true, "Revalidate": true, "Close": true}
	aliases := map[string]bool{}
	violations := []string{}
	for _, imported := range file.Imports {
		importPath, unquoteErr := strconv.Unquote(imported.Path.Value)
		if unquoteErr != nil {
			return []string{"import parse failure: " + unquoteErr.Error()}
		}
		if importPath != "chengwang/internal/evidence" {
			continue
		}
		alias := "evidence"
		if imported.Name != nil {
			alias = imported.Name.Name
		}
		if alias == "." || alias == "_" {
			violations = append(violations, "dot or blank evidence import is forbidden")
			continue
		}
		aliases[alias] = true
	}
	sameEvidencePackage := file.Name.Name == "evidence" && path.Dir(relative) == "internal/evidence"
	if len(aliases) == 0 && !sameEvidencePackage {
		return violations
	}
	isEvidenceOpen := func(expr ast.Expr) (*ast.CallExpr, token.Pos, bool) {
		call, ok := expr.(*ast.CallExpr)
		if !ok {
			return nil, token.NoPos, false
		}
		switch direct := call.Fun.(type) {
		case *ast.SelectorExpr:
			if direct.Sel.Name != "OpenExistingArchiveSnapshot" {
				return nil, token.NoPos, false
			}
			qualifier, ok := direct.X.(*ast.Ident)
			if !ok || !aliases[qualifier.Name] {
				return nil, token.NoPos, false
			}
			return call, direct.Pos(), true
		case *ast.Ident:
			if sameEvidencePackage && direct.Name == "OpenExistingArchiveSnapshot" && direct.Obj == nil {
				return call, direct.Pos(), true
			}
		}
		return nil, token.NoPos, false
	}
	functions := []*ast.FuncDecl{}
	closedRanges := [][2]token.Pos{}
	ast.Inspect(file, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.FuncDecl:
			if value.Body != nil {
				functions = append(functions, value)
			}
		case *ast.FuncLit:
			closedRanges = append(closedRanges, [2]token.Pos{value.Pos(), value.End()})
		case *ast.GoStmt:
			closedRanges = append(closedRanges, [2]token.Pos{value.Pos(), value.End()})
		}
		return true
	})
	functionAt := func(position token.Pos) *ast.FuncDecl {
		for _, function := range functions {
			if function.Body.Pos() <= position && position <= function.Body.End() {
				return function
			}
		}
		return nil
	}
	functionBindingNamed := func(function *ast.FuncDecl, name string) bool {
		lists := []*ast.FieldList{function.Recv, function.Type.Params, function.Type.Results}
		for _, list := range lists {
			if list == nil {
				continue
			}
			for _, field := range list.List {
				for _, identifier := range field.Names {
					if identifier.Name == name {
						return true
					}
				}
			}
		}
		return false
	}
	inClosedRange := func(node ast.Node) bool {
		for _, closed := range closedRanges {
			if node.Pos() >= closed[0] && node.End() <= closed[1] {
				return true
			}
		}
		return false
	}
	allowedOpen := map[token.Pos]bool{}
	handleObjects := map[*ast.Object]*ast.FuncDecl{}
	handleDefinitions := map[token.Pos]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		assign, ok := node.(*ast.AssignStmt)
		if !ok || len(assign.Rhs) != 1 {
			return true
		}
		_, openPosition, ok := isEvidenceOpen(assign.Rhs[0])
		if !ok {
			return true
		}
		if assign.Tok != token.DEFINE {
			violations = append(violations, "Open must use a fresh function-local short declaration")
			return true
		}
		if len(assign.Lhs) != 2 {
			violations = append(violations, "Open short declaration must bind exactly handle and error")
			return true
		}
		handle, ok := assign.Lhs[0].(*ast.Ident)
		if !ok || handle.Name == "_" {
			violations = append(violations, "Open handle target must be one direct local identifier")
			return true
		}
		owner := functionAt(assign.Pos())
		if owner == nil || inClosedRange(assign) {
			violations = append(violations, "Open must execute directly in one named function body")
			return true
		}
		if functionBindingNamed(owner, handle.Name) {
			violations = append(violations, "Open handle may not shadow a parameter or named result")
			return true
		}
		if handle.Obj == nil || handle.Obj.Kind != ast.Var || handle.Obj.Decl != assign || handle.Obj.Pos() != handle.Pos() {
			violations = append(violations, "Open handle must be a newly declared function-local object")
			return true
		}
		if file.Scope != nil && file.Scope.Lookup(handle.Name) != nil {
			violations = append(violations, "Open handle may not shadow a file-scope binding")
			return true
		}
		allowedOpen[openPosition] = true
		handleObjects[handle.Obj] = owner
		handleDefinitions[handle.Pos()] = true
		return true
	})
	selectorNames := map[token.Pos]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if ok {
			selectorNames[selector.Sel.Pos()] = true
			qualifier, direct := selector.X.(*ast.Ident)
			if direct && aliases[qualifier.Name] && selector.Sel.Name == "OpenExistingArchiveSnapshot" && !allowedOpen[selector.Pos()] {
				violations = append(violations, "Open reference must be the direct callee of one validated local declaration")
			}
		}
		return true
	})
	if sameEvidencePackage {
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok || identifier.Name != "OpenExistingArchiveSnapshot" || identifier.Obj != nil || selectorNames[identifier.Pos()] || allowedOpen[identifier.Pos()] {
				return true
			}
			violations = append(violations, "Open reference must be the direct callee of one validated local declaration")
			return true
		})
	}
	allowedReceiver := map[token.Pos]bool{}
	ast.Inspect(file, func(node ast.Node) bool {
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		selector, ok := call.Fun.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		receiver, ok := selector.X.(*ast.Ident)
		if !ok {
			usesHandle := false
			ast.Inspect(selector.X, func(child ast.Node) bool {
				identifier, ok := child.(*ast.Ident)
				if ok && identifier.Obj != nil && handleObjects[identifier.Obj] != nil {
					usesHandle = true
				}
				return true
			})
			if usesHandle {
				violations = append(violations, "handle method requires direct identifier receiver")
			}
			return true
		}
		owner, tracked := handleObjects[receiver.Obj]
		if !tracked {
			return true
		}
		if relative != allowed {
			violations = append(violations, "handle receiver call is outside exact future adapter")
			return true
		}
		if !allowedMethods[selector.Sel.Name] {
			violations = append(violations, "unknown handle method is forbidden: "+selector.Sel.Name)
			return true
		}
		if inClosedRange(receiver) {
			violations = append(violations, "handle closure or goroutine use is forbidden")
			return true
		}
		if functionAt(call.Pos()) != owner {
			violations = append(violations, "handle receiver escaped its declaring function")
			return true
		}
		allowedReceiver[receiver.Pos()] = true
		return true
	})
	if sameEvidencePackage {
		ast.Inspect(file, func(node ast.Node) bool {
			identifier, ok := node.(*ast.Ident)
			if !ok || identifier.Obj != nil || selectorNames[identifier.Pos()] || !guardedPackageSymbols[identifier.Name] {
				return true
			}
			if relative != allowed {
				violations = append(violations, "archive symbol is outside exact future adapter: "+identifier.Name)
			}
			return true
		})
	}
	ast.Inspect(file, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if !ok {
			return true
		}
		qualifier, ok := selector.X.(*ast.Ident)
		if !ok || !aliases[qualifier.Name] || !guardedSymbols[selector.Sel.Name] {
			return true
		}
		if relative != allowed {
			violations = append(violations, "archive symbol is outside exact future adapter: "+selector.Sel.Name)
			return true
		}
		if selector.Sel.Name == "ExistingArchiveSnapshot" {
			violations = append(violations, "explicit handle type is forbidden in adapter surface")
		}
		return true
	})
	ast.Inspect(file, func(node ast.Node) bool {
		identifier, ok := node.(*ast.Ident)
		if !ok || identifier.Obj == nil || handleObjects[identifier.Obj] == nil || handleDefinitions[identifier.Pos()] || allowedReceiver[identifier.Pos()] {
			return true
		}
		violations = append(violations, "handle escape or unsupported use: "+identifier.Name)
		return true
	})
	return violations
}

func archiveViolationContains(violations []string, fragment string) bool {
	for _, violation := range violations {
		if strings.Contains(violation, fragment) {
			return true
		}
	}
	return false
}
