package restorecurrent

import (
	"fmt"
	"go/ast"
	"go/importer"
	"go/parser"
	"go/token"
	"go/types"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"testing"
)

var sourceGateAllowedImports = map[string]bool{
	"bufio": true, "bytes": true, "crypto/sha256": true, "embed": true, "encoding/hex": true,
	"encoding/json": true, "errors": true, "fmt": true, "io": true, "net/netip": true, "os": true,
	"path": true, "regexp": true, "sort": true, "strconv": true, "strings": true, "sync": true,
	"syscall": true, "time": true, "unicode/utf8": true,
	"chengwang/internal/probe": true, "chengwang/internal/restoreclock": true, "chengwang/internal/restorelease": true,
}

var sourceGateAllowedPrivilegedSelectors = map[string]bool{
	"os.File": true, "os.NewFile": true, "os.Open": true,
	"syscall.Close": true, "syscall.Fstat": true, "syscall.Open": true, "syscall.Openat": true,
	"syscall.Stat_t": true, "syscall.O_RDONLY": true, "syscall.O_DIRECTORY": true,
	"syscall.O_CLOEXEC": true, "syscall.O_NOFOLLOW": true, "syscall.O_NONBLOCK": true,
	"syscall.S_IFMT": true, "syscall.S_IFDIR": true, "syscall.S_IFREG": true,
}

var sourceGateAllowedInternalSelectors = map[string]bool{
	"chengwang/internal/probe.Catalog": true, "chengwang/internal/probe.ParseCatalogBytes": true,
	"chengwang/internal/restoreclock.Clock": true, "chengwang/internal/restoreclock.ErrUnsupported": true,
	"chengwang/internal/restoreclock.Open": true, "chengwang/internal/restoreclock.Snapshot": true,
	"chengwang/internal/restorelease.Acquire": true, "chengwang/internal/restorelease.ErrUnsupported": true,
	"chengwang/internal/restorelease.Identity": true, "chengwang/internal/restorelease.Lease": true,
}

var sourceGateAllowedReleaseSelectors = map[string]bool{
	"bytes.Equal": true, "bytes.IndexByte": true, "bytes.NewReader": true,
	"decoder.Decode": true, "decoder.DisallowUnknownFields": true, "decoder.More": true,
	"decoder.Token": true, "decoder.UseNumber": true, "errors.Join": true, "errors.New": true,
	"fmt.Sprint": true, "encoding/hex.EncodeToString": true, "encoding/json.Delim": true, "encoding/json.Marshal": true,
	"encoding/json.NewDecoder": true, "encoding/json.Unmarshal": true, "path.Clean": true, "path.IsAbs": true,
	"path.Join": true, "regexp.MustCompile": true, "releaseHashPattern.MatchString": true,
	"rendererVersionPattern.MatchString": true, "crypto/sha256.Sum256": true, "strings.ContainsAny": true,
	"strings.HasPrefix": true, "strings.Repeat": true, "strings.TrimPrefix": true,
	"unicode/utf8.Valid": true, "value.String": true,
}

var sourceGateBuiltins = map[string]bool{
	"append": true, "byte": true, "int64": true, "len": true, "make": true, "uint64": true,
}

var sourceGateForbiddenMutationMethods = map[string]bool{
	"Chdir": true, "Chmod": true, "Chown": true, "Encode": true, "Flush": true,
	"ReadFrom": true, "Sync": true, "Truncate": true, "Write": true, "WriteAt": true,
	"WriteString": true, "WriteTo": true,
}

var sourceGateForbiddenMutationFunctions = map[string]bool{
	"bufio.NewWriter": true, "bufio.NewWriterSize": true,
	"encoding/json.NewEncoder": true,
	"fmt.Fprint":               true, "fmt.Fprintf": true, "fmt.Fprintln": true,
	"fmt.Print": true, "fmt.Printf": true, "fmt.Println": true,
	"io.Copy": true, "io.CopyBuffer": true, "io.CopyN": true, "io.WriteString": true,
}

var sourceGateForbiddenBuiltins = map[string]bool{
	"close": true, "delete": true, "panic": true, "print": true, "println": true, "recover": true,
}

func TestReleaseObserverSourcePurityASTGate(t *testing.T) {
	_, currentFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate restorecurrent source directory")
	}
	packageDir := filepath.Dir(currentFile)
	entries, err := os.ReadDir(packageDir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") || strings.HasSuffix(entry.Name(), "_test.go") {
			continue
		}
		raw, err := os.ReadFile(filepath.Join(packageDir, entry.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if problems := inspectRestorecurrentSource(entry.Name(), raw, entry.Name() == "release.go"); len(problems) != 0 {
			t.Fatalf("source purity violation in %s: %s", entry.Name(), strings.Join(problems, "; "))
		}
	}
}

func TestReleaseObserverSourcePurityASTGateRejectsSyntaxBypasses(t *testing.T) {
	cases := map[string]string{
		"raw_import_alias":        "package restorecurrent\nimport fs `os`\nfunc mutate(){ _ = fs.Mkdir(\"/tmp/x\", 0700) }\n",
		"unicode_import_alias":    "package restorecurrent\nimport 文件 \"os\"\nfunc mutate(){ _ = 文件.Mkdir(\"/tmp/x\", 0700) }\n",
		"commented_import_alias":  "package restorecurrent\nimport fs /*comment*/ \"os\"\nfunc mutate(){ _ = fs.Mkdir(\"/tmp/x\", 0700) }\n",
		"indexed_receiver":        "package restorecurrent\ntype helper struct{}\nfunc (helper) mutate(){}\nfunc observe(values []helper){ values[0].mutate() }\n",
		"parenthesized_method":    "package restorecurrent\ntype helper struct{}\nfunc (helper) mutate(){}\nfunc observe(value helper){ (value.mutate)() }\n",
		"numeric_write_flags":     "package restorecurrent\nimport \"syscall\"\nfunc mutate(){ _, _ = syscall.Open(\"/tmp/x\", 1, 0) }\n",
		"parenthesized_syscall":   "package restorecurrent\nimport \"syscall\"\nfunc mutate(){ _, _ = (syscall.Open)(\"/tmp/x\", 1, 0) }\n",
		"syscall_function_value":  "package restorecurrent\nimport \"syscall\"\nfunc mutate(){ open := syscall.Open; _, _ = open(\"/tmp/x\", 1, 0) }\n",
		"release_println":         "package restorecurrent\nfunc observe(secret string){ println(secret) }\n",
		"release_package_write":   "package restorecurrent\nvar approved []byte\nfunc poison(raw []byte){ approved = append([]byte(nil), raw...) }\n",
		"release_package_address": "package restorecurrent\nimport \"encoding/json\"\nvar approved string\nfunc poison(raw []byte){ _ = json.Unmarshal(raw, &approved) }\n",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if problems := inspectRestorecurrentSource("release.go", []byte(source), true); len(problems) == 0 {
				t.Fatal("syntax bypass was accepted")
			}
		})
	}
}

func TestRestorecurrentSourcePurityASTGateRejectsFileMutationMethods(t *testing.T) {
	cases := map[string]string{
		"file_chmod":      "package restorecurrent\nimport \"os\"\nfunc mutate(file *os.File){ _ = file.Chmod(0600) }\n",
		"fmt_fprint":      "package restorecurrent\nimport (\"fmt\"; \"os\")\nfunc mutate(file *os.File){ _, _ = fmt.Fprint(file, \"x\") }\n",
		"io_copy":         "package restorecurrent\nimport (\"io\"; \"os\")\nfunc mutate(file *os.File, source io.Reader){ _, _ = io.Copy(file, source) }\n",
		"json_encoder":    "package restorecurrent\nimport (\"encoding/json\"; \"os\")\nfunc mutate(file *os.File){ _ = json.NewEncoder(file).Encode(1) }\n",
		"bufio_writer":    "package restorecurrent\nimport (\"bufio\"; \"os\")\nfunc mutate(file *os.File){ _ = bufio.NewWriter(file).Flush() }\n",
		"encoder_encode":  "package restorecurrent\nimport \"encoding/json\"\nfunc mutate(encoder *json.Encoder){ _ = encoder.Encode(1) }\n",
		"writer_flush":    "package restorecurrent\nimport \"bufio\"\nfunc mutate(writer *bufio.Writer){ _ = writer.Flush() }\n",
		"fmt_print":       "package restorecurrent\nimport \"fmt\"\nfunc mutate(secret string){ fmt.Print(secret) }\n",
		"builtin_println": "package restorecurrent\nfunc mutate(secret string){ println(secret) }\n",
		"internal_store":  "package restorecurrent\nimport \"chengwang/internal/probe\"\nfunc mutate(){ _, _ = probe.OpenStore(\"/tmp/state\", 1) }\n",
		"writer_write_to": "package restorecurrent\nimport (\"bytes\"; \"os\")\nfunc mutate(source *bytes.Buffer){ _, _ = source.WriteTo(os.NewFile(1, \"stdout\")) }\n",
	}
	for name, source := range cases {
		t.Run(name, func(t *testing.T) {
			if problems := inspectRestorecurrentSource("platform_linux.go", []byte(source), false); len(problems) == 0 {
				t.Fatal("file mutation path was accepted")
			}
		})
	}
}

func inspectRestorecurrentSource(name string, raw []byte, release bool) []string {
	parsed, err := parser.ParseFile(token.NewFileSet(), name, raw, parser.AllErrors)
	if err != nil {
		return []string{"Go parser rejected source"}
	}
	aliases := map[string]string{}
	problems := []string{}
	for _, spec := range parsed.Imports {
		importPath, err := strconv.Unquote(spec.Path.Value)
		if err != nil || !sourceGateAllowedImports[importPath] {
			problems = append(problems, "unapproved import")
			continue
		}
		alias := path.Base(importPath)
		if spec.Name != nil {
			alias = spec.Name.Name
		}
		if alias == "." || (alias == "_" && importPath != "embed") {
			problems = append(problems, "unapproved import form")
			continue
		}
		aliases[alias] = importPath
	}
	declared := map[string]bool{}
	if release {
		problems = append(problems, typeCheckReleaseCalls(name, raw)...)
		for _, declaration := range parsed.Decls {
			if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil {
				declared[function.Name.Name] = true
			}
		}
	}
	parents := map[ast.Node]ast.Node{}
	var stack []ast.Node
	ast.Inspect(parsed, func(node ast.Node) bool {
		if node == nil {
			stack = stack[:len(stack)-1]
			return true
		}
		if len(stack) != 0 {
			parents[node] = stack[len(stack)-1]
		}
		stack = append(stack, node)
		return true
	})
	ast.Inspect(parsed, func(node ast.Node) bool {
		selector, ok := node.(*ast.SelectorExpr)
		if ok {
			if sourceGateForbiddenMutationMethods[selector.Sel.Name] {
				problems = append(problems, "forbidden mutation method")
			}
			if base, baseOK := selector.X.(*ast.Ident); baseOK {
				importPath := aliases[base.Name]
				if importPath != "" && sourceGateForbiddenMutationFunctions[importPath+"."+selector.Sel.Name] {
					problems = append(problems, "forbidden mutation function")
				}
				if strings.HasPrefix(importPath, "chengwang/internal/") && !sourceGateAllowedInternalSelectors[importPath+"."+selector.Sel.Name] {
					problems = append(problems, "unreviewed internal package selector")
				}
				if importPath == "os" || importPath == "syscall" {
					if !sourceGateAllowedPrivilegedSelectors[importPath+"."+selector.Sel.Name] {
						problems = append(problems, "unreviewed privileged selector")
					}
					if importPath == "syscall" && (selector.Sel.Name == "Open" || selector.Sel.Name == "Openat") && !directCallTarget(selector, parents) {
						problems = append(problems, "syscall open function value escapes direct flag validation")
					}
				}
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		if syscallName, ok := syscallOpenName(call.Fun, aliases); ok {
			flagIndex := 1
			if syscallName == "Openat" {
				flagIndex = 2
			}
			if len(call.Args) <= flagIndex || !readOnlySyscallFlags(call.Args[flagIndex], aliases) {
				problems = append(problems, "syscall open flags are not an exact read-only expression")
			}
		}
		if identifier, ok := call.Fun.(*ast.Ident); ok && sourceGateForbiddenBuiltins[identifier.Name] {
			problems = append(problems, "forbidden builtin side effect")
		}
		if release {
			problems = append(problems, inspectReleaseCall(call.Fun, aliases, declared)...)
		}
		return true
	})
	sort.Strings(problems)
	return problems
}

func typeCheckReleaseCalls(name string, raw []byte) []string {
	fileSet := token.NewFileSet()
	releaseFile, err := parser.ParseFile(fileSet, name, raw, parser.AllErrors)
	if err != nil {
		return []string{"release source cannot be parsed for type checking"}
	}
	stub := `package restorecurrent
type configurationContents struct { identity, env, composeSource, composeJSON, composeBinding []byte }
type validatedEnvironment struct { projectName, releaseID string; values map[string]string }
type candidateIdentity struct { CandidateID string; IdentityGeneration uint64 }
type LocalReleaseDigests struct { ComposeSourceSHA256, ComposeRenderedSHA256, RenderedSemanticSHA256, LocalBindingSHA256 string }
var ErrInvalid error
const serviceName = "probe-agent"
`
	stubFile, err := parser.ParseFile(fileSet, "release_source_gate_stub.go", stub, parser.AllErrors)
	if err != nil {
		return []string{"release source gate stub cannot be parsed"}
	}
	info := &types.Info{
		Types:      map[ast.Expr]types.TypeAndValue{},
		Defs:       map[*ast.Ident]types.Object{},
		Uses:       map[*ast.Ident]types.Object{},
		Selections: map[*ast.SelectorExpr]*types.Selection{},
	}
	configuration := types.Config{Importer: importer.Default()}
	if _, err := configuration.Check("chengwang/internal/restorecurrent", fileSet, []*ast.File{releaseFile, stubFile}, info); err != nil {
		return []string{"release source does not type-check against the minimal pure boundary"}
	}
	declared := map[string]bool{}
	for _, declaration := range releaseFile.Decls {
		if function, ok := declaration.(*ast.FuncDecl); ok && function.Recv == nil {
			declared[function.Name.Name] = true
		}
	}
	allowedFunctions := map[string]bool{
		"bytes.Equal": true, "bytes.IndexByte": true, "bytes.NewReader": true,
		"crypto/sha256.Sum256": true, "encoding/hex.EncodeToString": true,
		"encoding/json.Marshal": true, "encoding/json.NewDecoder": true, "encoding/json.Unmarshal": true,
		"errors.Join": true, "errors.New": true, "fmt.Sprint": true,
		"path.Clean": true, "path.IsAbs": true, "path.Join": true, "regexp.MustCompile": true,
		"strings.ContainsAny": true, "strings.HasPrefix": true, "strings.Repeat": true,
		"strings.TrimPrefix": true, "unicode/utf8.Valid": true,
	}
	allowedMethods := map[string]bool{
		"*encoding/json.Decoder.Decode": true, "*encoding/json.Decoder.DisallowUnknownFields": true,
		"*encoding/json.Decoder.More": true, "*encoding/json.Decoder.Token": true,
		"*encoding/json.Decoder.UseNumber": true, "*regexp.Regexp.MatchString": true,
		"encoding/json.Number.String": true,
	}
	problems := []string{}
	ast.Inspect(releaseFile, func(node ast.Node) bool {
		switch value := node.(type) {
		case *ast.AssignStmt:
			for _, target := range value.Lhs {
				if expressionTouchesPackageVariable(target, info) {
					problems = append(problems, "typed release assignment mutates package state")
				}
			}
		case *ast.IncDecStmt:
			if expressionTouchesPackageVariable(value.X, info) {
				problems = append(problems, "typed release increment mutates package state")
			}
		case *ast.SendStmt:
			problems = append(problems, "typed release channel send is unapproved")
		case *ast.GoStmt:
			problems = append(problems, "typed release goroutine is unapproved")
		case *ast.DeferStmt:
			problems = append(problems, "typed release deferred call is unapproved")
		case *ast.UnaryExpr:
			if value.Op == token.AND && expressionTouchesPackageVariable(value.X, info) {
				problems = append(problems, "typed release package state address escapes")
			}
		}
		call, ok := node.(*ast.CallExpr)
		if !ok {
			return true
		}
		function := call.Fun
		for {
			switch indexed := function.(type) {
			case *ast.IndexExpr:
				function = indexed.X
				continue
			case *ast.IndexListExpr:
				function = indexed.X
				continue
			}
			break
		}
		if info.Types[function].IsType() {
			return true
		}
		switch value := function.(type) {
		case *ast.Ident:
			object := info.Uses[value]
			if builtin, ok := object.(*types.Builtin); ok {
				if sourceGateBuiltins[builtin.Name()] {
					return true
				}
				problems = append(problems, "typed release builtin call is unapproved")
				return true
			}
			if functionObject, ok := object.(*types.Func); ok && functionObject.Pkg() != nil &&
				functionObject.Pkg().Path() == "chengwang/internal/restorecurrent" && declared[functionObject.Name()] {
				return true
			}
			problems = append(problems, "typed release call escapes the pure source file")
		case *ast.SelectorExpr:
			if selection := info.Selections[value]; selection != nil {
				canonical := types.TypeString(selection.Recv(), func(pkg *types.Package) string { return pkg.Path() }) + "." + selection.Obj().Name()
				if !allowedMethods[canonical] {
					problems = append(problems, "typed release method call is unapproved")
				}
				return true
			}
			object := info.Uses[value.Sel]
			if object == nil || object.Pkg() == nil || !allowedFunctions[object.Pkg().Path()+"."+object.Name()] {
				problems = append(problems, "typed release package call is unapproved")
			}
		default:
			problems = append(problems, "typed release call expression is unapproved")
		}
		return true
	})
	return problems
}

func expressionTouchesPackageVariable(expression ast.Expr, info *types.Info) bool {
	switch value := expression.(type) {
	case *ast.Ident:
		object, ok := info.Uses[value].(*types.Var)
		return ok && object.Pkg() != nil && object.Parent() == object.Pkg().Scope()
	case *ast.ParenExpr:
		return expressionTouchesPackageVariable(value.X, info)
	case *ast.IndexExpr:
		return expressionTouchesPackageVariable(value.X, info)
	case *ast.IndexListExpr:
		return expressionTouchesPackageVariable(value.X, info)
	case *ast.SelectorExpr:
		return expressionTouchesPackageVariable(value.X, info)
	case *ast.StarExpr:
		return expressionTouchesPackageVariable(value.X, info)
	default:
		return false
	}
}

func inspectReleaseCall(expression ast.Expr, aliases map[string]string, declared map[string]bool) []string {
	switch value := expression.(type) {
	case *ast.Ident:
		if declared[value.Name] || sourceGateBuiltins[value.Name] {
			return nil
		}
		return []string{"release calls a helper outside release.go"}
	case *ast.IndexExpr:
		return inspectReleaseCall(value.X, aliases, declared)
	case *ast.IndexListExpr:
		return inspectReleaseCall(value.X, aliases, declared)
	case *ast.ArrayType:
		if value.Len == nil {
			if element, ok := value.Elt.(*ast.Ident); ok && element.Name == "byte" {
				return nil
			}
		}
		return []string{"release uses an unreviewed slice conversion"}
	case *ast.SelectorExpr:
		base, ok := value.X.(*ast.Ident)
		if !ok {
			return []string{"release calls a chained or indexed selector"}
		}
		canonical := base.Name + "." + value.Sel.Name
		if importPath, imported := aliases[base.Name]; imported {
			canonical = importPath + "." + value.Sel.Name
		}
		if sourceGateAllowedReleaseSelectors[canonical] {
			return nil
		}
		return []string{"release calls an unreviewed selector"}
	default:
		return []string{fmt.Sprintf("release uses an unreviewed call expression %T", expression)}
	}
}

func syscallOpenName(expression ast.Expr, aliases map[string]string) (string, bool) {
	for {
		parenthesized, ok := expression.(*ast.ParenExpr)
		if !ok {
			break
		}
		expression = parenthesized.X
	}
	selector, ok := expression.(*ast.SelectorExpr)
	if !ok {
		return "", false
	}
	base, ok := selector.X.(*ast.Ident)
	if !ok || aliases[base.Name] != "syscall" || (selector.Sel.Name != "Open" && selector.Sel.Name != "Openat") {
		return "", false
	}
	return selector.Sel.Name, true
}

func directCallTarget(selector *ast.SelectorExpr, parents map[ast.Node]ast.Node) bool {
	var current ast.Node = selector
	for {
		parent := parents[current]
		if parenthesized, ok := parent.(*ast.ParenExpr); ok && parenthesized.X == current {
			current = parenthesized
			continue
		}
		call, ok := parent.(*ast.CallExpr)
		return ok && call.Fun == current
	}
}

func readOnlySyscallFlags(expression ast.Expr, aliases map[string]string) bool {
	seenReadOnly := false
	var visit func(ast.Expr) bool
	visit = func(value ast.Expr) bool {
		switch current := value.(type) {
		case *ast.ParenExpr:
			return visit(current.X)
		case *ast.BinaryExpr:
			return current.Op == token.OR && visit(current.X) && visit(current.Y)
		case *ast.SelectorExpr:
			base, ok := current.X.(*ast.Ident)
			if !ok || aliases[base.Name] != "syscall" {
				return false
			}
			switch current.Sel.Name {
			case "O_RDONLY":
				seenReadOnly = true
				return true
			case "O_DIRECTORY", "O_CLOEXEC", "O_NOFOLLOW", "O_NONBLOCK":
				return true
			default:
				return false
			}
		default:
			return false
		}
	}
	return visit(expression) && seenReadOnly
}
