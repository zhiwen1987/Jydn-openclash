package restorecontracts

import (
	"bytes"
	"chengwang/internal/proberestore"
	"encoding/json"
	"fmt"
	jsonschema "github.com/santhosh-tekuri/jsonschema/v6"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"testing"
)

const draft2020SchemaURL = "https://json-schema.org/draft/2020-12/schema"

const (
	schemaValidatorModule  = "github.com/santhosh-tekuri/jsonschema/v6"
	schemaValidatorVersion = "v6.0.3"
)

func assertPinnedSchemaValidator(t testing.TB) {
	t.Helper()
	modules, err := os.ReadFile(filepath.Join(candidateRoot(t), "..", "..", "vendor", "modules.txt"))
	if err != nil {
		t.Fatal(err)
	}
	want := "# " + schemaValidatorModule + " " + schemaValidatorVersion
	for _, line := range strings.Split(string(modules), "\n") {
		if line == want {
			return
		}
	}
	t.Fatalf("schema validator pin %q is absent from vendor/modules.txt", want)
}

func candidateRoot(t testing.TB) string {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate schema test source")
	}
	return filepath.Join(filepath.Dir(source), "..", "..", "deploy", "m2b-candidate")
}

func decodeJSONValue(t testing.TB, data []byte) any {
	t.Helper()
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.UseNumber()
	var value any
	if err := decoder.Decode(&value); err != nil {
		t.Fatal(err)
	}
	if err := ensureEOF(decoder); err != nil {
		t.Fatal(err)
	}
	return value
}

func discoverDraft2020Schemas(t testing.TB) map[string][]byte {
	t.Helper()
	root := candidateRoot(t)
	var files []string
	err := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if !entry.IsDir() && strings.HasSuffix(entry.Name(), ".schema.json") {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(files)
	if len(files) != 11 {
		t.Fatalf("schema count=%d, want 11", len(files))
	}
	result := make(map[string][]byte, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		relative, err := filepath.Rel(root, file)
		if err != nil {
			t.Fatal(err)
		}
		value := decodeJSONValue(t, data)
		object, ok := value.(map[string]any)
		if !ok || object["$schema"] != draft2020SchemaURL {
			t.Fatalf("%s does not declare Draft 2020-12", relative)
		}
		result[filepath.ToSlash(relative)] = data
	}
	return result
}

func compileDraft2020Schemas(t testing.TB, documents map[string][]byte) map[string]*jsonschema.Schema {
	t.Helper()
	compiler := jsonschema.NewCompiler()
	compiler.DefaultDraft(jsonschema.Draft2020)
	compiler.AssertFormat()
	locations := make(map[string]string, len(documents))
	for name, data := range documents {
		location := "https://chengwang.invalid/offline-candidate/" + name
		if err := compiler.AddResource(location, decodeJSONValue(t, data)); err != nil {
			t.Fatalf("add schema resource %s: %v", name, err)
		}
		locations[name] = location
	}
	compiled := make(map[string]*jsonschema.Schema, len(documents))
	for name, location := range locations {
		schema, err := compiler.Compile(location)
		if err != nil {
			t.Fatalf("Draft 2020-12 compile %s: %v", name, err)
		}
		compiled[name] = schema
	}
	return compiled
}

func TestSchemasDraft2020CompileAndValidate(t *testing.T) {
	assertPinnedSchemaValidator(t)
	documents := discoverDraft2020Schemas(t)
	compiled := compileDraft2020Schemas(t, documents)
	if len(compiled) != 11 {
		t.Fatalf("compiled schema count=%d, want 11", len(compiled))
	}

	evidence := validEvidence("INPUT_BOUND")
	goldens := map[string]any{
		"restore-contracts/backup-v3.schema.json":             validBackup(t),
		"restore-contracts/restore-evidence-v1.schema.json":   evidence,
		"restore-contracts/anchor-v1.schema.json":             validAnchor(),
		"restore-contracts/receipt-checkpoint-v1.schema.json": validCheckpoint(),
	}
	for name, golden := range goldens {
		name, golden := name, golden
		t.Run("golden/"+name, func(t *testing.T) {
			instance := decodeJSONValue(t, encode(t, golden))
			if err := compiled[name].Validate(instance); err != nil {
				t.Fatalf("golden rejected by %s: %v", name, err)
			}
		})
	}

	for name, golden := range goldens {
		name, golden := name, golden
		for caseName, mutate := range map[string]func(map[string]any){
			"missing-required": func(instance map[string]any) { delete(instance, "schema") },
			"unexpected-field": func(instance map[string]any) { instance["unexpected"] = true },
			"wrong-const-type": func(instance map[string]any) { instance["schema"] = json.Number("1") },
		} {
			caseName, mutate := caseName, mutate
			t.Run("invalid/"+name+"/"+caseName, func(t *testing.T) {
				instance := decodeJSONValue(t, encode(t, golden)).(map[string]any)
				mutate(instance)
				if err := compiled[name].Validate(instance); err == nil {
					t.Fatalf("invalid %s fixture accepted by %s", caseName, name)
				}
			})
		}
	}

	t.Run("invalid-schema-is-rejected", func(t *testing.T) {
		compiler := jsonschema.NewCompiler()
		compiler.DefaultDraft(jsonschema.Draft2020)
		const location = "https://chengwang.invalid/offline-candidate/invalid.schema.json"
		invalidSchema := map[string]any{"$schema": draft2020SchemaURL, "type": json.Number("1")}
		if err := compiler.AddResource(location, invalidSchema); err != nil {
			t.Fatal(err)
		}
		if _, err := compiler.Compile(location); err == nil {
			t.Fatal("invalid Draft 2020-12 schema compiled successfully")
		}
	})
}

func loadContractSchemas(t *testing.T) map[string]map[string]any {
	t.Helper()
	directory := filepath.Join(candidateRoot(t), "restore-contracts")
	files, err := filepath.Glob(filepath.Join(directory, "*.schema.json"))
	if err != nil {
		t.Fatal(err)
	}
	if len(files) != 4 {
		t.Fatalf("schema count=%d, want 4", len(files))
	}
	result := make(map[string]map[string]any, len(files))
	for _, file := range files {
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatal(err)
		}
		if err := scanJSON(data); err != nil {
			t.Fatalf("%s is not strict JSON: %v", filepath.Base(file), err)
		}
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		var schema map[string]any
		if err := decoder.Decode(&schema); err != nil {
			t.Fatal(err)
		}
		if err := ensureEOF(decoder); err != nil {
			t.Fatal(err)
		}
		result[filepath.Base(file)] = schema
	}
	return result
}

func schemaMap(t *testing.T, value any, location string) map[string]any {
	t.Helper()
	result, ok := value.(map[string]any)
	if !ok {
		t.Fatalf("%s is %T, want object", location, value)
	}
	return result
}

func schemaStrings(t *testing.T, value any, location string) []string {
	t.Helper()
	values, ok := value.([]any)
	if !ok {
		t.Fatalf("%s is %T, want array", location, value)
	}
	result := make([]string, len(values))
	for index, value := range values {
		item, ok := value.(string)
		if !ok {
			t.Fatalf("%s[%d] is %T, want string", location, index, value)
		}
		result[index] = item
	}
	sort.Strings(result)
	return result
}

func sortedTrueKeys(values map[string]bool) []string {
	result := make([]string, 0, len(values))
	for key, enabled := range values {
		if enabled {
			result = append(result, key)
		}
	}
	sort.Strings(result)
	return result
}

func resolveLocalSchemaRef(t *testing.T, root map[string]any, node map[string]any) map[string]any {
	t.Helper()
	reference, exists := node["$ref"].(string)
	if !exists {
		return node
	}
	const prefix = "#/$defs/"
	if !strings.HasPrefix(reference, prefix) || strings.Contains(strings.TrimPrefix(reference, prefix), "/") {
		t.Fatalf("non-local or nested schema reference %q", reference)
	}
	definitions := schemaMap(t, root["$defs"], "$defs")
	name := strings.TrimPrefix(reference, prefix)
	target, exists := definitions[name]
	if !exists {
		t.Fatalf("unresolved schema reference %q", reference)
	}
	return schemaMap(t, target, reference)
}

func walkSchema(t *testing.T, root map[string]any, node any, location string) {
	t.Helper()
	switch value := node.(type) {
	case map[string]any:
		if reference, ok := value["$ref"].(string); ok {
			_ = reference
			resolveLocalSchemaRef(t, root, value)
		}
		if value["type"] == "object" {
			properties := schemaMap(t, value["properties"], location+".properties")
			required := schemaStrings(t, value["required"], location+".required")
			keys := make([]string, 0, len(properties))
			for key := range properties {
				keys = append(keys, key)
			}
			sort.Strings(keys)
			if !reflect.DeepEqual(required, keys) {
				t.Fatalf("%s required=%v properties=%v", location, required, keys)
			}
			if additional, ok := value["additionalProperties"].(bool); !ok || additional {
				t.Fatalf("%s must set additionalProperties=false", location)
			}
		}
		for key, child := range value {
			walkSchema(t, root, child, location+"."+key)
		}
	case []any:
		for index, child := range value {
			walkSchema(t, root, child, fmt.Sprintf("%s[%d]", location, index))
		}
	}
}

func schemaForWireType(t *testing.T, root map[string]any, node map[string]any, wire reflect.Type, location string) {
	t.Helper()
	node = resolveLocalSchemaRef(t, root, node)
	if alternatives, ok := node["oneOf"].([]any); ok {
		if len(alternatives) == 0 {
			t.Fatalf("%s has empty oneOf", location)
		}
		node = schemaMap(t, alternatives[0], location+".oneOf[0]")
	}
	for wire.Kind() == reflect.Pointer {
		wire = wire.Elem()
	}
	switch wire.Kind() {
	case reflect.Struct:
		properties := schemaMap(t, node["properties"], location+".properties")
		fields := make(map[string]reflect.Type, wire.NumField())
		for index := 0; index < wire.NumField(); index++ {
			field := wire.Field(index)
			name := strings.Split(field.Tag.Get("json"), ",")[0]
			if name != "" && name != "-" {
				fields[name] = field.Type
			}
		}
		if len(fields) != len(properties) {
			t.Fatalf("%s Go fields=%d schema properties=%d", location, len(fields), len(properties))
		}
		for name, fieldType := range fields {
			child, exists := properties[name]
			if !exists {
				t.Fatalf("%s Go field %q absent from schema", location, name)
			}
			schemaForWireType(t, root, schemaMap(t, child, location+"."+name), fieldType, location+"."+name)
		}
	case reflect.Slice, reflect.Array:
		items := schemaMap(t, node["items"], location+".items")
		schemaForWireType(t, root, items, wire.Elem(), location+"[]")
	}
}

func TestSchemaParityAndLocalReferences(t *testing.T) {
	schemas := loadContractSchemas(t)
	for name, schema := range schemas {
		walkSchema(t, schema, schema, name)
	}
	wires := map[string]reflect.Type{
		"backup-v3.schema.json":             reflect.TypeOf(BackupV3{}),
		"restore-evidence-v1.schema.json":   reflect.TypeOf(RestoreEvidenceV1{}),
		"anchor-v1.schema.json":             reflect.TypeOf(RestoreAnchorV1{}),
		"receipt-checkpoint-v1.schema.json": reflect.TypeOf(ReceiptCheckpointV1{}),
	}
	for name, wire := range wires {
		schemaForWireType(t, schemas[name], schemas[name], wire, name)
	}

	evidence := schemas["restore-evidence-v1.schema.json"]
	definitions := schemaMap(t, evidence["$defs"], "evidence.$defs")
	kinds := schemaStrings(t, schemaMap(t, definitions["kind"], "kind")["enum"], "kind.enum")
	if !reflect.DeepEqual(kinds, EvidenceKinds()) {
		t.Fatalf("kind enum drift: schema=%v Go=%v", kinds, EvidenceKinds())
	}
	fromPhases := schemaStrings(t, schemaMap(t, definitions["fromPhase"], "fromPhase")["enum"], "fromPhase.enum")
	if !reflect.DeepEqual(fromPhases, JournalPhases()) {
		t.Fatalf("fromPhase enum drift: schema=%v Go=%v", fromPhases, JournalPhases())
	}
	targetPhases := schemaStrings(t, schemaMap(t, definitions["phase"], "phase")["enum"], "phase.enum")
	wantTargets := make([]string, 0, len(JournalPhases())-1)
	for _, phase := range JournalPhases() {
		if phase != "NEW" {
			wantTargets = append(wantTargets, phase)
		}
	}
	sort.Strings(wantTargets)
	if !reflect.DeepEqual(targetPhases, wantTargets) {
		t.Fatalf("target phase enum drift: schema=%v Go=%v", targetPhases, wantTargets)
	}

	pairs := map[string]string{}
	fromSets := map[string][]string{}
	reasonPolicies := map[string]string{}
	for _, raw := range evidence["allOf"].([]any) {
		condition := schemaMap(t, raw, "evidence.allOf")
		ifProperties := schemaMap(t, schemaMap(t, condition["if"], "if")["properties"], "if.properties")
		kindNode, hasKind := ifProperties["kind"]
		thenProperties := schemaMap(t, schemaMap(t, condition["then"], "then")["properties"], "then.properties")
		targetNode, hasTarget := thenProperties["targetPhase"]
		if !hasKind || !hasTarget {
			continue
		}
		kind := schemaMap(t, kindNode, "if.kind")["const"].(string)
		if _, duplicate := pairs[kind]; duplicate {
			t.Fatalf("duplicate kind/target allOf contract for %s", kind)
		}
		pairs[kind] = schemaMap(t, targetNode, "then.targetPhase")["const"].(string)
		if reasonNode, exists := thenProperties["reasonCode"]; exists {
			reasonPolicies[kind], _ = schemaMap(t, reasonNode, "then.reasonCode")["const"].(string)
		}
		from := schemaMap(t, thenProperties["fromPhase"], "then.fromPhase")
		if single, ok := from["const"].(string); ok {
			fromSets[kind] = []string{single}
		} else {
			fromSets[kind] = schemaStrings(t, from["enum"], "then.fromPhase.enum")
		}
		sort.Strings(fromSets[kind])
	}
	if len(pairs) != len(evidencePhases) {
		t.Fatalf("schema has %d kind/phase contracts, want %d", len(pairs), len(evidencePhases))
	}
	for kind, target := range evidencePhases {
		if pairs[kind] != target {
			t.Fatalf("%s target schema=%q Go=%q", kind, pairs[kind], target)
		}
		wantFrom := make([]string, 0, len(evidenceTopology[kind].from))
		for phase := range evidenceTopology[kind].from {
			wantFrom = append(wantFrom, phase)
		}
		sort.Strings(wantFrom)
		if !reflect.DeepEqual(fromSets[kind], wantFrom) {
			t.Fatalf("%s from phases schema=%v Go=%v", kind, fromSets[kind], wantFrom)
		}
		if kind == "LOCKDOWN_VERIFIED" {
			if reasonPolicies[kind] != "LOCKDOWN_VERIFIED" {
				t.Fatalf("lockdown schema reason=%q", reasonPolicies[kind])
			}
		} else if reasonPolicies[kind] != "" {
			t.Fatalf("%s unexpectedly hard-codes reason %q unlike the journal", kind, reasonPolicies[kind])
		}
	}
	journalPhases := proberestore.Phases()
	for _, from := range journalPhases {
		for _, to := range journalPhases {
			schemaAllows := false
			goAllows := false
			for kind, target := range pairs {
				if target != string(to) {
					continue
				}
				for _, candidate := range fromSets[kind] {
					if candidate == string(from) {
						schemaAllows = true
						break
					}
				}
				if evidencePhases[kind] == string(to) && evidenceTopology[kind].from[string(from)] {
					goAllows = true
				}
			}
			journalAllows := proberestore.CanTransition(from, to)
			if schemaAllows != goAllows || goAllows != journalAllows {
				t.Fatalf("three-way transition drift %s -> %s: schema=%v Go=%v journal=%v", from, to, schemaAllows, goAllows, journalAllows)
			}
		}
	}
	if pattern := schemaMap(t, evidence["properties"], "evidence.properties")["reasonCode"].(map[string]any)["pattern"]; pattern != safeReason.String() {
		t.Fatalf("reason pattern=%v Go=%s", pattern, safeReason.String())
	}

	for _, name := range []string{"backup-v3.schema.json", "restore-evidence-v1.schema.json", "anchor-v1.schema.json", "receipt-checkpoint-v1.schema.json"} {
		definitions := schemaMap(t, schemas[name]["$defs"], name+".$defs")
		if unix := schemaMap(t, definitions["unix"], name+".unix")["maximum"]; unix != json.Number("253402300799") {
			t.Fatalf("%s Unix maximum=%v", name, unix)
		}
	}
	for _, name := range []string{"backup-v3.schema.json", "restore-evidence-v1.schema.json"} {
		definitions := schemaMap(t, schemas[name]["$defs"], name+".$defs")
		if pattern := schemaMap(t, definitions["absolutePath"], name+".absolutePath")["pattern"]; pattern != posixPathPattern.String() {
			t.Fatalf("%s POSIX path pattern=%v Go=%s", name, pattern, posixPathPattern.String())
		}
	}
	for _, name := range []string{"anchor-v1.schema.json", "receipt-checkpoint-v1.schema.json"} {
		definitions := schemaMap(t, schemas[name]["$defs"], name+".$defs")
		signer := schemaMap(t, definitions["signer"], name+".signer")
		signerProperties := schemaMap(t, signer["properties"], name+".signer.properties")
		algorithms := schemaStrings(t, schemaMap(t, signerProperties["algorithm"], name+".algorithm")["enum"], name+".algorithm.enum")
		if !reflect.DeepEqual(algorithms, sortedTrueKeys(signerAlgorithms)) {
			t.Fatalf("%s signer algorithms=%v Go=%v", name, algorithms, sortedTrueKeys(signerAlgorithms))
		}
		worm := schemaMap(t, definitions["worm"], name+".worm")
		wormProperties := schemaMap(t, worm["properties"], name+".worm.properties")
		classes := schemaStrings(t, schemaMap(t, wormProperties["backendClass"], name+".backendClass")["enum"], name+".backendClass.enum")
		if !reflect.DeepEqual(classes, sortedTrueKeys(wormBackendClasses)) {
			t.Fatalf("%s WORM classes=%v Go=%v", name, classes, sortedTrueKeys(wormBackendClasses))
		}
		signature := schemaMap(t, definitions["signature"], name+".signature")
		if signature["minLength"] != json.Number("4") || signature["maxLength"] != json.Number("96") {
			t.Fatalf("%s signature bounds=%v..%v", name, signature["minLength"], signature["maxLength"])
		}
	}
	anchorDefinitions := schemaMap(t, schemas["anchor-v1.schema.json"]["$defs"], "anchor.$defs")
	anchorPhases := schemaStrings(t, schemaMap(t, anchorDefinitions["phase"], "anchor.phase")["enum"], "anchor.phase.enum")
	if !reflect.DeepEqual(anchorPhases, JournalPhases()) {
		t.Fatalf("anchor phase enum drift: schema=%v Go=%v", anchorPhases, JournalPhases())
	}
	checks := schemaMap(t, schemaMap(t, definitions["payload"], "payload")["properties"], "payload.properties")["checks"]
	if got := schemaMap(t, checks, "checks")["maxItems"]; got != json.Number(fmt.Sprint(MaxChecks)) {
		t.Fatalf("checks maxItems=%v", got)
	}
	checkpoint := schemas["receipt-checkpoint-v1.schema.json"]
	if got := schemaMap(t, checkpoint["properties"], "checkpoint.properties")["receiptCount"].(map[string]any)["maximum"]; got != json.Number(fmt.Sprint(MaxReceiptCount)) {
		t.Fatalf("receiptCount maximum=%v", got)
	}
}
