package mihomodeploy

import (
	"reflect"
	"testing"
)

// MODEL metadata diagnostic only. Actual Linux Go reflection is the authority
// for updating the closed clone-schema pin and fixed property coverage counts.
// Logging a new graph does not validate a record or accept the typed copier.
func TestLifecycleRecoveryCompletionActualCloneShapeDiagnostic(t *testing.T) {
	root := reflect.TypeOf(lifecycleV3Wire{})
	digest, walked := lifecycleCloneTypeShape(root)
	if !walked || !lifecycleNonzeroHash(digest) {
		t.Fatal("MODEL completion graph is not a closed supported type graph")
	}
	w := &lifecycleV3Wire{}
	next, seen := 0, map[reflect.Type]bool{}
	lifecycleClonePropertyFill(t, reflect.ValueOf(w).Elem(), &next, seen)
	fields := 0
	for kind := range seen {
		fields += kind.NumField()
	}
	var slots []lifecycleClonePropertySlot
	lifecycleClonePropertySlots(reflect.ValueOf(w).Elem(), nil, map[string]bool{}, &slots)
	pointers, slices := 0, 0
	for _, slot := range slots {
		value := lifecycleClonePropertyAt(reflect.ValueOf(w).Elem(), slot.path)
		switch value.Kind() {
		case reflect.Pointer:
			pointers++
		case reflect.Slice:
			slices++
		default:
			t.Fatal("MODEL mutable slot has an unsupported kind")
		}
	}
	t.Logf("MODEL_ACTUAL_GO_METADATA digest=%s structs=%d fields=%d mutableSlots=%d pointers=%d slices=%d", digest, len(seen), fields, len(slots), pointers, slices)
}
