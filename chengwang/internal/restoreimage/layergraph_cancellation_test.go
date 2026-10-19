package restoreimage

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"reflect"
	"strings"
	"testing"
	"time"
)

// Deterministic cancellation without scheduling, goroutines, or wall-clock
// assumptions. The decoder must poll during input consumption, not only after
// a single output Read has scanned all the empty deflate blocks.
// This counting probe is used only by single-threaded tests, not production.
type graphCancelContext struct{ calls, after int }

func (*graphCancelContext) Deadline() (time.Time, bool) { return time.Time{}, false }
func (*graphCancelContext) Done() <-chan struct{}       { return nil }
func (ctx *graphCancelContext) Err() error {
	ctx.calls++
	if ctx.calls >= ctx.after {
		return context.Canceled
	}
	return nil
}
func (*graphCancelContext) Value(any) any { return nil }

func TestLayerGraphObservesCancellationWithinEmptyDeflateInput(t *testing.T) {
	raw := []byte{0x1f, 0x8b, 8, 0, 0, 0, 0, 0, 0, 255}
	for i := 0; i < 20000; i++ {
		raw = append(raw, 0, 0, 0, 255, 255)
	}
	raw = append(raw, 1, 0, 0, 255, 255)
	raw = append(raw, make([]byte, 8)...)
	if n, ok := decodedLayerDigestMatches(context.Background(), raw, testOCILayer, graphTestDigest(nil), 0); !ok || n != 0 {
		t.Fatal("empty-block gzip fixture is not valid")
	}
	ctx := &graphCancelContext{after: 4}
	if _, ok := decodedLayerDigestMatches(ctx, raw, testOCILayer, graphTestDigest(nil), 0); ok {
		t.Fatal("empty deflate blocks hid in-progress cancellation")
	}
	if ctx.calls != 4 {
		t.Fatal("decoder did not stop at first cancelled input checkpoint")
	}
}

func TestLayerGraphObservesCancellationDuringHashAndDecodedOutput(t *testing.T) {
	raw := bytes.Repeat([]byte("x"), 100000)
	if rawLayerDigestMatches(&graphCancelContext{after: 2}, raw, graphTestDigest(raw)) {
		t.Fatal("raw hashing ignored in-progress cancellation")
	}
	compressed := graphTestGzip(t, raw)
	if _, ok := decodedLayerDigestMatches(&graphCancelContext{after: 4}, compressed, testOCILayer, graphTestDigest(raw), int64(len(raw))); ok {
		t.Fatal("decoding ignored in-progress cancellation")
	}
}

func TestLayerGraphPreservesBlockedAssociationAndSecretFreeOutput(t *testing.T) {
	secret := "FIXTURE-LAYER-SECRET-do-not-retain"
	fixture := graphTestBuild(t, false, graphTestCompressed(t, secret, false))
	graph, err := ValidateLocalLayers(context.Background(), fixture.expected, fixture.manifest, fixture.config, fixture.blobs)
	if err != nil {
		t.Fatal(err)
	}
	_, facts := associationFixture(t)
	facts.imageID = graph.Content().ConfigDigest()
	association, err := bindFacts(graph.Content(), facts)
	if err != nil || association.Authorization() != "BLOCKED" || !exactBlockers(association.Blockers()) {
		t.Fatal("byte graph weakened runtime authorization")
	}
	encoded, err := json.Marshal(graph)
	if err != nil || string(encoded) != "{}" || strings.Contains(fmt.Sprintf("%#v", graph), secret) {
		t.Fatal("graph retained a sensitive payload or serialized trust surface")
	}
	allowed := map[string]bool{"Content": true, "Boundary": true, "GraphSHA256": true, "LayerCount": true, "RawBytes": true, "UncompressedBytes": true}
	typeOf := reflect.TypeOf(graph)
	for i := 0; i < typeOf.NumMethod(); i++ {
		if !allowed[typeOf.Method(i).Name] {
			t.Fatal("graph gained an unreviewed public capability")
		}
	}
	for i := 0; i < typeOf.NumField(); i++ {
		if typeOf.Field(i).IsExported() {
			t.Fatal("graph exposes mutable state")
		}
	}
}
