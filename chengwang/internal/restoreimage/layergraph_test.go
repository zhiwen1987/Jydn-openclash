package restoreimage

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"reflect"
	"strings"
	"testing"

	"chengwang/internal/restoreruntime"
)

// These fixtures bind real compressed bytes to their actual decoded digest.
// Their payloads deliberately need not be tar archives: this API proves bytes,
// not safe filesystem extraction or image provenance.
type graphTestLayer struct {
	media         string
	blob, decoded []byte
}

type graphTestFixture struct {
	expected         Expected
	manifest, config []byte
	blobs            [][]byte
}

func graphTestDigest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}

func graphTestJSON(t *testing.T, value any) []byte {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func graphTestGzip(t *testing.T, raw []byte) []byte {
	t.Helper()
	var buffer bytes.Buffer
	writer := gzip.NewWriter(&buffer)
	if _, err := writer.Write(raw); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return buffer.Bytes()
}

func graphTestRaw(raw string) graphTestLayer {
	return graphTestLayer{media: "application/vnd.oci.image.layer.v1.tar", blob: []byte(raw), decoded: []byte(raw)}
}

func graphTestCompressed(t *testing.T, raw string, docker bool) graphTestLayer {
	t.Helper()
	media := "application/vnd.oci.image.layer.v1.tar+gzip"
	if docker {
		media = "application/vnd.docker.image.rootfs.diff.tar.gzip"
	}
	return graphTestLayer{media: media, blob: graphTestGzip(t, []byte(raw)), decoded: []byte(raw)}
}

func graphTestBuild(t *testing.T, docker bool, layers ...graphTestLayer) graphTestFixture {
	t.Helper()
	manifestType, configType := "application/vnd.oci.image.manifest.v1+json", "application/vnd.oci.image.config.v1+json"
	if docker {
		manifestType, configType = "application/vnd.docker.distribution.manifest.v2+json", "application/vnd.docker.container.image.v1+json"
	}
	diffs, descriptors, blobs := make([]string, len(layers)), make([]any, len(layers)), make([][]byte, len(layers))
	for i, layer := range layers {
		diffs[i] = graphTestDigest(layer.decoded)
		descriptors[i] = map[string]any{"mediaType": layer.media, "digest": graphTestDigest(layer.blob), "size": len(layer.blob)}
		blobs[i] = append([]byte(nil), layer.blob...)
	}
	config := graphTestJSON(t, map[string]any{"os": "linux", "architecture": "amd64", "rootfs": map[string]any{"type": "layers", "diff_ids": diffs}})
	manifest := graphTestJSON(t, map[string]any{"schemaVersion": 2, "mediaType": manifestType, "config": map[string]any{"mediaType": configType, "digest": graphTestDigest(config), "size": len(config)}, "layers": descriptors})
	return graphTestFixture{Expected{Reference: "registry.example.test/team/probe@" + graphTestDigest(manifest), OS: "linux", Architecture: "amd64"}, manifest, config, blobs}
}

func graphTestReject(t *testing.T, graph LayerGraph, err error) {
	t.Helper()
	if !errors.Is(err, ErrInvalid) || err != ErrInvalid {
		t.Fatalf("expected fixed ErrInvalid, got %v", err)
	}
	if !reflect.DeepEqual(graph, LayerGraph{}) {
		t.Fatal("failure exposed nonzero layer graph")
	}
}

func TestLayerGraphAcceptsBoundBytesAndPreservesAdvisoryBoundary(t *testing.T) {
	gzipAsRaw := graphTestGzip(t, []byte("raw media type determines decoding"))
	for _, tc := range []struct {
		name   string
		docker bool
		layers []graphTestLayer
	}{
		{"oci-raw", false, []graphTestLayer{graphTestRaw("not a tar archive")}},
		{"raw-bytes-with-gzip-magic", false, []graphTestLayer{{media: "application/vnd.oci.image.layer.v1.tar", blob: gzipAsRaw, decoded: gzipAsRaw}}},
		{"oci-gzip", false, []graphTestLayer{graphTestCompressed(t, "payload one", false)}},
		{"docker-gzip", true, []graphTestLayer{graphTestCompressed(t, "payload two", true)}},
		{"mixed-ordered", false, []graphTestLayer{graphTestRaw("first"), graphTestCompressed(t, "second", false)}},
		{"empty-decoded-gzip", false, []graphTestLayer{graphTestCompressed(t, "", false)}},
		{"repeated-blob", false, []graphTestLayer{graphTestRaw("same"), graphTestRaw("same")}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			fixture := graphTestBuild(t, tc.docker, tc.layers...)
			graph, err := ValidateLocalLayers(context.Background(), fixture.expected, fixture.manifest, fixture.config, fixture.blobs)
			if err != nil {
				t.Fatal(err)
			}
			var raw, decoded int64
			for _, layer := range tc.layers {
				raw += int64(len(layer.blob))
				decoded += int64(len(layer.decoded))
			}
			if graph.Boundary() != LayerGraphBoundary || LayerGraphBoundary != "ADVISORY_LOCAL_OCI_DIGEST_GRAPH_BOUND" || graph.LayerCount() != len(tc.layers) || graph.RawBytes() != raw || graph.UncompressedBytes() != decoded {
				t.Fatal("incorrect graph boundary or byte accounting")
			}
			content := graph.Content()
			if content.Boundary() != ContentBoundary || content.ManifestDigest() != graphTestDigest(fixture.manifest) || content.ConfigDigest() != graphTestDigest(fixture.config) || content.LayerCount() != graph.LayerCount() {
				t.Fatal("graph lost original content identity")
			}
			if !digestPattern.MatchString(graph.GraphSHA256()) {
				t.Fatal("graph digest is not canonical SHA-256")
			}
			again, err := ValidateLocalLayers(context.Background(), fixture.expected, fixture.manifest, fixture.config, fixture.blobs)
			if err != nil || graph.GraphSHA256() != again.GraphSHA256() {
				t.Fatal("same graph is nondeterministic")
			}
			_, err = BindLocal(content, restoreruntime.Observation{})
			if err != ErrInvalid {
				t.Fatal("byte graph manufactured runtime acceptance")
			}
			before := graph.GraphSHA256()
			fixture.manifest[0], fixture.config[0] = '!', '!'
			for _, blob := range fixture.blobs {
				if len(blob) > 0 {
					blob[0] ^= 255
				}
			}
			if graph.GraphSHA256() != before || graph.Content().ManifestDigest() != content.ManifestDigest() {
				t.Fatal("graph retained mutable input state")
			}
		})
	}
}

func TestLayerGraphRejectsContextAndLayerCountFailures(t *testing.T) {
	fixture := graphTestBuild(t, false, graphTestRaw("payload"))
	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	for _, tc := range []struct {
		name  string
		ctx   context.Context
		blobs [][]byte
	}{
		{"nil-context", nil, fixture.blobs}, {"canceled", canceled, fixture.blobs},
		{"nil-layers", context.Background(), nil}, {"empty-layers", context.Background(), [][]byte{}},
		{"extra-layer", context.Background(), append(fixture.blobs, []byte("extra"))},
		{"nil-blob", context.Background(), [][]byte{nil}}, {"empty-blob", context.Background(), [][]byte{{}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			graph, err := ValidateLocalLayers(tc.ctx, fixture.expected, fixture.manifest, fixture.config, tc.blobs)
			graphTestReject(t, graph, err)
		})
	}
}

func TestLayerGraphRejectsIndependentDigestAndCompressionFailures(t *testing.T) {
	for _, name := range []string{"raw-digest", "raw-size-short", "raw-size-long", "diff-id", "reordered", "gzip-crc", "gzip-isize", "gzip-truncated", "gzip-header", "gzip-trailing-junk", "gzip-trailing-zero", "gzip-concatenated", "gzip-content-as-raw", "raw-content-as-gzip"} {
		t.Run(name, func(t *testing.T) {
			layer := graphTestCompressed(t, "sensitive-payload-for-test-only", false)
			switch name {
			case "gzip-crc":
				layer.blob[len(layer.blob)-8] ^= 1
			case "gzip-isize":
				layer.blob[len(layer.blob)-4] ^= 1
			case "gzip-truncated":
				layer.blob = layer.blob[:len(layer.blob)-3]
			case "gzip-header":
				layer.blob[0] = 0
			case "gzip-trailing-junk":
				layer.blob = append(layer.blob, []byte("junk")...)
			case "gzip-trailing-zero":
				layer.blob = append(layer.blob, 0)
			case "gzip-concatenated":
				layer.blob = append(layer.blob, graphTestGzip(t, []byte("second"))...)
				layer.decoded = append(layer.decoded, []byte("second")...)
			case "gzip-content-as-raw":
				layer.media = "application/vnd.oci.image.layer.v1.tar"
			case "raw-content-as-gzip":
				layer.blob = []byte("plain text")
			case "diff-id":
				layer.decoded = []byte("other decoded payload")
			}
			fixture := graphTestBuild(t, false, layer)
			switch name {
			case "raw-digest":
				fixture.blobs[0][len(fixture.blobs[0])/2] ^= 1
			case "raw-size-short":
				fixture.blobs[0] = fixture.blobs[0][:len(fixture.blobs[0])-1]
			case "raw-size-long":
				fixture.blobs[0] = append(fixture.blobs[0], 1)
			case "reordered":
				fixture = graphTestBuild(t, false, graphTestRaw("first"), graphTestRaw("other"))
				fixture.blobs[0], fixture.blobs[1] = fixture.blobs[1], fixture.blobs[0]
			}
			graph, err := ValidateLocalLayers(context.Background(), fixture.expected, fixture.manifest, fixture.config, fixture.blobs)
			graphTestReject(t, graph, err)
		})
	}
}

func TestLayerGraphRejectsInvalidBaseContentBeforeLayerWork(t *testing.T) {
	for _, name := range []string{"manifest", "config", "reference", "platform"} {
		t.Run(name, func(t *testing.T) {
			fixture := graphTestBuild(t, false, graphTestRaw("payload"))
			switch name {
			case "manifest":
				fixture.manifest = []byte(`{"schemaVersion":2}`)
			case "config":
				fixture.config = []byte(`{}`)
			case "reference":
				fixture.expected.Reference = "registry.example.test/team/probe:latest"
			case "platform":
				fixture.expected.Architecture = "arm64"
			}
			graph, err := ValidateLocalLayers(context.Background(), fixture.expected, fixture.manifest, fixture.config, fixture.blobs)
			graphTestReject(t, graph, err)
		})
	}
}

func TestLayerGraphBudgetDefaultsAndInvalidOverrides(t *testing.T) {
	want := layerLimits{maxLayerCompressed: 128 << 20, maxTotalCompressed: 512 << 20, maxLayerUncompressed: 512 << 20, maxTotalUncompressed: 1 << 30, maxExpansionRatio: 200, minExpansionBytes: 1 << 20}
	if !reflect.DeepEqual(defaultLayerLimits(), want) {
		t.Fatal("resource policy defaults changed")
	}
	fixture := graphTestBuild(t, false, graphTestRaw("payload"))
	for _, field := range []string{"layer-compressed", "total-compressed", "layer-uncompressed", "total-uncompressed", "ratio", "floor"} {
		for _, mode := range []string{"zero", "negative", "above-default"} {
			t.Run(field+"-"+mode, func(t *testing.T) {
				limits := defaultLayerLimits()
				var target *int64
				switch field {
				case "layer-compressed":
					target = &limits.maxLayerCompressed
				case "total-compressed":
					target = &limits.maxTotalCompressed
				case "layer-uncompressed":
					target = &limits.maxLayerUncompressed
				case "total-uncompressed":
					target = &limits.maxTotalUncompressed
				case "ratio":
					target = &limits.maxExpansionRatio
				case "floor":
					target = &limits.minExpansionBytes
				}
				switch mode {
				case "zero":
					*target = 0
				case "negative":
					*target = -1
				case "above-default":
					*target++
				}
				graph, err := validateLocalLayers(context.Background(), fixture.expected, fixture.manifest, fixture.config, fixture.blobs, limits)
				graphTestReject(t, graph, err)
			})
		}
	}
}

func TestLayerGraphSmallByteBudgets(t *testing.T) {
	for _, field := range []string{"layer-compressed", "total-compressed", "layer-uncompressed", "total-uncompressed"} {
		for _, exceeded := range []bool{false, true} {
			name := field + "-exact"
			if exceeded {
				name = field + "-exceeded"
			}
			t.Run(name, func(t *testing.T) {
				fixture := graphTestBuild(t, false, graphTestRaw("0123456789"), graphTestRaw("abcdefghij"))
				limits := layerLimits{1000, 1000, 1000, 1000, 200, 1000}
				var target *int64
				var value int64
				switch field {
				case "layer-compressed":
					target = &limits.maxLayerCompressed
					value = 10
				case "total-compressed":
					target = &limits.maxTotalCompressed
					value = 20
				case "layer-uncompressed":
					target = &limits.maxLayerUncompressed
					value = 10
				case "total-uncompressed":
					target = &limits.maxTotalUncompressed
					value = 20
				}
				if exceeded {
					value--
				}
				*target = value
				graph, err := validateLocalLayers(context.Background(), fixture.expected, fixture.manifest, fixture.config, fixture.blobs, limits)
				if exceeded {
					graphTestReject(t, graph, err)
				} else if err != nil || graph.RawBytes() != 20 || graph.UncompressedBytes() != 20 {
					t.Fatalf("exact budget rejected: %v", err)
				}
			})
		}
	}
	for _, exceeded := range []bool{false, true} {
		name := "expansion-floor-exact"
		if exceeded {
			name = "expansion-floor-exceeded"
		}
		t.Run(name, func(t *testing.T) {
			fixture := graphTestBuild(t, false, graphTestCompressed(t, strings.Repeat("x", 4000), false))
			limits := layerLimits{10000, 10000, 10000, 10000, 1, 4000}
			if exceeded {
				limits.minExpansionBytes--
			}
			graph, err := validateLocalLayers(context.Background(), fixture.expected, fixture.manifest, fixture.config, fixture.blobs, limits)
			if exceeded {
				graphTestReject(t, graph, err)
			} else if err != nil || graph.UncompressedBytes() != 4000 {
				t.Fatalf("exact expansion floor rejected: %v", err)
			}
		})
	}
}

func TestLayerGraphCompressedExpansionAndRepeatedOccurrenceBudgets(t *testing.T) {
	t.Run("gzip-ratio-rejected-before-large-output", func(t *testing.T) {
		fixture := graphTestBuild(t, false, graphTestCompressed(t, strings.Repeat("x", 4000), false))
		limits := layerLimits{10000, 10000, 10000, 10000, 2, 1}
		graph, err := validateLocalLayers(context.Background(), fixture.expected, fixture.manifest, fixture.config, fixture.blobs, limits)
		graphTestReject(t, graph, err)
	})
	t.Run("gzip-ratio-allows-bounded-expansion", func(t *testing.T) {
		fixture := graphTestBuild(t, false, graphTestCompressed(t, strings.Repeat("x", 4000), false))
		limits := layerLimits{10000, 10000, 10000, 10000, 200, 1}
		graph, err := validateLocalLayers(context.Background(), fixture.expected, fixture.manifest, fixture.config, fixture.blobs, limits)
		if err != nil || graph.UncompressedBytes() != 4000 {
			t.Fatalf("bounded valid ratio rejected: %v", err)
		}
	})
	for _, budget := range []string{"raw", "decoded"} {
		t.Run("duplicate-layer-counted-twice-"+budget, func(t *testing.T) {
			layer := graphTestCompressed(t, "same decoded bytes", false)
			fixture := graphTestBuild(t, false, layer, layer)
			limits := layerLimits{1000, 1000, 1000, 1000, 200, 1000}
			if budget == "raw" {
				limits.maxTotalCompressed = int64(len(layer.blob)*2 - 1)
			} else {
				limits.maxTotalUncompressed = int64(len(layer.decoded)*2 - 1)
			}
			graph, err := validateLocalLayers(context.Background(), fixture.expected, fixture.manifest, fixture.config, fixture.blobs, limits)
			graphTestReject(t, graph, err)
		})
	}
}

func TestLayerGraphDigestBindsOriginalCompressedRepresentation(t *testing.T) {
	layer := graphTestCompressed(t, "unchanged decoded payload", false)
	first := graphTestBuild(t, false, layer)
	graph, err := ValidateLocalLayers(context.Background(), first.expected, first.manifest, first.config, first.blobs)
	if err != nil {
		t.Fatal(err)
	}
	// Changing MTIME changes the compressed byte identity without changing the
	// decoded payload or its diff_id. Both are valid, distinct byte graphs.
	layer.blob = append([]byte(nil), layer.blob...)
	layer.blob[4] = 1
	second := graphTestBuild(t, false, layer)
	other, err := ValidateLocalLayers(context.Background(), second.expected, second.manifest, second.config, second.blobs)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(first.config, second.config) || graph.Content().ConfigDigest() != other.Content().ConfigDigest() {
		t.Fatal("fixture changed decoded identity")
	}
	if graph.Content().ManifestDigest() == other.Content().ManifestDigest() || graph.GraphSHA256() == other.GraphSHA256() {
		t.Fatal("graph digest ignored the original compressed representation")
	}
}
