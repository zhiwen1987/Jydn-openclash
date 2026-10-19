package restoreimage

import (
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"strconv"
)

const LayerGraphBoundary = "ADVISORY_LOCAL_OCI_DIGEST_GRAPH_BOUND"

// LayerGraph records an ordered local digest graph, not tar semantics, Registry
// provenance, signatures, immutable deployment, or current runtime liveness.
// It retains no layer/config bytes and grants no additional authorization.
type LayerGraph struct {
	content                     Content
	boundary, graphSHA256       string
	rawBytes, uncompressedBytes int64
}

func (g LayerGraph) Content() Content         { return g.content }
func (g LayerGraph) Boundary() string         { return g.boundary }
func (g LayerGraph) GraphSHA256() string      { return g.graphSHA256 }
func (g LayerGraph) LayerCount() int          { return g.content.LayerCount() }
func (g LayerGraph) RawBytes() int64          { return g.rawBytes }
func (g LayerGraph) UncompressedBytes() int64 { return g.uncompressedBytes }

type layerLimits struct {
	maxLayerCompressed, maxTotalCompressed     int64
	maxLayerUncompressed, maxTotalUncompressed int64
	maxExpansionRatio, minExpansionBytes       int64
}

func defaultLayerLimits() layerLimits {
	return layerLimits{
		maxLayerCompressed: 128 << 20, maxTotalCompressed: 512 << 20,
		maxLayerUncompressed: 512 << 20, maxTotalUncompressed: 1 << 30,
		maxExpansionRatio: 200, minExpansionBytes: 1 << 20,
	}
}

func validLayerLimits(limits layerLimits) bool {
	maximum := defaultLayerLimits()
	return limits.maxLayerCompressed > 0 && limits.maxLayerCompressed <= maximum.maxLayerCompressed &&
		limits.maxTotalCompressed > 0 && limits.maxTotalCompressed <= maximum.maxTotalCompressed &&
		limits.maxLayerUncompressed > 0 && limits.maxLayerUncompressed <= maximum.maxLayerUncompressed &&
		limits.maxTotalUncompressed > 0 && limits.maxTotalUncompressed <= maximum.maxTotalUncompressed &&
		limits.maxExpansionRatio > 0 && limits.maxExpansionRatio <= maximum.maxExpansionRatio &&
		limits.minExpansionBytes > 0 && limits.minExpansionBytes <= maximum.minExpansionBytes
}

// ValidateLocalLayers consumes caller-owned byte slices in manifest order.
// Inputs must remain unchanged during the call. Slices avoid arbitrary blocking
// Readers; cancellation is checked between bounded hashing/decoding chunks.
// Compression is limited to raw OCI bytes and a single gzip member. Layers are
// never extracted, executed, opened by path, or fetched by the package.
func ValidateLocalLayers(ctx context.Context, expected Expected, manifestRaw, configRaw []byte, layers [][]byte) (LayerGraph, error) {
	return validateLocalLayers(ctx, expected, manifestRaw, configRaw, layers, defaultLayerLimits())
}

func validateLocalLayers(ctx context.Context, expected Expected, manifestRaw, configRaw []byte, layers [][]byte, limits layerLimits) (LayerGraph, error) {
	if ctx == nil || ctx.Err() != nil || !validLayerLimits(limits) || len(layers) == 0 || len(layers) > maximumLayers {
		return LayerGraph{}, ErrInvalid
	}
	content, err := ValidateLocal(expected, manifestRaw, configRaw)
	if err != nil || len(layers) != content.LayerCount() {
		return LayerGraph{}, ErrInvalid
	}
	var image manifest
	var configuration struct {
		RootFS struct {
			DiffIDs []string `json:"diff_ids"`
		} `json:"rootfs"`
	}
	if json.Unmarshal(manifestRaw, &image) != nil || json.Unmarshal(configRaw, &configuration) != nil {
		return LayerGraph{}, ErrInvalid
	}
	var rawTotal int64
	for i, raw := range layers {
		size := int64(len(raw))
		if size == 0 || size != image.Layers[i].Size || size > limits.maxLayerCompressed || size > limits.maxTotalCompressed-rawTotal {
			return LayerGraph{}, ErrInvalid
		}
		rawTotal += size
	}
	graphHash := sha256.New()
	graphHash.Write([]byte("chengwang.local-oci-digest-graph/v1\x00" + content.Reference() + "\x00" + content.ConfigDigest() + "\x00"))
	var decodedTotal int64
	for i, raw := range layers {
		if ctx.Err() != nil {
			return LayerGraph{}, ErrInvalid
		}
		descriptor := image.Layers[i]
		if !rawLayerDigestMatches(ctx, raw, descriptor.Digest) {
			return LayerGraph{}, ErrInvalid
		}
		effectiveLimit := limits.maxLayerUncompressed
		if remaining := limits.maxTotalUncompressed - decodedTotal; remaining < effectiveLimit {
			effectiveLimit = remaining
		}
		// Multiplication is bounded by 128 MiB * 200, well below int64.
		expansionLimit := int64(len(raw)) * limits.maxExpansionRatio
		if expansionLimit < limits.minExpansionBytes {
			expansionLimit = limits.minExpansionBytes
		}
		if expansionLimit < effectiveLimit {
			effectiveLimit = expansionLimit
		}
		decodedSize, ok := decodedLayerDigestMatches(ctx, raw, descriptor.MediaType, configuration.RootFS.DiffIDs[i], effectiveLimit)
		if !ok {
			return LayerGraph{}, ErrInvalid
		}
		decodedTotal += decodedSize
		graphHash.Write([]byte(descriptor.Digest + "\x00" + configuration.RootFS.DiffIDs[i] + "\x00" +
			strconv.FormatInt(int64(len(raw)), 10) + "\x00" + strconv.FormatInt(decodedSize, 10) + "\x00"))
	}
	if ctx.Err() != nil {
		return LayerGraph{}, ErrInvalid
	}
	return LayerGraph{
		content: content, boundary: LayerGraphBoundary,
		graphSHA256: "sha256:" + hex.EncodeToString(graphHash.Sum(nil)),
		rawBytes:    rawTotal, uncompressedBytes: decodedTotal,
	}, nil
}

func rawLayerDigestMatches(ctx context.Context, raw []byte, expected string) bool {
	hash := sha256.New()
	for offset := 0; offset < len(raw); {
		if ctx.Err() != nil {
			return false
		}
		end := offset + 32*1024
		if end > len(raw) {
			end = len(raw)
		}
		hash.Write(raw[offset:end])
		offset = end
	}
	return "sha256:"+hex.EncodeToString(hash.Sum(nil)) == expected
}

func decodedLayerDigestMatches(ctx context.Context, raw []byte, mediaType, expected string, maximum int64) (int64, bool) {
	if maximum < 0 || ctx.Err() != nil {
		return 0, false
	}
	source := &layerByteSource{ctx: ctx, data: bytes.NewReader(raw)}
	var decoded io.Reader = source
	var compressed *gzip.Reader
	if mediaType == "application/vnd.oci.image.layer.v1.tar+gzip" || mediaType == "application/vnd.docker.image.rootfs.diff.tar.gzip" {
		var err error
		compressed, err = gzip.NewReader(source)
		if err != nil {
			return 0, false
		}
		defer compressed.Close()
		compressed.Multistream(false)
		decoded = compressed
	}
	hash := sha256.New()
	var count int64
	var buffer [32 * 1024]byte
	for {
		if ctx.Err() != nil {
			return 0, false
		}
		// Read at most one byte beyond the remaining budget to distinguish an
		// exact-size EOF from a stream that exceeds the limit.
		request := int64(len(buffer))
		if remaining := maximum - count; remaining < request {
			request = remaining + 1
		}
		n, err := decoded.Read(buffer[:int(request)])
		if int64(n) > maximum-count {
			return 0, false
		}
		count += int64(n)
		if n > 0 {
			hash.Write(buffer[:n])
		}
		if err == io.EOF {
			break
		}
		if err != nil || n == 0 {
			return 0, false
		}
	}
	if source.Len() != 0 || ctx.Err() != nil || "sha256:"+hex.EncodeToString(hash.Sum(nil)) != expected {
		return 0, false
	}
	return count, true
}

// A bounded output Read is insufficient for cancellation: a deflate stream may
// contain many empty blocks and consume substantial input without producing
// output. Bound context-check intervals on compressed input as well. ReadByte
// also prevents gzip from buffering past the end of its single member.
type layerByteSource struct {
	ctx                    context.Context
	data                   *bytes.Reader
	bytesUntilContextCheck int
}

func (source *layerByteSource) Read(target []byte) (int, error) {
	if source.ctx.Err() != nil {
		return 0, ErrInvalid
	}
	if len(target) > 32*1024 {
		target = target[:32*1024]
	}
	n, err := source.data.Read(target)
	source.bytesUntilContextCheck = 32*1024 - n
	return n, err
}

func (source *layerByteSource) ReadByte() (byte, error) {
	if source.bytesUntilContextCheck <= 0 {
		if source.ctx.Err() != nil {
			return 0, ErrInvalid
		}
		source.bytesUntilContextCheck = 32 * 1024
	}
	value, err := source.data.ReadByte()
	if err == nil {
		source.bytesUntilContextCheck--
	}
	return value, err
}

func (source *layerByteSource) Len() int { return source.data.Len() }
