// Package registry reads one approved immutable image from an IP-pinned HTTPS
// registry. It returns only a validated digest graph and public observation data.
package registry

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"

	"chengwang/image-binding/policy"
	"chengwang/internal/restoreimage"
)

var ErrInvalid = errors.New("invalid approved registry observation")

const (
	maxJSON        = 1 << 20
	maxLayer       = 128 << 20
	maxTotal       = 512 << 20
	maxHeader      = 32 << 10
	ociManifest    = "application/vnd.oci.image.manifest.v1+json"
	dockerManifest = "application/vnd.docker.distribution.manifest.v2+json"
)

// Observation is not a deployment authorization or proof of current runtime.
// No image configuration, token, URL challenge or remote error is retained.
type Observation struct {
	verified                      bool
	graph                         restoreimage.LayerGraph
	approvalHash, reference, host string
	observedAt                    time.Time
}

func (o Observation) Verified() bool                 { return o.verified }
func (o Observation) Graph() restoreimage.LayerGraph { return o.graph }
func (o Observation) ApprovalSHA256() string         { return o.approvalHash }
func (o Observation) Reference() string              { return o.reference }
func (o Observation) RegistryHost() string           { return o.host }
func (o Observation) ObservedAt() time.Time          { return o.observedAt }

type descriptor struct {
	MediaType   string            `json:"mediaType"`
	Digest      string            `json:"digest"`
	Size        int64             `json:"size"`
	Annotations map[string]string `json:"annotations,omitempty"`
}

type manifest struct {
	SchemaVersion int               `json:"schemaVersion"`
	MediaType     string            `json:"mediaType"`
	Config        descriptor        `json:"config"`
	Layers        []descriptor      `json:"layers"`
	Annotations   map[string]string `json:"annotations,omitempty"`
}

type metadata struct {
	size                              int64
	mediaType, digest, etag, modified string
}

type reader struct {
	approval           policy.Approved
	dial               func(context.Context) (net.Conn, error)
	host, repo, bearer string
}

// Read uses approved literal IPs and validates TLS against the reference host.
// It never resolves DNS, follows redirects, evaluates authentication challenges,
// executes image bytes, or writes to a registry. Hard process limits are external.
func Read(ctx context.Context, approval policy.Approved, roots *x509.CertPool, bearerToken string) (Observation, error) {
	if ctx == nil {
		return Observation{}, ErrInvalid
	}
	if err := ctx.Err(); err != nil {
		return Observation{}, err
	}
	callerCtx := ctx
	if !approval.ValidAt(time.Now()) || !validToken(bearerToken) {
		return Observation{}, ErrInvalid
	}
	approvedSPKI := approval.RegistrySPKISHA256()
	if !validDigest(approvedSPKI) {
		return Observation{}, ErrInvalid
	}
	reference := approval.Reference()
	left, digest, ok := strings.Cut(reference, "@")
	host, repo, hasRepo := strings.Cut(left, "/")
	if !ok || !hasRepo || host == "" || repo == "" || !validDigest(digest) {
		return Observation{}, ErrInvalid
	}
	uri, err := url.Parse("https://" + host)
	if err != nil || uri.Host != host || uri.Hostname() == "" || uri.User != nil || uri.Path != "" || uri.RawQuery != "" || uri.Fragment != "" {
		return Observation{}, ErrInvalid
	}
	port := uri.Port()
	if port == "" {
		port = "443"
	}
	ips := approval.RegistryIPs()
	if len(ips) == 0 || len(ips) > 16 {
		return Observation{}, ErrInvalid
	}
	for _, raw := range ips {
		ip, err := netip.ParseAddr(raw)
		if err != nil || ip.String() != raw || ip.Zone() != "" || ip.IsUnspecified() || ip.IsMulticast() {
			return Observation{}, ErrInvalid
		}
	}
	deadline := time.Now().Add(2 * time.Minute)
	if expires := time.Unix(approval.NotAfterUnix(), 0); expires.Before(deadline) {
		deadline = expires
	}
	ctx, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	tlsConfig := &tls.Config{MinVersion: tls.VersionTLS12, RootCAs: roots, ServerName: uri.Hostname(), NextProtos: []string{"http/1.1"}}
	dial := func(callCtx context.Context) (net.Conn, error) {
		for _, ip := range ips {
			if !approval.ValidAt(time.Now()) {
				return nil, ErrInvalid
			}
			if err := callCtx.Err(); err != nil {
				return nil, err
			}
			dialCtx, stop := context.WithTimeout(callCtx, 5*time.Second)
			conn, err := (&net.Dialer{Timeout: 5 * time.Second}).DialContext(dialCtx, "tcp", net.JoinHostPort(ip, port))
			if err == nil {
				secure := tls.Client(conn, tlsConfig.Clone())
				err = secure.HandshakeContext(dialCtx)
				if err == nil {
					peers := secure.ConnectionState().PeerCertificates
					if len(peers) > 0 && hash(peers[0].RawSubjectPublicKeyInfo) == approvedSPKI {
						stop()
						return secure, nil
					}
				}
				conn.Close()
			}
			stop()
		}
		return nil, ErrInvalid
	}
	r := reader{approval: approval, host: host, repo: repo, bearer: bearerToken, dial: dial}
	fail := func() (Observation, error) {
		if callerCtx.Err() != nil {
			return Observation{}, callerCtx.Err()
		}
		return Observation{}, ErrInvalid
	}
	manifestRaw, meta, err := r.fetch(ctx, "manifests", digest, 0, maxJSON, []string{ociManifest, dockerManifest})
	if err != nil {
		return fail()
	}
	var image manifest
	decoder := json.NewDecoder(bytes.NewReader(manifestRaw))
	decoder.DisallowUnknownFields()
	if decoder.Decode(&image) != nil || decoder.Decode(&struct{}{}) != io.EOF || image.SchemaVersion != 2 || image.MediaType != meta.mediaType || len(image.Layers) == 0 || len(image.Layers) > 128 || !validDescriptor(image.Config, maxJSON) {
		return fail()
	}
	configType := "application/vnd.oci.image.config.v1+json"
	if image.MediaType == dockerManifest {
		configType = "application/vnd.docker.container.image.v1+json"
	}
	if image.Config.MediaType != configType {
		return fail()
	}
	var total int64
	for _, layer := range image.Layers {
		if !validDescriptor(layer, maxLayer) || layer.Size > maxTotal-total || !validLayerType(image.MediaType, layer.MediaType) {
			return fail()
		}
		total += layer.Size
	}
	configRaw, _, err := r.fetch(ctx, "blobs", image.Config.Digest, image.Config.Size, maxJSON, []string{configType, "application/octet-stream"})
	if err != nil {
		return fail()
	}
	layers := make([][]byte, 0, len(image.Layers))
	for _, layer := range image.Layers {
		raw, _, err := r.fetch(ctx, "blobs", layer.Digest, layer.Size, maxLayer, []string{layer.MediaType, "application/octet-stream"})
		if err != nil {
			return fail()
		}
		layers = append(layers, raw)
	}
	if !approval.ValidAt(time.Now()) {
		return fail()
	}
	graph, err := restoreimage.ValidateLocalLayers(ctx, restoreimage.Expected{Reference: reference, OS: approval.OS(), Architecture: approval.Architecture(), Variant: approval.Variant()}, manifestRaw, configRaw, layers)
	if err != nil {
		return fail()
	}
	finalRaw, finalMeta, err := r.fetch(ctx, "manifests", digest, int64(len(manifestRaw)), maxJSON, []string{image.MediaType})
	if err != nil || meta != finalMeta || !bytes.Equal(manifestRaw, finalRaw) || !approval.ValidAt(time.Now()) {
		return fail()
	}
	if err := ctx.Err(); err != nil {
		return fail()
	}
	observedAt := time.Now().UTC()
	if !approval.ValidAt(observedAt) {
		return fail()
	}
	return Observation{verified: true, graph: graph, approvalHash: approval.SHA256(), reference: reference, host: host, observedAt: observedAt}, nil
}

func (r *reader) fetch(ctx context.Context, kind, digest string, size, limit int64, types []string) ([]byte, metadata, error) {
	before, _, err := r.request(ctx, http.MethodHead, kind, digest, size, limit, types)
	if err != nil {
		return nil, metadata{}, ErrInvalid
	}
	middle, raw, err := r.request(ctx, http.MethodGet, kind, digest, before.size, limit, types)
	if err != nil || before != middle {
		return nil, metadata{}, ErrInvalid
	}
	after, _, err := r.request(ctx, http.MethodHead, kind, digest, before.size, limit, types)
	if err != nil || before != after {
		return nil, metadata{}, ErrInvalid
	}
	return raw, before, nil
}

func (r *reader) request(ctx context.Context, method, kind, digest string, size, limit int64, types []string) (metadata, []byte, error) {
	if !r.approval.ValidAt(time.Now()) || ctx.Err() != nil || (method != http.MethodGet && method != http.MethodHead) || (kind != "manifests" && kind != "blobs") || !validDigest(digest) {
		return metadata{}, nil, ErrInvalid
	}
	uri := url.URL{Scheme: "https", Host: r.host, Path: "/v2/" + r.repo + "/" + kind + "/" + digest}
	req, err := http.NewRequestWithContext(ctx, method, uri.String(), nil)
	if err != nil {
		return metadata{}, nil, ErrInvalid
	}
	req.Header.Set("Accept", strings.Join(types, ", "))
	if r.bearer != "" {
		req.Header.Set("Authorization", "Bearer "+r.bearer)
	}
	req.Close = true
	conn, err := r.dial(ctx)
	if err != nil {
		return metadata{}, nil, ErrInvalid
	}
	defer conn.Close()
	stop := context.AfterFunc(ctx, func() { conn.Close() })
	defer stop()
	if deadline, ok := ctx.Deadline(); ok {
		if conn.SetDeadline(deadline) != nil {
			return metadata{}, nil, ErrInvalid
		}
	}
	if !r.approval.ValidAt(time.Now()) || ctx.Err() != nil || req.Write(conn) != nil {
		return metadata{}, nil, ErrInvalid
	}
	if conn.SetReadDeadline(boundedDeadline(ctx, 10*time.Second)) != nil {
		return metadata{}, nil, ErrInvalid
	}
	source := bufio.NewReaderSize(conn, 4096)
	var header []byte
	for {
		line, readErr := source.ReadSlice('\n')
		header = append(header, line...)
		if len(header) > maxHeader {
			return metadata{}, nil, ErrInvalid
		}
		if readErr == bufio.ErrBufferFull {
			continue
		}
		if readErr != nil {
			return metadata{}, nil, ErrInvalid
		}
		if bytes.HasSuffix(header, []byte("\r\n\r\n")) {
			break
		}
	}
	if !validRawHeader(header[:len(header)-4]) {
		return metadata{}, nil, ErrInvalid
	}
	if deadline, ok := ctx.Deadline(); ok {
		if conn.SetReadDeadline(deadline) != nil {
			return metadata{}, nil, ErrInvalid
		}
	}
	wire := bufio.NewReader(io.MultiReader(bytes.NewReader(header), source))
	resp, err := http.ReadResponse(wire, req)
	if err != nil {
		return metadata{}, nil, ErrInvalid
	}
	// Close the socket before Body.Close so a rejected length cannot make
	// net/http drain an attacker-sized response while unwinding this call.
	defer func() { conn.Close(); resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK || len(resp.TransferEncoding) != 0 || len(resp.Trailer) != 0 || len(resp.Header.Values("Content-Encoding")) != 0 || !r.approval.ValidAt(time.Now()) {
		return metadata{}, nil, ErrInvalid
	}
	length, ok := single(resp.Header, "Content-Length", true)
	n, err := strconv.ParseInt(length, 10, 64)
	if !ok || err != nil || strconv.FormatInt(n, 10) != length || n <= 0 || n > limit || resp.ContentLength != n || (size != 0 && n != size) {
		return metadata{}, nil, ErrInvalid
	}
	ct, ok := single(resp.Header, "Content-Type", true)
	if !ok || !contains(types, ct) {
		return metadata{}, nil, ErrInvalid
	}
	dcd, ok := single(resp.Header, "Docker-Content-Digest", false)
	if !ok || (dcd != "" && dcd != digest) {
		return metadata{}, nil, ErrInvalid
	}
	etag, ok := single(resp.Header, "Etag", false)
	if !ok || (etag != "" && (len(etag) > 512 || !strings.HasPrefix(etag, "\"") || !strings.HasSuffix(etag, "\"") || strings.ContainsAny(etag, "\r\n\x00"))) {
		return metadata{}, nil, ErrInvalid
	}
	modified, ok := single(resp.Header, "Last-Modified", false)
	if !ok {
		return metadata{}, nil, ErrInvalid
	}
	if modified != "" {
		if _, err := http.ParseTime(modified); err != nil {
			return metadata{}, nil, ErrInvalid
		}
	}
	m := metadata{size: n, mediaType: ct, digest: dcd, etag: etag, modified: modified}
	if method == http.MethodHead {
		if !cleanEOF(ctx, conn, wire) || !r.approval.ValidAt(time.Now()) || ctx.Err() != nil {
			return metadata{}, nil, ErrInvalid
		}
		return m, nil, nil
	}
	raw, err := io.ReadAll(io.LimitReader(resp.Body, n+1))
	if err != nil || int64(len(raw)) != n || hash(raw) != digest || !cleanEOF(ctx, conn, wire) || !r.approval.ValidAt(time.Now()) || ctx.Err() != nil {
		return metadata{}, nil, ErrInvalid
	}
	return m, raw, nil
}

func single(h http.Header, key string, required bool) (string, bool) {
	values := h.Values(key)
	if len(values) == 0 {
		return "", !required
	}
	if len(values) != 1 || values[0] == "" || strings.TrimSpace(values[0]) != values[0] {
		return "", false
	}
	return values[0], true
}
func contains(values []string, value string) bool {
	for _, v := range values {
		if v == value {
			return true
		}
	}
	return false
}
func hash(raw []byte) string { h := sha256.Sum256(raw); return "sha256:" + hex.EncodeToString(h[:]) }
func validDigest(value string) bool {
	if len(value) != 71 || !strings.HasPrefix(value, "sha256:") {
		return false
	}
	for _, c := range value[7:] {
		if !(c >= '0' && c <= '9' || c >= 'a' && c <= 'f') {
			return false
		}
	}
	return true
}
func validDescriptor(d descriptor, max int64) bool {
	return d.Size > 0 && d.Size <= max && validDigest(d.Digest)
}
func validToken(token string) bool {
	if len(token) > 8192 {
		return false
	}
	for _, c := range token {
		if c <= 32 || c >= 127 {
			return false
		}
	}
	return true
}
func validLayerType(manifestType, layerType string) bool {
	if manifestType == dockerManifest {
		return layerType == "application/vnd.docker.image.rootfs.diff.tar.gzip"
	}
	return layerType == "application/vnd.oci.image.layer.v1.tar" || layerType == "application/vnd.oci.image.layer.v1.tar+gzip"
}

func boundedDeadline(ctx context.Context, duration time.Duration) time.Time {
	deadline := time.Now().Add(duration)
	if total, ok := ctx.Deadline(); ok && total.Before(deadline) {
		deadline = total
	}
	return deadline
}
func cleanEOF(ctx context.Context, conn net.Conn, wire *bufio.Reader) bool {
	if conn.SetReadDeadline(boundedDeadline(ctx, 10*time.Second)) != nil {
		return false
	}
	_, err := wire.ReadByte()
	return err == io.EOF
}

// Inspect raw HTTP/1 headers before net/http normalizes duplicate lengths.
// Each GET/HEAD uses a fresh TLS connection and requires its final clean EOF.
func validRawHeader(raw []byte) bool {
	// net/http also accepts bare LF line endings. Reject them before splitting
	// CRLF lines so a hidden first header cannot bypass duplicate detection.
	if strings.ContainsAny(strings.ReplaceAll(string(raw), "\r\n", ""), "\r\n") {
		return false
	}
	lines := strings.Split(string(raw), "\r\n")
	if len(lines) < 2 {
		return false
	}
	status := strings.Fields(lines[0])
	if len(status) < 2 || status[0] != "HTTP/1.1" || status[1] != "200" {
		return false
	}
	seen := map[string]bool{}
	for _, line := range lines[1:] {
		key, value, ok := strings.Cut(line, ":")
		if !ok || key == "" || strings.TrimSpace(key) != key {
			return false
		}
		for _, c := range key {
			if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || strings.ContainsRune("!#$%&'*+-.^_`|~", c)) {
				return false
			}
		}
		key = strings.ToLower(key)
		if seen[key] || key == "transfer-encoding" || key == "trailer" || key == "content-encoding" {
			return false
		}
		seen[key] = true
		for _, c := range value {
			if c < 32 && c != '\t' || c == 127 {
				return false
			}
		}
	}
	return seen["content-length"] && seen["content-type"]
}
