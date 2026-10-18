package probe

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptrace"
	"net/url"
	"sync"
	"time"
)

const (
	minRunnerTimeout       = 100 * time.Millisecond
	maxRunnerTimeout       = 30 * time.Second
	maxResponseHeaderBytes = 16 << 10
)

type dialContextFunc func(context.Context, string, string) (net.Conn, error)

// Runner executes one HTTPS target from a validated catalog. It is an
// advisory evidence producer only: it has no selector, DNS, reload, repair, or
// routing mutation capability.
type Runner struct {
	timeout     time.Duration
	dialContext dialContextFunc
	rootCAs     *x509.CertPool
	now         func() time.Time
	newRunID    func() (string, error)
}

func NewRunner(timeout time.Duration) (*Runner, error) {
	if timeout < minRunnerTimeout || timeout > maxRunnerTimeout {
		return nil, fmt.Errorf("runner timeout must be between %s and %s", minRunnerTimeout, maxRunnerTimeout)
	}
	dialer := &net.Dialer{Timeout: timeout, KeepAlive: -1}
	return &Runner{
		timeout:     timeout,
		dialContext: dialer.DialContext,
		now:         time.Now,
		newRunID:    randomRunID,
	}, nil
}

// runResolved is deliberately package-private: production callers must use
// ResolveAndRun so a self-constructed public IP cannot bypass fresh resolution.
// Tests use it to exercise the HTTP transport against local fixtures.
func (r *Runner) runResolved(ctx context.Context, catalog Catalog, targetID string, resolved ResolvedTarget) ProbeResult {
	attemptedAt := r.now().UTC()
	result := newUnknownResult(attemptedAt)
	if !idPattern.MatchString(targetID) {
		return r.finishInvalid(result, "invalid_probe_id")
	}
	result.ProbeID = targetID

	computedDigest, err := DigestCatalog(catalog)
	if err != nil {
		return r.finishInvalid(result, "invalid_catalog")
	}
	if catalog.Digest == "" || catalog.Digest != computedDigest {
		return r.finishInvalid(result, "catalog_digest_mismatch")
	}
	result.CatalogDigest = computedDigest
	result.AgentID = catalog.Agent.ID
	result.Independence = catalog.Agent.Independence

	target, ok := catalogTarget(catalog, targetID)
	if !ok {
		return r.finishInvalid(result, "target_not_allowlisted")
	}
	result.PathID = target.PathID
	result.ExpiresAt = attemptedAt.Add(time.Duration(target.TTLSeconds) * time.Second)
	if err := ValidateResolvedTarget(target, resolved); err != nil {
		return r.finishInvalid(result, "invalid_resolved_target")
	}

	runID, err := r.newRunID()
	if err != nil {
		return r.finishInvalid(result, "run_id_unavailable")
	}
	result.RunID = runID
	result.Layers.DNS = layerResult(LayerAvailable, attemptedAt, result.ExpiresAt, 0, "resolved_and_pinned")

	requestURL, err := targetURL(target)
	if err != nil { // ValidateTarget should make this unreachable; fail closed.
		return r.finishInvalid(result, "invalid_probe_input")
	}
	probeTimeout := time.Duration(target.TimeoutSeconds) * time.Second
	if probeTimeout > r.timeout {
		probeTimeout = r.timeout
	}
	runCtx, cancel := context.WithTimeout(ctx, probeTimeout)
	defer cancel()

	trace := &traceTimings{now: r.now}
	req, err := http.NewRequestWithContext(runCtx, target.Method, requestURL.String(), nil)
	if err != nil {
		return r.finishInvalid(result, "invalid_probe_input")
	}
	req = req.WithContext(httptrace.WithClientTrace(req.Context(), trace.clientTrace()))

	transport := &http.Transport{
		Proxy: nil,
		DialContext: func(dialCtx context.Context, network, _ string) (net.Conn, error) {
			return r.dialContext(dialCtx, network, resolved.DialAddress)
		},
		ForceAttemptHTTP2:      false,
		TLSNextProto:           map[string]func(string, *tls.Conn) http.RoundTripper{},
		DisableKeepAlives:      true,
		DisableCompression:     true,
		MaxIdleConns:           0,
		MaxIdleConnsPerHost:    0,
		IdleConnTimeout:        0,
		TLSHandshakeTimeout:    probeTimeout,
		ResponseHeaderTimeout:  probeTimeout,
		ExpectContinueTimeout:  time.Second,
		MaxResponseHeaderBytes: maxResponseHeaderBytes,
		TLSClientConfig: &tls.Config{
			MinVersion: tls.VersionTLS12,
			ServerName: resolved.ServerName,
			RootCAs:    r.rootCAs,
			NextProtos: []string{"http/1.1"},
		},
	}
	client := &http.Client{Transport: transport, CheckRedirect: NoRedirect, Jar: nil}
	defer transport.CloseIdleConnections()

	response, requestErr := client.Do(req)
	if requestErr != nil {
		return r.finishTransportError(result, trace.snapshot(), requestErr, runCtx.Err())
	}
	defer response.Body.Close()

	status := response.StatusCode
	result.HTTPStatus = &status
	body, oversized, readErr := readBounded(response.Body, target.MaxBodyBytes, response.ContentLength)
	result.ResponseBytes = int64(len(body))
	if !oversized && readErr == nil {
		digest := sha256.Sum256(body)
		result.ContentDigest = "sha256:" + hex.EncodeToString(digest[:])
	}
	completedAt := r.now().UTC()
	result.CompletedAt = completedAt
	result.ExpiresAt = completedAt.Add(time.Duration(target.TTLSeconds) * time.Second)
	result.StageTimings = trace.snapshot().stageTimings(attemptedAt, completedAt)
	result.Layers.Connect = layerResult(LayerAvailable, completedAt, result.ExpiresAt, result.StageTimings.ConnectMillis, "tcp_connected")
	result.Layers.TLS = layerResult(LayerAvailable, completedAt, result.ExpiresAt, result.StageTimings.TLSMillis, "tls_verified")
	result.Layers.HTTP = layerResult(LayerAvailable, completedAt, result.ExpiresAt, result.StageTimings.HTTPMillis, "http_response_received")

	switch {
	case readErr != nil:
		result.Conclusion = ConclusionUnknown
		result.Outcome = OutcomeIndeterminate
		result.ErrorClass = "response_read_failed"
		result.Layers.HTTP.State = LayerDegraded
		result.Layers.HTTP.Reason = "response_read_failed"
		result.Layers.Business = layerResult(LayerUnknown, completedAt, result.ExpiresAt, 0, "response_unusable")
		return result
	case oversized:
		result.Conclusion = ConclusionUnknown
		result.Outcome = OutcomeIndeterminate
		result.ErrorClass = "response_too_large"
		result.Layers.HTTP.State = LayerDegraded
		result.Layers.HTTP.Reason = "response_too_large"
		result.Layers.Business = layerResult(LayerUnknown, completedAt, result.ExpiresAt, 0, "response_unusable")
		return result
	}

	classified := classifyResponse(target, status, body, response.Header.Get("Retry-After"), completedAt)
	result.Conclusion = classified.conclusion
	result.Outcome = classified.outcome
	result.ErrorClass = classified.errorClass
	result.Layers.Business = layerResult(classified.businessState, completedAt, result.ExpiresAt, 0, classified.reason)
	result.Layers.Business.RetryAfterSeconds = classified.retryAfterSecond
	return result
}

// ResolveAndRun accounts for DNS in the same total timeout budget as the HTTPS
// exchange. The injected resolver is expected to be the deployment's fixed,
// trusted resolver; it is never selected from a request or catalog field.
func (r *Runner) ResolveAndRun(ctx context.Context, catalog Catalog, targetID string, resolver Resolver) ProbeResult {
	attemptedAt := r.now().UTC()
	result := newUnknownResult(attemptedAt)
	if !idPattern.MatchString(targetID) {
		return r.finishInvalid(result, "invalid_probe_id")
	}
	result.ProbeID = targetID

	computedDigest, err := DigestCatalog(catalog)
	if err != nil {
		return r.finishInvalid(result, "invalid_catalog")
	}
	if catalog.Digest == "" || catalog.Digest != computedDigest {
		return r.finishInvalid(result, "catalog_digest_mismatch")
	}
	result.CatalogDigest = computedDigest
	result.AgentID = catalog.Agent.ID
	result.Independence = catalog.Agent.Independence
	target, ok := catalogTarget(catalog, targetID)
	if !ok {
		return r.finishInvalid(result, "target_not_allowlisted")
	}
	result.PathID = target.PathID
	result.ExpiresAt = attemptedAt.Add(time.Duration(target.TTLSeconds) * time.Second)

	totalTimeout := time.Duration(target.TimeoutSeconds) * time.Second
	if totalTimeout > r.timeout {
		totalTimeout = r.timeout
	}
	runCtx, cancel := context.WithTimeout(ctx, totalTimeout)
	defer cancel()
	resolved, resolveErr := ResolveAndPin(runCtx, resolver, target)
	resolvedAt := r.now().UTC()
	dnsMillis := elapsedMillis(attemptedAt, resolvedAt)
	if resolveErr != nil {
		runID, idErr := r.newRunID()
		if idErr != nil {
			return r.finishInvalid(result, "run_id_unavailable")
		}
		result.RunID = runID
		result.CompletedAt = resolvedAt
		result.ExpiresAt = resolvedAt.Add(time.Duration(target.TTLSeconds) * time.Second)
		result.StageTimings.DNSMillis = dnsMillis
		result.StageTimings.TotalMillis = elapsedMillis(attemptedAt, resolvedAt)
		result.Layers = unknownLayers(resolvedAt, result.ExpiresAt, "not_observed")
		switch {
		case errors.Is(runCtx.Err(), context.Canceled) || errors.Is(resolveErr, context.Canceled):
			result.Conclusion = ConclusionUnknown
			result.Outcome = OutcomeIndeterminate
			result.ErrorClass = "canceled"
			result.Layers.DNS = layerResult(LayerUnknown, resolvedAt, result.ExpiresAt, dnsMillis, "probe_canceled")
		case errors.Is(runCtx.Err(), context.DeadlineExceeded) || errors.Is(resolveErr, context.DeadlineExceeded):
			result.Conclusion = ConclusionUnavailable
			result.Outcome = OutcomeFail
			result.ErrorClass = "dns_timeout"
			result.Layers.DNS = layerResult(LayerUnavailable, resolvedAt, result.ExpiresAt, dnsMillis, "dns_timeout")
		default:
			result.Conclusion = ConclusionUnavailable
			result.Outcome = OutcomeFail
			result.ErrorClass = "dns_failure"
			result.Layers.DNS = layerResult(LayerUnavailable, resolvedAt, result.ExpiresAt, dnsMillis, "dns_failure")
		}
		return result
	}

	result = r.runResolved(runCtx, catalog, targetID, resolved)
	result.AttemptedAt = attemptedAt
	result.StageTimings.DNSMillis = dnsMillis
	result.StageTimings.TotalMillis = elapsedMillis(attemptedAt, result.CompletedAt)
	result.Layers.DNS.LatencyMillis = dnsMillis
	result.Layers.DNS.ObservedAt = resolvedAt
	return result
}

func (r *Runner) finishInvalid(result ProbeResult, errorClass string) ProbeResult {
	completedAt := r.now().UTC()
	result.CompletedAt = completedAt
	if result.ExpiresAt.IsZero() {
		result.ExpiresAt = completedAt
	}
	result.Conclusion = ConclusionUnknown
	result.Outcome = OutcomeIndeterminate
	result.ErrorClass = errorClass
	result.StageTimings.TotalMillis = elapsedMillis(result.AttemptedAt, completedAt)
	result.Layers = unknownLayers(completedAt, result.ExpiresAt, errorClass)
	return result
}

func (r *Runner) finishTransportError(result ProbeResult, trace traceSnapshot, requestErr, contextErr error) ProbeResult {
	completedAt := r.now().UTC()
	result.CompletedAt = completedAt
	ttl := result.ExpiresAt.Sub(result.AttemptedAt)
	if ttl < 0 {
		ttl = 0
	}
	result.ExpiresAt = completedAt.Add(ttl)
	result.StageTimings = trace.stageTimings(result.AttemptedAt, completedAt)
	result.Conclusion = ConclusionUnavailable
	result.Outcome = OutcomeFail
	result.Layers.Connect = layerResult(LayerUnknown, completedAt, result.ExpiresAt, result.StageTimings.ConnectMillis, "not_observed")
	result.Layers.TLS = layerResult(LayerUnknown, completedAt, result.ExpiresAt, result.StageTimings.TLSMillis, "not_observed")
	result.Layers.HTTP = layerResult(LayerUnknown, completedAt, result.ExpiresAt, result.StageTimings.HTTPMillis, "not_observed")
	result.Layers.Business = layerResult(LayerUnknown, completedAt, result.ExpiresAt, 0, "transport_unavailable")

	if errors.Is(contextErr, context.Canceled) || errors.Is(requestErr, context.Canceled) {
		result.Conclusion = ConclusionUnknown
		result.Outcome = OutcomeIndeterminate
		result.ErrorClass = "canceled"
		result.Layers.Business.Reason = "probe_canceled"
		return result
	}
	if errors.Is(contextErr, context.DeadlineExceeded) || errors.Is(requestErr, context.DeadlineExceeded) {
		result.ErrorClass = "timeout"
		switch {
		case !trace.connectDone || trace.connectErr != nil:
			result.Layers.Connect = layerResult(LayerUnavailable, completedAt, result.ExpiresAt, result.StageTimings.ConnectMillis, "timeout")
		case !trace.tlsStarted || !trace.tlsDone || trace.tlsErr != nil:
			result.Layers.Connect = layerResult(LayerAvailable, completedAt, result.ExpiresAt, result.StageTimings.ConnectMillis, "tcp_connected")
			result.Layers.TLS = layerResult(LayerUnavailable, completedAt, result.ExpiresAt, result.StageTimings.TLSMillis, "timeout")
		default:
			result.Layers.Connect = layerResult(LayerAvailable, completedAt, result.ExpiresAt, result.StageTimings.ConnectMillis, "tcp_connected")
			result.Layers.TLS = layerResult(LayerAvailable, completedAt, result.ExpiresAt, result.StageTimings.TLSMillis, "tls_verified")
			result.Layers.HTTP = layerResult(LayerUnavailable, completedAt, result.ExpiresAt, result.StageTimings.HTTPMillis, "timeout")
		}
		return result
	}
	if trace.connectDone && trace.connectErr == nil {
		result.Layers.Connect = layerResult(LayerAvailable, completedAt, result.ExpiresAt, result.StageTimings.ConnectMillis, "tcp_connected")
	}
	if trace.tlsStarted && trace.tlsDone && trace.tlsErr == nil {
		result.Layers.TLS = layerResult(LayerAvailable, completedAt, result.ExpiresAt, result.StageTimings.TLSMillis, "tls_verified")
	}
	if trace.tlsStarted && trace.tlsDone && trace.tlsErr != nil {
		result.ErrorClass = "tls_failure"
		result.Layers.TLS = layerResult(LayerUnavailable, completedAt, result.ExpiresAt, result.StageTimings.TLSMillis, "tls_failure")
		return result
	}
	if !trace.connectDone || trace.connectErr != nil {
		result.ErrorClass = "connect_failure"
		result.Layers.Connect = layerResult(LayerUnavailable, completedAt, result.ExpiresAt, result.StageTimings.ConnectMillis, "connect_failure")
		return result
	}
	result.ErrorClass = "http_transport_failure"
	result.Layers.HTTP = layerResult(LayerUnavailable, completedAt, result.ExpiresAt, result.StageTimings.HTTPMillis, "http_transport_failure")
	return result
}

func catalogTarget(catalog Catalog, targetID string) (Target, bool) {
	for _, target := range catalog.Probes {
		if target.ID == targetID {
			return target, true
		}
	}
	return Target{}, false
}

func targetURL(target Target) (*url.URL, error) {
	requestURI, err := url.ParseRequestURI(target.RequestPath)
	if err != nil {
		return nil, err
	}
	return &url.URL{
		Scheme:   "https",
		Host:     net.JoinHostPort(target.Host, fmt.Sprintf("%d", target.Port)),
		Path:     requestURI.Path,
		RawPath:  requestURI.RawPath,
		RawQuery: requestURI.RawQuery,
	}, nil
}

func readBounded(body io.Reader, limit, contentLength int64) ([]byte, bool, error) {
	if contentLength > limit {
		return nil, true, nil
	}
	data, err := io.ReadAll(io.LimitReader(body, limit+1))
	if err != nil {
		return nil, false, err
	}
	if int64(len(data)) > limit {
		return data[:limit], true, nil
	}
	return data, false, nil
}

func newUnknownResult(attemptedAt time.Time) ProbeResult {
	return ProbeResult{
		SchemaVersion: ResultSchemaV1,
		AttemptedAt:   attemptedAt,
		AdvisoryOnly:  true,
		Conclusion:    ConclusionUnknown,
		Outcome:       OutcomeIndeterminate,
		Layers:        unknownLayers(attemptedAt, attemptedAt, "not_observed"),
	}
}

func unknownLayers(observedAt, expiresAt time.Time, reason string) LayerResults {
	unknown := layerResult(LayerUnknown, observedAt, expiresAt, 0, reason)
	return LayerResults{DNS: unknown, Connect: unknown, TLS: unknown, HTTP: unknown, Business: unknown}
}

func layerResult(state LayerState, observedAt, expiresAt time.Time, latencyMillis int64, reason string) LayerResult {
	return LayerResult{State: state, ObservedAt: observedAt, ExpiresAt: expiresAt, LatencyMillis: latencyMillis, Reason: reason}
}

func randomRunID() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", err
	}
	return hex.EncodeToString(raw[:]), nil
}

func elapsedMillis(start, end time.Time) int64 {
	if start.IsZero() || end.Before(start) {
		return 0
	}
	return end.Sub(start).Milliseconds()
}

type traceTimings struct {
	mu                               sync.Mutex
	now                              func() time.Time
	connectStart, connectEnd         time.Time
	tlsStart, tlsEnd                 time.Time
	firstResponseByte                time.Time
	connectDone, tlsStarted, tlsDone bool
	connectErr, tlsErr               error
}

func (t *traceTimings) clientTrace() *httptrace.ClientTrace {
	return &httptrace.ClientTrace{
		ConnectStart: func(_, _ string) {
			t.mu.Lock()
			t.connectStart = t.now()
			t.mu.Unlock()
		},
		ConnectDone: func(_, _ string, err error) {
			t.mu.Lock()
			t.connectEnd, t.connectDone, t.connectErr = t.now(), true, err
			t.mu.Unlock()
		},
		TLSHandshakeStart: func() {
			t.mu.Lock()
			t.tlsStart, t.tlsStarted = t.now(), true
			t.mu.Unlock()
		},
		TLSHandshakeDone: func(_ tls.ConnectionState, err error) {
			t.mu.Lock()
			t.tlsEnd, t.tlsDone, t.tlsErr = t.now(), true, err
			t.mu.Unlock()
		},
		GotFirstResponseByte: func() {
			t.mu.Lock()
			t.firstResponseByte = t.now()
			t.mu.Unlock()
		},
	}
}

type traceSnapshot struct {
	connectStart, connectEnd         time.Time
	tlsStart, tlsEnd                 time.Time
	firstResponseByte                time.Time
	connectDone, tlsStarted, tlsDone bool
	connectErr, tlsErr               error
}

func (t *traceTimings) snapshot() traceSnapshot {
	t.mu.Lock()
	defer t.mu.Unlock()
	return traceSnapshot{
		connectStart: t.connectStart, connectEnd: t.connectEnd,
		tlsStart: t.tlsStart, tlsEnd: t.tlsEnd, firstResponseByte: t.firstResponseByte,
		connectDone: t.connectDone, tlsStarted: t.tlsStarted, tlsDone: t.tlsDone,
		connectErr: t.connectErr, tlsErr: t.tlsErr,
	}
}

func (t traceSnapshot) stageTimings(attemptedAt, completedAt time.Time) StageTimings {
	result := StageTimings{TotalMillis: elapsedMillis(attemptedAt, completedAt)}
	result.ConnectMillis = elapsedMillis(t.connectStart, t.connectEnd)
	result.TLSMillis = elapsedMillis(t.tlsStart, t.tlsEnd)
	httpStart := t.tlsEnd
	if httpStart.IsZero() {
		httpStart = t.connectEnd
	}
	result.HTTPMillis = elapsedMillis(httpStart, t.firstResponseByte)
	return result
}
