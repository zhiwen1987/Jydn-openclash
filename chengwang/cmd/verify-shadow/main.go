// Command verify-shadow performs a bounded, read-only acceptance check against
// a running Chengwang Shadow control plane. It never supplies credentials and
// never calls a mutating endpoint.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"chengwang/internal/capability"
)

const maxResponseBytes = 1 << 20

type check struct {
	Name   string `json:"name"`
	Passed bool   `json:"passed"`
	Detail string `json:"detail"`
}

type report struct {
	GeneratedAt string  `json:"generatedAt"`
	BaseURL     string  `json:"baseUrl"`
	Passed      bool    `json:"passed"`
	Checks      []check `json:"checks"`
}

type healthResponse struct {
	Status                   string `json:"status"`
	Mode                     string `json:"mode"`
	MihomoReadbackConfigured bool   `json:"mihomoReadbackConfigured"`
	EvidenceConfigured       bool   `json:"evidenceConfigured"`
	EvidenceIntegrity        bool   `json:"evidenceIntegrity"`
}

type operationBoundary struct {
	Effect                string `json:"effect"`
	DeviceActionsExecuted bool   `json:"deviceActionsExecuted"`
	Code                  string `json:"code"`
}

type shadowAttestation struct {
	Mode                     string `json:"mode"`
	ProductionControlEnabled bool   `json:"productionControlEnabled"`
	IdentityConfigured       bool   `json:"identityConfigured"`
	OperationWritesEnabled   bool   `json:"operationWritesEnabled"`
	DeviceActionsExecuted    bool   `json:"deviceActionsExecuted"`
	Evidence                 struct {
		Valid      bool      `json:"valid"`
		VerifiedAt time.Time `json:"verifiedAt"`
	} `json:"evidence"`
	Mihomo struct {
		Configured       bool      `json:"configured"`
		Reachable        bool      `json:"reachable"`
		Fresh            bool      `json:"fresh"`
		LastSuccessfulAt time.Time `json:"lastSuccessfulAt"`
	} `json:"mihomo"`
}

func main() {
	base := flag.String("base-url", "http://127.0.0.1:7811", "Chengwang base URL")
	timeout := flag.Duration("timeout", 8*time.Second, "total acceptance timeout")
	expectedCapabilities := flag.Int("expected-capabilities", 15, "exact expected capability count")
	flag.Parse()

	ctx, cancel := context.WithTimeout(context.Background(), *timeout)
	defer cancel()
	r, err := verify(ctx, *base, *expectedCapabilities)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(2)
	}
	if err := json.NewEncoder(os.Stdout).Encode(r); err != nil {
		fmt.Fprintln(os.Stderr, "encode report:", err)
		os.Exit(2)
	}
	if !r.Passed {
		os.Exit(1)
	}
}

func verify(ctx context.Context, rawBase string, expectedCapabilities int) (report, error) {
	base, err := parseBaseURL(rawBase)
	if err != nil {
		return report{}, err
	}
	if expectedCapabilities < 1 || expectedCapabilities > 10000 {
		return report{}, errors.New("expected-capabilities must be between 1 and 10000")
	}
	client := &http.Client{
		Transport: http.DefaultTransport,
		CheckRedirect: func(_ *http.Request, _ []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	r := report{GeneratedAt: time.Now().UTC().Truncate(time.Second).Format(time.RFC3339), BaseURL: base.String(), Passed: true, Checks: []check{}}
	add := func(name string, passed bool, detail string) {
		r.Checks = append(r.Checks, check{Name: name, Passed: passed, Detail: detail})
		if !passed {
			r.Passed = false
		}
	}

	var health healthResponse
	headers, err := getJSON(ctx, client, endpoint(base, "/api/v1/health"), http.StatusOK, &health)
	add("health", err == nil && health.Status == "ok" && health.Mode == "shadow" && health.EvidenceConfigured && health.EvidenceIntegrity && health.MihomoReadbackConfigured, safeDetail(err, "status=%s mode=%s evidence=%t mihomo=%t", health.Status, health.Mode, health.EvidenceIntegrity, health.MihomoReadbackConfigured))
	add("security_headers", err == nil && headers.Get("X-Content-Type-Options") == "nosniff" && headers.Get("Referrer-Policy") == "no-referrer", safeDetail(err, "nosniff=%t no-referrer=%t", headers.Get("X-Content-Type-Options") == "nosniff", headers.Get("Referrer-Policy") == "no-referrer"))

	var capabilities capability.Report
	_, err = getJSON(ctx, client, endpoint(base, "/api/v1/capabilities"), http.StatusOK, &capabilities)
	identityBlocked := capabilityState(capabilities, "real_authentication") == capability.StateBlocked
	operationsBlocked := capabilityState(capabilities, "durable_operation_control") == capability.StateBlocked
	add("capability_truth", err == nil && len(capabilities.Capabilities) == expectedCapabilities && !capabilities.ProductionControlEnabled && identityBlocked && operationsBlocked, safeDetail(err, "count=%d production-control=%t identity-blocked=%t operations-blocked=%t", len(capabilities.Capabilities), capabilities.ProductionControlEnabled, identityBlocked, operationsBlocked))

	var boundary operationBoundary
	_, err = getJSON(ctx, client, endpoint(base, "/api/v1/operations"), http.StatusServiceUnavailable, &boundary)
	add("operation_fail_closed", err == nil && boundary.Code == "operation_control_not_configured" && boundary.Effect == "local_record_only" && !boundary.DeviceActionsExecuted, safeDetail(err, "code=%s effect=%s device-actions=%t", boundary.Code, boundary.Effect, boundary.DeviceActionsExecuted))

	var attestation shadowAttestation
	_, err = getJSON(ctx, client, endpoint(base, "/api/v1/attestation/shadow"), http.StatusOK, &attestation)
	attested := err == nil && attestation.Mode == "shadow" && !attestation.ProductionControlEnabled &&
		!attestation.IdentityConfigured && !attestation.OperationWritesEnabled && !attestation.DeviceActionsExecuted &&
		attestation.Evidence.Valid && !attestation.Evidence.VerifiedAt.IsZero() &&
		attestation.Mihomo.Configured && attestation.Mihomo.Reachable && attestation.Mihomo.Fresh && !attestation.Mihomo.LastSuccessfulAt.IsZero()
	add("shadow_attestation", attested, safeDetail(err, "mode=%s production-control=%t identity=%t operation-writes=%t device-actions=%t evidence=%t mihomo-configured=%t mihomo-reachable=%t mihomo-fresh=%t", attestation.Mode, attestation.ProductionControlEnabled, attestation.IdentityConfigured, attestation.OperationWritesEnabled, attestation.DeviceActionsExecuted, attestation.Evidence.Valid, attestation.Mihomo.Configured, attestation.Mihomo.Reachable, attestation.Mihomo.Fresh))

	return r, nil
}

func parseBaseURL(raw string) (*url.URL, error) {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil {
		return nil, fmt.Errorf("parse base URL: %w", err)
	}
	if (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || (u.EscapedPath() != "" && u.EscapedPath() != "/") {
		return nil, errors.New("base URL must be an http(s) origin without credentials, path, query, or fragment")
	}
	u.Path = ""
	return u, nil
}

func endpoint(base *url.URL, path string) string {
	u := *base
	u.Path = path
	return u.String()
}

func getJSON(ctx context.Context, client *http.Client, target string, expectedStatus int, dst any) (http.Header, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != expectedStatus {
		_, _ = io.Copy(io.Discard, io.LimitReader(resp.Body, maxResponseBytes))
		return resp.Header, fmt.Errorf("unexpected HTTP status %d", resp.StatusCode)
	}
	contentType := strings.ToLower(resp.Header.Get("Content-Type"))
	if !strings.HasPrefix(contentType, "application/json") {
		return resp.Header, errors.New("response is not JSON")
	}
	limited := io.LimitReader(resp.Body, maxResponseBytes+1)
	data, err := io.ReadAll(limited)
	if err != nil {
		return resp.Header, err
	}
	if len(data) > maxResponseBytes {
		return resp.Header, errors.New("response exceeds 1 MiB")
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	if err := decoder.Decode(dst); err != nil {
		return resp.Header, fmt.Errorf("decode JSON: %w", err)
	}
	if decoder.Decode(&struct{}{}) != io.EOF {
		return resp.Header, errors.New("response contains multiple JSON values")
	}
	return resp.Header, nil
}

func capabilityState(r capability.Report, id string) capability.State {
	for _, item := range r.Capabilities {
		if item.ID == id {
			return item.State
		}
	}
	return ""
}

func safeDetail(err error, format string, args ...any) string {
	if err != nil {
		return err.Error()
	}
	return fmt.Sprintf(format, args...)
}
