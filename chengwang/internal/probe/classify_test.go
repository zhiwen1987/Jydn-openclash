package probe

import (
	"net/http"
	"testing"
	"time"
)

func TestClassifyResponseSemanticsOverrideExpectedStatus(t *testing.T) {
	now := time.Date(2026, 10, 18, 10, 0, 0, 0, time.UTC)
	target := Target{ExpectedStatus: []int{200, 204, 302, 401, 403, 429, 500}, RequiredMarker: "ready"}
	tests := []struct {
		name       string
		status     int
		body       string
		conclusion Conclusion
		outcome    Outcome
		state      LayerState
		errorClass string
	}{
		{"matching", 200, "service ready", ConclusionAvailable, OutcomePass, LayerAvailable, ""},
		{"marker mismatch", 200, "service pending", ConclusionUnknown, OutcomeIndeterminate, LayerUnknown, "contract_mismatch"},
		{"unexpected 2xx", 201, "service ready", ConclusionUnknown, OutcomeIndeterminate, LayerUnknown, "contract_mismatch"},
		{"redirect", 302, "service ready", ConclusionUnknown, OutcomeIndeterminate, LayerUnknown, "redirect_blocked"},
		{"unauthorized", 401, "service ready", ConclusionRestricted, OutcomeIndeterminate, LayerRestricted, "restricted"},
		{"forbidden", 403, "service ready", ConclusionRestricted, OutcomeIndeterminate, LayerRestricted, "restricted"},
		{"rate limited", 429, "service ready", ConclusionRateLimited, OutcomeIndeterminate, LayerRateLimited, "rate_limited"},
		{"service failure", 500, "service ready", ConclusionUnknown, OutcomeIndeterminate, LayerUnknown, "service_failure"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := classifyResponse(target, test.status, []byte(test.body), "60", now)
			if got.conclusion != test.conclusion || got.outcome != test.outcome || got.businessState != test.state || got.errorClass != test.errorClass {
				t.Fatalf("classification = %#v", got)
			}
		})
	}
}

func TestParseRetryAfterIsBounded(t *testing.T) {
	now := time.Date(2026, 10, 18, 10, 0, 0, 250_000_000, time.UTC)
	tests := []struct {
		value string
		want  int64
	}{
		{"120", 120},
		{"0", 0},
		{"-1", 0},
		{"3601", 0},
		{"9223372036854775807", 0},
		{"garbage", 0},
		{now.Add(90 * time.Second).Format(http.TimeFormat), 90},
		{now.Add(-time.Second).Format(http.TimeFormat), 0},
		{now.Add(2 * time.Hour).Format(http.TimeFormat), 0},
	}
	for _, test := range tests {
		if got := parseRetryAfter(test.value, now); got != test.want {
			t.Errorf("parseRetryAfter(%q) = %d, want %d", test.value, got, test.want)
		}
	}
}
