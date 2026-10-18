package probe

import (
	"bytes"
	"net/http"
	"strconv"
	"strings"
	"time"
)

const maxRetryAfter = time.Hour

type responseClassification struct {
	conclusion       Conclusion
	outcome          Outcome
	businessState    LayerState
	reason           string
	errorClass       string
	retryAfterSecond int64
}

// classifyResponse intentionally gives the protocol semantics precedence over
// the catalog's expected-status list. In particular, an accidentally
// allowlisted 401, 403, 429, redirect, or 5xx can never become a passing
// business result.
func classifyResponse(target Target, status int, body []byte, retryAfter string, observedAt time.Time) responseClassification {
	switch {
	case status == http.StatusUnauthorized || status == http.StatusForbidden:
		return responseClassification{
			conclusion:    ConclusionRestricted,
			outcome:       OutcomeIndeterminate,
			businessState: LayerRestricted,
			reason:        "access_restricted",
			errorClass:    "restricted",
		}
	case status == http.StatusTooManyRequests:
		return responseClassification{
			conclusion:       ConclusionRateLimited,
			outcome:          OutcomeIndeterminate,
			businessState:    LayerRateLimited,
			reason:           "rate_limited",
			errorClass:       "rate_limited",
			retryAfterSecond: parseRetryAfter(retryAfter, observedAt),
		}
	case status >= 300 && status <= 399:
		return indeterminate("redirect_blocked")
	case status >= 500 && status <= 599:
		return indeterminate("service_failure")
	case status < 200 || status > 299:
		return indeterminate("unexpected_http_status")
	case !containsStatus(target.ExpectedStatus, status):
		return indeterminate("contract_mismatch")
	case target.RequiredMarker != "" && !bytes.Contains(body, []byte(target.RequiredMarker)):
		return indeterminate("contract_mismatch")
	default:
		return responseClassification{
			conclusion:    ConclusionAvailable,
			outcome:       OutcomePass,
			businessState: LayerAvailable,
			reason:        "contract_matched",
		}
	}
}

func indeterminate(reason string) responseClassification {
	return responseClassification{
		conclusion:    ConclusionUnknown,
		outcome:       OutcomeIndeterminate,
		businessState: LayerUnknown,
		reason:        reason,
		errorClass:    reason,
	}
}

func containsStatus(statuses []int, wanted int) bool {
	for _, status := range statuses {
		if status == wanted {
			return true
		}
	}
	return false
}

// parseRetryAfter accepts the two RFC forms but returns only a bounded delay.
// Invalid, negative, past, and over-budget values are ignored so an untrusted
// peer cannot create an unbounded scheduler pause.
func parseRetryAfter(value string, observedAt time.Time) int64 {
	value = strings.TrimSpace(value)
	if value == "" || len(value) > 128 {
		return 0
	}
	if seconds, err := strconv.ParseInt(value, 10, 64); err == nil {
		if seconds > 0 && seconds <= int64(maxRetryAfter/time.Second) {
			return seconds
		}
		return 0
	}
	when, err := http.ParseTime(value)
	if err != nil {
		return 0
	}
	delay := when.Sub(observedAt)
	if delay <= 0 || delay > maxRetryAfter {
		return 0
	}
	// HTTP dates have one-second precision. Round up defensively if a caller
	// supplied a sub-second observation timestamp.
	return int64((delay + time.Second - 1) / time.Second)
}
