package probeview

import "chengwang/internal/probe"

// Keep a local explicit vocabulary. Future upstream result fields or arbitrary
// error strings must not silently become part of the management API contract.
func allowedEvidenceText(value string) bool {
	switch value {
	case "access_restricted", "canceled", "catalog_digest_mismatch", "connect_failure", "contract_matched", "contract_mismatch", "dns_failure", "dns_timeout", "http_response_received", "http_transport_failure", "invalid_catalog", "invalid_probe_id", "invalid_probe_input", "invalid_resolved_target", "not_observed", "probe_canceled", "rate_limited", "redirect_blocked", "resolved_and_pinned", "response_read_failed", "response_too_large", "response_unusable", "restricted", "run_id_unavailable", "service_failure", "target_not_allowlisted", "tcp_connected", "timeout", "tls_failure", "tls_verified", "transport_unavailable", "unexpected_http_status":
		return true
	}
	return false
}

func safeReason(value string) string {
	switch value {
	case "insufficient_evidence", "evidence_stale_or_clock_invalid", "two_consecutive_contract_matches", "awaiting_success_confirmation", "three_consecutive_transport_failures", "failure_below_unavailable_threshold":
		return value
	}
	if allowedEvidenceText(value) {
		return value
	}
	return "no_current_evidence"
}

func projectLayer(layer probe.LayerResult) Layer {
	reason := layer.Reason
	if !allowedEvidenceText(reason) {
		reason = "not_observed"
	}
	return Layer{State: layer.State, ObservedAt: layer.ObservedAt, ExpiresAt: layer.ExpiresAt, LatencyMillis: layer.LatencyMillis, RetryAfterSeconds: layer.RetryAfterSeconds, Reason: reason}
}

func projectSample(result probe.ProbeResult) Sample {
	var status *int
	if result.HTTPStatus != nil {
		value := *result.HTTPStatus
		status = &value
	}
	errorClass := result.ErrorClass
	if errorClass != "" && !allowedEvidenceText(errorClass) {
		errorClass = "response_unusable"
	}
	return Sample{
		RunID: result.RunID, ProbeID: result.ProbeID, PathID: result.PathID,
		AttemptedAt: result.AttemptedAt, CompletedAt: result.CompletedAt, ExpiresAt: result.ExpiresAt,
		Conclusion: result.Conclusion, Outcome: result.Outcome, HTTPStatus: status,
		ResponseBytes: result.ResponseBytes, ErrorClass: errorClass,
		Layers: Layers{DNS: projectLayer(result.Layers.DNS), Connect: projectLayer(result.Layers.Connect), TLS: projectLayer(result.Layers.TLS), HTTP: projectLayer(result.Layers.HTTP), Business: projectLayer(result.Layers.Business)},
	}
}

func rejectionCounts(issues []probe.ReadIssue) Rejections {
	var counts Rejections
	for _, issue := range issues {
		switch issue.Reason {
		case "unknown_schema", "unknown_result_schema", "segment_size_invalid", "segment_json_duplicate_key", "segment_json_invalid":
			counts.Format++
		case "content_digest_mismatch", "content_digest_invalid", "filename_mismatch":
			counts.Integrity++
		case "catalog_digest_mismatch", "catalog_membership_mismatch":
			counts.Catalog++
		case "future_result":
			counts.Future++
		case "duplicate_run_id":
			counts.Duplicate++
		case "result_identity_invalid", "result_not_advisory", "result_time_invalid", "result_contract_time_invalid", "result_value_invalid", "result_enum_invalid", "evidence_ref_invalid", "result_layer_invalid", "result_http_status_invalid":
			counts.Semantic++
		default:
			// A future upstream validator reason remains a safe counted rejection,
			// never an arbitrary string exposed by this API.
			counts.Semantic++
		}
	}
	return counts
}
