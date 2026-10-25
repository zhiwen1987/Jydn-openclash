package api

import (
	"net/http"
	"regexp"
	"strings"

	"chengwang/internal/mihomodeploy"
)

const mihomoRecoveryPrefix = "/api/v1/lab/mihomo/recoveries"

func validMihomoRecoveryView(v mihomodeploy.LabRecoveryView, id string) bool {
	if v.Schema != mihomodeploy.LabRecoveryViewSchema || v.Boundary != mihomodeploy.LabBackendBoundary ||
		!mihomoRecoveryID.MatchString(v.RecoveryID) || (id != "" && v.RecoveryID != id) || v.Revision == 0 || v.HeadGeneration == 0 ||
		!validMihomoLabHash(v.PlanSHA256) || !mihomoLabID.MatchString(v.UnknownOperationID) || !validMihomoLabHash(v.OriginalPlanSHA256) ||
		!validMihomoLabHash(v.PreviousHeadSHA256) || !validMihomoLabHash(v.HeadSHA256) ||
		!validMihomoLabHash(v.TargetArtifactRecordSHA256) || !validMihomoLabHash(v.TargetConfigSHA256) ||
		!validMihomoLabTime(v.ExpiresAt) || !validMihomoLabProof(v.Proof) {
		return false
	}
	switch v.Phase {
	case "PLANNED", "APPROVED", "STOP_ARMED", "OLD_EPOCH_QUIESCED", "START_ARMED", "RECOVERY_UNKNOWN", "FAILED_RECONCILED", "REVOKED_UNSTARTED":
		if v.HeadAdvanced {
			return false
		}
		if v.Phase != "RECOVERY_UNKNOWN" && v.Phase != "FAILED_RECONCILED" {
			return v.Failure == nil
		}
		f := v.Failure
		if f == nil || f.Schema != mihomodeploy.LabRecoveryFailureViewSchema ||
			(f.Code != "PROCESS_REOPENED" && f.Code != "QUIESCENCE_REJECTED" && f.Code != "SERVICE_CONTEXT_CANCELLED" && f.Code != "AUTHORITY_CHANGED" && f.Code != "EXPLICIT_REVOKED" && f.Code != "EXPIRED" && f.Code != "START_UNCERTAIN") {
			return false
		}
		switch f.CleanupState {
		case "SETTLED":
			if v.Phase == "FAILED_RECONCILED" {
				return validMihomoLabHash(f.CleanupSHA256) && f.NextAction == "CREATE_RECOVERY"
			}
			return validMihomoLabHash(f.CleanupSHA256) && f.NextAction == "CORE_RECONCILIATION_REQUIRED"
		case "UNCERTAIN":
			return validMihomoLabHash(f.CleanupSHA256) && f.NextAction == "CLOSE_REQUIRED"
		case "PENDING":
			return f.CleanupSHA256 == "" && f.NextAction == "CLOSE_REQUIRED"
		default:
			return false
		}
	case "COMPLETED":
		return v.HeadAdvanced && v.HeadSHA256 != v.PreviousHeadSHA256 && v.Failure == nil
	default:
		return false
	}
}

var mihomoRecoveryID = regexp.MustCompile(`^labrec_[a-f0-9]{32}$`)

func (s *server) mihomoRecovery(w http.ResponseWriter, r *http.Request) {
	values := r.Header.Values("Authorization")
	if len(values) != 1 || !strictImageTrustBearer(values[0]) {
		w.Header().Set("WWW-Authenticate", `Bearer realm="chengwang"`)
		mihomoLabError(w, http.StatusUnauthorized, "mihomo_lab_unauthenticated", false)
		return
	}
	if !requestTransportSecure(r) {
		mihomoLabError(w, http.StatusUpgradeRequired, "mihomo_lab_secure_transport_required", false)
		return
	}
	if nilSubscriptionInterface(s.options.MihomoRecoveries) || !validMihomoLabScope(s.mihomoRecoveryScope) || s.mihomoRecoveryScope != s.mihomoLabScope {
		mihomoLabError(w, http.StatusServiceUnavailable, "mihomo_lab_unavailable", false)
		return
	}
	if r.URL.RawPath != "" || r.URL.EscapedPath() != r.URL.Path || r.URL.RawQuery != "" || r.URL.ForceQuery || r.URL.Fragment != "" || r.URL.RawFragment != "" ||
		strings.Contains(r.URL.Path, "//") || strings.Contains(r.URL.Path, "/./") || strings.Contains(r.URL.Path, "/../") {
		mihomoLabError(w, http.StatusBadRequest, "mihomo_lab_invalid", false)
		return
	}
	method, action, id := "", "", ""
	switch r.URL.Path {
	case mihomoRecoveryPrefix:
		method, action = http.MethodPost, "create"
	default:
		parts := strings.Split(strings.TrimPrefix(r.URL.Path, mihomoRecoveryPrefix+"/"), "/")
		if len(parts) > 0 {
			id = parts[0]
		}
		if len(parts) == 1 {
			method, action = http.MethodGet, "inspect"
		} else if len(parts) == 2 {
			switch parts[1] {
			case "approvals":
				method, action = http.MethodPost, "approve"
			case "execute":
				method, action = http.MethodPost, "execute"
			case "revocations":
				method, action = http.MethodPost, "revoke"
			}
		}
	}
	if action == "" {
		mihomoLabError(w, http.StatusNotFound, "mihomo_lab_not_found", false)
		return
	}
	if id != "" && !mihomoRecoveryID.MatchString(id) {
		mihomoLabError(w, http.StatusBadRequest, "mihomo_lab_invalid", false)
		return
	}
	if r.Method != method {
		w.Header().Set("Allow", method)
		mihomoLabError(w, http.StatusMethodNotAllowed, "mihomo_lab_method_not_allowed", false)
		return
	}
	if method == http.MethodPost && !s.options.MihomoRecoveryWritesEnabled {
		mihomoLabError(w, http.StatusServiceUnavailable, "mihomo_lab_writes_disabled", false)
		return
	}
	if r.Context().Err() != nil {
		mihomoLabError(w, http.StatusServiceUnavailable, "mihomo_lab_unavailable", false)
		return
	}
	chunked := len(r.TransferEncoding) == 1 && r.TransferEncoding[0] == "chunked" && r.ContentLength == -1
	write := method == http.MethodPost
	if (len(r.TransferEncoding) != 0 && (!write || !chunked)) || len(r.Header.Values("Content-Encoding")) != 0 {
		mihomoLabError(w, http.StatusBadRequest, "mihomo_lab_invalid", false)
		return
	}
	authorization := append([]string(nil), values...)
	if !write {
		if r.ContentLength != 0 || (r.Body != nil && r.Body != http.NoBody) {
			mihomoLabError(w, http.StatusBadRequest, "mihomo_lab_invalid", false)
			return
		}
		v, err := s.options.MihomoRecoveries.Inspect(r.Context(), authorization, id)
		if err != nil {
			mihomoLabBackendError(w, err, false)
			return
		}
		if !validMihomoRecoveryView(v, id) {
			mihomoLabError(w, http.StatusServiceUnavailable, "mihomo_lab_unavailable", false)
			return
		}
		writeMihomoLab(w, http.StatusOK, "mihomo_lab_ok", false, v)
		return
	}
	object, ok := readMihomoLabObject(w, r)
	if !ok {
		return
	}
	var v mihomodeploy.LabRecoveryView
	var err error
	expectedHash := ""
	if action == "create" {
		if !exactMihomoLabKeys(object, "unknownOperationId", "originalPlanSHA256", "revision", "ttlSeconds") {
			mihomoLabError(w, http.StatusBadRequest, "mihomo_lab_invalid", false)
			return
		}
		unknownID, idOK := object["unknownOperationId"].(string)
		plan, planOK := object["originalPlanSHA256"].(string)
		revision, revisionOK := mihomoLabNumber(object["revision"])
		ttl, ttlOK := mihomoLabNumber(object["ttlSeconds"])
		if !idOK || !mihomoLabID.MatchString(unknownID) || !planOK || !validMihomoLabHash(plan) || !revisionOK || revision == 0 || !ttlOK || ttl < 1 || ttl > 300 {
			mihomoLabError(w, http.StatusBadRequest, "mihomo_lab_invalid", false)
			return
		}
		expectedHash = plan
		v, err = s.options.MihomoRecoveries.Create(r.Context(), authorization, mihomodeploy.LabRecoveryCreateRequest{
			UnknownOperationID: unknownID, OriginalPlanSHA256: plan, Revision: revision, TTLSeconds: uint16(ttl)})
	} else {
		keys := []string{"planSHA256", "revision"}
		if action == "revoke" {
			keys = append(keys, "reason")
		}
		if !exactMihomoLabKeys(object, keys...) {
			mihomoLabError(w, http.StatusBadRequest, "mihomo_lab_invalid", false)
			return
		}
		plan, planOK := object["planSHA256"].(string)
		revision, revisionOK := mihomoLabNumber(object["revision"])
		if !planOK || !validMihomoLabHash(plan) || !revisionOK || revision == 0 {
			mihomoLabError(w, http.StatusBadRequest, "mihomo_lab_invalid", false)
			return
		}
		expectedHash = plan
		switch action {
		case "approve":
			v, err = s.options.MihomoRecoveries.Approve(r.Context(), authorization, id, mihomodeploy.LabRecoveryApprovalRequest{PlanSHA256: plan, Revision: revision})
		case "execute":
			v, err = s.options.MihomoRecoveries.Execute(r.Context(), authorization, id, mihomodeploy.LabRecoveryExecuteRequest{PlanSHA256: plan, Revision: revision})
		case "revoke":
			reason, reasonOK := object["reason"].(string)
			if !reasonOK || (reason != "OPERATOR_REQUESTED" && reason != "SAFETY_STOP") {
				mihomoLabError(w, http.StatusBadRequest, "mihomo_lab_invalid", false)
				return
			}
			v, err = s.options.MihomoRecoveries.Revoke(r.Context(), authorization, id, mihomodeploy.LabRecoveryRevokeRequest{PlanSHA256: plan, Revision: revision, Reason: reason})
		}
	}
	if err != nil {
		mihomoLabBackendError(w, err, true)
		return
	}
	if !validMihomoRecoveryView(v, v.RecoveryID) || (id != "" && v.RecoveryID != id) || (action != "create" && v.PlanSHA256 != expectedHash) ||
		(action == "create" && v.OriginalPlanSHA256 != expectedHash) {
		mihomoLabError(w, http.StatusServiceUnavailable, "mihomo_lab_unavailable", true)
		return
	}
	status := http.StatusOK
	if action == "create" {
		status = http.StatusCreated
	}
	// A successful POST has durably created/approved/revoked a recovery or has
	// crossed the physical Execute boundary. Replayed success is still a prior
	// mutation acknowledgement, never a read-only response.
	writeMihomoLab(w, status, "mihomo_lab_ok", true, v)
}
