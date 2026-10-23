package api

import (
	"encoding/json"
	"net/http"

	"chengwang/internal/authz"
	"chengwang/internal/probeview"
)

// ProbeReader is cache-only. HTTP cannot trigger a scan, schedule a probe,
// change a catalog, or turn an advisory observation into an action.
type ProbeReader interface {
	Status() probeview.Status
	Details() probeview.Details
}

func probeRequest(w http.ResponseWriter, r *http.Request) bool {
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "只允许只读 GET 请求")
		return false
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery {
		writeError(w, http.StatusBadRequest, "invalid_probe_query", "探针读回不接受查询参数")
		return false
	}
	return true
}

func (s *server) probeStatus(w http.ResponseWriter, r *http.Request) {
	if !probeRequest(w, r) {
		return
	}
	status := probeview.DisabledStatus()
	if s.options.Probes != nil {
		status = s.options.Probes.Status()
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *server) probeDetails(w http.ResponseWriter, r *http.Request) {
	// Authorization is evaluated even when probe readback is disabled. Neither
	// a missing component nor a malformed query bypasses management admission.
	if _, ok := s.managementPreflight(w, r, authz.ActionReadResource); !ok {
		return
	}
	if !probeRequest(w, r) {
		return
	}
	if s.options.Probes == nil {
		writeError(w, http.StatusServiceUnavailable, "probe_not_configured", "主动探针读回尚未配置")
		return
	}
	detail := s.options.Probes.Details()
	if len(detail.Targets) > 256 || len(detail.Samples) > 200 {
		writeError(w, http.StatusServiceUnavailable, "probe_projection_invalid", "探针读回安全投影无效")
		return
	}
	// Encode before sending headers: a malformed time or an oversized DTO must
	// not produce a partially successful response or reveal an encoder error.
	raw, err := json.Marshal(detail)
	if err != nil || len(raw)+1 > 1<<20 {
		writeError(w, http.StatusServiceUnavailable, "probe_projection_invalid", "探针读回安全投影无效")
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}
