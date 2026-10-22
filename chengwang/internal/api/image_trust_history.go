package api

import (
	"net/http"
	"strconv"
	"strings"

	"chengwang/internal/authz"
	"chengwang/internal/imagetrust"
)

func (s *server) imageTrustHistory(w http.ResponseWriter, r *http.Request) {
	principal, ok := s.imageTrustPreflight(w, r, authz.ActionHistoryImageTrust, false)
	if !ok {
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeImageTrustError(w, http.StatusMethodNotAllowed, imagetrust.CodeInvalid, false)
		return
	}
	if r.ContentLength != 0 || len(r.TransferEncoding) != 0 || len(r.Header.Values("Content-Encoding")) != 0 {
		writeImageTrustError(w, http.StatusBadRequest, imagetrust.CodeInvalid, false)
		return
	}
	query, ok := parseImageTrustHistoryQuery(r.URL.RawQuery, r.URL.ForceQuery)
	if !ok {
		writeImageTrustError(w, http.StatusBadRequest, imagetrust.CodeInvalid, false)
		return
	}
	backend, ok := s.options.ImageTrust.(imagetrust.HistoryBackend)
	if !ok {
		writeImageTrustError(w, http.StatusServiceUnavailable, imagetrust.CodeUnavailable, false)
		return
	}
	history, err := backend.History(r.Context(), principal, query)
	if err != nil {
		writeImageTrustBackendError(w, err, false)
		return
	}
	history.Boundary, history.Authorization, history.DeviceActionsExecuted = imagetrust.HistoryBoundary, "BLOCKED", false
	writeJSON(w, http.StatusOK, history)
}

func parseImageTrustHistoryQuery(raw string, force bool) (imagetrust.HistoryRequest, bool) {
	query := imagetrust.HistoryRequest{Limit: 20}
	if raw == "" {
		return query, !force
	}
	if len(raw) > 128 {
		return imagetrust.HistoryRequest{}, false
	}
	seen := map[string]bool{}
	for _, part := range strings.Split(raw, "&") {
		key, value, ok := strings.Cut(part, "=")
		if !ok || seen[key] || value == "" {
			return imagetrust.HistoryRequest{}, false
		}
		seen[key] = true
		n, err := strconv.ParseUint(value, 10, 64)
		if err != nil || strconv.FormatUint(n, 10) != value {
			return imagetrust.HistoryRequest{}, false
		}
		switch key {
		case "limit":
			if n < 1 || n > 50 {
				return imagetrust.HistoryRequest{}, false
			}
			query.Limit = int(n)
		case "offset":
			if n > 4096 {
				return imagetrust.HistoryRequest{}, false
			}
			query.Offset = int(n)
		case "sequence":
			query.Sequence = n
		default:
			return imagetrust.HistoryRequest{}, false
		}
	}
	return query, true
}
