package api

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"chengwang/internal/overview"
)

func overviewContextError(w http.ResponseWriter, err error) bool {
	if errors.Is(err, context.DeadlineExceeded) {
		writeError(w, http.StatusGatewayTimeout, "overview_deadline", "实际证据汇总已超过读取预算")
		return true
	}
	if errors.Is(err, context.Canceled) {
		writeError(w, http.StatusRequestTimeout, "overview_canceled", "实际证据汇总读取已取消")
		return true
	}
	return false
}

func (s *server) overview(w http.ResponseWriter, r *http.Request) {
	if r.URL.Path != "/api/v1/overview" || r.URL.EscapedPath() != "/api/v1/overview" {
		writeError(w, http.StatusNotFound, "overview_path_invalid", "实际证据汇总路径无效")
		return
	}
	if r.Method != http.MethodGet {
		w.Header().Set("Allow", http.MethodGet)
		writeError(w, http.StatusMethodNotAllowed, "method_not_allowed", "只允许只读 GET 请求")
		return
	}
	if r.URL.RawQuery != "" || r.URL.ForceQuery || r.ContentLength != 0 ||
		(r.Body != nil && r.Body != http.NoBody) || len(r.TransferEncoding) != 0 || len(r.Header.Values("Content-Encoding")) != 0 {
		writeError(w, http.StatusBadRequest, "invalid_overview_request", "实际证据汇总不接受查询参数、请求正文或内容编码")
		return
	}
	if nilSubscriptionInterface(s.options.Overview) {
		writeError(w, http.StatusServiceUnavailable, "overview_not_configured", "实际证据汇总尚未启用")
		return
	}
	// Existing Status getters cannot be interrupted while holding their own
	// locks. This budget is cooperative; no abandoned goroutine is created.
	ctx, cancel := context.WithTimeout(r.Context(), 500*time.Millisecond)
	defer cancel()
	if overviewContextError(w, ctx.Err()) { return }
	value, err := s.options.Overview.Snapshot(ctx)
	if overviewContextError(w, ctx.Err()) || overviewContextError(w, err) { return }
	if err != nil || overview.Validate(value) != nil {
		writeError(w, http.StatusServiceUnavailable, "overview_projection_invalid", "实际证据汇总安全投影无效")
		return
	}
	raw, err := json.Marshal(value)
	if err != nil || len(raw)+1 > 64<<10 {
		writeError(w, http.StatusServiceUnavailable, "overview_projection_invalid", "实际证据汇总安全投影无效")
		return
	}
	if overviewContextError(w, ctx.Err()) { return }
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(append(raw, '\n'))
}
