// Package dockerreadonlyproxy exposes one purpose-built, secret-free runtime
// snapshot endpoint. It is not a generic Docker API proxy.
package dockerreadonlyproxy

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"regexp"
	"strings"
	"time"

	"chengwang/internal/runtimewire"
)

const SnapshotPathPrefix = "/v1/runtime-snapshot/"

var projectPattern = regexp.MustCompile(`^chengwang-m2b-probe-[a-z0-9][a-z0-9_-]{0,19}-[0-9a-f]{12}-candidate$`)

var ErrUnavailable = errors.New("runtime snapshot unavailable")

type Collector interface {
	Snapshot(context.Context, string) (runtimewire.Snapshot, error)
}

type Server struct{ collector Collector }

func NewServer(collector Collector) (*Server, error) {
	if collector == nil {
		return nil, ErrUnavailable
	}
	return &Server{collector: collector}, nil
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	writer.Header().Set("Cache-Control", "no-store")
	writer.Header().Set("Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'")
	writer.Header().Set("X-Content-Type-Options", "nosniff")
	if request.Method != http.MethodGet || request.Body == nil || request.ContentLength > 0 || request.URL.RawQuery != "" || request.URL.Fragment != "" {
		http.Error(writer, "request rejected", http.StatusMethodNotAllowed)
		return
	}
	project, ok := snapshotProject(request.URL.EscapedPath())
	if !ok {
		http.NotFound(writer, request)
		return
	}
	context, cancel := context.WithTimeout(request.Context(), 4*time.Second)
	defer cancel()
	snapshot, err := s.collector.Snapshot(context, project)
	if err != nil {
		http.Error(writer, "runtime snapshot unavailable", http.StatusServiceUnavailable)
		return
	}
	writer.Header().Set("Content-Type", "application/json")
	encoder := json.NewEncoder(writer)
	encoder.SetEscapeHTML(true)
	if err := encoder.Encode(snapshot); err != nil {
		return
	}
}

func snapshotProject(escapedPath string) (string, bool) {
	if !strings.HasPrefix(escapedPath, SnapshotPathPrefix) || !strings.HasSuffix(escapedPath, "/probe-agent") {
		return "", false
	}
	project := strings.TrimSuffix(strings.TrimPrefix(escapedPath, SnapshotPathPrefix), "/probe-agent")
	if strings.Contains(project, "/") || !projectPattern.MatchString(project) {
		return "", false
	}
	return project, true
}
