package mihomodeploy

// Source-owned loopback-only diagnostic services adapted from the actual local
// apply experiment. These are runtime helpers, not a general proxy/relay.
import (
 "bufio"
 "bytes"
 "context"
 "errors"
 "io"
 "net"
 "net/http"
 "net/url"
 "strconv"
 "sync"
 "time"
)

const labLocalOrigin = "127.0.0.1:28415"
const labLocalMixed = "127.0.0.1:28411"
const labLocalRouteHeader = "X-Chengwang-Apply-Route"

func labLocalObserved(raw []byte) *labLocalBody {
 return &labLocalBody{SHA256:labConfigHash(raw),Bytes:len(raw),Complete:true}
}
type labLocalBody struct {
	SHA256   string `json:"sha256"`
	Bytes    int    `json:"bytes"`
	Complete bool   `json:"complete"`
}
type labLocalCounter struct {
	Role               string `json:"role"`
	ConnectIngress     int    `json:"connectIngress"`
	TunnelRequests     int    `json:"tunnelRequests"`
	ForwardInvocations int    `json:"forwardInvocations"`
	OriginRequests     int    `json:"originRequests"`
	Rejected           int    `json:"rejected"`
}
type labLocalRoute struct {
	Phase          string         `json:"phase"`
	NonceSHA256    string         `json:"nonceSHA256"`
	ClientResponse *labLocalBody     `json:"clientResponse"`
	ProxyResponse  *labLocalBody     `json:"proxyResponse"`
	OriginResponse *labLocalBody     `json:"originResponse"`
	CountersBefore []labLocalCounter `json:"countersBefore"`
	CountersAfter  []labLocalCounter `json:"countersAfter"`
	Matched        bool           `json:"matched"`
}
type labLocalFixtureCleanup struct {
	Role                    string `json:"role"`
	ShutdownReturned        bool   `json:"shutdownReturned"`
	ServeReturned           bool   `json:"serveReturned"`
	ForcedConnectionsClosed int    `json:"forcedConnectionsClosed"`
	ErrorClass              string `json:"errorClass"`
}
type labLocalOriginRecord struct{ proxy, origin *labLocalBody }
type labLocalFixture struct {
	mu          sync.Mutex
	markers     map[string]string
	expected    map[string]string
	consumed    map[string]bool
	finished    map[string]chan struct{}
	records     map[string]labLocalOriginRecord
	counters    map[string]labLocalCounter
	connections map[net.Conn]string
	servers     []*labLocalHTTPServer
	handlers    sync.WaitGroup
}
type labLocalHTTPServer struct {
	role   string
	server *http.Server
	done   chan struct{}
	err    error
}

func newLabLocalFixture(a, b string) *labLocalFixture {
	return &labLocalFixture{markers: map[string]string{"A": a, "B": b}, expected: map[string]string{}, consumed: map[string]bool{}, finished: map[string]chan struct{}{}, records: map[string]labLocalOriginRecord{}, counters: map[string]labLocalCounter{"A": {Role: "A"}, "B": {Role: "B"}, "origin": {Role: "origin"}}, connections: map[net.Conn]string{}}
}
func (f *labLocalFixture) add(role string, edit func(*labLocalCounter)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.counters[role]
	edit(&c)
	f.counters[role] = c
}
func (f *labLocalFixture) snapshot() []labLocalCounter {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []labLocalCounter{f.counters["A"], f.counters["B"], f.counters["origin"]}
}
func labLocalMarker(role, nonce string) []byte {
	return []byte("chengwang-local-service-marker/v1:" + role + ":" + nonce + "\n")
}
func (f *labLocalFixture) listen(role, address string, handler http.HandlerFunc) error {
	l, e := net.Listen("tcp4", address)
	if e != nil {
		return errLabKernelListeners
	}
	s := &labLocalHTTPServer{role: role, done: make(chan struct{})}
	s.server = &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8 << 10}
	f.servers = append(f.servers, s)
	go func() { s.err = s.server.Serve(l); close(s.done) }()
	return nil
}
func (f *labLocalFixture) start() error {
	if e := f.listen("origin", labLocalOrigin, f.origin); e != nil {
		return e
	}
	if e := f.listen("A", "127.0.0.1:28413", func(w http.ResponseWriter, r *http.Request) { f.proxy("A", w, r) }); e != nil {
		return e
	}
	return f.listen("B", "127.0.0.1:28414", func(w http.ResponseWriter, r *http.Request) { f.proxy("B", w, r) })
}
func (f *labLocalFixture) origin(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	f.mu.Lock()
	role, known := f.expected[nonce]
	marker := f.markers[role]
	f.mu.Unlock()
	if !known || r.Method != "GET" || r.Host != labLocalOrigin || r.URL.Path != "/marker" || r.URL.RawQuery != "nonce="+nonce || r.Header.Get(labLocalRouteHeader) != marker || marker == "" {
		f.add("origin", func(c *labLocalCounter) { c.Rejected++ })
		http.Error(w, "local marker rejected", 403)
		return
	}
	f.add(role, func(c *labLocalCounter) { c.OriginRequests++ })
	f.add("origin", func(c *labLocalCounter) { c.OriginRequests++ })
	body := labLocalMarker(role, nonce)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	n, e := w.Write(body)
	if e == nil && n == len(body) {
		f.mu.Lock()
		record := f.records[nonce]
		record.origin = labLocalObserved(body)
		f.records[nonce] = record
		f.mu.Unlock()
	}
}
func labLocalOriginTransport() *http.Transport {
	d := &net.Dialer{Timeout: time.Second}
	return &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != labLocalOrigin {
			return nil, errLabKernelInput
		}
		return d.DialContext(ctx, "tcp4", labLocalOrigin)
	}, DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: false, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 8 << 10}
}
func (f *labLocalFixture) proxy(role string, w http.ResponseWriter, r *http.Request) {
	f.handlers.Add(1)
	defer f.handlers.Done()
	// Fixed upstream http.go:94-117 sends CONNECT even for this plain HTTP
	// destination. No arbitrary host, DNS lookup or general TCP relay exists.
	if r.Method != "CONNECT" || r.Host != labLocalOrigin || r.RequestURI != labLocalOrigin || r.URL.Host != labLocalOrigin || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		f.add(role, func(c *labLocalCounter) { c.Rejected++ })
		http.Error(w, "fixed connect target rejected", 403)
		return
	}
	f.add(role, func(c *labLocalCounter) { c.ConnectIngress++ })
	h, ok := w.(http.Hijacker)
	if !ok {
		f.add(role, func(c *labLocalCounter) { c.Rejected++ })
		http.Error(w, "connect unavailable", 500)
		return
	}
	conn, rw, e := h.Hijack()
	if e != nil {
		f.add(role, func(c *labLocalCounter) { c.Rejected++ })
		return
	}
	f.mu.Lock()
	f.connections[conn] = role
	f.mu.Unlock()
	defer func() { _ = conn.Close(); f.mu.Lock(); delete(f.connections, conn); f.mu.Unlock() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil || rw.Flush() != nil {
		f.add(role, func(c *labLocalCounter) { c.Rejected++ })
		return
	}
	inside, e := http.ReadRequest(bufio.NewReader(io.LimitReader(rw.Reader, 8<<10)))
	if e != nil {
		f.add(role, func(c *labLocalCounter) { c.Rejected++ })
		return
	}
	defer inside.Body.Close()
	nonce := inside.URL.Query().Get("nonce")
	f.mu.Lock()
	expected := f.expected[nonce]
	marker := f.markers[role]
	f.mu.Unlock()
	if inside.Method != "GET" || inside.Host != labLocalOrigin || inside.URL.Path != "/marker" || inside.URL.RawQuery != "nonce="+nonce || !lifecycleNonzeroHash(nonce) || expected != role || inside.ContentLength > 0 || len(inside.TransferEncoding) != 0 || (inside.URL.Host != "" && inside.URL.Host != labLocalOrigin) {
		f.add(role, func(c *labLocalCounter) { c.Rejected++ })
		return
	}
	f.mu.Lock()
	used := f.consumed[nonce]
	done := f.finished[nonce]
	if !used && done != nil {
		f.consumed[nonce] = true
	}
	f.mu.Unlock()
	if used || done == nil {
		f.add(role, func(c *labLocalCounter) { c.Rejected++ })
		return
	}
	defer close(done)
	f.add(role, func(c *labLocalCounter) { c.TunnelRequests++ })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, "GET", "http://"+labLocalOrigin+"/marker?nonce="+nonce, nil)
	if e != nil {
		return
	}
	request.Close = true
	request.Header.Set(labLocalRouteHeader, marker)
	transport := labLocalOriginTransport()
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f.add(role, func(c *labLocalCounter) { c.ForwardInvocations++ })
	response, e := client.Do(request)
	if e != nil {
		f.add(role, func(c *labLocalCounter) { c.Rejected++ })
		return
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 4097))
	if e != nil || response.StatusCode != 200 || len(body) > 4096 || !bytes.Equal(body, labLocalMarker(role, nonce)) {
		f.add(role, func(c *labLocalCounter) { c.Rejected++ })
		return
	}
	f.mu.Lock()
	record := f.records[nonce]
	record.proxy = labLocalObserved(body)
	f.records[nonce] = record
	f.mu.Unlock()
	// Forward actual bytes read from the real origin, not a locally fabricated
	// proxy response. Strip all inbound/client headers before the origin call.
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Close = true
	response.TransferEncoding = nil
	if response.Write(conn) != nil {
		f.add(role, func(c *labLocalCounter) { c.Rejected++ })
	}
}
func (f *labLocalFixture) route(ctx context.Context, phase, role string) labLocalRoute {
	nonce, e := labServiceRandom()
	result := labLocalRoute{Phase: phase, CountersBefore: f.snapshot()}
	if e != nil {
		return result
	}
	result.NonceSHA256 = labConfigHash([]byte(nonce))
	done := make(chan struct{})
	f.mu.Lock()
	f.expected[nonce] = role
	f.finished[nonce] = done
	f.mu.Unlock()
	proxyURL, _ := url.Parse("http://" + labLocalMixed)
	dialer := &net.Dialer{Timeout: time.Second}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != labLocalMixed {
			return nil, errLabKernelInput
		}
		return dialer.DialContext(ctx, "tcp4", labLocalMixed)
	}, DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 8 << 10, ResponseHeaderTimeout: 2 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "GET", "http://"+labLocalOrigin+"/marker?nonce="+nonce, nil)
	if e == nil {
		req.Close = true
		response, re := client.Do(req)
		if re == nil {
			raw, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
			closeErr := response.Body.Close()
			if readErr == nil && closeErr == nil && response.StatusCode == 200 && len(raw) <= 4096 {
				result.ClientResponse = labLocalObserved(raw)
			}
		}
	}
	completed := false
	if result.ClientResponse != nil {
		select {
		case <-done:
			completed = true
		case <-time.After(500 * time.Millisecond):
		case <-ctx.Done():
		}
	}
	f.mu.Lock()
	record := f.records[nonce]
	result.ProxyResponse = record.proxy
	result.OriginResponse = record.origin
	f.mu.Unlock()
	result.CountersAfter = f.snapshot()
	matched := completed && result.ClientResponse != nil && result.ProxyResponse != nil && result.OriginResponse != nil && *result.ClientResponse == *result.ProxyResponse && *result.ClientResponse == *result.OriginResponse && result.ClientResponse.SHA256 == labConfigHash(labLocalMarker(role, nonce))
	for i, before := range result.CountersBefore {
		after := result.CountersAfter[i]
		if after.Rejected != before.Rejected {
			matched = false
		}
		if before.Role == role {
			matched = matched && after.ConnectIngress-before.ConnectIngress == 1 && after.TunnelRequests-before.TunnelRequests == 1 && after.ForwardInvocations-before.ForwardInvocations == 1 && after.OriginRequests-before.OriginRequests == 1
		} else if before.Role == "origin" {
			matched = matched && after.OriginRequests-before.OriginRequests == 1
		} else {
			matched = matched && after == before
		}
	}
	result.Matched = matched
	return result
}
func (f *labLocalFixture) stop() []labLocalFixtureCleanup {
	out := make([]labLocalFixtureCleanup, 0, len(f.servers))
	for _, s := range f.servers {
		v := labLocalFixtureCleanup{Role: s.role, ErrorClass: "NONE"}
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		e := s.server.Shutdown(ctx)
		cancel()
		v.ShutdownReturned = true
		f.mu.Lock()
		for conn, role := range f.connections {
			if role == s.role {
				if conn.Close() == nil {
					v.ForcedConnectionsClosed++
				}
			}
		}
		f.mu.Unlock()
		if e != nil {
			_ = s.server.Close()
			v.ErrorClass = "SHUTDOWN"
		}
		select {
		case <-s.done:
			v.ServeReturned = true
			if !errors.Is(s.err, http.ErrServerClosed) {
				v.ErrorClass = "SERVE"
			}
		case <-time.After(time.Second):
			v.ErrorClass = "SERVE_TIMEOUT"
		}
		out = append(out, v)
	}
	waited := make(chan struct{})
	go func() { f.handlers.Wait(); close(waited) }()
	select {
	case <-waited:
	case <-time.After(time.Second):
		for i := range out {
			out[i].ErrorClass = "HANDLER_TIMEOUT"
		}
	}
	return out
}
