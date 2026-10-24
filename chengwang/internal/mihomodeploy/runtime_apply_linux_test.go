//go:build linux && chengwang_mihomo_apply

package mihomodeploy

import (
	"bufio"
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"chengwang/internal/adapter/mihomo"
	"chengwang/internal/domain"
)

// Real fixed-kernel experiment, not a MODEL, product API, approval, head
// commit, internet business test, or production capability. Never Skip when
// the source-owned Linux worker envelope is missing: this tag must fail.
const applyPrivateOutput = "/tmp/mihomo-apply-private"
const applyScope = "ACTUAL_FIXED_KERNEL_LOCAL_APPLY_EXPERIMENT_NOT_API_AUTHORIZATION_HEAD_OR_PRODUCTION"
const applyOrigin = "127.0.0.1:28415"
const applyController = "http://127.0.0.1:28412"
const applyMixed = "127.0.0.1:28411"
const applyRouteHeader = "X-Chengwang-Apply-Route"

type applyBinding struct {
	SHA256 string `json:"sha256"`
	Bytes  int    `json:"bytes"`
}
type applyBody struct {
	SHA256   string `json:"sha256"`
	Bytes    int    `json:"bytes"`
	Complete bool   `json:"complete"`
}
type applyProbe struct {
	Role       string     `json:"role"`
	StatusCode *int       `json:"statusCode"`
	Body       *applyBody `json:"body"`
	ErrorClass string     `json:"errorClass"`
}
type applyCounter struct {
	Role               string `json:"role"`
	ConnectIngress     int    `json:"connectIngress"`
	TunnelRequests     int    `json:"tunnelRequests"`
	ForwardInvocations int    `json:"forwardInvocations"`
	OriginRequests     int    `json:"originRequests"`
	Rejected           int    `json:"rejected"`
}
type applyRoute struct {
	Phase          string         `json:"phase"`
	NonceSHA256    string         `json:"nonceSHA256"`
	ClientResponse *applyBody     `json:"clientResponse"`
	ProxyResponse  *applyBody     `json:"proxyResponse"`
	OriginResponse *applyBody     `json:"originResponse"`
	CountersBefore []applyCounter `json:"countersBefore"`
	CountersAfter  []applyCounter `json:"countersAfter"`
	Matched        bool           `json:"matched"`
}
type applyFixtureCleanup struct {
	Role                    string `json:"role"`
	ShutdownReturned        bool   `json:"shutdownReturned"`
	ServeReturned           bool   `json:"serveReturned"`
	ForcedConnectionsClosed int    `json:"forcedConnectionsClosed"`
	ErrorClass              string `json:"errorClass"`
}
type applyFlags struct {
	API         bool `json:"apiExercised"`
	Auth        bool `json:"authorizationExercised"`
	AuthProven  bool `json:"authorizationProven"`
	Full        bool `json:"fullPayloadProven"`
	Head        bool `json:"headAdvanced"`
	Production  bool `json:"production"`
	PerGET      bool `json:"perGetRawEvidenceAvailable"`
	Independent bool `json:"independentProjectionRecomputeProven"`
	Internet    bool `json:"internetBusinessProven"`
}
type applyReport struct {
	Schema            string                     `json:"schema"`
	Scope             string                     `json:"scope"`
	SourceCommit      string                     `json:"sourceCommit"`
	Outcome           string                     `json:"outcome"`
	FailureCode       *string                    `json:"failureCode"`
	BaseInput         *applyBinding              `json:"baseInput"`
	CandidateInput    *applyBinding              `json:"candidateInput"`
	SyntaxSHA256      *string                    `json:"syntaxSHA256"`
	KernelObservation *labKernelStartObservation `json:"kernelObservation"`
	OwnedBefore       *labKernelIdentity         `json:"ownedBefore"`
	OwnedAfter        *labKernelIdentity         `json:"ownedAfter"`
	Readbacks         struct {
		Baseline  *mihomo.LabReadbackReport `json:"baseline"`
		Candidate *mihomo.LabReadbackReport `json:"candidate"`
	} `json:"readbacks"`
	GetEvidence       struct {
		Baseline  *applyBinding `json:"baseline"`
		Candidate *applyBinding `json:"candidate"`
	} `json:"getEvidence"`
	Readiness               []applyProbe          `json:"readiness"`
	ClientReloadInvocations int                   `json:"clientReloadInvocations"`
	ControllerReceivedCount *int                  `json:"controllerReceivedCount"`
	ReloadPayload           *applyBinding         `json:"reloadPayload"`
	ReloadResult            *mihomo.ReloadResult  `json:"reloadResult"`
	ReloadErrorClass        *string               `json:"reloadErrorClass"`
	Routes                  []applyRoute          `json:"routes"`
	FixtureCleanup          []applyFixtureCleanup `json:"fixtureCleanup"`
	Flags                   applyFlags            `json:"flags"`
}
type applyFacts struct {
	Code                    *string                    `json:"code"`
	BaseInput               *applyBinding              `json:"baseInput"`
	CandidateInput          *applyBinding              `json:"candidateInput"`
	ReceiptSHA256           *string                    `json:"receiptSHA256"`
	KernelObservation       *labKernelStartObservation `json:"kernelObservation"`
	OwnedIdentity           *labKernelIdentity         `json:"ownedIdentity"`
	ReadinessProbe          *applyProbe                `json:"readinessProbe"`
	Readback                *mihomo.LabReadbackReport  `json:"readback"`
	GetEvidence             *applyBinding              `json:"getEvidence"`
	ReloadPayload           *applyBinding              `json:"reloadPayload"`
	ReloadResult            *mihomo.ReloadResult       `json:"reloadResult"`
	ClientReloadInvocations *int                       `json:"clientReloadInvocations"`
	Route                   *applyRoute                `json:"route"`
	FixtureCleanup          []applyFixtureCleanup      `json:"fixtureCleanup"`
}
type applySyntax struct {
	Schema        string                    `json:"schema"`
	SourceCommit  string                    `json:"sourceCommit"`
	Binary        applyBinding              `json:"binary"`
	ReceiptSHA256 string                    `json:"receiptSHA256"`
	Input         applyBinding              `json:"input"`
	ArgvClass     string                    `json:"argvClass"`
	Observation   labKernelStartObservation `json:"observation"`
}

type applyOutput struct {
	directory *os.File
	identity  syscall.Stat_t
	journal   *os.File
	seq       int
}

func applyOpenOutput() (*applyOutput, error) {
	if os.Getuid() != 10001 || os.Getgid() != 10001 || !labKernelPlain(applyPrivateOutput) {
		return nil, errLabKernelInput
	}
	fd, e := syscall.Open(applyPrivateOutput, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0)
	if e != nil {
		return nil, errLabKernelInput
	}
	d := os.NewFile(uintptr(fd), applyPrivateOutput)
	var st syscall.Stat_t
	if syscall.Fstat(fd, &st) != nil || st.Mode&07777 != 0700 || st.Uid != 10001 || st.Gid != 10001 {
		_ = d.Close()
		return nil, errLabKernelInput
	}
	names, e := d.Readdirnames(-1)
	if e != nil || len(names) != 0 {
		_ = d.Close()
		return nil, errLabKernelInput
	}
	o := &applyOutput{directory: d, identity: st}
	j, e := o.create("apply-observations.jsonl")
	if e != nil {
		_ = d.Close()
		return nil, e
	}
	o.journal = j
	return o, nil
}
func (o *applyOutput) create(name string) (*os.File, error) {
	allowed := map[string]bool{"apply-observations.jsonl": true, "apply-report.json": true, "kernel.stdout": true, "kernel.stderr": true, "syntax.exec.json": true, "syntax.stdout": true, "syntax.stderr": true, ".secrets.private.json": true, "base.config.private.yaml": true, "candidate.config.private.yaml": true}
	for _, phase := range []string{"baseline", "candidate"} {
		allowed[phase+"-get-evidence.json"] = true
		for ordinal := 1; ordinal <= 8; ordinal++ {
			allowed[phase+"-get-0"+strconv.Itoa(ordinal)+".body"] = true
		}
	}
	if o == nil || o.directory == nil || !allowed[name] {
		return nil, errLabKernelInput
	}
	var st, named syscall.Stat_t
	if syscall.Fstat(int(o.directory.Fd()), &st) != nil || syscall.Lstat(applyPrivateOutput, &named) != nil || st.Dev != o.identity.Dev || st.Ino != o.identity.Ino || st.Mode != o.identity.Mode || st.Uid != o.identity.Uid || st.Gid != o.identity.Gid || named.Dev != st.Dev || named.Ino != st.Ino {
		return nil, errLabKernelInput
	}
	fd, e := syscall.Openat(int(o.directory.Fd()), name, syscall.O_WRONLY|syscall.O_CREAT|syscall.O_EXCL|syscall.O_NOFOLLOW|syscall.O_CLOEXEC, 0600)
	if e != nil {
		return nil, errLabKernelInput
	}
	f := os.NewFile(uintptr(fd), name)
	if syscall.Fstat(fd, &st) != nil || st.Mode&syscall.S_IFMT != syscall.S_IFREG || st.Mode&07777 != 0600 || st.Nlink != 1 || st.Uid != 10001 || st.Gid != 10001 {
		_ = f.Close()
		return nil, errLabKernelInput
	}
	return f, nil
}
func (o *applyOutput) write(name string, raw []byte) error {
	f, e := o.create(name)
	if e != nil {
		return e
	}
	n, e := f.Write(raw)
	syncErr := f.Sync()
	closeErr := f.Close()
	if e != nil || n != len(raw) || syncErr != nil || closeErr != nil || o.directory.Sync() != nil {
		return errLabKernelInput
	}
	return nil
}
func applyJSON(v any) ([]byte, error) {
	b, e := json.Marshal(v)
	if e != nil {
		return nil, errLabKernelInput
	}
	return append(b, '\n'), nil
}
func (o *applyOutput) event(stage string, facts applyFacts) error {
	if o == nil || o.journal == nil || o.seq >= 128 {
		return errLabKernelInput
	}
	o.seq++
	row := struct {
		Schema   string     `json:"schema"`
		Seq      int        `json:"seq"`
		Stage    string     `json:"stage"`
		Observed string     `json:"observedAtUTC"`
		Facts    applyFacts `json:"facts"`
	}{"chengwang.mihomo-apply-observation/v1", o.seq, stage, time.Now().UTC().Format(time.RFC3339Nano), facts}
	raw, e := applyJSON(row)
	if e != nil {
		return e
	}
	n, e := o.journal.Write(raw)
	if e != nil || n != len(raw) || o.journal.Sync() != nil {
		return errLabKernelInput
	}
	return nil
}
func applyRandom() (string, error) {
	var b [32]byte
	if _, e := rand.Read(b[:]); e != nil {
		return "", errLabKernelInput
	}
	return hex.EncodeToString(b[:]), nil
}
func applyBind(raw []byte) *applyBinding {
	return &applyBinding{SHA256: labConfigHash(raw), Bytes: len(raw)}
}
func applyObserved(raw []byte) *applyBody {
	return &applyBody{SHA256: labConfigHash(raw), Bytes: len(raw), Complete: true}
}

// Export the original entity-response evidence from the same eight GETs.
// The capture lease is released before the next phase. On failure only real
// available prefixes are staged; no unavailable body is replaced by empty bytes.
func (o *applyOutput) capture(phase string, evidence *mihomo.LabReadbackEvidence) (bound *applyBinding, failure error) {
	defer func() {
		if evidence.Release() != nil {
			failure = errLabKernelInput
		}
	}()
	if phase != "baseline" && phase != "candidate" {
		return nil, errLabKernelInput
	}
	descriptor, e := evidence.Descriptor()
	if e != nil {
		return nil, errLabKernelInput
	}
	transcript, e := evidence.PrivateTranscript()
	if e != nil || int64(len(transcript)) != descriptor.TranscriptBytes || labConfigHash(transcript) != descriptor.TranscriptSHA256 {
		return nil, errLabKernelInput
	}
	available := 0
	for ordinal := uint8(1); ordinal <= 8; ordinal++ {
		body, bodyErr := evidence.PrivateBody(ordinal)
		if bodyErr != nil {
			if descriptor.Outcome == "COMPLETE" {
				return nil, errLabKernelInput
			}
			continue
		}
		if body == nil || len(body) > (8<<20)+1 || o.write(phase+"-get-0"+strconv.Itoa(int(ordinal))+".body", body) != nil {
			return nil, errLabKernelInput
		}
		available++
	}
	if o.write(phase+"-get-evidence.json", transcript) != nil {
		return nil, errLabKernelInput
	}
	bound = applyBind(transcript)
	if descriptor.Outcome != "COMPLETE" || available != 8 || descriptor.SlotsEntered != 8 || descriptor.DoInvocations != 8 || descriptor.ResponsesObserved != 8 || descriptor.ReadAttempts != 8 || descriptor.CompletedBodies != 8 || descriptor.LimitReached {
		return bound, errLabKernelInput
	}
	return bound, nil
}

type applyOriginRecord struct{ proxy, origin *applyBody }
type applyFixture struct {
	mu          sync.Mutex
	markers     map[string]string
	expected    map[string]string
	consumed    map[string]bool
	finished    map[string]chan struct{}
	records     map[string]applyOriginRecord
	counters    map[string]applyCounter
	connections map[net.Conn]string
	servers     []*applyHTTPServer
	handlers    sync.WaitGroup
}
type applyHTTPServer struct {
	role   string
	server *http.Server
	done   chan struct{}
	err    error
}

func newApplyFixture(a, b string) *applyFixture {
	return &applyFixture{markers: map[string]string{"A": a, "B": b}, expected: map[string]string{}, consumed: map[string]bool{}, finished: map[string]chan struct{}{}, records: map[string]applyOriginRecord{}, counters: map[string]applyCounter{"A": {Role: "A"}, "B": {Role: "B"}, "origin": {Role: "origin"}}, connections: map[net.Conn]string{}}
}
func (f *applyFixture) add(role string, edit func(*applyCounter)) {
	f.mu.Lock()
	defer f.mu.Unlock()
	c := f.counters[role]
	edit(&c)
	f.counters[role] = c
}
func (f *applyFixture) snapshot() []applyCounter {
	f.mu.Lock()
	defer f.mu.Unlock()
	return []applyCounter{f.counters["A"], f.counters["B"], f.counters["origin"]}
}
func applyMarker(role, nonce string) []byte {
	return []byte("chengwang-local-apply-marker/v1:" + role + ":" + nonce + "\n")
}
func (f *applyFixture) listen(role, address string, handler http.HandlerFunc) error {
	l, e := net.Listen("tcp4", address)
	if e != nil {
		return errLabKernelListeners
	}
	s := &applyHTTPServer{role: role, done: make(chan struct{})}
	s.server = &http.Server{Handler: handler, ReadHeaderTimeout: time.Second, ReadTimeout: 3 * time.Second, WriteTimeout: 3 * time.Second, IdleTimeout: time.Second, MaxHeaderBytes: 8 << 10}
	f.servers = append(f.servers, s)
	go func() { s.err = s.server.Serve(l); close(s.done) }()
	return nil
}
func (f *applyFixture) start() error {
	if e := f.listen("origin", applyOrigin, f.origin); e != nil {
		return e
	}
	if e := f.listen("A", "127.0.0.1:28413", func(w http.ResponseWriter, r *http.Request) { f.proxy("A", w, r) }); e != nil {
		return e
	}
	return f.listen("B", "127.0.0.1:28414", func(w http.ResponseWriter, r *http.Request) { f.proxy("B", w, r) })
}
func (f *applyFixture) origin(w http.ResponseWriter, r *http.Request) {
	nonce := r.URL.Query().Get("nonce")
	f.mu.Lock()
	role, known := f.expected[nonce]
	marker := f.markers[role]
	f.mu.Unlock()
	if !known || r.Method != "GET" || r.Host != applyOrigin || r.URL.Path != "/marker" || r.URL.RawQuery != "nonce="+nonce || r.Header.Get(applyRouteHeader) != marker || marker == "" {
		f.add("origin", func(c *applyCounter) { c.Rejected++ })
		http.Error(w, "local marker rejected", 403)
		return
	}
	f.add(role, func(c *applyCounter) { c.OriginRequests++ })
	f.add("origin", func(c *applyCounter) { c.OriginRequests++ })
	body := applyMarker(role, nonce)
	w.Header().Set("Content-Type", "text/plain")
	w.Header().Set("Connection", "close")
	w.Header().Set("Content-Length", strconv.Itoa(len(body)))
	n, e := w.Write(body)
	if e == nil && n == len(body) {
		f.mu.Lock()
		record := f.records[nonce]
		record.origin = applyObserved(body)
		f.records[nonce] = record
		f.mu.Unlock()
	}
}
func applyOriginTransport() *http.Transport {
	d := &net.Dialer{Timeout: time.Second}
	return &http.Transport{Proxy: nil, DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != applyOrigin {
			return nil, errLabKernelInput
		}
		return d.DialContext(ctx, "tcp4", applyOrigin)
	}, DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: false, ResponseHeaderTimeout: time.Second, MaxResponseHeaderBytes: 8 << 10}
}
func (f *applyFixture) proxy(role string, w http.ResponseWriter, r *http.Request) {
	f.handlers.Add(1)
	defer f.handlers.Done()
	// Fixed upstream http.go:94-117 sends CONNECT even for this plain HTTP
	// destination. No arbitrary host, DNS lookup or general TCP relay exists.
	if r.Method != "CONNECT" || r.Host != applyOrigin || r.RequestURI != applyOrigin || r.URL.Host != applyOrigin || r.ContentLength > 0 || len(r.TransferEncoding) != 0 {
		f.add(role, func(c *applyCounter) { c.Rejected++ })
		http.Error(w, "fixed connect target rejected", 403)
		return
	}
	f.add(role, func(c *applyCounter) { c.ConnectIngress++ })
	h, ok := w.(http.Hijacker)
	if !ok {
		f.add(role, func(c *applyCounter) { c.Rejected++ })
		http.Error(w, "connect unavailable", 500)
		return
	}
	conn, rw, e := h.Hijack()
	if e != nil {
		f.add(role, func(c *applyCounter) { c.Rejected++ })
		return
	}
	f.mu.Lock()
	f.connections[conn] = role
	f.mu.Unlock()
	defer func() { _ = conn.Close(); f.mu.Lock(); delete(f.connections, conn); f.mu.Unlock() }()
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	if _, e = rw.WriteString("HTTP/1.1 200 Connection Established\r\n\r\n"); e != nil || rw.Flush() != nil {
		f.add(role, func(c *applyCounter) { c.Rejected++ })
		return
	}
	inside, e := http.ReadRequest(bufio.NewReader(io.LimitReader(rw.Reader, 8<<10)))
	if e != nil {
		f.add(role, func(c *applyCounter) { c.Rejected++ })
		return
	}
	defer inside.Body.Close()
	nonce := inside.URL.Query().Get("nonce")
	f.mu.Lock()
	expected := f.expected[nonce]
	marker := f.markers[role]
	f.mu.Unlock()
	if inside.Method != "GET" || inside.Host != applyOrigin || inside.URL.Path != "/marker" || inside.URL.RawQuery != "nonce="+nonce || !labKernelDigest.MatchString(nonce) || expected != role || inside.ContentLength > 0 || len(inside.TransferEncoding) != 0 || (inside.URL.Host != "" && inside.URL.Host != applyOrigin) {
		f.add(role, func(c *applyCounter) { c.Rejected++ })
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
		f.add(role, func(c *applyCounter) { c.Rejected++ })
		return
	}
	defer close(done)
	f.add(role, func(c *applyCounter) { c.TunnelRequests++ })
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	request, e := http.NewRequestWithContext(ctx, "GET", "http://"+applyOrigin+"/marker?nonce="+nonce, nil)
	if e != nil {
		return
	}
	request.Close = true
	request.Header.Set(applyRouteHeader, marker)
	transport := applyOriginTransport()
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	f.add(role, func(c *applyCounter) { c.ForwardInvocations++ })
	response, e := client.Do(request)
	if e != nil {
		f.add(role, func(c *applyCounter) { c.Rejected++ })
		return
	}
	defer response.Body.Close()
	body, e := io.ReadAll(io.LimitReader(response.Body, 4097))
	if e != nil || response.StatusCode != 200 || len(body) > 4096 || !bytes.Equal(body, applyMarker(role, nonce)) {
		f.add(role, func(c *applyCounter) { c.Rejected++ })
		return
	}
	f.mu.Lock()
	record := f.records[nonce]
	record.proxy = applyObserved(body)
	f.records[nonce] = record
	f.mu.Unlock()
	// Forward actual bytes read from the real origin, not a locally fabricated
	// proxy response. Strip all inbound/client headers before the origin call.
	response.Body = io.NopCloser(bytes.NewReader(body))
	response.ContentLength = int64(len(body))
	response.Close = true
	response.TransferEncoding = nil
	if response.Write(conn) != nil {
		f.add(role, func(c *applyCounter) { c.Rejected++ })
	}
}
func (f *applyFixture) route(ctx context.Context, phase, role string) applyRoute {
	nonce, e := applyRandom()
	result := applyRoute{Phase: phase, CountersBefore: f.snapshot()}
	if e != nil {
		return result
	}
	result.NonceSHA256 = labConfigHash([]byte(nonce))
	done := make(chan struct{})
	f.mu.Lock()
	f.expected[nonce] = role
	f.finished[nonce] = done
	f.mu.Unlock()
	proxyURL, _ := url.Parse("http://" + applyMixed)
	dialer := &net.Dialer{Timeout: time.Second}
	transport := &http.Transport{Proxy: http.ProxyURL(proxyURL), DialContext: func(ctx context.Context, network, address string) (net.Conn, error) {
		if address != applyMixed {
			return nil, errLabKernelInput
		}
		return dialer.DialContext(ctx, "tcp4", applyMixed)
	}, DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 8 << 10, ResponseHeaderTimeout: 2 * time.Second}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 3 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "GET", "http://"+applyOrigin+"/marker?nonce="+nonce, nil)
	if e == nil {
		req.Close = true
		response, re := client.Do(req)
		if re == nil {
			raw, readErr := io.ReadAll(io.LimitReader(response.Body, 4097))
			closeErr := response.Body.Close()
			if readErr == nil && closeErr == nil && response.StatusCode == 200 && len(raw) <= 4096 {
				result.ClientResponse = applyObserved(raw)
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
	matched := completed && result.ClientResponse != nil && result.ProxyResponse != nil && result.OriginResponse != nil && *result.ClientResponse == *result.ProxyResponse && *result.ClientResponse == *result.OriginResponse && result.ClientResponse.SHA256 == labConfigHash(applyMarker(role, nonce))
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
func (f *applyFixture) stop() []applyFixtureCleanup {
	out := make([]applyFixtureCleanup, 0, len(f.servers))
	for _, s := range f.servers {
		v := applyFixtureCleanup{Role: s.role, ErrorClass: "NONE"}
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

func applyVersion(raw []byte) bool {
	var v struct {
		Meta    *bool  `json:"meta"`
		Version string `json:"version"`
	}
	if _, e := labKernelExactKeys(raw, "meta", "version"); e != nil {
		return false
	}
	return labKernelJSON(raw, &v) == nil && v.Meta != nil && *v.Meta && v.Version == "v1.19.32"
}
func applyProbeVersion(ctx context.Context, role, secret string) applyProbe {
	result := applyProbe{Role: role, ErrorClass: "NETWORK"}
	d := &net.Dialer{Timeout: 250 * time.Millisecond}
	transport := &http.Transport{Proxy: nil, DialContext: d.DialContext, DisableKeepAlives: true, DisableCompression: true, ForceAttemptHTTP2: false, ResponseHeaderTimeout: 250 * time.Millisecond, MaxResponseHeaderBytes: 8 << 10}
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, Timeout: 250 * time.Millisecond, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	req, e := http.NewRequestWithContext(ctx, "GET", applyController+"/version", nil)
	if e != nil {
		return result
	}
	req.Close = true
	req.Header.Set("Accept", "application/json")
	req.Header.Set("Accept-Encoding", "identity")
	if role != "NONE" {
		req.Header.Set("Authorization", "Bearer "+secret)
	}
	response, e := client.Do(req)
	if e != nil {
		return result
	}
	defer response.Body.Close()
	status := response.StatusCode
	result.StatusCode = &status
	raw, e := io.ReadAll(io.LimitReader(response.Body, 4097))
	if e != nil || len(raw) > 4096 {
		result.ErrorClass = "BODY"
		return result
	}
	result.Body = applyObserved(raw)
	if role == "VALID" {
		if status != 200 || !applyVersion(raw) {
			result.ErrorClass = "NOT_READY"
			return result
		}
	} else if status != 401 {
		result.ErrorClass = "SHAPE"
		return result
	}
	result.ErrorClass = "NONE"
	return result
}

func applySyntaxCheck(ctx context.Context, in *labKernelInput, a *LabConfigArtifact, out *applyOutput) (*applySyntax, error) {
	raw := a.Bytes()
	record := &applySyntax{Schema: "chengwang.mihomo-apply-syntax-exec/v1", SourceCommit: in.commit, Binary: applyBinding{SHA256: in.binaryHash, Bytes: int(in.binaryBytes)}, ReceiptSHA256: in.receiptHash, Input: *applyBind(raw), ArgvClass: "STDIN_TEST", Observation: labKernelStartObservation{WaitErrorClass: "NOT_WAITED"}}
	if a.AdmissionError() != nil || in.verify() != nil {
		return record, errLabKernelInput
	}
	home, e := labKernelNewHome()
	if e != nil {
		return record, e
	}
	session, cancel := context.WithTimeout(ctx, 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(session, labKernelPath, "-t", "-d", home, "-f", "-")
	cmd.Dir = home
	cmd.Stdin = bytes.NewReader(raw)
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=" + home, "TMPDIR=" + filepath.Join(home, "tmp"), "LANG=C.UTF-8", "LC_ALL=C.UTF-8", "TZ=UTC"}
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true, Pdeathsig: syscall.SIGKILL}
	cmd.WaitDelay = time.Second
	var killed atomic.Bool
	cmd.Cancel = func() error {
		if cmd.Process == nil {
			return os.ErrProcessDone
		}
		e := cmd.Process.Kill()
		if e == nil {
			killed.Store(true)
		}
		return e
	}
	or, ow, e := os.Pipe()
	if e != nil {
		return record, errLabKernelStart
	}
	defer or.Close()
	er, ew, e := os.Pipe()
	if e != nil {
		_ = ow.Close()
		return record, errLabKernelStart
	}
	defer er.Close()
	stdout, stderr := &labKernelWriter{}, &labKernelWriter{}
	cmd.Stdout = ow
	cmd.Stderr = ew
	readers := make(chan struct{}, 2)
	for _, pair := range []struct {
		file   *os.File
		writer *labKernelWriter
	}{{or, stdout}, {er, stderr}} {
		go func(file *os.File, writer *labKernelWriter) {
			_, e := io.Copy(writer, file)
			writer.finish(e)
			readers <- struct{}{}
		}(pair.file, pair.writer)
	}
	runtime.LockOSThread()
	record.Observation.Attempted = true
	startErr := cmd.Start()
	_ = ow.Close()
	_ = ew.Close()
	started := startErr == nil
	record.Observation.Started = &started
	waited := false
	record.Observation.WaitReturned = &waited
	if started {
		pid := cmd.Process.Pid
		record.Observation.PID = &pid
		term := false
		record.Observation.TermSent = &term
		if stat, e := labKernelRead("/proc/"+strconv.Itoa(pid)+"/stat", 4096); e == nil {
			if ticks, _, e := labKernelProcStat(stat, pid); e == nil {
				record.Observation.StartTicks = &ticks
			}
		}
		waitErr := cmd.Wait()
		waited = true
		record.Observation.WaitErrorClass = "NONE"
		if waitErr != nil {
			var exited *exec.ExitError
			if errors.As(waitErr, &exited) {
				record.Observation.WaitErrorClass = "EXIT_STATUS"
			} else {
				record.Observation.WaitErrorClass = "WAIT_ERROR"
			}
		}
		if cmd.ProcessState != nil {
			if status, ok := cmd.ProcessState.Sys().(syscall.WaitStatus); ok {
				if status.Signaled() {
					signal := int(status.Signal())
					record.Observation.Signal = &signal
				} else {
					code := status.ExitStatus()
					record.Observation.ExitCode = &code
				}
			}
		}
		if e := syscall.Kill(-pid, 0); e == syscall.ESRCH {
			absent := true
			record.Observation.GroupAbsent = &absent
		} else if e == nil {
			absent := false
			record.Observation.GroupAbsent = &absent
		}
		killSent := killed.Load()
		record.Observation.KillSent = &killSent
	}
	runtime.UnlockOSThread()
	_ = or.SetReadDeadline(time.Now().Add(time.Second))
	_ = er.SetReadDeadline(time.Now().Add(time.Second))
	<-readers
	<-readers
	outRaw, outMeta := stdout.snapshot()
	errRaw, errMeta := stderr.snapshot()
	record.Observation.Stdout = &outMeta
	record.Observation.Stderr = &errMeta
	if out.write("syntax.stdout", outRaw) != nil || out.write("syntax.stderr", errRaw) != nil {
		return record, errLabKernelInput
	}
	if !started || !waited || record.Observation.ExitCode == nil || *record.Observation.ExitCode != 0 || record.Observation.Signal != nil || record.Observation.KillSent == nil || *record.Observation.KillSent || record.Observation.GroupAbsent == nil || !*record.Observation.GroupAbsent || record.Observation.WaitErrorClass != "NONE" || session.Err() != nil || !outMeta.Complete || !errMeta.Complete || outMeta.Truncated || errMeta.Truncated || len(errRaw) != 0 || !bytes.HasSuffix(outRaw, []byte("configuration file config.yaml test is successful\n")) || in.verify() != nil {
		return record, errLabKernelStart
	}
	return record, nil
}

type applyExperiment struct {
	out     *applyOutput
	report  applyReport
	input   *labKernelInput
	kernel  *ownedLabKernel
	fixture *applyFixture
}

func (x *applyExperiment) event(stage string, facts applyFacts) bool {
	return x.out.event(stage, facts) == nil
}
func (x *applyExperiment) run(ctx context.Context) string {
	in, e := openLabKernelInput()
	if e != nil {
		return "INPUT_REJECTED"
	}
	x.input = in
	x.report.SourceCommit = in.commit
	if !x.event("INPUT_OPENED", applyFacts{ReceiptSHA256: &in.receiptHash}) {
		return "EVIDENCE_IO"
	}
	controller, e := applyRandom()
	if e != nil {
		return "PRIVATE_ENTROPY"
	}
	aMarker, e := applyRandom()
	if e != nil {
		return "PRIVATE_ENTROPY"
	}
	bMarker, e := applyRandom()
	if e != nil || controller == aMarker || aMarker == bMarker || bMarker == controller {
		return "PRIVATE_ENTROPY"
	}
	secrets, e := applyJSON(struct {
		Schema     string `json:"schema"`
		Controller string `json:"controller"`
		A          string `json:"routeA"`
		B          string `json:"routeB"`
	}{"chengwang.mihomo-apply-private-secrets/v1", controller, aMarker, bMarker})
	if e != nil || x.out.write(".secrets.private.json", secrets) != nil {
		return "EVIDENCE_IO"
	}
	build := func(target string) (*LabConfigArtifact, error) {
		return BuildLabConfig(LabConfigSpec{MixedPort: 28411, ControllerPort: 28412, ControllerSecret: controller, DefaultTarget: target, HTTPNodes: []LabHTTPNode{{ID: "apply-a", Server: "127.0.0.1", Port: 28413}, {ID: "apply-b", Server: "127.0.0.1", Port: 28414}}, Draft: domain.PolicyDraft{Name: "controlled actual local apply " + target}})
	}
	base, e := build("apply-a")
	if e != nil || base.AdmissionError() != nil {
		return "BASE_ARTIFACT"
	}
	candidate, e := build("apply-b")
	if e != nil || candidate.AdmissionError() != nil {
		return "CANDIDATE_ARTIFACT"
	}
	baseRaw, candidateRaw := base.Bytes(), candidate.Bytes()
	x.report.BaseInput = applyBind(baseRaw)
	x.report.CandidateInput = applyBind(candidateRaw)
	if x.out.write("base.config.private.yaml", baseRaw) != nil || x.out.write("candidate.config.private.yaml", candidateRaw) != nil {
		return "EVIDENCE_IO"
	}
	oldExpected, e := labExpectationForArtifact(base)
	if e != nil {
		return "BASE_PROJECTION"
	}
	newExpected, e := labExpectationForArtifact(candidate)
	if e != nil {
		return "CANDIDATE_PROJECTION"
	}
	if !x.event("ARTIFACTS_BOUND", applyFacts{BaseInput: x.report.BaseInput, CandidateInput: x.report.CandidateInput}) {
		return "EVIDENCE_IO"
	}
	x.fixture = newApplyFixture(aMarker, bMarker)
	if x.fixture.start() != nil {
		return "FIXTURE_LISTEN"
	}
	if !x.event("FIXTURES_LISTENING", applyFacts{}) {
		return "EVIDENCE_IO"
	}
	if !x.event("KERNEL_START_BEGIN", applyFacts{BaseInput: x.report.BaseInput}) {
		return "EVIDENCE_IO"
	}
	x.kernel, e = startOwnedLabKernel(ctx, in, base)
	if e != nil {
		var observed *labKernelStartError
		if errors.As(e, &observed) {
			v := observed.observation()
			x.report.KernelObservation = &v
			if x.kernel == nil {
				x.kernel = observed.owned()
			}
		}
		_ = x.event("KERNEL_START_RESULT", applyFacts{KernelObservation: x.report.KernelObservation})
		return "KERNEL_START"
	}
	observed := x.kernel.startObservation()
	x.report.KernelObservation = &observed
	if !x.event("KERNEL_START_RESULT", applyFacts{KernelObservation: &observed}) {
		return "EVIDENCE_IO"
	}
	readyCtx, cancel := context.WithTimeout(ctx, 10*time.Second)
	ready := false
	for attempt := 0; attempt < 32; attempt++ {
		probe := applyProbeVersion(readyCtx, "VALID", controller)
		if probe.ErrorClass == "NONE" && x.kernel.verifyListeners() != nil {
			probe.ErrorClass = "NOT_READY"
		}
		x.report.Readiness = append(x.report.Readiness, probe)
		if !x.event("READINESS_PROBE", applyFacts{ReadinessProbe: &probe}) {
			cancel()
			return "EVIDENCE_IO"
		}
		if probe.ErrorClass == "NONE" {
			ready = true
			break
		}
		timer := time.NewTimer(50 * time.Millisecond)
		select {
		case <-timer.C:
		case <-readyCtx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
		}
		if readyCtx.Err() != nil {
			break
		}
	}
	cancel()
	if !ready {
		return "CONTROLLER_NOT_READY"
	}
	for _, role := range []string{"NONE", "WRONG"} {
		secret := ""
		if role == "WRONG" {
			secret = strings.Repeat("wrong_", 10)
		}
		probe := applyProbeVersion(ctx, role, secret)
		x.report.Readiness = append(x.report.Readiness, probe)
		if !x.event("READINESS_PROBE", applyFacts{ReadinessProbe: &probe}) {
			return "EVIDENCE_IO"
		}
		if probe.ErrorClass != "NONE" {
			return "CONTROLLER_AUTH"
		}
	}
	identity, e := x.kernel.identity()
	if e != nil || x.kernel.verifyListeners() != nil {
		return "OWNED_IDENTITY"
	}
	x.report.OwnedBefore = &identity
	reader, e := mihomo.NewLabReadbackClient(28412, controller, 5*time.Second)
	if e != nil {
		return "READER_INPUT"
	}
	if !x.event("BASELINE_READ_BEGIN", applyFacts{OwnedIdentity: &identity}) {
		return "EVIDENCE_IO"
	}
	samples, baselineEvidence, readErr := reader.ReadStableCaptured(ctx)
	x.report.GetEvidence.Baseline, e = x.out.capture("baseline", &baselineEvidence)
	if readErr != nil {
		return "BASELINE_READBACK"
	}
	if e != nil {
		return "EVIDENCE_IO"
	}
	baseline, e := mihomo.CompareLabReadback(samples, oldExpected, newExpected)
	if e != nil {
		return "BASELINE_COMPARE"
	}
	x.report.Readbacks.Baseline = &baseline
	if !x.event("BASELINE_READ_RESULT", applyFacts{Readback: &baseline, GetEvidence: x.report.GetEvidence.Baseline}) {
		return "EVIDENCE_IO"
	}
	if baseline.Conclusion != mihomo.LabStableOldProjection || baseline.RequestsObserved != 8 || baseline.FullPayloadProven || baseline.AuthorizationProven || baseline.DataplaneProven || baseline.Production {
		return "BASELINE_DRIFT"
	}
	route := x.fixture.route(ctx, "BASELINE_A", "A")
	x.report.Routes = append(x.report.Routes, route)
	if !x.event("BASELINE_ROUTE_RESULT", applyFacts{Route: &route}) {
		return "EVIDENCE_IO"
	}
	if !route.Matched {
		return "BASELINE_ROUTE"
	}
	if !x.event("SYNTAX_BEGIN", applyFacts{CandidateInput: x.report.CandidateInput}) {
		return "EVIDENCE_IO"
	}
	syntax, syntaxErr := applySyntaxCheck(ctx, in, candidate, x.out)
	syntaxRaw, e := applyJSON(syntax)
	if e != nil || x.out.write("syntax.exec.json", syntaxRaw) != nil {
		return "EVIDENCE_IO"
	}
	syntaxHash := labConfigHash(syntaxRaw)
	x.report.SyntaxSHA256 = &syntaxHash
	if !x.event("SYNTAX_RESULT", applyFacts{CandidateInput: x.report.CandidateInput, KernelObservation: &syntax.Observation}) {
		return "EVIDENCE_IO"
	}
	if syntaxErr != nil {
		return "CANDIDATE_SYNTAX"
	}
	before, e := x.kernel.identity()
	if e != nil || before != identity || x.kernel.verifyListeners() != nil || in.verify() != nil {
		return "PRE_RELOAD_IDENTITY"
	}
	writer, e := mihomo.NewWriteClient(applyController, controller, 3*time.Second)
	if e != nil {
		return "WRITER_INPUT"
	}
	if !x.event("RELOAD_BEGIN", applyFacts{ReloadPayload: x.report.CandidateInput}) {
		return "EVIDENCE_IO"
	}
	// The local experiment deliberately calls the actual client directly. No
	// product API, authority check, approval, lease or head is invented here.
	x.report.ClientReloadInvocations++
	x.report.ReloadPayload = applyBind(candidateRaw)
	result, reloadErr := writer.Reload(ctx, candidateRaw)
	x.report.ReloadResult = &result
	classification := "NONE"
	if reloadErr != nil {
		classification = "UNKNOWN"
		if result.State == mihomo.ReloadRejected {
			classification = "REJECTED"
			if !result.Dispatched {
				classification = "UNSENT_REJECTED"
			}
		}
	}
	x.report.ReloadErrorClass = &classification
	if !x.event("RELOAD_RESULT", applyFacts{ReloadPayload: x.report.ReloadPayload, ReloadResult: &result, ClientReloadInvocations: &x.report.ClientReloadInvocations}) {
		return "EVIDENCE_IO"
	}
	if reloadErr != nil || result.State != mihomo.ReloadAcknowledged || !result.Dispatched || result.StatusCode != 204 {
		return "RELOAD_NOT_ACKNOWLEDGED"
	}
	if !x.event("CANDIDATE_READ_BEGIN", applyFacts{}) {
		return "EVIDENCE_IO"
	}
	samples, candidateEvidence, readErr := reader.ReadStableCaptured(ctx)
	x.report.GetEvidence.Candidate, e = x.out.capture("candidate", &candidateEvidence)
	if readErr != nil {
		return "CANDIDATE_READBACK"
	}
	if e != nil {
		return "EVIDENCE_IO"
	}
	x.report.Flags.PerGET = x.report.GetEvidence.Baseline != nil && x.report.GetEvidence.Candidate != nil
	afterRead, e := mihomo.CompareLabReadback(samples, oldExpected, newExpected)
	if e != nil {
		return "CANDIDATE_COMPARE"
	}
	x.report.Readbacks.Candidate = &afterRead
	if !x.event("CANDIDATE_READ_RESULT", applyFacts{Readback: &afterRead, GetEvidence: x.report.GetEvidence.Candidate}) {
		return "EVIDENCE_IO"
	}
	if afterRead.Conclusion != mihomo.LabStableNewProjection || afterRead.RequestsObserved != 8 || afterRead.FullPayloadProven || afterRead.AuthorizationProven || afterRead.DataplaneProven || afterRead.Production {
		return "CANDIDATE_DRIFT"
	}
	route = x.fixture.route(ctx, "CANDIDATE_B", "B")
	x.report.Routes = append(x.report.Routes, route)
	if !x.event("CANDIDATE_ROUTE_RESULT", applyFacts{Route: &route}) {
		return "EVIDENCE_IO"
	}
	if !route.Matched {
		return "CANDIDATE_ROUTE"
	}
	after, e := x.kernel.identity()
	if e != nil || after != identity || x.kernel.verifyListeners() != nil || in.verify() != nil {
		return "FINAL_OWNED_IDENTITY"
	}
	x.report.OwnedAfter = &after
	if !x.event("OWNED_FINAL_RESULT", applyFacts{OwnedIdentity: &after}) {
		return "EVIDENCE_IO"
	}
	return ""
}
func (x *applyExperiment) cleanup() string {
	code := ""
	if x.kernel != nil {
		_, e := x.kernel.stop(context.Background())
		observed := x.kernel.startObservation()
		x.report.KernelObservation = &observed
		if e != nil {
			code = "KERNEL_STOP"
		}
		raw, _ := x.kernel.stdout.snapshot()
		if x.out.write("kernel.stdout", raw) != nil {
			code = "EVIDENCE_IO"
		}
		raw, _ = x.kernel.stderr.snapshot()
		if x.out.write("kernel.stderr", raw) != nil {
			code = "EVIDENCE_IO"
		}
		if !x.event("KERNEL_STOP_RESULT", applyFacts{KernelObservation: &observed}) {
			code = "EVIDENCE_IO"
		}
	}
	if x.fixture != nil {
		x.report.FixtureCleanup = x.fixture.stop()
		for _, v := range x.report.FixtureCleanup {
			if v.ErrorClass != "NONE" || !v.ShutdownReturned || !v.ServeReturned {
				code = "FIXTURE_STOP"
			}
		}
		if !x.event("FIXTURE_STOP_RESULT", applyFacts{FixtureCleanup: x.report.FixtureCleanup}) {
			code = "EVIDENCE_IO"
		}
	}
	return code
}
func TestMihomoApplyReloadReadbackAndLocalProxy(t *testing.T) {
	out, e := applyOpenOutput()
	if e != nil {
		t.Fatal("real apply worker envelope unavailable")
	}
	defer out.directory.Close()
	defer out.journal.Close()
	commit := ""
	if value := os.Getenv("CHENGWANG_MIHOMO_APPLY_SOURCE_COMMIT"); labKernelCommit.MatchString(value) {
		commit = value
	}
	x := &applyExperiment{out: out, report: applyReport{Schema: "chengwang.mihomo-runtime-apply-report/v2", Scope: applyScope, SourceCommit: commit, Outcome: "FAIL", Readiness: []applyProbe{}, Routes: []applyRoute{}, FixtureCleanup: []applyFixtureCleanup{}}}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	// All terminal paths, including panic/t.Fatal in the future, retain cleanup
	// and a safe FAIL report. No raw errors, secrets, body or request URL in logs.
	code := "EXPERIMENT_NOT_COMPLETED"
	defer func() {
		cleanupCode := x.cleanup()
		if code == "" {
			code = cleanupCode
		}
		if code == "" {
			x.report.Outcome = "PASS"
			x.report.FailureCode = nil
		} else {
			x.report.FailureCode = &code
		}
		if !x.event("FINAL_RESULT", applyFacts{Code: x.report.FailureCode}) {
			code = "EVIDENCE_IO"
			x.report.Outcome = "FAIL"
			x.report.FailureCode = &code
			t.Error("real apply evidence journal failed")
		}
		raw, e := applyJSON(x.report)
		if e != nil || out.write("apply-report.json", raw) != nil {
			t.Error("real apply evidence finalization failed")
		}
		if code != "" && !t.Failed() {
			t.Error("real local apply cleanup or observation failed")
		}
	}()
	code = x.run(ctx)
	if code != "" {
		t.Fatal("real local apply experiment failed; inspect fenced evidence")
	}
}
