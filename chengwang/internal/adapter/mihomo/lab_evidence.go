package mihomo

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"
)

const labEvidenceSchema = "chengwang.mihomo-lab-get-evidence/v1"
const labEvidenceScope = "PRIVATE_HTTP_ENTITY_RESPONSE_EVIDENCE_NOT_AUTHORIZATION_OR_PAYLOAD_PROOF"
const labEvidenceLabel = "private same-response laboratory evidence; not authorization or payload proof"
const labEvidenceMetadataLimit = 1 << 20
const labEvidenceHeaderLimit = 16 << 10

var ErrLabEvidenceUnavailable = errors.New("laboratory response evidence unavailable")
var ErrLabEvidenceBusy = errors.New("laboratory response evidence already retained")

// A value contains only an opaque pointer, including fmt's unsupported-verb
// reflection path. Raw entity bodies and selected parsed header bytes are
// private until the source-owned exporter's disclosure fence has passed.
type LabReadbackEvidence struct{ core *labEvidenceCore }

type LabEvidenceDescriptor struct {
	Schema            string  `json:"schema"`
	Scope             string  `json:"scope"`
	Outcome           string  `json:"outcome"`
	FailureClass      *string `json:"failureClass"`
	SlotsEntered      int     `json:"slotsEntered"`
	DoInvocations     int     `json:"doInvocations"`
	ResponsesObserved int     `json:"responsesObserved"`
	ReadAttempts      int     `json:"readAttempts"`
	CompletedBodies   int     `json:"completedBodies"`
	RetainedBytes     int64   `json:"retainedBytes"`
	LimitReached      bool    `json:"limitReached"`
	ContextState      string  `json:"contextState"`
	TranscriptSHA256  string  `json:"transcriptSHA256"`
	TranscriptBytes   int64   `json:"transcriptBytes"`
}

type labEvidenceSlot struct {
	Ordinal      int    `json:"ordinal"`
	Round        int    `json:"round"`
	EndpointKind string `json:"endpointKind"`
}
type labEvidenceHeaders struct {
	ContentTypeValuesB64      []string `json:"contentTypeValuesB64"`
	ContentEncodingValuesB64  []string `json:"contentEncodingValuesB64"`
	TransferEncodingValuesB64 []string `json:"transferEncodingValuesB64"`
	SetCookieCount            int      `json:"setCookieCount"`
}
type labEvidenceRecord struct {
	Ordinal          int                 `json:"ordinal"`
	Round            int                 `json:"round"`
	EndpointKind     string              `json:"endpointKind"`
	RequestBuilt     bool                `json:"requestBuilt"`
	DoInvoked        bool                `json:"doInvoked"`
	ResponseObserved bool                `json:"responseObserved"`
	StatusCode       *int                `json:"statusCode"`
	Headers          *labEvidenceHeaders `json:"headers"`
	ContentLength    *int64              `json:"contentLength"`
	Uncompressed     *bool               `json:"uncompressed"`
	ReadAttempted    bool                `json:"readAttempted"`
	RetainedBytes    *int64              `json:"retainedBytes"`
	RetainedSHA256   *string             `json:"retainedSHA256"`
	NaturalEOF       *bool               `json:"naturalEOF"`
	ReadErrorClass   *string             `json:"readErrorClass"`
	LimitReached     bool                `json:"limitReached"`
	CloseAttempted   bool                `json:"closeAttempted"`
	CloseErrorClass  *string             `json:"closeErrorClass"`
	ContextState     string              `json:"contextState"`
	ParseState       string              `json:"parseState"`
	TerminalClass    string              `json:"terminalClass"`
}
type labEvidenceTranscript struct {
	Schema            string              `json:"schema"`
	Scope             string              `json:"scope"`
	ExpectedSchedule  []labEvidenceSlot   `json:"expectedSchedule"`
	Records           []labEvidenceRecord `json:"records"`
	SlotsEntered      int                 `json:"slotsEntered"`
	DoInvocations     int                 `json:"doInvocations"`
	ResponsesObserved int                 `json:"responsesObserved"`
	ReadAttempts      int                 `json:"readAttempts"`
	CompletedBodies   int                 `json:"completedBodies"`
	RetainedBytes     int64               `json:"retainedBytes"`
	Outcome           string              `json:"outcome"`
	FailureClass      *string             `json:"failureClass"`
	LimitReached      bool                `json:"limitReached"`
	ContextState      string              `json:"contextState"`
}
type labEvidenceCore struct {
	mu         sync.Mutex
	owner      *labReaderCore
	wire       labEvidenceTranscript
	bodies     [][]byte
	transcript []byte
	finalized  bool
	released   bool
}

func (LabReadbackEvidence) String() string             { return labEvidenceLabel }
func (LabReadbackEvidence) GoString() string           { return labEvidenceLabel }
func (LabReadbackEvidence) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, labEvidenceLabel) }
func (LabReadbackEvidence) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"PRIVATE_HTTP_ENTITY_RESPONSE_EVIDENCE_NOT_AUTHORIZATION_OR_PAYLOAD_PROOF"}`), nil
}
func (e *LabReadbackEvidence) UnmarshalJSON([]byte) error {
	if e != nil {
		if e.core != nil {
			_ = e.Release()
		}
		e.core = nil
	}
	return ErrLabReadbackInput
}

func labEvidenceContext(ctx context.Context) string {
	if ctx != nil {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) {
			return "DEADLINE"
		}
		if ctx.Err() != nil {
			return "CANCELED"
		}
	}
	return "ACTIVE"
}
func labEvidenceError(err error) string {
	if err == nil {
		return "NONE"
	}
	if errors.Is(err, context.Canceled) {
		return "CANCELED"
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return "DEADLINE"
	}
	return "IO"
}
func labEvidenceSchedule() []labEvidenceSlot {
	rows := make([]labEvidenceSlot, 0, 8)
	for round := 1; round <= 2; round++ {
		for _, kind := range []string{"VERSION", "CONFIGS", "PROXIES", "RULES"} {
			rows = append(rows, labEvidenceSlot{len(rows) + 1, round, kind})
		}
	}
	return rows
}
func (c *labEvidenceCore) begin(path string) *labEvidenceRecord {
	if c == nil {
		return nil
	}
	i := len(c.wire.Records)
	if i >= 8 {
		return nil
	}
	kind := ""
	switch path {
	case "/version":
		kind = "VERSION"
	case "/configs":
		kind = "CONFIGS"
	case "/proxies":
		kind = "PROXIES"
	case "/rules":
		kind = "RULES"
	}
	if kind == "" || c.wire.ExpectedSchedule[i].EndpointKind != kind {
		return nil
	}
	c.wire.Records = append(c.wire.Records, labEvidenceRecord{Ordinal: i + 1, Round: i/4 + 1, EndpointKind: kind,
		ContextState: "ACTIVE", ParseState: "NOT_ATTEMPTED", TerminalClass: "NONE"})
	c.bodies = append(c.bodies, nil)
	return &c.wire.Records[i]
}
func labEvidenceTerminal(r *labEvidenceRecord, code string) {
	if r != nil && r.TerminalClass == "NONE" {
		r.TerminalClass = code
	}
}
func (c *labEvidenceCore) shape(err error) {
	if c == nil || len(c.wire.Records) == 0 {
		return
	}
	r := &c.wire.Records[len(c.wire.Records)-1]
	if err == nil {
		r.ParseState = "SHAPE_ACCEPTED"
		return
	}
	r.ParseState = "SHAPE_REJECTED"
	code := "SHAPE"
	if errors.Is(err, ErrLabReadbackLimit) {
		code = "LIMIT"
		r.LimitReached = true
	}
	labEvidenceTerminal(r, code)
}
func labEvidenceResponse(r *labEvidenceRecord, resp *http.Response) bool {
	if r == nil {
		return true
	}
	r.ResponseObserved = true
	status, length, uncompressed := resp.StatusCode, resp.ContentLength, resp.Uncompressed
	r.StatusCode = &status
	r.ContentLength = &length
	r.Uncompressed = &uncompressed
	ct, ce, te := resp.Header.Values("Content-Type"), resp.Header.Values("Content-Encoding"), resp.TransferEncoding
	cookies := len(resp.Header.Values("Set-Cookie"))
	if len(ct) > labEvidenceHeaderLimit || len(ce) > labEvidenceHeaderLimit || len(te) > labEvidenceHeaderLimit || cookies > labEvidenceHeaderLimit {
		return false
	}
	total, count := 0, 0
	for _, values := range [][]string{ct, ce, te} {
		for _, v := range values {
			count++
			if count > labEvidenceHeaderLimit || len(v) > labEvidenceHeaderLimit-total {
				return false
			}
			total += len(v)
		}
	}
	encode := func(values []string) []string {
		out := make([]string, 0, len(values))
		for _, v := range values {
			out = append(out, base64.StdEncoding.EncodeToString([]byte(v)))
		}
		return out
	}
	r.Headers = &labEvidenceHeaders{encode(ct), encode(ce), encode(te), cookies}
	return true
}

// This is the only entity-body reader used by both APIs. Natural EOF comes
// from Body.Read itself, never an artificial LimitReader EOF. The single
// probe byte is retained even with EOF/error, and is always over the limit.
// Capacity growth is clamped; small version responses do not allocate 8MiB.
func labReadEntity(body io.Reader) (raw []byte, eof bool, err error) {
	const maximum = labReadbackBodyLimit + 1
	raw = make([]byte, 0, 512)
	empty := 0
	for len(raw) < maximum {
		if len(raw) == cap(raw) {
			next := cap(raw) * 2
			if next > maximum {
				next = maximum
			}
			grown := make([]byte, len(raw), next)
			copy(grown, raw)
			raw = grown
		}
		room := cap(raw) - len(raw)
		if room > maximum-len(raw) {
			room = maximum - len(raw)
		}
		old := len(raw)
		n, readErr := body.Read(raw[old : old+room])
		if n < 0 || n > room {
			return raw, false, ErrLabReadbackUnavailable
		}
		raw = raw[:old+n]
		if readErr == io.EOF {
			return raw, true, nil
		}
		if readErr != nil {
			return raw, false, readErr
		}
		if n == 0 {
			empty++
			if empty >= 100 {
				return raw, false, io.ErrNoProgress
			}
		} else {
			empty = 0
		}
	}
	return raw, false, nil
}
func (c *labEvidenceCore) retain(r *labEvidenceRecord, raw []byte, eof bool, err error) {
	if c == nil || r == nil {
		return
	}
	size, hash, code := int64(len(raw)), labDigest(raw), labEvidenceError(err)
	r.RetainedBytes = &size
	r.RetainedSHA256 = &hash
	r.NaturalEOF = &eof
	r.ReadErrorClass = &code
	r.LimitReached = len(raw) > labReadbackBodyLimit
	// The decoder consumes this exact private buffer. It is never exported
	// directly; PrivateBody makes a detached copy after finalization.
	c.bodies[r.Ordinal-1] = raw
}
func (c *labEvidenceCore) finish(ctx context.Context, runErr error) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released || c.finalized {
		return ErrLabEvidenceUnavailable
	}
	w := &c.wire
	w.SlotsEntered = len(w.Records)
	w.ContextState = labEvidenceContext(ctx)
	first := ""
	for _, r := range w.Records {
		if r.DoInvoked {
			w.DoInvocations++
		}
		if r.ResponseObserved {
			w.ResponsesObserved++
		}
		if r.ReadAttempted {
			w.ReadAttempts++
		}
		if r.RetainedBytes != nil {
			w.RetainedBytes += *r.RetainedBytes
		}
		w.LimitReached = w.LimitReached || r.LimitReached
		// Physical body completion is independent of a later JSON/shape/Close
		// resource rejection. An oversized probe fails this length condition.
		if r.NaturalEOF != nil && *r.NaturalEOF && r.ReadErrorClass != nil && *r.ReadErrorClass == "NONE" && r.RetainedBytes != nil && *r.RetainedBytes <= labReadbackBodyLimit {
			w.CompletedBodies++
		}
		if first == "" && r.TerminalClass != "NONE" {
			first = r.TerminalClass
		}
	}
	if first == "" && w.ContextState != "ACTIVE" {
		first = "CONTEXT"
	}
	if first == "" && (runErr != nil || len(w.Records) != 8) {
		first = "INTERNAL"
	}
	if first == "" && (w.DoInvocations != 8 || w.ResponsesObserved != 8 || w.ReadAttempts != 8 || w.CompletedBodies != 8) {
		first = "INTERNAL"
	}
	if first == "" {
		for _, r := range w.Records {
			if !r.RequestBuilt || !r.DoInvoked || !r.ResponseObserved || r.StatusCode == nil || *r.StatusCode != 200 || r.Headers == nil || r.Uncompressed == nil || *r.Uncompressed || !r.ReadAttempted || !r.CloseAttempted || r.CloseErrorClass == nil || *r.CloseErrorClass != "NONE" || r.ParseState != "SHAPE_ACCEPTED" {
				first = "INTERNAL"
				break
			}
		}
	}
	w.Outcome = "COMPLETE"
	if first != "" {
		w.Outcome = "FAILED"
		w.FailureClass = &first
	}
	raw, err := json.Marshal(w)
	if err != nil || len(raw)+1 > labEvidenceMetadataLimit {
		return ErrLabReadbackLimit
	}
	c.transcript = append(raw, '\n')
	c.finalized = true
	if first != "" && runErr == nil {
		return ErrLabReadbackUnavailable
	}
	return nil
}

func (e *LabReadbackEvidence) Descriptor() (LabEvidenceDescriptor, error) {
	if e == nil || e.core == nil {
		return LabEvidenceDescriptor{}, ErrLabEvidenceUnavailable
	}
	c := e.core
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released || !c.finalized {
		return LabEvidenceDescriptor{}, ErrLabEvidenceUnavailable
	}
	w := c.wire
	var failure *string
	if w.FailureClass != nil {
		v := *w.FailureClass
		failure = &v
	}
	return LabEvidenceDescriptor{w.Schema, w.Scope, w.Outcome, failure, w.SlotsEntered, w.DoInvocations, w.ResponsesObserved,
		w.ReadAttempts, w.CompletedBodies, w.RetainedBytes, w.LimitReached, w.ContextState, labDigest(c.transcript), int64(len(c.transcript))}, nil
}
func (e *LabReadbackEvidence) PrivateTranscript() ([]byte, error) {
	if e == nil || e.core == nil {
		return nil, ErrLabEvidenceUnavailable
	}
	c := e.core
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.released || !c.finalized {
		return nil, ErrLabEvidenceUnavailable
	}
	out := make([]byte, len(c.transcript))
	copy(out, c.transcript)
	return out, nil
}
func (e *LabReadbackEvidence) PrivateBody(ordinal uint8) ([]byte, error) {
	if e == nil || e.core == nil {
		return nil, ErrLabEvidenceUnavailable
	}
	c := e.core
	c.mu.Lock()
	defer c.mu.Unlock()
	i := int(ordinal) - 1
	if c.released || !c.finalized || i < 0 || i >= len(c.wire.Records) || !c.wire.Records[i].ReadAttempted || c.wire.Records[i].RetainedBytes == nil {
		return nil, ErrLabEvidenceUnavailable
	}
	out := make([]byte, len(c.bodies[i]))
	copy(out, c.bodies[i])
	return out, nil
}
func (e *LabReadbackEvidence) Release() error {
	if e == nil || e.core == nil {
		return ErrLabEvidenceUnavailable
	}
	c := e.core
	c.mu.Lock()
	if c.released {
		c.mu.Unlock()
		return ErrLabEvidenceUnavailable
	}
	owner := c.owner
	c.owner = nil
	c.released = true
	c.bodies = nil
	c.transcript = nil
	c.wire = labEvidenceTranscript{}
	c.mu.Unlock()
	if owner != nil {
		owner.captureMu.Lock()
		if owner.capture == c {
			owner.capture = nil
		}
		owner.captureMu.Unlock()
	}
	return nil
}

// One retained capture per client core, including after return. Callers must
// stage private copies and Release before the next captured run. Body capacity
// is at most 64MiB+8 and metadata at most 1MiB per archive. Getter copies,
// decoder allocations, GC and process RSS are additional, not a hard bound.
func (c *LabReadbackClient) ReadStableCaptured(ctx context.Context) (LabSamples, LabReadbackEvidence, error) {
	if c == nil || c.core == nil || c.core.client == nil || !labContextOK(ctx) {
		return LabSamples{}, LabReadbackEvidence{}, ErrLabReadbackUnavailable
	}
	owner := c.core
	owner.captureMu.Lock()
	if owner.capture != nil {
		owner.captureMu.Unlock()
		return LabSamples{}, LabReadbackEvidence{}, ErrLabEvidenceBusy
	}
	core := &labEvidenceCore{owner: owner, wire: labEvidenceTranscript{Schema: labEvidenceSchema, Scope: labEvidenceScope,
		ExpectedSchedule: labEvidenceSchedule(), Records: make([]labEvidenceRecord, 0, 8)}, bodies: make([][]byte, 0, 8)}
	owner.capture = core
	owner.captureMu.Unlock()
	evidence := LabReadbackEvidence{core: core}
	returned := false
	defer func() {
		if !returned {
			_ = evidence.Release()
		}
	}()
	budget := owner.timeout
	if budget > 5*time.Second {
		budget = 5 * time.Second
	}
	ctx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	samples, err := c.readStable(ctx, core)
	if finishErr := core.finish(ctx, err); finishErr != nil {
		samples = LabSamples{}
		if err == nil {
			err = finishErr
		}
	}
	returned = true
	return samples, evidence, err
}
