package mihomodeploy

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
)

// All constructors and handles are private, laboratory-only capabilities. The
// fixed worker supplies already independently verified input in its namespace.
// This layer grants no approval, network controller write, or durable head.
const labKernelScope = "OWNED_ISOLATED_LAB_PROCESS_NOT_AUTHORIZATION_OR_PRODUCTION"
const labKernelDebug = "private owned laboratory kernel"

var (
	errLabKernelInput       = errors.New("laboratory kernel input rejected")
	errLabKernelStart       = errors.New("laboratory kernel start rejected")
	errLabKernelIdentity    = errors.New("laboratory kernel identity rejected")
	errLabKernelListeners   = errors.New("laboratory kernel listener ownership rejected")
	errLabKernelClosed      = errors.New("laboratory kernel handle closed")
	errLabKernelStop        = errors.New("laboratory kernel stop uncertain")
	errLabKernelUnsupported = errors.New("laboratory kernel platform unsupported")
)

// A value copy contains only a core pointer: even fmt's special %p bad-verb
// path cannot recursively reveal private paths, bytes, process or file handles.
type labKernelInput struct{ *labKernelInputCore }
type ownedLabKernel struct{ *ownedLabKernelCore }
type labKernelStartError struct{ *labKernelStartErrorCore }
type labKernelStartErrorCore struct{ kernel *ownedLabKernel }

// Null means not observed. Failed Start and a Start that has not returned are
// different observations. No raw operating-system error or private stream is
// ever placed in this metadata.
type labKernelStartObservation struct {
	Attempted      bool             `json:"attempted"`
	Started        *bool            `json:"started"`
	PID            *int             `json:"pid"`
	StartTicks     *uint64          `json:"startTicks"`
	WaitReturned   *bool            `json:"waitReturned"`
	WaitErrorClass string           `json:"waitErrorClass"`
	ExitCode       *int             `json:"exitCode"`
	Signal         *int             `json:"signal"`
	TermSent       *bool            `json:"termSent"`
	KillSent       *bool            `json:"killSent"`
	GroupAbsent    *bool            `json:"groupAbsent"`
	Stdout         *labKernelStream `json:"stdout"`
	Stderr         *labKernelStream `json:"stderr"`
}

func (labKernelStartError) Error() string {
	return "laboratory kernel start did not establish an owned identity"
}
func (labKernelStartError) String() string             { return labKernelDebug }
func (labKernelStartError) GoString() string           { return labKernelDebug }
func (labKernelStartError) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, labKernelDebug) }
func (labKernelStartError) Unwrap() error              { return errLabKernelStart }
func (e labKernelStartError) MarshalJSON() ([]byte, error) {
	return json.Marshal(struct {
		Scope       string                    `json:"scope"`
		Observation labKernelStartObservation `json:"observation"`
	}{labKernelScope, (&e).observation()})
}
func (e *labKernelStartError) owned() *ownedLabKernel {
	if e == nil || e.labKernelStartErrorCore == nil {
		return nil
	}
	return e.kernel
}
func (e *labKernelStartError) observation() labKernelStartObservation {
	if e == nil || e.labKernelStartErrorCore == nil || e.kernel == nil {
		return labKernelStartObservation{}
	}
	return e.kernel.startObservation()
}

func (labKernelInput) String() string             { return labKernelDebug }
func (labKernelInput) GoString() string           { return labKernelDebug }
func (labKernelInput) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, labKernelDebug) }
func (labKernelInput) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"OWNED_ISOLATED_LAB_INPUT_NOT_AUTHORIZATION"}`), nil
}
func (ownedLabKernel) String() string             { return labKernelDebug }
func (ownedLabKernel) GoString() string           { return labKernelDebug }
func (ownedLabKernel) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, labKernelDebug) }
func (ownedLabKernel) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"OWNED_ISOLATED_LAB_PROCESS_NOT_AUTHORIZATION_OR_PRODUCTION"}`), nil
}

// These are measured metadata copies, never constructor arguments or authority.
type labKernelIdentity struct {
	PID            int    `json:"pid"`
	StartTicks     uint64 `json:"startTicks"`
	NetNSInode     uint64 `json:"netNSInode"`
	ELFSHA256      string `json:"elfSHA256"`
	ELFBytes       int64  `json:"elfBytes"`
	SourceCommit   string `json:"sourceCommit"`
	ArtifactSHA256 string `json:"artifactSHA256"`
	ControllerPort uint16 `json:"controllerPort"`
	MixedPort      uint16 `json:"mixedPort"`
}
type labKernelStream struct {
	Bytes      int    `json:"bytes"`
	TotalBytes int64  `json:"totalBytes"`
	SHA256     string `json:"sha256"`
	Truncated  bool   `json:"truncated"`
	Complete   bool   `json:"complete"`
}
type labKernelExit struct {
	Started        bool            `json:"started"`
	WaitReturned   bool            `json:"waitReturned"`
	WaitErrorClass string          `json:"waitErrorClass"`
	ExitCode       *int            `json:"exitCode"`
	Signal         *int            `json:"signal"`
	TermSent       bool            `json:"termSent"`
	KillSent       bool            `json:"killSent"`
	GroupAbsent    *bool           `json:"groupAbsent"`
	Stdout         labKernelStream `json:"stdout"`
	Stderr         labKernelStream `json:"stderr"`
}
