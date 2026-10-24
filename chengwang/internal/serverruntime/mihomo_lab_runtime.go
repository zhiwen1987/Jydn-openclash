package serverruntime

import (
	"context"
	"errors"
	"fmt"
	"io"
	"reflect"
	"regexp"
	"sync"
	"time"

	"chengwang/internal/api"
	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/mihomodeploy"
)

const MihomoLabIdentityFile = "/tmp/chengwang-mihomo-service-identities/credentials.json"
const mihomoLabRuntimeDebug = "private isolated laboratory runtime; not production authority"

var errMihomoLabRuntime = errors.New("isolated Mihomo lifecycle runtime unavailable")
var mihomoLabScopePart = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$`)

func mihomoLabContextPresent(ctx context.Context) bool {
	if ctx == nil { return false }
	v := reflect.ValueOf(ctx)
	switch v.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return !v.IsNil()
	default:
		return true
	}
}

// The feature is explicitly selected by trusted startup configuration. It has
// no HTTP-controlled constructor, target URL, PID, credential or filesystem path.
func mihomoLabConfigFromEnvironment(c *Config) error {
	value, err := StrictBoolEnv("CHENGWANG_MIHOMO_LAB_ENABLED")
	if err != nil {
		return errMihomoLabRuntime
	}
	c.MihomoLabEnabled = value
	return nil
}

func validateMihomoLabConfig(c Config) error {
	if !c.MihomoLabEnabled {
		return nil
	}
	if c.Mode != mihomodeploy.LabEnvironment || c.IdentitiesFile != MihomoLabIdentityFile || c.AdminToken != "" ||
		!mihomoLabScopePart.MatchString(c.TenantID) || !mihomoLabScopePart.MatchString(c.SiteID) ||
		!mihomoLabScopePart.MatchString(c.ManagementObjectID) || c.MihomoURL != "" || c.MihomoToken != "" ||
		len(c.MihomoAllowedHosts) != 0 || c.AllowPublish || c.OperationWritesEnabled ||
		c.SubscriptionsEnabled || c.SubscriptionWritesEnabled || c.ProbeReadEnabled || c.LiveOverviewEnabled {
		return errMihomoLabRuntime
	}
	return nil
}

type MihomoLabRuntime struct{ core *mihomoLabRuntimeCore }
type mihomoLabRuntimeCore struct {
	mu      sync.Mutex
	closeMu sync.Mutex
	manager *authn.SnapshotManager
	service *mihomodeploy.LabService
	ready   bool
	writable bool
	closing bool
	closed  bool
}

func (MihomoLabRuntime) String() string { return mihomoLabRuntimeDebug }
func (MihomoLabRuntime) GoString() string { return mihomoLabRuntimeDebug }
func (MihomoLabRuntime) Format(s fmt.State, _ rune) { _, _ = io.WriteString(s, mihomoLabRuntimeDebug) }
func (MihomoLabRuntime) MarshalJSON() ([]byte, error) {
	return []byte(`{"scope":"ISOLATED_LAB_RUNTIME_NOT_AUTHORIZATION"}`), nil
}
func (*MihomoLabRuntime) UnmarshalJSON([]byte) error { return errMihomoLabRuntime }

// A nonnil runtime must be retained and closed even alongside an error. An
// uncertain service startup is never treated as evidence that no process ran.
func OpenMihomoLabRuntime(ctx context.Context, c Config) (*MihomoLabRuntime, error) {
	if !c.MihomoLabEnabled {
		return nil, nil
	}
	if !mihomoLabContextPresent(ctx) || ctx.Err() != nil || validateMihomoLabConfig(c) != nil {
		return nil, errMihomoLabRuntime
	}
	manager, err := authn.OpenSnapshotManager(MihomoLabIdentityFile, time.Now().UTC())
	if err != nil {
		return nil, errMihomoLabRuntime
	}
	r := &MihomoLabRuntime{core: &mihomoLabRuntimeCore{manager: manager}}
	scope := authz.ResourceScope{TenantID: c.TenantID, SiteID: c.SiteID, ObjectType: mihomodeploy.LabObjectType,
		ObjectID: c.ManagementObjectID, Environment: mihomodeploy.LabEnvironment}
	service, err := mihomodeploy.OpenIsolatedLabService(ctx, manager, scope)
	r.core.service = service
	if service == nil || service.Scope() != scope || !service.DiagnosticReady() {
		return r, errMihomoLabRuntime
	}
	r.core.ready = true
	// A reopened, verified persistent record can serve protected diagnostics
	// while factory readiness failed. It never regains device-write authority.
	r.core.writable = err == nil
	return r, nil
}

func (r *MihomoLabRuntime) Backend() mihomodeploy.LabBackend {
	if r == nil || r.core == nil {
		return nil
	}
	c := r.core
	c.mu.Lock()
	defer c.mu.Unlock()
	if !c.ready || c.closing || c.closed || c.service == nil {
		return nil
	}
	return c.service
}

func (r *MihomoLabRuntime) ApplyAPIOptions(options api.Options) api.Options {
	options.MihomoLab = r.Backend()
	options.MihomoLabWritesEnabled = false
	if r != nil && r.core != nil {
		r.core.mu.Lock()
		options.MihomoLabWritesEnabled = options.MihomoLab != nil && r.core.ready && r.core.writable && !r.core.closing && !r.core.closed
		r.core.mu.Unlock()
	}
	return options
}

// Release the manager only after the source-owned service proves its close.
// Failure retains ownership and returns an error on every unresolved attempt.
func (r *MihomoLabRuntime) Close(ctx context.Context) error {
	if r == nil || r.core == nil {
		return nil
	}
	if !mihomoLabContextPresent(ctx) {
		return errMihomoLabRuntime
	}
	c := r.core
	c.closeMu.Lock()
	defer c.closeMu.Unlock()
	c.mu.Lock()
	if c.closed {
		c.mu.Unlock()
		return nil
	}
	c.closing = true
	service, manager := c.service, c.manager
	c.mu.Unlock()
	if service != nil && service.Close(ctx) != nil {
		return errMihomoLabRuntime
	}
	if manager != nil && manager.Close() != nil {
		return errMihomoLabRuntime
	}
	c.mu.Lock()
	c.ready = false
	c.writable = false
	c.closed = true
	c.service = nil
	c.manager = nil
	c.mu.Unlock()
	return nil
}
