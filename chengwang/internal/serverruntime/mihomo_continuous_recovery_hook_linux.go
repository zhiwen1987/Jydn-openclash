//go:build linux && chengwang_mihomo_service && chengwang_mihomo_recovery_native && chengwang_mihomo_recovery_continuous_fault && !chengwang_mihomo_faults && !chengwang_mihomo_completion_native

package serverruntime

import (
	"errors"
	"sync"
	"time"

	"chengwang/internal/authn"
	"chengwang/internal/authz"
	"chengwang/internal/mihomodeploy"
)

var errLabContinuousRecoveryHarness = errors.New("isolated continuous recovery harness unavailable")

type labContinuousRecoveryHarnessResult struct {
	handle *mihomodeploy.LabContinuousRecoveryFaultHandle
	err    error
}

type labContinuousRecoveryHarnessIssuer struct {
	sync.Mutex
	armed               bool
	consumed            bool
	credentialAttempted bool
	credentialStore     *authn.Store
	credentialManager   *authn.SnapshotManager
	result              chan labContinuousRecoveryHarnessResult
}

var processLabContinuousRecoveryHarness labContinuousRecoveryHarnessIssuer

// armLabContinuousRecoveryHarness is process-local and one-way. It has no
// reset, environment, HTTP, Options or serialized-capability input.
func armLabContinuousRecoveryHarness() (<-chan labContinuousRecoveryHarnessResult, error) {
	i := &processLabContinuousRecoveryHarness
	i.Lock()
	defer i.Unlock()
	if i.armed || i.consumed || i.credentialAttempted || i.credentialStore != nil || i.credentialManager != nil || i.result != nil {
		return nil, errLabContinuousRecoveryHarness
	}
	i.armed = true
	i.result = make(chan labContinuousRecoveryHarnessResult, 1)
	return i.result, nil
}

// claimLabContinuousRecoveryCredentials consumes the source arm before any
// handler or listener is published. The bundle constructor owns the only
// v2 decoder and returns one stable initial Store/SnapshotManager pair.
func claimLabContinuousRecoveryCredentials(c Config, now time.Time) (*authn.Store, *authn.SnapshotManager, bool, error) {
	return claimLabContinuousRecoveryCredentialsFrom(&processLabContinuousRecoveryHarness, c, now)
}

func claimLabContinuousRecoveryCredentialsFrom(i *labContinuousRecoveryHarnessIssuer, c Config, now time.Time) (*authn.Store, *authn.SnapshotManager, bool, error) {
	if i == nil {
		return nil, nil, true, errLabContinuousRecoveryHarness
	}
	i.Lock()
	if !i.armed {
		i.Unlock()
		return nil, nil, false, nil
	}
	if i.consumed || i.credentialAttempted || i.credentialStore != nil || i.credentialManager != nil || i.result == nil {
		i.Unlock()
		return nil, nil, true, errLabContinuousRecoveryHarness
	}
	i.credentialAttempted = true
	i.Unlock()

	expected := authz.ResourceScope{TenantID: "sub-tenant", SiteID: "sub-site", ObjectType: mihomodeploy.LabObjectType,
		ObjectID: "local", Environment: mihomodeploy.LabEnvironment}
	configured := authz.ResourceScope{TenantID: c.TenantID, SiteID: c.SiteID, ObjectType: mihomodeploy.LabObjectType,
		ObjectID: c.ManagementObjectID, Environment: c.Mode}
	if !c.MihomoLabEnabled || validateMihomoLabConfig(c) != nil || c.IdentitiesFile != MihomoLabIdentityFile || configured != expected {
		return nil, nil, true, errLabContinuousRecoveryHarness
	}
	bundle, err := authn.OpenContinuousRecoveryCredentialBundle(c.IdentitiesFile, now)
	if err != nil || bundle == nil {
		return nil, nil, true, errLabContinuousRecoveryHarness
	}
	scope, err := bundle.Scope()
	if err != nil || scope != expected {
		_ = bundle.Close()
		return nil, nil, true, errLabContinuousRecoveryHarness
	}
	store, manager, err := bundle.Consume()
	if err != nil || store == nil || manager == nil {
		_ = bundle.Close()
		return nil, nil, true, errLabContinuousRecoveryHarness
	}

	i.Lock()
	defer i.Unlock()
	if !i.armed || i.consumed || !i.credentialAttempted || i.credentialStore != nil || i.credentialManager != nil || i.result == nil {
		_ = manager.Close()
		return nil, nil, true, errLabContinuousRecoveryHarness
	}
	i.credentialStore, i.credentialManager = store, manager
	return store, manager, true, nil
}

// RunWith calls this after it has installed the actual runtime cleanup owner,
// but before it publishes a handler or listener. An unarmed exact-tag build is
// a no-op so unrelated tests under the same positive tags remain independent.
func bindLabContinuousRecoveryHarness(runtime *MihomoLabRuntime, identity *authn.Store) error {
	i := &processLabContinuousRecoveryHarness
	i.Lock()
	if !i.armed {
		i.Unlock()
		return nil
	}
	if i.consumed || !i.credentialAttempted || i.credentialStore == nil || i.credentialManager == nil || i.result == nil {
		i.Unlock()
		return errLabContinuousRecoveryHarness
	}
	i.consumed = true
	result := i.result
	expectedStore, expectedManager := i.credentialStore, i.credentialManager
	i.Unlock()

	if runtime == nil || runtime.core == nil || identity == nil || identity != expectedStore {
		err := errLabContinuousRecoveryHarness
		result <- labContinuousRecoveryHarnessResult{err: err}
		return err
	}
	c := runtime.core
	c.mu.Lock()
	service := c.service
	valid := c.ready && c.writable && !c.closing && !c.closed && service != nil && c.manager == expectedManager && c.boundCredentials
	c.mu.Unlock()
	if !valid {
		err := errLabContinuousRecoveryHarness
		result <- labContinuousRecoveryHarnessResult{err: err}
		return err
	}
	handle, err := mihomodeploy.BeginLabContinuousRecoveryResponseLoss(service)
	if err != nil || handle == nil {
		if err == nil {
			err = errLabContinuousRecoveryHarness
		}
		result <- labContinuousRecoveryHarnessResult{err: err}
		return err
	}
	result <- labContinuousRecoveryHarnessResult{handle: handle}
	return nil
}
