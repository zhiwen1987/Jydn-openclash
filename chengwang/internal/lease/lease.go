// Package lease provides a durable, fail-closed, single-device lease store.
//
// A monotonically increasing fencing token is issued whenever an expired or
// released scope is acquired. Callers must pass both the owner and token when
// renewing or releasing a lease; the token, rather than wall-clock time, is
// the authority an eventual device executor should compare.
package lease

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
	"time"
)

const (
	MinTTL = time.Second
	MaxTTL = 24 * time.Hour
)

var (
	ErrStoreLocked     = errors.New("lease store is locked by another controller")
	ErrStoreClosed     = errors.New("lease store is closed")
	ErrStorePoisoned   = errors.New("lease store is fail-closed after an uncertain commit")
	ErrCommitUncertain = errors.New("lease snapshot rename succeeded but directory durability is uncertain")
	ErrClockRollback   = errors.New("lease clock moved backwards")
	ErrLeaseHeld       = errors.New("lease is held by another owner or token")
	ErrLeaseNotHeld    = errors.New("lease is not held")
	ErrLeaseExpired    = errors.New("lease has expired")
	ErrOwnerMismatch   = errors.New("lease owner does not match")
	ErrTokenMismatch   = errors.New("lease fencing token does not match")
	ErrTokenExhausted  = errors.New("lease fencing token is exhausted")
	ErrStoreLimit      = errors.New("lease store limit exceeded")
)

var safeComponent = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._:/@-]*$`)

// Scope uniquely identifies the protected device-level resource. All four
// fields participate in its stable identity so leases cannot cross an
// environment, tenant, site, or object boundary accidentally.
type Scope struct {
	Tenant      string `json:"tenant"`
	Site        string `json:"site"`
	Object      string `json:"object"`
	Environment string `json:"environment"`
}

// Lease is a detached view of an active durable lease.
type Lease struct {
	Scope      Scope     `json:"scope"`
	Owner      string    `json:"owner"`
	Token      uint64    `json:"token"`
	AcquiredAt time.Time `json:"acquiredAt"`
	RenewedAt  time.Time `json:"renewedAt"`
	ExpiresAt  time.Time `json:"expiresAt"`
}

// Clock makes lease time deterministic in tests and replaceable by a trusted
// local time source. Implementations must be safe for concurrent use.
type Clock interface {
	Now() time.Time
}

// ClockFunc adapts a function to Clock.
type ClockFunc func() time.Time

func (f ClockFunc) Now() time.Time { return f() }

// Option configures a FileStore.
type Option func(*storeOptions) error

// WithClock sets the clock used for expiry and rollback detection.
func WithClock(clock Clock) Option {
	return func(options *storeOptions) error {
		if clock == nil {
			return errors.New("lease clock is required")
		}
		options.clock = clock
		return nil
	}
}

func normalizeScope(scope Scope) (Scope, error) {
	fields := []struct {
		name  string
		value *string
	}{
		{"tenant", &scope.Tenant},
		{"site", &scope.Site},
		{"object", &scope.Object},
		{"environment", &scope.Environment},
	}
	for _, field := range fields {
		*field.value = strings.TrimSpace(*field.value)
		if *field.value == "" {
			return Scope{}, fmt.Errorf("scope %s is required", field.name)
		}
		if len(*field.value) > 128 {
			return Scope{}, fmt.Errorf("scope %s exceeds 128 bytes", field.name)
		}
		if !safeComponent.MatchString(*field.value) {
			return Scope{}, fmt.Errorf("scope %s contains unsupported characters", field.name)
		}
	}
	return scope, nil
}

func normalizeOwner(owner string) (string, error) {
	owner = strings.TrimSpace(owner)
	if owner == "" {
		return "", errors.New("lease owner is required")
	}
	if len(owner) > 128 || !safeComponent.MatchString(owner) {
		return "", errors.New("lease owner contains unsupported characters or exceeds 128 bytes")
	}
	return owner, nil
}

func validateTTL(ttl time.Duration) error {
	if ttl < MinTTL || ttl > MaxTTL {
		return fmt.Errorf("lease TTL must be between %s and %s", MinTTL, MaxTTL)
	}
	return nil
}
