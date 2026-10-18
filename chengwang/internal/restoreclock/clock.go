// Package restoreclock provides process-local Linux kernel clock observations
// for restore evidence collection. It does not provide an external time
// anchor and cannot prove time continuity across a reboot or process restart.
package restoreclock

import (
	"errors"
	"regexp"
	"sync"
	"time"
)

var (
	ErrUnsupported = errors.New("trusted restore clock is unsupported")
	ErrInvalid     = errors.New("trusted restore clock sample is invalid")
	ErrRollback    = errors.New("trusted restore clock moved backwards")
	ErrBootChanged = errors.New("trusted restore clock boot identity changed")
	ErrWindow      = errors.New("trusted restore clock observation window is invalid")
	ErrForeign     = errors.New("trusted restore clock snapshot belongs to another clock")
	ErrPoisoned    = errors.New("trusted restore clock is poisoned")
)

const (
	maximumWindow = 5 * time.Minute
	maximumDrift  = 5 * time.Second
	maximumUnix   = int64(253402300799)
)

var bootIDPattern = regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$`)

// seal is deliberately non-zero-sized. Go may give distinct zero-sized
// allocations the same address, which would make pointer identity unsuitable
// for binding a Snapshot to one Clock instance.
type seal struct{ marker byte }

type Snapshot struct {
	wall       time.Time
	bootID     string
	boottimeNS uint64
	seal       *seal
}

func (s Snapshot) WallUTC() time.Time { return s.wall }
func (s Snapshot) BootID() string     { return s.bootID }
func (s Snapshot) BoottimeNS() uint64 { return s.boottimeNS }

type sampler func() (rawSample, error)

type rawSample struct {
	wall       time.Time
	bootID     string
	boottimeNS uint64
}

type Clock struct {
	mu       sync.Mutex
	sample   sampler
	seal     *seal
	last     Snapshot
	poisoned bool
}

// Open samples the platform directly. It accepts no caller-supplied wall
// time, boot identifier, or boottime value.
func Open() (*Clock, Snapshot, error) {
	return openWithSampler(platformSample)
}

func openWithSampler(sample sampler) (*Clock, Snapshot, error) {
	if sample == nil {
		return nil, Snapshot{}, ErrInvalid
	}
	raw, err := sample()
	if err != nil {
		return nil, Snapshot{}, err
	}
	if err := validateRaw(raw); err != nil {
		return nil, Snapshot{}, err
	}
	token := &seal{marker: 1}
	first := Snapshot{wall: raw.wall.UTC(), bootID: raw.bootID, boottimeNS: raw.boottimeNS, seal: token}
	return &Clock{sample: sample, seal: token, last: first}, first, nil
}

// Observe obtains a new platform sample and rejects boot changes or either
// clock moving backwards. A failed observation permanently poisons the Clock.
func (c *Clock) Observe() (Snapshot, error) {
	if c == nil {
		return Snapshot{}, ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.observeLocked()
}

// ObserveWithin additionally proves that the interval since start stayed
// within maxDuration and that realtime elapsed did not diverge from boottime
// by more than maxDrift. start must have been emitted by this Clock.
func (c *Clock) ObserveWithin(start Snapshot, maxDuration, maxDrift time.Duration) (Snapshot, error) {
	if c == nil {
		return Snapshot{}, ErrInvalid
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.poisoned {
		return Snapshot{}, ErrPoisoned
	}
	if start.seal == nil || start.seal != c.seal {
		c.poisoned = true
		return Snapshot{}, errors.Join(ErrPoisoned, ErrForeign)
	}
	if maxDuration <= 0 || maxDuration > maximumWindow || maxDrift < 0 || maxDrift > maximumDrift {
		c.poisoned = true
		return Snapshot{}, errors.Join(ErrPoisoned, ErrWindow)
	}
	if start.bootID != c.last.bootID || start.boottimeNS > c.last.boottimeNS || start.wall.After(c.last.wall) {
		c.poisoned = true
		return Snapshot{}, errors.Join(ErrPoisoned, ErrWindow)
	}
	next, err := c.observeLocked()
	if err != nil {
		return Snapshot{}, err
	}
	if next.bootID != start.bootID || next.boottimeNS < start.boottimeNS || next.wall.Before(start.wall) {
		c.poisoned = true
		return Snapshot{}, errors.Join(ErrPoisoned, ErrWindow)
	}
	bootElapsedNS := next.boottimeNS - start.boottimeNS
	if bootElapsedNS > uint64(maxDuration) {
		c.poisoned = true
		return Snapshot{}, errors.Join(ErrPoisoned, ErrWindow)
	}
	bootElapsed := time.Duration(bootElapsedNS)
	wallElapsed := next.wall.Sub(start.wall)
	if wallElapsed < 0 || wallElapsed > maxDuration || durationDifference(bootElapsed, wallElapsed) > maxDrift {
		c.poisoned = true
		return Snapshot{}, errors.Join(ErrPoisoned, ErrWindow)
	}
	return next, nil
}

func (c *Clock) observeLocked() (Snapshot, error) {
	if c.sample == nil || c.seal == nil || c.last.seal != c.seal {
		c.poisoned = true
		return Snapshot{}, errors.Join(ErrPoisoned, ErrInvalid)
	}
	if c.poisoned {
		return Snapshot{}, ErrPoisoned
	}
	raw, err := c.sample()
	if err != nil {
		c.poisoned = true
		return Snapshot{}, errors.Join(ErrPoisoned, err)
	}
	if err := validateRaw(raw); err != nil {
		c.poisoned = true
		return Snapshot{}, errors.Join(ErrPoisoned, err)
	}
	next := Snapshot{wall: raw.wall.UTC(), bootID: raw.bootID, boottimeNS: raw.boottimeNS, seal: c.seal}
	if next.bootID != c.last.bootID {
		c.poisoned = true
		return Snapshot{}, errors.Join(ErrPoisoned, ErrBootChanged)
	}
	if next.boottimeNS < c.last.boottimeNS || next.wall.Before(c.last.wall) {
		c.poisoned = true
		return Snapshot{}, errors.Join(ErrPoisoned, ErrRollback)
	}
	c.last = next
	return next, nil
}

func validateRaw(raw rawSample) error {
	wall := raw.wall.UTC()
	if raw.boottimeNS == 0 || !bootIDPattern.MatchString(raw.bootID) || wall.IsZero() || wall.Unix() < 0 || wall.Unix() > maximumUnix {
		return ErrInvalid
	}
	return nil
}

func durationDifference(left, right time.Duration) time.Duration {
	if left >= right {
		return left - right
	}
	return right - left
}
