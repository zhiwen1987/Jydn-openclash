package probe

import (
	"errors"
	"sync"
)

type stateValidationLock struct {
	mu       sync.Mutex
	verify   func() error
	release  func() error
	closed   bool
	poisoned bool
}

func (l *stateValidationLock) Verify() error {
	if l == nil {
		return errors.New("state validation lock is missing")
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return errors.New("state validation lock is closed")
	}
	if l.poisoned {
		return errors.New("state validation lock is poisoned")
	}
	if l.verify == nil {
		l.poisoned = true
		return errors.New("state validation lock verifier is missing")
	}
	if err := l.verify(); err != nil {
		l.poisoned = true
		return errors.Join(errors.New("state validation lock verification failed"), err)
	}
	return nil
}

func (l *stateValidationLock) Close() error {
	if l == nil {
		return nil
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closed {
		return nil
	}
	l.closed = true
	if l.release == nil {
		return nil
	}
	return l.release()
}
