package refresh

import (
	"context"
	"math/rand/v2"
	"time"
)

// Run performs its first callback immediately, then successful periodic polls
// or bounded exponential retries with jitter. It spawns no goroutines. The
// trusted callback must honor its context; this cannot interrupt disk syscalls
// or an SDK that ignores cancellation. Callback errors never establish Fresh.
func (c *Client) Run(ctx context.Context, callback func(context.Context) error) error {
	if c == nil || ctx == nil || callback == nil {
		return ErrInvalid
	}
	if !c.running.CompareAndSwap(false, true) {
		return ErrBusy
	}
	defer c.running.Store(false)
	base := c.interval / 4
	if base > 5*time.Second {
		base = 5 * time.Second
	}
	if base < time.Second {
		base = time.Second
	}
	backoff := base
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		attempt, cancel := context.WithTimeout(ctx, c.timeout)
		err := callback(attempt)
		if err == nil && attempt.Err() != nil {
			err = ErrFetch
		}
		cancel()
		if stopped := ctx.Err(); stopped != nil {
			return stopped
		}
		delay := c.interval
		if err != nil {
			// Range [backoff/2,backoff], at least 1ns. The next base is capped
			// independently, so arithmetic cannot overflow under Config bounds.
			half := backoff / 2
			if half < 1 {
				half = 1
			}
			delay = half + time.Duration(rand.Int64N(int64(half)+1))
			if backoff < c.interval {
				backoff *= 2
				if backoff > c.interval {
					backoff = c.interval
				}
			}
		} else {
			backoff = base
		}
		timer := time.NewTimer(delay)
		select {
		case <-ctx.Done():
			if !timer.Stop() {
				select {
				case <-timer.C:
				default:
				}
			}
			return ctx.Err()
		case <-timer.C:
		}
	}
}
