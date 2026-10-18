package restoreclock

import (
	"errors"
	"testing"
	"time"
)

const testBootID = "123e4567-e89b-42d3-a456-426614174000"

func raw(wall time.Time, boottime time.Duration) rawSample {
	return rawSample{wall: wall.UTC(), bootID: testBootID, boottimeNS: uint64(boottime)}
}

func sequence(samples ...rawSample) sampler {
	index := 0
	return func() (rawSample, error) {
		if index >= len(samples) {
			return rawSample{}, errors.New("sample sequence exhausted")
		}
		value := samples[index]
		index++
		return value, nil
	}
}

func TestOpenAndObserveReturnOpaqueMonotonicSnapshots(t *testing.T) {
	base := time.Unix(1_800_000_000, 0).UTC()
	clock, first, err := openWithSampler(sequence(raw(base, time.Second), raw(base.Add(time.Second), 2*time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	second, err := clock.Observe()
	if err != nil {
		t.Fatal(err)
	}
	if first.BootID() != testBootID || first.WallUTC() != base || first.BoottimeNS() != uint64(time.Second) || second.BoottimeNS() != uint64(2*time.Second) {
		t.Fatalf("unexpected snapshots: first=%+v second=%+v", first, second)
	}
}

func TestClockRejectsBootChangeAndPoisons(t *testing.T) {
	base := time.Unix(1_800_000_000, 0).UTC()
	changed := raw(base.Add(time.Second), 2*time.Second)
	changed.bootID = "223e4567-e89b-42d3-a456-426614174000"
	clock, _, err := openWithSampler(sequence(raw(base, time.Second), changed))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clock.Observe(); !errors.Is(err, ErrBootChanged) || !errors.Is(err, ErrPoisoned) {
		t.Fatalf("boot change error=%v", err)
	}
	if _, err := clock.Observe(); !errors.Is(err, ErrPoisoned) {
		t.Fatalf("poison not sticky: %v", err)
	}
}

func TestClockRejectsWallAndBoottimeRollback(t *testing.T) {
	base := time.Unix(1_800_000_000, 0).UTC()
	for _, tc := range []struct {
		name string
		next rawSample
	}{
		{name: "wall", next: raw(base.Add(-time.Nanosecond), 2*time.Second)},
		{name: "boottime", next: raw(base.Add(time.Second), time.Second-time.Nanosecond)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock, _, err := openWithSampler(sequence(raw(base, time.Second), tc.next))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := clock.Observe(); !errors.Is(err, ErrRollback) || !errors.Is(err, ErrPoisoned) {
				t.Fatalf("rollback error=%v", err)
			}
		})
	}
}

func TestObserveWithinRejectsForeignExcessiveAndDivergentWindows(t *testing.T) {
	base := time.Unix(1_800_000_000, 0).UTC()
	t.Run("foreign", func(t *testing.T) {
		clock, _, err := openWithSampler(sequence(raw(base, time.Second)))
		if err != nil {
			t.Fatal(err)
		}
		_, foreign, err := openWithSampler(sequence(raw(base, time.Second)))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := clock.ObserveWithin(foreign, time.Second, time.Second); !errors.Is(err, ErrForeign) || !errors.Is(err, ErrPoisoned) {
			t.Fatalf("foreign error=%v", err)
		}
	})
	t.Run("unsigned overflow", func(t *testing.T) {
		clock, first, err := openWithSampler(sequence(raw(base, time.Nanosecond), rawSample{wall: base.Add(time.Second), bootID: testBootID, boottimeNS: ^uint64(0)}))
		if err != nil {
			t.Fatal(err)
		}
		if _, err := clock.ObserveWithin(first, 30*time.Second, time.Second); !errors.Is(err, ErrWindow) || !errors.Is(err, ErrPoisoned) {
			t.Fatalf("overflow error=%v", err)
		}
	})
	for _, tc := range []struct {
		name string
		next rawSample
	}{
		{name: "excessive", next: raw(base.Add(31*time.Second), 32*time.Second)},
		{name: "divergent", next: raw(base.Add(10*time.Second), 2*time.Second)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			clock, first, err := openWithSampler(sequence(raw(base, time.Second), tc.next))
			if err != nil {
				t.Fatal(err)
			}
			if _, err := clock.ObserveWithin(first, 30*time.Second, time.Second); !errors.Is(err, ErrWindow) || !errors.Is(err, ErrPoisoned) {
				t.Fatalf("window error=%v", err)
			}
		})
	}
}

func TestNilAndZeroClockFailClosed(t *testing.T) {
	var nilClock *Clock
	if _, err := nilClock.Observe(); !errors.Is(err, ErrInvalid) {
		t.Fatalf("nil clock error=%v", err)
	}
	if _, err := (&Clock{}).Observe(); !errors.Is(err, ErrInvalid) || !errors.Is(err, ErrPoisoned) {
		t.Fatalf("zero clock error=%v", err)
	}
}

func TestClockRejectsInvalidSamplesAndBounds(t *testing.T) {
	base := time.Unix(1_800_000_000, 0).UTC()
	for _, sample := range []rawSample{
		{},
		{wall: base, bootID: "bad", boottimeNS: 1},
		{wall: base, bootID: testBootID, boottimeNS: 0},
	} {
		if _, _, err := openWithSampler(sequence(sample)); !errors.Is(err, ErrInvalid) {
			t.Fatalf("invalid sample error=%v sample=%+v", err, sample)
		}
	}
	clock, first, err := openWithSampler(sequence(raw(base, time.Second)))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := clock.ObserveWithin(first, maximumWindow+time.Second, 0); !errors.Is(err, ErrWindow) {
		t.Fatalf("bounds error=%v", err)
	}
}
