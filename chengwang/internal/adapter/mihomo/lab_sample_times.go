package mihomo

import "time"

// LabSampleTimes contains only the observed start and completion of one
// non-atomic HTTP projection sample. These values prove neither freshness,
// projection stability, process ownership nor recovery authorization.
type LabSampleTimes struct {
	StartedAt   time.Time
	CompletedAt time.Time
}

// SampleTimes returns detached time values from the two opaque samples. It
// performs no request or current-clock check. Callers must separately compare
// the samples and enforce their own authorized operation's absolute window.
func (samples LabSamples) SampleTimes() ([2]LabSampleTimes, error) {
	var zero [2]LabSampleTimes
	if samples.core == nil || samples.core.requests != 8 {
		return zero, ErrLabReadbackInput
	}
	a, b := samples.core.samples[0], samples.core.samples[1]
	for _, sample := range [2]labSample{a, b} {
		digest, err := labProjectionDigest(sample.projection)
		if err != nil || digest != sample.digest || sample.witness == "" || sample.started.IsZero() || sample.completed.IsZero() {
			return zero, ErrLabReadbackInput
		}
	}
	if a.completed.Before(a.started) || b.started.Before(a.completed) || b.completed.Before(b.started) {
		return zero, ErrLabReadbackInput
	}
	return [2]LabSampleTimes{
		{StartedAt: a.started, CompletedAt: a.completed},
		{StartedAt: b.started, CompletedAt: b.completed},
	}, nil
}
