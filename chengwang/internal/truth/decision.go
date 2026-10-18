package truth

import (
	"math"
	"strings"
	"time"
)

type observationAssessment struct {
	freshness Freshness
	reasons   []BlockReason
}

// AssessObservation classifies an observation without mutating it. The time
// intervals are half-open: [ObservedAt, staleAt) is fresh, [staleAt,
// ExpiresAt) is stale, and ExpiresAt itself is expired.
func AssessObservation[T any](now time.Time, observed *Observed[T], policy Policy) (Freshness, []BlockReason) {
	assessment := assessObservation(now, observed, policy)
	return assessment.freshness, cloneReasons(assessment.reasons)
}

// Decide permits coordination only when all three state classes are present,
// Actual is authoritative, and Observed is fresh, evidenced, and sufficiently
// confident. It never promotes Observed, cache, or demo data into Actual.
func Decide[D, A, O any](now time.Time, desired *Desired[D], actual *Actual[A], observed *Observed[O], policy Policy) Decision {
	reasons := make([]BlockReason, 0, 4)

	if !validPolicy(policy) {
		reasons = append(reasons, reason(BlockInvalidPolicy, "policy", "新鲜度窗口和最低置信度策略无效"))
	}
	if desired == nil || !desired.Known {
		reasons = append(reasons, reason(BlockDesiredMissing, "desired", "缺少明确的期望状态"))
	}
	if actual == nil || !actual.Known {
		reasons = append(reasons, reason(BlockActualUnknown, "actual", "实际生效状态未知"))
	} else if !isAuthoritativeActualSource(actual.Source) {
		reasons = append(reasons, reason(BlockActualSourceUntrusted, "actual.source", "实际状态不是来自目标运行配置或设备读回"))
	}

	assessment := assessObservation(now, observed, policy)
	reasons = append(reasons, assessment.reasons...)

	return Decision{
		Allowed:     len(reasons) == 0 && assessment.freshness == FreshnessFresh,
		EvaluatedAt: now,
		Freshness:   assessment.freshness,
		Reasons:     reasons,
	}
}

func assessObservation[T any](now time.Time, observed *Observed[T], policy Policy) observationAssessment {
	if observed == nil || !observed.Known {
		return observationAssessment{
			freshness: FreshnessUnknown,
			reasons:   []BlockReason{reason(BlockObservedMissing, "observed", "缺少运行态观测")},
		}
	}

	reasons := make([]BlockReason, 0, 3)
	if strings.TrimSpace(observed.EvidenceRef) == "" {
		reasons = append(reasons, reason(BlockObservedEvidenceMissing, "observed.evidenceRef", "观测没有可追溯的证据引用"))
	}
	if !isTrustedObservationSource(observed.Source) {
		reasons = append(reasons, reason(BlockObservedSourceUntrusted, "observed.source", "观测来自缓存、演示或未知来源"))
	}
	if math.IsNaN(observed.Confidence) || math.IsInf(observed.Confidence, 0) || observed.Confidence < 0 || observed.Confidence > 1 {
		reasons = append(reasons, reason(BlockObservedConfidenceInvalid, "observed.confidence", "观测置信度必须位于 0 到 1 之间"))
	}
	if observed.ObservedAt.IsZero() || observed.ExpiresAt.IsZero() || !observed.ExpiresAt.After(observed.ObservedAt) {
		reasons = append(reasons, reason(BlockObservedTimeInvalid, "observed", "观测时间或失效时间无效"))
	}
	if !observed.ObservedAt.IsZero() && now.Before(observed.ObservedAt) {
		reasons = append(reasons, reason(BlockClockRollback, "observed.observedAt", "当前时间早于观测时间，可能发生时钟回拨"))
	}
	if !validPolicy(policy) {
		return observationAssessment{freshness: FreshnessUnknown, reasons: reasons}
	}
	if len(reasons) != 0 {
		return observationAssessment{freshness: FreshnessUnknown, reasons: reasons}
	}

	if !now.Before(observed.ExpiresAt) {
		return observationAssessment{
			freshness: FreshnessExpired,
			reasons:   []BlockReason{reason(BlockObservedExpired, "observed.expiresAt", "观测已经超过失效时间")},
		}
	}

	staleAt := observed.ObservedAt.Add(policy.FreshFor)
	// An overflow or wrap would make the temporal judgment unsafe.
	if staleAt.Before(observed.ObservedAt) {
		return observationAssessment{
			freshness: FreshnessUnknown,
			reasons:   []BlockReason{reason(BlockObservedTimeInvalid, "policy.freshFor", "新鲜度窗口导致无效时间范围")},
		}
	}
	if !now.Before(staleAt) {
		return observationAssessment{
			freshness: FreshnessStale,
			reasons:   []BlockReason{reason(BlockObservedStale, "observed.observedAt", "观测仍未失效，但已超过新鲜度窗口")},
		}
	}
	if observed.Confidence < policy.MinConfidence {
		return observationAssessment{
			freshness: FreshnessFresh,
			reasons:   []BlockReason{reason(BlockObservedConfidenceLow, "observed.confidence", "观测置信度低于协调阈值")},
		}
	}

	return observationAssessment{freshness: FreshnessFresh, reasons: []BlockReason{}}
}

func validPolicy(policy Policy) bool {
	return policy.FreshFor > 0 && !math.IsNaN(policy.MinConfidence) && !math.IsInf(policy.MinConfidence, 0) && policy.MinConfidence >= 0 && policy.MinConfidence <= 1
}

func isAuthoritativeActualSource(source Source) bool {
	switch source {
	case SourceRuntimeConfiguration, SourceDeviceReadback:
		return true
	default:
		return false
	}
}

func isTrustedObservationSource(source Source) bool {
	switch source {
	case SourceRuntimeAPI, SourceActiveProbe, SourceDeviceTelemetry, SourceDeviceReadback:
		return true
	default:
		return false
	}
}

func reason(code BlockCode, field, message string) BlockReason {
	return BlockReason{Code: code, Field: field, Message: message}
}

func cloneReasons(source []BlockReason) []BlockReason {
	if len(source) == 0 {
		return []BlockReason{}
	}
	result := make([]BlockReason, len(source))
	copy(result, source)
	return result
}
