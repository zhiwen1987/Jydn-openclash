package mihomo

// This separate comparison names one selected target. It does not distinguish
// an old epoch from a new epoch or prove the full private configuration.
type LabTargetReadbackConclusion string

const (
	LabTargetProjectionMatched  LabTargetReadbackConclusion = "TARGET_PROJECTION_MATCHED"
	LabTargetProjectionDrift    LabTargetReadbackConclusion = "TARGET_PROJECTION_DRIFT"
	LabTargetProjectionUnstable LabTargetReadbackConclusion = "TARGET_PROJECTION_UNSTABLE"
)

// This DTO is only a bounded HTTP projection report. It is not a constructor
// for a process identity, recovery fact, authorization or completed new head.
type LabTargetReadbackReport struct {
	Schema                   string                      `json:"schema"`
	Conclusion               LabTargetReadbackConclusion `json:"conclusion"`
	SampleCount              int                         `json:"sampleCount"`
	RequestsObserved         int                         `json:"requestsObserved"`
	TargetProjectionSHA256   string                      `json:"targetProjectionSHA256"`
	ObservedProjectionSHA256 *string                     `json:"observedProjectionSHA256"`
	DataplaneProven          bool                        `json:"dataplaneProven"`
	FullPayloadProven        bool                        `json:"fullPayloadProven"`
	AuthorizationProven      bool                        `json:"authorizationProven"`
	Production               bool                        `json:"production"`
}

// CompareLabTargetReadback reuses the original sample, expectation, digest,
// witness, time-order and exact eight-request checks. Equal expectations are
// intentionally still AMBIGUOUS in CompareLabReadback; here that result only
// means the observed projection matches the one explicitly selected target.
func CompareLabTargetReadback(samples LabSamples, target LabExpectation) (LabTargetReadbackReport, error) {
	comparison, err := CompareLabReadback(samples, target, target)
	if err != nil {
		return LabTargetReadbackReport{}, err
	}
	return labTargetReadbackFromComparison(comparison)
}

func labTargetReadbackFromComparison(comparison LabReadbackReport) (LabTargetReadbackReport, error) {
	if comparison.SampleCount != 2 || comparison.RequestsObserved != 8 || comparison.PreviousProjectionSHA256 == "" || comparison.PreviousProjectionSHA256 != comparison.CandidateProjectionSHA256 || comparison.DataplaneProven || comparison.FullPayloadProven || comparison.AuthorizationProven || comparison.Production {
		return LabTargetReadbackReport{}, ErrLabReadbackInput
	}
	r := LabTargetReadbackReport{
		Schema:                 "chengwang.mihomo-selected-target-readback/v1",
		SampleCount:            2,
		RequestsObserved:       8,
		TargetProjectionSHA256: comparison.CandidateProjectionSHA256,
	}
	switch comparison.Conclusion {
	case LabProjectionAmbiguous:
		if comparison.ObservedProjectionSHA256 == nil || *comparison.ObservedProjectionSHA256 != r.TargetProjectionSHA256 {
			return LabTargetReadbackReport{}, ErrLabReadbackInput
		}
		r.Conclusion = LabTargetProjectionMatched
	case LabProjectionDrift:
		if comparison.ObservedProjectionSHA256 == nil || *comparison.ObservedProjectionSHA256 == r.TargetProjectionSHA256 {
			return LabTargetReadbackReport{}, ErrLabReadbackInput
		}
		r.Conclusion = LabTargetProjectionDrift
	case LabProjectionUnstable:
		if comparison.ObservedProjectionSHA256 != nil {
			return LabTargetReadbackReport{}, ErrLabReadbackInput
		}
		r.Conclusion = LabTargetProjectionUnstable
	default:
		// STABLE_NEW/OLD would contradict this equal-target comparison, and
		// future conclusions require an explicit versioned interpretation.
		return LabTargetReadbackReport{}, ErrLabReadbackInput
	}
	if comparison.ObservedProjectionSHA256 != nil {
		digest := *comparison.ObservedProjectionSHA256
		r.ObservedProjectionSHA256 = &digest
	}
	return r, nil
}
