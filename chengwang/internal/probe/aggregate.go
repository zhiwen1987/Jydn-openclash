package probe

import (
	"sort"
	"time"
)

const (
	availabilitySuccessThreshold = 2
	unavailabilityFailThreshold  = 3
)

// ProbeAggregate is a conservative, advisory summary for exactly one probe
// and path. It never combines different businesses or promotes a path result
// to node health.
type ProbeAggregate struct {
	CatalogDigest      string            `json:"catalogDigest"`
	AgentID            string            `json:"agentId"`
	ProbeID            string            `json:"probeId"`
	PathID             string            `json:"pathId"`
	State              Conclusion        `json:"state"`
	Reason             string            `json:"reason"`
	ObservedAt         *time.Time        `json:"observedAt,omitempty"`
	ExpiresAt          *time.Time        `json:"expiresAt,omitempty"`
	ConsecutiveSuccess int               `json:"consecutiveSuccess"`
	ConsecutiveFailure int               `json:"consecutiveFailure"`
	Independence       IndependenceLevel `json:"independence"`
	AdvisoryOnly       bool              `json:"advisoryOnly"`
}

// AggregateByProbe reduces verified results without crossing probe or path
// boundaries. Expired evidence is unknown immediately. Two consecutive
// successes are required for available and three consecutive definitive
// transport failures for unavailable.
func AggregateByProbe(results []ProbeResult, now time.Time) []ProbeAggregate {
	type aggregateKey struct {
		CatalogDigest string
		AgentID       string
		Independence  IndependenceLevel
		ProbeID       string
		PathID        string
	}
	grouped := make(map[aggregateKey][]ProbeResult)
	for _, result := range results {
		if !result.AdvisoryOnly || !validSpoolCatalogDigest(result.CatalogDigest) || !idPattern.MatchString(result.AgentID) || !idPattern.MatchString(result.ProbeID) || !idPattern.MatchString(result.PathID) || result.Independence != IndependenceP1 {
			continue
		}
		key := aggregateKey{
			CatalogDigest: result.CatalogDigest, AgentID: result.AgentID,
			Independence: result.Independence, ProbeID: result.ProbeID, PathID: result.PathID,
		}
		grouped[key] = append(grouped[key], result)
	}

	aggregates := make([]ProbeAggregate, 0, len(grouped))
	for _, group := range grouped {
		sort.SliceStable(group, func(i, j int) bool {
			if group[i].CompletedAt.Equal(group[j].CompletedAt) {
				return group[i].RunID < group[j].RunID
			}
			return group[i].CompletedAt.Before(group[j].CompletedAt)
		})
		latest := group[len(group)-1]
		aggregate := ProbeAggregate{
			CatalogDigest: latest.CatalogDigest, AgentID: latest.AgentID,
			ProbeID: latest.ProbeID, PathID: latest.PathID,
			State: ConclusionUnknown, Reason: "insufficient_evidence",
			Independence: latest.Independence, AdvisoryOnly: true,
		}
		observedAt, expiresAt := latest.CompletedAt, latest.ExpiresAt
		aggregate.ObservedAt, aggregate.ExpiresAt = &observedAt, &expiresAt
		if now.IsZero() || !latest.ExpiresAt.After(now) || latest.CompletedAt.After(now) {
			aggregate.Reason = "evidence_stale_or_clock_invalid"
			aggregates = append(aggregates, aggregate)
			continue
		}

		for i := len(group) - 1; i >= 0; i-- {
			result := group[i]
			if !result.ExpiresAt.After(now) || result.CompletedAt.After(now) {
				break
			}
			if result.Conclusion == ConclusionAvailable && result.Outcome == OutcomePass {
				if aggregate.ConsecutiveFailure > 0 {
					break
				}
				aggregate.ConsecutiveSuccess++
				continue
			}
			if result.Conclusion == ConclusionUnavailable && result.Outcome == OutcomeFail {
				if aggregate.ConsecutiveSuccess > 0 {
					break
				}
				aggregate.ConsecutiveFailure++
				continue
			}
			break
		}

		switch latest.Conclusion {
		case ConclusionRestricted:
			aggregate.State, aggregate.Reason = ConclusionRestricted, latest.ErrorClass
		case ConclusionRateLimited:
			aggregate.State, aggregate.Reason = ConclusionRateLimited, "rate_limited"
		case ConclusionAvailable:
			if aggregate.ConsecutiveSuccess >= availabilitySuccessThreshold {
				aggregate.State, aggregate.Reason = ConclusionAvailable, "two_consecutive_contract_matches"
			} else {
				aggregate.State, aggregate.Reason = ConclusionDegraded, "awaiting_success_confirmation"
			}
		case ConclusionUnavailable:
			if aggregate.ConsecutiveFailure >= unavailabilityFailThreshold {
				aggregate.State, aggregate.Reason = ConclusionUnavailable, "three_consecutive_transport_failures"
			} else {
				aggregate.State, aggregate.Reason = ConclusionDegraded, "failure_below_unavailable_threshold"
			}
		default:
			aggregate.State = ConclusionUnknown
			if latest.ErrorClass != "" {
				aggregate.Reason = latest.ErrorClass
			}
		}
		aggregates = append(aggregates, aggregate)
	}
	sort.Slice(aggregates, func(i, j int) bool {
		if aggregates[i].CatalogDigest != aggregates[j].CatalogDigest {
			return aggregates[i].CatalogDigest < aggregates[j].CatalogDigest
		}
		if aggregates[i].AgentID != aggregates[j].AgentID {
			return aggregates[i].AgentID < aggregates[j].AgentID
		}
		if aggregates[i].ProbeID == aggregates[j].ProbeID {
			return aggregates[i].PathID < aggregates[j].PathID
		}
		return aggregates[i].ProbeID < aggregates[j].ProbeID
	})
	return aggregates
}
