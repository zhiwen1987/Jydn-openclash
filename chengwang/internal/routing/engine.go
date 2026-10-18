package routing

import (
	"fmt"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

type Engine struct {
	rules    []Rule
	resolver SetResolver
}

func NewEngine(rules []Rule, resolver SetResolver) (*Engine, error) {
	copyRules := append([]Rule(nil), rules...)
	ids := map[string]struct{}{}
	for _, rule := range copyRules {
		if rule.ID == "" || rule.Name == "" || rule.Action.Type == "" || rule.Action.Target == "" {
			return nil, fmt.Errorf("rule %q is incomplete", rule.ID)
		}
		if _, exists := ids[rule.ID]; exists {
			return nil, fmt.Errorf("duplicate rule %q", rule.ID)
		}
		ids[rule.ID] = struct{}{}
		if rule.Layer < LayerSafety || rule.Layer > LayerFallback {
			return nil, fmt.Errorf("rule %q has invalid layer", rule.ID)
		}
		for _, group := range rule.Groups {
			if group.Operator != MatchAny && group.Operator != MatchAll {
				return nil, fmt.Errorf("rule %q has invalid condition operator", rule.ID)
			}
		}
	}
	sort.SliceStable(copyRules, func(i, j int) bool {
		if copyRules[i].Layer == copyRules[j].Layer {
			return copyRules[i].Priority < copyRules[j].Priority
		}
		return copyRules[i].Layer < copyRules[j].Layer
	})
	return &Engine{rules: copyRules, resolver: resolver}, nil
}

func (e *Engine) Decide(traffic Traffic) Decision {
	traffic.Domain = normalizeDomain(traffic.Domain)
	traffic.Network = strings.ToLower(strings.TrimSpace(traffic.Network))
	for _, rule := range e.rules {
		if !rule.Enabled {
			continue
		}
		matched, evidence := e.matchRule(rule, traffic)
		if matched {
			return Decision{Matched: true, Action: rule.Action, Evidence: Evidence{
				RuleID: rule.ID, RuleName: rule.Name, Layer: rule.Layer, MatchedBy: evidence, Action: rule.Action,
			}}
		}
	}
	return Decision{}
}

func (e *Engine) matchRule(rule Rule, traffic Traffic) (bool, []string) {
	if len(rule.Groups) == 0 {
		return rule.Layer == LayerFallback, []string{"最终兜底"}
	}
	allEvidence := make([]string, 0)
	for _, group := range rule.Groups {
		matched, evidence := e.matchGroup(group, traffic)
		if !matched {
			return false, nil
		}
		allEvidence = append(allEvidence, evidence...)
	}
	return true, allEvidence
}

func (e *Engine) matchGroup(group ConditionGroup, traffic Traffic) (bool, []string) {
	if len(group.Conditions) == 0 {
		return false, nil
	}
	evidence := make([]string, 0)
	matchedCount := 0
	for _, condition := range group.Conditions {
		matched := e.matchCondition(condition, traffic)
		if condition.Not {
			matched = !matched
		}
		if matched {
			matchedCount++
			evidence = append(evidence, fmt.Sprintf("%s:%s", condition.Type, condition.Value))
		}
	}
	if group.Operator == MatchAny {
		return matchedCount > 0, evidence
	}
	return matchedCount == len(group.Conditions), evidence
}

func (e *Engine) matchCondition(condition Condition, traffic Traffic) bool {
	value := strings.TrimSpace(condition.Value)
	switch condition.Type {
	case DomainExact:
		return traffic.Domain == normalizeDomain(value)
	case DomainSuffix:
		suffix := normalizeDomain(strings.TrimPrefix(value, "+."))
		return traffic.Domain == suffix || strings.HasSuffix(traffic.Domain, "."+suffix)
	case DomainKeyword:
		return value != "" && strings.Contains(traffic.Domain, strings.ToLower(value))
	case GeoSite:
		return e.resolver != nil && e.resolver.InGeoSite(value, traffic.Domain)
	case IPCIDR:
		prefix, err := netip.ParsePrefix(value)
		return err == nil && traffic.DestinationIP.IsValid() && prefix.Contains(traffic.DestinationIP)
	case GeoIP:
		return e.resolver != nil && e.resolver.InGeoIP(value, traffic.DestinationIP)
	case ASN:
		return e.resolver != nil && e.resolver.InASN(value, traffic.DestinationIP)
	case SourceIP:
		prefix, err := netip.ParsePrefix(value)
		return err == nil && traffic.SourceIP.IsValid() && prefix.Contains(traffic.SourceIP)
	case SourceDevice:
		return strings.EqualFold(value, traffic.SourceDevice)
	case DestinationPort:
		port, err := strconv.ParseUint(value, 10, 16)
		return err == nil && uint16(port) == traffic.Port
	case Network:
		return strings.EqualFold(value, traffic.Network)
	case Process:
		return strings.EqualFold(value, traffic.Process)
	default:
		return false
	}
}

func normalizeDomain(value string) string {
	return strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
}
