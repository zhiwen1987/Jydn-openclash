package mihomo

import (
	"fmt"
	"strings"

	"chengwang/internal/domain"
)

func Compare(desired domain.PolicyDraft, actual RuntimeSnapshot) ReadbackReport {
	drifts := make([]Drift, 0)
	groups := make(map[string]ProxyState, len(actual.Proxies))
	for _, proxy := range actual.Proxies {
		if proxy.All != nil {
			groups[proxy.Name] = proxy
		}
	}

	for index, pool := range desired.Pools {
		path := fmt.Sprintf("pools[%d]", index)
		group, exists := groups[pool.ID]
		if !exists {
			drifts = append(drifts, Drift{
				Kind: "missing_proxy_group", Path: path, Severity: "error",
				Expected: pool.ID, Message: "Mihomo 中缺少目标策略组",
			})
			continue
		}
		if !equalStrings(pool.Members, group.All) {
			drifts = append(drifts, Drift{
				Kind: "group_members_mismatch", Path: path + ".members", Severity: "error",
				Expected: append([]string(nil), pool.Members...), Actual: append([]string(nil), group.All...),
				Message: "策略组成员或顺序与目标状态不一致",
			})
		}
	}

	type actualRule struct {
		proxy string
	}
	rules := make(map[string]actualRule)
	for _, rule := range actual.Rules {
		if normalizeRuleType(rule.Type) != "domainsuffix" {
			continue
		}
		key := normalizeDomain(rule.Payload)
		if _, exists := rules[key]; !exists {
			rules[key] = actualRule{proxy: rule.Proxy}
		}
	}

	expectedRuleCount := 0
	for businessIndex, business := range desired.Businesses {
		for domainIndex, domainName := range business.Domains {
			expectedRuleCount++
			path := fmt.Sprintf("businesses[%d].domains[%d]", businessIndex, domainIndex)
			rule, exists := rules[normalizeDomain(domainName)]
			if !exists {
				drifts = append(drifts, Drift{
					Kind: "missing_domain_rule", Path: path, Severity: "error",
					Expected: map[string]string{"domain": domainName, "target": business.Strategy},
					Message:  "Mihomo 中缺少目标域名规则",
				})
				continue
			}
			if rule.proxy != business.Strategy {
				drifts = append(drifts, Drift{
					Kind: "rule_target_mismatch", Path: path, Severity: "error",
					Expected: business.Strategy, Actual: rule.proxy,
					Message: "域名规则的实际目标与期望策略不一致",
				})
			}
		}
	}

	if drifts == nil {
		drifts = []Drift{}
	}
	return ReadbackReport{
		ObservedAt:        actual.ObservedAt,
		ControllerVersion: actual.Version.Version,
		Match:             len(drifts) == 0,
		Counts: ReadbackCounts{
			ExpectedGroups: len(desired.Pools),
			ObservedGroups: len(groups),
			ExpectedRules:  expectedRuleCount,
			ObservedRules:  len(actual.Rules),
		},
		Drifts: drifts,
	}
}

func normalizeRuleType(value string) string {
	value = strings.ToLower(value)
	value = strings.ReplaceAll(value, "-", "")
	value = strings.ReplaceAll(value, "_", "")
	return value
}

func normalizeDomain(value string) string {
	return strings.ToLower(strings.TrimPrefix(strings.TrimSpace(value), "+."))
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
