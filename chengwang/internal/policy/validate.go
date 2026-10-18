package policy

import (
	"fmt"
	"net"
	"regexp"
	"sort"
	"strings"

	"chengwang/internal/domain"
)

var idPattern = regexp.MustCompile(`^[\pL\pN][\pL\pN._ -]{0,63}$`)

func Validate(draft domain.PolicyDraft) domain.ValidationResult {
	issues := make([]domain.ValidationIssue, 0)
	add := func(code, severity, path, message string) {
		issues = append(issues, domain.ValidationIssue{Code: code, Severity: severity, Path: path, Message: message})
	}

	if strings.TrimSpace(draft.Name) == "" {
		add("draft.name.required", "error", "name", "配置名称不能为空")
	}

	pools := map[string]domain.NodePool{}
	for i, pool := range draft.Pools {
		path := fmt.Sprintf("pools[%d]", i)
		if !idPattern.MatchString(pool.ID) {
			add("pool.id.invalid", "error", path+".id", "节点池 ID 格式无效")
		}
		if _, exists := pools[pool.ID]; exists {
			add("pool.id.duplicate", "error", path+".id", "节点池 ID 重复")
		}
		pools[pool.ID] = pool
	}

	seenBusinesses := map[string]struct{}{}
	for i, business := range draft.Businesses {
		path := fmt.Sprintf("businesses[%d]", i)
		if !idPattern.MatchString(business.ID) {
			add("business.id.invalid", "error", path+".id", "业务 ID 格式无效")
		}
		if _, exists := seenBusinesses[business.ID]; exists {
			add("business.id.duplicate", "error", path+".id", "业务 ID 重复")
		}
		seenBusinesses[business.ID] = struct{}{}

		if len(business.Domains) == 0 {
			add("business.domains.empty", "error", path+".domains", "业务至少需要一个域名")
		}
		for j, domainName := range business.Domains {
			if !validDomain(domainName) {
				add("business.domain.invalid", "error", fmt.Sprintf("%s.domains[%d]", path, j), "域名格式无效")
			}
		}

		choices := append([]string{business.Strategy}, business.Candidates...)
		for j, choice := range choices {
			if choice == "" {
				add("business.choice.empty", "error", fmt.Sprintf("%s.candidates[%d]", path, j), "策略选项不能为空")
				continue
			}
			if builtin(choice) {
				continue
			}
			pool, exists := pools[choice]
			if !exists {
				add("business.pool.missing", "error", path+".candidates", "引用了不存在的节点池: "+choice)
				continue
			}
			if len(pool.Members) == 0 && !business.SkipEmptyPools {
				add("business.pool.empty", "error", path+".candidates", "节点池为空且未启用跳过空池: "+choice)
			}
		}
		if business.FailuresToSwitch < 1 || business.FailuresToSwitch > 10 {
			add("business.failureThreshold.range", "error", path+".failuresToSwitch", "连续失败阈值必须在 1 到 10 之间")
		}
		if business.SwitchCooldownSec < 30 {
			add("business.cooldown.tooShort", "error", path+".switchCooldownSec", "切换冷却不得低于 30 秒")
		}
	}

	for _, resolver := range append(append([]string{}, draft.DNS.DomesticResolvers...), draft.DNS.OverseasResolvers...) {
		if net.ParseIP(resolver) == nil && !strings.HasPrefix(resolver, "https://") && !strings.HasPrefix(resolver, "tls://") {
			add("dns.resolver.invalid", "error", "dns", "解析器必须是 IP、https:// 或 tls:// 地址: "+resolver)
		}
	}

	sort.SliceStable(issues, func(i, j int) bool {
		if issues[i].Severity == issues[j].Severity {
			return issues[i].Path < issues[j].Path
		}
		return issues[i].Severity == "error"
	})
	valid := true
	for _, issue := range issues {
		if issue.Severity == "error" {
			valid = false
			break
		}
	}
	return domain.ValidationResult{Valid: valid, Issues: issues}
}

func builtin(value string) bool {
	switch value {
	case string(domain.StrategyDefault), string(domain.StrategyDirect), string(domain.StrategyReject), string(domain.StrategyStable), string(domain.StrategyAuto), string(domain.StrategyManual):
		return true
	default:
		return false
	}
}

func validDomain(value string) bool {
	value = strings.TrimSpace(strings.TrimPrefix(value, "+."))
	if len(value) < 2 || len(value) > 253 || strings.ContainsAny(value, " /:@") {
		return false
	}
	parts := strings.Split(value, ".")
	for _, part := range parts {
		if part == "" || len(part) > 63 || strings.HasPrefix(part, "-") || strings.HasSuffix(part, "-") {
			return false
		}
	}
	return true
}
