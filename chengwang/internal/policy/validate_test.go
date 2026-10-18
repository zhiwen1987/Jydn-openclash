package policy

import (
	"strings"
	"testing"

	"chengwang/internal/domain"
)

func validDraft() domain.PolicyDraft {
	return domain.PolicyDraft{
		Name:  "test",
		Pools: []domain.NodePool{{ID: "chatgpt_pool", Name: "ChatGPT 专用节点池", Members: []string{"us-01"}}},
		Businesses: []domain.BusinessPolicy{{
			ID: "chatgpt", Name: "ChatGPT", Domains: []string{"chatgpt.com"}, Strategy: "chatgpt_pool",
			Candidates: []string{"chatgpt_pool", "DIRECT"}, SkipEmptyPools: true, FailuresToSwitch: 3, SwitchCooldownSec: 300,
		}},
		DNS: domain.DNSPolicy{DomesticResolvers: []string{"223.5.5.5"}, OverseasResolvers: []string{"https://1.1.1.1/dns-query"}},
	}
}

func TestValidateAcceptsWellFormedDraft(t *testing.T) {
	result := Validate(validDraft())
	if !result.Valid || len(result.Issues) != 0 {
		t.Fatalf("expected valid draft, got %#v", result)
	}
}

func TestValidateRejectsDanglingAndEmptyPool(t *testing.T) {
	draft := validDraft()
	draft.Businesses[0].Candidates = []string{"missing"}
	result := Validate(draft)
	if result.Valid || !hasCode(result, "business.pool.missing") {
		t.Fatalf("expected missing pool issue, got %#v", result)
	}

	draft = validDraft()
	draft.Pools[0].Members = nil
	draft.Businesses[0].SkipEmptyPools = false
	result = Validate(draft)
	if result.Valid || !hasCode(result, "business.pool.empty") {
		t.Fatalf("expected empty pool issue, got %#v", result)
	}
}

func TestCompileIsDeterministic(t *testing.T) {
	first, err := CompileMihomo(validDraft())
	if err != nil {
		t.Fatal(err)
	}
	second, err := CompileMihomo(validDraft())
	if err != nil || string(first) != string(second) {
		t.Fatal("compiler output is not deterministic")
	}
	if !strings.Contains(string(first), "DOMAIN-SUFFIX,chatgpt.com,chatgpt_pool") {
		t.Fatalf("unexpected artifact: %s", first)
	}
}

func hasCode(result domain.ValidationResult, code string) bool {
	for _, issue := range result.Issues {
		if issue.Code == code {
			return true
		}
	}
	return false
}
