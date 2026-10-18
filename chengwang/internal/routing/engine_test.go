package routing

import (
	"net/netip"
	"testing"
)

type fakeSets struct{}

func (fakeSets) InGeoSite(set, domain string) bool { return set == "cn" && domain == "baidu.com" }
func (fakeSets) InGeoIP(country string, ip netip.Addr) bool {
	return country == "CN" && netip.MustParsePrefix("1.0.1.0/24").Contains(ip)
}
func (fakeSets) InASN(asn string, ip netip.Addr) bool { return asn == "AS4134" && ip.IsValid() }

func rulesForTest() []Rule {
	return []Rule{
		{ID: "chatgpt", Name: "对话助手", Layer: LayerCustomBusiness, Priority: 20, Enabled: true, Groups: []ConditionGroup{{Operator: MatchAny, Conditions: []Condition{{Type: DomainSuffix, Value: "chatgpt.com"}, {Type: DomainSuffix, Value: "openai.com"}}}}, Action: Action{Type: "pool", Target: "ai_pool"}},
		{ID: "cn-domain", Name: "国内域名", Layer: LayerDomestic, Priority: 10, Enabled: true, Groups: []ConditionGroup{{Operator: MatchAny, Conditions: []Condition{{Type: DomainSuffix, Value: "cn"}, {Type: GeoSite, Value: "cn"}}}}, Action: Action{Type: "direct", Target: "DIRECT"}},
		{ID: "cn-ip", Name: "国内 IP", Layer: LayerDomestic, Priority: 20, Enabled: true, Groups: []ConditionGroup{{Operator: MatchAny, Conditions: []Condition{{Type: GeoIP, Value: "CN"}}}}, Action: Action{Type: "direct", Target: "DIRECT"}},
		{ID: "fallback", Name: "最终兜底", Layer: LayerFallback, Priority: 1, Enabled: true, Action: Action{Type: "pool", Target: "default_proxy"}},
	}
}

func TestCustomBusinessPrecedesGeographicFallback(t *testing.T) {
	engine, err := NewEngine(rulesForTest(), fakeSets{})
	if err != nil {
		t.Fatal(err)
	}
	decision := engine.Decide(Traffic{Domain: "api.chatgpt.com", DestinationIP: netip.MustParseAddr("1.0.1.8")})
	if decision.Action.Target != "ai_pool" || decision.Evidence.RuleID != "chatgpt" {
		t.Fatalf("custom business lost precedence: %#v", decision)
	}
}

func TestDomesticDomainAndIPRouteDirect(t *testing.T) {
	engine, _ := NewEngine(rulesForTest(), fakeSets{})
	for _, traffic := range []Traffic{
		{Domain: "developer.amd.com.cn"},
		{Domain: "unknown.example", DestinationIP: netip.MustParseAddr("1.0.1.9")},
	} {
		decision := engine.Decide(traffic)
		if decision.Action.Target != "DIRECT" {
			t.Fatalf("expected direct for %#v, got %#v", traffic, decision)
		}
	}
}

func TestFallbackIsDeterministic(t *testing.T) {
	engine, _ := NewEngine(rulesForTest(), fakeSets{})
	decision := engine.Decide(Traffic{Domain: "example.org"})
	if decision.Action.Target != "default_proxy" || decision.Evidence.RuleName != "最终兜底" {
		t.Fatalf("unexpected fallback: %#v", decision)
	}
}

func TestAllConditionsMustMatch(t *testing.T) {
	rules := []Rule{{ID: "device-process", Name: "设备应用", Layer: LayerCustomBusiness, Priority: 1, Enabled: true, Groups: []ConditionGroup{{Operator: MatchAll, Conditions: []Condition{{Type: SourceDevice, Value: "office-pc"}, {Type: Process, Value: "chrome.exe"}}}}, Action: Action{Type: "pool", Target: "work_pool"}}}
	engine, _ := NewEngine(rules, nil)
	if engine.Decide(Traffic{SourceDevice: "office-pc", Process: "firefox.exe"}).Matched {
		t.Fatal("partial all-group match must not route")
	}
	if !engine.Decide(Traffic{SourceDevice: "office-pc", Process: "chrome.exe"}).Matched {
		t.Fatal("complete all-group should route")
	}
}
