package proxyiface

import (
	"testing"

	"chengwang/internal/domain"
)

func validInterface() domain.ProxyInterface {
	return domain.ProxyInterface{
		ID: "lan_mixed", Name: "局域网 Mixed", Type: "mixed", Core: "Mihomo",
		Listen: "0.0.0.0", Port: 7890, UDP: true, LANAccess: true,
		AuthMode: "password", AuthReference: "lan-proxy-users", Enabled: true,
		AccessScope: "lan", MaxConnections: 512, IdleTimeoutSec: 300,
		AuditEnabled: true, RoutingProfile: "家庭主网",
	}
}

func TestValidInterfaceSet(t *testing.T) {
	result := Validate([]domain.ProxyInterface{validInterface(), {
		ID: "control_api", Name: "控制 API", Type: "api", Core: "Mihomo",
		Listen: "127.0.0.1", Port: 9090, AuthMode: "token", AuthReference: "local-admin-token",
		AccessScope: "local", Enabled: true, RoutingProfile: "家庭主网",
	}})
	if !result.Valid || len(result.Issues) != 0 {
		t.Fatalf("expected valid configuration, got %+v", result)
	}
}

func TestRejectsDuplicateBinding(t *testing.T) {
	first := validInterface()
	second := first
	second.ID = "lan_http"
	second.Name = "局域网 HTTP"
	second.Type = "http"
	result := Validate([]domain.ProxyInterface{first, second})
	assertIssue(t, result, "binding_conflict")
}

func TestRejectsUnauthenticatedLANProxy(t *testing.T) {
	item := validInterface()
	item.AuthMode = "none"
	item.AuthReference = ""
	result := Validate([]domain.ProxyInterface{item})
	assertIssue(t, result, "lan_auth_required")
}

func TestRejectsInsecureRemoteAPI(t *testing.T) {
	item := validInterface()
	item.ID, item.Type, item.Name = "remote_api", "api", "远程 API"
	item.AuthMode, item.AuthReference, item.TLS = "password", "users", false
	result := Validate([]domain.ProxyInterface{item})
	assertIssue(t, result, "insecure_remote_api")
}

func TestRejectsPortOnTUN(t *testing.T) {
	item := validInterface()
	item.ID, item.Type, item.Name = "main_tun", "tun", "主 TUN"
	item.Listen, item.Port, item.LANAccess, item.AuthMode, item.AuthReference = "chengwang0", 7890, false, "none", ""
	result := Validate([]domain.ProxyInterface{item})
	assertIssue(t, result, "tun_port_forbidden")
}

func assertIssue(t *testing.T, result domain.ValidationResult, code string) {
	t.Helper()
	for _, current := range result.Issues {
		if current.Code == code {
			return
		}
	}
	t.Fatalf("expected issue %q, got %+v", code, result)
}
