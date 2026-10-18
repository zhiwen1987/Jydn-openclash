package probe

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"strings"
	"testing"
)

type fakeResolver struct {
	addresses []netip.Addr
	err       error
	chain     []string
	cnameErr  error
	network   string
	host      string
}

func (r *fakeResolver) LookupCNAMEChain(_ context.Context, host string) ([]string, error) {
	r.host = host
	return append([]string(nil), r.chain...), r.cnameErr
}

func (r *fakeResolver) LookupNetIP(_ context.Context, network, host string) ([]netip.Addr, error) {
	r.network = network
	r.host = host
	return append([]netip.Addr(nil), r.addresses...), r.err
}

func TestValidatePublicIP(t *testing.T) {
	rejected := []string{
		"0.0.0.0", "127.0.0.1", "10.0.0.1", "100.64.0.1", "169.254.169.254",
		"168.63.129.16", "192.0.2.1", "198.19.0.1", "198.51.100.1", "203.0.113.1",
		"224.0.0.1", "240.0.0.1", "::", "::1", "::ffff:8.8.8.8", "fc00::1", "fe80::1",
		"ff02::1", "2001:db8::1", "64:ff9b::808:808",
		"3fff::1",
	}
	for _, text := range rejected {
		t.Run("reject_"+strings.ReplaceAll(text, ":", "_"), func(t *testing.T) {
			if err := ValidatePublicIP(netip.MustParseAddr(text)); err == nil {
				t.Fatalf("ValidatePublicIP(%s) accepted prohibited address", text)
			}
		})
	}
	for _, text := range []string{"8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"} {
		t.Run("allow_"+strings.ReplaceAll(text, ":", "_"), func(t *testing.T) {
			if err := ValidatePublicIP(netip.MustParseAddr(text)); err != nil {
				t.Fatalf("ValidatePublicIP(%s) error = %v", text, err)
			}
		})
	}
}

func TestResolveAndPinValidatesAllAnswers(t *testing.T) {
	target := validCatalog().Probes[0]
	resolver := &fakeResolver{chain: []string{target.Host + "."}, addresses: []netip.Addr{
		netip.MustParseAddr("9.9.9.9"),
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("9.9.9.9"),
	}}
	resolved, err := ResolveAndPin(context.Background(), resolver, target)
	if err != nil {
		t.Fatalf("ResolveAndPin() error = %v", err)
	}
	if resolver.network != "ip" || resolver.host != target.Host {
		t.Fatalf("unexpected lookup %q %q", resolver.network, resolver.host)
	}
	if resolved.IP != netip.MustParseAddr("1.1.1.1") || resolved.DialAddress != "1.1.1.1:443" {
		t.Fatalf("target was not deterministically pinned: %+v", resolved)
	}
	if resolved.ServerName != target.Host || resolved.Host != target.Host || len(resolved.ValidatedIPs) != 2 {
		t.Fatalf("SNI or validated addresses incorrect: %+v", resolved)
	}
	if err := ValidateResolvedTarget(target, resolved); err != nil {
		t.Fatalf("ValidateResolvedTarget() error = %v", err)
	}

	mixed := &fakeResolver{chain: []string{target.Host}, addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1"), netip.MustParseAddr("127.0.0.1")}}
	if _, err := ResolveAndPin(context.Background(), mixed, target); err == nil || !strings.Contains(err.Error(), "unsafe DNS answer") {
		t.Fatalf("mixed public/private answer error = %v", err)
	}

	tooMany := &fakeResolver{chain: []string{target.Host}}
	for i := 1; i <= MaxResolvedAddresses+1; i++ {
		tooMany.addresses = append(tooMany.addresses, netip.MustParseAddr("8.8.8.8"))
	}
	if _, err := ResolveAndPin(context.Background(), tooMany, target); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("oversized DNS answer error = %v", err)
	}

	failed := &fakeResolver{chain: []string{target.Host}, err: errors.New("offline")}
	if _, err := ResolveAndPin(context.Background(), failed, target); err == nil {
		t.Fatal("resolver error was ignored")
	}
}

func TestValidateResolvedTargetRejectsForgery(t *testing.T) {
	target := validCatalog().Probes[0]
	ip := netip.MustParseAddr("1.1.1.1")
	base := ResolvedTarget{
		TargetID: target.ID, Host: target.Host, CanonicalChain: []string{target.Host}, CanonicalName: target.Host, ServerName: target.Host, Port: target.Port,
		IP: ip, ValidatedIPs: []netip.Addr{ip}, DialAddress: "1.1.1.1:443",
	}
	tests := []struct {
		name   string
		mutate func(*ResolvedTarget)
	}{
		{"target ID", func(r *ResolvedTarget) { r.TargetID = "other" }},
		{"host", func(r *ResolvedTarget) { r.Host = "other.example.com" }},
		{"CNAME", func(r *ResolvedTarget) { r.CanonicalName = "other.example.com" }},
		{"SNI", func(r *ResolvedTarget) { r.ServerName = "other.example.com" }},
		{"port", func(r *ResolvedTarget) { r.Port = 8443 }},
		{"private selected", func(r *ResolvedTarget) { r.IP = netip.MustParseAddr("127.0.0.1") }},
		{"selected missing", func(r *ResolvedTarget) { r.ValidatedIPs = []netip.Addr{netip.MustParseAddr("8.8.8.8")} }},
		{"duplicate list", func(r *ResolvedTarget) { r.ValidatedIPs = []netip.Addr{ip, ip} }},
		{"forged dial", func(r *ResolvedTarget) { r.DialAddress = "8.8.8.8:443" }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			resolved := base
			resolved.ValidatedIPs = append([]netip.Addr(nil), base.ValidatedIPs...)
			test.mutate(&resolved)
			if err := ValidateResolvedTarget(target, resolved); err == nil {
				t.Fatal("ValidateResolvedTarget() accepted forged target")
			}
		})
	}
}

func TestResolveAndPinRequiresAllowlistedCanonicalName(t *testing.T) {
	target := validCatalog().Probes[0]
	resolver := &fakeResolver{
		chain:     []string{target.Host, "cdn.vendor.example."},
		addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")},
	}
	if _, err := ResolveAndPin(context.Background(), resolver, target); err == nil || !strings.Contains(err.Error(), "not allowlisted") {
		t.Fatalf("unapproved CNAME error = %v", err)
	}
	target.AllowedCNAMEs = []string{"cdn.vendor.example"}
	resolved, err := ResolveAndPin(context.Background(), resolver, target)
	if err != nil {
		t.Fatalf("allowlisted CNAME was rejected: %v", err)
	}
	if resolved.CanonicalName != "cdn.vendor.example" {
		t.Fatalf("canonical name = %q", resolved.CanonicalName)
	}
	loop := &fakeResolver{chain: []string{target.Host, "cdn.vendor.example", target.Host}, addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	if _, err := ResolveAndPin(context.Background(), loop, target); err == nil {
		t.Fatal("CNAME loop was accepted")
	}
	intermediate := &fakeResolver{chain: []string{target.Host, "unapproved.vendor.example", "cdn.vendor.example"}, addresses: []netip.Addr{netip.MustParseAddr("1.1.1.1")}}
	if _, err := ResolveAndPin(context.Background(), intermediate, target); err == nil {
		t.Fatal("unapproved intermediate CNAME was accepted")
	}
}

func TestNoRedirectPreservesResponse(t *testing.T) {
	if err := NoRedirect(nil, nil); !errors.Is(err, http.ErrUseLastResponse) {
		t.Fatalf("NoRedirect() error = %v", err)
	}
}
