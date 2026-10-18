package probe

import (
	"context"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

const MaxResolvedAddresses = 16

// DNSResolution is one resolver snapshot. The chain and address set must come
// from the same bounded resolution operation so DNS rebinding cannot occur
// between two independently fetched pieces of evidence.
type DNSResolution struct {
	CanonicalChain []string
	Addresses      []netip.Addr
}

// Resolver returns the complete, ordered CNAME chain and every A/AAAA address
// in one operation. net.Resolver is deliberately insufficient because
// LookupCNAME exposes only the final canonical name. Production must supply a
// fixed trusted resolver capable of returning the full bounded snapshot.
type Resolver interface {
	ResolveHost(ctx context.Context, host string) (DNSResolution, error)
}

// NoRedirect is suitable for http.Client.CheckRedirect. ErrUseLastResponse
// preserves the original 3xx response for classification without following it.
func NoRedirect(_ *http.Request, _ []*http.Request) error {
	return http.ErrUseLastResponse
}

// ResolveAndPin validates every DNS answer before selecting one immutable dial
// destination. ServerName remains the exact catalog hostname for TLS SNI.
func ResolveAndPin(ctx context.Context, resolver Resolver, target Target) (ResolvedTarget, error) {
	if err := ValidateTarget(target); err != nil {
		return ResolvedTarget{}, fmt.Errorf("invalid target: %w", err)
	}
	if resolver == nil {
		return ResolvedTarget{}, errors.New("resolver is nil")
	}
	snapshot, err := resolver.ResolveHost(ctx, target.Host)
	if err != nil {
		return ResolvedTarget{}, fmt.Errorf("resolve target snapshot: %w", err)
	}
	validatedChain, err := validateCanonicalChain(target, snapshot.CanonicalChain)
	if err != nil {
		return ResolvedTarget{}, err
	}
	canonical := validatedChain[len(validatedChain)-1]
	addresses := snapshot.Addresses
	if len(addresses) == 0 {
		return ResolvedTarget{}, errors.New("resolver returned no addresses")
	}
	if len(addresses) > MaxResolvedAddresses {
		return ResolvedTarget{}, fmt.Errorf("resolver returned more than %d addresses", MaxResolvedAddresses)
	}

	validated := make([]netip.Addr, 0, len(addresses))
	seen := make(map[netip.Addr]struct{}, len(addresses))
	for _, address := range addresses {
		if err := ValidatePublicIP(address); err != nil {
			// Reject the whole answer set: accepting only its public subset would
			// leave a mixed DNS-rebinding answer usable.
			return ResolvedTarget{}, fmt.Errorf("unsafe DNS answer: %w", err)
		}
		if _, duplicate := seen[address]; duplicate {
			continue
		}
		seen[address] = struct{}{}
		validated = append(validated, address)
	}
	if len(validated) == 0 {
		return ResolvedTarget{}, errors.New("resolver returned no unique addresses")
	}
	sort.Slice(validated, func(i, j int) bool { return validated[i].Compare(validated[j]) < 0 })
	selected := validated[0]
	result := ResolvedTarget{
		TargetID:       target.ID,
		Host:           target.Host,
		CanonicalChain: append([]string(nil), validatedChain...),
		CanonicalName:  canonical,
		ServerName:     target.Host,
		Port:           target.Port,
		IP:             selected,
		ValidatedIPs:   append([]netip.Addr(nil), validated...),
		DialAddress:    net.JoinHostPort(selected.String(), strconv.Itoa(int(target.Port))),
	}
	if err := ValidateResolvedTarget(target, result); err != nil {
		return ResolvedTarget{}, err
	}
	return result, nil
}

// ValidateResolvedTarget prevents a caller from forging a plan that bypasses
// ResolveAndPin. Runners must call it immediately before dialing.
func ValidateResolvedTarget(target Target, resolved ResolvedTarget) error {
	if err := ValidateTarget(target); err != nil {
		return fmt.Errorf("invalid target: %w", err)
	}
	if resolved.TargetID != target.ID || resolved.Host != target.Host || resolved.ServerName != target.Host || resolved.Port != target.Port {
		return errors.New("resolved target does not match catalog target")
	}
	validatedChain, err := validateCanonicalChain(target, resolved.CanonicalChain)
	if err != nil {
		return err
	}
	if resolved.CanonicalName != validatedChain[len(validatedChain)-1] {
		return errors.New("resolved canonical name does not match the validated chain")
	}
	if err := ValidatePublicIP(resolved.IP); err != nil {
		return fmt.Errorf("resolved IP: %w", err)
	}
	if len(resolved.ValidatedIPs) == 0 || len(resolved.ValidatedIPs) > MaxResolvedAddresses {
		return fmt.Errorf("validatedIps must contain 1-%d addresses", MaxResolvedAddresses)
	}
	selectedPresent := false
	seen := make(map[netip.Addr]struct{}, len(resolved.ValidatedIPs))
	for _, address := range resolved.ValidatedIPs {
		if err := ValidatePublicIP(address); err != nil {
			return fmt.Errorf("validated IP: %w", err)
		}
		if _, duplicate := seen[address]; duplicate {
			return errors.New("validatedIps contains a duplicate")
		}
		seen[address] = struct{}{}
		if address == resolved.IP {
			selectedPresent = true
		}
	}
	if !selectedPresent {
		return errors.New("selected IP is not in validatedIps")
	}
	expectedDialAddress := net.JoinHostPort(resolved.IP.String(), strconv.Itoa(int(target.Port)))
	if resolved.DialAddress != expectedDialAddress {
		return errors.New("dialAddress does not match the pinned IP and port")
	}
	return nil
}

func validateCanonicalChain(target Target, chain []string) ([]string, error) {
	if len(chain) < 1 || len(chain) > MaxAllowedCNAMEs+1 {
		return nil, fmt.Errorf("canonical chain must contain 1-%d names", MaxAllowedCNAMEs+1)
	}
	validated := make([]string, 0, len(chain))
	seen := make(map[string]struct{}, len(chain))
	for index, name := range chain {
		name = strings.ToLower(strings.TrimSuffix(name, "."))
		if err := validateExactHost(name); err != nil {
			return nil, fmt.Errorf("unsafe canonical chain entry: %w", err)
		}
		if index == 0 && name != target.Host {
			return nil, errors.New("canonical chain does not start with the catalog host")
		}
		if index > 0 && !containsExactString(target.AllowedCNAMEs, name) {
			return nil, fmt.Errorf("canonical name %q is not allowlisted", name)
		}
		if _, duplicate := seen[name]; duplicate {
			return nil, errors.New("canonical chain contains a loop or duplicate")
		}
		seen[name] = struct{}{}
		validated = append(validated, name)
	}
	return validated, nil
}

func containsExactString(values []string, wanted string) bool {
	for _, value := range values {
		if value == wanted {
			return true
		}
	}
	return false
}

// ValidatePublicIP permits only directly dialable global unicast addresses and
// explicitly excludes special-use, documentation, metadata, and mapped ranges.
func ValidatePublicIP(address netip.Addr) error {
	if !address.IsValid() {
		return errors.New("address is invalid")
	}
	if address.Is4In6() {
		return errors.New("IPv4-mapped IPv6 addresses are prohibited")
	}
	if !address.IsGlobalUnicast() || address.IsUnspecified() || address.IsLoopback() || address.IsPrivate() || address.IsLinkLocalUnicast() || address.IsLinkLocalMulticast() || address.IsMulticast() {
		return fmt.Errorf("address %s is not permitted global unicast", address)
	}
	for _, prefix := range prohibitedPrefixes {
		if prefix.Contains(address) {
			return fmt.Errorf("address %s is in prohibited range %s", address, prefix)
		}
	}
	for _, metadata := range prohibitedMetadataAddresses {
		if address == metadata {
			return fmt.Errorf("address %s is a metadata or platform service address", address)
		}
	}
	return nil
}

var prohibitedPrefixes = []netip.Prefix{
	netip.MustParsePrefix("0.0.0.0/8"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("192.0.0.0/24"),
	netip.MustParsePrefix("192.0.2.0/24"),
	netip.MustParsePrefix("192.88.99.0/24"),
	netip.MustParsePrefix("198.18.0.0/15"),
	netip.MustParsePrefix("198.51.100.0/24"),
	netip.MustParsePrefix("203.0.113.0/24"),
	netip.MustParsePrefix("240.0.0.0/4"),
	netip.MustParsePrefix("64:ff9b::/96"),
	netip.MustParsePrefix("64:ff9b:1::/48"),
	netip.MustParsePrefix("100::/64"),
	netip.MustParsePrefix("2001::/23"),
	netip.MustParsePrefix("2001:2::/48"),
	netip.MustParsePrefix("2001:db8::/32"),
	netip.MustParsePrefix("2002::/16"),
	netip.MustParsePrefix("3fff::/20"),
	netip.MustParsePrefix("fc00::/7"),
	netip.MustParsePrefix("fec0::/10"),
}

var prohibitedMetadataAddresses = []netip.Addr{
	netip.MustParseAddr("100.100.100.200"),
	netip.MustParseAddr("168.63.129.16"),
	netip.MustParseAddr("169.254.169.254"),
	netip.MustParseAddr("169.254.170.2"),
}
