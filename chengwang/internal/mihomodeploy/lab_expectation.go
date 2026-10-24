package mihomodeploy

import (
	"bytes"
	"errors"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"

	"chengwang/internal/adapter/mihomo"
	"go.yaml.in/yaml/v3"
)

var errLabExpectationArtifact = errors.New("admitted laboratory artifact projection rejected")

// Only actual admitted canonical private artifact bytes supply this expected
// projection. It proves neither a running head, hidden endpoint application,
// authorization nor business availability. No response/YAML/secret is logged.
func labExpectationForArtifact(artifact *LabConfigArtifact) (mihomo.LabExpectation, error) {
	var zero mihomo.LabExpectation
	if artifact == nil || artifact.AdmissionError() != nil { return zero, errLabExpectationArtifact }
	raw := artifact.Bytes()
	var value labRawConfig
	decoder := yaml.NewDecoder(bytes.NewReader(raw)); decoder.KnownFields(true)
	if decoder.Decode(&value) != nil { return zero, errLabExpectationArtifact }
	var extra any
	if decoder.Decode(&extra) != io.EOF { return zero, errLabExpectationArtifact }
	host, port, err := net.SplitHostPort(value.ExternalController)
	parsed, parseErr := strconv.ParseUint(port, 10, 16)
	if err != nil || parseErr != nil || host != "127.0.0.1" || parsed < 1024 || uint16(parsed) == value.MixedPort || value.MixedPort < 1024 || !labSecret.MatchString(value.Secret) ||
		value.ExternalController != net.JoinHostPort(host, strconv.Itoa(int(parsed))) { return zero, errLabExpectationArtifact }
	basis := renderedLabConfig(value.MixedPort, uint16(parsed), value.Secret, value.Proxies, value.Groups, value.Rules)
	canonical, err := yaml.Marshal(basis)
	if err != nil || !bytes.Equal(canonical, raw) { return zero, errLabExpectationArtifact }
	spec := mihomo.LabExpectedSpec{MixedPort: value.MixedPort, HTTPNames: []string{}, Selectors: []mihomo.LabSelectorSpec{}, Rules: []mihomo.LabRuleSpec{}}
	endpoints := map[string]bool{}
	for index, proxy := range value.Proxies {
		address, err := netip.ParseAddr(proxy.Server)
		if err != nil || !address.Is4() || !address.IsLoopback() || proxy.Type != "http" || !labConfigID(proxy.Name) || proxy.Port < 1024 || proxy.Port == value.MixedPort || proxy.Port == uint16(parsed) { return zero, errLabExpectationArtifact }
		endpoint := net.JoinHostPort(address.String(), strconv.Itoa(int(proxy.Port)))
		// The compiler sorts definitions before rendering and rejects endpoint
		// aliases. Never silently sort a different private source into a DTO:
		// GLOBAL membership follows the original rendered definition order.
		if endpoints[endpoint] || (index > 0 && value.Proxies[index-1].Name >= proxy.Name) { return zero, errLabExpectationArtifact }
		endpoints[endpoint] = true
		spec.HTTPNames = append(spec.HTTPNames, proxy.Name)
	}
	for index, group := range value.Groups {
		if group.Type != "select" || (index > 0 && value.Groups[index-1].Name >= group.Name) { return zero, errLabExpectationArtifact }
		spec.Selectors = append(spec.Selectors, mihomo.LabSelectorSpec{Name: group.Name, Members: append([]string{}, group.Proxies...)})
	}
	for _, rule := range value.Rules {
		parts := strings.Split(rule, ",")
		if len(parts) == 3 && parts[0] == "DOMAIN-SUFFIX" {
			spec.Rules = append(spec.Rules, mihomo.LabRuleSpec{Type: "DomainSuffix", Payload: parts[1], Proxy: parts[2]})
		} else if len(parts) == 2 && parts[0] == "MATCH" {
			spec.Rules = append(spec.Rules, mihomo.LabRuleSpec{Type: "Match", Payload: "", Proxy: parts[1]})
		} else { return zero, errLabExpectationArtifact }
	}
	result, err := mihomo.NewLabExpectation(spec)
	if err != nil { return zero, errLabExpectationArtifact }
	return result, nil
}
