package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/netip"
	"os"
	"regexp"
	"strings"
	"time"
	"unicode/utf8"

	"chengwang/internal/probe"
)

const (
	probeEgressPolicySchema      = "chengwang.probe-egress-policy/v1"
	probeEgressDestinationSchema = "chengwang.probe-egress-destination/v1"
	maximumEgressPolicyBytes     = int64(64 << 10)
	maximumPolicyNotes           = 16
	maximumPolicyTextBytes       = 512

	egressDestinationFixedDoT     = "fixed-dot"
	egressDestinationCatalogProbe = "catalog-probe"
)

var (
	preflightSHA256Pattern      = regexp.MustCompile(`^[0-9a-f]{64}$`)
	policyRevisionPattern       = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9._-]{0,63}$`)
	attestationReferencePattern = regexp.MustCompile(`^evidence:[a-z0-9][a-z0-9._-]{0,127}$`)
)

type preflightConfig struct {
	catalogPath        string
	doTCAPath          string
	egressPolicyPath   string
	doTUpstream        netip.AddrPort
	doTServerName      string
	expectedCatalogSHA string
	expectedDoTCASHA   string
	expectedEgressSHA  string
}

// probeEgressPolicy is an administrative desired-state contract. Parsing it
// does not attest that a host ruleset is installed or effective. The external
// verifier remains responsible for binding a fresh runtime attestation to the
// policy, catalog, image, network namespace, boot identity, and counter deltas.
type probeEgressPolicy struct {
	Schema              string                          `json:"schema"`
	Revision            string                          `json:"revision"`
	Approval            probeEgressApproval             `json:"approval"`
	Enforcement         administrativeEgressExpectation `json:"enforcement"`
	AllowedDestinations []probeEgressDestination        `json:"allowedDestinations"`
	Notes               []string                        `json:"notes,omitempty"`
}

type probeEgressApproval struct {
	Status     string    `json:"status"`
	Owner      string    `json:"owner"`
	ApprovedAt time.Time `json:"approvedAt"`
}

// The v1 wire schema retains its original field names for compatibility. In
// this process they are declarations and an attestation reference only; their
// presence is never treated as proof of live enforcement.
type administrativeEgressExpectation struct {
	DesiredState   string `json:"state"`
	ExpectedMode   string `json:"mode"`
	AttestationRef string `json:"runtimeEvidence"`
}

// A destination is a closed reference, not an arbitrary URL. fixed-dot binds
// the exact public IP:853 and SNI. catalog-probe binds an approved probe ID to
// the digest of the complete validated catalog contract.
type probeEgressDestination struct {
	Schema        string `json:"schema"`
	Kind          string `json:"kind"`
	Endpoint      string `json:"endpoint,omitempty"`
	ServerName    string `json:"serverName,omitempty"`
	ProbeID       string `json:"probeId,omitempty"`
	CatalogDigest string `json:"catalogDigest,omitempty"`
}

func runPreflightCommand(args []string, output io.Writer, now func() time.Time) error {
	if output == nil {
		output = io.Discard
	}
	if now == nil {
		return errors.New("preflight current-time source is required")
	}
	if err := rejectAmbiguousArguments(args); err != nil {
		return err
	}
	flags := flag.NewFlagSet("probe-agent preflight", flag.ContinueOnError)
	flags.SetOutput(output)
	value := preflightConfig{}
	var upstream string
	flags.StringVar(&value.catalogPath, "catalog", "", "immutable probe catalog path")
	flags.StringVar(&value.doTCAPath, "dot-ca", "", "immutable DoT CA bundle path")
	flags.StringVar(&value.egressPolicyPath, "egress-policy", "", "immutable approved egress policy path")
	flags.StringVar(&upstream, "dot-upstream", "", "fixed public DoT endpoint as IP:853")
	flags.StringVar(&value.doTServerName, "dot-server-name", "", "TLS SNI name for the fixed DoT endpoint")
	flags.StringVar(&value.expectedCatalogSHA, "expected-catalog-sha256", "", "expected raw catalog SHA-256")
	flags.StringVar(&value.expectedDoTCASHA, "expected-dot-ca-sha256", "", "expected raw DoT CA SHA-256")
	flags.StringVar(&value.expectedEgressSHA, "expected-egress-policy-sha256", "", "expected raw egress-policy SHA-256")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return errors.New("preflight positional arguments are prohibited")
	}
	inputs := []struct{ name, value string }{
		{"catalog", value.catalogPath}, {"dot-ca", value.doTCAPath},
		{"egress-policy", value.egressPolicyPath}, {"dot-upstream", upstream},
		{"dot-server-name", value.doTServerName},
		{"expected-catalog-sha256", value.expectedCatalogSHA},
		{"expected-dot-ca-sha256", value.expectedDoTCASHA},
		{"expected-egress-policy-sha256", value.expectedEgressSHA},
	}
	for _, input := range inputs {
		if strings.TrimSpace(input.value) == "" {
			return fmt.Errorf("preflight --%s is required", input.name)
		}
		if input.value != strings.TrimSpace(input.value) {
			return fmt.Errorf("preflight --%s must not contain surrounding whitespace", input.name)
		}
	}
	for _, input := range inputs[5:] {
		if !preflightSHA256Pattern.MatchString(input.value) {
			return fmt.Errorf("preflight --%s must be 64 lowercase hexadecimal characters", input.name)
		}
	}
	parsedUpstream, err := netip.ParseAddrPort(upstream)
	if err != nil || !parsedUpstream.IsValid() || parsedUpstream.Port() != 853 {
		return errors.New("preflight --dot-upstream must be a fixed IP on port 853")
	}
	if err := probe.ValidatePublicIP(parsedUpstream.Addr()); err != nil {
		return errors.New("preflight --dot-upstream must be a permitted public IP on port 853")
	}
	value.doTUpstream = parsedUpstream
	return executePreflight(value, now().UTC())
}

func executePreflight(value preflightConfig, now time.Time) error {
	if now.IsZero() {
		return errors.New("preflight current time is invalid")
	}
	if err := ensureDistinctPreflightFiles(value.catalogPath, value.doTCAPath, value.egressPolicyPath); err != nil {
		return err
	}
	catalogRaw, err := readRegularFile(value.catalogPath, probe.MaxCatalogBytes)
	if err != nil {
		return fmt.Errorf("preflight catalog input is unsafe: %w", err)
	}
	caRaw, err := readRegularFile(value.doTCAPath, maxCAFileBytes)
	if err != nil {
		return fmt.Errorf("preflight DoT CA input is unsafe: %w", err)
	}
	policyRaw, err := readRegularFile(value.egressPolicyPath, maximumEgressPolicyBytes)
	if err != nil {
		return fmt.Errorf("preflight egress policy input is unsafe: %w", err)
	}
	if !matchesRawSHA256(catalogRaw, value.expectedCatalogSHA) {
		return errors.New("preflight catalog SHA-256 mismatch")
	}
	if !matchesRawSHA256(caRaw, value.expectedDoTCASHA) {
		return errors.New("preflight DoT CA SHA-256 mismatch")
	}
	if !matchesRawSHA256(policyRaw, value.expectedEgressSHA) {
		return errors.New("preflight egress policy SHA-256 mismatch")
	}

	catalog, err := probe.ParseCatalogBytes(catalogRaw)
	if err != nil {
		return fmt.Errorf("preflight catalog validation failed: %w", err)
	}
	roots, err := parseCAPoolBytes(caRaw)
	if err != nil {
		return fmt.Errorf("preflight DoT CA validation failed: %w", err)
	}
	if _, err := probe.NewFixedDoTResolver(probe.FixedDoTResolverConfig{
		Upstream: value.doTUpstream, ServerName: value.doTServerName,
		RootCAs: roots, Timeout: time.Second,
	}); err != nil {
		return fmt.Errorf("preflight fixed DoT contract is invalid: %w", err)
	}
	policy, err := parseProbeEgressPolicy(policyRaw)
	if err != nil {
		return err
	}
	return validateProbeEgressPolicy(policy, catalog, value.doTUpstream, value.doTServerName, now)
}

func parseProbeEgressPolicy(raw []byte) (probeEgressPolicy, error) {
	if int64(len(raw)) > maximumEgressPolicyBytes {
		return probeEgressPolicy{}, errors.New("preflight egress policy exceeds its size limit")
	}
	if err := rejectDuplicatePreflightJSONKeys(raw); err != nil {
		return probeEgressPolicy{}, err
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.DisallowUnknownFields()
	var policy probeEgressPolicy
	if err := decoder.Decode(&policy); err != nil {
		return probeEgressPolicy{}, errors.New("preflight egress policy JSON contains an unknown field or invalid value")
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return probeEgressPolicy{}, errors.New("preflight egress policy must contain exactly one JSON value")
	}
	return policy, nil
}

func validateProbeEgressPolicy(policy probeEgressPolicy, catalog probe.Catalog, upstream netip.AddrPort, serverName string, now time.Time) error {
	if policy.Schema != probeEgressPolicySchema {
		return errors.New("preflight egress policy schema is invalid")
	}
	if !policyRevisionPattern.MatchString(policy.Revision) {
		return errors.New("preflight egress policy revision is invalid")
	}
	if policy.Approval.Status != "approved" {
		return errors.New("preflight egress policy approval is not approved")
	}
	if err := validateBoundedPolicyText(policy.Approval.Owner, 128); err != nil {
		return errors.New("preflight egress policy approval owner is invalid")
	}
	if policy.Approval.ApprovedAt.IsZero() || policy.Approval.ApprovedAt.UnixNano() < 0 || policy.Approval.ApprovedAt.After(now) {
		return errors.New("preflight egress policy approval time is invalid or in the future")
	}
	if policy.Enforcement.DesiredState != "enforced" || policy.Enforcement.ExpectedMode != "default-deny" {
		return errors.New("preflight desired egress contract must declare state=enforced and mode=default-deny")
	}
	if !attestationReferencePattern.MatchString(policy.Enforcement.AttestationRef) {
		return errors.New("preflight egress policy attestation reference format is invalid")
	}
	if len(policy.Notes) > maximumPolicyNotes {
		return errors.New("preflight egress policy has too many notes")
	}
	for _, note := range policy.Notes {
		if err := validateBoundedPolicyText(note, maximumPolicyTextBytes); err != nil {
			return errors.New("preflight egress policy note is invalid")
		}
	}
	if len(policy.AllowedDestinations) == 0 || len(policy.AllowedDestinations) != len(catalog.Probes)+1 {
		return errors.New("preflight allowed destinations must contain one fixed DoT contract and every catalog probe")
	}

	probeIDs := make(map[string]struct{}, len(catalog.Probes))
	for _, target := range catalog.Probes {
		probeIDs[target.ID] = struct{}{}
	}
	seenProbeIDs := make(map[string]struct{}, len(catalog.Probes))
	fixedDoTCount := 0
	for index, destination := range policy.AllowedDestinations {
		if destination.Schema != probeEgressDestinationSchema {
			return fmt.Errorf("preflight allowed destination %d schema is invalid", index)
		}
		switch destination.Kind {
		case egressDestinationFixedDoT:
			if destination.ProbeID != "" || destination.CatalogDigest != "" {
				return fmt.Errorf("preflight allowed destination %d mixes fixed DoT and catalog fields", index)
			}
			endpoint, err := netip.ParseAddrPort(destination.Endpoint)
			if err != nil || !endpoint.IsValid() || endpoint.String() != destination.Endpoint || endpoint.Port() != 853 {
				return fmt.Errorf("preflight allowed destination %d has an invalid fixed DoT endpoint", index)
			}
			if err := probe.ValidatePublicIP(endpoint.Addr()); err != nil {
				return fmt.Errorf("preflight allowed destination %d fixed DoT endpoint is not public", index)
			}
			if endpoint != upstream || destination.ServerName != serverName {
				return fmt.Errorf("preflight allowed destination %d does not match the configured fixed DoT contract", index)
			}
			fixedDoTCount++
		case egressDestinationCatalogProbe:
			if destination.Endpoint != "" || destination.ServerName != "" {
				return fmt.Errorf("preflight allowed destination %d mixes catalog and endpoint fields", index)
			}
			if destination.CatalogDigest != catalog.Digest {
				return fmt.Errorf("preflight allowed destination %d catalog digest does not match", index)
			}
			if _, exists := probeIDs[destination.ProbeID]; !exists {
				return fmt.Errorf("preflight allowed destination %d does not reference an approved catalog probe", index)
			}
			if _, duplicate := seenProbeIDs[destination.ProbeID]; duplicate {
				return fmt.Errorf("preflight allowed destination %d duplicates a catalog probe", index)
			}
			seenProbeIDs[destination.ProbeID] = struct{}{}
		default:
			return fmt.Errorf("preflight allowed destination %d kind is invalid", index)
		}
	}
	if fixedDoTCount != 1 || len(seenProbeIDs) != len(probeIDs) {
		return errors.New("preflight allowed destinations are incomplete or duplicated")
	}
	return nil
}

func ensureDistinctPreflightFiles(paths ...string) error {
	infos := make([]os.FileInfo, len(paths))
	for index, path := range paths {
		if strings.TrimSpace(path) == "" || path != strings.TrimSpace(path) {
			return errors.New("preflight input path is missing or has surrounding whitespace")
		}
		info, err := os.Lstat(path)
		if err != nil {
			return errors.New("preflight input file cannot be inspected")
		}
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return errors.New("preflight input must be a non-symlink regular file")
		}
		infos[index] = info
	}
	for first := 0; first < len(infos); first++ {
		for second := first + 1; second < len(infos); second++ {
			if os.SameFile(infos[first], infos[second]) {
				return errors.New("preflight catalog, DoT CA, and egress policy must be distinct files")
			}
		}
	}
	return nil
}

func matchesRawSHA256(raw []byte, expected string) bool {
	digest := sha256.Sum256(raw)
	return hex.EncodeToString(digest[:]) == expected
}

func validateBoundedPolicyText(text string, maximum int) error {
	if text == "" || text != strings.TrimSpace(text) || len(text) > maximum || !utf8.ValidString(text) {
		return errors.New("text is empty, unbounded, or malformed")
	}
	if strings.IndexFunc(text, func(character rune) bool { return character < 0x20 || character == 0x7f }) >= 0 {
		return errors.New("text contains a control character")
	}
	return nil
}

func rejectDuplicatePreflightJSONKeys(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	if err := consumeStrictJSONValue(decoder); err != nil {
		return errors.New("preflight egress policy JSON contains a duplicate key or malformed value")
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return errors.New("preflight egress policy JSON has trailing data")
		}
		return fmt.Errorf("preflight egress policy JSON has invalid trailing data: %w", err)
	}
	return nil
}
