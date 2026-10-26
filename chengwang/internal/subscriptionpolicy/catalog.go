// Package subscriptionpolicy loads immutable operator-owned subscription
// configuration. Loading and describing a directory never approves a source,
// writes an inventory, or dials a network. Only the application service owns
// durable approval and its scope/source-bound keyed policy digest.
package subscriptionpolicy

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"net/netip"
	"regexp"
	"sort"
	"strconv"
	"time"
	"unicode/utf8"

	"chengwang/internal/probe"
	"chengwang/internal/subscription"
	"chengwang/internal/subscriptionctl"
)

const MaxCatalogBytes = 256 << 10
const resolverTimeout = 5 * time.Second

var (
	ErrInvalid     = errors.New("subscription policy invalid")
	ErrUnsafe      = errors.New("subscription policy unsafe custody")
	ErrChanged     = errors.New("subscription policy changed during read")
	ErrUnsupported = errors.New("subscription policy secure load unsupported")
	ErrUnavailable = errors.New("subscription policy unavailable")
	ErrNotFound    = errors.New("subscription policy reference not found")
	ErrScopeDenied = errors.New("subscription policy scope denied")
	partPattern    = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$`)
	sourcePattern  = regexp.MustCompile(`^src_[a-f0-9]{32}$`)
	commandPattern = regexp.MustCompile(`^cmd_[a-f0-9]{32}$`)
)

type Owner struct{ UID, GID uint32 }

// Catalog has no exported private configuration. Its value and pointer forms
// both use constant formatting, including when nested in another object.
type Catalog struct{ core *catalogCore }

type catalogCore struct {
	scope    subscription.Scope
	resolver *probe.FixedDoTResolver
	sources  map[string]source
}

type source struct {
	config   sourceConfig
	roots    *x509.CertPool
	material []byte
}

type resolverConfig struct {
	Upstream   string `json:"upstream"`
	ServerName string `json:"serverName"`
	CAPEM      string `json:"caPEM"`
}

type sourceConfig struct {
	ReferenceID   string         `json:"referenceId"`
	Revision      uint64         `json:"revision"`
	SecretVersion string         `json:"secretVersion"`
	URL           string         `json:"url"`
	AllowedCNAMEs []string       `json:"allowedCnames"`
	CAPEM         string         `json:"caPEM"`
	Refresh       *refreshConfig `json:"refresh,omitempty"`
}

type refreshConfig struct {
	SourceID               string `json:"sourceId"`
	ApprovalID             string `json:"approvalId"`
	ApprovalSourceRevision uint64 `json:"approvalSourceRevision"`
	IntervalSeconds        uint64 `json:"intervalSeconds"`
	ApprovalTTLSeconds     uint64 `json:"approvalTtlSeconds"`
	MaxStaleSeconds        uint64 `json:"maxStaleSeconds"`
	MaxBackoffSeconds      uint64 `json:"maxBackoffSeconds"`
}

func (Catalog) String() string               { return "subscription trusted policy directory" }
func (Catalog) GoString() string             { return "subscription trusted policy directory" }
func (Catalog) MarshalJSON() ([]byte, error) { return []byte(`{}`), nil }

var _ subscriptionctl.PolicyProvider = (*Catalog)(nil)

func contextError(ctx context.Context) error {
	if ctx == nil {
		return ErrInvalid
	}
	return ctx.Err()
}

// ParseBytes accepts PRIVATE trusted configuration, not a body supplied by an
// HTTP caller. Runtime configuration must enter through LoadSecure. This pure
// constructor performs no dialing, approval, persistence, or environment edit.
func ParseBytes(raw []byte) (*Catalog, error) {
	if len(raw) == 0 || len(raw) > MaxCatalogBytes || !utf8.Valid(raw) {
		return nil, ErrInvalid
	}
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	budget := 0
	value, err := strictValue(decoder, 0, &budget)
	if err != nil {
		return nil, ErrInvalid
	}
	if _, err = decoder.Token(); err != io.EOF {
		return nil, ErrInvalid
	}
	root, ok := object(value, "version", "scope", "resolver", "sources")
	if !ok || uintValue(root["version"]) != 1 {
		return nil, ErrInvalid
	}
	scopeObject, ok := object(root["scope"], "tenantId", "siteId", "environment")
	if !ok {
		return nil, ErrInvalid
	}
	scope := subscription.Scope{TenantID: text(scopeObject["tenantId"]), SiteID: text(scopeObject["siteId"]), Environment: text(scopeObject["environment"])}
	if !validScope(scope) {
		return nil, ErrInvalid
	}
	resolverObject, ok := object(root["resolver"], "upstream", "serverName", "caPEM")
	if !ok {
		return nil, ErrInvalid
	}
	rc := resolverConfig{Upstream: text(resolverObject["upstream"]), ServerName: text(resolverObject["serverName"]), CAPEM: text(resolverObject["caPEM"])}
	if !stringFields(resolverObject) {
		return nil, ErrInvalid
	}
	upstream, err := netip.ParseAddrPort(rc.Upstream)
	if err != nil || upstream.String() != rc.Upstream || upstream.Addr().Zone() != "" || upstream.Addr().Is4In6() {
		return nil, ErrInvalid
	}
	resolverRoots, err := roots(rc.CAPEM)
	if err != nil {
		return nil, err
	}
	resolver, err := probe.NewFixedDoTResolver(probe.FixedDoTResolverConfig{Upstream: upstream, ServerName: rc.ServerName, RootCAs: resolverRoots, Timeout: resolverTimeout})
	if err != nil {
		return nil, ErrInvalid
	}
	entries, ok := root["sources"].([]any)
	if !ok || len(entries) == 0 || len(entries) > subscription.MaxSources {
		return nil, ErrInvalid
	}
	catalog := &Catalog{core: &catalogCore{scope: scope, resolver: resolver, sources: make(map[string]source, len(entries))}}
	for _, entry := range entries {
		fields, ok := object(entry, "referenceId", "revision", "secretVersion", "url", "allowedCnames", "caPEM")
		if !ok {
			fields, ok = object(entry, "referenceId", "revision", "secretVersion", "url", "allowedCnames", "caPEM", "refresh")
		}
		if !ok {
			return nil, ErrInvalid
		}
		config := sourceConfig{ReferenceID: text(fields["referenceId"]), Revision: uintValue(fields["revision"]), SecretVersion: text(fields["secretVersion"]), URL: text(fields["url"]), CAPEM: text(fields["caPEM"])}
		if !partPattern.MatchString(config.ReferenceID) || !partPattern.MatchString(config.SecretVersion) || config.Revision == 0 {
			return nil, ErrInvalid
		}
		if _, exists := catalog.core.sources[config.ReferenceID]; exists {
			return nil, ErrInvalid
		}
		if _, ok := fields["caPEM"].(string); !ok {
			return nil, ErrInvalid
		}
		if raw, exists := fields["refresh"]; exists {
			refresh, ok := object(raw, "sourceId", "approvalId", "approvalSourceRevision", "intervalSeconds", "approvalTtlSeconds", "maxStaleSeconds", "maxBackoffSeconds")
			if !ok {
				return nil, ErrInvalid
			}
			config.Refresh = &refreshConfig{SourceID: text(refresh["sourceId"]), ApprovalID: text(refresh["approvalId"]), ApprovalSourceRevision: uintValue(refresh["approvalSourceRevision"]), IntervalSeconds: uintValue(refresh["intervalSeconds"]), ApprovalTTLSeconds: uintValue(refresh["approvalTtlSeconds"]), MaxStaleSeconds: uintValue(refresh["maxStaleSeconds"]), MaxBackoffSeconds: uintValue(refresh["maxBackoffSeconds"])}
			if !sourcePattern.MatchString(config.Refresh.SourceID) || !commandPattern.MatchString(config.Refresh.ApprovalID) || config.Refresh.ApprovalSourceRevision == 0 ||
				config.Refresh.IntervalSeconds < uint64(subscription.MinRefreshInterval/time.Second) || config.Refresh.IntervalSeconds > uint64(subscription.MaxRefreshInterval/time.Second) ||
				config.Refresh.ApprovalTTLSeconds < uint64(subscription.MinRefreshInterval/time.Second) || config.Refresh.ApprovalTTLSeconds > uint64(subscription.MaxApprovalTTL/time.Second) ||
				config.Refresh.MaxStaleSeconds < config.Refresh.IntervalSeconds || config.Refresh.MaxStaleSeconds > uint64(subscription.MaxApprovalTTL/time.Second) ||
				config.Refresh.MaxBackoffSeconds < config.Refresh.IntervalSeconds || config.Refresh.MaxBackoffSeconds > uint64(subscription.MaxRefreshInterval/time.Second) {
				return nil, ErrInvalid
			}
		}
		aliases, ok := fields["allowedCnames"].([]any)
		if !ok || len(aliases) > probe.MaxAllowedCNAMEs {
			return nil, ErrInvalid
		}
		config.AllowedCNAMEs = make([]string, 0, len(aliases))
		seen := make(map[string]bool, len(aliases))
		for _, alias := range aliases {
			name, ok := alias.(string)
			if !ok || seen[name] {
				return nil, ErrInvalid
			}
			seen[name] = true
			config.AllowedCNAMEs = append(config.AllowedCNAMEs, name)
		}
		sort.Strings(config.AllowedCNAMEs)
		pool, err := roots(config.CAPEM)
		if err != nil {
			return nil, err
		}
		policy := subscription.SourcePolicy{Scope: scope, SourceID: "src_00000000000000000000000000000000", URL: config.URL, AllowedCNAMEs: config.AllowedCNAMEs}
		if _, err := subscription.NewFetcher(policy, subscription.FetchConfig{Resolver: resolver, RootCAs: pool}); err != nil {
			return nil, ErrInvalid
		}
		// A struct fixes field order; sorted allowlists have identical effective
		// membership. Inline PEM bytes remain conservatively bound verbatim.
		materialSource := struct {
			ReferenceID   string   `json:"referenceId"`
			Revision      uint64   `json:"revision"`
			SecretVersion string   `json:"secretVersion"`
			URL           string   `json:"url"`
			AllowedCNAMEs []string `json:"allowedCnames"`
			CAPEM         string   `json:"caPEM"`
		}{config.ReferenceID, config.Revision, config.SecretVersion, config.URL, config.AllowedCNAMEs, config.CAPEM}
		material, err := json.Marshal(struct {
			Version                int                `json:"version"`
			Scope                  subscription.Scope `json:"scope"`
			Source                 any                `json:"source"`
			Resolver               resolverConfig     `json:"resolver"`
			ResolverTimeoutSeconds int                `json:"resolverTimeoutSeconds"`
		}{1, scope, materialSource, rc, 5})
		if err != nil {
			return nil, ErrInvalid
		}
		catalog.core.sources[config.ReferenceID] = source{config: config, roots: pool, material: material}
	}
	return catalog, nil
}

func validScope(scope subscription.Scope) bool {
	return partPattern.MatchString(scope.TenantID) && partPattern.MatchString(scope.SiteID) && partPattern.MatchString(scope.Environment)
}

func roots(raw string) (*x509.CertPool, error) {
	if len(raw) == 0 || len(raw) > 65536 {
		return nil, ErrInvalid
	}
	pool, count := x509.NewCertPool(), 0
	remaining := []byte(raw)
	for len(bytes.TrimSpace(remaining)) > 0 {
		remaining = bytes.TrimSpace(remaining)
		if !bytes.HasPrefix(remaining, []byte("-----BEGIN CERTIFICATE-----")) {
			return nil, ErrInvalid
		}
		end := bytes.Index(remaining, []byte("-----END CERTIFICATE-----"))
		if end < 0 {
			return nil, ErrInvalid
		}
		end += len("-----END CERTIFICATE-----")
		fragment := remaining[:end]
		if bytes.Count(fragment, []byte("-----BEGIN CERTIFICATE-----")) != 1 {
			return nil, ErrInvalid
		}
		block, rest := pem.Decode(fragment)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 || len(bytes.TrimSpace(rest)) != 0 {
			return nil, ErrInvalid
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA || !certificate.BasicConstraintsValid {
			return nil, ErrInvalid
		}
		pool.AddCert(certificate)
		count++
		if count > 32 {
			return nil, ErrInvalid
		}
		remaining = remaining[end:]
	}
	if count == 0 {
		return nil, ErrInvalid
	}
	return pool, nil
}

// Scope returns only the immutable scope value, without I/O or private data.
func (catalog *Catalog) Scope() subscription.Scope {
	if catalog == nil || catalog.core == nil {
		return subscription.Scope{}
	}
	return catalog.core.scope
}

func (catalog *Catalog) Describe(reference string) (subscriptionctl.PolicyDescriptor, error) {
	if catalog == nil || catalog.core == nil {
		return subscriptionctl.PolicyDescriptor{}, ErrUnavailable
	}
	entry, ok := catalog.core.sources[reference]
	if !ok {
		return subscriptionctl.PolicyDescriptor{}, ErrNotFound
	}
	return subscriptionctl.PolicyDescriptor{ReferenceID: entry.config.ReferenceID, Revision: entry.config.Revision, Material: append([]byte(nil), entry.material...)}, nil
}

// Fetch is not an approval API. Its caller must first enforce its own durable
// scope/source-bound approval. No resolver, transport or dial hook is accepted.
func (catalog *Catalog) Fetch(ctx context.Context, scope subscription.Scope, sourceID, reference string) (subscription.FetchResult, error) {
	if err := contextError(ctx); err != nil {
		return subscription.FetchResult{}, err
	}
	if catalog == nil || catalog.core == nil {
		return subscription.FetchResult{}, ErrUnavailable
	}
	if scope != catalog.core.scope {
		return subscription.FetchResult{}, ErrScopeDenied
	}
	if !sourcePattern.MatchString(sourceID) {
		return subscription.FetchResult{}, ErrInvalid
	}
	entry, ok := catalog.core.sources[reference]
	if !ok {
		return subscription.FetchResult{}, ErrNotFound
	}
	fetcher, err := subscription.NewFetcher(subscription.SourcePolicy{Scope: scope, SourceID: sourceID, URL: entry.config.URL, AllowedCNAMEs: entry.config.AllowedCNAMEs}, subscription.FetchConfig{Resolver: catalog.core.resolver, RootCAs: entry.roots})
	if err != nil {
		return subscription.FetchResult{}, ErrInvalid
	}
	return fetcher.Fetch(ctx)
}

func object(value any, keys ...string) (map[string]any, bool) {
	m, ok := value.(map[string]any)
	if !ok || len(m) != len(keys) {
		return nil, false
	}
	for _, key := range keys {
		if _, exists := m[key]; !exists {
			return nil, false
		}
	}
	return m, true
}
func text(value any) string { result, _ := value.(string); return result }
func stringFields(fields map[string]any) bool {
	for _, value := range fields {
		if _, ok := value.(string); !ok {
			return false
		}
	}
	return true
}
func uintValue(value any) uint64 {
	number, ok := value.(json.Number)
	if !ok {
		return 0
	}
	result, err := strconv.ParseUint(string(number), 10, 64)
	if err != nil {
		return 0
	}
	return result
}

func strictValue(decoder *json.Decoder, depth int, count *int) (any, error) {
	*count++
	if depth > 16 || *count > 32768 {
		return nil, ErrInvalid
	}
	token, err := decoder.Token()
	if err != nil {
		return nil, ErrInvalid
	}
	delim, container := token.(json.Delim)
	if !container {
		return token, nil
	}
	switch delim {
	case '{':
		value := make(map[string]any)
		for decoder.More() {
			key, err := decoder.Token()
			if err != nil {
				return nil, ErrInvalid
			}
			name, ok := key.(string)
			if !ok {
				return nil, ErrInvalid
			}
			if _, exists := value[name]; exists {
				return nil, ErrInvalid
			}
			item, err := strictValue(decoder, depth+1, count)
			if err != nil {
				return nil, err
			}
			value[name] = item
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim('}') {
			return nil, ErrInvalid
		}
		return value, nil
	case '[':
		value := make([]any, 0)
		for decoder.More() {
			item, err := strictValue(decoder, depth+1, count)
			if err != nil {
				return nil, err
			}
			value = append(value, item)
		}
		end, err := decoder.Token()
		if err != nil || end != json.Delim(']') {
			return nil, ErrInvalid
		}
		return value, nil
	default:
		return nil, ErrInvalid
	}
}
