// Package refresh downloads bounded catalogue candidates from one independently
// configured HTTPS source. It is not TUF and does not authenticate catalogue
// signatures, mutate Stores, mark trust fresh, or authorize deployments.
package refresh

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"errors"
	"io"
	"mime"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"sync/atomic"
	"time"
)

const MaxCatalogueBytes = 256 << 10
const MaxBatchBytes = 4 << 20
const MaxBatchGenerations = 64

var ErrInvalid = errors.New("invalid catalogue refresh configuration")
var ErrFetch = errors.New("catalogue refresh rejected")
var ErrBusy = errors.New("catalogue refresh already running")

type Config struct {
	BaseURL  string
	IP       string
	SPKI     string
	Roots    *x509.CertPool
	Interval time.Duration
	MaxAge   time.Duration
	Timeout  time.Duration
}
type Client struct {
	base                      string
	host                      string
	address                   string
	dialAddress               string
	spki                      [32]byte
	roots                     *x509.CertPool
	interval, maxAge, timeout time.Duration
	busy                      atomic.Bool
	running                   atomic.Bool
}

func New(config Config) (*Client, error) {
	if config.Roots == nil || len(config.BaseURL) > 2048 {
		return nil, ErrInvalid
	}
	if config.Interval == 0 {
		config.Interval = time.Minute
	}
	if config.MaxAge == 0 {
		config.MaxAge = 5 * time.Minute
	}
	if config.Timeout == 0 {
		config.Timeout = 30 * time.Second
	}
	if config.Interval < time.Second || config.Interval > time.Hour || config.MaxAge < config.Interval || config.MaxAge > time.Hour || config.Timeout < 100*time.Millisecond || config.Timeout > 2*time.Minute {
		return nil, ErrInvalid
	}
	u, err := url.Parse(config.BaseURL)
	if err != nil || u.Scheme != "https" || u.Host == "" || u.User != nil || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || u.RawFragment != "" || u.Opaque != "" || u.RawPath != "" || strings.ContainsAny(config.BaseURL, "\\%#\r\n\t ") || u.Host != strings.ToLower(u.Host) {
		return nil, ErrInvalid
	}
	host := u.Hostname()
	if host == "" || !validHost(host) {
		return nil, ErrInvalid
	}
	port := u.Port()
	if port == "" {
		if strings.HasSuffix(u.Host, ":") {
			return nil, ErrInvalid
		}
		port = "443"
	} else {
		n, err := strconv.ParseUint(port, 10, 16)
		if err != nil || n == 0 || strconv.FormatUint(n, 10) != port {
			return nil, ErrInvalid
		}
	}
	if u.Host != host && u.Host != net.JoinHostPort(host, port) && u.Host != "["+host+"]" {
		return nil, ErrInvalid
	}
	if u.Path != "" && (u.Path[0] != '/' || strings.Contains(u.Path, "//")) {
		return nil, ErrInvalid
	}
	for _, part := range strings.Split(u.Path, "/") {
		if part == "." || part == ".." {
			return nil, ErrInvalid
		}
		for _, ch := range part {
			if !(ch >= 'a' && ch <= 'z' || ch >= 'A' && ch <= 'Z' || ch >= '0' && ch <= '9' || ch == '-' || ch == '_' || ch == '.') {
				return nil, ErrInvalid
			}
		}
	}
	ip, err := netip.ParseAddr(config.IP)
	if err != nil || ip.String() != config.IP || ip.Zone() != "" || ip.Is4In6() || ip.IsMulticast() || ip.IsUnspecified() {
		return nil, ErrInvalid
	}
	if !digestValid(config.SPKI) {
		return nil, ErrInvalid
	}
	pin, err := hex.DecodeString(config.SPKI[7:])
	if err != nil {
		return nil, ErrInvalid
	}
	c := &Client{base: strings.TrimSuffix(u.String(), "/") + "/", host: host, address: net.JoinHostPort(host, port), dialAddress: net.JoinHostPort(config.IP, port), roots: config.Roots.Clone(), interval: config.Interval, maxAge: config.MaxAge, timeout: config.Timeout}
	copy(c.spki[:], pin)
	return c, nil
}
func (c *Client) Interval() time.Duration {
	if c == nil {
		return 0
	}
	return c.interval
}
func (c *Client) MaxAge() time.Duration {
	if c == nil {
		return 0
	}
	return c.maxAge
}
func (c *Client) Timeout() time.Duration {
	if c == nil {
		return 0
	}
	return c.timeout
}

// Fetch treats generation only as an untrusted download hint. Every returned
// envelope MUST subsequently pass the real Store's sequential signed update.
// Same generation is a no-op only for an exact raw-envelope digest match.
// On any failure it returns no partial batch and no freshness assertion.
func (c *Client) Fetch(ctx context.Context, generation uint64, hash string) ([][]byte, error) {
	if c == nil || ctx == nil || ctx.Err() != nil || generation == 0 || !digestValid(hash) {
		return nil, ErrFetch
	}
	if !c.busy.CompareAndSwap(false, true) {
		return nil, ErrBusy
	}
	defer c.busy.Store(false)
	ctx, cancel := context.WithTimeout(ctx, c.timeout)
	defer cancel()
	transport := c.transport()
	defer transport.CloseIdleConnections()
	client := &http.Client{Transport: transport, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}
	latest, err := c.get(ctx, client, "latest.json", MaxCatalogueBytes)
	if err != nil {
		return nil, ErrFetch
	}
	next, ok := generationHint(latest)
	if !ok || next < generation {
		return nil, ErrFetch
	}
	if next == generation {
		if digest(latest) != hash || ctx.Err() != nil {
			return nil, ErrFetch
		}
		return [][]byte{}, nil
	}
	if next-generation > MaxBatchGenerations {
		return nil, ErrFetch
	}
	result := make([][]byte, 0, int(next-generation))
	total := len(latest)
	for expected := generation + 1; expected < next; expected++ {
		raw, err := c.get(ctx, client, strconv.FormatUint(expected, 10)+".json", MaxBatchBytes-total)
		if err != nil {
			return nil, ErrFetch
		}
		found, ok := generationHint(raw)
		if !ok || found != expected || len(raw) > MaxBatchBytes-total {
			return nil, ErrFetch
		}
		total += len(raw)
		result = append(result, raw)
	}
	if total > MaxBatchBytes || ctx.Err() != nil {
		return nil, ErrFetch
	}
	result = append(result, bytes.Clone(latest))
	return result, nil
}
func (c *Client) transport() *http.Transport {
	return &http.Transport{Proxy: nil, DisableCompression: true, DisableKeepAlives: true, ForceAttemptHTTP2: false, MaxResponseHeaderBytes: 16 << 10, ResponseHeaderTimeout: c.timeout, MaxConnsPerHost: 1,
		DialTLSContext: func(ctx context.Context, network, address string) (net.Conn, error) {
			if network != "tcp" || address != c.address {
				return nil, ErrFetch
			}
			conn, err := (&net.Dialer{Timeout: c.timeout}).DialContext(ctx, "tcp", c.dialAddress)
			if err != nil {
				return nil, ErrFetch
			}
			tlsConn := tls.Client(conn, &tls.Config{RootCAs: c.roots, ServerName: c.host, MinVersion: tls.VersionTLS12, NextProtos: []string{"http/1.1"}, VerifyConnection: func(state tls.ConnectionState) error {
				if len(state.PeerCertificates) == 0 {
					return ErrFetch
				}
				sum := sha256.Sum256(state.PeerCertificates[0].RawSubjectPublicKeyInfo)
				if subtle.ConstantTimeCompare(sum[:], c.spki[:]) != 1 {
					return ErrFetch
				}
				return nil
			}})
			if err := tlsConn.HandshakeContext(ctx); err != nil {
				conn.Close()
				return nil, ErrFetch
			}
			return tlsConn, nil
		},
	}
}
func (c *Client) get(ctx context.Context, client *http.Client, name string, limit int) ([]byte, error) {
	if limit > MaxCatalogueBytes {
		limit = MaxCatalogueBytes
	}
	if limit < 1 {
		return nil, ErrFetch
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.base+name, nil)
	if err != nil {
		return nil, ErrFetch
	}
	req.Header.Set("Accept", "application/json")
	req.Close = true
	response, err := client.Do(req)
	if err != nil {
		return nil, ErrFetch
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK || response.ContentLength < 1 || response.ContentLength > int64(limit) || len(response.TransferEncoding) != 0 || len(response.Trailer) != 0 || len(response.Header.Values("Trailer")) != 0 || len(response.Header.Values("Content-Encoding")) != 0 || len(response.Header.Values("Content-Type")) != 1 {
		return nil, ErrFetch
	}
	media, params, err := mime.ParseMediaType(response.Header.Get("Content-Type"))
	if err != nil || media != "application/json" || len(params) > 1 || len(params) == 1 && !strings.EqualFold(params["charset"], "utf-8") {
		return nil, ErrFetch
	}
	raw, err := io.ReadAll(io.LimitReader(response.Body, int64(limit)+1))
	if err != nil || len(raw) == 0 || len(raw) > limit || int64(len(raw)) != response.ContentLength || ctx.Err() != nil {
		return nil, ErrFetch
	}
	return raw, nil
}
func validHost(s string) bool {
	if ip, err := netip.ParseAddr(s); err == nil {
		return ip.Zone() == "" && !ip.Is4In6() && !ip.IsUnspecified() && !ip.IsMulticast() && ip.String() == s
	}
	if len(s) > 253 {
		return false
	}
	for _, part := range strings.Split(s, ".") {
		if len(part) == 0 || len(part) > 63 || part[0] == '-' || part[len(part)-1] == '-' {
			return false
		}
		for _, ch := range part {
			if !(ch >= 'a' && ch <= 'z' || ch >= '0' && ch <= '9' || ch == '-') {
				return false
			}
		}
	}
	return true
}
func digestValid(s string) bool {
	if len(s) != 71 || s[:7] != "sha256:" {
		return false
	}
	return hexValid(s[7:], 64)
}
func hexValid(s string, size int) bool {
	if len(s) != size {
		return false
	}
	for _, ch := range s {
		if !(ch >= '0' && ch <= '9' || ch >= 'a' && ch <= 'f') {
			return false
		}
	}
	return true
}
func digest(raw []byte) string {
	sum := sha256.Sum256(raw)
	return "sha256:" + hex.EncodeToString(sum[:])
}
