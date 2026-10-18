package probe

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"errors"
	"io"
	"math/big"
	"net/netip"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

func TestFixedDoTResolverReturnsCompleteChainAndAllAddresses(t *testing.T) {
	const (
		host  = "service.example.com"
		edge  = "edge.example.net"
		final = "origin.example.net"
	)
	var queries atomic.Int32
	server := startTestDoTServer(t, 0, func(question testDNSQuestion) ([]testDNSRecord, uint16) {
		queries.Add(1)
		switch question.host {
		case host:
			return []testDNSRecord{
				{owner: host, rrType: dnsTypeCNAME, cname: edge},
				{owner: edge, rrType: dnsTypeCNAME, cname: final},
			}, 0
		case final:
			if question.rrType == dnsTypeA {
				return []testDNSRecord{
					{owner: final, rrType: dnsTypeA, address: netip.MustParseAddr("8.8.8.8")},
					{owner: final, rrType: dnsTypeA, address: netip.MustParseAddr("1.1.1.1")},
				}, 0
			}
			return []testDNSRecord{
				{owner: final, rrType: dnsTypeAAAA, address: netip.MustParseAddr("2606:4700:4700::1111")},
				{owner: final, rrType: dnsTypeAAAA, address: netip.MustParseAddr("2001:4860:4860::8888")},
			}, 0
		default:
			return nil, 3
		}
	})
	resolver := newTestFixedDoTResolver(t, server, 2*time.Second, "resolver.test")

	snapshot, err := resolver.ResolveHost(context.Background(), host)
	if err != nil {
		t.Fatalf("ResolveHost() error = %v", err)
	}
	if want := []string{host, edge, final}; !reflect.DeepEqual(snapshot.CanonicalChain, want) {
		t.Fatalf("ResolveHost().CanonicalChain = %v, want %v", snapshot.CanonicalChain, want)
	}
	wantAddresses := []netip.Addr{
		netip.MustParseAddr("1.1.1.1"),
		netip.MustParseAddr("8.8.8.8"),
		netip.MustParseAddr("2001:4860:4860::8888"),
		netip.MustParseAddr("2606:4700:4700::1111"),
	}
	if !reflect.DeepEqual(snapshot.Addresses, wantAddresses) {
		t.Fatalf("ResolveHost().Addresses = %v, want %v", snapshot.Addresses, wantAddresses)
	}
	if queries.Load() != 4 {
		t.Fatalf("query count = %d, want 4 (A+AAAA for alias and terminal)", queries.Load())
	}

	target := validResolverTarget(host, edge, final)
	resolved, err := ResolveAndPin(context.Background(), resolver, target)
	if err != nil {
		t.Fatalf("ResolveAndPin() error = %v", err)
	}
	if !reflect.DeepEqual(resolved.CanonicalChain, []string{host, edge, final}) || !reflect.DeepEqual(resolved.ValidatedIPs, wantAddresses) {
		t.Fatalf("ResolveAndPin() returned incomplete evidence: %+v", resolved)
	}
}

func TestFixedDoTResolverReturnsBothAddressFamilies(t *testing.T) {
	const host = "dualstack.example.com"
	server := startTestDoTServer(t, 0, func(question testDNSQuestion) ([]testDNSRecord, uint16) {
		if question.rrType == dnsTypeA {
			return []testDNSRecord{{owner: host, rrType: dnsTypeA, address: netip.MustParseAddr("9.9.9.9")}}, 0
		}
		return []testDNSRecord{{owner: host, rrType: dnsTypeAAAA, address: netip.MustParseAddr("2620:fe::fe")}}, 0
	})
	resolver := newTestFixedDoTResolver(t, server, time.Second, "resolver.test")

	snapshot, err := resolver.ResolveHost(context.Background(), host)
	want := []netip.Addr{netip.MustParseAddr("9.9.9.9"), netip.MustParseAddr("2620:fe::fe")}
	if err != nil || !reflect.DeepEqual(snapshot.Addresses, want) {
		t.Fatalf("ResolveHost() = %+v, %v", snapshot, err)
	}
}

func TestFixedDoTResolverNeverFallsBackToSystemDNS(t *testing.T) {
	var queries atomic.Int32
	server := startTestDoTServer(t, 0, func(testDNSQuestion) ([]testDNSRecord, uint16) {
		queries.Add(1)
		return nil, 3 // authoritative test endpoint says NXDOMAIN
	})
	resolver := newTestFixedDoTResolver(t, server, time.Second, "resolver.test")

	if _, err := resolver.ResolveHost(context.Background(), "localhost.example"); err == nil || !strings.Contains(err.Error(), "rcode 3") {
		t.Fatalf("ResolveHost() error = %v, want fixed-upstream NXDOMAIN", err)
	}
	if queries.Load() != 1 {
		t.Fatalf("fixed endpoint query count = %d, want 1", queries.Load())
	}
}

func TestFixedDoTResolverHonorsTimeoutAndCancellation(t *testing.T) {
	server := startTestDoTServer(t, 150*time.Millisecond, func(testDNSQuestion) ([]testDNSRecord, uint16) {
		return nil, 0
	})
	resolver := newTestFixedDoTResolver(t, server, 30*time.Millisecond, "resolver.test")

	started := time.Now()
	if _, err := resolver.ResolveHost(context.Background(), "slow.example.com"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("timeout error = %v, want deadline exceeded", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("timeout took %s, want bounded cancellation", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	started = time.Now()
	if _, err := resolver.ResolveHost(ctx, "slow.example.com"); !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error = %v, want canceled", err)
	}
	if elapsed := time.Since(started); elapsed > 100*time.Millisecond {
		t.Fatalf("pre-canceled lookup took %s", elapsed)
	}
}

func TestFixedDoTResolverRejectsCertificateMismatch(t *testing.T) {
	server := startTestDoTServer(t, 0, func(testDNSQuestion) ([]testDNSRecord, uint16) { return nil, 0 })
	resolver := newTestFixedDoTResolver(t, server, time.Second, "wrong-name.example")
	if _, err := resolver.ResolveHost(context.Background(), "service.example.com"); err == nil || !strings.Contains(err.Error(), "certificate") {
		t.Fatalf("certificate mismatch error = %v", err)
	}
}

func TestFixedDoTResolverRejectsConflictingAndLoopingCNAMEs(t *testing.T) {
	const host = "service.example.com"
	t.Run("conflict", func(t *testing.T) {
		server := startTestDoTServer(t, 0, func(testDNSQuestion) ([]testDNSRecord, uint16) {
			return []testDNSRecord{
				{owner: host, rrType: dnsTypeCNAME, cname: "one.example.net"},
				{owner: host, rrType: dnsTypeCNAME, cname: "two.example.net"},
			}, 0
		})
		resolver := newTestFixedDoTResolver(t, server, time.Second, "resolver.test")
		if _, err := resolver.ResolveHost(context.Background(), host); err == nil || !strings.Contains(err.Error(), "conflicting CNAME") {
			t.Fatalf("conflicting CNAME error = %v", err)
		}
	})
	t.Run("loop", func(t *testing.T) {
		server := startTestDoTServer(t, 0, func(testDNSQuestion) ([]testDNSRecord, uint16) {
			return []testDNSRecord{
				{owner: host, rrType: dnsTypeCNAME, cname: "edge.example.net"},
				{owner: "edge.example.net", rrType: dnsTypeCNAME, cname: host},
			}, 0
		})
		resolver := newTestFixedDoTResolver(t, server, time.Second, "resolver.test")
		if _, err := resolver.ResolveHost(context.Background(), host); err == nil || !strings.Contains(err.Error(), "CNAME loop") {
			t.Fatalf("CNAME loop error = %v", err)
		}
	})
	t.Run("different address families disagree", func(t *testing.T) {
		server := startTestDoTServer(t, 0, func(question testDNSQuestion) ([]testDNSRecord, uint16) {
			alias := "ipv4.example.net"
			if question.rrType == dnsTypeAAAA {
				alias = "ipv6.example.net"
			}
			return []testDNSRecord{{owner: host, rrType: dnsTypeCNAME, cname: alias}}, 0
		})
		resolver := newTestFixedDoTResolver(t, server, time.Second, "resolver.test")
		if _, err := resolver.ResolveHost(context.Background(), host); err == nil || !strings.Contains(err.Error(), "conflicting CNAME") {
			t.Fatalf("cross-family CNAME disagreement error = %v", err)
		}
	})
}

func TestNewFixedDoTResolverRejectsUnsafeConfiguration(t *testing.T) {
	valid := FixedDoTResolverConfig{
		Upstream:   netip.MustParseAddrPort("127.0.0.1:853"),
		ServerName: "resolver.example",
		Timeout:    time.Second,
	}
	tests := []struct {
		name   string
		mutate func(*FixedDoTResolverConfig)
	}{
		{"missing upstream", func(config *FixedDoTResolverConfig) { config.Upstream = netip.AddrPort{} }},
		{"zero port", func(config *FixedDoTResolverConfig) { config.Upstream = netip.MustParseAddrPort("127.0.0.1:0") }},
		{"multicast", func(config *FixedDoTResolverConfig) { config.Upstream = netip.MustParseAddrPort("224.0.0.1:853") }},
		{"IP server name", func(config *FixedDoTResolverConfig) { config.ServerName = "1.1.1.1" }},
		{"zero timeout", func(config *FixedDoTResolverConfig) { config.Timeout = 0 }},
		{"excessive timeout", func(config *FixedDoTResolverConfig) { config.Timeout = maxResolverTimeout + time.Second }},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := valid
			test.mutate(&config)
			if _, err := NewFixedDoTResolver(config); err == nil {
				t.Fatal("NewFixedDoTResolver accepted invalid configuration")
			}
		})
	}
}

func TestParseDNSResponseSupportsBoundedCompression(t *testing.T) {
	const host = "service.example.com"
	query, queryID, err := buildDNSQuery(host, dnsTypeA)
	if err != nil {
		t.Fatalf("buildDNSQuery() error = %v", err)
	}
	response := make([]byte, 12)
	copy(response[0:2], query[0:2])
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], 1)
	response = append(response, query[12:]...)
	response = append(response,
		0xc0, 0x0c, // owner: pointer to service.example.com
		0x00, dnsTypeCNAME,
		0x00, dnsClassIN,
		0x00, 0x00, 0x00, 0x1e,
		0x00, 0x07, // four-byte label plus pointer
		0x04, 'e', 'd', 'g', 'e', 0xc0, 0x14, // edge + pointer to example.com
	)
	records, err := parseDNSResponse(response, queryID, host, dnsTypeA)
	if err != nil {
		t.Fatalf("parseDNSResponse() error = %v", err)
	}
	if len(records) != 1 || records[0].owner != host || records[0].cname != "edge.example.com" {
		t.Fatalf("compressed CNAME records = %+v", records)
	}

	response[len(response)-2] = 0xc0
	response[len(response)-1] = byte(len(response) - 2)
	if _, err := parseDNSResponse(response, queryID, host, dnsTypeA); err == nil {
		t.Fatal("parseDNSResponse accepted a compression pointer loop")
	}
}

func TestParseDNSResponseRejectsRecordCountFlood(t *testing.T) {
	query, queryID, err := buildDNSQuery("service.example.com", dnsTypeA)
	if err != nil {
		t.Fatalf("buildDNSQuery() error = %v", err)
	}
	response := append([]byte(nil), query...)
	binary.BigEndian.PutUint16(response[2:4], 0x8180)
	binary.BigEndian.PutUint16(response[6:8], maxDNSRecords+1)
	if _, err := parseDNSResponse(response, queryID, "service.example.com", dnsTypeA); err == nil || !strings.Contains(err.Error(), "more than") {
		t.Fatalf("record-count flood error = %v", err)
	}
}

func validResolverTarget(host string, aliases ...string) Target {
	return Target{
		ID:              "resolver-target",
		PathID:          "direct",
		Kind:            ProbeHTTPS,
		Host:            host,
		AllowedCNAMEs:   aliases,
		Port:            443,
		RequestPath:     "/health",
		Method:          "GET",
		ExpectedStatus:  []int{200},
		IntervalSeconds: 60,
		TimeoutSeconds:  2,
		TTLSeconds:      60,
		MaxBodyBytes:    1024,
	}
}

type testDNSQuestion struct {
	host   string
	rrType uint16
}

type testDNSRecord struct {
	owner   string
	rrType  uint16
	cname   string
	address netip.Addr
}

type testDoTServer struct {
	address netip.AddrPort
	roots   *x509.CertPool
	close   func()
}

func startTestDoTServer(t *testing.T, responseDelay time.Duration, handler func(testDNSQuestion) ([]testDNSRecord, uint16)) testDoTServer {
	t.Helper()
	certificate, roots := makeTestDoTCertificate(t)
	listener, err := tls.Listen("tcp", "127.0.0.1:0", &tls.Config{
		Certificates: []tls.Certificate{certificate},
		MinVersion:   tls.VersionTLS12,
	})
	if err != nil {
		t.Fatalf("listen test DoT: %v", err)
	}
	address, err := netip.ParseAddrPort(listener.Addr().String())
	if err != nil {
		listener.Close()
		t.Fatalf("parse test DoT address: %v", err)
	}

	var wait sync.WaitGroup
	closed := make(chan struct{})
	wait.Add(1)
	go func() {
		defer wait.Done()
		for {
			connection, acceptErr := listener.Accept()
			if acceptErr != nil {
				select {
				case <-closed:
					return
				default:
					return
				}
			}
			wait.Add(1)
			go func() {
				defer wait.Done()
				defer connection.Close()
				var length [2]byte
				if _, readErr := io.ReadFull(connection, length[:]); readErr != nil {
					return
				}
				query := make([]byte, int(binary.BigEndian.Uint16(length[:])))
				if len(query) < 12 {
					return
				}
				if _, readErr := io.ReadFull(connection, query); readErr != nil {
					return
				}
				question, questionEnd, parseErr := parseTestDNSQuestion(query)
				if parseErr != nil {
					return
				}
				if responseDelay != 0 {
					time.Sleep(responseDelay)
				}
				records, rcode := handler(question)
				response := buildTestDNSResponse(query, questionEnd, records, rcode)
				framed := make([]byte, len(response)+2)
				binary.BigEndian.PutUint16(framed[:2], uint16(len(response)))
				copy(framed[2:], response)
				_, _ = connection.Write(framed)
			}()
		}
	}()

	var closeOnce sync.Once
	closeServer := func() {
		closeOnce.Do(func() {
			close(closed)
			_ = listener.Close()
			wait.Wait()
		})
	}
	t.Cleanup(closeServer)
	return testDoTServer{address: address, roots: roots, close: closeServer}
}

func newTestFixedDoTResolver(t *testing.T, server testDoTServer, timeout time.Duration, serverName string) *FixedDoTResolver {
	t.Helper()
	resolver, err := NewFixedDoTResolver(FixedDoTResolverConfig{
		Upstream:   server.address,
		ServerName: serverName,
		RootCAs:    server.roots,
		Timeout:    timeout,
	})
	if err != nil {
		t.Fatalf("NewFixedDoTResolver() error = %v", err)
	}
	return resolver
}

func makeTestDoTCertificate(t *testing.T) (tls.Certificate, *x509.CertPool) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate CA key: %v", err)
	}
	now := time.Now()
	caTemplate := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "test DoT CA"},
		NotBefore:             now.Add(-time.Minute),
		NotAfter:              now.Add(time.Hour),
		IsCA:                  true,
		BasicConstraintsValid: true,
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTemplate, caTemplate, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create CA certificate: %v", err)
	}
	caCertificate, err := x509.ParseCertificate(caDER)
	if err != nil {
		t.Fatalf("parse CA certificate: %v", err)
	}
	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate leaf key: %v", err)
	}
	leafTemplate := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "resolver.test"},
		DNSNames:     []string{"resolver.test"},
		NotBefore:    now.Add(-time.Minute),
		NotAfter:     now.Add(time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTemplate, caCertificate, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatalf("create leaf certificate: %v", err)
	}
	certificate := tls.Certificate{
		Certificate: [][]byte{leafDER, caDER},
		PrivateKey:  leafKey,
	}
	roots := x509.NewCertPool()
	roots.AddCert(caCertificate)
	return certificate, roots
}

func parseTestDNSQuestion(query []byte) (testDNSQuestion, int, error) {
	if len(query) < 12 || binary.BigEndian.Uint16(query[4:6]) != 1 {
		return testDNSQuestion{}, 0, errors.New("invalid test DNS query")
	}
	host, offset, err := decodeDNSName(query, 12)
	if err != nil || offset+4 > len(query) {
		return testDNSQuestion{}, 0, errors.New("invalid test DNS question")
	}
	rrType := binary.BigEndian.Uint16(query[offset : offset+2])
	if binary.BigEndian.Uint16(query[offset+2:offset+4]) != dnsClassIN {
		return testDNSQuestion{}, 0, errors.New("invalid test DNS class")
	}
	return testDNSQuestion{host: host, rrType: rrType}, offset + 4, nil
}

func buildTestDNSResponse(query []byte, questionEnd int, records []testDNSRecord, rcode uint16) []byte {
	response := make([]byte, 12, 512)
	copy(response[0:2], query[0:2])
	binary.BigEndian.PutUint16(response[2:4], 0x8180|(rcode&0x000f))
	binary.BigEndian.PutUint16(response[4:6], 1)
	binary.BigEndian.PutUint16(response[6:8], uint16(len(records)))
	response = append(response, query[12:questionEnd]...)
	for _, record := range records {
		response = appendTestDNSName(response, record.owner)
		recordHeader := make([]byte, 10)
		binary.BigEndian.PutUint16(recordHeader[0:2], record.rrType)
		binary.BigEndian.PutUint16(recordHeader[2:4], dnsClassIN)
		binary.BigEndian.PutUint32(recordHeader[4:8], 30)
		response = append(response, recordHeader...)
		var rdata []byte
		switch record.rrType {
		case dnsTypeCNAME:
			rdata = appendTestDNSName(nil, record.cname)
		case dnsTypeA:
			address := record.address.As4()
			rdata = append(rdata, address[:]...)
		case dnsTypeAAAA:
			address := record.address.As16()
			rdata = append(rdata, address[:]...)
		}
		binary.BigEndian.PutUint16(response[len(response)-2:], uint16(len(rdata)))
		response = append(response, rdata...)
	}
	return response
}

func appendTestDNSName(message []byte, host string) []byte {
	for _, label := range strings.Split(host, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	return append(message, 0)
}
