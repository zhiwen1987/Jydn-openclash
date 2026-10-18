package probe

import (
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"sort"
	"strings"
	"time"
)

const (
	dnsTypeA     = 1
	dnsTypeCNAME = 5
	dnsTypeAAAA  = 28
	dnsClassIN   = 1

	maxDNSMessageBytes = 65535
	maxDNSRecords      = 512
	maxDNSNameJumps    = 32
	maxResolverTimeout = 10 * time.Second
	minResolverTimeout = 10 * time.Millisecond
)

// FixedDoTResolverConfig describes one immutable DNS-over-TLS upstream. The
// endpoint is an IP address by design: constructing the resolver never needs
// the system resolver, and queries can never fall back to it.
type FixedDoTResolverConfig struct {
	Upstream   netip.AddrPort
	ServerName string
	RootCAs    *x509.CertPool
	Timeout    time.Duration
}

// FixedDoTResolver resolves only through one certificate-verified DoT
// endpoint. It implements DNS wire parsing itself because net.Resolver does
// not expose the complete ordered CNAME chain required by Resolver.
type FixedDoTResolver struct {
	upstream   netip.AddrPort
	serverName string
	rootCAs    *x509.CertPool
	timeout    time.Duration
}

// NewFixedDoTResolver constructs a resolver without dialing the network.
// InsecureSkipVerify is intentionally not configurable.
func NewFixedDoTResolver(config FixedDoTResolverConfig) (*FixedDoTResolver, error) {
	if !config.Upstream.IsValid() || config.Upstream.Port() == 0 {
		return nil, errors.New("DoT upstream must be a fixed IP and non-zero port")
	}
	address := config.Upstream.Addr()
	if address.IsUnspecified() || address.IsMulticast() {
		return nil, errors.New("DoT upstream must be a unicast IP")
	}
	if err := validateExactHost(config.ServerName); err != nil {
		return nil, fmt.Errorf("DoT serverName: %w", err)
	}
	if config.Timeout < minResolverTimeout || config.Timeout > maxResolverTimeout {
		return nil, fmt.Errorf("DoT timeout must be between %s and %s", minResolverTimeout, maxResolverTimeout)
	}

	var roots *x509.CertPool
	if config.RootCAs != nil {
		roots = config.RootCAs.Clone()
	}
	return &FixedDoTResolver{
		upstream:   config.Upstream,
		serverName: config.ServerName,
		rootCAs:    roots,
		timeout:    config.Timeout,
	}, nil
}

// ResolveHost returns one internally consistent snapshot. A and AAAA answers
// are resolved under one total deadline and conflicting chains are rejected.
func (resolver *FixedDoTResolver) ResolveHost(ctx context.Context, host string) (DNSResolution, error) {
	snapshot, err := resolver.resolve(ctx, host)
	if err != nil {
		return DNSResolution{}, err
	}
	return DNSResolution{
		CanonicalChain: append([]string(nil), snapshot.chain...),
		Addresses:      append([]netip.Addr(nil), snapshot.addresses...),
	}, nil
}

type dnsSnapshot struct {
	chain     []string
	addresses []netip.Addr
}

func (resolver *FixedDoTResolver) resolve(parent context.Context, host string) (dnsSnapshot, error) {
	if resolver == nil {
		return dnsSnapshot{}, errors.New("fixed DoT resolver is nil")
	}
	if parent == nil {
		return dnsSnapshot{}, errors.New("resolver context is nil")
	}
	if err := validateExactHost(host); err != nil {
		return dnsSnapshot{}, fmt.Errorf("resolve host: %w", err)
	}
	ctx, cancel := context.WithTimeout(parent, resolver.timeout)
	defer cancel()

	chain := []string{host}
	seen := map[string]struct{}{host: {}}
	current := host
	for len(chain) <= MaxAllowedCNAMEs+1 {
		recordsA, err := resolver.query(ctx, current, dnsTypeA)
		if err != nil {
			return dnsSnapshot{}, fmt.Errorf("query A for %s: %w", current, err)
		}
		recordsAAAA, err := resolver.query(ctx, current, dnsTypeAAAA)
		if err != nil {
			return dnsSnapshot{}, fmt.Errorf("query AAAA for %s: %w", current, err)
		}
		records := append(recordsA, recordsAAAA...)
		aliases, addressesByName, err := indexDNSAnswers(records)
		if err != nil {
			return dnsSnapshot{}, err
		}

		advanced := false
		usedAliases := make(map[string]struct{})
		for {
			next, exists := aliases[current]
			if !exists {
				break
			}
			usedAliases[current] = struct{}{}
			if _, duplicate := seen[next]; duplicate {
				return dnsSnapshot{}, errors.New("fixed DoT resolver returned a CNAME loop")
			}
			if len(chain) == MaxAllowedCNAMEs+1 {
				return dnsSnapshot{}, fmt.Errorf("fixed DoT resolver returned more than %d CNAME hops", MaxAllowedCNAMEs)
			}
			seen[next] = struct{}{}
			chain = append(chain, next)
			current = next
			advanced = true
		}
		for owner := range aliases {
			if _, used := usedAliases[owner]; !used {
				return dnsSnapshot{}, fmt.Errorf("fixed DoT resolver returned unrelated CNAME owner %q", owner)
			}
		}
		if advanced {
			// Query the terminal name explicitly. This avoids relying on optional
			// glue and ensures both complete terminal A and AAAA RRsets are read.
			continue
		}

		addresses := addressesByName[current]
		if len(addresses) == 0 {
			return dnsSnapshot{}, fmt.Errorf("fixed DoT resolver returned no addresses for %s", current)
		}
		addresses = uniqueSortedAddresses(addresses)
		if len(addresses) > MaxResolvedAddresses {
			return dnsSnapshot{}, fmt.Errorf("fixed DoT resolver returned more than %d addresses", MaxResolvedAddresses)
		}
		return dnsSnapshot{chain: chain, addresses: addresses}, nil
	}
	return dnsSnapshot{}, fmt.Errorf("fixed DoT resolver returned more than %d CNAME hops", MaxAllowedCNAMEs)
}

type dnsAnswer struct {
	owner   string
	rrType  uint16
	cname   string
	address netip.Addr
}

func indexDNSAnswers(records []dnsAnswer) (map[string]string, map[string][]netip.Addr, error) {
	aliases := make(map[string]string)
	addresses := make(map[string][]netip.Addr)
	for _, record := range records {
		switch record.rrType {
		case dnsTypeCNAME:
			if existing, exists := aliases[record.owner]; exists && existing != record.cname {
				return nil, nil, fmt.Errorf("conflicting CNAME answers for %q", record.owner)
			}
			aliases[record.owner] = record.cname
		case dnsTypeA, dnsTypeAAAA:
			addresses[record.owner] = append(addresses[record.owner], record.address)
		}
	}
	for owner := range aliases {
		if len(addresses[owner]) != 0 {
			return nil, nil, fmt.Errorf("CNAME owner %q also has address records", owner)
		}
	}
	return aliases, addresses, nil
}

func uniqueSortedAddresses(addresses []netip.Addr) []netip.Addr {
	seen := make(map[netip.Addr]struct{}, len(addresses))
	result := make([]netip.Addr, 0, len(addresses))
	for _, address := range addresses {
		if _, exists := seen[address]; exists {
			continue
		}
		seen[address] = struct{}{}
		result = append(result, address)
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Compare(result[j]) < 0 })
	return result
}

func (resolver *FixedDoTResolver) query(ctx context.Context, host string, queryType uint16) ([]dnsAnswer, error) {
	message, queryID, err := buildDNSQuery(host, queryType)
	if err != nil {
		return nil, err
	}

	dialer := net.Dialer{}
	rawConnection, err := dialer.DialContext(ctx, "tcp", resolver.upstream.String())
	if err != nil {
		return nil, resolverContextError(ctx, fmt.Errorf("dial fixed DoT upstream: %w", err))
	}
	tlsConnection := tls.Client(rawConnection, &tls.Config{
		MinVersion: tls.VersionTLS12,
		ServerName: resolver.serverName,
		RootCAs:    resolver.rootCAs,
	})
	defer tlsConnection.Close()
	if deadline, exists := ctx.Deadline(); exists {
		if err := tlsConnection.SetDeadline(deadline); err != nil {
			return nil, fmt.Errorf("set DoT deadline: %w", err)
		}
	}
	stopCancellationWatch := make(chan struct{})
	go func() {
		select {
		case <-ctx.Done():
			_ = tlsConnection.Close()
		case <-stopCancellationWatch:
		}
	}()
	defer close(stopCancellationWatch)

	if err := tlsConnection.HandshakeContext(ctx); err != nil {
		return nil, resolverContextError(ctx, fmt.Errorf("verify fixed DoT upstream: %w", err))
	}
	framed := make([]byte, 2+len(message))
	binary.BigEndian.PutUint16(framed[:2], uint16(len(message)))
	copy(framed[2:], message)
	if err := writeAll(tlsConnection, framed); err != nil {
		return nil, resolverContextError(ctx, fmt.Errorf("write DoT query: %w", err))
	}
	var length [2]byte
	if _, err := io.ReadFull(tlsConnection, length[:]); err != nil {
		return nil, resolverContextError(ctx, fmt.Errorf("read DoT response length: %w", err))
	}
	responseLength := int(binary.BigEndian.Uint16(length[:]))
	if responseLength < 12 || responseLength > maxDNSMessageBytes {
		return nil, fmt.Errorf("invalid DoT response length %d", responseLength)
	}
	response := make([]byte, responseLength)
	if _, err := io.ReadFull(tlsConnection, response); err != nil {
		return nil, resolverContextError(ctx, fmt.Errorf("read DoT response: %w", err))
	}
	return parseDNSResponse(response, queryID, host, queryType)
}

func resolverContextError(ctx context.Context, fallback error) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	var networkError net.Error
	if errors.As(fallback, &networkError) && networkError.Timeout() {
		if deadline, exists := ctx.Deadline(); exists && !time.Now().Before(deadline) {
			return context.DeadlineExceeded
		}
	}
	return fallback
}

func writeAll(writer io.Writer, data []byte) error {
	for len(data) != 0 {
		written, err := writer.Write(data)
		if err != nil {
			return err
		}
		if written == 0 {
			return io.ErrUnexpectedEOF
		}
		data = data[written:]
	}
	return nil
}

func buildDNSQuery(host string, queryType uint16) ([]byte, uint16, error) {
	if err := validateExactHost(host); err != nil {
		return nil, 0, err
	}
	if queryType != dnsTypeA && queryType != dnsTypeAAAA {
		return nil, 0, errors.New("only A and AAAA queries are supported")
	}
	var randomID [2]byte
	if _, err := rand.Read(randomID[:]); err != nil {
		return nil, 0, fmt.Errorf("generate DNS query id: %w", err)
	}
	queryID := binary.BigEndian.Uint16(randomID[:])
	message := make([]byte, 12, 12+len(host)+6)
	binary.BigEndian.PutUint16(message[0:2], queryID)
	binary.BigEndian.PutUint16(message[2:4], 0x0100) // recursion desired
	binary.BigEndian.PutUint16(message[4:6], 1)
	for _, label := range strings.Split(host, ".") {
		message = append(message, byte(len(label)))
		message = append(message, label...)
	}
	message = append(message, 0, 0, 0, 0, 0)
	binary.BigEndian.PutUint16(message[len(message)-4:len(message)-2], queryType)
	binary.BigEndian.PutUint16(message[len(message)-2:], dnsClassIN)
	return message, queryID, nil
}

func parseDNSResponse(message []byte, queryID uint16, queryHost string, queryType uint16) ([]dnsAnswer, error) {
	if len(message) < 12 {
		return nil, errors.New("DNS response is shorter than its header")
	}
	if binary.BigEndian.Uint16(message[0:2]) != queryID {
		return nil, errors.New("DNS response id does not match query")
	}
	flags := binary.BigEndian.Uint16(message[2:4])
	if flags&0x8000 == 0 || flags&0x7800 != 0 {
		return nil, errors.New("DNS response has invalid QR or opcode flags")
	}
	if flags&0x0200 != 0 {
		return nil, errors.New("truncated DNS-over-TLS response is prohibited")
	}
	if rcode := flags & 0x000f; rcode != 0 {
		return nil, fmt.Errorf("DNS response returned rcode %d", rcode)
	}
	questionCount := int(binary.BigEndian.Uint16(message[4:6]))
	answerCount := int(binary.BigEndian.Uint16(message[6:8]))
	authorityCount := int(binary.BigEndian.Uint16(message[8:10]))
	additionalCount := int(binary.BigEndian.Uint16(message[10:12]))
	if questionCount != 1 {
		return nil, fmt.Errorf("DNS response has %d questions, want 1", questionCount)
	}
	if answerCount+authorityCount+additionalCount > maxDNSRecords {
		return nil, fmt.Errorf("DNS response has more than %d records", maxDNSRecords)
	}

	offset := 12
	questionName, next, err := decodeDNSName(message, offset)
	if err != nil {
		return nil, fmt.Errorf("decode DNS question: %w", err)
	}
	offset = next
	if offset+4 > len(message) {
		return nil, errors.New("DNS question is truncated")
	}
	responseQueryType := binary.BigEndian.Uint16(message[offset : offset+2])
	responseQueryClass := binary.BigEndian.Uint16(message[offset+2 : offset+4])
	offset += 4
	if questionName != queryHost || responseQueryType != queryType || responseQueryClass != dnsClassIN {
		return nil, errors.New("DNS response question does not match query")
	}

	answers := make([]dnsAnswer, 0, answerCount)
	totalRecords := answerCount + authorityCount + additionalCount
	for index := 0; index < totalRecords; index++ {
		owner, rrNext, err := decodeDNSName(message, offset)
		if err != nil {
			return nil, fmt.Errorf("decode DNS record owner: %w", err)
		}
		offset = rrNext
		if offset+10 > len(message) {
			return nil, errors.New("DNS record header is truncated")
		}
		rrType := binary.BigEndian.Uint16(message[offset : offset+2])
		rrClass := binary.BigEndian.Uint16(message[offset+2 : offset+4])
		rdataLength := int(binary.BigEndian.Uint16(message[offset+8 : offset+10]))
		offset += 10
		if rdataLength < 0 || offset+rdataLength > len(message) {
			return nil, errors.New("DNS record data is truncated")
		}
		rdataStart, rdataEnd := offset, offset+rdataLength
		isAnswer := index < answerCount
		if isAnswer && rrClass == dnsClassIN {
			record := dnsAnswer{owner: owner, rrType: rrType}
			switch rrType {
			case dnsTypeCNAME:
				record.cname, next, err = decodeDNSName(message, rdataStart)
				if err != nil || next != rdataEnd {
					if err == nil {
						err = errors.New("CNAME data length does not match encoded name")
					}
					return nil, fmt.Errorf("decode CNAME answer: %w", err)
				}
				answers = append(answers, record)
			case dnsTypeA:
				if rdataLength != 4 {
					return nil, errors.New("A answer has invalid length")
				}
				record.address = netip.AddrFrom4([4]byte(message[rdataStart:rdataEnd]))
				answers = append(answers, record)
			case dnsTypeAAAA:
				if rdataLength != 16 {
					return nil, errors.New("AAAA answer has invalid length")
				}
				record.address = netip.AddrFrom16([16]byte(message[rdataStart:rdataEnd]))
				answers = append(answers, record)
			}
		}
		offset = rdataEnd
	}
	if offset != len(message) {
		return nil, errors.New("DNS response contains trailing bytes")
	}
	return answers, nil
}

func decodeDNSName(message []byte, offset int) (string, int, error) {
	if offset < 0 || offset >= len(message) {
		return "", 0, errors.New("DNS name offset is out of range")
	}
	labels := make([]string, 0, 4)
	visited := make(map[int]struct{})
	position := offset
	next := -1
	wireLength := 1
	for jumps := 0; jumps <= maxDNSNameJumps; {
		if position >= len(message) {
			return "", 0, errors.New("DNS name is truncated")
		}
		length := int(message[position])
		switch {
		case length&0xc0 == 0xc0:
			if position+1 >= len(message) {
				return "", 0, errors.New("DNS compression pointer is truncated")
			}
			pointer := ((length & 0x3f) << 8) | int(message[position+1])
			if pointer >= len(message) {
				return "", 0, errors.New("DNS compression pointer is out of range")
			}
			if _, duplicate := visited[pointer]; duplicate {
				return "", 0, errors.New("DNS compression pointer loop")
			}
			visited[pointer] = struct{}{}
			if next < 0 {
				next = position + 2
			}
			position = pointer
			jumps++
		case length&0xc0 != 0:
			return "", 0, errors.New("unsupported DNS label encoding")
		case length == 0:
			if next < 0 {
				next = position + 1
			}
			name := strings.ToLower(strings.Join(labels, "."))
			if err := validateExactHost(name); err != nil {
				return "", 0, fmt.Errorf("invalid DNS hostname: %w", err)
			}
			return name, next, nil
		default:
			if length > 63 || position+1+length > len(message) {
				return "", 0, errors.New("DNS label is truncated or too long")
			}
			wireLength += 1 + length
			if wireLength > 255 {
				return "", 0, errors.New("DNS name exceeds 255 wire bytes")
			}
			labels = append(labels, string(message[position+1:position+1+length]))
			position += 1 + length
		}
	}
	return "", 0, errors.New("DNS name has too many compression jumps")
}
