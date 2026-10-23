package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"testing"
)

const parserTestUUID = "11111111-2222-4333-8444-555555555555"

func parserTestInput(content string) ParseInput {
	return ParseInput{Scope: Scope{TenantID: "tenant", SiteID: "site", Environment: "lab"}, SourceID: "src_0123456789abcdef0123456789abcdef", Format: FormatAuto, Content: []byte(content), IdentityKey: bytes.Repeat([]byte{0x41}, 32)}
}

func parserTestParse(t *testing.T, input ParseInput) Parsed {
	t.Helper()
	parsed, err := Parse(input)
	if err != nil {
		t.Fatalf("safe parser failure: %v", err)
	}
	if len(parsed.Nodes) == 0 || !strings.HasPrefix(parsed.Digest, "hmac-sha256:") || len(parsed.Digest) != 76 {
		t.Fatal("missing canonical private result")
	}
	return parsed
}

func parserTestReject(t *testing.T, input ParseInput, codes ...Code) {
	t.Helper()
	parsed, err := Parse(input)
	var failure *Failure
	if !errors.As(err, &failure) || !reflect.DeepEqual(parsed, Parsed{}) {
		t.Fatal("expected closed Failure and zero partial result")
	}
	for _, code := range codes {
		if failure.Code == code {
			return
		}
	}
	t.Fatalf("unexpected fixed failure code: %s", failure.Code)
}

func parserTestSS(name, password string) string {
	return fmt.Sprintf("  - name: %q\n    type: ss\n    server: node.example\n    port: 443\n    cipher: aes-128-gcm\n    password: %q\n", name, password)
}

func parserTestConfig(t *testing.T, node ParsedNode) map[string]any {
	t.Helper()
	var object map[string]any
	if err := json.Unmarshal(node.Config, &object); err != nil {
		t.Fatal("invalid canonical config")
	}
	return object
}

func TestSubscriptionParserMihomoProtocols(t *testing.T) {
	raw := "proxies:\n" + parserTestSS("private ss", "private-pass") + `
  - {name: vmess, type: vmess, server: vm.example, port: 443, uuid: ` + parserTestUUID + `, alterId: 0, cipher: auto, tls: true}
  - {name: vless, type: vless, server: vl.example, port: 8443, uuid: ` + parserTestUUID + `, tls: true, flow: xtls-rprx-vision}
  - {name: trojan, type: trojan, server: tr.example, port: 443, password: secret, sni: tr.example}
  - {name: http, type: http, server: http.example, port: 8080, username: user, password: secret}
  - {name: socks, type: socks5, server: socks.example, port: 1080, udp: true}
`
	parsed := parserTestParse(t, parserTestInput(raw))
	if parsed.Format != FormatMihomo || len(parsed.Nodes) != 6 || parsed.DuplicateCount != 0 {
		t.Fatal("provider protocol coverage mismatch")
	}
	seen := map[string]bool{}
	for _, node := range parsed.Nodes {
		if len(node.ID) != 37 || !strings.HasPrefix(node.ID, "node_") || node.PrivateName == "" || seen[node.Protocol] {
			t.Fatal("invalid private node projection")
		}
		seen[node.Protocol] = true
		if node.CredentialConfigured != (node.Protocol != "socks5") {
			t.Fatal("credential presence mismatch")
		}
	}
}

func TestSubscriptionParserURIProtocols(t *testing.T) {
	vmess := base64.StdEncoding.EncodeToString([]byte(`{"v":"2","ps":"vm","add":"vm.example","port":"443","id":"` + parserTestUUID + `","aid":"0","net":"tcp","type":"none","tls":"tls"}`))
	raw := "ss://YWVzLTEyOC1nY206c2VjcmV0@ss.example:443#ss\nvmess://" + vmess + "\nvless://" + parserTestUUID + "@vl.example:443?encryption=none&security=tls#vl\ntrojan://secret@tr.example:443?sni=tr.example#tr\nhttps://user:secret@http.example:443#http\nsocks5://user:secret@[2001:db8::1]:1080#socks"
	parsed := parserTestParse(t, parserTestInput(raw))
	if parsed.Format != FormatURI || len(parsed.Nodes) != 6 {
		t.Fatal("URI protocol coverage mismatch")
	}
	for _, node := range parsed.Nodes {
		if !node.CredentialConfigured {
			t.Fatal("URI credentials were lost")
		}
	}
}

func TestSubscriptionParserBase64VariantsAndAuto(t *testing.T) {
	raw := []byte("trojan://p%40ss@tr.example:443#private\nhttp://proxy.example:8080#plain")
	plain := parserTestParse(t, parserTestInput(string(raw)))
	for _, encoding := range []*base64.Encoding{base64.StdEncoding, base64.RawStdEncoding, base64.URLEncoding, base64.RawURLEncoding} {
		encoded := encoding.EncodeToString(raw)
		input := parserTestInput(encoded[:8] + "\n\t" + encoded[8:])
		parsed := parserTestParse(t, input)
		if parsed.Format != FormatBase64URI || !reflect.DeepEqual(parsed.Nodes, plain.Nodes) {
			t.Fatal("base64 form altered canonical nodes")
		}
		input.Format = FormatBase64URI
		_ = parserTestParse(t, input)
	}
	input := parserTestInput("not base64 and not a URI")
	parserTestReject(t, input, CodeInputInvalid)
	input = parserTestInput(string(raw))
	input.Format = Format("json-demo")
	parserTestReject(t, input, CodeFormatUnsupported)
}

func TestSubscriptionParserShadowsocksSIP002AndLegacy(t *testing.T) {
	legacy := base64.StdEncoding.EncodeToString([]byte("aes-128-gcm:p@ss:word@ss.example:443"))
	// Legacy userinfo contains a literal @ in the password: last @ is authority.
	simpleLegacy := base64.RawStdEncoding.EncodeToString([]byte("aes-128-gcm:secret@ss.example:443"))
	forms := []string{"ss://YWVzLTEyOC1nY206c2VjcmV0@ss.example:443#same", "ss://aes-128-gcm:secret@ss.example:443#same", "ss://" + simpleLegacy + "#same"}
	first := parserTestParse(t, parserTestInput(forms[0]))
	for _, form := range forms[1:] {
		got := parserTestParse(t, parserTestInput(form))
		if !reflect.DeepEqual(got.Nodes, first.Nodes) {
			t.Fatal("SS URI forms are not canonical")
		}
	}
	encoded := parserTestParse(t, parserTestInput("ss://aes-128-gcm:p%40ss%3Aword@ss.example:443#same"))
	got := parserTestParse(t, parserTestInput("ss://"+legacy+"#same"))
	if !reflect.DeepEqual(got.Nodes, encoded.Nodes) {
		t.Fatal("legacy credentials not preserved")
	}
	parserTestReject(t, parserTestInput("ss://YWVzLTEyOC1nY206c2VjcmV0@ss.example:443?plugin=obfs#same"), CodeFormatUnsupported)
	parserTestReject(t, parserTestInput("ss://aes-128-gcm:secret@ss.example:443?plugin=obfs"), CodeFormatUnsupported)
}

func TestSubscriptionParserVMessStrictJSON(t *testing.T) {
	makeURI := func(raw string) ParseInput {
		return parserTestInput("vmess://" + base64.StdEncoding.EncodeToString([]byte(raw)))
	}
	valid := `{"v":"2","ps":"node","add":"vm.example","port":443,"id":"` + parserTestUUID + `","aid":0,"net":"ws","host":"front.example","path":"/ws","tls":"tls","sni":"tls.example"}`
	parsed := parserTestParse(t, makeURI(valid))
	config := parserTestConfig(t, parsed.Nodes[0])
	if config["tls"] != true || config["alterId"] != float64(0) || config["network"] != "ws" {
		t.Fatal("VMess public format conversion lost config")
	}
	for _, bad := range []string{`{"add":"first.example","add":"second.example"}`, strings.Replace(valid, `"v":"2"`, `"v":"3"`, 1), strings.Replace(valid, `"net":"ws"`, `"net":"kcp"`, 1), strings.Replace(valid, `"net":"ws"`, `"net":"ws","unexpected":"secret"`, 1), valid + "{}", strings.Replace(valid, `"aid":0`, `"aid":0.5`, 1)} {
		parserTestReject(t, makeURI(bad), CodeInputInvalid, CodeFormatUnsupported)
	}
}

func TestSubscriptionParserPrivateTransportPreservation(t *testing.T) {
	raw := `proxies:
  - name: private-ws
    type: vless
    server: VLESS.EXAMPLE
    port: 443
    uuid: ` + parserTestUUID + `
    tls: true
    servername: tls.example
    alpn: [h2, http/1.1]
    client-fingerprint: chrome
    skip-cert-verify: false
    network: ws
    ws-opts:
      path: /secret-path
      headers: {Host: front.example, X-Private: private-header}
  - name: private-grpc
    type: trojan
    server: grpc.example
    port: 443
    password: private-grpc-password
    network: grpc
    grpc-opts: {grpc-service-name: private-service}
  - name: private-http
    type: http
    server: proxy.example
    port: 8443
    tls: true
    headers: {X-Secret: private-http-header}
`
	parsed := parserTestParse(t, parserTestInput(raw))
	all := ""
	for _, node := range parsed.Nodes {
		all += string(node.Config)
	}
	for _, expected := range []string{"private-header", "private-service", "private-http-header", "private-grpc-password", "/secret-path", "vless.example", "skip-cert-verify"} {
		if !strings.Contains(all, expected) {
			t.Fatal("private option was silently lost")
		}
	}
}

func TestSubscriptionParserUnsupportedFieldsRejectWholeBatch(t *testing.T) {
	for _, field := range []string{"plugin: obfs", "plugin-opts: {mode: tls}", "smux: {enabled: true}", "dialer-proxy: other", "reality-opts: {public-key: secret}", "made-up: secret"} {
		input := parserTestInput("proxies:\n" + parserTestSS("valid", "p") + parserTestSS("unsupported", "q") + "    " + field + "\n")
		parserTestReject(t, input, CodeFormatUnsupported)
	}
	input := parserTestInput("proxies:\n" + parserTestSS("node", "p") + "rules: []\n")
	parserTestReject(t, input, CodeFormatUnsupported)
}

func TestSubscriptionParserUnsupportedProtocolsRejectWholeBatch(t *testing.T) {
	for _, protocol := range []string{"ssr", "hysteria2", "tuic", "wireguard", "direct", "reject"} {
		parserTestReject(t, parserTestInput("proxies:\n"+parserTestSS("good", "p")+"  - {name: bad, type: "+protocol+", server: node.example, port: 443}\n"), CodeProtocolUnsupported)
		parserTestReject(t, parserTestInput("http://good.example:8080\n"+protocol+"://secret@bad.example:443"), CodeProtocolUnsupported)
	}
	parserTestReject(t, parserTestInput("proxies:\n- {name: n, type: SS, server: node.example, port: 443}"), CodeProtocolUnsupported)
}

func TestSubscriptionParserYAMLComplexityLimits(t *testing.T) {
	deep := "proxies: " + strings.Repeat("[", MaxDepth+1) + "x" + strings.Repeat("]", MaxDepth+1)
	parserTestReject(t, parserTestInput(deep), CodeInputLimit)
	var syntax strings.Builder
	syntax.WriteString("proxies:\n- headers: {")
	for i := 0; i < MaxSyntaxNodes/2+1; i++ {
		fmt.Fprintf(&syntax, "x%d: x,", i)
	}
	syntax.WriteString("}\n")
	parserTestReject(t, parserTestInput(syntax.String()), CodeInputLimit)
	var nodes strings.Builder
	nodes.WriteString("proxies:\n")
	for i := 0; i < MaxNodes; i++ {
		nodes.WriteString(parserTestSS(fmt.Sprint(i), fmt.Sprint(i)))
	}
	if got := parserTestParse(t, parserTestInput(nodes.String())); len(got.Nodes) != MaxNodes {
		t.Fatal("1024 node boundary rejected")
	}
	nodes.WriteString(parserTestSS("extra", "extra"))
	parserTestReject(t, parserTestInput(nodes.String()), CodeInputLimit)
}

func TestSubscriptionParserYAMLDuplicateKeys(t *testing.T) {
	for _, raw := range []string{"proxies: []\nproxies: []", "proxies:\n" + parserTestSS("node", "p") + "    password: q\n", "proxies:\n- {name: n, type: http, server: proxy.example, port: 80, headers: {Host: a, Host: b}}", "proxies:\n- {name: n, type: http, server: proxy.example, port: 80, \"port\": 81}"} {
		parserTestReject(t, parserTestInput(raw), CodeInputInvalid)
	}
}

func TestSubscriptionParserYAMLAnchorsAliasesTags(t *testing.T) {
	for _, raw := range []string{"proxies: &items []", "proxies: [*missing]", "proxies:\n- &node {name: n, type: http, server: proxy.example, port: 80}\n- *node", "proxies: !!seq []", "proxies: !private []", "proxies: ! []", "proxies:\n- {name: ! \"n\", type: http, server: proxy.example, port: 80}", "proxies:\n- {name: !!str n, type: http, server: proxy.example, port: 80}", "proxies:\n- {<<: {name: n}, type: http, server: proxy.example, port: 80}"} {
		parserTestReject(t, parserTestInput(raw), CodeInputInvalid)
	}
}

func TestSubscriptionParserYAMLDocumentsAndRoot(t *testing.T) {
	for _, raw := range []string{"proxies: []\n---\nproxies: []", "proxies: []\n---\n", "proxies: null", "proxies: {}", "proxies: [null]", "proxies: [5]", "{rules: []}", "---\n[]"} {
		parserTestReject(t, parserTestInput(raw), CodeInputInvalid, CodeFormatUnsupported)
	}
	parserTestReject(t, parserTestInput("proxies: []"), CodeEmpty)
	_ = parserTestParse(t, parserTestInput("---\nproxies:\n"+parserTestSS("node", "secret")))
	_ = parserTestParse(t, parserTestInput("# actual provider comment\nproxies:\n"+parserTestSS("node", "secret")))
}

func TestSubscriptionParserInputBoundsAndUTF8(t *testing.T) {
	for _, raw := range [][]byte{nil, []byte(" \r\n\t")} {
		input := parserTestInput("")
		input.Content = raw
		parserTestReject(t, input, CodeEmpty)
	}
	for _, raw := range [][]byte{{0xff}, []byte("proxies:\x00 []")} {
		input := parserTestInput("")
		input.Content = raw
		parserTestReject(t, input, CodeInputInvalid)
	}
	parserTestReject(t, parserTestInput(strings.Repeat("x", MaxInputBytes+1)), CodeInputLimit)
	parserTestReject(t, parserTestInput("proxies:\n"+parserTestSS("node", strings.Repeat("p", MaxScalarBytes+1))), CodeInputLimit)
	parserTestReject(t, parserTestInput("http://proxy.example:8080#"+strings.Repeat("n", MaxScalarBytes+1)), CodeInputInvalid)
}

func TestSubscriptionParserScopeSourceKeyValidation(t *testing.T) {
	input := parserTestInput("http://proxy.example:8080")
	for _, mutate := range []func(*ParseInput){func(i *ParseInput) { i.Scope.TenantID = "" }, func(i *ParseInput) { i.Scope.SiteID = "../secret" }, func(i *ParseInput) { i.Scope.Environment = "prod\n" }, func(i *ParseInput) { i.SourceID = "src-not-valid" }, func(i *ParseInput) { i.IdentityKey = nil }, func(i *ParseInput) { i.IdentityKey = make([]byte, 31) }, func(i *ParseInput) { i.IdentityKey = make([]byte, 33) }} {
		copyInput := input
		mutate(&copyInput)
		parserTestReject(t, copyInput, CodeInputInvalid)
	}
}

func TestSubscriptionParserIdentityStableRenameAndReorder(t *testing.T) {
	first := parserTestParse(t, parserTestInput("proxies:\n"+parserTestSS("name one", "p")+parserTestSS("name two", "q")))
	second := parserTestParse(t, parserTestInput("proxies:\n"+parserTestSS("renamed two", "q")+parserTestSS("renamed one", "p")))
	for i := range first.Nodes {
		if first.Nodes[i].ID != second.Nodes[i].ID {
			t.Fatal("name/order became identity authority")
		}
		if i > 0 && first.Nodes[i-1].ID >= first.Nodes[i].ID {
			t.Fatal("nodes not ordered by opaque ID")
		}
	}
	if first.Digest == second.Digest {
		t.Fatal("original byte commitment ignored changes")
	}
}

func TestSubscriptionParserIdentityScopeSourceKeySeparation(t *testing.T) {
	input := parserTestInput("proxies:\n" + parserTestSS("same", "secret"))
	first := parserTestParse(t, input)
	for _, mutate := range []func(*ParseInput){func(i *ParseInput) { i.Scope.SiteID = "other" }, func(i *ParseInput) { i.Scope.TenantID = "other" }, func(i *ParseInput) { i.Scope.Environment = "other" }, func(i *ParseInput) { i.SourceID = "src_1123456789abcdef0123456789abcdef" }, func(i *ParseInput) { i.IdentityKey = bytes.Repeat([]byte{0x42}, 32) }} {
		copyInput := input
		mutate(&copyInput)
		got := parserTestParse(t, copyInput)
		if got.Nodes[0].ID == first.Nodes[0].ID || got.Digest == first.Digest {
			t.Fatal("identity crossed private scope/source/key")
		}
	}
}

func TestSubscriptionParserIdentityCredentialAndConnectionChanges(t *testing.T) {
	raw := "proxies:\n" + parserTestSS("node", "secret")
	first := parserTestParse(t, parserTestInput(raw))
	for _, altered := range []string{strings.Replace(raw, "secret", "different", 1), strings.Replace(raw, "443", "8443", 1), strings.Replace(raw, "node.example", "other.example", 1), raw + "    udp: true\n"} {
		got := parserTestParse(t, parserTestInput(altered))
		if first.Nodes[0].ID == got.Nodes[0].ID {
			t.Fatal("connection mutation preserved identity")
		}
	}
	uppercase := parserTestParse(t, parserTestInput(strings.Replace(raw, "node.example", "NODE.EXAMPLE", 1)))
	if uppercase.Nodes[0].ID != first.Nodes[0].ID {
		t.Fatal("DNS casing not canonical")
	}
}

func TestSubscriptionParserDedupDeterministicNames(t *testing.T) {
	first := parserTestParse(t, parserTestInput("proxies:\n"+parserTestSS("z-name", "p")+parserTestSS("a-name", "p")+parserTestSS("q-name", "q")))
	second := parserTestParse(t, parserTestInput("proxies:\n"+parserTestSS("q-name", "q")+parserTestSS("a-name", "p")+parserTestSS("z-name", "p")))
	if first.DuplicateCount != 1 || len(first.Nodes) != 2 || !reflect.DeepEqual(first.Nodes, second.Nodes) {
		t.Fatal("duplicate resolution is order-dependent")
	}
	for _, node := range first.Nodes {
		if node.PrivateName == "z-name" || !strings.Contains(string(node.Config), node.PrivateName) {
			t.Fatal("deterministic private name/config disagree")
		}
	}
}

func TestSubscriptionParserPrivateJSONNeverLeaks(t *testing.T) {
	input := parserTestInput("proxies:\n" + parserTestSS("private-name-canary", "private-password-canary"))
	parsed := parserTestParse(t, input)
	for _, value := range []any{input, parsed, parsed.Nodes[0], nodeView(parsed.Nodes[0])} {
		raw, err := json.Marshal(value)
		if err != nil || bytes.Contains(raw, []byte("private-name-canary")) || bytes.Contains(raw, []byte("private-password-canary")) || bytes.Contains(raw, input.IdentityKey) || bytes.Contains(raw, []byte("node.example")) {
			t.Fatal("private ingress/config/name escaped JSON")
		}
	}
	if nodeView(parsed.Nodes[0]).State != "unknown" {
		t.Fatal("parsing asserted connectivity")
	}
}

func TestSubscriptionParserInputOutputDetached(t *testing.T) {
	input := parserTestInput("proxies:\n" + parserTestSS("private", "secret"))
	content, key := bytes.Clone(input.Content), bytes.Clone(input.IdentityKey)
	first := parserTestParse(t, input)
	if !bytes.Equal(content, input.Content) || !bytes.Equal(key, input.IdentityKey) {
		t.Fatal("parser mutated caller bytes")
	}
	second := parserTestParse(t, input)
	first.Nodes[0].Config[0] = 'x'
	first.Nodes[0].PrivateName = "changed"
	if second.Nodes[0].Config[0] != '{' || second.Nodes[0].PrivateName != "private" {
		t.Fatal("returned projections alias")
	}
	input.Content[0] = 'x'
	if second.Nodes[0].Config[0] != '{' {
		t.Fatal("output retained raw input memory")
	}
}

func TestSubscriptionParserURIQueryAndAuthorityClosed(t *testing.T) {
	for _, raw := range []string{"http://proxy.example", "http://u@proxy.example:80", "http://proxy.example:80/path", "http://proxy.example:80?secret=x", "http://proxy.example:80?", "trojan://p:q@tr.example:443", "trojan://p@tr.example:443?allowInsecure=1", "vless://" + parserTestUUID + "@vl.example:443?type=ws&type=tcp", "vless://" + parserTestUUID + "@vl.example:443?security=reality", "vless://" + parserTestUUID + "@vl.example:443?type=tcp&path=/ignored", "vless://" + parserTestUUID + "@vl.example:443?security=tls&encryption=unknown", "trojan://p@tr.example:443?security=none", "http://proxy.example:80#bad%0Aname", "http://proxy.example:80#bad%ffname"} {
		parserTestReject(t, parserTestInput(raw), CodeInputInvalid, CodeFormatUnsupported)
	}
}

func TestSubscriptionParserTypedOptionsNoCoercion(t *testing.T) {
	base := "proxies:\n" + parserTestSS("node", "p")
	for _, raw := range []string{strings.Replace(base, "port: 443", "port: '443'", 1), strings.Replace(base, "port: 443", "port: 0x1bb", 1), strings.Replace(base, "port: 443", "port: 4.43", 1), base + "    udp: 'true'\n", base + "    tfo: yes\n", strings.Replace(base, `password: "p"`, "password: 42", 1)} {
		parserTestReject(t, parserTestInput(raw), CodeInputInvalid)
	}
	parserTestReject(t, parserTestInput("proxies:\n- {name: n, type: http, server: node.example, port: 80, skip-cert-verify: true}"), CodeFormatUnsupported)
	parserTestReject(t, parserTestInput("proxies:\n- {name: n, type: trojan, server: node.example, port: 443, password: p, network: ws, ws-opts: {early-data-header-name: X-Early}}"), CodeFormatUnsupported)
}

func TestSubscriptionParserPortsHostsCredentials(t *testing.T) {
	for _, address := range []string{"proxy.example:0", "proxy.example:65536", "-proxy.example:80", "proxy..example:80", "proxy.example.:80", "proxy_example:80", "[fe80::1%25eth0]:80"} {
		parserTestReject(t, parserTestInput("http://"+address), CodeInputInvalid)
	}
	for _, raw := range []string{"trojan://@tr.example:443", "vless://not-a-uuid@vl.example:443", "http://user:@proxy.example:80", "http://:pass@proxy.example:80"} {
		parserTestReject(t, parserTestInput(raw), CodeInputInvalid)
	}
	for _, raw := range []string{"http://127.0.0.1:1", "http://[2001:db8::1]:65535", "socks5://proxy.example:1080"} {
		_ = parserTestParse(t, parserTestInput(raw))
	}
}

func TestSubscriptionParserFailureSanitization(t *testing.T) {
	canary := "PRIVATE-URL-PASSWORD-CANARY"
	for _, raw := range []string{"proxies: [!" + canary + " x]", "trojan://" + canary + "@bad.example:999999", "proxies:\n" + parserTestSS(canary, canary) + "    unknown: " + canary, "ss://" + canary, "proxies: {\"" + canary + "\":"} {
		_, err := Parse(parserTestInput(raw))
		var failure *Failure
		if !errors.As(err, &failure) || strings.Contains(err.Error(), canary) || strings.Contains(err.Error(), "://") || err.Error() != string(failure.Code) {
			t.Fatal("raw parser error or private data escaped")
		}
	}
}

func TestSubscriptionParserDeterministicReparse(t *testing.T) {
	input := parserTestInput("proxies:\n" + parserTestSS("private one", "p") + parserTestSS("private two", "q") + parserTestSS("private duplicate", "p"))
	first := parserTestParse(t, input)
	for i := 0; i < 20; i++ {
		if got := parserTestParse(t, input); !reflect.DeepEqual(first, got) {
			t.Fatal("same private bytes cannot be independently revalidated")
		}
	}
	if first.Digest != "hmac-sha256:"+keyedDigest(input.IdentityKey, []byte(scopeKey(input.Scope)), []byte(input.SourceID), input.Content) {
		t.Fatal("original-byte digest formula mismatch")
	}
}

func TestSubscriptionParserConcurrentParsingNoSharedState(t *testing.T) {
	input := parserTestInput("proxies:\n" + parserTestSS("private", "secret"))
	first := parserTestParse(t, input)
	var group sync.WaitGroup
	failures := make(chan bool, 16)
	for i := 0; i < 16; i++ {
		group.Add(1)
		go func() {
			defer group.Done()
			got, err := Parse(input)
			failures <- err != nil || !reflect.DeepEqual(first, got)
		}()
	}
	group.Wait()
	close(failures)
	for failed := range failures {
		if failed {
			t.Fatal("parallel independent parsing changed result")
		}
	}
}
