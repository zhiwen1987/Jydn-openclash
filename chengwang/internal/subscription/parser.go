package subscription

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"io"
	"net"
	"net/url"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf8"

	"go.yaml.in/yaml/v3"
)

// Parse admits a deliberately closed subset of real provider formats. It does
// not fetch, test connectivity, compile a kernel config or assert node health.
// Unknown options (including plugins, reality, multiplexing, dialer proxies and
// unimplemented transports) reject the WHOLE input, never a partially valid set.
// Config and names remain private, including credentials and transport headers.
func Parse(input ParseInput) (Parsed, error) {
	if !validScope(input.Scope) || !validSource(input.SourceID) || len(input.IdentityKey) != 32 {
		return Parsed{}, fail(CodeInputInvalid)
	}
	if len(input.Content) > MaxInputBytes {
		return Parsed{}, fail(CodeInputLimit)
	}
	if !utf8.Valid(input.Content) || bytes.IndexByte(input.Content, 0) >= 0 {
		return Parsed{}, fail(CodeInputInvalid)
	}
	content := bytes.TrimSpace(input.Content)
	if len(content) == 0 {
		return Parsed{}, fail(CodeEmpty)
	}
	format := input.Format
	if format == "" || format == FormatAuto {
		first := bytes.TrimPrefix(content, []byte{0xef, 0xbb, 0xbf})
		for _, line := range bytes.Split(first, []byte("\n")) {
			line = bytes.TrimSpace(line)
			if len(line) != 0 && line[0] != '#' {
				first = line
				break
			}
		}
		if bytes.HasPrefix(first, []byte("proxies:")) || bytes.HasPrefix(first, []byte("---")) || bytes.HasPrefix(first, []byte("{")) {
			format = FormatMihomo
		} else if bytes.Contains(content, []byte("://")) {
			format = FormatURI
		} else {
			format = FormatBase64URI
		}
	}
	var objects []map[string]any
	var err error
	switch format {
	case FormatMihomo:
		objects, err = parserProvider(content)
	case FormatURI, FormatBase64URI:
		if format == FormatBase64URI {
			content, err = parserBase64(string(content), true)
		}
		if err == nil {
			objects, err = parserURIs(content)
		}
	default:
		err = fail(CodeFormatUnsupported)
	}
	if err != nil {
		return Parsed{}, err
	}
	if len(objects) == 0 {
		return Parsed{}, fail(CodeEmpty)
	}
	if len(objects) > MaxNodes {
		return Parsed{}, fail(CodeInputLimit)
	}
	result := Parsed{Format: format, Digest: "hmac-sha256:" + keyedDigest(input.IdentityKey, []byte(scopeKey(input.Scope)), []byte(input.SourceID), input.Content)}
	unique := make(map[string]ParsedNode, len(objects))
	for _, object := range objects {
		credential, validateErr := parserValidate(object)
		if validateErr != nil {
			return Parsed{}, validateErr
		}
		name := object["name"].(string)
		connection := make(map[string]any, len(object)-1)
		for key, value := range object {
			if key != "name" {
				connection[key] = value
			}
		}
		canonical, marshalErr := json.Marshal(connection)
		if marshalErr != nil {
			return Parsed{}, fail(CodeInputInvalid)
		}
		id := "node_" + keyedDigest(input.IdentityKey, []byte(scopeKey(input.Scope)), []byte(input.SourceID), canonical)[:32]
		if previous, ok := unique[id]; ok {
			// A truncated-ID collision must not silently merge distinct configs.
			var old map[string]any
			if json.Unmarshal(previous.Config, &old) != nil {
				return Parsed{}, fail(CodeInputInvalid)
			}
			delete(old, "name")
			oldRaw, _ := json.Marshal(old)
			if !bytes.Equal(canonical, oldRaw) {
				return Parsed{}, fail(CodeConflict)
			}
			result.DuplicateCount++
			if previous.PrivateName <= name {
				continue
			}
		}
		raw, marshalErr := json.Marshal(object)
		if marshalErr != nil {
			return Parsed{}, fail(CodeInputInvalid)
		}
		unique[id] = ParsedNode{ID: id, Protocol: object["type"].(string), PrivateName: name, Config: raw, CredentialConfigured: credential}
	}
	for _, node := range unique {
		result.Nodes = append(result.Nodes, node)
	}
	sort.Slice(result.Nodes, func(i, j int) bool { return result.Nodes[i].ID < result.Nodes[j].ID })
	return result, nil
}

func parserProvider(raw []byte) ([]map[string]any, error) {
	value, err := parserYAML(raw)
	if err != nil {
		return nil, err
	}
	root, ok := value.(map[string]any)
	if !ok || len(root) != 1 {
		return nil, fail(CodeFormatUnsupported)
	}
	list, ok := root["proxies"].([]any)
	if !ok {
		return nil, fail(CodeInputInvalid)
	}
	if len(list) > MaxNodes {
		return nil, fail(CodeInputLimit)
	}
	objects := make([]map[string]any, 0, len(list))
	for _, item := range list {
		object, valid := item.(map[string]any)
		if !valid {
			return nil, fail(CodeInputInvalid)
		}
		objects = append(objects, object)
	}
	return objects, nil
}

func parserYAML(raw []byte) (any, error) {
	decoder := yaml.NewDecoder(bytes.NewReader(raw))
	var document yaml.Node
	if decoder.Decode(&document) != nil || document.Kind != yaml.DocumentNode || len(document.Content) != 1 {
		return nil, fail(CodeInputInvalid)
	}
	var extra yaml.Node
	if decoder.Decode(&extra) != io.EOF {
		return nil, fail(CodeInputInvalid)
	}
	// yaml.Node drops TaggedStyle for the non-specific `!` tag on quoted
	// scalars and collections. Retain its original start token as well, rather
	// than accidentally accepting those explicit tags through the AST check.
	textLines := strings.Split(string(raw), "\n")
	lines := make([][]rune, len(textLines))
	for i, line := range textLines {
		lines[i] = []rune(line)
	}
	count := 0
	return parserYAMLValue(document.Content[0], 1, &count, lines)
}

var parserDecimal = regexp.MustCompile(`^(0|[1-9][0-9]*)$`)
var parserUUID = regexp.MustCompile(`^[a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12}$`)

func parserYAMLValue(node *yaml.Node, depth int, count *int, lines [][]rune) (any, error) {
	(*count)++
	if depth > MaxDepth || *count > MaxSyntaxNodes || len(node.Value) > MaxScalarBytes {
		return nil, fail(CodeInputLimit)
	}
	if node.Anchor != "" || node.Alias != nil || node.Kind == yaml.AliasNode || node.Style&yaml.TaggedStyle != 0 {
		return nil, fail(CodeInputInvalid)
	}
	if node.Line > 0 && node.Line <= len(lines) && node.Column > 0 && node.Column <= len(lines[node.Line-1]) && lines[node.Line-1][node.Column-1] == '!' {
		return nil, fail(CodeInputInvalid)
	}
	switch node.Kind {
	case yaml.MappingNode:
		if node.Tag != "!!map" || len(node.Content)%2 != 0 {
			return nil, fail(CodeInputInvalid)
		}
		object := make(map[string]any, len(node.Content)/2)
		for i := 0; i < len(node.Content); i += 2 {
			key, err := parserYAMLValue(node.Content[i], depth+1, count, lines)
			if err != nil {
				return nil, err
			}
			text, ok := key.(string)
			if !ok || text == "" || text == "<<" {
				return nil, fail(CodeInputInvalid)
			}
			if _, duplicate := object[text]; duplicate {
				return nil, fail(CodeInputInvalid)
			}
			value, err := parserYAMLValue(node.Content[i+1], depth+1, count, lines)
			if err != nil {
				return nil, err
			}
			object[text] = value
		}
		return object, nil
	case yaml.SequenceNode:
		if node.Tag != "!!seq" {
			return nil, fail(CodeInputInvalid)
		}
		values := make([]any, 0, len(node.Content))
		for _, child := range node.Content {
			value, err := parserYAMLValue(child, depth+1, count, lines)
			if err != nil {
				return nil, err
			}
			values = append(values, value)
		}
		return values, nil
	case yaml.ScalarNode:
		switch node.Tag {
		case "!!str":
			if !parserText(node.Value, true) {
				return nil, fail(CodeInputInvalid)
			}
			return node.Value, nil
		case "!!int":
			if !parserDecimal.MatchString(node.Value) {
				return nil, fail(CodeInputInvalid)
			}
			number, err := strconv.Atoi(node.Value)
			if err != nil {
				return nil, fail(CodeInputInvalid)
			}
			return number, nil
		case "!!bool":
			if node.Value == "true" {
				return true, nil
			}
			if node.Value == "false" {
				return false, nil
			}
		}
	}
	return nil, fail(CodeInputInvalid)
}

func parserText(value string, empty bool) bool {
	return (empty || value != "") && len(value) <= MaxScalarBytes && utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsControl)
}

func parserHost(value string) (string, bool) {
	if ip := net.ParseIP(value); ip != nil {
		return ip.String(), true
	}
	if len(value) == 0 || len(value) > 253 || strings.HasSuffix(value, ".") {
		return "", false
	}
	for _, label := range strings.Split(value, ".") {
		if len(label) == 0 || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return "", false
		}
		for _, character := range label {
			if character != '-' && !(character >= 'a' && character <= 'z') && !(character >= 'A' && character <= 'Z') && !(character >= '0' && character <= '9') {
				return "", false
			}
		}
	}
	return strings.ToLower(value), true
}

func parserKeys(object map[string]any, allowed string) bool {
	set := strings.Fields(allowed)
	for key := range object {
		found := false
		for _, candidate := range set {
			found = found || key == candidate
		}
		if !found {
			return false
		}
	}
	return true
}

func parserString(object map[string]any, key string, required bool) bool {
	value, exists := object[key]
	if !exists {
		return !required
	}
	text, ok := value.(string)
	return ok && parserText(text, !required)
}

func parserValidate(object map[string]any) (bool, error) {
	protocol, ok := object["type"].(string)
	if !ok {
		return false, fail(CodeInputInvalid)
	}
	fields := "name type server port udp tfo"
	switch protocol {
	case "ss":
		fields += " cipher password"
	case "vmess":
		fields += " uuid alterId cipher tls servername alpn client-fingerprint skip-cert-verify network ws-opts grpc-opts"
	case "vless":
		fields += " uuid flow tls servername alpn client-fingerprint skip-cert-verify network ws-opts grpc-opts"
	case "trojan":
		fields += " password sni alpn client-fingerprint skip-cert-verify network ws-opts grpc-opts"
	case "http", "socks5":
		fields += " username password tls sni skip-cert-verify"
		if protocol == "http" {
			fields += " headers"
		}
	default:
		return false, fail(CodeProtocolUnsupported)
	}
	if !parserKeys(object, fields) {
		return false, fail(CodeFormatUnsupported)
	}
	if !parserString(object, "name", true) || !parserString(object, "server", true) {
		return false, fail(CodeInputInvalid)
	}
	host, valid := parserHost(object["server"].(string))
	port, number := object["port"].(int)
	if !valid || !number || port < 1 || port > 65535 {
		return false, fail(CodeInputInvalid)
	}
	object["server"] = host
	for _, key := range []string{"udp", "tfo", "tls", "skip-cert-verify"} {
		if value, exists := object[key]; exists {
			flag, boolean := value.(bool)
			if !boolean {
				return false, fail(CodeInputInvalid)
			}
			if key == "skip-cert-verify" && flag {
				return false, fail(CodeFormatUnsupported)
			}
		}
	}
	for _, key := range []string{"password", "username", "cipher", "uuid", "flow", "sni", "servername", "network", "client-fingerprint"} {
		if !parserString(object, key, false) {
			return false, fail(CodeInputInvalid)
		}
	}
	credential := false
	switch protocol {
	case "ss":
		cipher, _ := object["cipher"].(string)
		if !parserString(object, "password", true) || !parserMember(cipher, "aes-128-gcm aes-192-gcm aes-256-gcm chacha20-ietf-poly1305 xchacha20-ietf-poly1305 2022-blake3-aes-128-gcm 2022-blake3-aes-256-gcm 2022-blake3-chacha20-poly1305") {
			return false, fail(CodeFormatUnsupported)
		}
		credential = true
	case "vmess", "vless":
		uuid, _ := object["uuid"].(string)
		if !parserUUID.MatchString(uuid) {
			return false, fail(CodeInputInvalid)
		}
		object["uuid"] = strings.ToLower(uuid)
		credential = true
		if protocol == "vmess" {
			cipher, cipherOK := object["cipher"].(string)
			alter, alterOK := object["alterId"].(int)
			if !cipherOK || !parserMember(cipher, "auto none zero aes-128-gcm chacha20-poly1305") || !alterOK || alter < 0 || alter > 65535 {
				return false, fail(CodeInputInvalid)
			}
		} else if flow, present := object["flow"]; present && flow != "" && flow != "xtls-rprx-vision" {
			return false, fail(CodeFormatUnsupported)
		}
	case "trojan":
		if !parserString(object, "password", true) {
			return false, fail(CodeInputInvalid)
		}
		credential = true
	case "http", "socks5":
		_, user := object["username"]
		_, password := object["password"]
		if user != password || user && (!parserString(object, "username", true) || !parserString(object, "password", true)) {
			return false, fail(CodeInputInvalid)
		}
		credential = user
	}
	for _, key := range []string{"sni", "servername"} {
		if value, exists := object[key]; exists {
			if _, hostOK := parserHost(value.(string)); !hostOK {
				return false, fail(CodeInputInvalid)
			}
		}
	}
	if list, exists := object["alpn"]; exists {
		values, listOK := list.([]any)
		if !listOK || len(values) == 0 || len(values) > 16 {
			return false, fail(CodeInputInvalid)
		}
		for _, value := range values {
			text, stringOK := value.(string)
			if !stringOK || !parserText(text, false) {
				return false, fail(CodeInputInvalid)
			}
		}
	}
	if headers, exists := object["headers"]; exists && !parserHeaders(headers) {
		return false, fail(CodeInputInvalid)
	}
	if err := parserTransport(object); err != nil {
		return false, err
	}
	return credential, nil
}

func parserMember(value, allowed string) bool {
	for _, item := range strings.Fields(allowed) {
		if item == value {
			return true
		}
	}
	return false
}

func parserHeaders(value any) bool {
	object, ok := value.(map[string]any)
	if !ok || len(object) > 64 {
		return false
	}
	for key := range object {
		if !parserText(key, false) || !parserString(object, key, false) {
			return false
		}
	}
	return true
}

func parserTransport(object map[string]any) error {
	network, _ := object["network"].(string)
	if network != "" && !parserMember(network, "tcp ws grpc") {
		return fail(CodeFormatUnsupported)
	}
	for _, pair := range [][2]string{{"ws-opts", "ws"}, {"grpc-opts", "grpc"}} {
		value, present := object[pair[0]]
		if !present {
			continue
		}
		options, ok := value.(map[string]any)
		if !ok || network != pair[1] {
			return fail(CodeInputInvalid)
		}
		if pair[1] == "ws" {
			if !parserKeys(options, "path headers") {
				return fail(CodeFormatUnsupported)
			}
			if !parserString(options, "path", false) {
				return fail(CodeInputInvalid)
			}
			if headers, exists := options["headers"]; exists && !parserHeaders(headers) {
				return fail(CodeInputInvalid)
			}
		} else if !parserKeys(options, "grpc-service-name") {
			return fail(CodeFormatUnsupported)
		} else if !parserString(options, "grpc-service-name", true) {
			return fail(CodeInputInvalid)
		}
	}
	return nil
}

func parserBase64(value string, wrapped bool) ([]byte, error) {
	if wrapped {
		value = strings.Map(func(r rune) rune {
			if r == ' ' || r == '\t' || r == '\r' || r == '\n' {
				return -1
			}
			return r
		}, value)
	} else if strings.ContainsAny(value, " \t\r\n") {
		return nil, fail(CodeInputInvalid)
	}
	for _, encoding := range []*base64.Encoding{base64.StdEncoding.Strict(), base64.RawStdEncoding.Strict(), base64.URLEncoding.Strict(), base64.RawURLEncoding.Strict()} {
		raw, err := encoding.DecodeString(value)
		if err == nil && len(raw) <= MaxInputBytes && utf8.Valid(raw) && bytes.IndexByte(raw, 0) < 0 {
			return raw, nil
		}
	}
	return nil, fail(CodeInputInvalid)
}

func parserURIs(raw []byte) ([]map[string]any, error) {
	if !utf8.Valid(raw) || len(raw) > MaxInputBytes {
		return nil, fail(CodeInputInvalid)
	}
	objects := make([]map[string]any, 0)
	for _, line := range strings.Split(string(raw), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if len(objects) >= MaxNodes {
			return nil, fail(CodeInputLimit)
		}
		if len(line) > MaxScalarBytes*4 || !parserTextURI(line) {
			return nil, fail(CodeInputLimit)
		}
		object, err := parserURI(line)
		if err != nil {
			return nil, err
		}
		objects = append(objects, object)
	}
	return objects, nil
}

func parserTextURI(value string) bool {
	return utf8.ValidString(value) && !strings.ContainsFunc(value, unicode.IsSpace) && !strings.ContainsFunc(value, unicode.IsControl)
}

func parserURI(value string) (map[string]any, error) {
	if strings.HasPrefix(value, "vmess://") {
		return parserVMess(strings.TrimPrefix(value, "vmess://"))
	}
	if strings.HasPrefix(value, "ss://") {
		// SIP002 and the legacy base64(method:password@server:port) form.
		payload := strings.TrimPrefix(value, "ss://")
		beforeFragment, fragment, hasFragment := strings.Cut(payload, "#")
		if !strings.Contains(beforeFragment, "@") {
			decoded, err := parserBase64(beforeFragment, false)
			if err != nil {
				return nil, err
			}
			separator := strings.LastIndexByte(string(decoded), '@')
			if separator < 1 {
				return nil, fail(CodeInputInvalid)
			}
			credentials, address := string(decoded[:separator]), string(decoded[separator+1:])
			method, password, valid := strings.Cut(credentials, ":")
			if !valid {
				return nil, fail(CodeInputInvalid)
			}
			value = "ss://" + url.UserPassword(method, password).String() + "@" + address
			if hasFragment {
				value += "#" + fragment
			}
		}
	}
	u, err := url.Parse(value)
	if err != nil || u.Opaque != "" || u.Host == "" || u.ForceQuery || u.RawPath != "" || u.Path != "" && u.Path != "/" {
		return nil, fail(CodeInputInvalid)
	}
	protocol := u.Scheme
	if protocol == "https" {
		protocol = "http"
	}
	if !parserMember(protocol, "ss vless trojan http socks5") {
		return nil, fail(CodeProtocolUnsupported)
	}
	port, err := strconv.Atoi(u.Port())
	if err != nil || !parserDecimal.MatchString(u.Port()) {
		return nil, fail(CodeInputInvalid)
	}
	name := u.Fragment
	if name == "" {
		name = "imported"
	}
	object := map[string]any{"name": name, "type": protocol, "server": u.Hostname(), "port": port}
	query, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return nil, fail(CodeInputInvalid)
	}
	for _, values := range query {
		if len(values) != 1 {
			return nil, fail(CodeInputInvalid)
		}
	}
	if protocol == "ss" {
		if len(query) != 0 || u.User == nil {
			return nil, fail(CodeFormatUnsupported)
		}
		method := u.User.Username()
		password, exists := u.User.Password()
		if !exists {
			decoded, decodeErr := parserBase64(method, false)
			if decodeErr != nil {
				return nil, decodeErr
			}
			method, password, exists = strings.Cut(string(decoded), ":")
		}
		if !exists {
			return nil, fail(CodeInputInvalid)
		}
		object["cipher"], object["password"] = method, password
	} else if protocol == "http" || protocol == "socks5" {
		if len(query) != 0 {
			return nil, fail(CodeFormatUnsupported)
		}
		if u.User != nil {
			password, exists := u.User.Password()
			if !exists {
				return nil, fail(CodeInputInvalid)
			}
			object["username"], object["password"] = u.User.Username(), password
		}
		if u.Scheme == "https" {
			object["tls"] = true
		}
	} else {
		if u.User == nil {
			return nil, fail(CodeInputInvalid)
		}
		if _, password := u.User.Password(); password {
			return nil, fail(CodeInputInvalid)
		}
		if protocol == "vless" {
			object["uuid"] = u.User.Username()
		} else {
			object["password"] = u.User.Username()
		}
		if err := parserURIOptions(object, query); err != nil {
			return nil, err
		}
	}
	return object, nil
}

func parserURIOptions(object map[string]any, query url.Values) error {
	for key := range query {
		if !parserMember(key, "encryption security type sni host path serviceName alpn fp flow") {
			return fail(CodeFormatUnsupported)
		}
	}
	protocol := object["type"].(string)
	if value, exists := query["encryption"]; exists && (protocol != "vless" || value[0] != "none") {
		return fail(CodeFormatUnsupported)
	}
	if value, exists := query["security"]; exists {
		if value[0] != "tls" && (value[0] != "none" || protocol == "trojan") {
			return fail(CodeFormatUnsupported)
		}
		if protocol == "vless" {
			object["tls"] = value[0] == "tls"
		}
	}
	if value, exists := query["sni"]; exists {
		key := "servername"
		if protocol == "trojan" {
			key = "sni"
		}
		object[key] = value[0]
	}
	if value, exists := query["fp"]; exists {
		object["client-fingerprint"] = value[0]
	}
	if value, exists := query["flow"]; exists {
		if protocol != "vless" {
			return fail(CodeFormatUnsupported)
		}
		object["flow"] = value[0]
	}
	if value, exists := query["alpn"]; exists {
		list := make([]any, 0)
		for _, item := range strings.Split(value[0], ",") {
			list = append(list, item)
		}
		object["alpn"] = list
	}
	network := query.Get("type")
	if network == "" {
		network = "tcp"
	}
	object["network"] = network
	if network == "ws" {
		options := make(map[string]any)
		if value, exists := query["path"]; exists {
			options["path"] = value[0]
		}
		if value, exists := query["host"]; exists {
			options["headers"] = map[string]any{"Host": value[0]}
		}
		object["ws-opts"] = options
	} else if query.Has("host") || query.Has("path") {
		return fail(CodeFormatUnsupported)
	}
	if network == "grpc" {
		object["grpc-opts"] = map[string]any{"grpc-service-name": query.Get("serviceName")}
	} else if query.Has("serviceName") {
		return fail(CodeFormatUnsupported)
	}
	return nil
}

func parserVMess(payload string) (map[string]any, error) {
	raw, err := parserBase64(payload, false)
	if err != nil {
		return nil, err
	}
	if !json.Valid(raw) {
		return nil, fail(CodeInputInvalid)
	}
	decoded, err := parserYAML(raw)
	if err != nil {
		return nil, err
	}
	value, ok := decoded.(map[string]any)
	if !ok || !parserKeys(value, "v ps add port id aid scy net type host path tls sni alpn fp") {
		return nil, fail(CodeFormatUnsupported)
	}
	for key := range value {
		if key == "port" || key == "aid" || key == "v" {
			continue
		}
		if !parserString(value, key, false) {
			return nil, fail(CodeInputInvalid)
		}
	}
	integer := func(key string, defaultValue int) (int, bool) {
		v, exists := value[key]
		if !exists {
			return defaultValue, true
		}
		if n, valid := v.(int); valid {
			return n, true
		}
		text, valid := v.(string)
		if !valid || !parserDecimal.MatchString(text) {
			return 0, false
		}
		n, parseErr := strconv.Atoi(text)
		return n, parseErr == nil
	}
	version, validVersion := integer("v", 2)
	port, validPort := integer("port", 0)
	alter, validAlter := integer("aid", 0)
	if !validVersion || version != 2 || !validPort || !validAlter {
		return nil, fail(CodeInputInvalid)
	}
	get := func(key, defaultValue string) string {
		text, _ := value[key].(string)
		if text == "" {
			return defaultValue
		}
		return text
	}
	if get("type", "none") != "none" {
		return nil, fail(CodeFormatUnsupported)
	}
	object := map[string]any{"name": get("ps", "imported"), "type": "vmess", "server": get("add", ""), "port": port, "uuid": get("id", ""), "alterId": alter, "cipher": get("scy", "auto")}
	query := url.Values{"type": {get("net", "tcp")}}
	for source, target := range map[string]string{"host": "host", "path": "path", "sni": "sni", "alpn": "alpn", "fp": "fp"} {
		if text := get(source, ""); text != "" {
			query.Set(target, text)
		}
	}
	if tls := get("tls", ""); tls != "" {
		if tls != "tls" && tls != "none" {
			return nil, fail(CodeFormatUnsupported)
		}
		object["tls"] = tls == "tls"
	}
	if err := parserURIOptions(object, query); err != nil {
		return nil, err
	}
	return object, nil
}
