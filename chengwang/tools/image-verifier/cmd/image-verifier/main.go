// image-verifier consumes one bounded JSON request on stdin. It never fetches
// roots, opens candidate paths, or authorizes deployment. Run under an external
// process timeout/resource limit: the upstream cryptographic API cannot be
// interrupted mid-verification by the signal context.
package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"unicode/utf8"

	verifier "chengwang-image-verifier"
)

const maxRequestBytes = 3 << 20

var errRequest = errors.New("invalid request")

type request struct {
	expected verifier.Expected
	bundle   []byte
	root     []byte
}

func main() {
	if len(os.Args) != 1 {
		os.Exit(fail(os.Stdout))
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(runWithContext(ctx, os.Stdin, os.Stdout))
}

func run(input io.Reader, output io.Writer) int {
	return runWithContext(context.Background(), input, output)
}

func runWithContext(ctx context.Context, input io.Reader, output io.Writer) int {
	if ctx == nil || ctx.Err() != nil {
		return fail(output)
	}
	r, err := parseRequest(input)
	if err != nil || ctx.Err() != nil {
		return fail(output)
	}
	result, err := verifier.Verify(ctx, r.expected, r.bundle, r.root)
	if err != nil || !result.Verified() {
		return fail(output)
	}
	// No certificate, identity, predicate, raw request, root, or SDK error is
	// emitted. A successful cryptographic observation remains advisory only.
	response := struct {
		Boundary          string `json:"boundary"`
		Authorization     string `json:"authorization"`
		ArtifactSHA256    string `json:"artifactSHA256"`
		BundleSHA256      string `json:"bundleSHA256"`
		TrustedRootSHA256 string `json:"trustedRootSHA256"`
	}{result.Boundary(), result.Authorization(), result.ArtifactSHA256(), result.BundleSHA256(), result.TrustedRootSHA256()}
	if json.NewEncoder(output).Encode(response) != nil {
		return 1
	}
	return 0
}

func fail(output io.Writer) int {
	_, _ = io.WriteString(output, "{\"error\":\"INVALID_REQUEST_OR_PROOF\",\"authorization\":\"BLOCKED\"}\n")
	return 1
}

func parseRequest(input io.Reader) (request, error) {
	raw, err := io.ReadAll(io.LimitReader(input, maxRequestBytes+1))
	if err != nil || len(raw) == 0 || len(raw) > maxRequestBytes || !utf8.Valid(raw) {
		return request{}, errRequest
	}
	d := json.NewDecoder(bytes.NewReader(raw))
	if !takeDelimiter(d, '{') {
		return request{}, errRequest
	}
	r := request{}
	seen := map[string]bool{}
	for d.More() {
		key, ok := takeString(d, 32)
		if !ok || seen[key] {
			return request{}, errRequest
		}
		seen[key] = true
		switch key {
		case "expected":
			r.expected, err = parseExpected(d)
		case "bundle", "trustedRoot":
			limit := verifier.MaxBundleBytes
			if key == "trustedRoot" {
				limit = verifier.MaxRootBytes
			}
			var encoded string
			encoded, ok = takeString(d, base64.StdEncoding.EncodedLen(limit))
			if !ok || encoded == "" {
				return request{}, errRequest
			}
			var decoded []byte
			decoded, err = base64.StdEncoding.Strict().DecodeString(encoded)
			if err == nil && (len(decoded) == 0 || len(decoded) > limit || base64.StdEncoding.EncodeToString(decoded) != encoded) {
				err = errRequest
			}
			if key == "bundle" {
				r.bundle = decoded
			} else {
				r.root = decoded
			}
		default:
			return request{}, errRequest
		}
		if err != nil {
			return request{}, errRequest
		}
	}
	if len(seen) != 3 || !takeDelimiter(d, '}') {
		return request{}, errRequest
	}
	if _, err := d.Token(); err != io.EOF {
		return request{}, errRequest
	}
	return r, nil
}

func parseExpected(d *json.Decoder) (verifier.Expected, error) {
	e := verifier.Expected{}
	if !takeDelimiter(d, '{') {
		return e, errRequest
	}
	fields := map[string]*string{
		"artifactSHA256": &e.ArtifactSHA256, "trustedRootSHA256": &e.TrustedRootSHA256,
		"logID": &e.LogID, "issuer": &e.Issuer, "san": &e.SAN,
		"subjectName": &e.SubjectName, "predicateType": &e.PredicateType,
	}
	seen := map[string]bool{}
	for d.More() {
		key, ok := takeString(d, 32)
		if !ok || seen[key] {
			return verifier.Expected{}, errRequest
		}
		seen[key] = true
		value, ok := takeString(d, 2048)
		if !ok {
			return verifier.Expected{}, errRequest
		}
		if key == "kind" {
			e.Kind = verifier.Kind(value)
		} else if field, exists := fields[key]; exists {
			*field = value
		} else {
			return verifier.Expected{}, errRequest
		}
	}
	if !takeDelimiter(d, '}') {
		return verifier.Expected{}, errRequest
	}
	for _, required := range []string{"artifactSHA256", "trustedRootSHA256", "logID", "issuer", "san", "kind"} {
		if !seen[required] {
			return verifier.Expected{}, errRequest
		}
	}
	return e, nil
}

func takeDelimiter(d *json.Decoder, want json.Delim) bool {
	token, err := d.Token()
	return err == nil && token == want
}

func takeString(d *json.Decoder, limit int) (string, bool) {
	token, err := d.Token()
	value, ok := token.(string)
	return value, err == nil && ok && len(value) <= limit && !strings.ContainsRune(value, utf8.RuneError)
}
