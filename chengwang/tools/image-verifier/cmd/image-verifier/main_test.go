package main

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

const failureOutput = "{\"error\":\"INVALID_REQUEST_OR_PROOF\",\"authorization\":\"BLOCKED\"}\n"

func fixtureRequest(t *testing.T, dsse bool) string {
	t.Helper()
	name, kind := "message.sigstore.json", "message-signature"
	if dsse {
		name, kind = "dsse.sigstore.json", "dsse"
	}
	bundle, err := os.ReadFile("../../testdata/" + name)
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.ReadFile("../../testdata/trusted-root.json")
	if err != nil {
		t.Fatal(err)
	}
	expected := map[string]string{
		"artifactSHA256":    "sha256:a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf",
		"trustedRootSHA256": "sha256:4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c",
		"logID":             "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d",
		"issuer":            "https://token.actions.githubusercontent.com",
		"san":               "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main",
		"kind":              kind,
	}
	if dsse {
		expected["subjectName"] = "a.txt"
		expected["predicateType"] = "https://slsa.dev/provenance/v1"
	}
	raw, err := json.Marshal(map[string]any{"expected": expected, "bundle": base64.StdEncoding.EncodeToString(bundle), "trustedRoot": base64.StdEncoding.EncodeToString(root)})
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

func TestRunOfficialFixtures(t *testing.T) {
	for _, dsse := range []bool{false, true} {
		name := "message"
		wantBundle := "sha256:82382358bdf586d1a184820ac0d0ff06eb737f459fe03baebbbd2c76e80b54a9"
		if dsse {
			name = "dsse"
			wantBundle = "sha256:0b205ad5900e2f8009cb97a1e97c38e7759a64e4356ac97797bf3cbf7d7551c7"
		}
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if code := run(strings.NewReader(fixtureRequest(t, dsse)), &out); code != 0 {
				t.Fatalf("code %d output %s", code, out.String())
			}
			var result map[string]string
			if err := json.Unmarshal(out.Bytes(), &result); err != nil {
				t.Fatal(err)
			}
			if len(result) != 5 || result["boundary"] != "ADVISORY_SIGSTORE_BUNDLE_VERIFIED" || result["authorization"] != "BLOCKED" || result["bundleSHA256"] != wantBundle || result["artifactSHA256"] != "sha256:a0cfc71271d6e278e57cd332ff957c3f7043fdda354c4cbb190a30d56efa01bf" || result["trustedRootSHA256"] != "sha256:4364d7724c04cc912ce2a6c45ed2610e8d8d1c4dc857fb500292738d4d9c8d2c" {
				t.Fatalf("unexpected public output %s", out.String())
			}
		})
	}
}

func TestRunRejectsAmbiguousRequests(t *testing.T) {
	valid := fixtureRequest(t, false)
	cases := map[string]string{
		"empty": "", "null": "null", "array": "[]", "incomplete": "{", "missing": "{}",
		"unknown":           strings.Replace(valid, "{", "{\"secret\":\"DO_NOT_LEAK\",", 1),
		"duplicate":         strings.Replace(valid, "{", "{\"bundle\":\"AA==\",", 1),
		"escapedDuplicate":  strings.Replace(valid, "{", "{\"b\\u0075ndle\":\"AA==\",", 1),
		"caseAlias":         strings.Replace(valid, "\"bundle\":", "\"Bundle\":", 1),
		"nullBundle":        strings.Replace(valid, "\"bundle\":", "\"bundle\":null,\"unused\":", 1),
		"unknownExpected":   strings.Replace(valid, "\"expected\":{", "\"expected\":{\"secret\":\"DO_NOT_LEAK\",", 1),
		"duplicateExpected": strings.Replace(valid, "\"expected\":{", "\"expected\":{\"kind\":\"dsse\",", 1),
		"caseAliasExpected": strings.Replace(valid, "artifactSHA256", "ArtifactSHA256", 1),
		"missingExpected":   strings.Replace(valid, "\"kind\":\"message-signature\",", "", 1),
		"nullExpected":      strings.Replace(valid, "\"expected\":{", "\"expected\":null,\"unused\":{", 1),
		"nestedExpected":    strings.Replace(valid, "\"kind\":\"message-signature\"", "\"kind\":{}", 1),
		"policyWrong":       strings.Replace(valid, "https://token.actions.githubusercontent.com", "https://untrusted.invalid", 1),
		"trailingObject":    valid + " {}", "trailingNull": valid + " null", "trailingGarbage": valid + " secret",
		"invalidUTF8": string([]byte{0xff}),
		"oversize":    strings.Repeat(" ", maxRequestBytes+1),
	}
	for name, input := range cases {
		t.Run(name, func(t *testing.T) {
			var out bytes.Buffer
			if code := run(strings.NewReader(input), &out); code == 0 || out.String() != failureOutput {
				t.Fatalf("code %d output %q", code, out.String())
			}
		})
	}
}

func TestParseOfficialRequests(t *testing.T) {
	for _, dsse := range []bool{false, true} {
		r, err := parseRequest(strings.NewReader(fixtureRequest(t, dsse)))
		wantKind, wantLength := "message-signature", 10054
		if dsse {
			wantKind, wantLength = "dsse", 11737
		}
		if err != nil || string(r.expected.Kind) != wantKind || len(r.bundle) != wantLength || len(r.root) != 7014 || r.expected.LogID != "c0d23d6ad406973f9559f3ba2d1ca01f84147d8ffc5b8445c224f98b9591801d" {
			t.Fatalf("incorrect parsed request: kind=%s bundle=%d root=%d err=%v", r.expected.Kind, len(r.bundle), len(r.root), err)
		}
	}
}

func TestCLIProcessContract(t *testing.T) {
	executable := filepath.Join(t.TempDir(), "image-verifier")
	if runtime.GOOS == "windows" {
		executable += ".exe"
	}
	buildCtx, stopBuild := context.WithTimeout(context.Background(), 120*time.Second)
	defer stopBuild()
	build := exec.CommandContext(buildCtx, "go", "build", "-mod=readonly", "-o", executable, ".")
	if output, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build CLI: %v: %s", err, output)
	}
	for _, dsse := range []bool{false, true} {
		name := "message"
		if dsse {
			name = "dsse"
		}
		t.Run(name, func(t *testing.T) {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			cmd := exec.CommandContext(ctx, executable)
			cmd.Stdin = strings.NewReader(fixtureRequest(t, dsse))
			output, err := cmd.CombinedOutput()
			if err != nil || !bytes.Contains(output, []byte(`"authorization":"BLOCKED"`)) || !bytes.Contains(output, []byte(`"boundary":"ADVISORY_SIGSTORE_BUNDLE_VERIFIED"`)) {
				t.Fatalf("CLI fixture %s: %v output %s", name, err, output)
			}
		})
	}
	t.Run("tampered-policy", func(t *testing.T) {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable)
		cmd.Stdin = strings.NewReader(strings.Replace(fixtureRequest(t, false), "https://token.actions.githubusercontent.com", "https://untrusted.invalid", 1))
		output, err := cmd.CombinedOutput()
		var exit *exec.ExitError
		if !errors.As(err, &exit) || exit.ExitCode() != 1 || string(output) != failureOutput {
			t.Fatalf("CLI tamper failure: %v output %q", err, output)
		}
	})
	t.Run("external-hard-deadline", func(t *testing.T) {
		// Hold the inherited stdin pipe open without supplying EOF. A signal
		// context cannot cancel this blocking read; the parent process deadline
		// must kill the actual child. This does NOT prove SDK crypto cancellation.
		readEnd, writeEnd, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		defer readEnd.Close()
		defer writeEnd.Close()
		ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
		defer cancel()
		cmd := exec.CommandContext(ctx, executable)
		cmd.Stdin = readEnd
		started := time.Now()
		if err := cmd.Start(); err != nil {
			t.Fatal(err)
		}
		if err := cmd.Wait(); err == nil || ctx.Err() != context.DeadlineExceeded || time.Since(started) > 5*time.Second {
			t.Fatalf("external kill not demonstrated: error=%v context=%v elapsed=%s", err, ctx.Err(), time.Since(started))
		}
	})
}

func TestParseRejectsBase64AndSizes(t *testing.T) {
	valid := fixtureRequest(t, false)
	var fields map[string]any
	if err := json.Unmarshal([]byte(valid), &fields); err != nil {
		t.Fatal(err)
	}
	for name, encoded := range map[string]string{
		"empty": "", "invalid": "DO_NOT_LEAK", "newline": "AA==\n",
		"noncanonicalPadding": "AB==", "noPadding": "AA", "oversizeDecoded": base64.StdEncoding.EncodeToString(make([]byte, (1<<20)+1)),
	} {
		t.Run(name, func(t *testing.T) {
			fields["bundle"] = encoded
			raw, _ := json.Marshal(fields)
			if _, err := parseRequest(bytes.NewReader(raw)); err == nil {
				t.Fatal("accepted invalid base64")
			}
		})
	}
	fields["bundle"] = "AA=="
	fields["expected"].(map[string]any)["san"] = strings.Repeat("x", 2049)
	raw, _ := json.Marshal(fields)
	if _, err := parseRequest(bytes.NewReader(raw)); err == nil {
		t.Fatal("accepted oversized policy field")
	}
}

type badReader struct{}

func (badReader) Read([]byte) (int, error) { return 0, errors.New("DO_NOT_LEAK") }

type badWriter struct{}

func (badWriter) Write([]byte) (int, error) { return 0, errors.New("DO_NOT_LEAK") }

func TestIOErrorsAndCancellationAreClosed(t *testing.T) {
	var out bytes.Buffer
	if run(badReader{}, &out) == 0 || out.String() != failureOutput {
		t.Fatal("reader failure leaked or passed")
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	out.Reset()
	if runWithContext(ctx, strings.NewReader(fixtureRequest(t, false)), &out) == 0 || out.String() != failureOutput {
		t.Fatal("cancelled input passed")
	}
	if run(strings.NewReader(fixtureRequest(t, false)), badWriter{}) == 0 {
		t.Fatal("write failure passed")
	}
	if run(strings.NewReader("{}"), io.Discard) == 0 {
		t.Fatal("invalid input passed with discarded output")
	}
}
