//go:build linux && probereadbacklab

// Package probereadbacklab is an isolated CI driver, never a product writer.
package probereadbacklab

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"chengwang/internal/probe"
)

type rejected struct{ step string }

func demand(ok bool, step string) {
	if !ok {
		panic(rejected{step})
	}
}
func encoded(v any) []byte   { b, e := json.Marshal(v); demand(e == nil, "JSON_ENCODE"); return b }
func digest(b []byte) string { s := sha256.Sum256(b); return hex.EncodeToString(s[:]) }
func same(a, b any) bool     { return bytes.Equal(encoded(a), encoded(b)) }

// Duplicate-key and trailing-value rejection is independent of typed decode.
func decode(raw []byte, out any) {
	d := json.NewDecoder(bytes.NewReader(raw))
	d.UseNumber()
	var value func(int)
	value = func(depth int) {
		demand(depth <= 20, "JSON_DEPTH")
		tok, e := d.Token()
		demand(e == nil, "JSON_TOKEN")
		if mark, ok := tok.(json.Delim); ok {
			demand(mark == '{' || mark == '[', "JSON_DELIMITER")
			seen := map[string]bool{}
			for d.More() {
				if mark == '{' {
					k, e := d.Token()
					s, ok := k.(string)
					demand(e == nil && ok && !seen[s], "JSON_DUPLICATE")
					seen[s] = true
				}
				value(depth + 1)
			}
			end, e := d.Token()
			demand(e == nil && ((mark == '{' && end == json.Delim('}')) || (mark == '[' && end == json.Delim(']'))), "JSON_CLOSE")
		}
	}
	value(0)
	_, e := d.Token()
	demand(e == io.EOF, "JSON_EOF")
	d = json.NewDecoder(bytes.NewReader(raw))
	d.DisallowUnknownFields()
	demand(d.Decode(out) == nil && d.Decode(new(any)) == io.EOF, "JSON_SCHEMA")
}

func metadata(path string, dir bool) os.FileInfo {
	s, e := os.Lstat(path)
	demand(e == nil, "FILE_MISSING")
	x, ok := s.Sys().(*syscall.Stat_t)
	demand(ok && x.Uid == 10001 && x.Gid == 10001, "FILE_OWNER")
	demand(s.Mode()&(os.ModeSetuid|os.ModeSetgid|os.ModeSticky) == 0, "FILE_SPECIAL_MODE")
	if dir {
		demand(s.IsDir() && s.Mode().Perm() == 0700 && s.Mode()&os.ModeType == os.ModeDir, "DIRECTORY_MODE")
	} else {
		demand(s.Mode().IsRegular() && s.Mode().Perm() == 0600 && x.Nlink == 1, "FILE_MODE")
	}
	return s
}
func readFile(path string, limit int64) []byte {
	before := metadata(path, false)
	demand(before.Size() >= 0 && before.Size() <= limit, "FILE_SIZE")
	fd, e := syscall.Open(path, syscall.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK|syscall.O_CLOEXEC, 0)
	demand(e == nil, "FILE_OPEN")
	f := os.NewFile(uintptr(fd), "lab-input")
	defer f.Close()
	opened, e := f.Stat()
	demand(e == nil && os.SameFile(before, opened), "FILE_IDENTITY")
	raw, e := io.ReadAll(io.LimitReader(f, limit+1))
	demand(e == nil && int64(len(raw)) <= limit, "FILE_READ")
	after, e := f.Stat()
	named := metadata(path, false)
	demand(e == nil && os.SameFile(before, after) && os.SameFile(after, named) && before.Size() == after.Size() && before.ModTime() == after.ModTime() && after.Size() == int64(len(raw)), "FILE_CHANGED")
	initialStat := before.Sys().(*syscall.Stat_t)
	finalStat := after.Sys().(*syscall.Stat_t)
	namedStat := named.Sys().(*syscall.Stat_t)
	demand(initialStat.Ctim == finalStat.Ctim && finalStat.Ctim == namedStat.Ctim && initialStat.Mode == finalStat.Mode && finalStat.Nlink == 1, "FILE_METADATA_CHANGED")
	return raw
}
func writeFile(path string, raw []byte) {
	f, e := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
	demand(e == nil, "OUTPUT_EXISTS")
	n, e := f.Write(raw)
	if e != nil || n != len(raw) {
		_ = f.Close()
		demand(false, "OUTPUT_WRITE")
	}
	demand(f.Sync() == nil, "OUTPUT_SYNC")
	demand(f.Close() == nil, "OUTPUT_CLOSE")
	d, e := os.Open(filepath.Dir(path))
	demand(e == nil, "OUTPUT_DIRECTORY")
	e = d.Sync()
	_ = d.Close()
	demand(e == nil, "OUTPUT_DIRSYNC")
}
func mkdir(path string) { demand(os.Mkdir(path, 0700) == nil, "DIRECTORY_EXISTS") }

type sourceFile struct {
	Path   string `json:"path"`
	Bytes  int    `json:"bytes"`
	SHA256 string `json:"sha256"`
}
type rawFile struct {
	Name   string `json:"name"`
	Raw    []byte `json:"raw"`
	SHA256 string `json:"sha256"`
}
type tree struct {
	Files []sourceFile
	Raw   map[string][]byte
	SHA   string
}

var segmentName = regexp.MustCompile(`^[0-9]{20}-[a-f0-9]{16}\.json$`)

func sourceTree(root string) tree {
	t := tree{Files: []sourceFile{}, Raw: map[string][]byte{}}
	add := func(rel string) {
		b := readFile(filepath.Join(root, filepath.FromSlash(rel)), 64<<10)
		t.Raw[rel] = b
		t.Files = append(t.Files, sourceFile{rel, len(b), digest(b)})
	}
	add("catalog.json")
	for _, name := range []string{"spool", "ledger"} {
		base := filepath.Join(root, name)
		metadata(base, true)
		entries, e := os.ReadDir(base)
		demand(e == nil && len(entries) == 2, "STATE_ROOT_CLOSED_SET")
		dir, lock := "segments", ".probe-spool.lock"
		if name == "ledger" {
			dir, lock = "snapshots", ".probe-start-ledger.lock"
		}
		for _, entry := range entries {
			demand(entry.Name() == dir || entry.Name() == lock, "STATE_EXTRA_ENTRY")
		}
		add(name + "/" + lock)
		metadata(filepath.Join(base, dir), true)
		children, e := os.ReadDir(filepath.Join(base, dir))
		demand(e == nil && len(children) <= 16, "STATE_LIMIT")
		for _, child := range children {
			demand(!child.IsDir() && segmentName.MatchString(child.Name()), "STATE_EXTRA_DIRECTORY")
			add(name + "/" + dir + "/" + child.Name())
		}
	}
	sort.Slice(t.Files, func(i, j int) bool { return t.Files[i].Path < t.Files[j].Path })
	var b strings.Builder
	for _, f := range t.Files {
		b.WriteString(f.Path + "\t" + strconv.Itoa(f.Bytes) + "\t" + f.SHA256 + "\n")
	}
	t.SHA = digest([]byte(b.String()))
	return t
}
func rawEntries(t tree, prefix string) []rawFile {
	out := []rawFile{}
	for _, f := range t.Files {
		if strings.HasPrefix(f.Path, prefix) {
			out = append(out, rawFile{strings.TrimPrefix(f.Path, prefix), t.Raw[f.Path], f.SHA256})
		}
	}
	return out
}

type spoolPayload struct {
	Schema        string            `json:"schema"`
	CatalogDigest string            `json:"catalogDigest"`
	Result        probe.ProbeResult `json:"result"`
}
type spoolDisk struct {
	Schema        string            `json:"schema"`
	CatalogDigest string            `json:"catalogDigest"`
	Result        probe.ProbeResult `json:"result"`
	Digest        string            `json:"digest"`
}
type ledgerPayload struct {
	Schema          string                       `json:"schema"`
	CatalogDigest   string                       `json:"catalogDigest"`
	DirectoryDigest string                       `json:"directoryDigest"`
	AgentID         string                       `json:"agentId"`
	Sequence        uint64                       `json:"sequence"`
	LastClock       time.Time                    `json:"lastClock"`
	Starts          []probe.StartLedgerEntry     `json:"starts"`
	RateLimits      []probe.StartLedgerRateLimit `json:"rateLimits,omitempty"`
}
type ledgerDisk struct {
	ledgerPayload
	Digest string `json:"digest"`
}

func readResults(t tree, catalog probe.Catalog, now time.Time) []probe.ProbeResult {
	out := []probe.ProbeResult{}
	runs := map[string]bool{}
	starts := map[string]bool{}
	for _, file := range rawEntries(t, "spool/segments/") {
		var s spoolDisk
		decode(file.Raw, &s)
		demand(s.Schema == probe.SpoolSchemaV1 && s.CatalogDigest == catalog.Digest && s.Digest == "sha256:"+digest(encoded(spoolPayload{s.Schema, s.CatalogDigest, s.Result})), "SPOOL_DIGEST")
		r := s.Result
		want := fmtSegment(r.CompletedAt, s.Digest)
		demand(file.Name == want && r.SchemaVersion == probe.ResultSchemaV1 && r.CatalogDigest == catalog.Digest && r.AgentID == catalog.Agent.ID && r.Independence == probe.IndependenceP1 && r.AdvisoryOnly, "SPOOL_BINDING")
		demand(!runs[r.RunID] && !starts[r.EvidenceRef] && r.RunID != "" && r.EvidenceRef != "" && r.PathID == "direct", "SPOOL_DUPLICATE")
		demand(!r.CompletedAt.Before(r.AttemptedAt) && !r.CompletedAt.After(now) && r.ExpiresAt.Equal(r.CompletedAt.Add(120*time.Second)), "SPOOL_TIME")
		code := 200
		conclusion, outcome := probe.ConclusionAvailable, probe.OutcomePass
		switch r.ProbeID {
		case "pass":
		case "restricted":
			code = 403
			conclusion, outcome = probe.ConclusionRestricted, probe.OutcomeIndeterminate
		case "limited":
			code = 429
			conclusion, outcome = probe.ConclusionRateLimited, probe.OutcomeIndeterminate
		default:
			demand(false, "SPOOL_TARGET")
		}
		demand(r.HTTPStatus != nil && *r.HTTPStatus == code && r.Conclusion == conclusion && r.Outcome == outcome, "SPOOL_ACTUAL_HTTP")
		body := []byte("chengwang-probe-" + r.ProbeID + "-v1\n")
		demand(r.ResponseBytes == int64(len(body)) && r.ContentDigest == "sha256:"+digest(body), "SPOOL_ACTUAL_RESPONSE_BYTES")
		demand(r.Layers.DNS.State == probe.LayerAvailable && r.Layers.Connect.State == probe.LayerAvailable && r.Layers.TLS.State == probe.LayerAvailable && r.Layers.HTTP.State == probe.LayerAvailable && r.Layers.Business.State == probe.LayerState(conclusion), "SPOOL_ACTUAL_LAYERS")
		if code == 429 {
			demand(r.Layers.Business.RetryAfterSeconds == 30, "RATE_LIMIT_BINDING")
		}
		runs[r.RunID], starts[r.EvidenceRef] = true, true
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CompletedAt.Equal(out[j].CompletedAt) {
			return out[i].RunID < out[j].RunID
		}
		return out[i].CompletedAt.Before(out[j].CompletedAt)
	})
	return out
}
func fmtSegment(at time.Time, sha string) string {
	return strings.Repeat("0", max(0, 20-len(strconv.FormatInt(at.UnixNano(), 10)))) + strconv.FormatInt(at.UnixNano(), 10) + "-" + strings.TrimPrefix(sha, "sha256:")[:16] + ".json"
}
func readLedger(t tree, root string, catalog probe.Catalog, now time.Time) ledgerDisk {
	files := rawEntries(t, "ledger/snapshots/")
	demand(len(files) == 1, "LEDGER_SNAPSHOT_COUNT")
	var s ledgerDisk
	decode(files[0].Raw, &s)
	demand(s.Schema == probe.StartLedgerSchemaV2 && s.CatalogDigest == catalog.Digest && s.AgentID == catalog.Agent.ID && s.DirectoryDigest == "sha256:"+digest([]byte(filepath.Join(root, "ledger"))), "LEDGER_BINDING")
	demand(s.Digest == "sha256:"+digest(encoded(s.ledgerPayload)) && !s.LastClock.IsZero() && !s.LastClock.After(now), "LEDGER_DIGEST")
	want := strconv.FormatUint(s.Sequence, 10)
	want = strings.Repeat("0", max(0, 20-len(want))) + want + "-" + strings.TrimPrefix(s.Digest, "sha256:")[:16] + ".json"
	demand(files[0].Name == want, "LEDGER_FILENAME")
	return s
}
