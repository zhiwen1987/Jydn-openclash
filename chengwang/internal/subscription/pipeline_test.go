//go:build linux

package subscription

// This exercises real loopback TLS, the actual parser and private Linux files.
// The package-private dial mapping is a fixture, not actual netns DNS wiring,
// public Internet, authenticated product API or device publication evidence.
import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"os"
	"strings"
	"sync/atomic"
	"testing"
)

func TestSubscriptionPipelineTLSQuarantineManySourcesAndRestart(t *testing.T) {
	const secret = "pipeline-private-credential"
	const initial = "proxies:\n  - name: private-name-pipeline-private-credential\n    type: trojan\n    server: node.example\n    port: 443\n    password: pipeline-private-credential\n"
	var body atomic.Value
	body.Store(initial)
	prototype, endpoint := newFetchTest(t, "", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/yaml")
		_, _ = w.Write([]byte(body.Load().(string)))
	})
	scope := fetchTestPolicy().Scope
	directory := t.TempDir()
	if err := os.Chmod(directory, 0700); err != nil {
		t.Fatal("prepare private pipeline directory")
	}
	store, err := OpenStore(directory)
	if err != nil {
		t.Fatal("open pipeline store")
	}
	t.Cleanup(func() { _ = store.Close() })
	first, err := store.CreateSource(scope, "来源甲", "operator-1", "pipeline-create-a-0001")
	if err != nil {
		t.Fatal("create first independent source")
	}
	second, err := store.CreateSource(scope, "来源乙", "operator-1", "pipeline-create-b-0001")
	if err != nil || first.ID == second.ID {
		t.Fatal("create second independent source")
	}
	fetchFor := func(source SourceView) FetchResult {
		t.Helper()
		policy := fetchTestPolicy()
		policy.SourceID = source.ID
		policy.Scope = source.Scope
		fetcher, err := NewFetcher(policy, FetchConfig{Resolver: fetchTestDNS(), RootCAs: endpoint.roots})
		if err != nil {
			t.Fatal("bind approved source fetcher")
		}
		fetcher.dialContext = prototype.dialContext
		result, err := fetcher.Fetch(context.Background())
		if err != nil || result.SourceID != source.ID || result.Scope != source.Scope {
			t.Fatal("fetch actual source bytes over normal TLS")
		}
		return result
	}
	readSource := func(id string) SourceView {
		t.Helper()
		values, err := store.Sources(scope)
		if err != nil {
			t.Fatal("read independent source revisions")
		}
		for _, value := range values {
			if value.ID == id {
				return value
			}
		}
		t.Fatal("source disappeared")
		return SourceView{}
	}
	importFor := func(source SourceView, key string) CandidateView {
		t.Helper()
		result := fetchFor(source)
		candidate, err := store.Import(ImportRequest{Scope: scope, SourceID: source.ID, ExpectedRevision: source.Revision,
			ActorID: "operator-1", IdempotencyKey: key, Format: FormatAuto, Content: result.Content})
		if err != nil || candidate.State != CandidateQuarantined || candidate.NodeCount != 1 || len(candidate.Nodes) != 1 || candidate.Nodes[0].State != "unknown" {
			t.Fatal("import actual bytes into quarantine without inventing health")
		}
		return candidate
	}
	admit := func(candidate CandidateView, key string) SourceView {
		t.Helper()
		current := readSource(candidate.SourceID)
		result, err := store.Decide(DecisionRequest{Scope: scope, SourceID: candidate.SourceID, CandidateID: candidate.ID,
			ExpectedRevision: current.Revision, ExpectedDigest: candidate.Digest, ActorID: "operator-1", IdempotencyKey: key, Decision: CandidateAdmitted})
		if err != nil || result.AcceptedCandidateID != candidate.ID || result.Revision != current.Revision+1 {
			t.Fatal("explicitly admit only a local candidate")
		}
		return result
	}
	firstCandidate := importFor(first, "pipeline-import-a-0001")
	if readSource(first.ID).AcceptedCandidateID != "" {
		t.Fatal("quarantine unexpectedly changed admission")
	}
	first = admit(firstCandidate, "pipeline-admit-a-0001")
	secondCandidate := importFor(second, "pipeline-import-b-0001")
	second = admit(secondCandidate, "pipeline-admit-b-0001")
	if firstCandidate.Nodes[0].ID == secondCandidate.Nodes[0].ID {
		t.Fatal("node identity crossed source provenance")
	}
	body.Store("proxies: [{name: unsafe, type: unimplemented, server: node.example, port: 443}]\n")
	bad := fetchFor(first)
	_, err = store.Import(ImportRequest{Scope: scope, SourceID: first.ID, ExpectedRevision: first.Revision,
		ActorID: "operator-1", IdempotencyKey: "pipeline-bad-a-0001", Format: FormatAuto, Content: bad.Content})
	if err == nil || readSource(first.ID) != first || readSource(second.ID) != second {
		t.Fatal("bad source update changed admitted resources")
	}
	body.Store(strings.Replace(initial, "private-name-pipeline-private-credential", "renamed-private-node", 1))
	renamed := importFor(first, "pipeline-import-a-0002")
	if renamed.Nodes[0].ID != firstCandidate.Nodes[0].ID || renamed.ID == firstCandidate.ID {
		t.Fatal("rename lost stable identity or original candidate provenance")
	}
	first = admit(renamed, "pipeline-admit-a-0002")
	rolled, err := store.Rollback(scope, first.ID, firstCandidate.ID, first.Revision, "operator-1", "pipeline-rollback-a-0001")
	if err != nil || rolled.Revision != first.Revision+1 || rolled.AcceptedCandidateID != firstCandidate.ID {
		t.Fatal("local rollback did not create a new revision")
	}
	if err := store.Close(); err != nil {
		t.Fatal("close pipeline store normally")
	}
	store, err = OpenStore(directory)
	if err != nil {
		t.Fatal("restart and revalidate private raw candidates")
	}
	if readSource(first.ID) != rolled || readSource(second.ID) != second {
		t.Fatal("restart lost independent admission revisions")
	}
	views, err := store.Sources(scope)
	if err != nil {
		t.Fatal("read reopened safe source views")
	}
	candidates, err := store.Candidates(scope, first.ID)
	if err != nil || len(candidates) != 2 {
		t.Fatal("read reopened safe candidate views")
	}
	raw, err := json.Marshal(struct {
		Sources    []SourceView
		Candidates []CandidateView
	}{views, candidates})
	if err != nil || bytes.Contains(raw, []byte(secret)) || bytes.Contains(raw, []byte(fetchTestSecret)) || bytes.Contains(raw, []byte("node.example")) {
		t.Fatal("public resource projection leaked private source material")
	}
	if endpoint.requests.Load() != 4 || endpoint.dials.Load() != 4 {
		t.Fatal("pipeline retried or fetched an unapproved nested source")
	}
}
