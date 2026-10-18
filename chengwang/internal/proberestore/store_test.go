package proberestore

import (
	"bytes"
	"encoding/json"
	"errors"
	"testing"
)

func TestOpenRejectsBlankPath(t *testing.T) {
	for _, path := range []string{"", " ", "\t\r\n"} {
		if _, err := Open(path); err == nil {
			t.Fatalf("Open(%q) accepted", path)
		}
	}
}

func TestExactJSONKeysRejectAliasesAtEveryJournalLevel(t *testing.T) {
	j := advance(t, validJournal(t), PhaseLocked)
	b, _ := json.Marshal(j)
	cases := map[string][]byte{
		"top case alias": bytes.Replace(b, []byte(`"schema"`), []byte(`"Schema"`), 1),
		"identity alias": bytes.Replace(b, []byte(`"candidateId"`), []byte(`"CandidateId"`), 1),
		"digest alias":   bytes.Replace(b, []byte(`"bindingSha256"`), []byte(`"BindingSha256"`), 1),
		"event alias":    bytes.Replace(b, []byte(`"reasonCode"`), []byte(`"ReasonCode"`), 1),
		"duplicate":      bytes.Replace(b, []byte(`"schema":`), []byte(`"schema":"x","schema":`), 1),
		"unknown":        bytes.Replace(b, []byte(`"schema":`), []byte(`"unknown":1,"schema":`), 1),
		"trailing":       append(append([]byte{}, b...), []byte(` {}`)...),
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeJournal(value); err == nil {
				t.Fatal("invalid JSON accepted")
			}
		})
	}
}

func TestExactControlKeysRejectAliasesDuplicatesAndTruncation(t *testing.T) {
	j := advance(t, validJournal(t), PhaseFailed)
	r := advanceControl(j, newControl(validJournal(t), nil))
	b, _ := json.Marshal(r)
	cases := map[string][]byte{
		"top alias":        bytes.Replace(b, []byte(`"generation"`), []byte(`"Generation"`), 1),
		"journal alias":    bytes.Replace(b, []byte(`"operationId"`), []byte(`"OperationId"`), 1),
		"head alias":       bytes.Replace(b, []byte(`"head":{"operationId"`), []byte(`"head":{"OperationId"`), 1),
		"receipt alias":    bytes.Replace(b, []byte(`"receipts":[{"operationId"`), []byte(`"receipts":[{"OperationId"`), 1),
		"duplicate":        bytes.Replace(b, []byte(`"schema":`), []byte(`"schema":"x","schema":`), 1),
		"unknown":          bytes.Replace(b, []byte(`"generation":`), []byte(`"unknown":1,"generation":`), 1),
		"truncated record": b[:len(b)/2],
	}
	for name, value := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := decodeControl(value); err == nil {
				t.Fatal("invalid control record accepted")
			}
		})
	}
	r.Receipts = nil
	b, _ = json.Marshal(r)
	if _, err := decodeControl(b); err == nil {
		t.Fatal("null receipts accepted")
	}
}

func TestControlBindsHeadGenerationAndUniqueReceipts(t *testing.T) {
	j := validJournal(t)
	r := newControl(j, nil)
	if err := validateControl(r); err != nil {
		t.Fatal(err)
	}
	for name, mutate := range map[string]func(*controlRecord){
		"generation": func(v *controlRecord) { v.Generation = 0 },
		"sequence":   func(v *controlRecord) { v.Head.Sequence++ },
		"head":       func(v *controlRecord) { v.Head.HeadSHA256 = hashOf('f') },
		"manifest":   func(v *controlRecord) { v.Head.ManifestSHA256 = hashOf('f') },
	} {
		t.Run(name, func(t *testing.T) {
			v := r
			mutate(&v)
			if !errors.Is(validateControl(v), ErrReplayDetected) {
				t.Fatal("replay accepted")
			}
		})
	}
	terminal := advance(t, j, PhaseFailed)
	tr := advanceControl(terminal, r)
	if err := validateControl(tr); err != nil {
		t.Fatal(err)
	}
	tr.Receipts[0].Sequence--
	if !errors.Is(validateControl(tr), ErrReplayDetected) {
		t.Fatal("old terminal receipt accepted")
	}

	tr = advanceControl(terminal, r)
	duplicate := tr.Receipts[0]
	duplicate.OperationID = "restore-99"
	duplicate.BackupID = "backup-99"
	tr.Receipts = append(tr.Receipts, duplicate)
	if !errors.Is(validateControl(tr), ErrReplayDetected) {
		t.Fatal("duplicate manifest receipt accepted")
	}
}
