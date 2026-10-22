package evidence

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

func TestImageTrustD7RecoveryViewVerifiedDetachedAndReadOnly(t *testing.T) {
	s := openTestStore(t)
	event := testEvent("image_trust.update")
	event.Data = map[string]string{"catalogueSHA256": "public-digest"}
	first, _, err := s.AppendOnce(event, "image-trust/op/prepared")
	if err != nil {
		t.Fatal(err)
	}
	second, err := s.Append(testEvent("other.observation"))
	if err != nil {
		t.Fatal(err)
	}
	before := s.Status()
	view, err := s.RecoverySnapshot()
	if err != nil {
		t.Fatal(err)
	}
	for count, expected := range []string{genesisHash, first.Hash, second.Hash} {
		if actual, ok := view.HashAt(uint64(count)); !ok || actual != expected {
			t.Fatal("wrong verified prefix")
		}
	}
	if _, ok := view.HashAt(3); ok {
		t.Fatal("invented prefix")
	}
	copy, ok := view.Lookup("image-trust/op/prepared")
	if !ok || copy.Hash != first.Hash {
		t.Fatal("committed event missing")
	}
	copy.Data["catalogueSHA256"] = "changed"
	copy, _ = view.Lookup("image-trust/op/prepared")
	if copy.Data["catalogueSHA256"] != "public-digest" {
		t.Fatal("mutable view")
	}
	if _, ok := view.Lookup("missing"); ok {
		t.Fatal("invented event")
	}
	if after := s.Status(); after.Count != before.Count || after.LastHash != before.LastHash {
		t.Fatal("snapshot appended audit")
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.RecoverySnapshot(); err == nil {
		t.Fatal("closed store accepted")
	}
}

func TestImageTrustD7RecoveryViewRejectsCorruptOrStaleAudit(t *testing.T) {
	for _, kind := range []string{"checkpoint-stale", "changed-record", "missing-checkpoint"} {
		t.Run(kind, func(t *testing.T) {
			s := openTestStore(t)
			if _, err := s.Append(testEvent("recovery.before")); err != nil {
				t.Fatal(err)
			}
			checkpointPath := filepath.Join(s.dir, checkpointFilename)
			logPath := filepath.Join(s.dir, logFilename)
			switch kind {
			case "checkpoint-stale":
				if err := os.WriteFile(checkpointPath, []byte(`{"count":0,"lastHash":"`+genesisHash+`"}`), 0600); err != nil {
					t.Fatal(err)
				}
			case "changed-record":
				raw, err := os.ReadFile(logPath)
				if err != nil {
					t.Fatal(err)
				}
				if err = os.WriteFile(logPath, bytes.Replace(raw, []byte("recovery.before"), []byte("recovery.changed"), 1), 0600); err != nil {
					t.Fatal(err)
				}
			case "missing-checkpoint":
				if err := os.Remove(checkpointPath); err != nil {
					t.Fatal(err)
				}
			}
			before, readErr := os.ReadFile(checkpointPath)
			if _, err := s.RecoverySnapshot(); err == nil {
				t.Fatal("corrupt audit accepted")
			}
			after, afterErr := os.ReadFile(checkpointPath)
			if !bytes.Equal(before, after) || (readErr == nil) != (afterErr == nil) {
				t.Fatal("recovery repaired checkpoint")
			}
		})
	}
}
