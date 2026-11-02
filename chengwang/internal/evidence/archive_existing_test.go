package evidence

import (
	"encoding/json"
	"errors"
	"fmt"
	"reflect"
	"strings"
	"testing"
)

func TestArchiveEvidenceAnchorIsCachedValueProjection(t *testing.T) {
	anchor := ArchiveEvidenceAnchor{
		Root: ArchiveDirectoryAnchor{
			Identity:       ArchivePosixIdentity{Device: 1, Inode: 2, Mode: 040700, UID: 3, GID: 4, LinkCount: 5},
			EntryCount:     3,
			EntrySetSHA256: [32]byte{1, 2, 3},
		},
		Lock:            ArchiveFileAnchor{Identity: ArchivePosixIdentity{Inode: 6}, SHA256: [32]byte{4}},
		Log:             ArchiveFileAnchor{Identity: ArchivePosixIdentity{Inode: 7}, Length: 8, SHA256: [32]byte{5}},
		Checkpoint:      ArchiveFileAnchor{Identity: ArchivePosixIdentity{Inode: 9}, Length: 10, SHA256: [32]byte{6}},
		EventCount:      11,
		EventHead:       [32]byte{7},
		CheckpointCount: 11,
		CheckpointHead:  [32]byte{7},
	}
	snapshot := &ExistingArchiveSnapshot{anchor: anchor}
	first := snapshot.Anchor()
	first.EventCount = 99
	first.EventHead[0] = 99
	first.Root.Identity.Inode = 99
	if got := snapshot.Anchor(); got != anchor {
		t.Fatalf("caller mutation aliased cached anchor: got %#v", got)
	}
	if err := snapshot.Close(); err != nil {
		t.Fatalf("close empty projection handle: %v", err)
	}
	if got := snapshot.Anchor(); got != anchor {
		t.Fatal("close changed cached anchor")
	}
	var nilSnapshot *ExistingArchiveSnapshot
	if got := nilSnapshot.Anchor(); got != (ArchiveEvidenceAnchor{}) {
		t.Fatal("nil receiver did not return a zero projection")
	}
}

func TestArchiveProjectionFormattingAndSerializationAreRedacted(t *testing.T) {
	values := []any{
		ArchivePosixIdentity{Device: 12345},
		ArchiveDirectoryAnchor{EntryCount: 3},
		ArchiveFileAnchor{Length: 12345},
		ArchiveEvidenceAnchor{EventCount: 12345},
		ArchiveExistingReadLimits{MaxLogBytes: 12345, MaxEvents: 12345},
	}
	for _, value := range values {
		for _, rendered := range []string{fmt.Sprintf("%v", value), fmt.Sprintf("%#v", value)} {
			if !strings.Contains(rendered, "<redacted>") || strings.Contains(rendered, "12345") {
				t.Fatalf("projection formatting leaked fields: %q", rendered)
			}
		}
		if _, err := json.Marshal(value); !errors.Is(err, ErrArchiveProjectionForbidden) {
			t.Fatalf("JSON marshal did not reject %T: %v", value, err)
		}
		text, ok := value.(interface{ MarshalText() ([]byte, error) })
		if !ok {
			t.Fatalf("%T does not implement text marshaling rejection", value)
		}
		if _, err := text.MarshalText(); !errors.Is(err, ErrArchiveProjectionForbidden) {
			t.Fatalf("text marshal did not reject %T: %v", value, err)
		}
	}
	var decoded ArchiveEvidenceAnchor
	if err := json.Unmarshal([]byte(`{}`), &decoded); !errors.Is(err, ErrArchiveProjectionForbidden) {
		t.Fatalf("JSON unmarshal did not reject: %v", err)
	}
	if err := decoded.UnmarshalText([]byte("value")); !errors.Is(err, ErrArchiveProjectionForbidden) {
		t.Fatalf("text unmarshal did not reject: %v", err)
	}
}

func TestExistingArchiveSnapshotFormattingIsFixedAndOpaque(t *testing.T) {
	snapshot := ExistingArchiveSnapshot{
		anchor: ArchiveEvidenceAnchor{EventCount: 12345},
		state:  &existingArchiveSnapshotState{},
	}
	stateField, ok := reflect.TypeOf(snapshot).FieldByName("state")
	if !ok || stateField.Type.Kind() != reflect.Pointer {
		t.Fatal("snapshot must retain private state by pointer so value formatting never copies an active mutex")
	}
	for _, rendered := range []string{
		fmt.Sprintf("%v", snapshot),
		fmt.Sprintf("%+v", snapshot),
		fmt.Sprintf("%#v", snapshot),
		fmt.Sprintf("%v", &snapshot),
		fmt.Sprintf("%+v", &snapshot),
		fmt.Sprintf("%#v", &snapshot),
	} {
		if rendered != "evidence.ExistingArchiveSnapshot<redacted>" {
			t.Fatalf("snapshot formatting was not fixed redaction: %q", rendered)
		}
		for _, sentinel := range []string{"12345", "events.jsonl", "checkpoint.json", "writer.lock", "fd="} {
			if strings.Contains(rendered, sentinel) {
				t.Fatalf("snapshot formatting leaked %q: %q", sentinel, rendered)
			}
		}
	}
}

func TestArchiveProjectionContainsOnlyFixedValues(t *testing.T) {
	assertFixedProjectionType(t, reflect.TypeOf(ArchiveEvidenceAnchor{}), map[reflect.Type]bool{})
}

func assertFixedProjectionType(t *testing.T, value reflect.Type, seen map[reflect.Type]bool) {
	t.Helper()
	if seen[value] {
		return
	}
	seen[value] = true
	switch value.Kind() {
	case reflect.Struct:
		for i := 0; i < value.NumField(); i++ {
			assertFixedProjectionType(t, value.Field(i).Type, seen)
		}
	case reflect.Array:
		assertFixedProjectionType(t, value.Elem(), seen)
	case reflect.Uint8, reflect.Uint32, reflect.Uint64:
		return
	default:
		t.Fatalf("projection contains forbidden %s type %s", value.Kind(), value)
	}
}
