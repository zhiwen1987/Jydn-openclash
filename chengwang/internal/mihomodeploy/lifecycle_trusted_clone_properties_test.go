package mihomodeploy

import (
	"bytes"
	"encoding/json"
	"fmt"
	"reflect"
	"testing"
	"time"
)

// Typed-data properties only. Dense values are not valid WALs, principals,
// issued bases, owners, native processes or physical recovery observations.
type lifecycleClonePropertyStep struct {
	kind  byte
	index int
}
type lifecycleClonePropertySlot struct {
	name string
	path []lifecycleClonePropertyStep
}
type lifecycleClonePropertyCodec string

func (lifecycleClonePropertyCodec) MarshalJSON() ([]byte, error) { return []byte(`"MODEL"`), nil }

func lifecycleClonePropertyFill(t *testing.T, v reflect.Value, next *int, seen map[reflect.Type]bool) {
	t.Helper()
	(*next)++
	if v.Type() == reflect.TypeOf(time.Time{}) {
		v.Set(reflect.ValueOf(time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC).Add(time.Duration(*next) * time.Nanosecond)))
		return
	}
	if v.Type() == reflect.TypeOf((*json.RawMessage)(nil)) {
		v.SetZero() // current valid-domain RawMessage is nil; fallback is separate
		return
	}
	switch v.Kind() {
	case reflect.Struct:
		seen[v.Type()] = true
		for i := 0; i < v.NumField(); i++ {
			if !v.Field(i).CanSet() {
				t.Fatal("MODEL unexpected hidden business field")
			}
			lifecycleClonePropertyFill(t, v.Field(i), next, seen)
		}
	case reflect.Pointer:
		v.Set(reflect.New(v.Type().Elem()))
		lifecycleClonePropertyFill(t, v.Elem(), next, seen)
	case reflect.Slice:
		v.Set(reflect.MakeSlice(v.Type(), 1, 2))
		full := v.Slice(0, v.Cap())
		for i := 0; i < full.Len(); i++ {
			lifecycleClonePropertyFill(t, full.Index(i), next, seen)
		}
	case reflect.String:
		v.SetString(fmt.Sprintf("MODEL_%d", *next))
	case reflect.Bool:
		v.SetBool(true)
	case reflect.Int, reflect.Int64:
		v.SetInt(int64(*next))
	case reflect.Uint8:
		v.SetUint(uint64(*next%200 + 1))
	case reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(uint64(*next))
	default:
		t.Fatal("MODEL unexpected business type")
	}
}

func lifecycleClonePropertyDense(t *testing.T) lifecycleV3Record {
	t.Helper()
	w := &lifecycleV3Wire{}
	next, seen := 0, map[reflect.Type]bool{}
	lifecycleClonePropertyFill(t, reflect.ValueOf(w).Elem(), &next, seen)
	if len(seen) != 56 {
		t.Fatal("MODEL reachable structural schema changed")
	}
	return lifecycleV3Record{core: w}
}

func lifecycleClonePropertySmall() lifecycleV3Record {
	return lifecycleV3Record{core: &lifecycleV3Wire{
		LastTrustedAt: time.Date(2026, 10, 25, 0, 0, 0, 0, time.UTC),
		Current: lifecycleEpochLedger{
			Head:   lifecycleHead{Artifact: ArtifactDescriptor{Config: LabConfigDescriptor{Capabilities: []string{"MODEL"}}}},
			Active: &lifecycleActive{},
		},
	}}
}

func lifecycleClonePropertyRaw(t *testing.T, v any) []byte {
	t.Helper()
	raw, err := json.Marshal(v)
	if err != nil {
		t.Fatal("MODEL JSON source unavailable")
	}
	return raw
}

func lifecycleClonePropertyOldCopy(t *testing.T, raw []byte) lifecycleV3Record {
	t.Helper()
	var w lifecycleV3Wire
	if json.Unmarshal(raw, &w) != nil {
		t.Fatal("MODEL old JSON copy unavailable")
	}
	return lifecycleV3Record{core: &w}
}

func lifecycleClonePropertyCopied(t *testing.T, in lifecycleV3Record) lifecycleV3Record {
	t.Helper()
	raw := lifecycleClonePropertyRaw(t, in.core)
	old := lifecycleClonePropertyOldCopy(t, raw)
	// The old operation is Unmarshal(raw), not a byte-preserving JSON round
	// trip. Invalid UTF-8 becomes U+FFFD; encoding that valid rune again need
	// not reproduce the initial escaped replacement spelling.
	expected := lifecycleClonePropertyRaw(t, old.core)
	before := bytes.Clone(raw)
	out, err := cloneTrustedLifecycleV3(in, raw)
	if err != nil || out.core == nil || !reflect.DeepEqual(out.core, old.core) || !bytes.Equal(lifecycleClonePropertyRaw(t, out.core), expected) {
		t.Fatal("MODEL trusted copy differs from original JSON operation")
	}
	if !bytes.Equal(raw, before) || !bytes.Equal(raw, lifecycleClonePropertyRaw(t, in.core)) {
		t.Fatal("MODEL trusted copy changed its raw or typed source")
	}
	return out
}

func lifecycleClonePropertyPath(path []lifecycleClonePropertyStep, step lifecycleClonePropertyStep) []lifecycleClonePropertyStep {
	out := append([]lifecycleClonePropertyStep(nil), path...)
	return append(out, step)
}

func lifecycleClonePropertySlots(v reflect.Value, path []lifecycleClonePropertyStep, seen map[string]bool, slots *[]lifecycleClonePropertySlot) {
	if v.Type() == reflect.TypeOf(time.Time{}) {
		return // opaque immutable leaf
	}
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			lifecycleClonePropertySlots(v.Elem(), lifecycleClonePropertyPath(path, lifecycleClonePropertyStep{'*', 0}), seen, slots)
		}
	case reflect.Slice:
		if v.Len() > 0 {
			lifecycleClonePropertySlots(v.Index(v.Len()-1), lifecycleClonePropertyPath(path, lifecycleClonePropertyStep{'[', v.Len() - 1}), seen, slots)
		}
	case reflect.Struct:
		for i := 0; i < v.NumField(); i++ {
			f := v.Field(i)
			p := lifecycleClonePropertyPath(path, lifecycleClonePropertyStep{'.', i})
			name := v.Type().String() + "." + v.Type().Field(i).Name
			if (f.Kind() == reflect.Pointer || f.Kind() == reflect.Slice) && !seen[name] {
				seen[name] = true
				*slots = append(*slots, lifecycleClonePropertySlot{name, p})
			}
			lifecycleClonePropertySlots(f, p, seen, slots)
		}
	}
}

func lifecycleClonePropertyAt(v reflect.Value, path []lifecycleClonePropertyStep) reflect.Value {
	for _, step := range path {
		switch step.kind {
		case '.':
			v = v.Field(step.index)
		case '*':
			v = v.Elem()
		case '[':
			v = v.Index(step.index)
		}
	}
	return v
}

func lifecycleClonePropertySparseAt(path []lifecycleClonePropertyStep) (lifecycleV3Record, reflect.Value) {
	w := &lifecycleV3Wire{}
	v := reflect.ValueOf(w).Elem()
	for _, step := range path {
		switch step.kind {
		case '.':
			v = v.Field(step.index)
		case '*':
			if v.IsNil() {
				v.Set(reflect.New(v.Type().Elem()))
			}
			v = v.Elem()
		case '[':
			if v.Len() <= step.index {
				v.Set(reflect.MakeSlice(v.Type(), step.index+1, step.index+1))
			}
			v = v.Index(step.index)
		}
	}
	return lifecycleV3Record{core: w}, v
}

func lifecycleClonePropertyChange(v reflect.Value) {
	if v.Type() == reflect.TypeOf(time.Time{}) {
		v.Set(reflect.ValueOf(v.Interface().(time.Time).Add(time.Second)))
		return
	}
	switch v.Kind() {
	case reflect.Pointer:
		if v.IsNil() {
			v.Set(reflect.New(v.Type().Elem()))
		}
		lifecycleClonePropertyChange(v.Elem())
	case reflect.Slice:
		if v.Len() == 0 {
			v.Set(reflect.Append(v, reflect.Zero(v.Type().Elem())))
		}
		lifecycleClonePropertyChange(v.Index(v.Len() - 1))
	case reflect.Struct:
		if v.NumField() > 0 {
			lifecycleClonePropertyChange(v.Field(0))
		}
	case reflect.String:
		v.SetString("MUTATED_" + v.String())
	case reflect.Bool:
		v.SetBool(!v.Bool())
	case reflect.Int, reflect.Int64:
		v.SetInt(v.Int() + 1)
	case reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(v.Uint() + 1)
	}
}

func TestLifecycleRecoveryTrustedCloneCanonicalGraphAndShape(t *testing.T) {
	in := lifecycleClonePropertyDense(t)
	// Positive control: every currently reachable struct is traversed by the
	// typed path, not silently covered by the JSON fallback instead.
	c := &lifecycleCloneState{}
	direct := c.wire(*in.core)
	if c.err != nil || !reflect.DeepEqual(in.core, &direct) || !lifecycleCloneTypeSchema() || !lifecycleCloneTypeSchemaFor(reflect.TypeOf(lifecycleV3Wire{})) {
		t.Fatal("MODEL canonical 56-struct fast path or known STD pointer shape rejected")
	}
	out := lifecycleClonePropertyCopied(t, in)
	before := lifecycleClonePropertyRaw(t, in.core)
	var slots []lifecycleClonePropertySlot
	lifecycleClonePropertySlots(reflect.ValueOf(in.core).Elem(), nil, map[string]bool{}, &slots)
	if len(slots) != 79 {
		t.Fatal("MODEL mutable type-field coverage changed")
	}
	for _, slot := range slots {
		t.Run(slot.name, func(t *testing.T) {
			original := lifecycleClonePropertyAt(reflect.ValueOf(in.core).Elem(), slot.path)
			if original.Kind() == reflect.Pointer && original.IsNil() {
				return // Raw nil is a distinct fallback case
			}
			changed := lifecycleClonePropertyAt(reflect.ValueOf(out.core).Elem(), slot.path)
			if original.Pointer() == changed.Pointer() {
				t.Fatal("MODEL mutable business storage aliases original")
			}
			lifecycleClonePropertyChange(changed)
		})
	}
	if !bytes.Equal(before, lifecycleClonePropertyRaw(t, in.core)) {
		t.Fatal("MODEL clone mutations changed source graph")
	}
	for _, slot := range slots {
		t.Run("nil-empty-"+slot.name, func(t *testing.T) {
			// Only allocate the selected path, rather than cloning the complete
			// dense fixture once for each nil/empty/capacity table row.
			seed, value := lifecycleClonePropertySparseAt(slot.path)
			value.SetZero()
			zero := lifecycleClonePropertyCopied(t, seed)
			if !lifecycleClonePropertyAt(reflect.ValueOf(zero.core).Elem(), slot.path).IsNil() {
				t.Fatal("MODEL nil became nonnil")
			}
			if value.Kind() == reflect.Pointer {
				if value.Type() == reflect.TypeOf((*json.RawMessage)(nil)) {
					return // its nonnil null representation is a fallback test
				}
				value.Set(reflect.New(value.Type().Elem()))
				copied := lifecycleClonePropertyCopied(t, seed)
				got := lifecycleClonePropertyAt(reflect.ValueOf(copied.core).Elem(), slot.path)
				if got.IsNil() || got.Pointer() == value.Pointer() {
					t.Fatal("MODEL pointer-to-zero lost value or isolation")
				}
				return
			}
			value.Set(reflect.MakeSlice(value.Type(), 0, 0))
			empty := lifecycleClonePropertyCopied(t, seed)
			got := lifecycleClonePropertyAt(reflect.ValueOf(empty.core).Elem(), slot.path)
			if got.IsNil() || got.Len() != 0 {
				t.Fatal("MODEL empty became nil")
			}
			value.Set(reflect.MakeSlice(value.Type(), 0, 2))
			full := value.Slice(0, value.Cap())
			next := 0
			for i := 0; i < full.Len(); i++ {
				lifecycleClonePropertyFill(t, full.Index(i), &next, map[reflect.Type]bool{})
			}
			sentinel := lifecycleClonePropertyRaw(t, full.Interface())
			spare := lifecycleClonePropertyCopied(t, seed)
			cloned := lifecycleClonePropertyAt(reflect.ValueOf(spare.core).Elem(), slot.path)
			lifecycleClonePropertyChange(cloned) // append into its own storage
			if !bytes.Equal(sentinel, lifecycleClonePropertyRaw(t, full.Interface())) {
				t.Fatal("MODEL append changed original hidden capacity")
			}
		})
	}
	// These are closed metadata negatives, not claimed record-validation runs.
	root := reflect.TypeOf(lifecycleV3Wire{})
	fields := make([]reflect.StructField, root.NumField())
	for i := range fields {
		fields[i] = root.Field(i)
	}
	plain := reflect.StructOf(fields)
	plainDigest, plainWalked := lifecycleCloneTypeShape(plain)
	if !plainWalked || lifecycleCloneTypeSchemaFor(plain) {
		t.Fatal("MODEL plain metadata walk and fixed root identity were conflated")
	}
	future := reflect.StructOf(append(fields, reflect.StructField{Name: "Execution", Type: reflect.TypeOf((*int)(nil)), Tag: `json:"execution,omitempty"`}))
	futureDigest, futureWalked := lifecycleCloneTypeShape(future)
	if !futureWalked || futureDigest == plainDigest {
		t.Fatal("MODEL future reference did not change metadata fingerprint")
	}
	v := reflect.New(future).Elem()
	if lifecycleCloneTypeSchemaFor(v.Type()) {
		t.Fatal("MODEL zero future reference ignored")
	}
	v.FieldByName("Execution").Set(reflect.ValueOf(new(int)))
	if lifecycleCloneTypeSchemaFor(v.Type()) {
		t.Fatal("MODEL nonzero future reference ignored")
	}
	taggedFields := append([]reflect.StructField(nil), fields...)
	taggedFields[0].Tag = `json:"MODEL_changed_tag"`
	tagged := reflect.StructOf(taggedFields)
	tagDigest, tagWalked := lifecycleCloneTypeShape(tagged)
	if !tagWalked || tagDigest == plainDigest || lifecycleCloneTypeSchemaFor(tagged) {
		t.Fatal("MODEL changed tag was not an explicit schema mismatch")
	}
	codec := reflect.TypeOf(lifecycleClonePropertyCodec(""))
	if !codec.Implements(reflect.TypeOf((*json.Marshaler)(nil)).Elem()) {
		t.Fatal("MODEL codec negative did not actually have a codec")
	}
	codecRoot := reflect.StructOf(append(fields, reflect.StructField{Name: "Codec", Type: codec}))
	if _, walked := lifecycleCloneTypeShape(codecRoot); walked {
		t.Fatal("MODEL codec leaf passed metadata walk before fingerprint checking")
	}
	standardRoot := reflect.StructOf([]reflect.StructField{
		{Name: "Clock", Type: reflect.TypeOf((*time.Time)(nil))},
		{Name: "Raw", Type: reflect.TypeOf((*json.RawMessage)(nil))},
	})
	if _, walked := lifecycleCloneTypeShape(standardRoot); !walked {
		t.Fatal("MODEL known standard pointer codecs were treated as unknown codecs")
	}
}

func TestLifecycleRecoveryTrustedCloneSplitsSiblingAliases(t *testing.T) {
	in := lifecycleClonePropertyDense(t)
	// Each assignment below deliberately reuses mutable input storage. The old
	// JSON operation breaks these aliases; the typed copy must do the same.
	in.core.RetiredEpochs[0].Ledger = in.core.Current
	in.core.RecoveryHistory[0] = *in.core.Recovery
	in.core.Current.Completed[0].Active = *in.core.Current.Active
	in.core.Current.Active.Plan.Artifact.Config.Capabilities = in.core.Current.Head.Artifact.Config.Capabilities
	in.core.Current.Completed[0].Active.Plan.Artifact.Config.Capabilities = in.core.Current.Head.Artifact.Config.Capabilities
	source := lifecycleClonePropertyRaw(t, in.core)
	out := lifecycleClonePropertyCopied(t, in)
	retired := lifecycleClonePropertyRaw(t, out.core.RetiredEpochs)
	history := lifecycleClonePropertyRaw(t, out.core.RecoveryHistory)
	completed := lifecycleClonePropertyRaw(t, out.core.Current.Completed)
	*out.core.Current.Head.PreviousHeadSHA256 = "MUTATED_HEAD_POINTER"
	out.core.Current.Head.Artifact.Config.Capabilities[0] = "MUTATED_ARTIFACT_SLICE"
	*out.core.Current.Active.Approval.AuthoritySnapshotRef = "MUTATED_APPROVAL_POINTER"
	out.core.Recovery.Approval.DeclaredApproverRef = "MUTATED_RECOVERY_POINTER"
	*out.core.Recovery.Execution.Started.Observation.StartErrorClass = "MUTATED_STARTED_ERROR"
	*out.core.Recovery.Execution.Started.Observation.StartObservation.PID = -991
	out.core.Recovery.Execution.ArmedFailedQuiescence[0].Outcome = "MUTATED_ARMED_FAILURE_SLICE"
	if !bytes.Equal(source, lifecycleClonePropertyRaw(t, in.core)) || !bytes.Equal(retired, lifecycleClonePropertyRaw(t, out.core.RetiredEpochs)) ||
		!bytes.Equal(history, lifecycleClonePropertyRaw(t, out.core.RecoveryHistory)) || !bytes.Equal(completed, lifecycleClonePropertyRaw(t, out.core.Current.Completed)) {
		t.Fatal("MODEL source or cloned sibling paths still share business storage")
	}
}

func TestLifecycleRecoveryTrustedCloneRepresentationFallbackMatchesRaw(t *testing.T) {
	for _, kind := range []string{"named-offset", "anonymous-offset", "monotonic", "invalid-utf8", "raw-null", "raw-pointer-nil-slice", "raw-object"} {
		t.Run(kind, func(t *testing.T) {
			in := lifecycleClonePropertySmall()
			switch kind {
			case "named-offset":
				in.core.LastTrustedAt = in.core.LastTrustedAt.In(time.FixedZone("MODEL custom zone", 8*60*60))
			case "anonymous-offset":
				in.core.LastTrustedAt = in.core.LastTrustedAt.In(time.FixedZone("", 8*60*60))
			case "monotonic":
				in.core.LastTrustedAt = time.Now()
				if in.core.LastTrustedAt == in.core.LastTrustedAt.Round(0) {
					t.Fatal("MODEL did not construct monotonic representation")
				}
			case "invalid-utf8":
				in.core.Schema = string([]byte{0xff, 0xfe})
			case "raw-null":
				v := json.RawMessage("null")
				in.core.Current.Active.Recovery = &v
			case "raw-pointer-nil-slice":
				var v json.RawMessage
				in.core.Current.Active.Recovery = &v
			case "raw-object":
				v := json.RawMessage(`{"model":true}`)
				in.core.Current.Active.Recovery = &v
			}
			raw := lifecycleClonePropertyRaw(t, in.core)
			if kind == "invalid-utf8" {
				old := lifecycleClonePropertyOldCopy(t, raw)
				normalized := lifecycleClonePropertyRaw(t, old.core)
				if old.core.Schema != "\ufffd\ufffd" || bytes.Equal(raw, normalized) ||
					!bytes.Contains(raw, []byte(`\ufffd\ufffd`)) || !bytes.Contains(normalized, []byte("\ufffd\ufffd")) {
					t.Fatal("MODEL old JSON normalization counterexample was not reached")
				}
			}
			c := &lifecycleCloneState{}
			_ = c.wire(*in.core)
			if c.err != errLifecycleCloneRepresentation {
				t.Fatal("MODEL known representation did not reach original-JSON fallback classification")
			}
			out := lifecycleClonePropertyCopied(t, in)
			out.core.Current.Head.Artifact.Config.Capabilities[0] = "MUTATED_FALLBACK_SLICE"
			if out.core.Current.Active.Recovery != nil && len(*out.core.Current.Active.Recovery) != 0 {
				(*out.core.Current.Active.Recovery)[0] = '['
			}
			if !bytes.Equal(raw, lifecycleClonePropertyRaw(t, in.core)) {
				t.Fatal("MODEL fallback copy aliases source")
			}
		})
	}
	t.Run("accepted-STOP-ARMED-offset-binding", func(t *testing.T) {
		s, _, _, _, _, _ := lifecycleRecoveryModelArmed(t)
		in := lifecycleV3Copy(t, s.core.record)
		b := in.core.Recovery.StopBinding
		b.ArmedAt = b.ArmedAt.In(time.FixedZone("MODEL accepted +08", 8*60*60))
		b.ExpiresAt = b.ExpiresAt.In(time.FixedZone("MODEL accepted +08", 8*60*60))
		in = lifecycleV3Seal(t, in)
		raw, err := encodeLifecycleV3Record(in)
		if err != nil || in.core.Recovery.Phase != "STOP_ARMED" || in.core.Recovery.Quiescence != nil {
			t.Fatal("MODEL old legal offset branch not reached")
		}
		decoded, err := decodeLifecycleV3Record(raw)
		if err != nil {
			t.Fatal("MODEL existing strict decoder rejected source before copy")
		}
		lifecycleClonePropertyCopied(t, in)
		lifecycleClonePropertyCopied(t, decoded)
	})
	t.Run("canonical-equal-raw-null-memory-cannot-write", func(t *testing.T) {
		s, d, _, _, now := lifecycleRecoveryModelPlanned(t)
		before := append([]byte(nil), s.core.raw...)
		rawNull := json.RawMessage("null")
		s.core.record.core.Current.Active.Recovery = &rawNull
		if !bytes.Equal(lifecycleClonePropertyRaw(t, s.core.record.core), before) {
			t.Fatal("MODEL canonical-equal mutation branch not reached")
		}
		writes := d.writes
		base, err := s.core.verifiedBase()
		if err == nil {
			defer base.release()
			if base.intact(s.core) {
				t.Fatal("MODEL normalization was lost before actual base parity gate")
			}
			if draft, copyErr := base.copyRecord(); copyErr == nil && s.core.commitWithBase(base, draft, now) == nil {
				t.Fatal("MODEL cloned memory tamper bypassed actual base gate")
			}
		}
		if d.writes != writes {
			t.Fatal("MODEL untrusted typed representation wrote to disk")
		}
	})
}
