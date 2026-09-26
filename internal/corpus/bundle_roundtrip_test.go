package corpus

import (
	"reflect"
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/cite"
)

// TestPayloadRoundTripKeepsEveryCitationField is the ratchet over the bundle
// encoder.
//
// # WHY THIS TEST EXISTS
//
// MarshalPayload is written by hand: it appends JSON literals field by field
// rather than reflecting over the structs it represents. ParsePayload is not —
// it decodes with the same reflection decoder the YAML loader uses. So the
// encoder can fall behind the struct it is supposed to serialise, and nothing
// notices: the payload stays valid JSON, it verifies, it loads, and only the
// missing field is gone.
//
// That is not hypothetical. `appendRef` omitted `excerpt_kind`, so every excerpt
// in the shipped bundle arrived at the renderer with an empty kind. A renderer is
// permitted to print quotation marks only for a verbatim excerpt, so it correctly
// quoted nothing: the tool's headline claim is "every finding quotes the exact
// clause", and the bundle made it present every genuine quotation as
// "Clearance's reading:" instead.
//
// The comparison below is deliberately reflection-driven. A hand-listed set of
// fields would have been written from the same mental model that produced the
// bug, and would go stale in the same way. This way, adding a field to cite.Ref
// without teaching appendRef about it fails here.
func TestPayloadRoundTripKeepsEveryCitationField(t *testing.T) {
	probe := cite.Ref{
		URL:         "https://example.test/probe",
		Section:     "§1 (probe)",
		Excerpt:     "probe excerpt",
		ExcerptKind: cite.ExcerptVerbatim,
		RetrievedAt: "2026-09-25",
	}

	// Guard the guard. A zero field cannot be observed to survive a round trip,
	// so a field added to cite.Ref and left unset here would make this test pass
	// for the wrong reason. Fail loudly instead of silently proving less.
	pv, pt := reflect.ValueOf(probe), reflect.TypeOf(probe)
	for i := 0; i < pt.NumField(); i++ {
		if pv.Field(i).IsZero() {
			t.Fatalf("the probe leaves cite.Ref.%s zero, so this test cannot see whether it survives the bundle; give it a value above",
				pt.Field(i).Name)
		}
	}

	c := &Corpus{
		Version:     "0.0.0-roundtrip-test",
		globalTraps: []*Trap{{ID: "trap.probe", Citation: probe}},
	}

	payload := MarshalPayload(c)

	// Assert on the bytes as well as on the decoded value. If the encoder drops a
	// field and the decoder would also have ignored it, only this check names the
	// real cause: the writer never wrote it.
	for i := 0; i < pt.NumField(); i++ {
		tag := jsonNameOf(pt.Field(i))
		if tag == "" {
			continue
		}
		if !strings.Contains(string(payload), `"`+tag+`"`) {
			t.Errorf("MarshalPayload never writes the key %q, so cite.Ref.%s cannot survive the bundle",
				tag, pt.Field(i).Name)
		}
	}

	back, err := ParsePayload(payload)
	if err != nil {
		t.Fatalf("ParsePayload: %v", err)
	}
	if len(back.globalTraps) != 1 {
		t.Fatalf("round trip returned %d global traps, want 1", len(back.globalTraps))
	}

	got := reflect.ValueOf(back.globalTraps[0].Citation)
	for i := 0; i < pt.NumField(); i++ {
		want := pv.Field(i).Interface()
		have := got.Field(i).Interface()
		if !reflect.DeepEqual(want, have) {
			t.Errorf("cite.Ref.%s did not survive the bundle round trip: wrote %#v, read back %#v",
				pt.Field(i).Name, want, have)
		}
	}
}

// jsonNameOf returns the name a field is serialised under, preferring the `json`
// tag and falling back to the field name, so the byte-level assertion above
// tracks the same name the encoder uses.
func jsonNameOf(f reflect.StructField) string {
	tag := f.Tag.Get("json")
	if tag == "" {
		return f.Name
	}
	name, _, _ := strings.Cut(tag, ",")
	if name == "-" {
		return ""
	}
	return name
}
