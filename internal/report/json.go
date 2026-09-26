package report

import (
	"bytes"
	"encoding/json"
	"io"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// Format names an output format. The set is closed on purpose: a format the
// tool cannot render is a format it must refuse rather than approximate.
//
// The set is exactly the one the frozen CLI contract names — `human json md
// sarif` — and no more. A format added here without being added to the contract
// would be a flag the docs do not mention; a format named in the contract and
// missing here is the defect notImplemented existed to paper over.
type Format string

const (
	// FormatHuman is the terminal rendering (§1).
	FormatHuman Format = "human"
	// FormatJSON is the canonical machine contract (§2).
	FormatJSON Format = "json"
	// FormatMarkdown is the PR-comment rendering (§3).
	FormatMarkdown Format = "md"
	// FormatSARIF is the code-scanning rendering (§4).
	FormatSARIF Format = "sarif"
)

// Valid reports whether f is a format this package can render.
func (f Format) Valid() bool {
	return f == FormatHuman || f == FormatJSON ||
		f == FormatMarkdown || f == FormatSARIF
}

// Formats lists every format this build renders, in the order the help text
// shows them. It exists so that a caller building a usage message or validating
// a flag does not hardcode the list a second time — the failure that produces
// is a help string that mentions a format the binary rejects.
func Formats() []Format {
	return []Format{FormatHuman, FormatJSON, FormatMarkdown, FormatSARIF}
}

// Write renders v in format f. It is the single entry point the interface
// layer uses, so that "which renderer ran" is decided in one place and a
// caller cannot accidentally render a verdict twice in two formats.
func Write(w io.Writer, v verdict.Verdict, f Format, opts Options) error {
	switch f {
	case FormatHuman:
		return WriteHuman(w, v, opts)
	case FormatJSON:
		return WriteJSON(w, v)
	case FormatMarkdown:
		return WriteMarkdown(w, v, opts)
	case FormatSARIF:
		return WriteSARIF(w, v)
	}
	// A format outside the closed set is refused, not approximated. This is the
	// same refusal the CLI makes for a bad --format, reported under the code
	// that names it (E-RENDER-007, exit 2); it is not a permission problem, so
	// it is not E-RENDER-001.
	return cerr.New(cerr.ERender007, string(f))
}

// MarshalJSON renders the canonical machine contract (§2).
//
// The output is byte-stable: encoding/json emits struct fields in declaration
// order, the verdict's arrays were already sorted by Fold, and no map is ever
// marshalled. Two runs on identical input therefore produce identical bytes
// once meta.scanned_at and meta.duration_ms are zeroed — which is exactly what
// TestJSONDeterminism asserts.
func MarshalJSON(v verdict.Verdict) ([]byte, error) {
	n := normalise(v)

	var buf bytes.Buffer
	enc := json.NewEncoder(&buf)
	// EscapeHTML would rewrite `&` in a citation URL as \u0026, turning a
	// clickable link into an unreadable one. The JSON is a document, not an
	// HTML fragment, so there is nothing to escape for.
	enc.SetEscapeHTML(false)
	enc.SetIndent("", "  ")
	if err := enc.Encode(n); err != nil {
		return nil, cerr.Wrap(cerr.ERender002, err)
	}
	// Encoder.Encode appends a newline. That is deliberate: a JSON file with no
	// trailing newline breaks every POSIX text tool and makes `cat` leave the
	// shell prompt glued to the last brace.
	return buf.Bytes(), nil
}

// WriteJSON writes the machine contract.
func WriteJSON(w io.Writer, v verdict.Verdict) error {
	b, err := MarshalJSON(v)
	if err != nil {
		return err
	}
	_, err = w.Write(b)
	return err
}

// Deterministic returns the canonical bytes with the two non-deterministic
// fields zeroed. It exists so that a caller — and the test suite — can compare
// two runs of the same project without special-casing the clock.
func Deterministic(v verdict.Verdict) ([]byte, error) {
	v.Meta.ScannedAt = 0
	v.Meta.DurationMS = 0
	return MarshalJSON(v)
}

// normalise removes every nil slice from the rendered document.
//
// A consumer must never have to null-check: `"blockers": []` and
// `"blockers": null` mean the same thing to a human and two very different
// things to a program. Go's zero value for a slice is nil, and a nil slice
// marshals as null, so every slice that reaches the renderer is replaced with
// an empty one here rather than being fixed up at each construction site.
//
// This is a rendering concern, not a decision: it cannot change the verdict,
// only how absence is spelled.
func normalise(v verdict.Verdict) verdict.Verdict {
	v.Blockers = normaliseFindings(v.Blockers)
	v.Conditions = normaliseFindings(v.Conditions)
	v.Notes = normaliseFindings(v.Notes)
	if v.Undetermined == nil {
		v.Undetermined = []graph.Undetermined{}
	}
	for i := range v.Undetermined {
		if v.Undetermined[i].Evidence == nil {
			v.Undetermined[i].Evidence = []graph.Evidence{}
		}
	}
	return v
}

func normaliseFindings(fs []policy.Finding) []policy.Finding {
	if fs == nil {
		return []policy.Finding{}
	}
	for i := range fs {
		if fs[i].Evidence == nil {
			fs[i].Evidence = []graph.Evidence{}
		}
	}
	return fs
}
