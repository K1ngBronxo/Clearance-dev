// Package policy evaluates obligations against declared intent. It is L3: pure,
// deterministic, no I/O, no clock, no randomness, no map iteration order.
//
// Evaluate(DependencyGraph, Corpus, Intent) → []Finding
//
// This is the only place in the system where a judgement is made. Everything
// else either reads files or formats text. Because it is pure, the entire
// decision engine is testable with in-memory literals — no temp directories, no
// fixtures on disk, no mocks. If a test ever needs a mock to exercise this
// package, the layering has been violated.
package policy

import (
	"github.com/clearance-dev/clearance/internal/cite"
	"github.com/clearance-dev/clearance/internal/expr"
	"github.com/clearance-dev/clearance/internal/graph"
)

// Severity is how hard a finding pushes against shipping.
type Severity string

const (
	SeverityBlock     Severity = "BLOCK"
	SeverityCondition Severity = "CONDITION"
	SeverityNote      Severity = "NOTE"
	SeverityInfo      Severity = "INFO"
)

// Weight orders severities for sorting. Higher is more severe.
func (s Severity) Weight() int {
	switch s {
	case SeverityBlock:
		return 3
	case SeverityCondition:
		return 2
	case SeverityNote:
		return 1
	case SeverityInfo:
		return 0
	}
	return -1
}

// Valid reports whether s is one of the four severities.
func (s Severity) Valid() bool { return s.Weight() >= 0 }

// Confidence is the honest labelling of how much the tool actually knows.
//
// It is not a probability, not a quality score, and not a measure of severity.
// It exists because the failure mode of a licence tool is not "found nothing" —
// it is "confidently wrong". Confidence is the safety valve.
type Confidence string

const (
	ConfidenceHigh   Confidence = "HIGH"
	ConfidenceMedium Confidence = "MEDIUM"
	ConfidenceLow    Confidence = "LOW"
)

// Weight orders confidence. Higher is stronger.
func (c Confidence) Weight() int {
	switch c {
	case ConfidenceHigh:
		return 2
	case ConfidenceMedium:
		return 1
	case ConfidenceLow:
		return 0
	}
	return -1
}

// Valid reports whether c is one of the three levels. There is no zero value:
// a Finding cannot exist without a confidence (INV-2), and this is how the
// constructor enforces it.
func (c Confidence) Valid() bool { return c.Weight() >= 0 }

// Weakest returns the weaker of two confidences. This is the propagation rule
// (§4 of the confidence model): if one leg of an argument is uncertain, the
// conclusion is uncertain. Any other rule lets a strong source launder a weak
// one.
func Weakest(a, b Confidence) Confidence {
	if a.Weight() <= b.Weight() {
		return a
	}
	return b
}

// Fix is a compatible alternative, when the corpus knows one.
type Fix struct {
	Action      string     `json:"action"`
	Suggestion  string     `json:"suggestion"`
	Alternative string     `json:"alternative,omitempty"`
	Confidence  Confidence `json:"confidence"`
}

// Finding is one evaluated obligation that applies to this project.
//
// Note the fields that have no zero value: Citation (INV-1) and Confidence
// (INV-2). Both are set by the only constructor, newFinding, which resolves the
// citation first. If the citation does not resolve, the Finding is not created.
// There is no other way to build one.
type Finding struct {
	ID           string        `json:"id"`
	DependencyID string        `json:"dependency_id"`
	Kind         string        `json:"kind"`
	Severity     Severity      `json:"severity"`
	Confidence   Confidence    `json:"confidence"`
	Title        string        `json:"title"`
	Reason       string        `json:"reason"`
	Citation     cite.Citation `json:"citation"`

	// Licence is what this finding is *about*: the resolved SPDX identifier, or
	// the raw string the manifest carried when nothing could be resolved.
	//
	// It is carried on the finding so that a renderer can print the licence
	// column without importing the scanner. R6 forbids L4 from reaching into
	// L1, so the fact has to travel with the decision rather than be looked up
	// at render time — and a renderer that looked it up could print a licence
	// the decision never saw.
	Licence  string           `json:"licence"`
	Evidence []graph.Evidence `json:"evidence"`
	Fix      *Fix             `json:"fix,omitempty"`
	TrapID   string           `json:"trap_id,omitempty"`

	// Predicate is the exact expression that fired. A verdict a user cannot
	// interrogate is a verdict they will not trust, so every finding carries
	// its own explanation.
	Predicate *expr.Expr `json:"predicate"`

	// UndeterminedField names the intent field that was undeclared, when that is
	// why the finding is a NOTE rather than a BLOCK. It is how the tool tells
	// the user exactly which fact to supply (E-POLICY-009).
	UndeterminedField string `json:"undetermined_field,omitempty"`
}

// sortKey gives findings a total, stable order: severity descending, then
// dependency id, then kind. This is the documented ordering for the JSON
// contract's blockers/conditions/notes arrays.
func (f Finding) sortKey() string {
	// Invert the severity weight so that higher severity sorts first without a
	// separate descending comparison.
	w := 9 - f.Severity.Weight()
	return itoaDigit(w) + "\x00" + f.DependencyID + "\x00" + f.Kind + "\x00" + f.ID
}

func itoaDigit(n int) string {
	if n < 0 {
		n = 0
	}
	if n > 9 {
		n = 9
	}
	return string(rune('0' + n))
}
