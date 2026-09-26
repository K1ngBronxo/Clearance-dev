// Package verdict is the verdict algebra: the exact, deterministic rules that
// turn a set of findings into a single decision.
//
// This is the most important package in the project. If it is wrong, nothing
// else matters. It is small on purpose — four rules, in order, small enough to
// hold in your head and to hold in a test.
//
// It is L3: pure. No I/O, no clock, no randomness, no map iteration order.
// Given the same findings it produces the same verdict, always (INV-6).
package verdict

import (
	"sort"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/policy"
)

// Class is the answer. There are exactly four, and UNKNOWN is one of them.
type Class string

const (
	Ship            Class = "SHIP"
	ShipConditional Class = "SHIP_CONDITIONAL"
	DoNotShip       Class = "DO_NOT_SHIP"
	Undetermined    Class = "UNDETERMINED"
)

// ExitCode maps a verdict to its process exit code (ADR-008, frozen forever).
//
// Note that UNDETERMINED is exit 0 by default: the tool found something it could
// not classify, and it says so loudly, but it does not fail a build unless the
// user asked for that with --strict. Failing by default would train users to
// ignore the tool, which is a worse outcome than a loud warning.
func (c Class) ExitCode(strict bool) int {
	switch c {
	case DoNotShip:
		return cerr.ExitDoNotShip
	case Undetermined:
		if strict {
			return cerr.ExitUndetermined
		}
		return cerr.ExitOK
	}
	return cerr.ExitOK
}

// Label is the human rendering, used in the header block.
func (c Class) Label() string {
	switch c {
	case Ship:
		return "SHIP"
	case ShipConditional:
		return "SHIP CONDITIONAL"
	case DoNotShip:
		return "DO NOT SHIP"
	case Undetermined:
		return "UNDETERMINED"
	}
	return string(c)
}

// Summary is the count block at the top of every rendering.
type Summary struct {
	Dependencies int `json:"dependencies"`
	WeightFiles  int `json:"weight_files"`
	UpstreamCLIs int `json:"upstream_clis"`
	Blockers     int `json:"blockers"`
	Conditions   int `json:"conditions"`
	Undetermined int `json:"undetermined"`
}

// Meta carries everything that is *not* part of the decision.
//
// The split matters: ScannedAt and DurationMS are the only non-deterministic
// fields in the whole output, and they live here so that a test can zero them
// and compare the rest byte for byte (INV-6). They are injected by the
// interface layer, never by the decision layer, because the decision layer must
// be pure (ADR-004).
type Meta struct {
	ToolVersion     string `json:"tool_version"`
	CorpusVersion   string `json:"corpus_version"`
	CorpusSigned    bool   `json:"corpus_signed"`
	IntentHash      string `json:"intent_hash"`
	ConfigPath      string `json:"config_path"`
	ScannedAt       int64  `json:"scanned_at"`
	DurationMS      int64  `json:"duration_ms"`
	BuildCommit     string `json:"build_commit"`
	BuildProvenance string `json:"build_provenance"`
}

// Verdict is the product's output type.
//
// Note what the primary type is: a Verdict, not a Report. Reports are
// renderings of a verdict. That naming is Principle 1 made structural.
type Verdict struct {
	SchemaVersion int    `json:"schema_version"`
	Verdict       Class  `json:"verdict"`
	Project       string `json:"project"`

	Summary Summary `json:"summary"`

	// Arrays are always present, never null: a consumer must never have to
	// null-check.
	Blockers     []policy.Finding     `json:"blockers"`
	Conditions   []policy.Finding     `json:"conditions"`
	Notes        []policy.Finding     `json:"notes"`
	Undetermined []graph.Undetermined `json:"undetermined"`

	Meta Meta `json:"meta"`
}

// Input is everything the fold needs.
type Input struct {
	Findings     []policy.Finding
	Undetermined []graph.Undetermined

	// AllowMediumBlockers promotes MEDIUM findings to blocking. There is
	// deliberately no equivalent for LOW.
	AllowMediumBlockers bool
}

// Fold applies the four rules.
//
//	(a) if any blocker exists          → DO NOT SHIP
//	(b) else if undetermined count > 0 → UNDETERMINED
//	(c) else if any condition exists   → SHIP CONDITIONAL
//	(d) else                           → SHIP
//
// The order is normative and the rationale for each position is written down
// here, because every one of these orderings is a decision someone will
// eventually propose changing:
//
//   - A blocker comes first because a definite block must never be diluted by
//     an unrelated uncertainty. If one dependency is definitively forbidden and
//     another is merely unknown, the answer is DO NOT SHIP.
//   - UNDETERMINED outranks SHIP CONDITIONAL because a condition is a *known*
//     requirement while an undetermined is an *unknown* risk, and unknown beats
//     known when the alternative is a false pass.
//   - SHIP is last and claims the least: it does not say the stack is free of
//     licence risk, only that no known obligation contradicts the declared
//     intent.
func Fold(in Input) Verdict {
	v := Verdict{
		SchemaVersion: 1,
		Blockers:      []policy.Finding{},
		Conditions:    []policy.Finding{},
		Notes:         []policy.Finding{},
		Undetermined:  []graph.Undetermined{},
	}

	for _, f := range in.Findings {
		// The confidence gate is applied here, and it is INV-2 in practice: a
		// LOW finding can never be in the blockers slice, so it can never
		// produce DO NOT SHIP. A tool that does not know must not make a
		// decision that costs someone money.
		switch policy.EffectiveSeverity(f, in.AllowMediumBlockers) {
		case policy.SeverityBlock:
			v.Blockers = append(v.Blockers, f)
		case policy.SeverityCondition:
			v.Conditions = append(v.Conditions, f)
		default:
			v.Notes = append(v.Notes, f)
		}
	}
	v.Undetermined = append(v.Undetermined, in.Undetermined...)

	// Explicit, stable ordering. Never map iteration order, never input order.
	sort.SliceStable(v.Blockers, func(i, j int) bool { return less(v.Blockers[i], v.Blockers[j]) })
	sort.SliceStable(v.Conditions, func(i, j int) bool { return less(v.Conditions[i], v.Conditions[j]) })
	sort.SliceStable(v.Notes, func(i, j int) bool { return less(v.Notes[i], v.Notes[j]) })
	sort.SliceStable(v.Undetermined, func(i, j int) bool {
		return v.Undetermined[i].SortKey() < v.Undetermined[j].SortKey()
	})

	// ── the four rules ──────────────────────────────────────────────────────
	switch {
	case len(v.Blockers) > 0:
		v.Verdict = DoNotShip
	case len(v.Undetermined) > 0:
		v.Verdict = Undetermined
	case len(v.Conditions) > 0:
		v.Verdict = ShipConditional
	default:
		v.Verdict = Ship
	}

	v.Summary.Blockers = len(v.Blockers)
	v.Summary.Conditions = len(v.Conditions)
	v.Summary.Undetermined = len(v.Undetermined)
	return v
}

// less orders findings by (severity desc, dependency id, kind). The severity
// component is redundant inside a single slice, but keeping one comparator for
// all three slices means the ordering can never diverge between them.
func less(a, b policy.Finding) bool {
	if a.Severity.Weight() != b.Severity.Weight() {
		return a.Severity.Weight() > b.Severity.Weight()
	}
	if a.DependencyID != b.DependencyID {
		return a.DependencyID < b.DependencyID
	}
	if a.Kind != b.Kind {
		return a.Kind < b.Kind
	}
	return a.ID < b.ID
}

// TotalityCheck asserts that Fold produced a valid class. It exists because
// E-POLICY-010 documents "the verdict fold produced no result", and a test
// should be able to prove that can never happen.
//
// The fold is total by construction — the switch has a default — but a future
// edit could remove it, and this is the assertion that catches that edit.
func (v Verdict) TotalityCheck() error {
	switch v.Verdict {
	case Ship, ShipConditional, DoNotShip, Undetermined:
		return nil
	}
	return cerr.New(cerr.EPolicy010)
}
