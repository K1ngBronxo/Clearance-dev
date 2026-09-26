// Package obligations is the vocabulary and the validator for the things a
// licence requires.
//
// # WHAT IT IS FOR
//
// A corpus entry carries a list of obligations, and each one is a sentence like
// "you must ship the licence text" together with the condition under which it
// applies. The corpus package stores those lists; this package says what they
// MEAN, and refuses the ones that mean nothing.
//
// # WHY IT EXISTS AT ALL, GIVEN THAT corpus ALREADY HAS AN Obligation TYPE
//
// Because until this package existed, `kind` was a free string. The corpus
// loader validated an obligation's id, its severity, its confidence, its
// message length, its predicate and its citation — everything except the one
// field that decides what the finding is CALLED. A maintainer who typed
//
//	kind: atribution          # one t
//
// got a corpus that loaded cleanly, a signature that verified, a green build,
// and a finding rendered as "atribution obligation" in every report the tool
// ever produced. The typo was invisible in the only place it mattered, which is
// the output a stranger reads at 2am.
//
// The same hole existed for a fix's `action` (`replace | rebrand | attribute |
// configure | remove`), which is the field that tells a reader what to DO. Both
// are closed here.
//
// # LAYER, AND WHY THIS PACKAGE DOES NOT IMPORT corpus
//
// L2, beside `corpus`. The obvious shape — `Resolve(entry *corpus.Entry)` —
// would make this package import `corpus`, and `corpus` must import THIS
// package to validate at load time. Go forbids that cycle outright, so the
// dependency has to point one way, and the useful direction is `corpus →
// obligations`: the vocabulary is the stable thing and the storage format is
// the thing that changes.
//
// So the input is a small mirror (`Source`) rather than `corpus.Obligation`.
// That is not duplication for its own sake — it is what lets the loader refuse
// a bad corpus on the same path as every other schema check, instead of
// discovering it at render time.
//
// # WHY THE SEVERITY AND CONFIDENCE FIELDS HERE ARE STRINGS
//
// Because `policy` is L3 and this package is L2, and an L2 package that named
// an L3 type would be the exact upward import the layering exists to prevent.
// `policyfile` made the same choice for the same reason and says so in its own
// package comment. The conversion to the typed vocabulary happens in L3, once,
// where the decision is actually made.
package obligations

import (
	"sort"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/cite"
	"github.com/clearance-dev/clearance/internal/expr"
)

// Kind is one of the eleven things a licence can require.
//
// The set is closed, and it is closed on purpose. PLAN/02-SPECIFICATIONS/
// 02-corpus-schema-spec.md §4 enumerates it, corpus/SCHEMA.md repeats it, and
// TestObligationVocabularyMatchesTheSpec reads the spec and asserts that the
// constants below are exactly that set — so a kind added to the spec without a
// constant here, or a constant added here without a spec row, is a red build
// rather than a decision nobody wrote down.
//
// A new kind is not a corpus edit. It is a spec change, a constant, a
// description, a typical severity, and this paragraph's list, in one commit.
type Kind string

// The closed vocabulary. The constant name, the string value and the spec's
// prose are three different things and all three matter: the string is what the
// YAML says, the constant is what the code says, and the name is what a
// reviewer greps for.
const (
	// Attribution — you must credit the author.
	Attribution Kind = "ATTRIBUTION"

	// SourceDisclosure — you must offer source. The copyleft core.
	SourceDisclosure Kind = "SOURCE_DISCLOSURE"

	// LicenceInclusion — you must ship the licence text alongside the work.
	LicenceInclusion Kind = "LICENCE_INCLUSION"

	// StateChanges — you must mark the files you modified.
	StateChanges Kind = "STATE_CHANGES"

	// NonCommercial — commercial use is forbidden outright.
	NonCommercial Kind = "NON_COMMERCIAL"

	// NetworkDisclosure — AGPL §13: users who reach the software over a network
	// are entitled to its source. This is the clause most often missed by a
	// team that reasoned correctly about GPL and then put the service behind an
	// HTTP endpoint.
	NetworkDisclosure Kind = "NETWORK_DISCLOSURE"

	// ScaleGate — a MAU or revenue threshold is what turns a permission into a
	// restriction, or a restriction into a licence you must buy.
	ScaleGate Kind = "SCALE_GATE"

	// TerritorialGate — commercial use requires separate permission in some
	// jurisdictions.
	TerritorialGate Kind = "TERRITORIAL_GATE"

	// BrandExclusion — the name and the logo are reserved even where the code
	// is free, so a fork must rebrand.
	BrandExclusion Kind = "BRAND_EXCLUSION"

	// PatentGrant — an explicit patent licence is granted, or is conspicuously
	// not. The "or is not" half is why this is an obligation and not a
	// footnote: Apache-2.0 grants patents and MIT is silent, and the silence is
	// the finding.
	PatentGrant Kind = "PATENT_GRANT"

	// PlatformToS — a term inherited from a third-party platform the project
	// invokes, rather than from a licence file in the repository.
	PlatformToS Kind = "PLATFORM_TOS"
)

// vocabulary is the single source of truth for iteration. Kinds() sorts it and
// Valid() reads it, so the two cannot disagree.
var vocabulary = []Kind{
	Attribution,
	SourceDisclosure,
	LicenceInclusion,
	StateChanges,
	NonCommercial,
	NetworkDisclosure,
	ScaleGate,
	TerritorialGate,
	BrandExclusion,
	PatentGrant,
	PlatformToS,
}

// descriptions is the one-line meaning of each kind, used by `clearance
// explain` and by the corpus browser. It is deliberately the same sentence as
// the spec's "Meaning" column, because two descriptions of the same kind that
// drift apart are worse than one that is slightly terse.
var descriptions = map[Kind]string{
	Attribution:       "You must credit the author.",
	SourceDisclosure:  "You must offer source (copyleft).",
	LicenceInclusion:  "You must ship the licence text.",
	StateChanges:      "You must mark modified files.",
	NonCommercial:     "Commercial use is forbidden.",
	NetworkDisclosure: "Network users are entitled to the source (AGPL §13).",
	ScaleGate:         "A MAU or revenue threshold gates commercial use.",
	TerritorialGate:   "Commercial use requires permission in some jurisdictions.",
	BrandExclusion:    "The name and logo are reserved; rebrand to fork.",
	PatentGrant:       "An explicit patent licence is, or is not, granted.",
	PlatformToS:       "An inherited third-party platform term.",
}

// typicalSeverity is the band the spec's §4 table gives each kind.
//
// It is NOT a constraint — the corpus is free to declare any valid severity,
// and it does: a NON_COMMERCIAL obligation on a licence that permits
// non-commercial research is a CONDITION rather than a BLOCK, and that is
// correct. What it is for is the sanity warning in MismatchedSeverity: a BLOCK
// on an ATTRIBUTION is almost always a typo, and a NOTE on a NON_COMMERCIAL is
// almost always a mistake that would let a commercial user ship.
var typicalSeverity = map[Kind][]string{
	Attribution:       {"CONDITION"},
	SourceDisclosure:  {"CONDITION", "BLOCK"},
	LicenceInclusion:  {"CONDITION"},
	StateChanges:      {"CONDITION"},
	NonCommercial:     {"BLOCK"},
	NetworkDisclosure: {"BLOCK"},
	ScaleGate:         {"CONDITION"},
	TerritorialGate:   {"CONDITION"},
	BrandExclusion:    {"CONDITION"},
	PatentGrant:       {"NOTE"},
	PlatformToS:       {"CONDITION", "BLOCK"},
}

// Valid reports whether k is in the closed vocabulary.
func (k Kind) Valid() bool {
	for _, want := range vocabulary {
		if k == want {
			return true
		}
	}
	return false
}

// Describe returns the one-line meaning of the kind, or a string that names the
// unknown kind so a caller can print it without a second branch.
func (k Kind) Describe() string {
	if d, ok := descriptions[k]; ok {
		return d
	}
	return "Unknown obligation kind '" + string(k) + "'."
}

// Title is what a finding's headline reads. It lives here rather than in a
// renderer so that the string "SOURCE_DISCLOSURE obligation" has exactly one
// definition, and so that a kind outside the vocabulary cannot reach a title at
// all.
func (k Kind) Title() string {
	return string(k) + " obligation"
}

// TypicalSeverity returns the severities the spec's table lists for this kind,
// sorted. An unknown kind returns nil.
//
// The copy is returned rather than the map's slice so a caller cannot reorder
// the vocabulary for every other caller in the process.
func (k Kind) TypicalSeverity() []string {
	got, ok := typicalSeverity[k]
	if !ok {
		return nil
	}
	out := append([]string(nil), got...)
	sort.Strings(out)
	return out
}

// Kinds returns the whole vocabulary, sorted, as a fresh slice.
//
// Sorted rather than in declaration order, because the caller is almost always
// a renderer and a renderer that depends on Go source order is a renderer whose
// output changes when someone tidies the const block (INV-6).
func Kinds() []Kind {
	out := append([]Kind(nil), vocabulary...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// KindsCSV returns the vocabulary as a comma-separated list, for a usage
// message or a validation error.
func KindsCSV() string {
	ks := Kinds()
	parts := make([]string, len(ks))
	for i, k := range ks {
		parts[i] = string(k)
	}
	return strings.Join(parts, ", ")
}

// KindOf parses a corpus string into a Kind. The second result is false for a
// value outside the vocabulary, which is what lets a caller distinguish "the
// corpus said ATTRIBUTION" from "the corpus said something else".
func KindOf(s string) (Kind, bool) {
	k := Kind(strings.TrimSpace(s))
	return k, k.Valid()
}

// ── the fix vocabulary ───────────────────────────────────────────────────────

// FixAction is what a reader should DO about a finding.
//
// This is the second closed vocabulary in the corpus that the loader did not
// check, and it is checked here for the same reason `kind` is. A fix with
// `action: replcae` renders as a suggestion the tool is telling the user to
// perform, in a field whose whole purpose is to be unambiguous.
type FixAction string

const (
	// Replace — swap the dependency for another one. The common case.
	Replace FixAction = "replace"
	// Rebrand — keep the code, change the name and the logo.
	Rebrand FixAction = "rebrand"
	// Attribute — keep everything, add the required credit.
	Attribute FixAction = "attribute"
	// Configure — change a setting rather than a dependency.
	Configure FixAction = "configure"
	// Remove — delete the dependency; it is not needed.
	Remove FixAction = "remove"
)

var fixActions = []FixAction{Replace, Rebrand, Attribute, Configure, Remove}

// Valid reports whether a is a known fix action.
func (a FixAction) Valid() bool {
	for _, want := range fixActions {
		if a == want {
			return true
		}
	}
	return false
}

// FixActions returns the vocabulary, sorted.
func FixActions() []FixAction {
	out := append([]FixAction(nil), fixActions...)
	sort.Slice(out, func(i, j int) bool { return out[i] < out[j] })
	return out
}

// ── the input mirror and the resolved form ───────────────────────────────────

// FixSource is the raw fix shape as the corpus carries it.
type FixSource struct {
	Action      string
	Suggestion  string
	Alternative string
	Confidence  string
}

// Source is the raw obligation shape as the corpus carries it.
//
// It mirrors corpus.Obligation field for field, minus the YAML tags. See the
// package comment for why the mirror exists rather than a direct reference: it
// is what breaks the import cycle between this package and the one that stores
// the YAML.
type Source struct {
	ID         string
	Kind       string
	Severity   string
	When       *expr.Expr
	Message    string
	Citation   cite.Ref
	Confidence string
	Fix        *FixSource
}

// Fix is a compatible alternative, when one is known. Its action is narrowed to
// the closed vocabulary.
type Fix struct {
	Action      FixAction
	Suggestion  string
	Alternative string
	Confidence  string
}

// Obligation is a source obligation whose kind and fix action have been proved
// to be in the vocabulary.
//
// # WHY A SEPARATE TYPE RATHER THAN A VALIDATED Source
//
// Because "this obligation has a known kind" is a fact the compiler should
// carry. The policy engine renders the kind into the finding's title, and the
// difference between "a string that happens to be a kind" and "a Kind" is the
// difference between a typo reaching the user and a typo failing the load. The
// only way to obtain an Obligation is through Resolve, and Resolve refuses an
// unknown kind — so a value of this type is evidence, not a hope.
type Obligation struct {
	ID         string
	Kind       Kind
	Severity   string
	When       *expr.Expr
	Message    string
	Citation   cite.Ref
	Confidence string
	Fix        *Fix

	// EntryID is the licence entry this obligation belongs to. Filled by
	// Resolve from the argument, so it is never empty on a value that came
	// through it.
	EntryID string
}

// Title is what the finding's headline reads. See Kind.Title.
func (o Obligation) Title() string { return o.Kind.Title() }

// Resolve projects a source list into validated obligations.
//
// entryID is carried onto every result and appears in the error detail, because
// a corpus author who has typed a bad kind needs to know WHICH file to open,
// and an obligation id alone does not say.
//
// It returns the first problem it finds rather than collecting them all. That
// is deliberate: the caller is the loader, the loader's job is to refuse rather
// than to skip, and a corpus with one unknown kind is a corpus that was not
// reviewed. Reporting the first one and stopping is what makes the fix a single
// edit rather than a loop of build-fix-build.
//
// The order of the returned slice is the declaration order of the input. That
// is the one place in this codebase where declaration order survives to a
// caller: Evaluate sorts findings at the end, so nothing user-visible depends
// on it, but a corpus author reading a test failure wants to see the
// obligations in the order they wrote them.
func Resolve(entryID string, src []Source) ([]Obligation, error) {
	out := make([]Obligation, 0, len(src))
	for i := range src {
		s := &src[i]

		kind, ok := KindOf(s.Kind)
		if !ok {
			return nil, cerr.New(cerr.ECorpus004,
				entryID+"#"+s.ID+" (unknown kind "+quote(s.Kind)+"; known kinds: "+KindsCSV()+")")
		}

		ob := Obligation{
			ID:         s.ID,
			Kind:       kind,
			Severity:   s.Severity,
			When:       s.When,
			Message:    s.Message,
			Citation:   s.Citation,
			Confidence: s.Confidence,
			EntryID:    entryID,
		}

		if s.Fix != nil {
			action := FixAction(strings.TrimSpace(s.Fix.Action))
			if !action.Valid() {
				return nil, cerr.New(cerr.ECorpus004,
					entryID+"#"+s.ID+" (unknown fix action "+quote(s.Fix.Action)+"; known actions: "+fixActionsCSV()+")")
			}
			ob.Fix = &Fix{
				Action:      action,
				Suggestion:  s.Fix.Suggestion,
				Alternative: s.Fix.Alternative,
				Confidence:  s.Fix.Confidence,
			}
		}

		out = append(out, ob)
	}
	return out, nil
}

// Validate is the loader's hook: it resolves the list and throws the result
// away, so that the loader does not have to know what an Obligation is in order
// to refuse a bad one.
//
// It is separate from Resolve so that the load path reads as one line and the
// decision path keeps the value.
func Validate(entryID string, src []Source) error {
	_, err := Resolve(entryID, src)
	return err
}

// MismatchedSeverity returns a sorted warning for every source obligation whose
// declared severity is outside the band the spec's table lists for its kind.
//
// # WHY THIS IS A WARNING AND NOT AN ERROR
//
// Because the band is a convention, not a rule, and a corpus author who
// deliberately departs from it is usually right. A NON_COMMERCIAL obligation on
// a licence that permits non-commercial research is a CONDITION and not a
// BLOCK, and refusing that would be the validator overruling the person who
// read the licence.
//
// What it catches is the other case: a BLOCK typed where a CONDITION was meant,
// or the reverse, which is the direction that costs money. It is surfaced as a
// notice so that it is visible without being fatal.
func MismatchedSeverity(entryID string, src []Source) []string {
	var out []string
	for i := range src {
		s := &src[i]
		kind, ok := KindOf(s.Kind)
		if !ok {
			continue // Resolve reports this; do not say it twice.
		}
		band := kind.TypicalSeverity()
		if len(band) == 0 {
			continue
		}
		got := strings.TrimSpace(s.Severity)
		found := false
		for _, want := range band {
			if got == want {
				found = true
				break
			}
		}
		if !found {
			out = append(out, entryID+"#"+s.ID+": kind "+string(kind)+
				" usually carries "+strings.Join(band, " or ")+", but declares "+quote(got)+".")
		}
	}
	sort.Strings(out)
	return out
}

func fixActionsCSV() string {
	as := FixActions()
	parts := make([]string, len(as))
	for i, a := range as {
		parts[i] = string(a)
	}
	return strings.Join(parts, ", ")
}

// quote renders a possibly-empty corpus value for a message. An empty string
// prints as (empty) rather than as ” so that the two cases are distinguishable
// in a load failure — "the field is missing" and "the field holds an empty
// string" are different bugs with different fixes.
func quote(s string) string {
	t := strings.TrimSpace(s)
	if t == "" {
		return "(empty)"
	}
	return "'" + t + "'"
}
