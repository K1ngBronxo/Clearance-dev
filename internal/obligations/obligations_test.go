package obligations

import (
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// TestVocabularyIsClosed asserts the boundary of the vocabulary in both
// directions: everything in the list is valid, and the two spellings a person
// actually produces by accident are not.
//
// The misspellings are written out rather than generated. A test that built its
// negative case from a transformation of a real kind would pass for any
// transformation the code happens to reject, including one that rejects
// everything.
func TestVocabularyIsClosed(t *testing.T) {
	for _, k := range Kinds() {
		if !k.Valid() {
			t.Errorf("Kinds() returned %q, which Valid() rejects.\nThe two read the "+
				"same slice, so this means one of them was edited without the other.", k)
		}
		if strings.TrimSpace(string(k)) != string(k) {
			t.Errorf("kind %q has surrounding whitespace; the corpus is compared "+
				"after trimming, so a padded constant would never match.", k)
		}
	}

	for _, bad := range []Kind{"atribution", "ATTRIBUTION ", "ATTRIBUTIONN", "", "attribution"} {
		if bad.Valid() {
			t.Errorf("Valid() accepted %q, which is not in the vocabulary.", bad)
		}
	}

	// Case matters. The corpus writes kinds in upper case and the loader must
	// not silently accept a lower-case one, because a corpus that mixes the two
	// would render two spellings of the same kind in the same report.
	if Kind("attribution").Valid() {
		t.Error("Valid() accepted the lower-case spelling 'attribution'.\n" +
			"KindOf trims but does not fold case on purpose: two spellings of one " +
			"kind in one corpus is a data problem, not a formatting one.")
	}
}

// TestEveryKindHasADescriptionAndABand catches the failure mode that a closed
// vocabulary invites: adding a constant and forgetting one of the two maps.
//
// Without this, a new kind would validate, load, and then render as
// "Unknown obligation kind 'X'." in `clearance explain` — a state where the
// value is accepted by every check and understood by none.
func TestEveryKindHasADescriptionAndABand(t *testing.T) {
	for _, k := range Kinds() {
		d, ok := descriptions[k]
		if !ok || strings.TrimSpace(d) == "" {
			t.Errorf("kind %q has no description in the descriptions map.\n"+
				"Describe() would fall through to the unknown-kind string, which is "+
				"the one message that must be unreachable for a valid kind.", k)
		}
		band := k.TypicalSeverity()
		if len(band) == 0 {
			t.Errorf("kind %q has no typical severity band.\nMismatchedSeverity "+
				"silently skips a kind with an empty band, so the sanity check would "+
				"stop covering it without saying so.", k)
		}
		for _, s := range band {
			switch s {
			case "BLOCK", "CONDITION", "NOTE", "INFO":
			default:
				t.Errorf("kind %q declares typical severity %q, which is not one of "+
					"BLOCK/CONDITION/NOTE/INFO.", k, s)
			}
		}
	}
}

// TestKindsIsSortedAndIsACopy asserts the two properties a caller depends on.
//
// Sorted, because every caller is a renderer and INV-6 makes a renderer's output
// a function of its input alone — a vocabulary that reordered when someone
// tidied the const block would change every `clearance explain --kinds` diff.
//
// A copy, because otherwise one caller sorting or truncating the slice would
// change what every other caller in the process sees.
func TestKindsIsSortedAndIsACopy(t *testing.T) {
	got := Kinds()
	if len(got) == 0 {
		t.Fatal("Kinds() returned nothing")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("Kinds() is not strictly sorted: %q comes before %q", got[i-1], got[i])
		}
	}

	// Mutate the returned slice and assert the next call is unaffected.
	first := got[0]
	got[0] = Kind("MUTATED")
	if again := Kinds(); again[0] == Kind("MUTATED") {
		t.Fatal("Kinds() returned the package's own slice; a caller that sorted or " +
			"truncated it would change the vocabulary for every other caller")
	}
	_ = first

	if csv := KindsCSV(); !strings.Contains(csv, string(Attribution)) ||
		!strings.Contains(csv, string(PlatformToS)) {
		t.Errorf("KindsCSV() does not list the whole vocabulary: %s", csv)
	}
}

// TestKindOfTrimsButDoesNotFold asserts the parsing contract: whitespace from a
// YAML block scalar is tolerated, case is not.
func TestKindOfTrimsButDoesNotFold(t *testing.T) {
	if k, ok := KindOf("  ATTRIBUTION  "); !ok || k != Attribution {
		t.Errorf("KindOf did not trim surrounding whitespace: got (%q, %v)", k, ok)
	}
	if _, ok := KindOf("  attribution  "); ok {
		t.Error("KindOf accepted a lower-case kind")
	}
	if _, ok := KindOf(""); ok {
		t.Error("KindOf accepted the empty string")
	}
}

// TestResolveAcceptsTheWholeVocabulary proves the happy path for every kind, so
// that a constant added to the list without a working code path is caught here
// rather than by a user.
func TestResolveAcceptsTheWholeVocabulary(t *testing.T) {
	src := make([]Source, 0, len(Kinds()))
	for _, k := range Kinds() {
		src = append(src, Source{
			ID:         strings.ToLower(string(k)) + ".test",
			Kind:       string(k),
			Severity:   "CONDITION",
			Confidence: "HIGH",
			Message:    "A message long enough to look like a real one.",
		})
	}

	got, err := Resolve("test-entry", src)
	if err != nil {
		t.Fatalf("Resolve refused the whole vocabulary: %v", err)
	}
	if len(got) != len(src) {
		t.Fatalf("Resolve returned %d obligations for %d sources", len(got), len(src))
	}
	for i := range got {
		if got[i].Kind != Kind(src[i].Kind) {
			t.Errorf("Resolve returned kind %q for source %q", got[i].Kind, src[i].Kind)
		}
		if got[i].EntryID != "test-entry" {
			t.Errorf("Resolve left EntryID as %q; every result must carry the entry "+
				"id it came from, because the load failure message names it.", got[i].EntryID)
		}
		if got[i].Fix != nil {
			t.Errorf("Resolve invented a Fix for an obligation that declared none")
		}
		if want := string(src[i].Kind) + " obligation"; got[i].Title() != want {
			t.Errorf("Title() = %q, want %q", got[i].Title(), want)
		}
	}

	// Declaration order survives, which is what a corpus author reading a test
	// failure wants.
	for i := range got {
		if got[i].ID != src[i].ID {
			t.Errorf("Resolve reordered the input at index %d: got %q, want %q",
				i, got[i].ID, src[i].ID)
			break
		}
	}
}

// TestResolveRefusesAnUnknownKind asserts the refusal names both the entry and
// the offending value.
//
// Both halves matter. The entry id is what tells a corpus author which file to
// open; the offending value is what tells them which of eleven kinds they
// mistyped. A message with only one of the two turns a one-line fix into a
// search.
func TestResolveRefusesAnUnknownKind(t *testing.T) {
	_, err := Resolve("mit", []Source{{
		ID:      "mit.attribution",
		Kind:    "atribution",
		Message: "You must retain the copyright notice.",
	}})
	if err == nil {
		t.Fatal("Resolve accepted the misspelled kind 'atribution'")
	}
	if cerr.CodeOf(err) != cerr.ECorpus004 {
		t.Errorf("Resolve reported %s, not E-CORPUS-004.\nE-CORPUS-004 is the code "+
			"the taxonomy documents as 'one entry failed validation'.", cerr.CodeOf(err))
	}
	msg := err.Error()
	for _, want := range []string{"mit", "mit.attribution", "atribution", "ATTRIBUTION"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q.\nGot: %s", want, msg)
		}
	}
}

// TestResolveRefusesAnUnknownFixAction is the same proof for the second
// vocabulary.
func TestResolveRefusesAnUnknownFixAction(t *testing.T) {
	_, err := Resolve("agpl-3.0-only", []Source{{
		ID:      "agpl.s13.network-use",
		Kind:    string(NetworkDisclosure),
		Message: "Offer network users the source.",
		Fix:     &FixSource{Action: "replcae", Suggestion: "Swap it out."},
	}})
	if err == nil {
		t.Fatal("Resolve accepted the misspelled fix action 'replcae'")
	}
	if cerr.CodeOf(err) != cerr.ECorpus004 {
		t.Errorf("Resolve reported %s, not E-CORPUS-004", cerr.CodeOf(err))
	}
	if msg := err.Error(); !strings.Contains(msg, "replcae") {
		t.Errorf("the refusal does not name the offending action.\nGot: %s", msg)
	}
}

// TestResolveCarriesTheFixThrough asserts that a valid fix survives with its
// action narrowed to the typed vocabulary, and that the narrowing is a
// conversion rather than a copy — a FixAction that is not in the vocabulary
// cannot reach the Fix.
func TestResolveCarriesTheFixThrough(t *testing.T) {
	got, err := Resolve("apache-2.0", []Source{{
		ID:      "apache-2.0.notice-retention",
		Kind:    string(Attribution),
		Message: "Copy the NOTICE file contents into your own NOTICE.",
		Fix: &FixSource{
			Action:      "attribute",
			Suggestion:  "Copy the NOTICE file contents into your own NOTICE.",
			Alternative: "Apache-2.0",
			Confidence:  "HIGH",
		},
	}})
	if err != nil {
		t.Fatalf("Resolve refused a valid fix: %v", err)
	}
	if len(got) != 1 || got[0].Fix == nil {
		t.Fatalf("the fix did not survive Resolve: %+v", got)
	}
	if got[0].Fix.Action != Attribute {
		t.Errorf("Fix.Action = %q, want %q", got[0].Fix.Action, Attribute)
	}
	if got[0].Fix.Alternative != "Apache-2.0" {
		t.Errorf("Fix.Alternative = %q, want Apache-2.0", got[0].Fix.Alternative)
	}
}

// TestFixActionVocabularyIsClosed mirrors TestVocabularyIsClosed for the second
// list.
func TestFixActionVocabularyIsClosed(t *testing.T) {
	got := FixActions()
	if len(got) == 0 {
		t.Fatal("FixActions() returned nothing")
	}
	for i := 1; i < len(got); i++ {
		if got[i-1] >= got[i] {
			t.Errorf("FixActions() is not strictly sorted: %q before %q", got[i-1], got[i])
		}
	}
	for _, a := range got {
		if !a.Valid() {
			t.Errorf("FixActions() returned %q, which Valid() rejects", a)
		}
	}
	for _, bad := range []FixAction{"replcae", "REPLACE", "", "rebase"} {
		if bad.Valid() {
			t.Errorf("Valid() accepted %q as a fix action", bad)
		}
	}
}

// TestMismatchedSeverityFiresInTheExpensiveDirection asserts the sanity warning
// on the two cases that cost money, and asserts that it stays quiet on a
// deliberate departure that is correct.
//
// A warning that fires on everything is a warning nobody reads, so the negative
// case is as load-bearing as the positive one.
func TestMismatchedSeverityFiresInTheExpensiveDirection(t *testing.T) {
	// A BLOCK on an ATTRIBUTION. The spec's band for ATTRIBUTION is CONDITION,
	// and a blocker is what makes a CI job fail — so this one stops a release.
	blockOnAttribution := []Source{{
		ID:       "mit.attribution",
		Kind:     string(Attribution),
		Severity: "BLOCK",
	}}
	if got := MismatchedSeverity("mit", blockOnAttribution); len(got) != 1 {
		t.Errorf("a BLOCK on an ATTRIBUTION produced %d warnings, want 1.\n"+
			"Got: %v", len(got), got)
	} else if !strings.Contains(got[0], "ATTRIBUTION") || !strings.Contains(got[0], "BLOCK") {
		t.Errorf("the warning does not name the kind and the severity: %q", got[0])
	}

	// A NOTE on a NON_COMMERCIAL. This is the direction that lets a commercial
	// user ship, and it is silent in every other check.
	noteOnNonCommercial := []Source{{
		ID:       "cc-by-nc-4.0.non-commercial",
		Kind:     string(NonCommercial),
		Severity: "NOTE",
	}}
	if got := MismatchedSeverity("cc-by-nc-4.0", noteOnNonCommercial); len(got) != 1 {
		t.Errorf("a NOTE on a NON_COMMERCIAL produced %d warnings, want 1.\n"+
			"A NON_COMMERCIAL obligation that does not block is the one mistake that "+
			"lets someone ship a licence violation, so this warning has to fire.",
			len(got))
	}

	// Correct declarations stay quiet, including a kind with a two-value band.
	quiet := []Source{
		{ID: "a", Kind: string(Attribution), Severity: "CONDITION"},
		{ID: "b", Kind: string(SourceDisclosure), Severity: "BLOCK"},
		{ID: "c", Kind: string(SourceDisclosure), Severity: "CONDITION"},
		{ID: "d", Kind: string(PatentGrant), Severity: "NOTE"},
	}
	if got := MismatchedSeverity("mixed", quiet); len(got) != 0 {
		t.Errorf("correctly declared severities produced warnings: %v", got)
	}

	// An unknown kind is Resolve's job to report, and saying it twice would put
	// two lines in the log for one typo.
	unknown := []Source{{ID: "e", Kind: "atribution", Severity: "BLOCK"}}
	if got := MismatchedSeverity("typo", unknown); len(got) != 0 {
		t.Errorf("MismatchedSeverity reported an unknown kind: %v\n"+
			"Resolve already refuses it; two messages for one typo is noise.", got)
	}

	// The result is sorted, because a caller renders it and INV-6 applies to
	// notices as much as to findings.
	many := []Source{
		{ID: "z", Kind: string(Attribution), Severity: "BLOCK"},
		{ID: "a", Kind: string(PatentGrant), Severity: "BLOCK"},
	}
	got := MismatchedSeverity("sorted", many)
	if len(got) != 2 {
		t.Fatalf("expected two warnings, got %d: %v", len(got), got)
	}
	if !strings.Contains(got[0], "#a") || !strings.Contains(got[1], "#z") {
		t.Errorf("MismatchedSeverity is not sorted by obligation id: %v", got)
	}
}

// TestDescribeIsTheSameSentenceAsTheSpec is a shape check, not a content check.
//
// The content check is TestObligationVocabularyMatchesTheSpec in the guard
// suite, which reads the spec file. What this asserts is the property that
// makes Describe() safe to print: a valid kind never falls through to the
// unknown-kind string, and an invalid one always does.
func TestDescribeIsTheSameSentenceAsTheSpec(t *testing.T) {
	for _, k := range Kinds() {
		d := k.Describe()
		if strings.HasPrefix(d, "Unknown obligation kind") {
			t.Errorf("Describe(%q) fell through to the unknown-kind message", k)
		}
		if !strings.HasSuffix(d, ".") {
			t.Errorf("Describe(%q) = %q, which is not a sentence", k, d)
		}
	}
	got := Kind("atribution").Describe()
	if !strings.Contains(got, "atribution") {
		t.Errorf("Describe of an unknown kind does not name it: %q", got)
	}
}

// TestQuoteDistinguishesEmptyFromMissing pins the one formatting decision in
// this package's error messages.
//
// "(empty)" and "”" are different bugs with different fixes — a missing key
// versus a key that holds nothing — and a corpus author debugging a load
// failure is reading this string to tell them apart.
func TestQuoteDistinguishesEmptyFromMissing(t *testing.T) {
	if got := quote(""); got != "(empty)" {
		t.Errorf("quote(\"\") = %q, want (empty)", got)
	}
	if got := quote("   "); got != "(empty)" {
		t.Errorf("quote(whitespace) = %q, want (empty)", got)
	}
	if got := quote("BLOCK"); got != "'BLOCK'" {
		t.Errorf("quote(\"BLOCK\") = %q, want 'BLOCK'", got)
	}
}

// TestValidateIsResolveWithoutTheValue asserts the two entry points cannot
// disagree.
//
// The loader calls Validate and the decision path calls Resolve; if Validate
// were ever reimplemented as something other than a call to Resolve, a corpus
// could pass the load and then fail to resolve — which is a load failure
// arriving at render time, the worst place for one.
func TestValidateIsResolveWithoutTheValue(t *testing.T) {
	bad := []Source{{ID: "x", Kind: "nope"}}
	if err := Validate("entry", bad); err == nil {
		t.Fatal("Validate accepted what Resolve refuses")
	}

	good := []Source{{ID: "x", Kind: string(Attribution), Severity: "CONDITION"}}
	if err := Validate("entry", good); err != nil {
		t.Fatalf("Validate refused what Resolve accepts: %v", err)
	}
}
