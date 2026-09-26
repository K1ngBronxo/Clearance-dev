package cite

import (
	"strings"
	"testing"
)

// TestAddRepeatedIdenticalCitationIsNotAConflict pins the fix for a false
// alarm that made the corpus loader cry wolf.
//
// One clause legitimately supports several findings: "SSPL is not
// OSI-approved" is cited by the licence entry and by the source-available
// trap, with the same words both times. The earlier implementation returned
// false for any repeat registration, so the loader printed "Two corpus
// entries cite X with different excerpts" when the excerpts were
// byte-identical. A warning that is wrong is worse than no warning, because
// it teaches the maintainer to skip the real one.
func TestAddRepeatedIdenticalCitationIsNotAConflict(t *testing.T) {
	ix := NewIndex()
	r := Ref{
		URL:         "https://example.invalid/licence",
		Section:     "§1",
		Excerpt:     "You may not do the thing.",
		ExcerptKind: ExcerptVerbatim,
	}

	if !ix.Add(r) {
		t.Fatal("first Add reported a conflict against an empty index")
	}
	if !ix.Add(r) {
		t.Error("second Add of the IDENTICAL citation reported a conflict; " +
			"one clause supporting two findings is normal")
	}
	if got := ix.Len(); got != 1 {
		t.Errorf("Len() = %d, want 1: the index keys on URL#section, so the "+
			"repeat must collapse to one entry", got)
	}
}

// TestAddDifferentExcerptForSameIDIsAConflict is the other half: the case the
// warning exists for. Two entries claiming the same clause with different
// words means a reader cannot know which text is the clause.
func TestAddDifferentExcerptForSameIDIsAConflict(t *testing.T) {
	ix := NewIndex()
	first := Ref{
		URL:         "https://example.invalid/licence",
		Section:     "Limitations",
		Excerpt:     "You may not provide the software as a managed service.",
		ExcerptKind: ExcerptVerbatim,
	}
	second := first
	second.Excerpt = "You may not disable the license key."

	if !ix.Add(first) {
		t.Fatal("first Add reported a conflict against an empty index")
	}
	if ix.Add(second) {
		t.Error("a different excerpt under the same citation ID was accepted; " +
			"the corpus would then hold two conflicting texts for one clause")
	}

	// The first registration wins, and that has to be observable: a user
	// running `clearance explain` must get one answer, not a coin toss.
	got, ok := ix.Get(first.ID())
	if !ok {
		t.Fatal("the citation is missing from the index")
	}
	if got.Excerpt != first.Excerpt {
		t.Errorf("Get returned %q, want the first registration %q",
			got.Excerpt, first.Excerpt)
	}
}

// TestAddDistinguishesSectionWithinOnePage guards the convention that made the
// Elastic entry correct. One page can state several prohibitions under one
// heading; the section string is what keeps their citation IDs apart.
func TestAddDistinguishesSectionWithinOnePage(t *testing.T) {
	ix := NewIndex()
	a := Ref{
		URL:         "https://example.invalid/licence",
		Section:     "Limitations (managed service)",
		Excerpt:     "You may not provide the software as a managed service.",
		ExcerptKind: ExcerptVerbatim,
	}
	b := Ref{
		URL:         "https://example.invalid/licence",
		Section:     "Limitations (licence key)",
		Excerpt:     "You may not disable the license key.",
		ExcerptKind: ExcerptVerbatim,
	}

	if !ix.Add(a) || !ix.Add(b) {
		t.Error("two qualifiers of the same heading were treated as one citation ID")
	}
	if got := ix.Len(); got != 2 {
		t.Errorf("Len() = %d, want 2", got)
	}
}

// TestExcerptKindMustBeDeclared is the structural half of INV-1's honesty
// rule: an excerpt may not exist without saying whether it is a quotation or
// a restatement. This is what makes a fabricated quotation unrepresentable
// rather than merely discouraged.
func TestExcerptKindMustBeDeclared(t *testing.T) {
	cases := []struct {
		name    string
		ref     Ref
		wantErr bool
	}{
		{
			name:    "excerpt with no kind",
			ref:     Ref{URL: "https://x.invalid", Section: "§1", Excerpt: "text"},
			wantErr: true,
		},
		{
			name:    "kind with no excerpt",
			ref:     Ref{URL: "https://x.invalid", Section: "§1", ExcerptKind: ExcerptVerbatim},
			wantErr: true,
		},
		{
			name:    "unknown kind",
			ref:     Ref{URL: "https://x.invalid", Section: "§1", Excerpt: "text", ExcerptKind: "probably"},
			wantErr: true,
		},
		{
			name:    "verbatim",
			ref:     Ref{URL: "https://x.invalid", Section: "§1", Excerpt: "text", ExcerptKind: ExcerptVerbatim},
			wantErr: false,
		},
		{
			name:    "paraphrase",
			ref:     Ref{URL: "https://x.invalid", Section: "§1", Excerpt: "text", ExcerptKind: ExcerptParaphrase},
			wantErr: false,
		},
		{
			name:    "unverified",
			ref:     Ref{URL: "https://x.invalid", Section: "§1", Excerpt: "text", ExcerptKind: ExcerptUnverified},
			wantErr: false,
		},
		{
			name:    "no excerpt at all is fine",
			ref:     Ref{URL: "https://x.invalid", Section: "§1"},
			wantErr: false,
		},
		{
			name:    "missing url",
			ref:     Ref{Section: "§1"},
			wantErr: true,
		},
		{
			name:    "missing section",
			ref:     Ref{URL: "https://x.invalid"},
			wantErr: true,
		},
		{
			name: "over the length limit",
			ref: Ref{
				URL:         "https://x.invalid",
				Section:     "§1",
				Excerpt:     strings.Repeat("a", MaxExcerpt+1),
				ExcerptKind: ExcerptVerbatim,
			},
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.ref.Validate()
			if tc.wantErr && err == nil {
				t.Error("Validate accepted a citation it should have refused")
			}
			if !tc.wantErr && err != nil {
				t.Errorf("Validate refused a valid citation: %v", err)
			}
		})
	}
}

// TestOnlyVerbatimMayBeQuoted is the single question a renderer is allowed to
// ask. If this returns true for anything but verbatim, the renderer prints
// quotation marks around text that was not quoted.
func TestOnlyVerbatimMayBeQuoted(t *testing.T) {
	if !ExcerptVerbatim.IsVerbatim() {
		t.Error("verbatim is not reported as quotable")
	}
	if ExcerptParaphrase.IsVerbatim() {
		t.Error("paraphrase would be rendered inside quotation marks")
	}
	if ExcerptUnverified.IsVerbatim() {
		t.Error("an unverified excerpt would be rendered inside quotation marks")
	}
	// The zero value is the dangerous one: a citation decoded from a corpus
	// file that forgot the field must not be quotable by default.
	if ExcerptKind("").IsVerbatim() {
		t.Error("the empty kind is quotable; a missing field would print as a quotation")
	}
}

// TestIDsAreSorted ensures the rendered order is stable (INV-6). `clearance
// corpus info` and `explain` both print these, and a map iteration order
// would make two runs of the same input disagree.
func TestIDsAreSorted(t *testing.T) {
	ix := NewIndex()
	for _, s := range []string{"c", "a", "b"} {
		ix.Add(Ref{URL: "https://x.invalid/" + s, Section: "§1"})
	}
	ids := ix.IDs()
	for i := 1; i < len(ids); i++ {
		if ids[i-1] > ids[i] {
			t.Fatalf("IDs() is not sorted: %v", ids)
		}
	}
}
