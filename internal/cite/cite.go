// Package cite is the citation vocabulary and the resolution gate for INV-1.
//
// INV-1: "A Finding may not exist without a Citation pointing at a corpus entry,
// which itself points at a primary source URL and a section."
//
// This package is the reason that invariant is structural rather than
// aspirational. A Finding is constructed only through a function that resolves
// its citation first; if the citation does not resolve, the Finding is not
// created. There is no code path that produces an uncited finding, because
// there is no way to build the type without one.
//
// The rule the product lives or dies by: an uncited finding is an opinion, and
// opinions are what every competitor already produces.
package cite

import (
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// Ref is a pointer to a clause, as written in a corpus entry.
type Ref struct {
	URL     string `yaml:"url" json:"url"`
	Section string `yaml:"section" json:"section"`
	Excerpt string `yaml:"excerpt,omitempty" json:"excerpt,omitempty"`

	// ExcerptKind is required whenever Excerpt is non-empty. See the
	// ExcerptKind doc comment: an excerpt that does not declare whether it is
	// a quotation or a restatement is rejected at corpus build time
	// (E-CORPUS-004, validation rule 13), because a paraphrase rendered in
	// quotation marks is a fabricated quotation.
	ExcerptKind ExcerptKind `yaml:"excerpt_kind,omitempty" json:"excerpt_kind,omitempty"`

	RetrievedAt string `yaml:"retrieved_at,omitempty" json:"retrieved_at,omitempty"`
}

// Citation is a resolved reference: what a finding carries.
type Citation struct {
	URL     string `json:"url"`
	Section string `json:"section"`
	Excerpt string `json:"excerpt,omitempty"`

	// ExcerptKind travels with the excerpt all the way to the renderer, so
	// that the decision to print quotation marks is made from data rather
	// than from a renderer's assumption.
	ExcerptKind ExcerptKind `json:"excerpt_kind,omitempty"`
}

// MaxExcerpt is the documented limit on a quoted excerpt. It is enforced
// because an excerpt is meant to be read in a terminal, and because a corpus
// entry that pastes a whole licence is a corpus entry nobody reviews.
const MaxExcerpt = 400

// ExcerptKind says whether an excerpt is a quotation or a restatement.
//
// # WHY THIS TYPE EXISTS
//
// The corpus was hand-written from memory of well-known licence texts. Fourteen
// excerpts were then audited against their claimed sources: two were genuine
// verbatim quotations. The other twelve were reworded — same meaning, different
// words — and were stored in the same field and rendered inside the same
// quotation marks.
//
// That is a fabricated quotation, produced by a tool whose strongest claim is
// "every finding quotes the exact clause". A reader could not tell the
// difference, because there was nothing to tell it with.
//
// So the distinction becomes structural, the same way INV-1 makes an uncited
// finding unrepresentable: an excerpt may not exist without declaring which it
// is, and there is no default. A renderer has to read this field to decide
// whether to print quotation marks, so it cannot print them by accident.
type ExcerptKind string

const (
	// ExcerptVerbatim means every character between the quotation marks
	// appears in the source document, in that order. Nothing else qualifies.
	// A single changed word disqualifies it.
	//
	// Claiming this is a claim that a human or a tool diffed the text against
	// the source. It is the only kind a renderer may print inside quotation
	// marks.
	ExcerptVerbatim ExcerptKind = "verbatim"

	// ExcerptParaphrase means the text restates the source's meaning in
	// Clearance's own words. It is honest and often clearer than the
	// original — but it is attributed as a reading, never presented as a
	// quotation.
	ExcerptParaphrase ExcerptKind = "paraphrase"

	// ExcerptUnverified means the text was written from knowledge of the
	// source and has not been diffed against it. It is the honest state of an
	// excerpt that nobody has checked, and it is deliberately distinct from
	// paraphrase: "we restated this" and "we do not know whether we restated
	// this or copied it" are different claims, and collapsing them would let
	// an unverified excerpt inherit a paraphrase's respectability.
	//
	// The whole corpus was migrated to this value on 23 September 2026, when
	// an audit found twelve of fourteen sampled excerpts were rewordings
	// presented as quotations. Entries are upgraded to verbatim only after
	// the text has been diffed, which makes `verbatim` a claim that means
	// something.
	ExcerptUnverified ExcerptKind = "unverified"
)

// Valid reports whether k is one of the three kinds.
func (k ExcerptKind) Valid() bool {
	return k == ExcerptVerbatim || k == ExcerptParaphrase || k == ExcerptUnverified
}

// IsVerbatim reports whether an excerpt of this kind may be rendered inside
// quotation marks. It is the only question a renderer should ask: quotation
// marks are a claim about the source, and only a checked claim may carry them.
func (k ExcerptKind) IsVerbatim() bool { return k == ExcerptVerbatim }

// ID is the stable identity of a citation: the URL and the section together.
// Two corpus entries citing the same clause therefore share an ID, which is
// what lets the corpus build a single index and what makes `clearance explain`
// able to find the clause from a finding.
func (r Ref) ID() string { return r.URL + "#" + r.Section }

// Validate checks the structural rules a corpus citation must satisfy. It is
// called at corpus build time, so a bad citation is caught before release
// rather than at a user's first run (E-CORPUS-004 / validation rule 10).
func (r Ref) Validate() error {
	if strings.TrimSpace(r.URL) == "" {
		return cerr.New(cerr.ECorpus004, "citation")
	}
	if strings.TrimSpace(r.Section) == "" {
		// A citation without a section is a citation without a location, which
		// is the thing this product exists to provide.
		return cerr.New(cerr.ECorpus004, "citation")
	}
	if len(r.Excerpt) > MaxExcerpt {
		return cerr.New(cerr.ECorpus004, "citation")
	}

	// An excerpt must declare what it is (validation rule 13).
	//
	// This is the check that makes the fabricated-quotation failure mode
	// impossible rather than merely discouraged. An excerpt with no kind is
	// refused, because the only two possibilities are that it is a quotation
	// or that it is not, and a corpus that cannot say which one is a corpus
	// that will eventually claim the wrong one.
	if r.Excerpt != "" {
		switch {
		case r.ExcerptKind == "":
			return cerr.New(cerr.ECorpus004,
				"citation: an excerpt is present but excerpt_kind is missing; declare 'verbatim', 'paraphrase' or 'unverified'")
		case !r.ExcerptKind.Valid():
			return cerr.New(cerr.ECorpus004,
				"citation: excerpt_kind '"+string(r.ExcerptKind)+"' is not 'verbatim', 'paraphrase' or 'unverified'")
		}
	} else if r.ExcerptKind != "" {
		// A kind with no excerpt asserts something about text that is not
		// there. It is almost always a YAML indentation mistake, and the
		// honest response is to refuse rather than to silently drop it.
		return cerr.New(cerr.ECorpus004,
			"citation: excerpt_kind declared but no excerpt is present")
	}
	return nil
}

// Index is the set of citations a corpus knows about, keyed by ID.
//
// It is built once, from the corpus, and it is the only thing that can resolve
// a reference. A citation that is not in the index cannot produce a finding.
type Index struct {
	byID map[string]Citation
}

// NewIndex returns an empty index.
func NewIndex() *Index { return &Index{byID: map[string]Citation{}} }

// Add registers a reference and reports whether it was consistent with what the
// index already held.
//
// It returns false ONLY when the same citation ID is already registered with
// different content. That is a genuine corpus inconsistency: two entries claim
// the same clause but quote it differently, and a reader would not know which
// to believe. The first registration wins.
//
// Registering the identical citation twice is not a conflict and returns true.
// One clause commonly supports several findings — "SSPL is not OSI-approved" is
// cited by both the licence entry and the source-available trap — and that is
// the corpus working as intended.
//
// An earlier version returned false for ANY repeat registration, so the loader
// warned that two entries "cite X with different excerpts" when the excerpts
// were byte-identical. A warning that cries wolf is a warning nobody reads,
// and it would have trained a maintainer to ignore the real one.
func (ix *Index) Add(r Ref) bool {
	id := r.ID()
	existing, exists := ix.byID[id]
	if !exists {
		ix.byID[id] = Citation{
			URL:         r.URL,
			Section:     r.Section,
			Excerpt:     r.Excerpt,
			ExcerptKind: r.ExcerptKind,
		}
		return true
	}
	return existing.URL == r.URL &&
		existing.Section == r.Section &&
		existing.Excerpt == r.Excerpt &&
		existing.ExcerptKind == r.ExcerptKind
}

// Len returns how many distinct citations the corpus carries. It appears in
// `clearance corpus info`, because "412 clause entries" is a claim the tool
// should be able to substantiate about itself.
func (ix *Index) Len() int {
	if ix == nil {
		return 0
	}
	return len(ix.byID)
}

// Resolve turns a Ref into a Citation, or fails with E-POLICY-002.
//
// A failure here is an INTERNAL error, not a user error: it means the corpus
// contains an obligation whose citation was never registered, which is a corpus
// bug that a release guard should have caught. The exit code is 4 and the
// message says so, because the user cannot fix it and must not be asked to.
func (ix *Index) Resolve(r Ref) (Citation, error) {
	if ix == nil {
		return Citation{}, cerr.New(cerr.EPolicy002, r.ID())
	}
	c, ok := ix.byID[r.ID()]
	if !ok {
		return Citation{}, cerr.New(cerr.EPolicy002, r.ID())
	}
	return c, nil
}

// Get returns a registered citation by ID, for `clearance explain`.
func (ix *Index) Get(id string) (Citation, bool) {
	if ix == nil {
		return Citation{}, false
	}
	c, ok := ix.byID[id]
	return c, ok
}

// IDs returns every registered citation ID, sorted. Sorted because the order is
// rendered (INV-6).
func (ix *Index) IDs() []string {
	if ix == nil {
		return nil
	}
	out := make([]string, 0, len(ix.byID))
	for id := range ix.byID {
		out = append(out, id)
	}
	sortStrings(out)
	return out
}

// sortStrings is a small insertion sort over a string slice. The corpus has
// hundreds of citations, not millions; an insertion sort here keeps the package
// free of a `sort` import in a file whose job is vocabulary, and the
// determinism requirement is met either way.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
