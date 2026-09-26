// The proof that the INV-1 gate can fail.
//
// # WHY THIS FILE EXISTS
//
// INV-1 is the product's headline invariant: "A Finding may not exist without a
// Citation pointing at a corpus entry." TestNoUncitedFinding asserts it
// end-to-end over every fixture — but on its own that assertion was
// unfalsifiable, because resolveCitation checked only that a reference carried
// a URL and a section and never consulted the corpus. Every fixture passed, so
// the guard reported success, and the invariant it was named after was enforced
// by nothing.
//
// The gate now resolves against cite.Index, and this file pins that directly
// from inside the package, because the mechanism is unexported. A guard that
// cannot fail is worse than no guard: it certifies what it does not check.
//
// # WHY THIS FILE IMPORTS NOTHING IMPURE
//
// `internal/policy` is L3, and the architecture guard enforces that L3 and L4
// import no `os`, no `net`, no `io/fs` — test files included, deliberately,
// because a test is code in the package and a shortcut is most tempting there.
// So this file uses no filesystem. The companion test that needs a temporary
// corpus, TestEvaluateRefusesAFindingItCannotCite, lives in the guard suite
// (internal/guard_invariants_test.go), which is an external test package and
// therefore not part of any layer. That split is the architecture rule working,
// not a workaround around it.
package policy

import (
	"testing"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/cite"
)

// TestResolveCitationRefusesAnUnregisteredCitation is the direct proof of the
// INV-1 gate.
func TestResolveCitationRefusesAnUnregisteredCitation(t *testing.T) {
	registered := cite.Ref{
		URL:         "https://example.test/licence",
		Section:     "Clause 4",
		Excerpt:     "the exact clause",
		ExcerptKind: cite.ExcerptVerbatim,
	}

	t.Run("an unregistered citation is refused", func(t *testing.T) {
		// The index is empty, so this reference points at nothing — which is
		// exactly the state INV-1 forbids a finding from being built in.
		empty := cite.NewIndex()
		_, err := resolveCitation(empty, registered)
		if err == nil {
			t.Fatal("resolveCitation accepted a citation that the corpus index " +
				"does not carry.\nINV-1 says a citation must point at a corpus " +
				"entry; a reference that resolves to nothing is an opinion with a " +
				"URL attached, and opinions are what every competitor already " +
				"produces.")
		}
		assertPolicyCode(t, err, cerr.EPolicy002)
	})

	t.Run("a registered citation resolves", func(t *testing.T) {
		// The control. Without it, a gate that refused everything would pass
		// the assertion above and the product would never produce a finding.
		ix := cite.NewIndex()
		if !ix.Add(registered) {
			t.Fatal("registering a fresh citation reported a conflict")
		}
		got, err := resolveCitation(ix, registered)
		if err != nil {
			t.Fatalf("a registered citation was refused: %v", err)
		}
		if got.URL != registered.URL || got.Section != registered.Section {
			t.Errorf("resolved citation is %+v, want url=%q section=%q",
				got, registered.URL, registered.Section)
		}
		// The excerpt kind must survive. Dropping it re-creates the defect the
		// field exists to prevent: a paraphrase arriving at a renderer with
		// nothing to distinguish it from a quotation, and being printed inside
		// quotation marks.
		if got.ExcerptKind != cite.ExcerptVerbatim {
			t.Errorf("excerpt kind is %q, want %q; a renderer decides whether to "+
				"print quotation marks from this field, so losing it means "+
				"printing them by accident",
				got.ExcerptKind, cite.ExcerptVerbatim)
		}
	})

	t.Run("a structurally empty citation is refused", func(t *testing.T) {
		// The structural half, still enforced. A gate that only consulted the
		// index would accept an empty reference if the index happened to carry
		// the empty key.
		ix := cite.NewIndex()
		for _, bad := range []cite.Ref{
			{Section: "Clause 4"},
			{URL: "https://example.test/licence"},
			{},
		} {
			if _, err := resolveCitation(ix, bad); err == nil {
				t.Errorf("resolveCitation accepted a citation with no URL or no "+
					"section: %+v", bad)
			} else {
				assertPolicyCode(t, err, cerr.EPolicy002)
			}
		}
	})

	t.Run("a nil index refuses rather than panics", func(t *testing.T) {
		// resolveCitation is called from constructors that receive the index as
		// a parameter. A nil there is a bug, and a bug must produce a typed
		// error rather than a panic in a user's CI.
		if _, err := resolveCitation(nil, registered); err == nil {
			t.Fatal("resolveCitation accepted a citation with a nil index")
		} else {
			assertPolicyCode(t, err, cerr.EPolicy002)
		}
	})
}

func assertPolicyCode(t *testing.T, err error, want cerr.Code) {
	t.Helper()
	e, ok := cerr.As(err)
	if !ok {
		t.Fatalf("expected %s, got an untyped error: %v", want, err)
	}
	if e.Code() != want {
		t.Fatalf("got %s (%v), want %s", e.Code(), err, want)
	}
}
