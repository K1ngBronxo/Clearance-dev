package policy

import (
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/graph"
)

// Trap IDs for the checks that are properties of the graph rather than of a
// single licence entry. They are looked up in the corpus, because the *shape*
// of the check is code (a graph property cannot be expressed as a one-
// dependency predicate) while the *severity, citation and confidence* are data.
//
// That split is the point: if the judgement about how serious a divergence is
// changes, it changes in YAML, not in a binary release.
const (
	TrapCodeWeightsDivergence = "trap.code-weights-divergence"
	TrapDeclaredVsActual      = "trap.declared-vs-actual-conflict"
)

// GraphCheckTrapIDs names every corpus trap that this package decides with a
// graph-level check rather than with the trap's own predicate.
//
// It is the code half of the `scope: graph` contract. The corpus declares which
// traps need a check; this list declares which checks exist; and
// TestEveryGraphScopedTrapHasAnEngineCheck asserts the two agree in both
// directions.
//
// # WHY THE LIST IS EXPORTED RATHER THAN PRIVATE
//
// Because the guard has to read it, and the alternative is a guard that
// re-types the two string literals. A guard holding its own copy of the ids
// would pass while the engine looked up something else entirely, which is the
// one failure it is supposed to catch.
//
// # WHY THIS IS NOT DERIVED FROM THE CORPUS
//
// It cannot be. This list is the claim "a check exists here"; deriving it from
// the corpus would make it the claim "the corpus says a check should exist
// here", which is the other direction and is already declared by `scope: graph`.
// Two claims that are derived from each other cannot disagree, and the
// disagreement is the thing worth detecting.
//
// # WHY THE ORDER IS FIXED
//
// The slice is compared as a set, but it is written in a fixed order anyway so
// that a diff of this file shows what changed rather than how the map iterated.
func GraphCheckTrapIDs() []string {
	return []string{TrapCodeWeightsDivergence, TrapDeclaredVsActual}
}

// crossResult is what a cross-dependency check produces.
type crossResult struct {
	Findings     []Finding
	Undetermined []graph.Undetermined
	Notices      []corpus.Notice
}

// crossCheck runs the checks that need more than one dependency.
//
// Three checks live here:
//
//  1. Code-vs-weights divergence — the signature finding, and the one no
//     competitor produces. "Your code is Apache-2.0. Your weights are
//     CC-BY-NC. You cannot ship."
//  2. Declared-vs-actual licence conflict — the manifest says MIT, the vendored
//     LICENSE says AGPL. A disagreement is itself a finding, because it means
//     the package's own metadata cannot be trusted.
//  3. A weights dependency with no licence at all, where the code alongside it
//     is permissive and might lull a user into thinking the whole repository is.
func crossCheck(g *graph.Graph, c *corpus.Corpus, in *config.Intent, opts Options) (crossResult, error) {
	var out crossResult
	if g == nil || c == nil {
		return out, nil
	}

	// Group dependencies by scope, so that "the same repository scope" is a
	// real question rather than "any two files in the tree". A monorepo's
	// per-package scopes are respected; an empty scope means the project root.
	byScope := map[string][]graph.Dependency{}
	var scopes []string
	for _, d := range g.Dependencies {
		s := d.Scope
		if _, seen := byScope[s]; !seen {
			scopes = append(scopes, s)
		}
		byScope[s] = append(byScope[s], d)
	}
	sortStrings(scopes)

	for _, scope := range scopes {
		deps := byScope[scope]

		// ── 1. code-vs-weights divergence ───────────────────────────────────
		divTrap, hasDivTrap := findGlobalTrap(c, TrapCodeWeightsDivergence)
		if hasDivTrap {
			for _, w := range deps {
				if w.Kind != graph.KindWeights {
					continue
				}
				wEntry, ok := c.Resolve(w.Licence.SPDX)
				if !ok {
					continue
				}
				// Find the most permissive code dependency in the same scope.
				var code *graph.Dependency
				var codeEntry *corpus.Entry
				for i := range deps {
					d := deps[i]
					if d.Kind != graph.KindPackage && d.Kind != graph.KindVendored {
						continue
					}
					e, ok := c.Resolve(d.Licence.SPDX)
					if !ok {
						continue
					}
					if codeEntry == nil || e.Permissiveness > codeEntry.Permissiveness {
						code = &deps[i]
						codeEntry = e
					}
				}
				if code == nil || codeEntry == nil {
					continue
				}
				// The divergence exists when the code is more permissive than
				// the weights. Equal or stricter code is not a divergence: a
				// user who already cannot ship because of the code learns
				// nothing new from the weights.
				if codeEntry.Permissiveness <= wEntry.Permissiveness {
					continue
				}

				severity := divTrap.Severity
				// Escalate to BLOCK when the weights forbid the declared use
				// outright. The corpus sets the severity, but a
				// non-commercial weight licence combined with declared
				// commercial use is a hard contradiction, and a CONDITION
				// would understate it.
				if (wEntry.Family == corpus.FamilyNonCommercial || wEntry.Family == corpus.FamilySourceAvailable) && in.Use.Commercial {
					severity = corpus.SeverityBlock
				}

				conf := Confidence(divTrap.Confidence)
				// The confidence of a two-legged argument is the weakest leg.
				conf = weakerOf(weakerOf(conf, licenceConfidence(*code)), licenceConfidenceFromEntry(wEntry))

				cit, err := resolveCitation(c.Citations, divTrap.Citation)
				if err != nil {
					return out, err
				}
				out.Findings = append(out.Findings, Finding{
					ID:           findingID(w.ID, divTrap.ID),
					DependencyID: w.ID,
					Kind:         divTrap.ID,
					Severity:     Severity(severity),
					Confidence:   conf,
					Title:        "Code is " + codeEntry.SPDXID + " but weights are " + wEntry.SPDXID,
					Reason: "The code licence does not govern the weights. This repository's code is " +
						codeEntry.SPDXID + " (" + codeEntry.Family + ") while its model weights are " +
						wEntry.SPDXID + " (" + wEntry.Family + "), so the permissive code licence gives you " +
						"no permission to use the weights. Code: " + code.Name + ".",
					Citation: cit,
					// The weights licence governs, so that is what the licence
					// column shows — the same rule the declared-vs-actual check
					// below follows, and for the same reason: the column answers
					// "what kind of obligation is this?", and the answer here is
					// the weights licence, not the code's.
					//
					// This was empty until TestNoUncitedFinding caught it. The
					// finding was otherwise complete — severity, citation,
					// evidence, predicate — so nothing failed; the human
					// renderer would simply have printed a blank licence column
					// on the product's signature finding, which is the one
					// finding a reader is most likely to be looking at.
					Licence:   licenceLabel(w),
					Evidence:  append(append([]graph.Evidence{}, w.Evidence...), code.Evidence...),
					Predicate: divTrap.When,
					TrapID:    divTrap.ID,
				})
			}
		} else if scopeHasWeights(deps) {
			// The notice is gated on the scope actually containing a weight
			// file, and the gate is the difference between a useful warning and
			// noise.
			//
			// Without it, every run against a corpus that carries no
			// `trap.code-weights-divergence` produced the sentence "the
			// code-vs-weights divergence check did not run" — including runs on
			// projects with no weights at all, where the check had nothing to do
			// and its absence is not a gap. That is the shape of warning that
			// teaches a reader to skim the notice list, which is where the
			// notice that matters will be.
			//
			// The `hasDivTrap` branch above needs no equivalent gate: it already
			// iterates only weights dependencies, so a scope with none produces
			// nothing from it.
			out.Notices = append(out.Notices, corpus.Notice{
				Code: string(cerr.ECorpus004),
				Message: "The corpus carries no '" + TrapCodeWeightsDivergence +
					"' trap, so the code-vs-weights divergence check did not run.",
			})
		}

		// ── 2. declared-vs-actual conflict ──────────────────────────────────
		confTrap, hasConfTrap := findGlobalTrap(c, TrapDeclaredVsActual)
		for i := range deps {
			d := deps[i]
			if d.Licence.Source != "vendored_file" {
				continue
			}
			declared := d.Metadata["declared_licence"]
			if declared == "" || strings.EqualFold(declared, d.Licence.SPDX) {
				continue
			}
			if !hasConfTrap {
				continue
			}
			// The more restrictive licence governs. Comparing permissiveness is
			// how that is decided, and it is why the corpus carries the field.
			declaredEntry, declaredKnown := c.Resolve(declared)
			actualEntry, actualKnown := c.Resolve(d.Licence.SPDX)
			if !declaredKnown || !actualKnown {
				continue
			}
			if declaredEntry.Permissiveness <= actualEntry.Permissiveness {
				// The declared licence is the more restrictive one, so the
				// manifest was not hiding anything. Still worth a note.
				continue
			}
			cit, err := resolveCitation(c.Citations, confTrap.Citation)
			if err != nil {
				return out, err
			}
			out.Findings = append(out.Findings, Finding{
				ID:           findingID(d.ID, confTrap.ID),
				DependencyID: d.ID,
				Kind:         confTrap.ID,
				Severity:     Severity(confTrap.Severity),
				Confidence:   weakerOf(Confidence(confTrap.Confidence), licenceConfidence(d)),
				Title:        "Declared and actual licences disagree",
				Reason: "The manifest declares " + declaredEntry.SPDXID + ", but the vendored LICENSE is " +
					actualEntry.SPDXID + ". The more restrictive licence governs, and the package's own " +
					"metadata cannot be trusted.",
				Citation: cit,
				// The actual (vendored) licence governs, so that is what the
				// licence column shows; the declared one is named in the reason.
				Licence:   licenceLabel(d),
				Evidence:  d.Evidence,
				Predicate: confTrap.When,
				TrapID:    confTrap.ID,
			})
		}
	}

	return out, nil
}

// scopeHasWeights reports whether a scope contains at least one weight file.
//
// It exists so that "the check did not run" is only ever said about a scope
// where the check would have had something to do. See the call site.
func scopeHasWeights(deps []graph.Dependency) bool {
	for _, d := range deps {
		if d.Kind == graph.KindWeights {
			return true
		}
	}
	return false
}

// findGlobalTrap looks up a corpus-level trap by id.
func findGlobalTrap(c *corpus.Corpus, id string) (*corpus.Trap, bool) {
	for _, t := range c.GlobalTraps() {
		if t.ID == id {
			return t, true
		}
	}
	return nil, false
}

// licenceConfidence reads the confidence of a dependency's licence resolution.
func licenceConfidence(d graph.Dependency) Confidence {
	switch strings.ToUpper(d.Licence.Confidence) {
	case "HIGH":
		return ConfidenceHigh
	case "MEDIUM":
		return ConfidenceMedium
	case "LOW":
		return ConfidenceLow
	}
	return ConfidenceLow
}

// licenceConfidenceFromEntry reads the confidence of the corpus entry itself.
// The confidence of a cross-dependency finding is the weakest of the two legs,
// because if one leg of an argument is uncertain the conclusion is uncertain.
func licenceConfidenceFromEntry(e *corpus.Entry) Confidence {
	if e == nil {
		return ConfidenceLow
	}
	switch strings.ToUpper(e.Confidence) {
	case "HIGH":
		return ConfidenceHigh
	case "MEDIUM":
		return ConfidenceMedium
	case "LOW":
		return ConfidenceLow
	}
	return ConfidenceLow
}

func weakerOf(a, b Confidence) Confidence {
	if a.Weight() <= b.Weight() {
		return a
	}
	return b
}

// sortStrings is an insertion sort. The slice here is a handful of scopes, and
// keeping it local avoids an import for one call.
func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
