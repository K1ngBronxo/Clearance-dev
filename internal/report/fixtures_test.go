package report

import (
	"github.com/clearance-dev/clearance/internal/cite"
	"github.com/clearance-dev/clearance/internal/expr"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// This file builds the representative verdicts the golden tests render.
//
// # WHY THE FIXTURES GO THROUGH verdict.Fold
//
// A hand-written Verdict literal would pin the *renderers* but not the join
// between the fold and the renderers — and that join is where the product's
// core invariant lives. The confidence gate (INV-2) is applied inside Fold, so
// a fixture built by hand could put a LOW-confidence BLOCK in the blockers
// slice and every renderer test would still pass while the product was broken.
//
// Building every fixture with verdict.Fold means the goldens pin the whole
// path: declared severity + confidence → effective band → rendered section →
// visible gate line. The tests then assert the invariant directly as well
// (TestLowConfidenceNeverBlocks); the fixtures are what make the *goldens*
// meaningful rather than merely stable.
//
// # THE FOUR CLASSES, PLUS ONE EDGE FIXTURE
//
//   - ship         — nothing found; the class that must still carry the disclaimer
//   - conditional  — a HIGH condition, a gated MEDIUM block, a gated LOW block
//   - blocked      — two HIGH blockers, one LOW note
//   - undetermined — two unclassified entries, unsigned corpus
//   - edge         — the defensive branches: missing citation, missing evidence,
//     missing confidence, unknown severity, unknown error code
//
// The edge fixture exists because those branches are the ones a future refactor
// is most likely to delete without noticing. They are reachable only on a
// corpus or scanner bug, which is exactly why nothing else exercises them.

// fixedScannedAt is the clock value every fixture uses.
//
// It is a real timestamp — 2025-09-24T08:00:00Z — rather than zero, so the SBOM
// exporters' RFC 3339 rendering is pinned by a golden instead of being skipped
// by the `ScannedAt <= 0` branch. Determinism is preserved because the value is
// a constant: the same fixture always renders the same bytes (INV-6).
const fixedScannedAt int64 = 1758700800

// pred builds a validated predicate from a corpus-shaped value. It panics on
// failure because a fixture that cannot build its own predicate is a broken
// test, not a product condition.
func pred(v any) *expr.Expr {
	e, err := expr.FromValue(v)
	if err != nil {
		panic("report fixtures: expr.FromValue: " + err.Error())
	}
	return e
}

// baseMeta is the meta block shared by every fixture. The two genuinely
// non-deterministic fields are set to constants so a golden is stable.
func baseMeta() verdict.Meta {
	return verdict.Meta{
		ToolVersion:     "0.9.1",
		CorpusVersion:   "2026.09.24",
		CorpusSigned:    true,
		IntentHash:      "9f2c1b7a4e8d0f3a5c6b1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a",
		ConfigPath:      "clearance.config.yml",
		ScannedAt:       fixedScannedAt,
		DurationMS:      42,
		BuildCommit:     "3b1f2a7",
		BuildProvenance: "local",
	}
}

// withCounts stamps the three summary fields Fold does not compute. Fold counts
// blockers, conditions and undetermined; the dependency, weight-file and
// upstream-CLI totals come from the graph, which the interface layer folds in
// before rendering. A fixture must supply them the same way the CLI does.
func withCounts(v verdict.Verdict, deps, weights, clis int) verdict.Verdict {
	v.Summary.Dependencies = deps
	v.Summary.WeightFiles = weights
	v.Summary.UpstreamCLIs = clis
	return v
}

// ─── the fixtures ───────────────────────────────────────────────────────────

// fixtureShip is the clean case. It has no findings at all, which is the
// verdict a reader is most likely to paste into a ticket and treat as a
// clearance — and therefore the one that most needs the disclaimer.
func fixtureShip() verdict.Verdict {
	v := verdict.Fold(verdict.Input{})
	v.Project = "acme-web"
	v.Meta = baseMeta()
	return withCounts(v, 3, 1, 0)
}

// fixtureConditional exercises the gate in both directions.
//
//   - the HIGH finding is a genuine condition and sits in Conditions untouched
//   - the MEDIUM BLOCK is demoted to Conditions and must render a gate line
//   - the LOW BLOCK is demoted all the way to Notes and must render a gate line
//
// If the gate ever stopped demoting, this fixture would produce DO NOT SHIP and
// the conditional golden would change — which is the point of pinning it.
func fixtureConditional() verdict.Verdict {
	high := policy.Finding{
		ID:           "f-attr-001",
		DependencyID: "npm:@mendable/firecrawl-js@1.2.3",
		Kind:         "attribution.required",
		Severity:     policy.SeverityCondition,
		Confidence:   policy.ConfidenceHigh,
		Title:        "Attribution notice must be preserved",
		Reason:       "The dependency is distributed under a licence whose attribution clause requires the notice to travel with every redistribution of the software, including a bundled web build.",
		Licence:      "MIT",
		Citation: cite.Citation{
			URL:     "https://opensource.org/license/mit",
			Section: "MIT License — the copyright notice and this permission notice shall be included",
			Excerpt: "The above copyright notice and this permission notice shall be included in all copies or substantial portions of the Software.",
			// Paraphrase: must render without quotation marks in the human form.
			ExcerptKind: cite.ExcerptParaphrase,
		},
		Evidence: []graph.Evidence{{
			Path: "package.json", LineStart: 12, LineEnd: 12,
		}},
		Fix: &policy.Fix{
			Action:     "add-notice",
			Suggestion: "Include the dependency's NOTICE file in the distributed bundle.",
			Confidence: policy.ConfidenceHigh,
		},
		Predicate: pred(map[string]any{"op": "==", "field": "use.distributed", "value": true}),
	}

	medium := policy.Finding{
		ID:           "f-net-002",
		DependencyID: "pypi:torch@2.4.0",
		Kind:         "network.disclosure",
		Severity:     policy.SeverityBlock,
		Confidence:   policy.ConfidenceMedium,
		Title:        "Network disclosure clause may apply",
		Reason:       "A network-interaction clause appears to apply, but the clause text is ambiguous about whether an internal-only deployment counts as interaction.",
		Licence:      "BSD-3-Clause",
		Citation: cite.Citation{
			URL:         "https://www.gnu.org/licenses/agpl-3.0.html",
			Section:     "AGPL-3.0 §13 — Remote Network Interaction",
			Excerpt:     "if you modify the Program, your modified version must prominently offer all users interacting with it remotely through a computer network an opportunity to receive the Corresponding Source",
			ExcerptKind: cite.ExcerptVerbatim,
		},
		Evidence: []graph.Evidence{{
			Path: "requirements.txt", LineStart: 4, LineEnd: 4,
		}},
	}

	low := policy.Finding{
		ID:           "f-lic-003",
		DependencyID: "cargo:leftpad@1.0.0",
		Kind:         "licence.ambiguous",
		Severity:     policy.SeverityBlock,
		Confidence:   policy.ConfidenceLow,
		Title:        "Licence text could not be classified",
		Reason:       "The licence file is a short custom notice that names no SPDX identifier and the tool could not map it to a known licence.",
		Licence:      "",
		Citation: cite.Citation{
			URL:         "https://example.invalid/leftpad/LICENSE",
			Section:     "LICENSE — custom notice",
			Excerpt:     "This software may be used, but the authors accept no liability and reserve all other rights.",
			ExcerptKind: cite.ExcerptUnverified,
		},
		Evidence: []graph.Evidence{{
			Path: "Cargo.lock", LineStart: 88, LineEnd: 90, Excerpt: "name = \"leftpad\"",
		}},
		UndeterminedField: "licence_model",
	}

	v := verdict.Fold(verdict.Input{Findings: []policy.Finding{high, medium, low}})
	v.Project = "acme-web"
	v.Meta = baseMeta()
	return withCounts(v, 5, 0, 1)
}

// fixtureBlocked is DO NOT SHIP. It carries the fields the richer renderings
// need — a trap id, a fix with an alternative, a verbatim citation, a line
// range — so the goldens pin those branches rather than the simplest one.
func fixtureBlocked() verdict.Verdict {
	block := policy.Finding{
		ID:           "f-copyleft-001",
		DependencyID: "npm:some-agpl-lib@3.0.0",
		Kind:         "copyleft.network",
		Severity:     policy.SeverityBlock,
		Confidence:   policy.ConfidenceHigh,
		Title:        "AGPL network clause contradicts a closed-source deployment",
		Reason:       "The dependency is licensed under the AGPL, which requires that users interacting with a modified version over a network be offered the Corresponding Source. The declared intent is a closed-source service, so the obligation cannot be met without a licence change or removing the dependency.",
		Licence:      "AGPL-3.0-only",
		Citation: cite.Citation{
			URL:         "https://www.gnu.org/licenses/agpl-3.0.html",
			Section:     "AGPL-3.0 §13 — Remote Network Interaction",
			Excerpt:     "Notwithstanding any other provision of this License, if you modify the Program, your modified version must prominently offer all users interacting with it remotely through a computer network (if your version supports such interaction) an opportunity to receive the Corresponding Source of your version by providing access to the Corresponding Source from a network server at no charge.",
			ExcerptKind: cite.ExcerptVerbatim,
		},
		Evidence: []graph.Evidence{{
			Path:      "package-lock.json",
			LineStart: 1042,
			LineEnd:   1048,
			Excerpt:   "\"license\": \"AGPL-3.0-only\"",
			SHA256:    "0f1e2d3c4b5a69788796a5b4c3d2e1f00f1e2d3c4b5a69788796a5b4c3d2e1f0",
		}},
		Fix: &policy.Fix{
			Action:      "replace-dependency",
			Suggestion:  "Replace with a permissively licensed alternative.",
			Alternative: "crawl4ai",
			Confidence:  policy.ConfidenceHigh,
		},
		TrapID:    "trap.agpl.network-service",
		Predicate: pred(map[string]any{"op": "and", "l": map[string]any{"op": "==", "field": "dep.licence.spdx", "value": "AGPL-3.0-only"}, "r": map[string]any{"op": "==", "field": "use.saas", "value": true}}),
	}

	weights := policy.Finding{
		ID:           "f-weights-002",
		DependencyID: "weights:models/llama-3.1-8b.bin",
		Kind:         "licence.custom",
		Severity:     policy.SeverityBlock,
		Confidence:   policy.ConfidenceHigh,
		Title:        "Model weights carry a bespoke community licence",
		Reason:       "The weights are governed by a bespoke community licence that is not an OSI-approved licence and carries field-of-use restrictions the declared intent does not satisfy.",
		Licence:      "Llama-3.1-Community",
		Citation: cite.Citation{
			URL:         "https://llama.meta.com/llama3_1/license/",
			Section:     "Llama 3.1 Community License — Additional Commercial Terms",
			Excerpt:     "If, on the Meta Llama 3.1 version release date, the monthly active users of the products or services made available by or for Licensee exceed 700 million monthly active users in the preceding calendar month, you must request a license from Meta.",
			ExcerptKind: cite.ExcerptUnverified,
		},
		Evidence: []graph.Evidence{{
			Path: "models/README.md", LineStart: 1, LineEnd: 3,
		}},
		TrapID: "trap.weights.mau-threshold",
	}

	note := policy.Finding{
		ID:           "f-notice-003",
		DependencyID: "npm:tiny-mit@1.0.0",
		Kind:         "notice.required",
		Severity:     policy.SeverityNote,
		Confidence:   policy.ConfidenceLow,
		Title:        "Notice file presence could not be confirmed",
		Reason:       "The package declares MIT but no NOTICE file was found in the vendored directory.",
		Licence:      "MIT",
		Citation: cite.Citation{
			URL:         "https://opensource.org/license/mit",
			Section:     "MIT License",
			ExcerptKind: cite.ExcerptUnverified,
		},
		Evidence: []graph.Evidence{{
			Path: "node_modules/tiny-mit/package.json", LineStart: 1, LineEnd: 1,
		}},
	}

	v := verdict.Fold(verdict.Input{Findings: []policy.Finding{block, weights, note}})
	v.Project = "acme-web"
	v.Meta = baseMeta()
	return withCounts(v, 9, 1, 0)
}

// fixtureUndetermined is the honest-gap case: a verdict that could not be
// decided because something could not be classified. The corpus is unsigned,
// which makes the human header name that as a plausible cause.
func fixtureUndetermined() verdict.Verdict {
	und := []graph.Undetermined{
		{
			ID:        "npm:leftpad@1.0.0",
			Kind:      graph.KindPackage,
			Reason:    "licence_file_unreadable",
			Detail:    "The LICENSE file declares charset latin-1; only UTF-8 is supported.",
			Evidence:  []graph.Evidence{{Path: "package.json", LineStart: 3, LineEnd: 3}},
			ErrorCode: "E-PARSE-010",
		},
		{
			ID:        "weights:models/x.bin",
			Kind:      graph.KindWeights,
			Reason:    "no_licence_found",
			Detail:    "No licence text was found beside the weight file and no metadata declares one.",
			Evidence:  []graph.Evidence{{Path: "models/x.bin", LineStart: 1, LineEnd: 1}},
			ErrorCode: "E-SCAN-010",
		},
	}

	v := verdict.Fold(verdict.Input{Undetermined: und})
	v.Project = "acme-web"
	v.Meta = baseMeta()
	v.Meta.CorpusSigned = false
	return withCounts(v, 2, 1, 0)
}

// fixtureEdge reaches the defensive branches. Every one of these is a state
// that should be impossible in production; the fixture pins the loud
// placeholder so a refactor cannot quietly replace it with an empty line.
//
// The findings are placed by Fold exactly as the confidence gate would place
// them, so this fixture also proves the gate does not crash on a finding whose
// confidence is the zero value.
func fixtureEdge() verdict.Verdict {
	noCitation := policy.Finding{
		ID:           "f-edge-citation",
		DependencyID: "npm:no-cite@1.0.0",
		Kind:         "citation.absent",
		Severity:     policy.SeverityCondition,
		Confidence:   policy.ConfidenceHigh,
		Title:        "Finding with no citation",
		Reason:       "This finding exists to pin the MISSING CITATION placeholder.",
		Licence:      "MIT",
		Evidence:     []graph.Evidence{{Path: "package.json", LineStart: 1}},
	}

	noEvidence := policy.Finding{
		ID:           "f-edge-evidence",
		DependencyID: "npm:no-evidence@1.0.0",
		Kind:         "evidence.absent",
		Severity:     policy.SeverityCondition,
		Confidence:   policy.ConfidenceHigh,
		Title:        "Finding with no evidence",
		Reason:       "This finding exists to pin the NONE RECORDED placeholder.",
		Licence:      "MIT",
		Citation: cite.Citation{
			URL:         "https://opensource.org/license/mit",
			Section:     "MIT License",
			ExcerptKind: cite.ExcerptUnverified,
		},
	}

	noConfidence := policy.Finding{
		ID:           "f-edge-confidence",
		DependencyID: "npm:no-confidence@1.0.0",
		Kind:         "confidence.absent",
		Severity:     policy.SeverityBlock,
		// Confidence deliberately left as the zero value. The gate's default
		// arm treats it as LOW, so it lands in Notes.
		Title:   "Finding with no confidence",
		Reason:  "This finding exists to pin the E-POLICY-007 placeholder.",
		Licence: "MIT",
		Citation: cite.Citation{
			URL:         "https://opensource.org/license/mit",
			Section:     "MIT License",
			ExcerptKind: cite.ExcerptUnverified,
		},
		Evidence: []graph.Evidence{{Path: "package.json", LineStart: 2}},
	}

	unknownSeverity := policy.Finding{
		ID:           "f-edge-severity",
		DependencyID: "npm:unknown-severity@1.0.0",
		Kind:         "severity.unknown",
		Severity:     policy.Severity("BOGUS"),
		Confidence:   policy.ConfidenceHigh,
		Title:        "Finding with an unknown severity",
		Reason:       "This finding exists to pin the [?] tag.",
		Licence:      "MIT",
		Citation: cite.Citation{
			URL:         "https://opensource.org/license/mit",
			Section:     "MIT License",
			ExcerptKind: cite.ExcerptUnverified,
		},
		Evidence: []graph.Evidence{{Path: "package.json", LineStart: 3}},
	}

	und := []graph.Undetermined{
		{
			ID:     "local:orphan.dat",
			Kind:   graph.KindAsset,
			Reason: "unknown_error_code",
			Detail: "This entry carries an error code the taxonomy does not know.",
			// No Evidence and a bogus code: exercises actionFor's fallback and
			// the human renderer's `reason:` arm.
			ErrorCode: "E-NOT-A-REAL-CODE",
		},
	}

	v := verdict.Fold(verdict.Input{
		Findings:     []policy.Finding{noCitation, noEvidence, noConfidence, unknownSeverity},
		Undetermined: und,
	})
	v.Project = "edge-cases"
	v.Meta = baseMeta()
	v.Meta.CorpusVersion = ""
	return withCounts(v, 0, 0, 0)
}

// namedFixture pairs a fixture with the name its goldens are filed under.
type namedFixture struct {
	name string
	v    verdict.Verdict
}

// allFixtures returns every fixture in a fixed order. A slice, not a map: the
// test names and the golden file names are derived from it, and a map would
// make the run order — and any failure output — differ between runs (INV-6
// applies to test output as much as to product output).
func allFixtures() []namedFixture {
	return []namedFixture{
		{"ship", fixtureShip()},
		{"conditional", fixtureConditional()},
		{"blocked", fixtureBlocked()},
		{"undetermined", fixtureUndetermined()},
		{"edge", fixtureEdge()},
	}
}
