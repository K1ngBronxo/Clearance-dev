// The ten invariant guards — the spine of the test suite.
//
// Each invariant is paired with "the test that enforces it", and the list ends
// with this sentence:
//
//	These ten tests are the spine of the test suite. If they are green, the
//	product is safe to ship even if everything else is imperfect. If any is
//	red, nothing else matters.
//
// # WHY THIS FILE EXISTS
//
// `make guard` named sixteen tests and ran almost none of them. Fourteen of the
// sixteen did not exist, so `go test -run '<sixteen names>'` matched two tests,
// passed, and printed "ok" — a gate that certified the ten invariants while
// checking two of them. The Makefile was not lying, exactly: it was naming an
// intention. But an intention is not a gate, and the failure mode is the worst
// one available to this product, because the gate's entire job is to make the
// product's central claim ("we do not bluff") true of itself.
//
// # THE RULE APPLIED TO EVERY TEST BELOW
//
// Each guard asserts its invariant in the direction that could actually fail,
// and each was verified to FAIL when the invariant was deliberately violated.
// A guard that cannot fail is worse than no guard, because it certifies what it
// does not check — which is exactly the defect this file repairs.
package clearance_test

import (
	"crypto/ed25519"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/cite"
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/report"
	"github.com/clearance-dev/clearance/internal/safefs"
	"github.com/clearance-dev/clearance/internal/safejson"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// ─────────────────────────────────────────────────────────────────────────────
// INV-1 — No verdict without a citation
// ─────────────────────────────────────────────────────────────────────────────

// TestNoUncitedFinding walks every fixture, produces every verdict, and asserts
// that every finding's citation resolves against the corpus index.
//
// The invariant: "A Finding may not exist without a Citation pointing at a
// corpus entry, which itself points at a primary source URL and a section."
//
// # WHY THIS IS NOT A TAUTOLOGY
//
// It was, until the INV-1 gate was closed. resolveCitation checked only that a
// reference carried a URL and a section; it never consulted cite.Index, so a
// finding could cite a clause the corpus does not carry and this test would
// still pass. The gate now resolves against the index and refuses with
// E-POLICY-002, and TestResolveCitationRefusesAnUnregisteredCitation (in
// internal/policy) pins that refusal directly, because an invariant is only as
// strong as the proof that it can be broken.
//
// The assertion here is deliberately made against the corpus index rather than
// against the finding, so that it is a statement about the world (this clause
// exists in the corpus) rather than about the finding's own consistency.
func TestNoUncitedFinding(t *testing.T) {
	c := guardLoadCorpus(t)
	fixtures := guardFixtureDirs(t)

	total := 0
	for _, dir := range fixtures {
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			v := guardMustRun(t, dir, c, policy.Options{})

			findings := guardAllFindings(v)
			total += len(findings)
			for _, f := range findings {
				ref := cite.Ref{
					URL:         f.Citation.URL,
					Section:     f.Citation.Section,
					Excerpt:     f.Citation.Excerpt,
					ExcerptKind: f.Citation.ExcerptKind,
				}
				if strings.TrimSpace(ref.URL) == "" || strings.TrimSpace(ref.Section) == "" {
					t.Errorf("finding %s (%s) carries no usable citation: url=%q section=%q",
						f.ID, f.Kind, ref.URL, ref.Section)
					continue
				}
				if _, err := c.Citations.Resolve(ref); err != nil {
					t.Errorf("finding %s (%s) cites %s, which the corpus index does not "+
						"carry: %v.\nAn uncited finding is an opinion, and opinions are "+
						"what every competitor already produces (INV-1).",
						f.ID, f.Kind, ref.ID(), err)
				}
			}

			// The licence column must be populated too. A blocker rendered as
			// `[BLOCK] firecrawl` with no licence is the one fact a reader
			// scans the list for, and the constructor that forgot it was a
			// real defect this repository has already shipped once.
			for _, f := range findings {
				if strings.TrimSpace(f.Licence) == "" {
					t.Errorf("finding %s (%s) carries no licence label", f.ID, f.Kind)
				}
			}
		})
	}

	// A run that produced no findings at all would pass every assertion above
	// while proving nothing, so the fixture set must actually exercise the
	// engine.
	if total == 0 {
		t.Fatalf("the fixtures produced no findings at all; this guard walked %d "+
			"fixtures and asserted nothing", len(fixtures))
	}
	t.Logf("INV-1: %d findings across %d fixtures, every citation resolved", total, len(fixtures))
}

// ─────────────────────────────────────────────────────────────────────────────
// INV-2 — Confidence is mandatory and never inflated
// ─────────────────────────────────────────────────────────────────────────────

// TestLowConfidenceNeverBlocks asserts that a LOW-confidence interpretation can
// never produce DO NOT SHIP, and that it does not vanish either.
//
// # BOTH DIRECTIONS MATTER
//
// The safety property is that LOW never blocks — the failure mode of this
// product is not "found nothing", it is "confidently wrong", and a tool that
// does not know must not make a decision that costs someone money.
//
// The second property is that the demoted finding is still VISIBLE. A MEDIUM
// blocker that silently disappeared from the report would be worse than one
// that blocked, because the user would never learn it existed. So the test
// asserts the finding lands in Notes with its raw clause attached, not merely
// that it failed to block.
func TestLowConfidenceNeverBlocks(t *testing.T) {
	// A finding that is structurally a blocker at every confidence level, so
	// that the only variable is confidence.
	blocker := func(conf policy.Confidence) policy.Finding {
		return policy.Finding{
			ID:           "f_test_" + string(conf),
			DependencyID: "npm:example@1.0.0",
			Kind:         "test.blocker",
			Severity:     policy.SeverityBlock,
			Confidence:   conf,
			Title:        "a blocker",
			Reason:       "a blocker at " + string(conf) + " confidence",
			Citation: cite.Citation{
				URL:         "https://example.test/clause",
				Section:     "Clause 1",
				Excerpt:     "the exact clause",
				ExcerptKind: cite.ExcerptVerbatim,
			},
			Licence: "AGPL-3.0-only",
		}
	}

	t.Run("LOW never blocks", func(t *testing.T) {
		// Both with and without the medium-blockers flag, because a future
		// option that promoted LOW by accident is exactly what this catches.
		for _, allowMedium := range []bool{false, true} {
			v := verdict.Fold(verdict.Input{
				Findings:            []policy.Finding{blocker(policy.ConfidenceLow)},
				AllowMediumBlockers: allowMedium,
			})
			if v.Verdict == verdict.DoNotShip {
				t.Errorf("a LOW-confidence BLOCK produced DO NOT SHIP "+
					"(allow_medium_blockers=%v).\nLOW is an admission that the tool "+
					"does not know, and a tool that does not know must not make a "+
					"decision that costs someone money (INV-2).", allowMedium)
			}
			if len(v.Blockers) != 0 {
				t.Errorf("a LOW-confidence finding reached the blockers slice "+
					"(allow_medium_blockers=%v); the confidence gate is applied in "+
					"Fold, and this is the assertion that it is.", allowMedium)
			}
			// Visible, not dropped.
			if len(v.Notes) != 1 {
				t.Errorf("the demoted finding is not in Notes (notes=%d, conditions=%d); "+
					"a finding that silently vanishes is worse than one that blocks",
					len(v.Notes), len(v.Conditions))
			}
			if len(v.Notes) == 1 && v.Notes[0].Confidence != policy.ConfidenceLow {
				t.Errorf("the note's confidence is %q, want LOW", v.Notes[0].Confidence)
			}
		}
	})

	t.Run("MEDIUM blocks only when asked", func(t *testing.T) {
		v := verdict.Fold(verdict.Input{
			Findings: []policy.Finding{blocker(policy.ConfidenceMedium)},
		})
		if v.Verdict != verdict.ShipConditional {
			t.Errorf("a MEDIUM BLOCK without --allow-medium-blockers produced %s, "+
				"want SHIP_CONDITIONAL", v.Verdict.Label())
		}

		v = verdict.Fold(verdict.Input{
			Findings:            []policy.Finding{blocker(policy.ConfidenceMedium)},
			AllowMediumBlockers: true,
		})
		if v.Verdict != verdict.DoNotShip {
			t.Errorf("a MEDIUM BLOCK with --allow-medium-blockers produced %s, "+
				"want DO NOT SHIP; the flag would otherwise be a no-op", v.Verdict.Label())
		}
	})

	t.Run("HIGH blocks", func(t *testing.T) {
		// The control. Without it, an EffectiveSeverity that returned NOTE for
		// everything would pass every assertion above.
		v := verdict.Fold(verdict.Input{
			Findings: []policy.Finding{blocker(policy.ConfidenceHigh)},
		})
		if v.Verdict != verdict.DoNotShip {
			t.Errorf("a HIGH-confidence BLOCK produced %s, want DO NOT SHIP",
				v.Verdict.Label())
		}
	})

	t.Run("no confidence means no finding", func(t *testing.T) {
		// INV-2's structural half: Confidence has no valid zero value, so a
		// finding that never set one cannot pass the gate.
		if policy.Confidence("").Valid() {
			t.Error("the zero Confidence is Valid(); a Finding could then exist " +
				"without a confidence (INV-2)")
		}
		for _, bad := range []policy.Confidence{"", "high", "CERTAIN", "low"} {
			if bad.Valid() {
				t.Errorf("Confidence(%q).Valid() is true; only HIGH, MEDIUM and LOW "+
					"are confidence levels", bad)
			}
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// INV-3 — The scanner never executes, never installs, never phones home
// ─────────────────────────────────────────────────────────────────────────────

// TestNoExecInScanner AST-scans the scanner package for the imports that would
// let a manifest cause code to run.
//
// INV-3: "The scanner reads files. It does not exec, os/exec, syscall.Exec,
// plugin.Open, eval, or run a package manager."
//
// # WHY AST AND NOT A GREP
//
// A grep for "os/exec" matches a comment that discusses it — this repository
// has several, deliberately, because the reasoning belongs next to the code. A
// grep is therefore either too noisy to keep green or too narrow to trust. The
// import graph is the actual question, so the import graph is what is parsed.
//
// This overlaps with arch_test.go's ScannerNeverExecutesAnything on purpose.
// That test runs under `make arch`; this one runs under `make guard`, and the
// Makefile names it. Two entry points, one rule, no drift: both read the same
// AST.
func TestNoExecInScanner(t *testing.T) {
	root := moduleRoot(t)
	dir := filepath.Join(root, "internal", "scanner")

	forbidden := map[string]string{
		"os/exec": "runs a process",
		"syscall": "can reach execve directly",
		"plugin":  "loads code at runtime",
		"unsafe":  "defeats the type system the rest of the design leans on",
	}

	found := map[string][]string{}
	scanned := 0
	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		scanned++
		f, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
		if parseErr != nil {
			return parseErr
		}
		for _, spec := range f.Imports {
			imported := strings.Trim(spec.Path.Value, `"`)
			if _, bad := forbidden[imported]; bad {
				rel, _ := filepath.Rel(root, path)
				found[imported] = append(found[imported], filepath.ToSlash(rel))
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walking internal/scanner: %v", err)
	}
	if scanned == 0 {
		t.Fatal("no .go files were scanned in internal/scanner; this guard would pass " +
			"against an empty directory, which is the failure mode it exists to prevent")
	}

	imports := make([]string, 0, len(found))
	for imp := range found {
		imports = append(imports, imp)
	}
	sort.Strings(imports)
	for _, imp := range imports {
		files := found[imp]
		sort.Strings(files)
		t.Errorf("internal/scanner imports %q — it %s.\n"+
			"Files: %s\n"+
			"A scanner that runs your code is a scanner that can be made to run an "+
			"attacker's code (INV-3). Vendored dependencies are attacker-controlled "+
			"input; the scanner reports what they declare and never executes it.",
			imp, forbidden[imp], strings.Join(files, ", "))
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// INV-5 — Every error is typed, classified, and actionable
// ─────────────────────────────────────────────────────────────────────────────

// errCodeRe matches an error code as it appears in prose: E-DOMAIN-123.
//
// The trailing `\d{3}` is deliberate. The taxonomy's one-page index writes
// ranges as `E-CFG-001…010`, which this pattern does not match — correctly,
// because a range is not a code and treating it as one would invent ninety
// codes that do not exist.
var errCodeRe = regexp.MustCompile(`E-[A-Z]+-\d{3}`)

// TestEveryErrorCodeIsDocumented asserts the correspondence in BOTH directions:
// every constant in the code table has a row in the taxonomy, and every code
// named in the taxonomy has a constant.
//
// # WHY BOTH DIRECTIONS
//
// One direction catches a code that was added to the binary and never
// documented — the user meets a code nobody can look up, which is the whole
// failure INV-5 exists to prevent ("a message without a code is a message that
// cannot be looked up").
//
// The other direction catches a code that was documented and never implemented
// — a promise in the docs that the binary does not keep, which is the worse
// failure for a product whose claim is that it does not bluff.
func TestEveryErrorCodeIsDocumented(t *testing.T) {
	docPath := guardPlanFile(t, filepath.Join("02-SPECIFICATIONS", "09-error-taxonomy.md"))
	raw, err := os.ReadFile(docPath)
	if err != nil {
		t.Fatalf("reading the error taxonomy: %v", err)
	}
	doc := string(raw)

	relDoc := filepath.ToSlash(filepath.Join("PLAN", "02-SPECIFICATIONS", "09-error-taxonomy.md"))

	// ── direction 1: every spec code appears in the document ────────────────
	specs := cerr.Specs()
	if len(specs) == 0 {
		t.Fatal("cerr.Specs() is empty; this guard would pass while checking nothing")
	}
	inDoc := map[string]bool{}
	for _, m := range errCodeRe.FindAllString(doc, -1) {
		inDoc[m] = true
	}

	for _, s := range specs {
		code := string(s.Code)
		if !inDoc[code] {
			t.Errorf("code %s (%s) exists in internal/cerr/code.go but is not documented "+
				"in %s.\nEvery code needs a cause, a class, an exit code, a message and "+
				"a recovery path, because errors are the interface with a stranger at "+
				"2am on a CI runner (INV-5).", code, s.Class, relDoc)
		}
	}

	// ── direction 2: every documented code exists as a constant ─────────────
	known := map[string]bool{}
	for _, s := range specs {
		known[string(s.Code)] = true
	}
	documented := make([]string, 0, len(inDoc))
	for code := range inDoc {
		documented = append(documented, code)
	}
	sort.Strings(documented)
	for _, code := range documented {
		if !known[code] {
			t.Errorf("the taxonomy documents %s, but internal/cerr has no such code.\n"+
				"A documented code that the binary cannot produce is a promise it does "+
				"not keep.", code)
		}
	}

	// ── the stated total must be the real total ─────────────────────────────
	//
	// The document opens with "**Total: 102 codes.**" and the index table breaks
	// that down by domain. A count in the prose that drifts from the code table
	// is a claim the repository cannot substantiate about itself, which is the
	// one kind of claim this product is not allowed to make.
	totalRe := regexp.MustCompile(`Total:\s*(\d+)\s*codes`)
	m := totalRe.FindStringSubmatch(doc)
	if m == nil {
		t.Fatalf("the taxonomy no longer states a total code count; this assertion " +
			"cannot be made and the document needs its total restored")
	}
	want, convErr := strconv.Atoi(m[1])
	if convErr != nil {
		t.Fatalf("parsing the stated total %q: %v", m[1], convErr)
	}
	if want != len(specs) {
		t.Errorf("the taxonomy says %d codes; internal/cerr defines %d.\n"+
			"Edit both in the same commit — that is the rule in ADR-021's amendment, "+
			"and this is the test that enforces it.", want, len(specs))
	}

	// ── every spec is internally coherent ───────────────────────────────────
	//
	// A code with no message, no recovery path, or a domain that disagrees with
	// its own name is a row a maintainer cannot use. Lookup() is the accessor
	// the CLI uses to render an error, so this asserts the table the CLI reads.
	seen := map[cerr.Code]bool{}
	for _, s := range specs {
		if seen[s.Code] {
			t.Errorf("code %s is defined twice", s.Code)
		}
		seen[s.Code] = true
		if strings.TrimSpace(s.Message) == "" {
			t.Errorf("code %s has no user message", s.Code)
		}
		if strings.TrimSpace(s.Recovery) == "" {
			t.Errorf("code %s has no recovery path; a code with no next step is a "+
				"dead end", s.Code)
		}
		if got := cerr.Domain(s.Code); got != s.Domain {
			t.Errorf("code %s declares domain %q but its name parses as %q",
				s.Code, s.Domain, got)
		}
		if _, ok := cerr.Lookup(s.Code); !ok {
			t.Errorf("code %s is in Specs() but Lookup() cannot find it", s.Code)
		}
	}
	t.Logf("INV-5: %d codes, documented in both directions", len(specs))
}

// ─────────────────────────────────────────────────────────────────────────────
// INV-6 — The log is append-only; verdicts are reproducible
// ─────────────────────────────────────────────────────────────────────────────

// TestVerdictDeterminism runs the same project many times and asserts the
// rendered verdict is byte-identical every time.
//
// INV-6: "A verdict is a pure function of (project files, config, corpus
// version). Given the same three, the same verdict must be produced —
// bit-for-bit."
//
// # THE THREE NON-DETERMINISM SOURCES THIS CATCHES
//
//  1. A map iterated into output. Go randomises map iteration order, so a
//     single `for k := range m` that reaches a rendered slice produces a
//     different order on almost every run. One run would never reveal it.
//  2. A clock read below the boundary. The only permitted clock reads are
//     meta.scanned_at and meta.duration_ms, injected by the interface layer and
//     zeroed by report.Deterministic.
//  3. Corpus load order. The loader sorts its file list; if it ever stopped,
//     the citation index would register conflicts in a different order and the
//     rendered excerpt for a shared clause would change.
//
// 100 iterations, not two. A map of three keys has a one-in-six chance of
// producing the same order twice by accident, so a two-run test passes roughly
// half the time against a real bug. This is the number the plan names, and it
// is the right number.
func TestVerdictDeterminism(t *testing.T) {
	c := guardLoadCorpus(t)
	fixtures := guardFixtureDirs(t)

	for _, dir := range fixtures {
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			var firstJSON, firstHuman []byte

			for i := 0; i < 100; i++ {
				v := guardMustRun(t, dir, c, policy.Options{})

				// The corpus version must be pinned in the output. A verdict
				// that cannot name the corpus that produced it cannot be
				// defended: if a user says "you told me last week this was
				// fine", the version is the answer.
				if strings.TrimSpace(v.Meta.CorpusVersion) == "" {
					t.Fatalf("run %d: meta.corpus_version is empty; the output must "+
						"name the corpus version that produced it (INV-6)", i)
				}

				j, err := report.Deterministic(v)
				if err != nil {
					t.Fatalf("run %d: rendering JSON: %v", i, err)
				}
				var hb strings.Builder
				if err := report.WriteHuman(&hb, v, report.Options{}); err != nil {
					t.Fatalf("run %d: rendering human: %v", i, err)
				}
				h := []byte(hb.String())

				if i == 0 {
					firstJSON, firstHuman = j, h
					continue
				}
				if string(j) != string(firstJSON) {
					t.Fatalf("run %d produced different JSON from run 0.\n"+
						"The verdict is not a pure function of its inputs (INV-6).\n"+
						"Usual causes: a map iterated into output, a clock read below "+
						"the boundary, or an unsorted slice.\n"+
						"--- run 0 ---\n%s\n--- run %d ---\n%s",
						i, firstJSON, i, j)
				}
				if string(h) != string(firstHuman) {
					t.Fatalf("run %d produced different human output from run 0.\n"+
						"The renderer is L4 and must be a pure Verdict -> bytes "+
						"function (INV-6).\n--- run 0 ---\n%s\n--- run %d ---\n%s",
						i, firstHuman, i, h)
				}
			}
		})
	}
}

// ─────────────────────────────────────────────────────────────────────────────
// INV-7 — Unknown is a first-class answer
// ─────────────────────────────────────────────────────────────────────────────

// TestUnknownNeverDefaultsToShip asserts that a licence the tool cannot
// identify produces UNDETERMINED, never SHIP, and never a guess.
//
// INV-7: "When the scanner cannot determine a licence, or the corpus has no
// entry, the result is UNDETERMINED with a reason — never a default of SHIP,
// and never a guess."
//
// # WHY THIS IS THE MOST IMPORTANT OUTPUT ASSERTION IN THE SUITE
//
// The most dangerous output this tool can produce is a false SHIP. Everything
// else it can get wrong is a missed finding; a false SHIP is a user shipping a
// product they cannot legally ship, having been told by a tool whose entire
// purpose was to prevent that. So the direction of the test is chosen for the
// damage: it asserts what the tool must NOT say.
//
// Two routes into "unknown" are exercised, because they are different code
// paths and only one of them was originally wired up:
//
//   - An unknown licence string, resolved by the scanner but absent from the
//     corpus → E-POLICY-001, "no_corpus_entry".
//   - No licence declared anywhere → the scanner cannot resolve one at all →
//     E-SCAN-011, "licence_unresolved".
func TestUnknownNeverDefaultsToShip(t *testing.T) {
	c := guardLoadCorpus(t)

	const baseConfig = `schema_version: 1

project:
  name: unknown-fixture

use:
  commercial: true
  licence_model: closed-source
  modified: false
  network_exposed: false
  distributed: false
  saas: false
`

	cases := []struct {
		name        string
		files       map[string]string
		wantReason  string
		wantErrCode string
	}{
		{
			// A dependency whose licence string the scanner can read but the
			// corpus does not carry. The scanner reports the fact; the corpus
			// cannot judge it. This is the E-POLICY-001 route.
			name: "a licence the corpus does not carry",
			files: map[string]string{
				"clearance.config.yml": baseConfig,
				"package.json": `{
  "name": "unknown-fixture",
  "version": "1.0.0",
  "license": "MIT"
}`,
				"package-lock.json": `{
  "name": "unknown-fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "unknown-fixture", "version": "1.0.0", "license": "MIT"},
    "node_modules/acme-enterprise-sdk": {
      "version": "9.9.0",
      "license": "LicenseRef-ACME-Proprietary-9.9"
    }
  }
}`,
			},
			wantReason:  "no_corpus_entry",
			wantErrCode: string(cerr.EPolicy001),
		},
		{
			// A dependency with no licence information anywhere. The scanner
			// has nothing to resolve, so the policy engine cannot evaluate it
			// at all. This is the E-SCAN-011 route — a different code path
			// from the case above, and the one that used to be silently
			// dropped on the floor before Evaluate read g.Undetermined.
			name: "no licence declared at all",
			files: map[string]string{
				"clearance.config.yml": baseConfig,
				"package.json": `{
  "name": "unknown-fixture",
  "version": "1.0.0",
  "license": "MIT"
}`,
				"package-lock.json": `{
  "name": "unknown-fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "unknown-fixture", "version": "1.0.0", "license": "MIT"},
    "node_modules/some-unlicensed-thing": {
      "version": "1.0.0"
    }
  }
}`,
			},
			wantReason:  "licence_unresolved",
			wantErrCode: string(cerr.EScan011),
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			dir := guardWriteTree(t, tc.files)
			v := guardMustRun(t, dir, c, policy.Options{})

			if v.Verdict == verdict.Ship {
				t.Fatalf("an unidentifiable licence produced SHIP.\n" +
					"This is the single most dangerous output this tool can produce " +
					"(INV-7): the user is told they may ship a stack the tool could " +
					"not read. An undeclared fact is UNKNOWN, never a default.")
			}
			if v.Verdict != verdict.Undetermined {
				t.Errorf("verdict = %s, want UNDETERMINED", v.Verdict.Label())
			}
			if len(v.Undetermined) == 0 {
				t.Fatal("the verdict is UNDETERMINED but carries no Undetermined " +
					"records, so the user cannot find out why")
			}

			// Every gap must be self-describing: a machine code, a human
			// sentence, and a typed error code the user can look up.
			var sawReason bool
			for _, u := range v.Undetermined {
				if strings.TrimSpace(u.Detail) == "" {
					t.Errorf("undetermined %s carries no human detail", u.ID)
				}
				if strings.TrimSpace(u.ErrorCode) == "" {
					t.Errorf("undetermined %s carries no error code; the user has "+
						"nothing to look up", u.ID)
				}
				if _, ok := cerr.Lookup(cerr.Code(u.ErrorCode)); !ok {
					t.Errorf("undetermined %s carries error code %q, which is not in "+
						"the taxonomy", u.ID, u.ErrorCode)
				}
				if u.Reason == tc.wantReason {
					sawReason = true
					if u.ErrorCode != tc.wantErrCode {
						t.Errorf("reason %q carries code %q, want %q",
							u.Reason, u.ErrorCode, tc.wantErrCode)
					}
				}
			}
			if !sawReason {
				t.Errorf("no undetermined record carries reason %q; got %v",
					tc.wantReason, guardReasons(v.Undetermined))
			}

			// Loud, not silent. INV-7's guard description is explicit: "the CI
			// exit code must be 0 with a loud warning (not a silent pass)".
			if got := v.Verdict.ExitCode(false); got != cerr.ExitOK {
				t.Errorf("exit code without --strict = %d, want %d.\n"+
					"Failing by default would train users to ignore the tool, which "+
					"is a worse outcome than a loud warning.", got, cerr.ExitOK)
			}
			if got := v.Verdict.ExitCode(true); got != cerr.ExitUndetermined {
				t.Errorf("exit code with --strict = %d, want %d",
					got, cerr.ExitUndetermined)
			}
		})
	}

	// The control. A config that declares everything and depends on a licence
	// the corpus knows must still be able to reach a non-UNDETERMINED verdict —
	// otherwise "never defaults to SHIP" would be satisfied by a tool that
	// always says UNDETERMINED, which is useless rather than honest.
	t.Run("a known licence still resolves", func(t *testing.T) {
		dir := guardWriteTree(t, map[string]string{
			"clearance.config.yml": baseConfig,
			"package.json": `{
  "name": "known-fixture",
  "version": "1.0.0",
  "license": "MIT"
}`,
			"package-lock.json": `{
  "name": "known-fixture",
  "version": "1.0.0",
  "lockfileVersion": 3,
  "requires": true,
  "packages": {
    "": {"name": "known-fixture", "version": "1.0.0", "license": "MIT"},
    "node_modules/lodash": {"version": "4.17.21", "license": "MIT"}
  }
}`,
		})
		v := guardMustRun(t, dir, c, policy.Options{})
		if v.Verdict == verdict.Undetermined {
			t.Errorf("a project depending only on MIT produced UNDETERMINED; "+
				"the engine cannot tell a known licence from an unknown one "+
				"(undetermined=%v)", guardReasons(v.Undetermined))
		}
		if len(v.Undetermined) != 0 {
			t.Errorf("a project depending only on MIT produced %d undetermined "+
				"records: %v", len(v.Undetermined), guardReasons(v.Undetermined))
		}
	})
}

func guardReasons(us []graph.Undetermined) []string {
	out := make([]string, 0, len(us))
	for _, u := range us {
		out = append(out, u.Reason+"/"+u.ErrorCode)
	}
	return out
}

// ─────────────────────────────────────────────────────────────────────────────
// INV-8 — Provenance degrades freely; upgrades only by audited correction
// ─────────────────────────────────────────────────────────────────────────────

// guardLicenceYAML builds a minimal but fully valid licence entry at a chosen
// confidence, optionally carrying a correction block.
//
// It is a template rather than a fixture file because the whole point is to
// vary one field — the confidence — against a previous version, and a pair of
// near-identical files on disk is how those drift apart.
func guardLicenceYAML(confidence, correction string) string {
	return `id: licence.synthetic
spdx_id: Synthetic-1.0
name: Synthetic Licence 1.0
family: permissive
osi_approved: false
fsf_libre: false
permissiveness: 3

obligations:
  - id: synthetic.attribution
    kind: ATTRIBUTION
    severity: CONDITION
    when:
      op: "=="
      field: use.distributed
      value: true
    message: >
      A synthetic obligation whose text is comfortably longer than the ten
      character minimum the corpus validator enforces.
    citation:
      url: https://example.test/synthetic
      section: "Clause 1"
    confidence: MEDIUM

traps: []

citation:
  url: https://example.test/synthetic
  section: "Synthetic Licence"
confidence: ` + confidence + `
last_verified: "2026-09-20"
` + correction
}

// TestConfidenceUpgradeRequiresCorrection asserts that a corpus entry whose
// confidence rose without a correction record fails to load.
//
// INV-8: "A corpus entry's confidence may be downgraded at any time. It may be
// upgraded only via a correction record with a stated reason and evidence."
//
// # WHY THIS IS THE QUIETEST DANGEROUS INVARIANT
//
// Without it, confidence laundering is trivial and invisible: a LOW guess
// becomes MEDIUM in one commit ("I'm fairly sure") and HIGH in another ("yes,
// definitely"), and nobody notices that no new evidence ever arrived. The
// output is identical throughout — only the confidence label moves — so no
// rendering test can catch it. The rule makes the laundering path require a
// written, published reason, and the load-time check is the only thing standing
// between a maintainer and a corpus that grades itself.
func TestConfidenceUpgradeRequiresCorrection(t *testing.T) {
	load := func(t *testing.T, files map[string]string, prev *corpus.Corpus) (*corpus.Corpus, error) {
		t.Helper()
		dir := guardWriteCorpusTree(t, files)
		return corpus.Load(corpus.LoadOptions{Dir: dir, Previous: prev, Today: guardToday})
	}

	// The previous version: LOW confidence.
	prev, err := load(t, map[string]string{
		"licences/synthetic.yaml": guardLicenceYAML(corpus.ConfidenceLow, ""),
	}, nil)
	if err != nil {
		t.Fatalf("the LOW baseline corpus does not load: %v", err)
	}
	if got := prev.Stats().Licences; got != 1 {
		t.Fatalf("baseline corpus holds %d licences, want 1", got)
	}

	t.Run("a silent rise is refused", func(t *testing.T) {
		_, err := load(t, map[string]string{
			"licences/synthetic.yaml": guardLicenceYAML(corpus.ConfidenceHigh, ""),
		}, prev)
		if err == nil {
			t.Fatal("a confidence that rose from LOW to HIGH with no correction " +
				"record loaded successfully.\nThis is confidence laundering: the " +
				"label moved and nothing else did, so the corpus now claims to know " +
				"something it never established (INV-8).")
		}
		assertCode(t, err, cerr.ECorpus006)
	})

	t.Run("a justified rise loads", func(t *testing.T) {
		c, err := load(t, map[string]string{
			"licences/synthetic.yaml": guardLicenceYAML(corpus.ConfidenceHigh, `correction:
  reason: The upstream licence text was read in full and diffed against the entry.
  evidence: https://example.test/synthetic
  from: LOW
  to: HIGH
  corrected_at: "2026-09-22"
  corrected_by: maintainer
`),
		}, prev)
		if err != nil {
			t.Fatalf("a properly documented confidence rise was refused: %v", err)
		}
		rises := c.ConfidenceRises
		if len(rises) != 1 {
			t.Fatalf("confidence rises recorded = %d, want 1", len(rises))
		}
		if !rises[0].HasCorrection {
			t.Error("the recorded rise does not carry its correction")
		}
		if rises[0].From != corpus.ConfidenceLow || rises[0].To != corpus.ConfidenceHigh {
			t.Errorf("recorded rise is %s -> %s, want LOW -> HIGH", rises[0].From, rises[0].To)
		}
	})

	t.Run("a correction that names the wrong starting level is refused", func(t *testing.T) {
		// The record claims the rise was MEDIUM -> HIGH, but the previous
		// corpus held LOW. The record therefore does not describe this change,
		// and accepting it would let a maintainer attach any correction block
		// they liked to any rise.
		_, err := load(t, map[string]string{
			"licences/synthetic.yaml": guardLicenceYAML(corpus.ConfidenceHigh, `correction:
  reason: A correction record that describes a different change.
  evidence: https://example.test/synthetic
  from: MEDIUM
  to: HIGH
  corrected_at: "2026-09-22"
  corrected_by: maintainer
`),
		}, prev)
		if err == nil {
			t.Fatal("a correction naming MEDIUM as the starting level was accepted " +
				"against a previous corpus that held LOW; the record does not " +
				"describe the change it authorises (INV-8)")
		}
		assertCode(t, err, cerr.ECorpus006)
	})

	t.Run("an incomplete correction is refused", func(t *testing.T) {
		// The structural half: a correction block present but missing its
		// reason or evidence. Without this, the laundering path is simply
		// "paste an empty correction: {}".
		_, err := load(t, map[string]string{
			"licences/synthetic.yaml": guardLicenceYAML(corpus.ConfidenceHigh, `correction:
  reason: ""
  evidence: ""
  from: LOW
  to: HIGH
  corrected_at: "2026-09-22"
  corrected_by: maintainer
`),
		}, prev)
		if err == nil {
			t.Fatal("a correction with an empty reason and empty evidence was accepted")
		}
		assertCode(t, err, cerr.ECorpus006)
	})

	t.Run("a correction that does not raise is refused", func(t *testing.T) {
		_, err := load(t, map[string]string{
			"licences/synthetic.yaml": guardLicenceYAML(corpus.ConfidenceHigh, `correction:
  reason: A correction that describes no rise at all.
  evidence: https://example.test/synthetic
  from: HIGH
  to: MEDIUM
  corrected_at: "2026-09-22"
  corrected_by: maintainer
`),
		}, prev)
		if err == nil {
			t.Fatal("a correction whose `to` is weaker than its `from` was accepted; " +
				"a correction that does not raise the confidence is not a correction")
		}
		assertCode(t, err, cerr.ECorpus006)
	})

	t.Run("degrading needs no correction", func(t *testing.T) {
		// INV-8's first clause: "A corpus entry's confidence may be downgraded
		// at any time." If this failed, a maintainer who found an error in an
		// entry could not correct it downwards without paperwork — which would
		// make the honest move the expensive one.
		if _, err := load(t, map[string]string{
			"licences/synthetic.yaml": guardLicenceYAML(corpus.ConfidenceLow, ""),
		}, prev); err != nil {
			t.Fatalf("a downgrade was refused: %v", err)
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// INV-9 — The corpus is signed, and the CLI refuses an unsigned update
// ─────────────────────────────────────────────────────────────────────────────

// TestUnsignedCorpusRejected asserts that a tampered, unsigned or wrongly-signed
// bundle is refused, and that the refusal changes nothing on disk.
//
// INV-9: "An unsigned or mis-signed bundle is rejected with E-CORPUS-002, and
// the previous corpus remains in force."
//
// # THE PART THAT IS EASY TO FORGET
//
// "The previous corpus remains in force" is not a statement about the error
// code; it is a statement about the filesystem. A verifier that reported a
// failure *after* overwriting the working corpus would satisfy every assertion
// about return values and still have destroyed the user's data. So this test
// checks the bytes on disk after a failed verification, not only the error.
func TestUnsignedCorpusRejected(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(nil)
	if err != nil {
		t.Fatalf("generating a test key: %v", err)
	}

	// A minimal but complete bundle: payload bytes, a manifest over them, and a
	// signature over the manifest's canonical bytes (ADR-003's scheme).
	payload := []byte(`{"licences":[],"traps":[],"tos":[],"territories":[]}`)
	manifest := func(sha, alg string, schema int) string {
		return `{"version":"2026.09.1","schema_version":` + strconv.Itoa(schema) +
			`,"built_at":"2026-09-23T00:00:00Z","signed_at":"2026-09-23T00:00:00Z"` +
			`,"sha256":"` + sha + `","entry_count":0,"signature_alg":"` + alg + `"}`
	}
	m := &corpus.Manifest{
		Version:       "2026.09.1",
		SchemaVersion: 1,
		BuiltAt:       "2026-09-23T00:00:00Z",
		SignedAt:      "2026-09-23T00:00:00Z",
		SHA256:        corpus.Digest(payload),
		EntryCount:    0,
		SignatureAlg:  "ed25519",
	}
	sig := corpus.SignManifest(priv, m)

	write := func(t *testing.T, payloadBytes []byte, manifestJSON string, sigText string) string {
		t.Helper()
		files := map[string]string{
			corpus.BundleFile:   string(payloadBytes),
			corpus.ManifestFile: manifestJSON,
		}
		if sigText != "" {
			files[corpus.SignatureFile] = sigText
		}
		return guardWriteTree(t, files)
	}

	verify := func(t *testing.T, dir string) error {
		t.Helper()
		root, err := safefs.New(dir, safefs.Limits{MaxFileSize: corpus.MaxCorpusBytes})
		if err != nil {
			t.Fatalf("opening the bundle root: %v", err)
		}
		_, err = corpus.Verify(root, pub)
		return err
	}

	t.Run("a correct bundle verifies", func(t *testing.T) {
		// The control. Without it, a Verify that always failed would pass every
		// assertion below.
		dir := write(t, payload, manifest(m.SHA256, "ed25519", 1), sig)
		if err := verify(t, dir); err != nil {
			t.Fatalf("a correctly signed bundle was refused: %v", err)
		}
	})

	t.Run("a tampered payload is refused and nothing is written", func(t *testing.T) {
		dir := write(t, payload, manifest(m.SHA256, "ed25519", 1), sig)

		// Tamper: one byte appended to the payload. The digest no longer
		// matches the signed manifest.
		tampered := append(append([]byte{}, payload...), ' ')
		tamperedPath := filepath.Join(dir, corpus.BundleFile)
		if err := os.WriteFile(tamperedPath, tampered, 0o644); err != nil {
			t.Fatalf("tampering with the payload: %v", err)
		}

		err := verify(t, dir)
		if err == nil {
			t.Fatal("a bundle whose payload was modified after signing verified " +
				"successfully. This is the exact attack the signature exists to " +
				"stop: a compromised mirror injecting false obligations (INV-9).")
		}
		assertCode(t, err, cerr.ECorpus002)

		// The refusal must not have rewritten anything. Compare the exact bytes.
		after, readErr := os.ReadFile(tamperedPath)
		if readErr != nil {
			t.Fatalf("re-reading the payload: %v", readErr)
		}
		if string(after) != string(tampered) {
			t.Error("the payload changed during a failed verification; a verifier " +
				"must not write (INV-9: the previous corpus remains in force)")
		}
	})

	t.Run("a missing signature is refused", func(t *testing.T) {
		dir := write(t, payload, manifest(m.SHA256, "ed25519", 1), "")
		err := verify(t, dir)
		if err == nil {
			t.Fatal("a bundle with no signature file verified successfully")
		}
		assertCode(t, err, cerr.ECorpus002)
	})

	t.Run("an explicitly unsigned bundle is refused", func(t *testing.T) {
		// signature_alg:"none" is refused unless a caller opts in, and the
		// runtime path never opts in. This is the assertion that the escape
		// hatch stays a developer tool.
		dir := write(t, payload, manifest(m.SHA256, "none", 1), "")
		err := verify(t, dir)
		if err == nil {
			t.Fatal("a bundle declaring signature_alg \"none\" verified successfully " +
				"on the production path")
		}
		assertCode(t, err, cerr.ECorpus002)
	})

	t.Run("a signature from an unknown key is refused", func(t *testing.T) {
		otherPub, otherPriv, keyErr := ed25519.GenerateKey(nil)
		if keyErr != nil {
			t.Fatalf("generating a second key: %v", keyErr)
		}
		if string(otherPub) == string(pub) {
			t.Fatal("the two generated keys are identical, so this sub-test proves nothing")
		}
		dir := write(t, payload, manifest(m.SHA256, "ed25519", 1),
			corpus.SignManifest(otherPriv, m))

		err := verify(t, dir)
		if err == nil {
			t.Fatal("a bundle signed by a key we do not hold verified successfully")
		}
		// A well-formed signature that does not verify under our key is the
		// signature of some other key: a mirror served something unofficial,
		// which is E-CORPUS-009, not a generic corruption code.
		assertCode(t, err, cerr.ECorpus009)
	})

	t.Run("a newer schema is refused", func(t *testing.T) {
		m2 := *m
		m2.SchemaVersion = corpus.SchemaVersion + 1
		dir := write(t, payload, manifest(m.SHA256, "ed25519", m2.SchemaVersion),
			corpus.SignManifest(priv, &m2))

		err := verify(t, dir)
		if err == nil {
			t.Fatal("a bundle declaring a schema version this binary cannot read " +
				"verified successfully; a corpus field this binary does not know " +
				"about might be one that changes a verdict")
		}
		assertCode(t, err, cerr.ECorpus003)
	})

	t.Run("the runtime loader fails closed", func(t *testing.T) {
		// LoadBundle uses the key compiled into the binary. This build embeds
		// none (PublicKey returns E-INT-005 on the all-zero development key),
		// so every load must fail rather than accept an unverified corpus.
		// Failing closed is the only acceptable direction here.
		dir := write(t, payload, manifest(m.SHA256, "ed25519", 1), sig)
		if _, loadErr := corpus.LoadBundleWith(dir, corpus.BundleOptions{}); loadErr == nil {
			t.Fatal("LoadBundleWith accepted a bundle it cannot verify. If this " +
				"fails because a real key is now embedded, the bundle must be " +
				"resigned by that key — but it must never load unverified (INV-9).")
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// INV-10 — Manifest and corpus inputs are parsed with strict, bounded decoders
// ─────────────────────────────────────────────────────────────────────────────

// TestManifestBomb asserts that a deeply nested JSON document is refused with
// E-PARSE-006 rather than exhausting the stack.
//
// INV-10: "JSON has a max depth, max key count, and max size. A malicious
// manifest is a real attack surface."
//
// # WHY A DEPTH LIMIT IS NOT PEDANTRY
//
// A 10 KB file of `[[[[[…]]]]` will recurse until the goroutine stack dies. On
// a developer's machine that is a stack overflow; on a CI runner it is a crash
// in the middle of a release gate, and the user learns nothing except that the
// tool fell over. encoding/json has no depth limit, which is one of the two
// reasons safejson exists.
//
// The boundary is asserted exactly — 64 nested arrays parse, 65 do not — rather
// than "deep input fails". A test that only checks the failure direction passes
// against a limit of 2, which would refuse every real lockfile.
func TestManifestBomb(t *testing.T) {
	limits := safejson.DefaultLimits()

	// A real lockfile is nowhere near the limit. This is the control: if the
	// bound were tightened to something unusable, this fails first.
	t.Run("ordinary input parses", func(t *testing.T) {
		doc := `{"name":"acme","dependencies":{"lodash":"^4.17.21"},"nested":{"a":{"b":[1,2,3]}}}`
		if _, err := safejson.Decode([]byte(doc), limits); err != nil {
			t.Fatalf("a three-deep manifest was refused: %v", err)
		}
	})

	t.Run("the depth boundary is exactly the documented one", func(t *testing.T) {
		atLimit := strings.Repeat("[", limits.MaxDepth) + "1" +
			strings.Repeat("]", limits.MaxDepth)
		if _, err := safejson.Decode([]byte(atLimit), limits); err != nil {
			t.Errorf("a document nested exactly %d deep was refused (%v); the limit "+
				"is documented as a maximum, not as an exclusive bound",
				limits.MaxDepth, err)
		}

		overLimit := strings.Repeat("[", limits.MaxDepth+1) + "1" +
			strings.Repeat("]", limits.MaxDepth+1)
		_, err := safejson.Decode([]byte(overLimit), limits)
		if err == nil {
			t.Fatalf("a document nested %d deep was accepted", limits.MaxDepth+1)
		}
		assertCode(t, err, cerr.EParse006)
	})

	t.Run("an array bomb is refused with E-PARSE-006", func(t *testing.T) {
		bomb := strings.Repeat("[", 5000) + strings.Repeat("]", 5000)
		_, err := safejson.Decode([]byte(bomb), limits)
		if err == nil {
			t.Fatal("a 10 KB array bomb parsed; this is the input that kills the " +
				"goroutine stack on a CI runner (INV-10)")
		}
		assertCode(t, err, cerr.EParse006)
	})

	t.Run("an object bomb is refused with E-PARSE-006", func(t *testing.T) {
		var b strings.Builder
		for i := 0; i < 5000; i++ {
			b.WriteString(`{"a":`)
		}
		b.WriteString("1")
		for i := 0; i < 5000; i++ {
			b.WriteString("}")
		}
		_, err := safejson.Decode([]byte(b.String()), limits)
		if err == nil {
			t.Fatal("a 5000-deep object bomb parsed")
		}
		assertCode(t, err, cerr.EParse006)
	})

	t.Run("a key-count bomb is refused", func(t *testing.T) {
		// The other bound. A document that is shallow but enormous is the
		// sibling attack: depth limits do not touch it, and an unbounded key
		// count is an unbounded allocation.
		small := safejson.Limits{MaxBytes: 8 << 20, MaxDepth: 64, MaxKeys: 8}
		var b strings.Builder
		b.WriteString("{")
		for i := 0; i < 20; i++ {
			if i > 0 {
				b.WriteString(",")
			}
			b.WriteString(`"k`)
			b.WriteString(strconv.Itoa(i))
			b.WriteString(`":1`)
		}
		b.WriteString("}")
		if _, err := safejson.Decode([]byte(b.String()), small); err == nil {
			t.Fatal("a document with 20 keys parsed under a limit of 8")
		}
	})
}

// ─────────────────────────────────────────────────────────────────────────────
// The meta-guard
// ─────────────────────────────────────────────────────────────────────────────

// TestEveryGuardTestNamedInTheMakefileExists is the guard for the guard list.
//
// # THE DEFECT THIS PREVENTS
//
// `make guard` runs `go test -run '<sixteen names>'`. If a name matches no
// test, `go test` does not complain — it runs the tests that do match, reports
// "ok", and exits 0. So the gate's coverage is a function of the Makefile's
// spelling, and a typo, a rename or a deleted test silently shrinks the gate
// while it keeps reporting success. Fourteen of the sixteen names were in that
// state: the gate certified ten invariants while checking two.
//
// This test parses the Makefile, extracts the two guard lists, parses every
// _test.go file in the module, and asserts that every named test exists. A
// guard name that no longer matches anything now fails the gate loudly, naming
// itself.
func TestEveryGuardTestNamedInTheMakefileExists(t *testing.T) {
	root := moduleRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("reading the Makefile: %v", err)
	}

	// The two variables the `guard` target expands. Both are pipe-separated
	// lists of test names; a line continuation would break this, so the parse
	// fails loudly rather than silently returning fewer names.
	var named []string
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "GUARD_") {
			continue
		}
		eq := strings.Index(trimmed, ":=")
		if eq < 0 {
			t.Fatalf("Makefile guard variable is not a := assignment: %q", trimmed)
		}
		value := strings.TrimSpace(trimmed[eq+2:])
		if strings.HasSuffix(value, "\\") {
			t.Fatalf("guard variable %q uses a line continuation; this parser does "+
				"not follow them, and silently reading half the list is exactly the "+
				"failure this test exists to prevent", trimmed)
		}
		for _, name := range strings.Split(value, "|") {
			name = strings.TrimSpace(name)
			if name == "" {
				continue
			}
			named = append(named, name)
		}
	}

	if len(named) == 0 {
		t.Fatal("the Makefile names no guard tests; `make guard` would pass by " +
			"running nothing at all")
	}

	// Every Test function declared anywhere in the module.
	defined := map[string]string{} // name -> file
	for _, top := range []string{"internal", "cmd"} {
		base := filepath.Join(root, top)
		walkErr := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
				return nil
			}
			f, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			rel, _ := filepath.Rel(root, path)
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || fn.Name == nil {
					continue
				}
				if strings.HasPrefix(fn.Name.Name, "Test") {
					defined[fn.Name.Name] = filepath.ToSlash(rel)
				}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walking %s: %v", base, walkErr)
		}
	}
	if len(defined) == 0 {
		t.Fatal("no test functions were found in the module at all; the walk is broken")
	}

	seen := map[string]bool{}
	for _, name := range named {
		if seen[name] {
			t.Errorf("the Makefile names %s twice", name)
			continue
		}
		seen[name] = true
		if file, ok := defined[name]; !ok {
			t.Errorf("`make guard` names %s, but no test with that name exists "+
				"anywhere in the module.\n"+
				"go test -run reports success when a name matches nothing, so this "+
				"name currently contributes zero coverage while looking like it "+
				"contributes some. Either write the test or remove the name.",
				name)
		} else {
			t.Logf("%-45s %s", name, file)
		}
	}
	t.Logf("%d guard tests named, %d test functions defined module-wide",
		len(named), len(defined))
}

// TestNoGuardIsLeftOutOfTheGate is the reverse of the test above.
//
// # WHY THE FORWARD CHECK IS NOT ENOUGH
//
// `TestEveryGuardTestNamedInTheMakefileExists` answers "does every name in the
// gate correspond to a real test?" That catches a name pointing at nothing. It
// cannot catch the opposite, which is the more expensive direction: a real guard
// that no name points at. Such a guard is written, reviewed, documented — and
// never run by `make guard`.
//
// Two were in exactly that state. `TestEvaluateRefusesAFindingItCannotCite` is
// one of the three layers this log cites for INV-1, and `make guard` did not run
// it. `TestCorpusPublicKeyIsStampable` was written to pin the corpus key's
// stampability and was left out of the gate in the same commit that added it.
// Both would have passed forever without ever being executed by the gate they
// were written for — a guard outside the gate is a comment with a compiler
// behind it.
//
// # THE CONVENTION THIS ENFORCES
//
// The guard suite is the files named `guard_*_test.go`. Every Test function in
// one of them is a guard, and every guard must be reachable from a `GUARD_*`
// variable. A test that is not a guard does not belong in one of these files,
// and moving it is cheaper than being unable to tell which guards run.
//
// # AND THE BLIND SPOT IN THAT CONVENTION, WHICH IS NOW NAMED
//
// "A guard is a Test function in a guard_*_test.go file" is only enforceable by
// walking for files with that name, and that is exactly what the loop below did.
// So a guard that *cannot* live in such a file was invisible to it.
//
// On 26 September 2026 one did. `TestOurOwnMakefileNamesNoThirdPartyProgram`
// asserted that Clearance's own build scripts name no third-party program, and
// it lived in internal/scanner/upstream_test.go because it drives unexported
// scanner functions. It was a guard. It was in no GUARD_* variable, so `make
// guard` never ran it. In the same period `make dogfood` reported eleven false
// third-party programs from a script that guard was written to police, and the
// guard was green throughout — not because it was wrong, but because nothing
// executed it. That is the defect this whole file exists to prevent, committed
// by the file itself.
//
// The blind spot is structural, so it gets a list rather than a cleverer
// heuristic: guessing which tests "look like guards" would manufacture exactly
// the false confidence this file is for. Every name below must be in a GUARD_*
// variable, and must still exist.
var guardsOutsideGuardFiles = map[string]string{
	"TestOurOwnScriptsNameNoThirdPartyProgram": "internal/scanner/upstream_test.go — drives unexported scanner functions",
	"TestQuotedCommandSubstitutionIsSplit":     "internal/scanner/upstream_test.go — drives the unexported splitter",
	"TestShellFunctionNamesAreNotPrograms":     "internal/scanner/upstream_test.go — drives the unexported splitter",
}

func TestNoGuardIsLeftOutOfTheGate(t *testing.T) {
	root := moduleRoot(t)

	raw, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("reading the Makefile: %v", err)
	}
	gated := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "GUARD_") {
			continue
		}
		eq := strings.Index(trimmed, ":=")
		if eq < 0 {
			t.Fatalf("Makefile guard variable is not a := assignment: %q", trimmed)
		}
		for _, name := range strings.Split(trimmed[eq+2:], "|") {
			if name = strings.TrimSpace(name); name != "" {
				gated[name] = true
			}
		}
	}
	if len(gated) == 0 {
		t.Fatal("no GUARD_* variables were parsed from the Makefile; this test " +
			"would otherwise pass by comparing against an empty set")
	}

	// allTests maps every Test function name under internal/ to the file it
	// lives in. Collected for every _test.go, not only guard_ ones, so the
	// out-of-file list below can be checked for staleness as well as for
	// coverage.
	allTests := map[string]string{}
	var found int
	walkErr := filepath.WalkDir(filepath.Join(root, "internal"),
		func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			f, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			rel, _ := filepath.Rel(root, path)
			inGuardFile := strings.HasPrefix(d.Name(), "guard_")
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || fn.Name == nil ||
					!strings.HasPrefix(fn.Name.Name, "Test") {
					continue
				}
				allTests[fn.Name.Name] = filepath.ToSlash(rel)
				if !inGuardFile {
					continue
				}
				found++
				if !gated[fn.Name.Name] {
					t.Errorf("%s is in %s but no GUARD_* variable names it.\n"+
						"`make guard` will never run it, so it cannot fail the "+
						"gate no matter what it asserts.\n"+
						"Add it to GUARD_INVARIANTS, GUARD_SECURITY or GUARD_BUILD "+
						"in the Makefile — or, if it is not a guard, move it out of "+
						"guard_*_test.go.",
						fn.Name.Name, filepath.ToSlash(rel))
				}
			}
			return nil
		})
	if walkErr != nil {
		t.Fatalf("walking internal/: %v", walkErr)
	}
	if found == 0 {
		t.Fatal("no Test functions were found in any guard_*_test.go file; the " +
			"walk is broken and this test is checking nothing")
	}

	// The guards the filename convention cannot see. Both directions matter: a
	// listed guard that is not gated is the original defect, and a listed guard
	// that no longer exists is a stale entry pretending the check still runs.
	for name, why := range guardsOutsideGuardFiles {
		where, exists := allTests[name]
		if !exists {
			t.Errorf("%s is in guardsOutsideGuardFiles but no test of that name "+
				"exists anywhere under internal/. Delete the line — a list that "+
				"can only grow stops describing anything.", name)
			continue
		}
		if !gated[name] {
			t.Errorf("%s is a guard in %s (%s) but no GUARD_* variable names it.\n"+
				"`make guard` will never run it, so it cannot fail the gate no "+
				"matter what it asserts. This is the blind spot described above "+
				"the list: the walk only sees guard_*_test.go files, and this "+
				"guard cannot live in one.", name, where, why)
		}
	}

	t.Logf("%d guards in guard_*_test.go, %d tests module-wide, %d guards "+
		"declared outside those files", found, len(allTests),
		len(guardsOutsideGuardFiles))
}

// TestEveryRunNameExists generalises the guard above from the GUARD_* variables
// to every test name that any build script in the repo passes to `-run`.
//
// # WHY THE GUARD ABOVE WAS NOT ENOUGH
//
// TestEveryGuardTestNamedInTheMakefileExists only reads lines beginning with
// `GUARD_`. Every other target was unchecked, and four names outside those
// variables were fictional:
//
//	TestFixtures                     (fixtures)        — did not exist
//	TestEveryDegradeCodeHasFixture   (fixtures)        — did not exist
//	TestCorpusEveryTrapHasFixture    (fixtures)        — did not exist
//	TestCorpusNoSilentUpgrade        (corpus-verify)   — the property was
//	                                                     tested, under a
//	                                                     different name
//	TestCorpusPredicatesTypecheck    (corpus-verify)   — did not exist
//	TestConformance                  (conformance)     — did not exist, and
//	                                                     neither did the
//	                                                     vectors
//
// `go test -run <name>` exits 0 when the name matches nothing, so `make
// fixtures` reported success while running almost nothing, and `make
// conformance` reported success while running nothing at all. The guard that
// was supposed to prevent exactly this looked only at the one group of names
// that happened to be correct.
//
// # WHY IT READS THE WORKFLOWS TOO, AND NOT ONLY THE MAKEFILE
//
// The first version of this test read the Makefile alone, and that was still
// not enough. The same hand-written list had been *copied* into two workflow
// files:
//
//	go test ./internal/... -run 'TestInvariant|TestArch|TestGuard' -count=1
//
// The module has no test whose name contains `TestInvariant` or `TestGuard`, so
// that command selected one test — TestArchitectureLayering — out of the 106
// that `go test ./internal/...` runs, and exited 0. It appeared in the `guard`
// job of ci.yml and of release.yml, the job that gates a release, under the
// name "Invariant / arch / guard tests (first, uncached)".
//
// A guard that read only the Makefile would have declared the tree clean while
// both copies were live. So the rule this test enforces is the general one: any
// `-run` name in any build script must exist. Both copies have since been
// deleted in favour of `make guard`, which is the single source of truth for
// which guards exist — and this test is what keeps it that way.
//
// # WHAT IT DOES NOT CHECK
//
// The pattern `^$` is skipped deliberately: it is how a target selects "no
// tests, benchmarks only", so matching nothing is the point. A `-run` pattern
// that is empty for any other reason is caught by TestBenchmarkSuiteIsNotEmpty
// and by the group counts in the guard above.
//
// It does not check that the *package scope* of the target matches where the
// test lives — a name that exists only in a package the target does not run
// would pass here. Every current target runs `./internal/...` or `./...`, so
// this cannot bite today; it is recorded rather than left to be discovered.
//
// # THE `$$` ESCAPE
//
// This test reads the Makefile as text, so it must undo Make's own escaping
// before it can compare anything. Make writes a literal `$` as `$$`, so `make
// bench`'s `-run '^$$'` reaches `go test` as `-run '^$'`. Comparing the raw
// source against the skip-list would therefore compare `^$$` to `^$`, miss,
// and report a deliberate no-op as a fictional test name.
//
// That is not hypothetical: the first version of this test did exactly that
// and failed on `make bench`. The unescaping below is what fixes it. The order
// matters — Make unescapes `$$` in the recipe text and does *not* rescan the
// result of a variable expansion, so `$$` is undone first and `$(...)` second.
// The unescaping is harmless in a workflow file, which has no `$$` escape.
func TestEveryRunNameExists(t *testing.T) {
	root := moduleRoot(t)

	// Every script in the repo that can pass a `-run` pattern: the Makefile, the
	// maintainer-only fragment it includes, and the workflow files.
	//
	// The fragment has to be read even though it is not published: it is where
	// the maintainer targets live now, several of them pass `-run`, and a
	// `-run` this guard cannot read is exactly the fictional name it exists to
	// catch. In the distribution the file is absent and there is nothing to
	// miss, because the targets that name those patterns went with it.
	sources := []string{"Makefile"}
	if _, ok := guardMaintainerPath(t, filepath.Join(root, "tools", "maintainer.mk")); ok {
		sources = append(sources, filepath.Join("tools", "maintainer.mk"))
	}
	workflowDir := filepath.Join(root, ".github", "workflows")
	entries, err := os.ReadDir(workflowDir)
	if err != nil {
		t.Fatalf("reading %s: %v", workflowDir, err)
	}
	for _, e := range entries {
		if e.IsDir() {
			continue
		}
		if n := e.Name(); strings.HasSuffix(n, ".yml") || strings.HasSuffix(n, ".yaml") {
			sources = append(sources, filepath.Join(".github", "workflows", n))
		}
	}
	if len(sources) < 2 {
		t.Fatalf("expected the Makefile and at least one workflow file, found %v.\n"+
			"This check would otherwise pass by reading one file.", sources)
	}

	raw, err := os.ReadFile(filepath.Join(root, "Makefile"))
	if err != nil {
		t.Fatalf("reading the Makefile: %v", err)
	}

	// Expand the GUARD_* variables first, so `-run '$(GUARD_INVARIANTS)'` is
	// read as the names it stands for rather than as a variable reference.
	vars := map[string]string{}
	for _, line := range strings.Split(string(raw), "\n") {
		trimmed := strings.TrimSpace(line)
		if !strings.HasPrefix(trimmed, "GUARD_") {
			continue
		}
		eq := strings.Index(trimmed, ":=")
		if eq < 0 {
			t.Fatalf("Makefile guard variable is not a := assignment: %q", trimmed)
		}
		name := strings.TrimSpace(trimmed[:eq])
		vars[name] = strings.TrimSpace(trimmed[eq+2:])
	}

	// Every Test function declared anywhere in the module, as before. The
	// script directories are all walked, not only the ones a target happens to
	// name, so the set this is checked against is the whole module.
	//
	// corpus-build is maintainer-only, so the distribution ships without it and
	// the walk covers whatever source directories this checkout has. A source
	// directory missing from a maintainer checkout stays fatal, and the
	// `defined` emptiness check below keeps an empty walk from reading as a
	// pass — see guardMaintainerPath.
	defined := map[string]bool{}
	for _, top := range []string{"internal", "cmd", "corpus-build"} {
		base := filepath.Join(root, top)
		if _, ok := guardMaintainerPath(t, base); !ok {
			continue
		}
		walkErr := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
				return nil
			}
			f, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || fn.Name == nil {
					continue
				}
				defined[fn.Name.Name] = true
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walking %s: %v", base, walkErr)
		}
	}
	if len(defined) == 0 {
		t.Fatal("no functions were found in the module at all; the walk is broken")
	}

	// Every `-run` argument in every build script, quoted or bare.
	runArg := regexp.MustCompile(`-run\s+(?:'([^']*)'|(\S+))`)
	// Comment lines are skipped: a `#` comment describing a target, or quoting
	// the old broken pattern as an example, must not be read as one.
	var checked, skipped int
	for _, rel := range sources {
		src, readErr := os.ReadFile(filepath.Join(root, rel))
		if readErr != nil {
			t.Fatalf("reading %s: %v", rel, readErr)
		}
		if len(src) == 0 {
			t.Fatalf("%s is empty; this check would silently skip it", rel)
		}
		for _, line := range strings.Split(string(src), "\n") {
			if strings.HasPrefix(strings.TrimSpace(line), "#") {
				continue
			}
			for _, m := range runArg.FindAllStringSubmatch(line, -1) {
				arg := m[1]
				if arg == "" {
					arg = m[2]
				}
				// Undo Make's `$$` escape first: `-run '^$$'` is `-run '^$'` by
				// the time `go test` sees it. See the note above on ordering.
				arg = strings.ReplaceAll(arg, "$$", "$")
				for name, value := range vars {
					arg = strings.ReplaceAll(arg, "$("+name+")", value)
				}
				if strings.Contains(arg, "$(") {
					t.Errorf("%s passes a -run pattern that still holds an "+
						"unexpanded Make variable: %q.\nThis check cannot verify "+
						"a name it cannot read, and silently skipping it is how a "+
						"fictional name survives.", rel, arg)
					continue
				}
				// A GitHub Actions expression. The guard cannot know what it
				// evaluates to, and skipping it quietly is the whole defect.
				if strings.Contains(arg, "${{") {
					t.Errorf("%s passes a -run pattern containing a workflow "+
						"expression: %q.\nThis check cannot verify a name it "+
						"cannot read.", rel, arg)
					continue
				}
				for _, name := range strings.Split(arg, "|") {
					name = strings.TrimSpace(name)
					if name == "" || name == "^$" {
						skipped++
						continue
					}
					checked++
					if !defined[name] {
						t.Errorf("%s passes -run %q, but no test with that "+
							"name exists anywhere in the module.\n"+
							"`go test` exits 0 when a -run name matches nothing, so "+
							"whatever passes it currently reports success while "+
							"running nothing. Either write the test or remove the "+
							"name.", rel, name)
					}
				}
			}
		}
	}

	if checked == 0 {
		t.Fatal("no -run test names were found in any build script at all; " +
			"this check is asserting nothing")
	}
	t.Logf("%d -run name(s) verified against the module across %d script(s), "+
		"%d intentional no-op pattern(s) skipped", checked, len(sources), skipped)
}

// TestBenchmarkSuiteIsNotEmpty asserts that `make bench` has something to run.
//
// # WHY A BENCHMARK TARGET NEEDS A GUARD
//
// `make bench` runs `go test ./... -run '^$' -bench . -benchmem`. The `-run '^$'`
// matches nothing, which is correct — benchmarks are selected by `-bench`. But
// `-bench .` with no Benchmark function in the module is not an error: the
// package reports `ok` and exits 0.
//
// So an empty benchmark suite and a working one are indistinguishable from the
// exit status, which is the same defect as a `-run` pattern naming a test that
// does not exist and a `-X` stamp naming a symbol that does not exist. This
// repository has now found that shape four times, in four
// different mechanisms. The mechanism differs; the failure is identical: a
// command succeeds without doing anything, and the success is the whole signal.
//
// The assertion is deliberately weak — at least one Benchmark exists somewhere
// — because the strong version ("the benchmark measures something useful") is
// not checkable and would be a comment pretending to be a test. What this
// catches is the suite being emptied, which is how it goes vacuous.
func TestBenchmarkSuiteIsNotEmpty(t *testing.T) {
	root := moduleRoot(t)

	var found []string
	for _, top := range []string{"internal", "cmd"} {
		base := filepath.Join(root, top)
		walkErr := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			f, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, 0)
			if parseErr != nil {
				return parseErr
			}
			rel, _ := filepath.Rel(root, path)
			for _, decl := range f.Decls {
				fn, ok := decl.(*ast.FuncDecl)
				if !ok || fn.Recv != nil || fn.Name == nil {
					continue
				}
				if strings.HasPrefix(fn.Name.Name, "Benchmark") {
					found = append(found, fn.Name.Name+" ("+filepath.ToSlash(rel)+")")
				}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("walking %s: %v", base, walkErr)
		}
	}

	sort.Strings(found)
	if len(found) == 0 {
		t.Fatal("the module declares no Benchmark function, so `make bench` " +
			"reports success while measuring nothing.\n" +
			"`go test -bench .` with no benchmarks is not an error, so the exit " +
			"status cannot tell the two cases apart.")
	}
	for _, b := range found {
		t.Logf("%s", b)
	}
}

// TestEveryStampedSymbolExists is the guard for the build metadata.
//
// # THE DEFECT THIS PREVENTS
//
// `go build -ldflags "-X <pkg>.<Name>=<value>"` sets a package-level string
// variable at link time. If <pkg>.<Name> does not exist, the linker does not
// complain — it ignores the flag, silently, and exits 0. A build config can
// therefore look like it stamps the version while stamping nothing, and every
// observable signal stays green: the build succeeds, the tests pass, the binary
// runs.
//
// That is exactly what had happened here. The Makefile, .goreleaser.yml and both
// builds in the release workflow all stamped `main.version`, `main.commit` and
// `main.date`, but those variables are declared in internal/cli, not in package
// main. Every binary ever built — local, goreleaser and CI — reported
// 0.0.0-dev / unknown / local, and nothing anywhere said so. The verdict's
// `build_provenance` field, which exists so a user can attribute a verdict to a
// build, said "local" for a release.
//
// This test extracts every `-X` target from the build configuration, resolves
// the Makefile's own variables, and asserts the named package exists in the
// module and declares a string variable of that name. A stamp that names
// nothing now fails loudly, and so does a config that has stopped containing any
// stamp at all.
func TestEveryStampedSymbolExists(t *testing.T) {
	root := moduleRoot(t)

	configs := []string{
		"Makefile",
		".goreleaser.yml",
		filepath.Join(".github", "workflows", "release.yml"),
	}

	// `-X importpath.Name=value`. The value may be `$(VAR)`, `${ver}` or
	// `{{.Version}}`, so the match stops at the first `=`.
	stampRe := regexp.MustCompile(`-X\s+([A-Za-z0-9_./\-]+)\.([A-Za-z0-9_]+)=`)

	total, read := 0, 0
	for _, rel := range configs {
		// release.yml is maintainer-only: it runs the corpus pre-flight, which
		// needs tools/ and a signed bundle, so the distribution ships without
		// it. The Makefile and .goreleaser.yml ship and stay required.
		path, ok := guardMaintainerPath(t, filepath.Join(root, rel))
		if !ok {
			continue
		}
		read++
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Errorf("reading %s: %v", rel, err)
			continue
		}
		text := stripCommentLines(string(raw))
		if rel == "Makefile" {
			text = expandMakeVars(text)
		}

		found := stampRe.FindAllStringSubmatch(text, -1)
		if len(found) == 0 {
			// Silence is not success. A config that stamps nothing is either a
			// file this test can no longer parse, or a build that has lost its
			// metadata. Both make this guard pass while checking nothing.
			t.Errorf("%s contains no link-time stamp this test can read.\n"+
				"Either the stamp was removed, or this parser no longer "+
				"understands the file. Both make this guard certify nothing.", rel)
			continue
		}

		for _, m := range found {
			pkg, name := m[1], m[2]
			total++

			dir, ok := moduleDirForStamp(root, pkg)
			if !ok {
				t.Errorf("%s stamps %s.%s, but %q names no package in this module.\n"+
					"The linker ignores -X for an unknown symbol and still reports "+
					"success, so this stamp currently does nothing at all.",
					rel, pkg, name, pkg)
				continue
			}
			if problem := stampedSymbolProblem(t, dir, name); problem != "" {
				t.Errorf("%s stamps %s.%s, but %s.\n"+
					"The linker ignores -X for a symbol it cannot set and still "+
					"reports success, so this stamp currently does nothing at all.",
					rel, pkg, name, problem)
			}
		}
	}

	if total == 0 {
		t.Fatal("no link-time stamps were found in any build config; this guard " +
			"is checking nothing")
	}
	t.Logf("%d link-time stamps verified across %d of %d build configs "+
		"(the rest are maintainer-only and not in this distribution)",
		total, read, len(configs))
}

// stripCommentLines drops whole-line comments, so that a `-X` mentioned in a
// comment explaining a past bug is not mistaken for a stamp. Both the Makefile
// and the YAML files use `#`.
func stripCommentLines(text string) string {
	var b strings.Builder
	for _, line := range strings.Split(text, "\n") {
		if strings.HasPrefix(strings.TrimSpace(line), "#") {
			continue
		}
		b.WriteString(line)
		b.WriteByte('\n')
	}
	return b.String()
}

// expandMakeVars substitutes `$(NAME)` for the one-line `NAME := value` and
// `NAME ?= value` assignments in a Makefile, so that `-X $(CLI_PKG).Version=…`
// can be read as an actual import path.
//
// It is not a make implementation. It resolves the handful of simple
// assignments this repository uses, and a variable it cannot resolve is left in
// place — which the caller then reports as a stamp naming no package, rather
// than quietly ignoring.
func expandMakeVars(text string) string {
	vars := map[string]string{}
	for _, line := range strings.Split(text, "\n") {
		trimmed := strings.TrimSpace(line)
		var name, value string
		switch {
		case strings.Contains(trimmed, ":="):
			i := strings.Index(trimmed, ":=")
			name, value = trimmed[:i], trimmed[i+2:]
		case strings.Contains(trimmed, "?="):
			i := strings.Index(trimmed, "?=")
			name, value = trimmed[:i], trimmed[i+2:]
		default:
			continue
		}
		name, value = strings.TrimSpace(name), strings.TrimSpace(value)
		// A recipe line is not an assignment; neither is a target.
		if name == "" || strings.ContainsAny(name, " \t#") {
			continue
		}
		vars[name] = value
	}
	for pass := 0; pass < 8; pass++ {
		before := text
		for name, value := range vars {
			text = strings.ReplaceAll(text, "$("+name+")", value)
		}
		if text == before {
			break
		}
	}
	return text
}

// moduleDirForStamp maps the package named by a `-X` flag to its directory in
// the module. `main` is the one alias the linker accepts that is not an import
// path, and in this repository it names cmd/clearance.
func moduleDirForStamp(root, pkg string) (string, bool) {
	if pkg == "main" {
		dir := filepath.Join(root, "cmd", "clearance")
		if _, err := os.Stat(dir); err == nil {
			return dir, true
		}
		return "", false
	}
	const modulePath = "github.com/clearance-dev/clearance/"
	if !strings.HasPrefix(pkg, modulePath) {
		return "", false
	}
	dir := filepath.Join(root,
		filepath.FromSlash(strings.TrimPrefix(pkg, modulePath)))
	if _, err := os.Stat(dir); err != nil {
		return "", false
	}
	return dir, true
}

// stampedSymbolProblem returns "" when the package in dir declares a
// package-level string variable called name that the linker's -X flag can
// actually set, or an explanation of why it cannot.
//
// # WHY "DECLARED AS A STRING" IS NOT THE QUESTION
//
// `-X` sets a string variable only when it is uninitialised or initialised to a
// **constant string expression**. A variable initialised by a function call is
// declared, is a string, and is invisible to `-X`: the linker ignores the flag,
// prints nothing, and exits 0. So the question this function answers is not
// "does the symbol exist" but "can the linker write to it".
//
// That distinction is not theoretical. Three separate stamps in this repository
// were dead for exactly this reason — `main.version` (wrong package),
// `main.commit`, `main.date` — and a fourth, the corpus public key, was
// initialised by `strings.Repeat`. The released binary would have carried the
// all-zero key and refused every signed corpus, while every build reported
// success. A check that only asked "does the symbol exist" would have passed all
// four.
//
// Test files are skipped: the linker stamps the compiled package, and a variable
// that exists only in a _test.go file is not in it.
func stampedSymbolProblem(t *testing.T, dir, name string) string {
	t.Helper()

	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") ||
			strings.HasSuffix(e.Name(), "_test.go") {
			continue
		}
		f, parseErr := parser.ParseFile(token.NewFileSet(),
			filepath.Join(dir, e.Name()), nil, 0)
		if parseErr != nil {
			t.Fatalf("parsing %s: %v", e.Name(), parseErr)
		}
		consts := fileConstStrings(f)

		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.VAR {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				for i, ident := range vs.Names {
					if ident.Name != name {
						continue
					}
					// A declared type that is not `string` is a symbol -X can
					// never set, whatever its initialiser looks like.
					if vs.Type != nil {
						id, isIdent := vs.Type.(*ast.Ident)
						if !isIdent || id.Name != "string" {
							return fmt.Sprintf("%s declares %q with a non-string "+
								"type", e.Name(), name)
						}
					}
					if len(vs.Values) == 0 {
						return "" // `var Name string` — -X can set it
					}
					if i >= len(vs.Values) {
						return fmt.Sprintf("%s declares %q in a multi-name spec "+
							"this check cannot read", e.Name(), name)
					}
					if !isConstantStringExpr(vs.Values[i], consts) {
						return fmt.Sprintf("%s initialises %q with an expression the "+
							"linker cannot set (only a constant string expression "+
							"is stampable)", e.Name(), name)
					}
					return ""
				}
			}
		}
	}
	return fmt.Sprintf("no package-level string variable %q is declared in %s",
		name, filepath.ToSlash(dir))
}

// isConstantStringExpr reports whether e is an expression `-X` can assign to a
// variable: a string literal, a concatenation of string literals, or a
// reference to a const declared in the same file.
func isConstantStringExpr(e ast.Expr, consts map[string]ast.Expr) bool {
	switch v := e.(type) {
	case *ast.BasicLit:
		return v.Kind == token.STRING
	case *ast.BinaryExpr:
		// Concatenating constants yields a constant.
		return v.Op == token.ADD &&
			isConstantStringExpr(v.X, consts) &&
			isConstantStringExpr(v.Y, consts)
	case *ast.ParenExpr:
		return isConstantStringExpr(v.X, consts)
	case *ast.Ident:
		// A named constant is still a constant, but only if it resolves.
		if target, ok := consts[v.Name]; ok {
			return isConstantStringExpr(target, consts)
		}
		return false
	default:
		// A call, a selector, a conversion: none of them are constants.
		return false
	}
}

// fileConstStrings maps every file-level const to its value expression, so that
// `var Key = defaultKey` can be recognised as stampable when defaultKey is a
// constant.
func fileConstStrings(f *ast.File) map[string]ast.Expr {
	out := map[string]ast.Expr{}
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.CONST {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Values) != len(vs.Names) {
				continue
			}
			for i, ident := range vs.Names {
				out[ident.Name] = vs.Values[i]
			}
		}
	}
	return out
}

// constStringValue returns the value of a constant string expression, and false
// if e is not one.
//
// This exists because `isConstantStringExpr` answers "can the linker stamp
// this?" but not "what would it stamp?" — and a test that pins the *value* of a
// stampable variable has to evaluate the same set of shapes the linker accepts.
// The alternative is what this file originally did: assert `*ast.BasicLit` and
// then contradict the check above it, which explicitly permits a concatenation
// of literals. A test that fails on a shape it just declared valid is worse than
// no test, because the failure looks like a product defect.
func constStringValue(e ast.Expr, consts map[string]ast.Expr) (string, bool) {
	switch v := e.(type) {
	case *ast.BasicLit:
		if v.Kind != token.STRING {
			return "", false
		}
		s, err := strconv.Unquote(v.Value)
		if err != nil {
			return "", false
		}
		return s, true
	case *ast.BinaryExpr:
		if v.Op != token.ADD {
			return "", false
		}
		left, ok := constStringValue(v.X, consts)
		if !ok {
			return "", false
		}
		right, ok := constStringValue(v.Y, consts)
		if !ok {
			return "", false
		}
		return left + right, true
	case *ast.ParenExpr:
		return constStringValue(v.X, consts)
	case *ast.Ident:
		target, ok := consts[v.Name]
		if !ok {
			return "", false
		}
		// Bounded by the map: a const that refers to itself is not valid Go,
		// and the parser would have rejected it before we got here.
		return constStringValue(target, consts)
	default:
		return "", false
	}
}

// TestCorpusPublicKeyIsStampable pins the one property that makes the embedded
// corpus key replaceable by a release build.
//
// # THE DEFECT THIS PREVENTS
//
// `devPublicKeyHex` is the corpus public key compiled into every binary. A
// release replaces it with `-X`. It was declared as
//
//	var devPublicKeyHex = strings.Repeat("0", ed25519.PublicKeySize*2)
//
// which is a function call, and `-X` only sets a variable initialised to a
// constant string expression. So the flag was ignored, silently, and the comment
// above the declaration confidently said the opposite.
//
// The consequence is the worst kind: a release carrying the all-zero key refuses
// every correctly signed corpus with E-INT-005, reports itself as a successful
// build, and gives the maintainer no signal at all that the corpus pipeline is
// broken. "The tool cannot read the data it exists to interpret" is not a
// failure mode to discover in production.
//
// This test is deliberately narrow. It asserts the property for the one variable
// that has no committed build config stamping it, and therefore no other test
// would notice.
func TestCorpusPublicKeyIsStampable(t *testing.T) {
	root := moduleRoot(t)
	dir := filepath.Join(root, "internal", "corpus")

	const name = "devPublicKeyHex"
	if problem := stampedSymbolProblem(t, dir, name); problem != "" {
		t.Fatalf("%s is not stampable by -ldflags: %s.\n"+
			"A release build replaces this variable with the real corpus public "+
			"key. If the linker cannot set it, the released binary carries the "+
			"all-zero key and refuses every signed corpus with E-INT-005 — while "+
			"the build reports success.\n"+
			"Declare it as a constant string literal (or a concatenation of them).",
			name, problem)
	}

	// The value itself must be a well-formed 32-byte key, because PublicKey
	// hex-decodes it and refuses anything else. A literal of the wrong length
	// would make every build fail closed, which is the right direction but the
	// wrong reason.
	raw, err := os.ReadFile(filepath.Join(dir, "verify.go"))
	if err != nil {
		t.Fatalf("reading verify.go: %v", err)
	}
	f, err := parser.ParseFile(token.NewFileSet(),
		filepath.Join(dir, "verify.go"), raw, 0)
	if err != nil {
		t.Fatalf("parsing verify.go: %v", err)
	}
	consts := fileConstStrings(f)
	for _, decl := range f.Decls {
		gen, ok := decl.(*ast.GenDecl)
		if !ok || gen.Tok != token.VAR {
			continue
		}
		for _, spec := range gen.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok {
				continue
			}
			for i, ident := range vs.Names {
				if ident.Name != name || i >= len(vs.Values) {
					continue
				}
				value, ok := constStringValue(vs.Values[i], consts)
				if !ok {
					t.Fatalf("%s is not a constant string expression, so this "+
						"test cannot measure it (the check above should have "+
						"caught this first)", name)
				}
				if want := ed25519.PublicKeySize * 2; len(value) != want {
					t.Fatalf("%s is %d characters; a hex-encoded Ed25519 public "+
						"key is %d. PublicKey would refuse it with E-INT-005, so "+
						"every corpus verification would fail closed.",
						name, len(value), want)
				}
				// All-zero is the deliberate "this build carries no corpus key"
				// sentinel. Anything else in a committed source tree would mean
				// a real key had been checked in, which is the one mistake this
				// file exists to make impossible.
				if strings.Trim(value, "0") != "" {
					t.Fatalf("%s is not the all-zero placeholder. A real corpus "+
						"key must never be committed to the source tree; it is "+
						"supplied at release time with -ldflags.", name)
				}
			}
		}
	}
}

// TestEvaluateRefusesAFindingItCannotCite asserts the INV-1 gate is actually on
// the path Evaluate takes.
//
// # WHY THIS IS SEPARATE FROM THE UNIT TEST
//
// TestResolveCitationRefusesAnUnregisteredCitation (internal/policy) proves the
// mechanism refuses. This proves the mechanism is CALLED. A gate that exists but
// is never reached is a gate in name only, and the difference is invisible from
// the outside — which is precisely how the original defect survived a green
// test suite.
//
// # HOW AN UNRESOLVABLE CITATION IS CONSTRUCTED
//
// The loader registers every citation it reads, so a corpus produced by
// corpus.Load always has a consistent index. That is why nothing in the happy
// path could trigger the defect, and why no test could observe it. The state it
// was meant to catch is still reachable — a corpus whose index and entries
// disagree — and it is reproduced here by replacing the index after a normal
// load. Every entry stays valid; the corpus simply no longer knows the clause
// its obligation cites.
//
// This test lives in the guard suite rather than in internal/policy because it
// needs a temporary directory, and internal/policy is L3: the architecture
// guard forbids `os` there, test files included.
func TestEvaluateRefusesAFindingItCannotCite(t *testing.T) {
	c := guardCitationGateCorpus(t)

	// The control: with the loader's own index, the same corpus and graph
	// produce a finding. Without this, the assertion below would pass against a
	// corpus that simply produced nothing.
	okEval, err := policy.Evaluate(guardCitationGateGraph(), c, guardCitationGateIntent(),
		policy.Options{Today: guardToday})
	if err != nil {
		t.Fatalf("the control run failed: %v", err)
	}
	if len(okEval.Findings) == 0 {
		t.Fatal("the control run produced no findings, so the assertion below " +
			"would pass for a reason unrelated to citations")
	}

	// Break the index and nothing else.
	broken := *c
	broken.Citations = cite.NewIndex()

	_, err = policy.Evaluate(guardCitationGateGraph(), &broken, guardCitationGateIntent(),
		policy.Options{Today: guardToday})
	if err == nil {
		t.Fatal("Evaluate produced findings from a corpus whose citation is not in " +
			"the index.\nEvery finding's citation must resolve against the corpus " +
			"that produced it (INV-1), and Evaluate holds the index — so this is " +
			"the layer where an unresolvable citation must stop.")
	}
	assertCode(t, err, cerr.EPolicy002)
}

// guardCitationGateLicenceYAML is a minimal valid licence entry whose single
// obligation fires whenever the project is commercial. The predicate is chosen
// so that the finding is certain to exist, giving the gate something to refuse.
const guardCitationGateLicenceYAML = `id: licence.synthetic
spdx_id: Synthetic-1.0
name: Synthetic Licence 1.0
family: permissive
osi_approved: false
fsf_libre: false
permissiveness: 3

obligations:
  - id: synthetic.attribution
    kind: ATTRIBUTION
    severity: CONDITION
    when:
      op: "=="
      field: use.commercial
      value: true
    message: >
      A synthetic obligation whose text is comfortably longer than the ten
      character minimum the corpus validator enforces.
    citation:
      url: https://example.test/synthetic
      section: "Clause 1"
    confidence: HIGH

traps: []

citation:
  url: https://example.test/synthetic
  section: "Synthetic Licence"
confidence: HIGH
last_verified: "2026-09-20"
`

// guardCitationGateCorpus loads a one-entry corpus from a temporary tree. It
// goes through corpus.Load rather than building a Corpus by hand because the
// Corpus's indexes are unexported, and because the point is to start from a
// corpus the loader considers valid.
func guardCitationGateCorpus(t *testing.T) *corpus.Corpus {
	t.Helper()
	dir := guardWriteTree(t, map[string]string{
		"licences/synthetic.yaml": guardCitationGateLicenceYAML,
	})
	c, err := corpus.Load(corpus.LoadOptions{Dir: dir, Today: guardToday})
	if err != nil {
		t.Fatalf("loading the citation-gate corpus: %v", err)
	}
	if got := c.Stats().Licences; got != 1 {
		t.Fatalf("citation-gate corpus holds %d licences, want 1", got)
	}
	return c
}

// guardCitationGateGraph is a one-dependency graph whose licence the
// citation-gate corpus carries.
func guardCitationGateGraph() *graph.Graph {
	return &graph.Graph{
		Root: ".",
		Dependencies: []graph.Dependency{{
			ID:        "npm:synthetic-sdk@1.0.0",
			Kind:      graph.KindPackage,
			Name:      "synthetic-sdk",
			Version:   "1.0.0",
			Ecosystem: "npm",
			Direct:    true,
			Licence: graph.LicenceRef{
				SPDX:       "Synthetic-1.0",
				Raw:        "Synthetic-1.0",
				Source:     "lockfile",
				Resolved:   true,
				Confidence: "HIGH",
			},
			Evidence: []graph.Evidence{{
				Path:      "package-lock.json",
				LineStart: 8,
				LineEnd:   11,
			}},
		}},
	}
}

// guardCitationGateIntent declares the one fact the obligation's predicate
// reads.
func guardCitationGateIntent() *config.Intent {
	in := &config.Intent{SchemaVersion: config.SchemaVersion}
	in.Project.Name = "citation-gate"
	in.Use.Commercial = true
	in.Use.LicenceModel = config.ClosedSource
	return in
}

// assertCode asserts that err carries the given cerr code.
//
// It asserts the CODE and not the message, because the message is a rendering
// concern and the code is the contract. A test that matched on message text
// would fail every time someone improved a sentence.
func assertCode(t *testing.T, err error, want cerr.Code) {
	t.Helper()
	if err == nil {
		t.Fatalf("expected %s, got nil", want)
	}
	e, ok := cerr.As(err)
	if !ok {
		t.Fatalf("expected %s, got an untyped error: %v", want, err)
	}
	if e.Code() != want {
		t.Fatalf("got %s (%v), want %s", e.Code(), err, want)
	}
}

// ── the upstream detector's credibility ──────────────────────────────────────

// noticeProgramName pulls the program name out of a "Detected a third-party …"
// notice.
//
// It parses the rendered sentence rather than reaching into the graph, because
// the rendered sentence is the contract: it is what the user reads, and the
// claim this guard exists to police is made in that sentence and nowhere else.
func noticeProgramName(msg string) (string, bool) {
	open := strings.IndexByte(msg, '\'')
	if open < 0 {
		return "", false
	}
	rest := msg[open+1:]
	shut := strings.IndexByte(rest, '\'')
	if shut < 0 {
		return "", false
	}
	return rest[:shut], true
}

// TestScannerNeverNamesANonProgram is the upstream detector's credibility
// invariant.
//
// # WHAT IT PINS
//
// A Notice that names a program is a factual claim: "your project invokes X".
// When X is `.PHONY:`, or `GUARD_CORPUS`, or `GO)`, or `o`, the claim is false.
// What that costs is blunt —
// "false positives are what kill a scanner's credibility" — and run over this
// repository's own tree the detector made 84 such claims, which is why
// `make dogfood` printed 84 lines of programs that do not exist.
//
// # WHY IT IS A GUARD AND NOT A UNIT TEST
//
// upstream_test.go pins the reader's grammar on inputs chosen by hand. This
// runs the whole pipeline — reader, ubiquitous-tool filter, platform matching,
// Notice construction — over a tree built from the shapes that broke it, and
// asserts on what a user would actually see. It is the layer that would have
// caught the bug from the outside.
//
// # THE ASSERTION IS A SET, NOT AN ABSENCE
//
// Asserting "no implausible name appears" would be satisfied by a reader that
// found nothing at all, which is the failure direction this product cares about
// most — a silent miss. So the expected set contains the five real programs the
// tree invokes as well as excluding the debris. Both halves have to hold.
func TestScannerNeverNamesANonProgram(t *testing.T) {
	c := guardLoadCorpus(t)

	dir := guardWriteTree(t, map[string]string{
		"clearance.config.yml": `schema_version: 1

project:
  name: detector-credibility

use:
  commercial: false
  licence_model: open-source
  modified: false
  network_exposed: false
  distributed: false
  saas: false
`,
		"go.mod": "module example.test/detector\n\ngo 1.23\n",

		// Every non-recipe line here is Makefile syntax and not shell, and the
		// `@` prefix, the `\` continuation and the `|` in the guard list are
		// each a shape that produced a program that does not exist.
		"Makefile": "# A Makefile is not a shell script.\n" +
			"GO ?= go\n" +
			"GUARD := TestAlpha|TestBeta\n" +
			".PHONY: build test\n" +
			".DEFAULT_GOAL := build\n" +
			"\n" +
			"build:\n" +
			"\t@acme-encode --in a.wav \\\n" +
			"\t\t--out b.mp3\n" +
			"\t$(GO) build ./...\n",

		// A continued command in a plain shell script: `-o out.mp4` is an
		// argument and used to be reported as a program called `o`.
		"scripts/run.sh": "acme-render -i in.mp4 \\\n  -o out.mp4\n",

		// A CI `run:` block: the `uses:` and `with:` keys are not commands, and
		// the continued signing step used to yield `output-signature` and
		// `dist/x.sig`.
		".github/workflows/ci.yml": "jobs:\n" +
			"  build:\n" +
			"    steps:\n" +
			"      - uses: actions/checkout@v4\n" +
			"        with:\n" +
			"          fetch-depth: 0\n" +
			"      - run: |\n" +
			"          acme-sign --yes \\\n" +
			"            --output-signature dist/x.sig \\\n" +
			"            dist/x\n",

		// The registry and namespace are the image's identity, so `tool` and
		// `base` must not appear in place of `ghcr.io/acme/base`.
		"Dockerfile": "FROM ghcr.io/acme/base:1.0\n" +
			"RUN acme-package -o /out \\\n" +
			"    ./src\n",
	})

	_, diag, err := guardRunDetailed(t, dir, c, policy.Options{})
	if err != nil {
		t.Fatalf("pipeline on the detector-credibility tree: %v", err)
	}

	var named []string
	for _, n := range diag.Notices {
		if n.Code != string(cerr.ECorpus004) ||
			!strings.HasPrefix(n.Message, "Detected a third-party ") {
			continue
		}
		name, ok := noticeProgramName(n.Message)
		if !ok {
			t.Errorf("a detector notice names no program, so its claim cannot be "+
				"checked: %q", n.Message)
			continue
		}
		named = append(named, name)
	}

	assertSameSet(t, "programs named by the detector", named, []string{
		"acme-encode",
		"acme-package",
		"acme-render",
		"acme-sign",
		"ghcr.io/acme/base",
	})
}

// TestEveryGoTestInvocationIsUncached asserts that every `go test` a build script
// runs carries -count=1.
//
// # WHY THIS IS A GUARD AND NOT A STYLE RULE
//
// `go test` replays a cached PASS when the test binary and the cacheable flags
// are unchanged, so a build script can report a green suite without executing a
// test — and nothing in the output distinguishes that green from a real one.
//
// This repository had two. `make fixtures` was one; the other was `make test`,
// the target whose entire job is to run the suite, and the same target the
// project's own acceptance rule asks to be green "with -count=1 (and -race)".
// Neither carried it. CI's test job had the same exposure, and worse: it
// restores the Go build cache, so the cached PASS is the *expected* case there.
//
// They were fixed by hand, one at a time, which is how a class of defect
// survives: two instances found and corrected, the rest never looked at. The
// sweep that followed found two more (`arch`, `corpus-verify`). This test closes
// the class, and it is the same shape as every other ratchet in this suite.
//
// Comments are skipped, so a build script may still *discuss* `go test` — the
// Makefile and both workflows do, in the notes explaining why a hand-written
// name list was removed — without tripping this.
func TestEveryGoTestInvocationIsUncached(t *testing.T) {
	root := moduleRoot(t)

	scripts := []string{filepath.Join(root, "Makefile")}
	// The maintainer-only targets live in an included fragment, so the `go test`
	// invocations they carry are read here too. Without this, moving a target
	// out of the Makefile would quietly take it out of this guard's reach —
	// which is the defect this test exists to close, reintroduced by a
	// refactor. In the distribution the fragment is absent and the targets that
	// carried those invocations went with it.
	if p, ok := guardMaintainerPath(t, filepath.Join(root, "tools", "maintainer.mk")); ok {
		scripts = append(scripts, p)
	}
	workflows, err := filepath.Glob(filepath.Join(root, ".github", "workflows", "*.yml"))
	if err != nil {
		t.Fatalf("globbing workflows: %v", err)
	}
	if len(workflows) == 0 {
		t.Fatal("no workflow files matched. The workflows are half of what this " +
			"guard polices; passing over an empty set would be a silent gap.")
	}
	scripts = append(scripts, workflows...)

	var checked int
	for _, path := range scripts {
		raw, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("reading %s: %v", path, err)
		}
		rel, _ := filepath.Rel(root, path)
		for i, line := range strings.Split(string(raw), "\n") {
			trimmed := strings.TrimSpace(line)
			// Strip a trailing comment before looking. In a Makefile and in a
			// YAML file alike, `#` starts one — and the target header
			//   test: guard arch ## go test ./... with -race + coverage
			// is documentation, not a command. The first version of this guard
			// reported that help string as an uncached-less invocation. A guard
			// that cries wolf on a help string is one people learn to ignore.
			if h := strings.Index(trimmed, "#"); h >= 0 {
				trimmed = strings.TrimSpace(trimmed[:h])
			}
			// The Makefile says `$(GO) test`; the workflows say `go test`.
			// Matching only the second found 2 invocations out of 10 — the same
			// too-narrow-tree defect this repository keeps re-finding, this time
			// inside the guard written to close it.
			if !strings.Contains(trimmed, "go test") &&
				!strings.Contains(trimmed, "$(GO) test") {
				continue
			}
			checked++
			if !strings.Contains(trimmed, "-count=1") {
				t.Errorf("%s:%d runs `go test` without -count=1:\n    %s\n"+
					"Go replays a cached PASS when the test binary and the "+
					"cacheable flags are unchanged, so this invocation can report "+
					"green without executing a test, and nothing distinguishes "+
					"that green from a real one. Add -count=1.",
					filepath.ToSlash(rel), i+1, trimmed)
			}
		}
	}
	if checked == 0 {
		t.Fatal("no `go test` invocations were found in any build script; the " +
			"scan is broken and this guard is checking nothing")
	}
	t.Logf("%d go test invocation(s) across %d build script(s), all uncached",
		checked, len(scripts))
}
