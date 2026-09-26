// Corpus-integrity guards: the fixtures, and the predicates that decide what
// they mean.
//
// # WHY THESE TWO ARE IN A FILE OF THEIR OWN
//
// Everything in guard_invariants_test.go and guard_security_test.go asks "does
// the engine behave correctly?" These two ask a different question: "is the
// data the engine reads sound?" Both matter, and they fail for different
// reasons — an engine bug is a code review, a corpus bug is an edit to a YAML
// file. Keeping them apart means a red build says which of the two to open.
//
// # WHY THEY ARE NAMED IN THE MAKEFILE
//
// `make fixtures` and `make corpus-verify` used to name six tests that did not
// exist. `go test -run <name>` exits 0 when the name matches nothing, so both
// targets reported success while running almost nothing — the same defect
// LOGS.md §5.15 documents for `make guard`. The two tests below are two of the
// six, written. The other four are recorded in §5.17.
//
// TestNoGuardIsLeftOutOfTheGate asserts that every Test function in a
// guard_*_test.go file is reachable from a GUARD_* variable, so the pairing
// between this file and the Makefile is enforced rather than remembered.
package clearance_test

import (
	"bytes"
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
	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/expr"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/obligations"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/safeyaml"
	"github.com/clearance-dev/clearance/internal/scanner"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// ── the fixture expectation ──────────────────────────────────────────────────

// fixtureFinding is one finding a fixture must produce, identified by the
// three fields that are stable across runs.
//
// NOT by Finding.ID: that is a content hash, so it changes whenever a message
// or a citation is reworded, and a fixture that pinned it would go red on an
// edit that changed no behaviour. (dependency, kind, severity) is what a
// reviewer actually wants to read in a failure, and it is stable.
//
// `severity` is the *effective* severity — the band the finding landed in after
// the confidence gate — not the severity the corpus declared. See
// fixtureFindings for why that distinction decides whether this harness asserts
// anything about INV-2.
type fixtureFinding struct {
	Dependency string `yaml:"dependency"`
	Kind       string `yaml:"kind"`
	Severity   string `yaml:"severity"`
}

// fixtureUndetermined is one thing the corpus could not classify.
type fixtureUndetermined struct {
	ID     string `yaml:"id"`
	Reason string `yaml:"reason"`
}

// fixtureExpectation is the content of fixtures/<name>/expected.yml.
type fixtureExpectation struct {
	Verdict string `yaml:"verdict"`

	// Why is required. See readFixtureExpectation.
	Why string `yaml:"why"`

	Findings     []fixtureFinding      `yaml:"findings"`
	Undetermined []fixtureUndetermined `yaml:"undetermined"`

	// Warnings lists the error codes the scan must raise, sorted.
	//
	// Optional, and most fixtures leave it empty. It exists for the cases where
	// the honest output is a warning rather than a finding — E-SCAN-021, a
	// spawn whose command name is not a literal, being the one that made it
	// necessary. Asserting "no findings" without also asserting "and it said
	// why" would let the tool fall silent about a spawn it could not identify,
	// which is a false pass.
	Warnings []string `yaml:"warnings"`

	// Notices lists the error codes the evaluation must raise, sorted.
	//
	// The same idea one layer up. A detected platform the corpus has no terms
	// for is a Notice and not a finding, because INV-1 leaves a finding with
	// nothing to cite — so a fixture for that case has to assert the Notice or
	// it asserts nothing at all.
	Notices []string `yaml:"notices"`
}

// readFixtureExpectation loads and validates fixtures/<name>/expected.yml.
//
// Both a missing file and a missing `why` are fatal, and both are deliberate.
// A fixture with no expectation cannot fail, so it certifies nothing while
// looking like a test; and an expectation with no stated reason is a recording
// of current behaviour, which cannot tell a future reader whether a red build
// means the code regressed or the expectation was simply wrong.
func readFixtureExpectation(t *testing.T, dir string) fixtureExpectation {
	t.Helper()

	path := filepath.Join(dir, "expected.yml")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading %s: %v\n"+
			"Every fixture must state the verdict it produces. A fixture with no "+
			"expectation cannot fail, so it certifies nothing.", path, err)
	}

	var exp fixtureExpectation
	if err := safeyaml.Unmarshal(raw, &exp, safeyaml.DefaultLimits()); err != nil {
		t.Fatalf("parsing %s: %v", path, err)
	}
	if strings.TrimSpace(exp.Verdict) == "" {
		t.Fatalf("%s declares no verdict", path)
	}
	if strings.TrimSpace(exp.Why) == "" {
		t.Fatalf("%s declares no `why`.\n"+
			"An expectation without a stated reason is a snapshot of what the code "+
			"happened to print. A snapshot cannot tell a reader whether a failure "+
			"means the code regressed or the expectation was wrong, so it is not a "+
			"test — it is a second copy of the output.", path)
	}
	return exp
}

// fixtureFindings renders every finding in a verdict as a sortable string.
//
// # THE SEVERITY HERE IS THE EFFECTIVE ONE, NOT THE DECLARED ONE
//
// Fold puts each finding into exactly one of the three slices by calling
// policy.EffectiveSeverity, and the confidence gate is what decides which. The
// slices are therefore a record of the effective severity, and this function
// reads the bucket rather than f.Severity.
//
// That distinction is the difference between a real assertion and a plausible
// one. f.Severity is the severity the corpus declared; a MEDIUM-confidence
// BLOCK is declared BLOCK and lands in Conditions. Pinning f.Severity would
// print "BLOCK" in the expectation while the verdict was SHIP CONDITIONAL —
// the fixture would read as if it proved a block, and would keep passing if the
// confidence gate were deleted and the finding really did become a blocker.
// INV-2's whole promise is "a LOW finding can never produce DO NOT SHIP", and a
// fixture harness that cannot see the difference is not testing INV-2.
//
// The cost is that a corpus edit which changes a clause's declared severity
// without changing its bucket is no longer caught here. That is the right
// trade: the declared severity is pinned by the corpus loader's closed enum and
// by TestCorpusPredicatesTypecheck, while the effective severity is what the
// user reads and what the verdict algebra consumes, and nothing else asserts
// it end to end.
func fixtureFindings(v verdict.Verdict) []string {
	bands := []struct {
		severity policy.Severity
		findings []policy.Finding
	}{
		{policy.SeverityBlock, v.Blockers},
		{policy.SeverityCondition, v.Conditions},
		{policy.SeverityNote, v.Notes},
	}
	var out []string
	for _, band := range bands {
		for _, f := range band.findings {
			out = append(out, strings.Join([]string{
				f.DependencyID, f.Kind, string(band.severity),
			}, "|"))
		}
	}
	return out
}

// fixtureUndeterminedStrings renders every unclassified item as a sortable
// string.
func fixtureUndeterminedStrings(v verdict.Verdict) []string {
	out := make([]string, 0, len(v.Undetermined))
	for _, u := range v.Undetermined {
		out = append(out, u.ID+"|"+u.Reason)
	}
	return out
}

// fixtureExpectStrings renders the expectation side in the same shape.
func fixtureExpectStrings(findings []fixtureFinding, undetermined []fixtureUndetermined) ([]string, []string) {
	f := make([]string, 0, len(findings))
	for _, x := range findings {
		f = append(f, strings.Join([]string{x.Dependency, x.Kind, x.Severity}, "|"))
	}
	u := make([]string, 0, len(undetermined))
	for _, x := range undetermined {
		u = append(u, x.ID+"|"+x.Reason)
	}
	return f, u
}

// assertSameSet compares two lists as sets, after sorting both.
//
// Order-insensitive on purpose: the finding order within a severity band is
// INV-6's business and is pinned 100 times over by TestVerdictDeterminism.
// Asserting it here as well would make a fixture fail for a reason that has
// nothing to do with the fixture.
func assertSameSet(t *testing.T, what string, got, want []string) {
	t.Helper()

	g := append([]string(nil), got...)
	w := append([]string(nil), want...)
	sort.Strings(g)
	sort.Strings(w)

	if strings.Join(g, "\n") == strings.Join(w, "\n") {
		return
	}

	t.Errorf("%s do not match.\n  got  (%d):\n    %s\n  want (%d):\n    %s",
		what, len(g), strings.Join(g, "\n    "), len(w), strings.Join(w, "\n    "))
}

// ── the fixtures ─────────────────────────────────────────────────────────────

// TestFixtures asserts that every fixture produces the verdict it declares.
//
// # WHAT THIS CLOSES
//
// The fixtures are described in guard_helpers_test.go as "the executable
// specification of the traps: each is a minimal project plus the verdict it
// must produce". The first half was true and the second half did not exist:
// there was no recorded verdict anywhere, and nothing ran the pipeline over
// them except the determinism guard, which only compares a fixture against
// itself and so passes whatever the verdict is.
//
// The consequence is worth stating plainly. `fixtures/mixed` sets
// `commercial: true` and `distributed: true`, and `fixtures/mixed-none` sets
// both false, against a byte-identical lockfile. That pair exists to prove that
// MIT's obligations are gated on the intent — and if the predicate stopped
// reading the intent, both would produce the same findings and every test in
// the repository would still be green. This test is what notices.
//
// # WHY THE UNDETERMINED LIST IS ASSERTED TOO
//
// Both mixed fixtures are UNDETERMINED, and that is INV-7 working rather than a
// fixture that failed to reach a real verdict: leftpad declares WTFPL, the
// corpus carries no entry for it, and the tool refuses to guess. A test that
// asserted only "verdict == UNDETERMINED" would pass if the reason changed to
// something else entirely, so the reason is pinned as well.
func TestFixtures(t *testing.T) {
	for _, dir := range guardFixtureDirs(t) {
		name := filepath.Base(dir)
		t.Run(name, func(t *testing.T) {
			exp := readFixtureExpectation(t, dir)
			// Resolved per fixture rather than once, because a fixture may
			// ship its own corpus — see guardFixtureCorpus.
			c := guardFixtureCorpus(t, dir)
			v, diag, err := guardRunDetailed(t, dir, c, policy.Options{})
			if err != nil {
				t.Fatalf("pipeline on %s: %v", dir, err)
			}

			if got := string(v.Verdict); got != exp.Verdict {
				t.Errorf("verdict = %s, want %s.\n"+
					"What this fixture is for: %s",
					got, exp.Verdict, strings.TrimSpace(exp.Why))
			}

			wantFindings, wantUndetermined := fixtureExpectStrings(exp.Findings, exp.Undetermined)
			assertSameSet(t, "findings", fixtureFindings(v), wantFindings)
			assertSameSet(t, "unclassified dependencies",
				fixtureUndeterminedStrings(v), wantUndetermined)

			wantWarnings := append([]string(nil), exp.Warnings...)
			sort.Strings(wantWarnings)
			assertSameSet(t, "scanner warnings", guardWarningCodes(diag.Warnings), wantWarnings)

			wantNotices := append([]string(nil), exp.Notices...)
			sort.Strings(wantNotices)
			assertSameSet(t, "evaluation notices", guardNoticeCodes(diag.Notices), wantNotices)

			t.Logf("%s: %s, %d finding(s), %d unclassified, %d warning(s), %d notice(s)",
				name, v.Verdict, len(fixtureFindings(v)), len(v.Undetermined),
				len(diag.Warnings), len(diag.Notices))
		})
	}
}

// ── trap coverage ────────────────────────────────────────────────────────────

// trapsWithNoFixture is the acknowledged gap: traps that are declared in the
// corpus and fired by no fixture.
//
// # THIS LIST MAY ONLY SHRINK, AND IT IS NOW EMPTY
//
// CONTRIBUTING.md states the rule plainly: "Every trap gets a minimal
// repository under fixtures/ that triggers it, plus the expected verdict. The
// fixture *is* the specification of the trap." When this test was written the
// corpus held eleven traps, every one of them was on this list, and the rule
// was met zero times over.
//
// # HOW IT WAS EMPTIED, WHICH WAS NOT BY WRITING FIXTURES
//
// Adding fixtures alone would have changed nothing. Ten of the eleven traps
// were declared with a `when` predicate over dep.* and use.*, and no code path
// evaluated that predicate: the loader read it, TestCorpusPredicatesTypecheck
// typechecked it, the corpus browser rendered it, and nothing ever ran it. A
// fixture for trap.gpl.proprietary-binary would have produced zero findings,
// and the fixture would then have been recorded as passing an expectation that
// asserted its own absence.
//
// The fix was in the engine. policy.Evaluate now evaluates every trap whose
// declared scope is `dependency` once per dependency, against the same context
// an obligation uses — including, in the two early-exit branches, dependencies
// whose licence did not resolve or has no corpus entry. The two remaining traps
// are declared `scope: graph` and are decided by the checks in
// policy/crosscheck.go, which is where they always were.
//
// So the eleven traps now each have a fixture, and the count in the test log
// reads "11 declared, 11 fired, 0 acknowledged". The list stays here, empty,
// because the three failure directions below are what keep it from filling back
// up.
//
// # THE THREE DIRECTIONS THIS FAILS IN
//
//   - a new trap with no fixture and no entry here;
//   - an entry here for a trap that is no longer declared;
//   - an entry here for a trap that now has a fixture.
//
// The second and third matter as much as the first: a list that can only grow
// becomes a list nobody prunes, and a stale acknowledgement is indistinguishable
// from a real one.
//
// To add a fixture, add fixtures/<name>/ that triggers the trap and records the
// verdict in its expected.yml. If a trap genuinely cannot have one, add it here
// with the reason — but the reason has to be better than "the engine does not
// evaluate it", because now it does.
var trapsWithNoFixture = []string{}

// TestEveryTrapIsEitherFiredByAFixtureOrListed asserts that every trap the
// corpus declares is either fired by some fixture, or on the acknowledged list
// above.
func TestEveryTrapIsEitherFiredByAFixtureOrListed(t *testing.T) {
	c := guardLoadCorpus(t)

	declared := map[string]bool{}
	for _, tr := range c.GlobalTraps() {
		declared[tr.ID] = true
	}
	for _, e := range c.Entries() {
		for i := range e.Traps {
			declared[e.Traps[i].ID] = true
		}
	}
	if len(declared) == 0 {
		t.Fatal("the corpus declares no traps at all; this guard would pass by " +
			"comparing two empty sets")
	}

	fired := map[string]bool{}
	for _, dir := range guardFixtureDirs(t) {
		v := guardMustRun(t, dir, c, policy.Options{})
		for _, f := range guardAllFindings(v) {
			if f.TrapID != "" {
				fired[f.TrapID] = true
			}
		}
	}

	acknowledged := map[string]bool{}
	for _, id := range trapsWithNoFixture {
		if acknowledged[id] {
			t.Errorf("%s is listed twice in trapsWithNoFixture", id)
		}
		acknowledged[id] = true
	}

	for id := range declared {
		if fired[id] || acknowledged[id] {
			continue
		}
		t.Errorf("trap %s is declared in the corpus, is fired by no fixture, and "+
			"is not on the acknowledged list.\n"+
			"CONTRIBUTING.md: \"Every trap gets a minimal repository under "+
			"fixtures/ that triggers it, plus the expected verdict. The fixture "+
			"*is* the specification of the trap.\"\n"+
			"Add the fixture, or add %q to trapsWithNoFixture to record the gap "+
			"deliberately.", id, id)
	}
	for id := range acknowledged {
		switch {
		case !declared[id]:
			t.Errorf("%s is on trapsWithNoFixture but the corpus no longer "+
				"declares it. Delete the line.", id)
		case fired[id]:
			t.Errorf("%s is on trapsWithNoFixture but a fixture now fires it. "+
				"Delete the line, so the list keeps meaning what it says.", id)
		}
	}

	t.Logf("%d trap(s) declared, %d fired by a fixture, %d acknowledged as "+
		"having none", len(declared), len(fired), len(acknowledged))
}

// ── degrade coverage ─────────────────────────────────────────────────────────

// The DEGRADE gap, in two lists.
//
// # WHY THIS RATCHET EXISTS, AND WHY IT IS THE TRAP ONE'S SHAPE
//
// A DEGRADE is the tool admitting it could not read something, so the verdict
// beside it is weaker than it looks. Every DEGRADE code exits 0
// (ClassDegrade => ExitOK) — deliberately, because a file the scanner skipped is
// not a blocker. That is exactly what makes it dangerous: nothing about the exit
// status or the verdict makes a reader look at the diagnostics, so a DEGRADE
// code can be declared, documented, rendered into every human report, and fired
// by no fixture at all while every gate stays green.
//
// The trap property has had a ratchet since trapsWithNoFixture was emptied. The
// degrade property had none: PLAN/04-QUALITY/02-fixture-catalogue.md §10 named a
// test for it, `TestEveryDegradeCodeHasFixture`, and that test did not exist. A
// named check that checks nothing is this repository's signature defect, so this
// is that test — written, rather than renamed out of the catalogue.
//
// # THE FIRST RUN, WHICH IS THE ARGUMENT FOR HAVING WRITTEN IT
//
// On the day it was written it reported: 36 DEGRADE codes declared, 5 fired by a
// fixture, 31 with none. Thirty-one of thirty-six codes whose wording, severity
// and rendering nothing had ever checked. No gate was red, because no gate
// looked.
//
// # WHY THERE ARE TWO LISTS RATHER THAN ONE
//
// One list would have let the backlog hide behind the impossibilities. Split,
// each list fails in the directions that matter to it, and neither can be used
// to silence the other.
//
// # THE THREE DIRECTIONS BOTH LISTS FAIL IN
//
//   - a new DEGRADE code with no fixture and no entry on either list;
//   - an entry for a code the taxonomy no longer declares;
//   - an entry for a code a fixture now fires.
//
// The second and third matter as much as the first: a list that can only grow
// becomes a list nobody prunes, and a stale acknowledgement is indistinguishable
// from a real one.
//
// degradeCodesNoFixtureCanFire is the part of the gap that is a property of the
// fixture *form*, not of the fixture *set*.
//
// A fixture is a directory of files on disk. That is enough to provoke almost
// every DEGRADE the scanner and the parser can emit, but it is not enough to
// provoke four families, and saying so precisely is the point of splitting this
// list in two. The families, and why each is out of reach:
//
//   - E-NET-001..008 (8). Every one is produced by the single network client
//     (internal/cli/netclient.go, C4) and describes something that happened
//     across a socket: an unreachable host, a bad certificate, a failed
//     signature, a redirect, an oversized bundle. A directory cannot present an
//     HTTP peer. These are exercised by httptest in the cli package, where the
//     peer can be scripted, and that is the only place they can be.
//
//   - E-AI-003..006, E-AI-010 (5). Same reason, plus a second one: the AI
//     explainer is opt-in and its codes describe a provider's behaviour (429,
//     an unvalidated response, an oversized response). A fixture cannot be
//     rate-limited.
//
//   - E-SCAN-003, E-SCAN-007 (2). These are properties of a filesystem, not of
//     file content: more files than the budget allows, and a file the process
//     may not read. The fixture tree is committed to git and has to stay small
//     and portable, and git does not carry an unreadable mode at all — on
//     Windows the permission does not exist to be committed.
//
//     E-SCAN-006 (a file too large to parse) was on this list until a fixture
//     landed that fires it, and the test failed until the line was deleted.
//     That is the ratchet moving in the direction it was built to move, and it
//     is recorded here because it is the evidence that the list is load-bearing
//     rather than decorative.
//
//   - E-PARSE-006, E-PARSE-008, E-PARSE-009 (3). Declared, cited and rendered,
//     and reachable by no input: the YAML decoder's own depth, alias and tag
//     failures are wrapped into E-PARSE-001/002 by the parser before the
//     specific code can be attached. TEAM.md §8 F8/F9 records the evidence.
//     These are not "no fixture yet" — they are a taxonomy defect, and the
//     honest disposition is to fix or remove the codes, not to write a fixture
//     for an input that cannot exist. Recorded for WP7.
//
//   - E-CORPUS-010 (1). Describes a malformed entry in *Clearance's own*
//     corpus. A fixture is a project to be scanned; it cannot malform the tool's
//     data. Exercised by the corpus-validation tests instead.
var degradeCodesNoFixtureCanFire = []string{
	"E-AI-003", "E-AI-004", "E-AI-005", "E-AI-006", "E-AI-010",
	"E-NET-001", "E-NET-002", "E-NET-003", "E-NET-004",
	"E-NET-005", "E-NET-006", "E-NET-007", "E-NET-008",
	"E-PARSE-006", "E-PARSE-008", "E-PARSE-009",
	"E-SCAN-003", "E-SCAN-007",
	"E-CORPUS-010",
}

// degradeCodesAwaitingAFixture is the part of the gap that is a backlog, and it
// is deliberately a different list from the one above so that it cannot hide
// there.
//
// Every code below is provokable by a directory of files. Each is listed with
// the fixture that would fire it, so the work is a fixture to write rather than
// a design question to answer. **This list must shrink to empty**, and the test
// is built to make that happen rather than to tolerate it: the moment a fixture
// fires one of these, the test fails until the line is deleted.
//
//	E-SCAN-008  a directory tree deeper than --max-depth
//	E-SCAN-013  a LICENSE whose terms are a PDF reference
//
// (E-SCAN-010 was on this list with a note claiming fixtures/weights-no-licence
// did not fire it. That note was wrong, and it was wrong because the guard was
// looking in the wrong place: E-SCAN-010 is carried as the ErrorCode of an
// UNDETERMINED entry, not as a warning or a notice. The fixture was firing it
// the whole time. A guard that looks in the wrong list reports a false gap,
// which is worse than reporting none — see the fired-set construction below.)
//
//	E-SCAN-014  a source file that fails to AST-parse
//	E-SCAN-017  a vendored dependency containing a .env
//	E-SCAN-020  a clearance ignore rule that excludes a dependency directory
//	E-PARSE-005 a licence file that cannot be parsed at all
//	E-PARSE-007 an SBOM declaring a specVersion below the minimum
//	E-PARSE-010 a manifest encoded as anything other than UTF-8
//	E-POLICY-009 a dependency whose licence cannot be determined, with no
//	            declaration in clearance.config.yml
var degradeCodesAwaitingAFixture = []string{
	"E-SCAN-008", "E-SCAN-013",
	"E-SCAN-014", "E-SCAN-017", "E-SCAN-020",
	"E-PARSE-005", "E-PARSE-007", "E-PARSE-010",
	"E-POLICY-009",
}

// TestEveryDegradeCodeIsEitherFiredByAFixtureOrListed asserts that every
// DEGRADE-class code in the taxonomy is either fired by some fixture's
// diagnostics, or on the acknowledged list above.
//
// It reads diagnostics, not findings, on purpose. A DEGRADE never reaches the
// finding list — that is what the class means — so a guard that read only
// findings would report every DEGRADE code as unfired and be wrong about all of
// them. See guardDiagnostics for why warnings and notices are kept apart.
func TestEveryDegradeCodeIsEitherFiredByAFixtureOrListed(t *testing.T) {
	c := guardLoadCorpus(t)

	declared := map[string]bool{}
	for _, s := range cerr.Specs() {
		if s.Class == cerr.ClassDegrade {
			declared[string(s.Code)] = true
		}
	}
	if len(declared) == 0 {
		t.Fatal("the taxonomy declares no DEGRADE codes at all; this guard " +
			"would pass by comparing two empty sets")
	}

	fired := map[string]bool{}
	for _, dir := range guardFixtureDirs(t) {
		v, diag, err := guardRunDetailed(t, dir, c, policy.Options{})
		if err != nil {
			// A fixture whose *expected* outcome is a refused pipeline is
			// legitimate — fixtures/no-manifest is exactly that, and it ends in
			// E-SCAN-009 before any diagnostics exist. Such a fixture still
			// exercises a code, so the code it failed with counts as fired
			// rather than being skipped. Skipping it would be a silent gap in a
			// guard whose whole subject is silent gaps.
			if code := cerr.CodeOf(err); code != "" {
				fired[string(code)] = true
				continue
			}
			t.Fatalf("pipeline on %s: %v (and the error carries no cerr code, "+
				"so no code can be credited for it)", dir, err)
		}
		for _, n := range diag.Notices {
			fired[n.Code] = true
		}
		for _, w := range diag.Warnings {
			fired[w.Code] = true
		}
		// A DEGRADE also lives on an UNDETERMINED entry, as its ErrorCode. That
		// is where the weights detector puts E-SCAN-010: the file was read, no
		// licence was found, and the code names the gap rather than warning about
		// it. This guard originally read only the diagnostics and therefore
		// reported E-SCAN-010 as unfired while fixtures/weights-no-licence was
		// firing it on every run. A guard that looks in the wrong list reports a
		// false gap, which is worse than reporting none.
		for _, u := range v.Undetermined {
			if u.ErrorCode != "" {
				fired[u.ErrorCode] = true
			}
		}
	}

	acknowledged := map[string]string{}
	for _, code := range degradeCodesNoFixtureCanFire {
		if prev, dup := acknowledged[code]; dup {
			t.Errorf("%s is listed twice: in %s and in "+
				"degradeCodesNoFixtureCanFire", code, prev)
		}
		acknowledged[code] = "degradeCodesNoFixtureCanFire"
	}
	for _, code := range degradeCodesAwaitingAFixture {
		if prev, dup := acknowledged[code]; dup {
			t.Errorf("%s is listed twice: in %s and in "+
				"degradeCodesAwaitingAFixture", code, prev)
		}
		acknowledged[code] = "degradeCodesAwaitingAFixture"
	}

	unfired := make([]string, 0, len(declared))
	firedCount := 0
	for code := range declared {
		if fired[code] {
			firedCount++
			continue
		}
		if _, ok := acknowledged[code]; !ok {
			unfired = append(unfired, code)
		}
	}
	sort.Strings(unfired)
	if len(unfired) > 0 {
		t.Errorf("DEGRADE-class code(s) fired by no fixture and on neither "+
			"acknowledgement list:\n  %s\n"+
			"A DEGRADE code no fixture fires is a code whose wording, severity "+
			"and rendering nothing checks. Give a fixture an input that "+
			"provokes it, or add it to degradeCodesAwaitingAFixture with the "+
			"fixture that would fire it — or, if a fixture structurally cannot "+
			"provoke it, to degradeCodesNoFixtureCanFire with the reason.",
			strings.Join(unfired, "\n  "))
	}
	for code, list := range acknowledged {
		switch {
		case !declared[code]:
			t.Errorf("%s is on %s but the taxonomy no longer declares it. "+
				"Delete the line.", code, list)
		case fired[code]:
			t.Errorf("%s is on %s but a fixture now fires it. Delete the line, "+
				"so the list keeps meaning what it says.", code, list)
		}
	}

	t.Logf("%d DEGRADE code(s) declared, %d fired by a fixture, %d "+
		"acknowledged: %d structurally unreachable by a fixture, %d awaiting "+
		"one", len(declared), firedCount, len(acknowledged),
		len(degradeCodesNoFixtureCanFire), len(degradeCodesAwaitingAFixture))
}

// ── corpus data with no engine reader ────────────────────────────────────────

// territoryGatesWithNoReader is the acknowledged gap: jurisdiction gates the
// corpus ships and no code path evaluates.
//
// # WHAT THIS LIST RECORDS
//
// corpus/territories/*.yaml carries jurisdiction overlays. Each territory entry
// holds a `gates:` list, and every gate has an id, a summary, a severity, a
// confidence and a resolved citation — the same shape as an obligation or a
// trap. PLAN/02-SPECIFICATIONS/07-detection-spec-assets-territories.md Part B
// §3 and §4 specify that a declared territory's gates produce findings, and the
// loader registers each gate's citation in the citation index (load.go), so the
// data is complete enough to render.
//
// Nothing reads it. `grep -rn 'Territory\|Gates' internal/policy/` finds no
// call site: the only readers of Territory() and Gate are corpus-build, which
// bundles the data, and the corpus browser, which prints it. So the gates are
// described, cited, severity-rated, shipped — and never evaluated. That is
// LOGS.md §5.18's defect in a second place, and it is worth saying plainly:
// a reader of corpus/territories/ would reasonably believe these gates are live.
//
// # WHY THIS IS AN ACKNOWLEDGEMENT AND NOT A FIX
//
// The TERRITORIAL-CLAUSE layer — a licence obligation gated on the `territories`
// intent field — is live and pinned by fixtures/territorial-gate,
// territorial-undeclared and territorial-clean. This list is about the OTHER
// half: the jurisdiction overlay.
//
// Making the overlay live needs product decisions the plan does not make:
//
//   - What identity a project-level finding carries. The spec's example is
//     headed `project (territorial)` and names no dependency id, and
//     policy.Finding has no field for "the project".
//   - Where its evidence points. human.go prints "evidence: NONE RECORDED —
//     this is a bug (INV-1)" for a finding with no evidence, and the spec's
//     example finding carries none.
//   - How a declared `global` maps onto jurisdiction-specific gates. The config
//     spec calls `global` a valid value and says it means everywhere; whether
//     that fires every territory's gates is a product decision, not a datum.
//   - What a declared territory with no corpus entry should say. The spec's
//     failure table rates that row INFO and assigns it no error code, and INV-1
//     makes an uncited INFO finding unrepresentable, so the row cannot be
//     implemented as written.
//
// Inventing any of those is the tool assuming a fact rather than reading one,
// which is the failure mode INV-7 exists to prevent. So the gap is recorded
// here, where it is visible and tested, rather than left as a property of the
// corpus that nobody notices.
//
// # THIS LIST MAY ONLY SHRINK, AND THE GUARD CHECKS BOTH DIRECTIONS
//
// It is the same ratchet as trapsWithNoFixture. An entry here for a gate the
// corpus no longer declares is an error, so a rename cannot leave a stale
// acknowledgement behind. Implementing the overlay therefore requires deleting
// the list, which is the point: the fix cannot be made silently.
//
// # WHAT THIS GUARD DOES NOT CHECK
//
// It does not detect the opposite event — someone implementing the overlay
// while leaving this list in place. Detecting that needs a fixture that fires a
// shipped gate, and the shipped gates are jurisdiction overlays, so such a
// fixture would have to assert the overlay's behaviour, which is the very thing
// the decisions above are missing. The acknowledgement is therefore one-way,
// and saying so is better than implying the guard covers it.
var territoryGatesWithNoReader = []string{
	"eu.ai-act-transparency",
	"eu.database-right",
	"gb.database-right",
	"gb.uk-gdpr",
	"territory.cn.algorithm-filing",
	"territory.cn.cross-border-data",
	"us.dmca-anticircumvention",
	"us.export-control",
}

// TestEveryTerritoryGateIsEitherEvaluatedOrAcknowledged asserts that every
// jurisdiction gate the corpus ships is either evaluated by some code path or
// on the acknowledged list above.
//
// It is the guard for the gap the list documents. Without it, the overlay could
// stay inert forever, or a new gate could be added to the corpus and quietly
// join the ones nothing reads, and no test would point at either.
func TestEveryTerritoryGateIsEitherEvaluatedOrAcknowledged(t *testing.T) {
	c := guardLoadCorpus(t)

	declared := map[string]bool{}
	for _, code := range c.SortedTerritoryCodes() {
		ter, ok := c.Territory(code)
		if !ok {
			t.Errorf("SortedTerritoryCodes listed %q but Territory(%q) does not "+
				"resolve it; the accessor and the index disagree", code, code)
			continue
		}
		for i := range ter.Gates {
			declared[ter.Gates[i].ID] = true
		}
	}
	if len(declared) == 0 {
		t.Fatal("the corpus declares no territory gate at all, so this guard is " +
			"comparing an empty set to a list.\nEither corpus/territories/ lost " +
			"its `gates:` lists, or the loader stopped reading them, and either " +
			"way this test is asserting nothing.")
	}

	acknowledged := map[string]bool{}
	for _, id := range territoryGatesWithNoReader {
		if acknowledged[id] {
			t.Errorf("%s is listed twice in territoryGatesWithNoReader", id)
		}
		acknowledged[id] = true
	}

	for _, id := range sortedKeys(declared) {
		if acknowledged[id] {
			continue
		}
		t.Errorf("territory gate %s is declared in the corpus, is read by no "+
			"code path, and is not on the acknowledged list.\n"+
			"A gate that nothing evaluates is described, cited and inert — the "+
			"defect LOGS.md §5.18 records for the trap catalogue.\n"+
			"Either wire the jurisdiction-overlay layer up, or add %q to "+
			"territoryGatesWithNoReader to record the gap deliberately.", id, id)
	}
	for _, id := range sortedKeys(acknowledged) {
		if !declared[id] {
			t.Errorf("%s is on territoryGatesWithNoReader but the corpus no "+
				"longer declares it. Delete the line, so the list keeps meaning "+
				"what it says.", id)
		}
	}

	t.Logf("%d territory gate(s) declared, %d acknowledged as having no reader",
		len(declared), len(acknowledged))
}

// ── graph kinds with no producer ─────────────────────────────────────────────

// kindsWithNoProducer is the acknowledged gap: graph.Kind values that are
// declared, rendered and reasoned about, and that no code path ever constructs.
//
// # WHAT THIS LIST RECORDS
//
// graph.Kind is the closed set of things that can carry terms. Every constant
// is meaningful to the code that consumes a dependency: engine.go skips the
// kinds whose terms arrive from another layer, sbom.go maps each to a CycloneDX
// component type, and the renderers print them.
//
// A kind that nothing ever constructs is not a type — it is an intention. It
// reads, everywhere it appears, exactly like a kind that works.
//
// # THE ASSET LAYER, WHICH IS NOW BUILT
//
// `asset` is the brand-asset layer. PLAN/02-SPECIFICATIONS/
// 07-detection-spec-assets-territories.md Part A specifies it: walk vendored
// dependency directories, match filenames against brand-asset patterns
// (logo.*, icon.*, favicon.*, wordmark.*, brand.*), read TRADEMARK/NOTICE files
// and classify them, and emit a Dependency of kind ASSET per dependency with a
// signal. corpus/traps/excluded-brand-assets.yml is given verbatim in §4, gated
// on `dep.kind == "asset" AND use.distributed == true`.
//
// It now exists, and the line that acknowledged its absence is gone.
// internal/scanner/assets.go is the detector; corpus/traps/
// excluded-brand-assets.yml is the trap; fixtures/excluded-brand-assets/ and
// fixtures/brand-assets-internal/ are the two-directional pair the catalogue
// calls for. The ratchet below is what forced the acknowledgement off the list
// — a kind on it that a fixture now produces is an error.
//
// The one thing the implementation had to add beyond the detector was in the
// engine, and it is worth recording here because it was invisible from the
// spec. `graph.KindAsset` shared a `continue` with `graph.KindUpstreamCLI` in
// policy.Evaluate, and that `continue` skipped the dependency-scoped trap pass
// along with the licence resolution. A detector alone would have produced a
// node that nothing ever judged: the fixture would have asserted no finding
// against a trap that could never fire. The kind now has its own case, and it
// evaluates the trap catalogue before it continues.
//
// # THE MODEL CARD
//
// `model_card` is the same defect the asset layer had, with less fanfare: the
// constant exists, and nothing in the module outside graph.go mentions it. A
// model card's licence terms are resolved by the weights detector through the
// ordinary licence fields (weights.go reads the string "model_card" as a
// licence *source*), so the kind is not needed for that — which is exactly why
// it should either be removed or be given the producer its name implies. It
// stays acknowledged here; the gap is real.
//
// # THE RATCHET
//
// Both directions, like the other two acknowledgement lists here. A kind on
// this list that a fixture now produces is an error, which is how implementing
// the asset layer removed its line. A kind the corpus/graph declares that is
// neither produced nor listed is an error, so a new dead kind cannot be added
// quietly.
var kindsWithNoProducer = []string{
	string(graph.KindModelCard),
}

// TestEveryGraphKindIsEitherProducedByAFixtureOrAcknowledged asserts that every
// graph.Kind the module declares is observed in at least one fixture, or is on
// the acknowledged list above.
//
// # WHY IT MEASURES VALUES AND NOT SOURCE TEXT
//
// A grep for `graph.KindAsset` in internal/scanner would be satisfied by the
// wrong thing: engine.go and sbom.go both NAME the constant, so a text search
// cannot tell "this kind is consumed" from "this kind is produced". What the
// claim actually is is "some code path constructs a Dependency of this kind",
// and the only honest way to check that is to run the scanner and look at what
// comes out.
//
// # WHY IT RUNS THE WHOLE FIXTURE SUITE
//
// Because that is the module's existing definition of "exercised end to end" —
// the same definition TestEveryTrapIsEitherFiredByAFixtureOrListed uses. A kind
// with a producer but no fixture would also be caught, which is the right
// outcome: an unexercised producer is one edit away from being an unexercised
// kind.
func TestEveryGraphKindIsEitherProducedByAFixtureOrAcknowledged(t *testing.T) {
	// The closed set, read from the type's own declaration rather than
	// re-typed here — a third copy of the list is a copy that drifts.
	declared := map[string]bool{}
	for _, name := range graphKindConstantNames(t) {
		declared[name] = true
	}
	if len(declared) == 0 {
		t.Fatal("no graph.Kind constants were found in internal/graph; this " +
			"guard is comparing an empty set to a list and asserting nothing")
	}

	produced := map[string]bool{}
	for _, dir := range guardFixtureDirs(t) {
		cfg, err := config.Load(config.Options{WorkDir: dir, UserConfigPath: "-"})
		if err != nil {
			t.Fatalf("loading the config for %s: %v", dir, err)
		}
		g, err := scanner.Scan(dir, scanner.Options{Intent: cfg.Intent})
		if err != nil {
			t.Fatalf("scanning %s: %v", dir, err)
		}
		for _, d := range g.Dependencies {
			produced[string(d.Kind)] = true
		}
	}
	if len(produced) == 0 {
		t.Fatal("the fixture suite produced no dependencies at all; this guard " +
			"would otherwise pass by comparing against an empty set")
	}

	acknowledged := map[string]bool{}
	for _, k := range kindsWithNoProducer {
		if acknowledged[k] {
			t.Errorf("%s is listed twice in kindsWithNoProducer", k)
		}
		acknowledged[k] = true
	}

	for _, k := range sortedKeys(declared) {
		if produced[k] || acknowledged[k] {
			continue
		}
		t.Errorf("graph.Kind %q is declared and no fixture ever produces it.\n"+
			"A kind nothing constructs is declared, rendered and reasoned about, "+
			"and inert — it reads exactly like a kind that works.\n"+
			"Either give it a producer and a fixture, or add it to "+
			"kindsWithNoProducer to record the gap deliberately.", k)
	}
	for _, k := range sortedKeys(acknowledged) {
		switch {
		case !declared[k]:
			t.Errorf("%q is on kindsWithNoProducer but graph no longer declares "+
				"it. Delete the line.", k)
		case produced[k]:
			t.Errorf("%q is on kindsWithNoProducer but a fixture now produces it. "+
				"Delete the line, so the list keeps meaning what it says.", k)
		}
	}

	t.Logf("%d graph kind(s) declared, %d produced by the fixture suite, %d "+
		"acknowledged as having no producer",
		len(declared), len(produced), len(acknowledged))
}

// graphKindConstantNames returns the string values of every `Kind` constant
// declared in internal/graph, sorted.
//
// It reads the source rather than reflecting over values because the question
// is "what kinds does this module CLAIM exist?", and a constant nothing
// constructs has no value to reflect over.
func graphKindConstantNames(t *testing.T) []string {
	t.Helper()

	dir := filepath.Join(moduleRoot(t), "internal", "graph")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	var out []string
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
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.CONST {
				continue
			}
			for _, spec := range gen.Specs {
				vs, ok := spec.(*ast.ValueSpec)
				if !ok {
					continue
				}
				// Only a constant whose declared type is `Kind`.
				if sel, ok := vs.Type.(*ast.Ident); !ok || sel.Name != "Kind" {
					continue
				}
				for _, v := range vs.Values {
					lit, ok := v.(*ast.BasicLit)
					if !ok || lit.Kind != token.STRING {
						continue
					}
					s, unqErr := strconv.Unquote(lit.Value)
					if unqErr != nil {
						t.Fatalf("unquoting a Kind constant in %s: %v", e.Name(), unqErr)
					}
					out = append(out, s)
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// ── the predicates ───────────────────────────────────────────────────────────

// TestCorpusPredicatesTypecheck asserts that every predicate in the shipped
// corpus is a well-formed, well-typed expression over the closed field
// registry.
//
// # WHY THIS IS NOT REDUNDANT WITH THE LOADER
//
// load.go already calls Validate() on the obligations of every entry, on the
// traps of every entry, and on every global trap. So this test cannot fail for
// a predicate that the loader sees — and that is the point. The failure it
// exists to catch is a predicate the loader does NOT see.
//
// A new entry kind that gains a `when` field, without a call to Validate() in
// its load path, would load cleanly and then evaluate to UNKNOWN forever. Every
// downstream symptom would be a wrong verdict, and no test would point at the
// corpus.
//
// # HOW THE WALK IS KEPT HONEST
//
// A walk is only as good as its list of places to look, and a walk whose list
// has gone stale passes by finding nothing — the exact failure mode this file
// exists to prevent. So the walk's coverage is not asserted by hand: the corpus
// package is scanned for every struct that declares a `When *expr.Expr` field,
// and each one must appear in predicateBearingTypes below. Adding a predicate
// to a new type fails this test until the walk is extended to reach it.
//
// # WHAT IS DELIBERATELY NOT ASSERTED
//
// An earlier draft of this test also checked each referenced field against
// expr.FieldPaths(). That check is unreachable: Validate() resolves fields
// through fieldByPath, and fieldByPath and FieldPaths() are both derived from
// the same `fields` slice, so a field that validates is registered by
// construction. A check that cannot fail is worse than no check, so it was
// removed rather than kept for the look of it.
func TestCorpusPredicatesTypecheck(t *testing.T) {
	c := guardLoadCorpus(t)

	// ── 1. the walk covers every predicate-bearing type ────────────────────
	//
	// predicateBearingTypes is the list of corpus types whose predicates this
	// test reaches. A type that declares `When *expr.Expr` but is absent here
	// has predicates that nothing validates, which is the defect above.
	predicateBearingTypes := map[string]bool{
		"Obligation": true, // entry.Obligations[i].When
		"Trap":       true, // entry.Traps[i].When and globalTraps[i].When
		"Clause":     true, // tos[platform].RestrictiveClauses[i].When
	}
	declared := scanPredicateBearingTypes(t)
	if len(declared) == 0 {
		t.Fatal("the scan found no struct declaring a `When *expr.Expr` field; " +
			"either the corpus types changed shape or the scan is broken, and " +
			"either way this guard is asserting nothing")
	}
	for _, name := range declared {
		if !predicateBearingTypes[name] {
			t.Errorf("corpus type %s declares a `When *expr.Expr` field, but this "+
				"test does not walk it.\n"+
				"Its predicates are therefore validated only if its load path "+
				"happens to call Validate(). Add it to the walk below, or the "+
				"corpus can carry a predicate nothing checks.", name)
		}
	}

	// ── 2. every predicate the walk reaches validates ──────────────────────
	var predicates int
	check := func(owner string, e *expr.Expr) {
		predicates++
		if e == nil {
			t.Errorf("%s carries a nil predicate; the loader requires one on every "+
				"obligation and trap", owner)
			return
		}
		if err := e.Validate(); err != nil {
			t.Errorf("%s does not validate: %v", owner, err)
		}
	}

	for _, e := range c.Entries() {
		for i := range e.Obligations {
			check("licence "+e.SPDXID+" obligation "+e.Obligations[i].ID,
				e.Obligations[i].When)
		}
		for i := range e.Traps {
			check("licence "+e.SPDXID+" trap "+e.Traps[i].ID, e.Traps[i].When)
		}
	}
	for _, tr := range c.GlobalTraps() {
		check("global trap "+tr.ID, tr.When)
	}
	for _, platform := range c.SortedToSPlatforms() {
		e, ok := c.ToS(platform)
		if !ok {
			t.Errorf("SortedToSPlatforms listed %q but ToS(%q) does not resolve it; the "+
				"accessor and the index disagree", platform, platform)
			continue
		}
		for i := range e.RestrictiveClauses {
			cl := &e.RestrictiveClauses[i]
			// A platform clause's predicate is optional — absent means "applies
			// whenever the platform is invoked" — so only a present one is
			// checked. Checking a nil one would fail the corpus for using the
			// documented default.
			if cl.When == nil {
				continue
			}
			check("platform "+e.Platform+" clause "+cl.ID, cl.When)
		}
	}

	// ── 3. the floor ───────────────────────────────────────────────────────
	//
	// A vacuous pass is the failure mode this whole file is about. If the walk
	// stops reaching the predicates — a field renamed, a slice moved — the test
	// would report success having asserted nothing, so the floor is explicit.
	if predicates == 0 {
		t.Fatal("no predicates were reached; the walk is broken and this guard " +
			"asserted nothing")
	}
	t.Logf("%d predicates typecheck across %d predicate-bearing type(s)",
		predicates, len(declared))
}

// scanPredicateBearingTypes returns the name of every struct type declared in
// internal/corpus that carries a `When *expr.Expr` field, sorted.
//
// It reads source rather than reflecting over loaded values on purpose: the
// question is "what could carry a predicate?", and a type that no corpus file
// currently populates would be invisible to a value-level walk while still
// being a place a predicate can hide.
func scanPredicateBearingTypes(t *testing.T) []string {
	t.Helper()

	dir := filepath.Join(moduleRoot(t), "internal", "corpus")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	var out []string
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
		for _, decl := range f.Decls {
			gen, ok := decl.(*ast.GenDecl)
			if !ok || gen.Tok != token.TYPE {
				continue
			}
			for _, spec := range gen.Specs {
				ts, ok := spec.(*ast.TypeSpec)
				if !ok {
					continue
				}
				st, ok := ts.Type.(*ast.StructType)
				if !ok || st.Fields == nil {
					continue
				}
				for _, field := range st.Fields.List {
					if !isWhenPredicateField(field) {
						continue
					}
					out = append(out, ts.Name.Name)
					break
				}
			}
		}
	}
	sort.Strings(out)
	return out
}

// isWhenPredicateField reports whether a struct field is `When *expr.Expr`.
func isWhenPredicateField(field *ast.Field) bool {
	for _, name := range field.Names {
		if name.Name != "When" {
			continue
		}
		star, ok := field.Type.(*ast.StarExpr)
		if !ok {
			return false
		}
		sel, ok := star.X.(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != "Expr" {
			return false
		}
		pkg, ok := sel.X.(*ast.Ident)
		return ok && pkg.Name == "expr"
	}
	return false
}

// ── the closed obligation vocabulary ─────────────────────────────────────────
//
// Three guards, and they are three because they answer three different
// questions about the same vocabulary. Between them they close the hole
// internal/obligations was written to close: that `kind` was a free string the
// loader never checked, so a typo reached the user as a finding's title.

// TestObligationVocabularyMatchesTheSpec asserts that the Go constants in
// internal/obligations are EXACTLY the kinds the schema spec lists.
//
// # WHY IT READS THE SPEC RATHER THAN A LIST IN THE TEST
//
// Because a list in the test is a third copy, and a third copy is a copy that
// drifts. The spec is the source of truth, the constant block is the
// implementation, and this test is the seam between them: adding a kind to one
// without the other is a red build rather than a decision nobody wrote down.
//
// The comparison is set equality in both directions on purpose. A constant with
// no spec row is an undocumented judgement; a spec row with no constant is a
// corpus author being told to write a value the loader will reject.
func TestObligationVocabularyMatchesTheSpec(t *testing.T) {
	path := guardPlanFile(t, "02-SPECIFICATIONS/02-corpus-schema-spec.md")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading the schema spec: %v", err)
	}

	// The §4 table's rows look like:
	//
	//	| `ATTRIBUTION` | You must credit the author | `CONDITION` |
	//
	// The kind is the first backticked token on a row that has three cells.
	// The header separator row (`|---|---|---|`) and the header itself carry no
	// backticks, so requiring a backticked first cell is enough to select rows
	// without hard-coding the section's line numbers — which would go stale the
	// first time someone inserted a paragraph above it.
	re := regexp.MustCompile("^\\|\\s*`([A-Z_]+)`\\s*\\|")
	fromSpec := map[string]bool{}
	for _, line := range strings.Split(string(raw), "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		fromSpec[m[1]] = true
	}
	if len(fromSpec) == 0 {
		t.Fatalf("no obligation kinds were parsed out of %s.\n"+
			"The parser looks for table rows whose first cell is a backticked "+
			"UPPER_CASE token. If the spec's §4 table was reformatted, fix the "+
			"parser — a test that silently parses nothing passes by comparing "+
			"against an empty set.", path)
	}

	fromCode := map[string]bool{}
	for _, k := range obligations.Kinds() {
		fromCode[string(k)] = true
	}

	for _, k := range sortedKeys(fromSpec) {
		if !fromCode[k] {
			t.Errorf("the schema spec lists kind %q but internal/obligations has no "+
				"constant for it.\nA corpus author following the spec would write a "+
				"value the loader rejects with E-CORPUS-004.", k)
		}
	}
	for _, k := range sortedKeys(fromCode) {
		if !fromSpec[k] {
			t.Errorf("internal/obligations defines kind %q but the schema spec's §4 "+
				"table does not list it.\nEither add the spec row, or delete the "+
				"constant — an undocumented kind is a judgement nobody wrote down.", k)
		}
	}
	t.Logf("obligation vocabulary: %d kinds, spec and code agree", len(fromCode))
}

// TestEveryObligationKindInTheCorpusIsKnown walks the shipped corpus and
// asserts that every obligation's kind and every fix's action is in the closed
// vocabulary.
//
// # WHY IT PARSES THE YAML RATHER THAN LOADING THE CORPUS
//
// corpus.Load now calls obligations.Validate, so this test would pass by
// construction if it went through the loader — and it would keep passing if
// someone deleted that call. Parsing the files here makes the test independent
// of the loader, so it is a check on the DATA as well as on the plumbing. The
// two failure modes are different: a bad kind in a YAML file is an edit, and a
// missing call in the loader is a code review.
func TestEveryObligationKindInTheCorpusIsKnown(t *testing.T) {
	dir := filepath.Join(guardCorpusPath(t), "licences")
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("reading %s: %v", dir, err)
	}

	lim := safeyaml.Limits{MaxBytes: 1 << 20, MaxDepth: 32}
	var checkedKinds, checkedActions int

	for _, de := range entries {
		if de.IsDir() {
			continue
		}
		ext := strings.ToLower(filepath.Ext(de.Name()))
		if ext != ".yml" && ext != ".yaml" {
			continue
		}
		rel := filepath.Join(dir, de.Name())
		data, err := os.ReadFile(rel)
		if err != nil {
			t.Fatalf("reading %s: %v", rel, err)
		}
		node, err := safeyaml.Parse(data, lim)
		if err != nil {
			t.Fatalf("parsing %s: %v", rel, err)
		}
		var e corpus.Entry
		if err := safeyaml.Decode(node, &e); err != nil {
			t.Fatalf("decoding %s: %v", rel, err)
		}
		for i := range e.Obligations {
			ob := &e.Obligations[i]
			checkedKinds++
			if _, ok := obligations.KindOf(ob.Kind); !ok {
				t.Errorf("%s: obligation %q declares kind %q, which is not in the "+
					"vocabulary.\nKnown kinds: %s",
					de.Name(), ob.ID, ob.Kind, obligations.KindsCSV())
			}
			if ob.Fix == nil {
				continue
			}
			checkedActions++
			if !obligations.FixAction(strings.TrimSpace(ob.Fix.Action)).Valid() {
				t.Errorf("%s: obligation %q declares fix action %q, which is not in "+
					"the vocabulary.", de.Name(), ob.ID, ob.Fix.Action)
			}
		}
	}

	if checkedKinds == 0 {
		t.Fatal("no obligations were found in the shipped corpus; this test would " +
			"otherwise pass by checking nothing")
	}
	t.Logf("checked %d obligation kinds and %d fix actions across the shipped corpus",
		checkedKinds, checkedActions)
}

// TestObligationValidatorRefusesATypo proves the validator can fail.
//
// # WHY A GUARD THAT CANNOT FAIL IS WORSE THAN NO GUARD
//
// Because it certifies a guarantee it does not check, and the certification is
// what stops anyone looking. The two tests above would both stay green if
// obligations.Resolve returned nil unconditionally: the first compares the
// vocabulary against the spec, and the second compares the corpus against the
// vocabulary — neither ever asks the validator a question whose answer could be
// "no".
//
// This one does. It builds a corpus that is correct in every respect except one
// letter of one kind, and asserts the load fails. The typo is spelled out
// rather than generated, because the whole point is that it is the typo a
// person actually makes.
func TestObligationValidatorRefusesATypo(t *testing.T) {
	dir := guardWriteCorpusTree(t, map[string]string{
		"licences/mit.yaml": `
id: mit
spdx_id: MIT
name: MIT License
family: permissive
osi_approved: true
fsf_libre: true
permissiveness: 5
confidence: HIGH
last_verified: "2026-09-01"
citation:
  url: https://opensource.org/license/mit
  section: "Permission is hereby granted"
obligations:
  - id: mit.attribution
    kind: atribution
    severity: CONDITION
    confidence: HIGH
    message: "You must retain the copyright notice in copies of the software."
    when:
      op: "=="
      field: use.distributed
      value: true
    citation:
      url: https://opensource.org/license/mit
      section: "The above copyright notice"
`,
	})

	_, err := corpus.Load(corpus.LoadOptions{Dir: dir, Today: guardToday})
	if err == nil {
		t.Fatal("a corpus whose obligation kind is misspelled ('atribution') loaded " +
			"successfully.\nThis is the exact defect internal/obligations exists to " +
			"close: the typo would have become a finding titled 'atribution " +
			"obligation' in every report, with a green build and a valid signature.")
	}
	if cerr.CodeOf(err) != cerr.ECorpus004 {
		t.Fatalf("the misspelled kind produced %v, not E-CORPUS-004.\nThe code "+
			"matters: E-CORPUS-004 is the one the taxonomy documents as 'one entry "+
			"failed validation', and a load failure reported under a different code "+
			"is a load failure nobody can look up.", err)
	}
	// The message has to name the offending value, or the corpus author has to
	// guess which of eleven kinds they mistyped.
	if msg := err.Error(); !strings.Contains(msg, "atribution") {
		t.Errorf("the refusal does not name the offending kind.\nGot: %s", msg)
	}
}

// TestFixActionValidatorRefusesATypo is the same proof for the second closed
// vocabulary. It is a separate test rather than a second case in the one above
// because the two vocabularies are validated by different lines, and a single
// test would let one of the lines be deleted while the other kept it green.
func TestFixActionValidatorRefusesATypo(t *testing.T) {
	dir := guardWriteCorpusTree(t, map[string]string{
		"licences/agpl-3.0-only.yaml": `
id: agpl-3.0-only
spdx_id: AGPL-3.0-only
name: GNU Affero General Public License v3.0 only
family: strong-copyleft
osi_approved: true
fsf_libre: true
permissiveness: 1
confidence: HIGH
last_verified: "2026-09-01"
citation:
  url: https://www.gnu.org/licenses/agpl-3.0.txt
  section: "§13"
obligations:
  - id: agpl.s13.network-use
    kind: NETWORK_DISCLOSURE
    severity: BLOCK
    confidence: HIGH
    message: "If users interact with your modified version over a network, you must offer them the source."
    when:
      op: "=="
      field: use.network_exposed
      value: true
    citation:
      url: https://www.gnu.org/licenses/agpl-3.0.txt
      section: "§13"
    fix:
      action: replcae
      suggestion: "Swap to a permissive alternative."
      confidence: MEDIUM
`,
	})

	_, err := corpus.Load(corpus.LoadOptions{Dir: dir, Today: guardToday})
	if err == nil {
		t.Fatal("a corpus whose fix action is misspelled ('replcae') loaded " +
			"successfully.\nA fix's action is the verb of the advice the tool gives; " +
			"an unrecognised one renders as advice with no verb.")
	}
	if cerr.CodeOf(err) != cerr.ECorpus004 {
		t.Fatalf("the misspelled fix action produced %v, not E-CORPUS-004.", err)
	}
	if msg := err.Error(); !strings.Contains(msg, "replcae") {
		t.Errorf("the refusal does not name the offending action.\nGot: %s", msg)
	}
}

// ── trap scope ───────────────────────────────────────────────────────────────

// TestEveryGraphScopedTrapHasAnEngineCheck asserts that the corpus's claim "this
// trap needs a graph-level check" and the engine's claim "a check exists here"
// agree in both directions.
//
// # THE CONTRACT
//
// A trap declares its `scope` because the difference cannot be inferred from the
// predicate. `trap.code-weights-divergence` carries
// `dep.kind == weights AND dep.licence.family != permissive`, which reads like
// an ordinary one-dependency test and is not one: the finding it exists for is a
// comparison between a repository's code licence and its weights licence, and no
// single dependency's facts contain that comparison. So the corpus says
// `scope: graph`, and internal/policy decides it and looks it up by id.
//
// # WHY BOTH DIRECTIONS, AND WHY NEITHER IS HYPOTHETICAL
//
//   - A graph-scoped trap with no check is declared, cited, rendered in the
//     corpus browser, and never evaluated. That was the state of all eleven
//     traps in this corpus until the dependency-scoped pass was added; the two
//     graph-scoped ones would have rejoined them the moment a third was added.
//
//   - A check naming a trap that is not declared graph-scoped is worse. If the
//     id does not exist, the check runs, finds nothing, and produces no finding
//     and no error — the trap it was written for is gone and the check that
//     replaced it is decorative. If the id exists but is dependency-scoped, the
//     engine evaluates it per-dependency *and* this check emits it, so the same
//     defect is reported twice with two different reason lines.
//
// Neither failure has an error code. Neither shows up in any other test. This is
// the only thing standing between the scope field and a corpus that has quietly
// stopped matching the code.
func TestEveryGraphScopedTrapHasAnEngineCheck(t *testing.T) {
	c := guardLoadCorpus(t)

	declared := map[string]bool{}
	dependencyScoped := 0
	for _, tr := range c.GlobalTraps() {
		if tr.IsGraphScoped() {
			declared[tr.ID] = true
			continue
		}
		dependencyScoped++
	}

	// Non-vacuity, in both directions. Without these two the guard passes when
	// the corpus has no graph traps at all, which is exactly what a corpus whose
	// `scope` field stopped being read would look like.
	if len(declared) == 0 {
		t.Error("the corpus declares no graph-scoped trap, so this guard is " +
			"comparing an empty set to a list.\nEither the traps that need a " +
			"graph check lost their `scope: graph`, or the field is no longer " +
			"being read.")
	}
	if dependencyScoped == 0 {
		t.Error("the corpus declares no dependency-scoped trap, so the engine's " +
			"per-dependency pass has nothing to evaluate and the catalogue is " +
			"entirely graph-scoped. That is not the design.")
	}

	checked := map[string]bool{}
	for _, id := range policy.GraphCheckTrapIDs() {
		if checked[id] {
			t.Errorf("%s is listed twice in policy.GraphCheckTrapIDs", id)
		}
		checked[id] = true
	}
	if len(checked) == 0 {
		t.Error("policy.GraphCheckTrapIDs is empty; the engine claims no graph " +
			"check exists at all.")
	}

	for _, id := range sortedKeys(declared) {
		if checked[id] {
			continue
		}
		t.Errorf("%s is declared `scope: graph` in the corpus, and no engine "+
			"check claims it.\n"+
			"The trap is inert: the engine skips it in the per-dependency pass "+
			"because it is graph-scoped, and nothing else looks it up. Add the "+
			"check to internal/policy/crosscheck.go and name it in "+
			"GraphCheckTrapIDs, or change the scope to `dependency` if its "+
			"predicate really can decide it.", id)
	}
	for _, id := range sortedKeys(checked) {
		if declared[id] {
			continue
		}
		t.Errorf("policy.GraphCheckTrapIDs names %s, and the corpus does not "+
			"declare it `scope: graph`.\n"+
			"Either the trap was renamed — in which case the check now looks up "+
			"an id that does not exist, finds nothing, and silently reports "+
			"nothing — or its scope was changed to `dependency`, in which case "+
			"the engine evaluates it per-dependency AND this check emits it, so "+
			"the finding appears twice.", id)
	}
}

// TestTrapScopeValidatorRefusesATypo asserts that a trap whose scope the engine
// does not understand fails to load.
//
// # WHY THE LOAD IS THE ONLY PLACE THIS CAN BE CAUGHT
//
// Because the failure it prevents is silent. A trap declaring `scope: grahp`
// would be read as the default by anything that resolved an unknown value to the
// default, evaluated against one dependency, and — for a trap that really needs
// the whole scope — either produce nothing at all or produce a weaker copy of a
// finding some other check already emits. No error code, no notice, and no way
// for a user to tell which of the two happened.
//
// The second case below is the other half of the rule: `scope: graph` on a trap
// attached to a licence entry is refused, because such a trap has exactly one
// dependency to be evaluated against, so no graph check can be looking for it
// and the engine skips it in the per-dependency pass. It would be inert in the
// same way, one layer down.
func TestTrapScopeValidatorRefusesATypo(t *testing.T) {
	for _, tc := range []struct {
		name  string
		scope string
		why   string
	}{
		{
			name:  "misspelled",
			scope: "grahp",
			why:   "a misspelled scope must not be read as the default; it would be evaluated against one dependency instead of the whole scope.",
		},
		{
			name:  "whitespace",
			scope: " ",
			why:   "whitespace is not a scope, and trimming it to empty would silently select the default.",
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := guardWriteCorpusTree(t, map[string]string{
				"traps/synthetic.yaml": `
id: trap.synthetic
title: "A synthetic trap"
summary: "A trap whose summary is comfortably longer than the minimum the validator enforces."
when:
  op: "=="
  field: dep.kind
  value: weights
scope: "` + tc.scope + `"
severity: BLOCK
confidence: HIGH
citation:
  url: https://example.test/synthetic
  section: "Clause 1"
`,
			})

			_, err := corpus.Load(corpus.LoadOptions{Dir: dir, Today: guardToday})
			if err == nil {
				t.Fatalf("a trap declaring scope %q loaded successfully.\n%s",
					tc.scope, tc.why)
			}
			if cerr.CodeOf(err) != cerr.ECorpus004 {
				t.Fatalf("the bad scope produced %v, not E-CORPUS-004.", err)
			}
		})
	}

	t.Run("graph scope on a licence-attached trap", func(t *testing.T) {
		dir := guardWriteCorpusTree(t, map[string]string{
			"licences/synthetic.yaml": `
id: licence.synthetic
spdx_id: Synthetic-1.0
name: Synthetic Licence 1.0
family: permissive
osi_approved: false
fsf_libre: false
permissiveness: 3
obligations: []
traps:
  - id: trap.synthetic-entry
    title: "A synthetic entry trap"
    summary: "A trap attached to a licence entry, whose summary is long enough."
    when:
      op: "=="
      field: dep.kind
      value: weights
    scope: graph
    severity: BLOCK
    confidence: HIGH
    citation:
      url: https://example.test/synthetic
      section: "Clause 1"
citation:
  url: https://example.test/synthetic
  section: "Synthetic Licence"
confidence: HIGH
last_verified: "2026-09-20"
`,
		})

		_, err := corpus.Load(corpus.LoadOptions{Dir: dir, Today: guardToday})
		if err == nil {
			t.Fatal("a licence-attached trap declaring `scope: graph` loaded " +
				"successfully.\nSuch a trap has exactly one dependency to be " +
				"evaluated against, so no graph check can be looking for it, and " +
				"the engine skips it in the per-dependency pass. It would be inert.")
		}
		if cerr.CodeOf(err) != cerr.ECorpus004 {
			t.Fatalf("the misplaced graph scope produced %v, not E-CORPUS-004.", err)
		}
	})
}

// ── notice codes ─────────────────────────────────────────────────────────────

// TestCorpusNoticeCodesMatchTheirDeclaredMeaning asserts that every code the
// loader attaches to a Notice is a code the taxonomy documents for that notice,
// and pins the meaning of the code that was wrongly borrowed.
//
// # THE DEFECT THIS EXISTS TO CATCH
//
// The loader announced "loaded without a previous corpus version; confidence
// rises could not be compared" under E-CORPUS-007, whose declared meaning — in
// the constant comment, in the table in internal/cerr/code.go, and in both
// PLAN/02-SPECIFICATIONS/09-error-taxonomy.md and
// PLAN/01-ARCHITECTURE/05-corpus-architecture.md — is "a citation URL is
// unreachable in the CI liveness check". Two unrelated conditions shared one
// code, and the notice's own words contradicted the message the table says that
// code renders. The loader wanted a code for a condition the taxonomy had none
// for, and the correct fix was to add E-CORPUS-012 rather than borrow a code
// that already meant something else: codes are never reused (ADR-008, and the
// package comment on internal/cerr/code.go).
//
// The two assertions at the end are the ratchet. They pin the *declared*
// meaning of E-CORPUS-007 and E-CORPUS-012, so the collision cannot be
// reintroduced by quietly reassigning either code — the way a future maintainer
// might, having seen the loader emit the wrong one and mistaking the code for
// the bug.
func TestCorpusNoticeCodesMatchTheirDeclaredMeaning(t *testing.T) {
	// The shipped corpus is loaded with no Previous version, which is exactly
	// the state in which the loader cannot run the cross-version half of INV-8
	// and must say so.
	c := guardLoadCorpus(t)

	var sawNoPrevious bool
	for _, n := range c.Notices {
		spec, ok := cerr.Lookup(cerr.Code(n.Code))
		if !ok {
			t.Errorf("a corpus notice carries %q, which is not in the error "+
				"taxonomy.\nA code a stranger cannot look up is the failure INV-5 "+
				"exists to prevent.\nNotice: %s", n.Code, n.Message)
			continue
		}
		if spec.Domain != "corpus" {
			t.Errorf("a corpus notice carries %s, whose declared domain is %q, "+
				"not 'corpus'.\nNotice: %s", n.Code, spec.Domain, n.Message)
		}

		if strings.Contains(n.Message, "without a previous corpus version") {
			sawNoPrevious = true
			if n.Code != string(cerr.ECorpus012) {
				t.Errorf("the 'no previous corpus version' notice is emitted as %s, "+
					"not E-CORPUS-012.\nE-CORPUS-012 is the code the taxonomy documents "+
					"for exactly this condition, and borrowing another code makes the "+
					"notice impossible to look up.\nNotice: %s", n.Code, n.Message)
			}
		}
	}
	if !sawNoPrevious {
		t.Fatal("the loader produced no 'no previous corpus version' notice when " +
			"loaded without a Previous version.\nThe notice is the whole point: an " +
			"INV-8 check that did not run must be announced, not left silent.")
	}

	// E-CORPUS-007 must keep meaning the citation-liveness condition. If a
	// future change repoints it at the INV-8 notice, this fails and says why.
	seven, ok := cerr.Lookup(cerr.ECorpus007)
	if !ok {
		t.Fatal("E-CORPUS-007 is no longer in the taxonomy; the citation-liveness " +
			"check has lost the code both PLAN documents record for it")
	}
	if !strings.Contains(seven.Message, "Citation URL") {
		t.Errorf("E-CORPUS-007 no longer describes an unreachable citation URL; its "+
			"message is %q.\nThat meaning is what PLAN/02-SPECIFICATIONS/09-error-taxonomy.md "+
			"and PLAN/01-ARCHITECTURE/05-corpus-architecture.md both record for it.",
			seven.Message)
	}

	// And E-CORPUS-012 must keep describing the missing previous version.
	twelve, ok := cerr.Lookup(cerr.ECorpus012)
	if !ok {
		t.Fatal("E-CORPUS-012 is not in the taxonomy; the INV-8 'no previous " +
			"version' notice has no code to render under")
	}
	if !strings.Contains(twelve.Message, "previous corpus version") {
		t.Errorf("E-CORPUS-012's declared message does not describe a missing "+
			"previous corpus version: %q", twelve.Message)
	}
}

// sortedKeys returns a map's keys, sorted, so that a failure lists them in a
// stable order (INV-6 applies to test output too).
func sortedKeys(m map[string]bool) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// TestShippedBundleIsACurrentCompileOfTheSource is the ratchet over the release
// artefact — the thing that actually ships and that nothing else looks at.
//
// # THE GAP IT CLOSES
//
// Every other corpus guard loads the YAML tree (guardLoadCorpus) and evaluates
// fixtures against it. That is the right source of truth, but it means the
// signed bundle goreleaser copies into every archive — corpus-dist/corpus.json —
// is exercised by no test at all. The release workflow only checks that the
// three files exist. A bundle compiled before a corpus edit therefore passes
// every gate, ships, and is discovered by a user.
//
// That is not hypothetical. On 25 September 2026 the bundle on disk was a
// compile of an older corpus: it carried an un-narrowed
// trap.licence.absent-all-rights-reserved that fired on brand-asset nodes and
// raised a false "no licence declared" BLOCK against a vendored TRADEMARK.md.
// Against that bundle, brand-assets-internal — the fixture that exists
// precisely to prove the `distributed` gate — produced SHIP CONDITIONAL where
// its own expected.yml says SHIP. The suite passed anyway, because it never
// read the bundle.
//
// # WHY BYTE EQUALITY IS BOTH THE STRONGEST AND A STABLE CHECK
//
// MarshalPayload is deterministic and date-independent: `Today` reaches only
// validation (validateEntry / validateToS), and StalenessDowngrade is applied at
// evaluation time by the policy engine, never during a load. So the payload is a
// pure function of the YAML tree, and comparing it byte for byte cannot go
// flaky. A field-by-field comparison would have to be told what to look at, and
// the field that goes missing is always the one nobody thought to list — which
// is how `excerpt_kind` was lost (see
// internal/corpus/bundle_roundtrip_test.go).
func TestShippedBundleIsACurrentCompileOfTheSource(t *testing.T) {
	payloadPath := filepath.Join(moduleRoot(t), "corpus-dist", "corpus.json")

	shipped, err := os.ReadFile(payloadPath)
	if err != nil {
		if os.IsNotExist(err) {
			// corpus-dist/ is a release artefact and git-ignored, so a fresh
			// clone and most CI jobs legitimately do not have it. This is a
			// skip rather than a pass: the check runs wherever the bundle
			// exists, which is the maintainer's machine and the release job —
			// the only two places a stale bundle can ship from.
			t.Skip("corpus-dist/ is not present; build it with `make corpus-dist` to run this check")
		}
		t.Fatalf("reading %s: %v", payloadPath, err)
	}

	want := corpus.MarshalPayload(guardLoadCorpus(t))
	if bytes.Equal(shipped, want) {
		return
	}

	// Name the likely cause before the numbers, because "differs by 1454 bytes"
	// is not actionable and "you edited the corpus and did not rebuild" is.
	t.Errorf("corpus-dist/corpus.json is not a compile of the current corpus source.\n"+
		"  shipped: %d bytes, sha256 %s\n"+
		"  source:  %d bytes, sha256 %s\n"+
		"The bundle is what a release ships and the YAML tree is what every other "+
		"guard reads, so the two can disagree with the whole suite green. Rebuild "+
		"and re-sign it (07-OPERATIONS/03-runbooks.md RUNBOOK 2):\n"+
		"  make corpus-dist CORPUS_KEY=<offline key> CORPUS_VERSION=<version>",
		len(shipped), corpus.Digest(shipped), len(want), corpus.Digest(want))
}
