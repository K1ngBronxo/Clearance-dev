// Package clearance_test holds the architectural guard.
//
// # WHY THIS FILE EXISTS
//
// The dependency rule is: a layer may import only from layers below it, never
// upward. It was written down long before it was enforced, and the text that
// stated it also said the enforcement was the whole point — that a parse of the
// import graph which fails the build on any upward import is the single most
// valuable structural test in the repository, because it is what stops a
// pipeline from becoming a mud ball.
//
// The file did not exist. The rule was documented and unenforced, which is the
// state in which architecture rots: every violation is individually reasonable,
// and the shape is only visible in aggregate.
//
// This test is deliberately mechanical. It does not know what any package does;
// it knows only which layer each package belongs to and refuses an import that
// points upward. That is the whole job.
//
// # Self-reference
//
// The guard necessarily contains the strings it searches for — "net/http" among
// them — and it lives in a directory that the walk also visits. Both are
// handled explicitly rather than by a clever trick, because a guard with a
// subtle blind spot is worse than no guard: it certifies what it does not
// check.
package clearance_test

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// modulePath is the prefix stripped from import paths to leave an
// intra-module path such as "internal/policy".
const modulePath = "github.com/clearance-dev/clearance/"

// self is this file, relative to the module root. It is excluded from the
// net/http scan because it names the string it searches for; including it
// would make the test fail on itself, which teaches nothing.
const self = "internal/arch_test.go"

// The layers, 0..5, in the order the architecture defines them.
const (
	layerPrimitives = 0
	layerDiscovery  = 1
	layerKnowledge  = 2
	layerDecision   = 3
	layerRender     = 4
	layerInterface  = 5
)

// layers assigns every package in the module to a layer.
//
// A package that is not listed here fails TestArchitectureLayering. That is the
// point: adding a package should require a deliberate decision about where it
// sits, and the failure message is the reminder.
//
// # Two packages are listed that do not exist yet
//
// `internal/confidence` (L3) and `internal/obligations` (L2) are named in the
// plan's layer diagram but are still empty directories. They are pre-assigned
// so that when they are implemented the classification is already made. The
// test only checks one direction — discovered packages must be assigned — so
// listing a package that is not there is harmless, and it documents intent.
var layers = map[string]int{
	// L0 — primitives. See the note on same-layer imports in
	// checkLayeringIsNeverViolated for why these may import each other.
	"internal/cerr":     layerPrimitives,
	"internal/cite":     layerPrimitives,
	"internal/config":   layerPrimitives,
	"internal/expr":     layerPrimitives,
	"internal/graph":    layerPrimitives,
	"internal/prov":     layerPrimitives,
	"internal/safefs":   layerPrimitives,
	"internal/safejson": layerPrimitives,
	"internal/safeyaml": layerPrimitives,

	// L1 — discovery.
	"internal/parsers": layerDiscovery,
	"internal/scanner": layerDiscovery,

	// L2 — knowledge.
	"internal/corpus":      layerKnowledge,
	"internal/obligations": layerKnowledge,
	"internal/policyfile":  layerKnowledge,

	// L3 — decision.
	"internal/confidence": layerDecision,
	"internal/policy":     layerDecision,
	"internal/verdict":    layerDecision,

	// L4 — render. `ai` sits here because it consumes a Verdict (L3) and
	// produces an artefact: a suggestion, which is rendered separately and is
	// never part of the verdict. It is pure, and the purity check below names
	// it, because the spec's two load-bearing AI tests need a stub transport
	// and a package that opened its own sockets could not be tested that way.
	"internal/ai":     layerRender,
	"internal/report": layerRender,

	// L5 — interface.
	"internal/cli":  layerInterface,
	"internal/mcp":  layerInterface,
	"cmd/clearance": layerInterface,
}

// impureImports are packages that read or write the world. The plan confines
// them to L0, L1 and L5 (§1.2): "everything at L3 and above is pure — no
// filesystem, no network, no clock, no randomness".
//
// `time` is deliberately absent from this list even though it looks impure.
// `time.Parse` is a pure function over a string — internal/policy uses it to
// compare two dates and reads no clock. Banning the import would forbid the
// pure use along with the impure one, so the clock itself is caught by
// checkDecisionLayerReadsNoClock instead.
var impureImports = map[string]string{
	"os":        "filesystem and environment access",
	"net":       "network access",
	"net/http":  "network access",
	"os/exec":   "process execution",
	"syscall":   "direct system calls",
	"io/fs":     "filesystem traversal",
	"math/rand": "non-deterministic output",
	"plugin":    "dynamic code loading",
}

// TestArchitectureLayering is the single entry point, named to match the
// `make arch` target, which runs exactly this test.
//
// The subtests are separate functions rather than one long body so that a
// failure names the rule it broke. "TestArchitectureLayering failed" is not a
// useful message; "OnlyOneFileImportsNetHTTP failed, and here is the file" is.
func TestArchitectureLayering(t *testing.T) {
	t.Run("EveryPackageHasALayer", checkEveryPackageHasALayer)
	t.Run("LayeringIsNeverViolated", checkLayeringIsNeverViolated)
	t.Run("DecisionAndRenderLayersArePure", checkDecisionAndRenderLayersArePure)
	t.Run("DecisionLayerReadsNoClock", checkDecisionLayerReadsNoClock)
	t.Run("OnlyOneFileImportsNetHTTP", checkOnlyOneFileImportsNetHTTP)
	t.Run("ScannerNeverExecutesAnything", checkScannerNeverExecutesAnything)
}

// checkEveryPackageHasALayer is the forcing function. Without it, a new package
// is simply unclassified, and an unclassified package is one that can import
// anything — which is how a layered design quietly becomes a single layer.
func checkEveryPackageHasALayer(t *testing.T) {
	root := moduleRoot(t)
	packages := packageDirs(t, root)

	for _, pkg := range packages {
		if _, ok := layers[pkg]; !ok {
			t.Errorf("package %q is not assigned a layer.\n"+
				"Add it to the `layers` map in internal/arch_test.go, choosing the\n"+
				"layer the table in this file assigns to it.\n"+
				"The layer you pick determines which packages it may import.", pkg)
		}
	}
}

// checkLayeringIsNeverViolated is the rule itself: no package may import a
// package that sits above it.
//
// # Two literal readings of the plan are not enforceable, and this test does
// # not pretend otherwise
//
//  1. §1.1 says L0 "may import Go stdlib only — never any other internal
//     package". That cannot hold: `cerr` is L0, and every other L0 package
//     imports it. `config` imports `cerr`, `safefs` and `safeyaml`; `cite`
//     imports `cerr`. A layer whose members may not reference each other is
//     not a layer, it is a set of isolated packages. The workable reading,
//     applied here, is that L0 is *closed*: a member may import other L0
//     members, never anything above.
//
//  2. §1.1 says L5 "may never import L1 internals, L2 internals", and the
//     layer diagram says "May depend on: L4. Never on internals." But §2's own
//     sequence diagram for one `clearance check .` shows the CLI calling
//     `config` (L0), `scanner` (L1) and `corpus` (L2). A composition root that
//     cannot name the things it composes is not a composition root. The
//     workable reading is that L5 may import any layer below it.
//
//  3. §1.1's prose says "only from layers strictly below it", but the same
//     table puts `scanner` and `parsers` both at L1, and `scanner` calls
//     `parsers`. Same-layer imports are therefore allowed.
//
// All three readings are recorded rather than silently applied, because a rule
// that is quietly relaxed in code and left absolute in the docs is a rule that
// gets re-litigated by every new contributor.
//
// What remains, and is enforced, is the invariant that actually matters and
// that no reading of the plan disputes: **imports never point upward.**
func checkLayeringIsNeverViolated(t *testing.T) {
	root := moduleRoot(t)
	graph := importGraph(t, root)

	// Deterministic order: a map iteration would report violations in a
	// different order on every run, and INV-6 applies to test output too.
	pkgs := make([]string, 0, len(graph))
	for pkg := range graph {
		pkgs = append(pkgs, pkg)
	}
	sort.Strings(pkgs)

	for _, pkg := range pkgs {
		from, known := layers[pkg]
		if !known {
			continue // checkEveryPackageHasALayer reports this.
		}
		for _, imported := range graph[pkg] {
			to, known := layers[imported]
			if !known {
				continue // Not an internal package: stdlib or third party.
			}
			if to > from {
				t.Errorf("layer violation: %s (L%d) imports %s (L%d).\n"+
					"An import may only point down or sideways, never up.\n"+
					"See the `layers` map in this file.",
					pkg, from, imported, to)
			}
		}
	}
}

// checkDecisionAndRenderLayersArePure enforces the purity boundary of §1.2.
//
// This is what makes the verdict reproducible: a decision layer that cannot
// read the clock or the filesystem cannot produce two different answers from
// the same input, and it can be unit-tested with in-memory literals and no
// fixtures on disk.
//
// This test caught a real breach. `internal/report` (L4) imported `os` to read
// NO_COLOR and TERM and to stat its writer, so that it could decide whether to
// emit ANSI colour. The probe moved to `internal/cli/tty.go` (L5, where the
// plan already confines I/O) and the renderer now takes `Options{Color: bool}`.
func checkDecisionAndRenderLayersArePure(t *testing.T) {
	root := moduleRoot(t)
	graph := importGraphProduction(t, root)

	for _, pkg := range []string{"internal/policy", "internal/verdict", "internal/report", "internal/ai"} {
		for _, imported := range graph[pkg] {
			if why, bad := impureImports[imported]; bad {
				t.Errorf("%s (L3+) imports %q — %s.\n"+
					"The purity boundary\n"+
					"confines I/O to L0, L1 and L5. Pass the value in as a parameter\n"+
					"instead, and let the L5 caller do the I/O.", pkg, imported, why)
			}
		}
	}
}

// checkDecisionLayerReadsNoClock closes the gap left by allowing the `time`
// import: `time.Parse` is pure and needed, `time.Now` is a clock read and is
// not.
//
// A verdict that depends on the wall clock is a verdict that cannot be
// reproduced, which breaks INV-6 and makes a disputed verdict undebatable —
// the user and the tool would disagree about what day it was.
//
// # WHY THIS PARSES RATHER THAN SEARCHES
//
// The first version of this guard read each file as text and looked for the
// substring "time.Now(". It worked, and it was wrong in both directions:
//
//   - It failed on a *comment*. internal/report/sbom.go documents that the
//     exporter must not call time.Now, and writing that sentence turned the
//     build red. The available fixes were to delete the explanation or to
//     weaken the guard, and both are worse than fixing the guard — a guard
//     whose false positives cost you the sentence you most wanted to write is a
//     guard that gets deleted.
//   - It passed on a *reference*. `f := time.Now` reads the clock and does not
//     contain the string "time.Now(".
//
// The AST sees what the compiler sees, so it has neither problem. It is the
// same lesson the scanner's own design draws for itself: a regex matches a
// comment, and the difference between a
// regex and a parse is the difference between a false positive and a finding.
func checkDecisionLayerReadsNoClock(t *testing.T) {
	root := moduleRoot(t)

	// The impure members of the time package. Sleep and AfterFunc block or
	// schedule, which makes a verdict depend on real elapsed time.
	impure := map[string]bool{
		"Now": true, "Since": true, "Until": true, "Tick": true,
		"After": true, "NewTimer": true, "NewTicker": true,
		"AfterFunc": true, "Sleep": true,
	}

	for _, pkg := range []string{"internal/policy", "internal/verdict", "internal/report", "internal/ai"} {
		dir := filepath.Join(root, filepath.FromSlash(pkg))
		entries, err := os.ReadDir(dir)
		if err != nil {
			t.Fatalf("read %s: %v", dir, err)
		}
		for _, e := range entries {
			if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
				continue
			}
			path := filepath.Join(dir, e.Name())
			fset := token.NewFileSet()
			file, err := parser.ParseFile(fset, path, nil, 0)
			if err != nil {
				t.Fatalf("parse %s: %v", e.Name(), err)
			}

			ast.Inspect(file, func(n ast.Node) bool {
				sel, ok := n.(*ast.SelectorExpr)
				if !ok {
					return true
				}
				ident, ok := sel.X.(*ast.Ident)
				if !ok || ident.Name != "time" {
					return true
				}
				// An import alias or a local variable named `time` would be a
				// false positive, and a shadowed `time` would be a false
				// negative for the real package. Neither is worth solving here:
				// the guard's job is to catch the obvious call, and a deliberate
				// evasion of an architectural guard is a different problem from
				// an accidental one.
				if !impure[sel.Sel.Name] {
					return true
				}
				t.Errorf("%s/%s calls time.%s at line %d.\n"+
					"The decision layer must be a pure function of its inputs.\n"+
					"Take the date as a parameter — corpus.LoadOptions.Today is the\n"+
					"existing precedent — rather than reading the clock.",
					pkg, e.Name(), sel.Sel.Name, fset.Position(sel.Pos()).Line)
				return true
			})
		}
	}
}

// checkOnlyOneFileImportsNetHTTP enforces the scoped form of INV-3 that ADR-021
// settled on: the scanner (L0–L4) never phones home, and exactly one file is
// permitted to open a socket at all.
//
// The invariant is "the scanner never phones home", and the mechanism is "no
// package in L0–L4 may import net/http". Pinning the mechanism to a *count* of
// one, and naming the file, means a second network client cannot be added
// without this test saying so.
func checkOnlyOneFileImportsNetHTTP(t *testing.T) {
	root := moduleRoot(t)
	const allowed = "internal/cli/netclient.go"

	var found []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			// Skip anything that is not the module's own source.
			if d.Name() == "testdata" || d.Name() == "dist" || d.Name() == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(d.Name(), ".go") {
			return nil
		}
		rel, relErr := filepath.Rel(root, path)
		if relErr != nil {
			return relErr
		}
		relSlash := filepath.ToSlash(rel)
		if relSlash == self {
			return nil // This guard names the string it searches for.
		}
		src, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		if strings.Contains(string(src), `"`+"net/http"+`"`) {
			found = append(found, relSlash)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk: %v", err)
	}
	sort.Strings(found)

	if len(found) == 0 {
		t.Fatalf("no file imports net/http; %s is missing, "+
			"so the corpus-update feature cannot work", allowed)
	}
	for _, f := range found {
		if f != allowed {
			t.Errorf("%s imports net/http.\n"+
				"Exactly one file may: %s.\n"+
				"INV-3 as scoped by ADR-021: the scanner (L0–L4) never phones home.\n"+
				"Route the call through the single client so that every outbound\n"+
				"request passes one host allowlist.", f, allowed)
		}
	}
}

// checkScannerNeverExecutesAnything enforces INV-3's most important clause: the
// scanner reports what a project *declares*, and never runs it.
//
// `os/exec` would let a manifest trigger a build step; `syscall` and `plugin`
// are the same capability by other routes. This is checked here as well as in
// the Makefile lint because the Makefile lint only runs when someone remembers
// to run it, and this runs on every `go test`.
func checkScannerNeverExecutesAnything(t *testing.T) {
	root := moduleRoot(t)
	graph := importGraph(t, root)

	for _, imported := range graph["internal/scanner"] {
		switch imported {
		case "os/exec", "syscall", "plugin", "unsafe":
			t.Errorf("internal/scanner imports %q.\n"+
				"The scanner reads declarations. It must never execute, load or\n"+
				"install anything it finds (INV-3).", imported)
		}
	}
}

// ── helpers ─────────────────────────────────────────────────────────────────

// moduleRoot walks up from the test's working directory until it finds go.mod.
//
// It does not assume a fixed depth: `go test ./internal` runs with the working
// directory set to internal/, but the file is also reachable from a repo-wide
// `go test ./...`, and hardcoding ".." would make this test pass or fail for a
// reason that has nothing to do with architecture.
func moduleRoot(t *testing.T) string {
	t.Helper()
	dir, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	for {
		if _, statErr := os.Stat(filepath.Join(dir, "go.mod")); statErr == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("walked to the filesystem root without finding go.mod")
		}
		dir = parent
	}
}

// packageDirs returns every directory in the module that is a real Go package,
// as a slash-separated path relative to the module root.
//
// A directory counts as a package only if it holds at least one non-test .go
// file. That rule does two jobs: it skips the planned-but-empty directories
// (`internal/confidence`, `internal/obligations`), and it skips `internal/`
// itself, which contains only this guard. A directory with no importable
// package cannot be imported, so it has no layer to get wrong.
func packageDirs(t *testing.T, root string) []string {
	t.Helper()
	hasSource := map[string]bool{}

	for _, top := range []string{"internal", "cmd"} {
		base := filepath.Join(root, top)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
				return nil
			}
			if strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}
			rel, relErr := filepath.Rel(root, filepath.Dir(path))
			if relErr != nil {
				return relErr
			}
			hasSource[filepath.ToSlash(rel)] = true
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}

	out := make([]string, 0, len(hasSource))
	for pkg := range hasSource {
		out = append(out, pkg)
	}
	sort.Strings(out)
	return out
}

// importGraph maps each package to the set of intra-module packages it
// imports, including imports from _test.go files.
//
// Test files are included deliberately. A test is code in the package, and a
// test that reaches up a layer is the same design smell as a source file that
// does — usually worse, because tests are where a shortcut is most tempting
// and least reviewed.
func importGraph(t *testing.T, root string) map[string][]string {
	t.Helper()
	return importGraphFiltered(t, root, true)
}

// importGraphProduction is importGraph without _test.go files.
//
// The purity rule asks what the *shipped* code imports; a golden-file test
// harness legitimately reads and writes files, and including it would make the
// rule unachievable for any package that has one. The layering rule keeps
// including test files — a test that reaches up a layer is still a design
// smell — so only the purity check uses this narrower graph.
func importGraphProduction(t *testing.T, root string) map[string][]string {
	t.Helper()
	return importGraphFiltered(t, root, false)
}

func importGraphFiltered(t *testing.T, root string, includeTests bool) map[string][]string {
	t.Helper()
	out := map[string][]string{}

	for _, top := range []string{"internal", "cmd"} {
		base := filepath.Join(root, top)
		err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if d.IsDir() || !strings.HasSuffix(d.Name(), ".go") {
				return nil
			}
			if !includeTests && strings.HasSuffix(d.Name(), "_test.go") {
				return nil
			}

			relDir, relErr := filepath.Rel(root, filepath.Dir(path))
			if relErr != nil {
				return relErr
			}
			pkg := filepath.ToSlash(relDir)

			// ImportsOnly: the import graph is the whole question, so there is
			// no reason to build an AST for the bodies.
			f, parseErr := parser.ParseFile(token.NewFileSet(), path, nil, parser.ImportsOnly)
			if parseErr != nil {
				return parseErr
			}
			for _, spec := range f.Imports {
				imported := strings.Trim(spec.Path.Value, `"`)

				// EVERY import is recorded, not only the intra-module ones.
				//
				// An earlier version skipped anything not prefixed with the
				// module path, on the theory that stdlib imports were not the
				// layering check's business. But the purity check *is* about
				// stdlib imports — it looks for "os", "net/http", "os/exec" —
				// and the scanner check looks for "syscall" and "plugin". With
				// those filtered out, three of the six rules in this file could
				// never fire. Verified: the purity test passed against a
				// deliberate `import _ "os"` in internal/verdict.
				//
				// A guard that cannot fail is worse than no guard, because it
				// certifies what it does not check.
				imported = strings.TrimPrefix(imported, modulePath)
				out[pkg] = append(out[pkg], imported)
			}
			return nil
		})
		if err != nil {
			t.Fatalf("walk %s: %v", base, err)
		}
	}

	for pkg := range out {
		out[pkg] = dedupeSorted(out[pkg])
	}
	return out
}

// dedupeSorted removes duplicates and sorts. Duplicates arise because two
// files in one package may import the same dependency; sorting keeps the
// reported violation order stable across runs (INV-6).
func dedupeSorted(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	sort.Strings(in)
	out := in[:1]
	for _, s := range in[1:] {
		if s != out[len(out)-1] {
			out = append(out, s)
		}
	}
	return out
}
