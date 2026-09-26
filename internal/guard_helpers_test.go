// Guard-test helpers. See guard_invariants_test.go and guard_security_test.go.
//
// # WHY THE GUARD TESTS LIVE HERE
//
// The guards are properties of the whole system, not of one package: INV-1 is a
// claim about the path from a manifest on disk to a rendered finding, and no
// single package can assert it. So they sit in `internal/`, next to
// arch_test.go, as an external test package (`clearance_test`) that may import
// every layer and may reach into none of their internals.
//
// That constraint is deliberate. A guard that can only use exported APIs is a
// guard that fails when the exported contract breaks, which is the contract the
// product actually promises. `internal/` holds no non-test Go file, so
// packageDirs in arch_test.go does not see a package here and no layer entry is
// needed.
//
// The two exceptions are named where they occur:
//
//   - TestNoUnexpectedEgress lives in internal/cli, because the egress policy
//     is unexported and must stay that way.
//   - The proof that the INV-1 gate can fail lives in internal/policy, because
//     resolveCitation is unexported. A guard that cannot fail is worse than no
//     guard, so the failure path is pinned rather than assumed.
package clearance_test

import (
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/mcp"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/scanner"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// guardToday is the date every guard test injects.
//
// Nothing in the guard suite may read the clock. A test that passes in
// September and fails in March because a `retrieved_at` crossed the 180-day
// staleness window is a test that reports a calendar event as a regression
// (INV-6).
const guardToday = "2026-09-23"

// guardLastVerifiedRe matches a `last_verified: "2026-09-25"` line in a corpus
// source file.
var guardLastVerifiedRe = regexp.MustCompile(`(?m)^\s*last_verified:\s*"?(\d{4}-\d{2}-\d{2})"?`)

// guardCorpusToday returns a date on or after every `last_verified` in the
// corpus at dir.
//
// # WHY THE SHIPPED CORPUS IS LOADED AT A DERIVED DATE, NOT AT guardToday
//
// guardToday is a fixed reference for corpora the tests write themselves: a
// fixture that pins the staleness rule dates its entry a known number of days
// before guardToday, and that arithmetic must not move. The shipped corpus is
// different — its dates are real, and a new entry verified after guardToday
// would fail E-CORPUS-008 ("last_verified is in the future"), turning a
// legitimate corpus edit into a red guard suite. Deriving the load date from
// the corpus removes that coupling without moving guardToday, so fixture
// corpora keep their fixed reference and the shipped one cannot be broken by
// adding a current entry. No guard reads the clock (INV-6).
func guardCorpusToday(t *testing.T, dir string) string {
	t.Helper()
	newest := ""
	walkErr := filepath.WalkDir(dir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		switch strings.ToLower(filepath.Ext(path)) {
		case ".yaml", ".yml":
		default:
			return nil
		}
		b, readErr := os.ReadFile(path)
		if readErr != nil {
			return readErr
		}
		for _, m := range guardLastVerifiedRe.FindAllStringSubmatch(string(b), -1) {
			if m[1] > newest { // ISO-8601 days compare lexicographically
				newest = m[1]
			}
		}
		return nil
	})
	if walkErr != nil {
		t.Fatalf("scanning %s for last_verified dates: %v", dir, walkErr)
	}
	if newest == "" {
		t.Fatalf("%s declares no last_verified date; the guard cannot derive a Today", dir)
	}
	return newest
}

// guardPlanFile resolves a path inside PLAN/.
//
// The plan is NOT inside the Go module: the repository is laid out as
//
//	DESIGN/  PLAN/  clearance/   <- the module is a sibling of the plan
//
// so a test running with its working directory inside the module has to look
// one level up. Both locations are tried, and a miss is fatal with the list of
// places that were tried — the same discipline resolveCorpusDir applies to the
// corpus, for the same reason: "not found" without saying where you looked is a
// failure nobody can act on.
//
// The one exception is a distribution that ships without the plan at all —
// which is what the public repository is, because the plan is deliberately not
// published. There is no evidence to check against, so the test skips rather
// than passes: a guard that went green with nothing behind it would be worse
// than one that did not run, and a skip is visible in the output while a
// silently passing guard is not. Where PLAN/ IS present — every maintainer
// checkout — a missing file stays fatal, so a typo in a citation path can never
// turn into a skip.
func guardPlanFile(t *testing.T, rel string) string {
	t.Helper()
	root := moduleRoot(t)
	dirs := []string{
		filepath.Join(root, "PLAN"),
		filepath.Join(root, "..", "PLAN"),
	}
	tried := make([]string, 0, len(dirs))
	planPresent := false
	for _, d := range dirs {
		if fi, err := os.Stat(d); err == nil && fi.IsDir() {
			planPresent = true
		}
		c := filepath.Join(d, filepath.FromSlash(rel))
		tried = append(tried, c)
		if _, err := os.Stat(c); err == nil {
			return c
		}
	}
	if !planPresent {
		t.Skipf("PLAN/ is not part of this distribution, so %s cannot be checked here. "+
			"The plan-anchored guards run in a maintainer checkout. Tried:\n  %s",
			rel, strings.Join(tried, "\n  "))
	}
	t.Fatalf("PLAN/%s not found. Tried:\n  %s", rel, strings.Join(tried, "\n  "))
	return ""
}

// guardCorpusPath is the corpus that ships with the binary, relative to the
// module root. It is the same corpus the binary resolves next to itself.
func guardCorpusPath(t *testing.T) string {
	t.Helper()
	dir := filepath.Join(moduleRoot(t), "corpus")
	if _, err := os.Stat(dir); err != nil {
		t.Fatalf("the shipped corpus is missing at %s: %v", dir, err)
	}
	return dir
}

// guardLoadCorpus loads the shipped corpus, failing the test if it does not
// load. Every guard that needs judgement needs it, and a guard that skipped
// because the corpus was absent would be a guard that proved nothing.
func guardLoadCorpus(t *testing.T) *corpus.Corpus {
	t.Helper()
	dir := guardCorpusPath(t)
	c, err := corpus.Load(corpus.LoadOptions{Dir: dir, Today: guardCorpusToday(t, dir)})
	if err != nil {
		t.Fatalf("loading the shipped corpus: %v", err)
	}
	return c
}

// guardFixtureCorpus returns the corpus a fixture is to be evaluated against.
//
// A fixture MAY ship its own corpus, in a `corpus/` subdirectory. If it does,
// that corpus is used; otherwise the shipped corpus is.
//
// # WHY A FIXTURE WOULD EVER WANT ITS OWN
//
// Two of the corpus's rules are about the corpus rather than about the project:
// the staleness downgrade (a ToS summary older than its window loses a
// confidence level) and the correction gate (a confidence may not be raised
// without a recorded correction). A fixture that wants to pin either of them
// needs a corpus whose `last_verified` is a known number of days before
// guardToday — and there is no way to write that into the shipped corpus
// without ageing every other fixture's expectations at the same time, or
// without the test quietly changing meaning as the calendar moves.
//
// So the fixture supplies the data the rule is about. That is the same trade
// the corpus itself makes: judgement lives in data, and a test of the judgement
// supplies the data.
//
// The directory is `corpus/` and not something cleverer because it is the same
// name the binary looks for next to itself, so a reader who knows the product
// already knows what the directory is.
func guardFixtureCorpus(t *testing.T, dir string) *corpus.Corpus {
	t.Helper()

	local := filepath.Join(dir, "corpus")
	if _, err := os.Stat(local); err != nil {
		return guardLoadCorpus(t)
	}

	c, err := corpus.Load(corpus.LoadOptions{Dir: local, Today: guardToday})
	if err != nil {
		t.Fatalf("loading the fixture-local corpus at %s: %v\n"+
			"A fixture that ships its own corpus is asserting something about the "+
			"corpus rules, so a corpus that does not load is the failure, not a "+
			"reason to fall back to the shipped one.", local, err)
	}
	return c
}

// guardFixtureDirs returns every fixture directory, sorted.
//
// The fixtures are the executable specification of the traps: each is a
// minimal project plus the verdict it must produce. Sorting is required because
// a walk's order is not a contract and the failure output must be stable
// (INV-6).
func guardFixtureDirs(t *testing.T) []string {
	t.Helper()
	base := filepath.Join(moduleRoot(t), "fixtures")
	entries, err := os.ReadDir(base)
	if err != nil {
		t.Fatalf("reading fixtures/: %v", err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() {
			out = append(out, filepath.Join(base, e.Name()))
		}
	}
	sort.Strings(out)
	if len(out) == 0 {
		t.Fatal("fixtures/ holds no fixture directories; the guard suite would pass by " +
			"walking nothing, which is the failure mode it exists to prevent")
	}
	return out
}

// guardRun is the whole product pipeline, in the order the CLI runs it:
// intent, then corpus, then scan, then evaluate, then fold.
//
// It deliberately does not go through the CLI. The CLI is tested on its own
// terms in internal/cli; what the guards need is the engine, and building the
// pipeline here keeps them independent of flag parsing.
//
// It returns the verdict even when an error occurs, so a caller can assert on
// both. A caller that only wants the happy path uses guardMustRun.
func guardRun(t *testing.T, projectDir string, c *corpus.Corpus, opts policy.Options) (verdict.Verdict, error) {
	t.Helper()
	v, _, err := guardRunDetailed(t, projectDir, c, opts)
	return v, err
}

// guardDiagnostics is everything the pipeline said that is not a finding.
//
// The two lists are kept apart rather than merged because they have different
// origins and different codes: a Warning comes from the scanner (something it
// could not read or could not identify), a Notice comes from the evaluation
// (something it read and has nothing to say about). Merging them would make a
// fixture unable to say which of the two fired.
type guardDiagnostics struct {
	Warnings []graph.Warning
	Notices  []corpus.Notice
}

// guardRunDetailed is guardRun plus the diagnostics.
//
// # WHY THE DIAGNOSTICS ARE PART OF THE RESULT
//
// Some of the product's most important statements are warnings or notices
// rather than findings, and a fixture could not see them before this existed.
//
// The clearest case is E-SCAN-021: a process spawn whose command name is not a
// literal. There is no clause to cite, so INV-1 makes a *finding*
// unrepresentable — but the tool must still say something, because a spawn it
// cannot identify is the difference between "no upstream tools" and "I could
// not tell what runs here". Silence there is a false pass.
//
// The second case is the spec's §7 row "platform detected, no corpus entry".
// The finding is deliberately a Notice rather than an INFO finding, for the
// same INV-1 reason, and a fixture that could only see findings would have
// asserted `findings: []` for a project that calls a tool the corpus has never
// heard of — which is exactly the fixture whose whole point is that the tool
// spoke up.
//
// A harness that could not see either list would let both be deleted by an
// edit, with every guard still green.
func guardRunDetailed(t *testing.T, projectDir string, c *corpus.Corpus, opts policy.Options) (verdict.Verdict, guardDiagnostics, error) {
	t.Helper()
	var diag guardDiagnostics

	cfg, err := config.Load(config.Options{
		WorkDir: projectDir,
		// "-" disables the user-level config. Without it, a guard test would
		// read the developer's own ~/.config/clearance/config.yml and could
		// pass or fail for a reason that has nothing to do with the code.
		UserConfigPath: "-",
	})
	if err != nil {
		return verdict.Verdict{}, diag, err
	}

	g, err := scanner.Scan(projectDir, scanner.Options{Intent: cfg.Intent})
	if err != nil {
		return verdict.Verdict{}, diag, err
	}
	diag.Warnings = g.Warnings

	if opts.Today == "" {
		opts.Today = guardToday
	}
	eval, err := policy.Evaluate(g, c, cfg.Intent, opts)
	if err != nil {
		return verdict.Verdict{}, diag, err
	}
	diag.Notices = eval.Notices

	v := verdict.Fold(verdict.Input{
		Findings:            eval.Findings,
		Undetermined:        eval.Undetermined,
		AllowMediumBlockers: opts.AllowMediumBlockers,
	})
	// The project name, not the project path. This mirrors cli.projectName, and
	// it matters: the verdict is a document a user pastes into a ticket, and an
	// absolute path in it leaks the user's directory layout (the privacy spine
	// asserts exactly that).
	v.Project = guardProjectName(cfg.Intent, projectDir)
	v.Summary.Dependencies = len(g.Dependencies)
	v.Summary.WeightFiles = g.CountWeights()
	v.Summary.UpstreamCLIs = g.CountUpstreamCLIs()
	v.Meta = verdict.Meta{
		ToolVersion:   "guard",
		CorpusVersion: c.Version,
		CorpusSigned:  c.Signed,
	}
	return v, diag, nil
}

// guardWarningCodes renders a warning list as sorted codes.
//
// Codes only, not messages: the message text is pinned by the error taxonomy
// and by TestEveryErrorCodeIsDocumented, and a fixture that pinned it would go
// red on a copy-edit. What the fixture is asserting is that the condition was
// *reported at all*, which is the code.
func guardWarningCodes(ws []graph.Warning) []string {
	out := make([]string, 0, len(ws))
	for _, w := range ws {
		out = append(out, w.Code)
	}
	sort.Strings(out)
	return out
}

// guardNoticeCodes renders a notice list as sorted codes, for the same reason.
func guardNoticeCodes(ns []corpus.Notice) []string {
	out := make([]string, 0, len(ns))
	for _, n := range ns {
		out = append(out, n.Code)
	}
	sort.Strings(out)
	return out
}

// guardProjectName mirrors cli.projectName. Duplicated rather than exported
// because exporting a naming helper from L5 so that a test can call it would
// invert the dependency for no gain.
func guardProjectName(in *config.Intent, root string) string {
	if in != nil && strings.TrimSpace(in.Project.Name) != "" {
		return in.Project.Name
	}
	return filepath.Base(root)
}

// guardMustRun is guardRun with the error turned into a fatal failure.
func guardMustRun(t *testing.T, projectDir string, c *corpus.Corpus, opts policy.Options) verdict.Verdict {
	t.Helper()
	v, err := guardRun(t, projectDir, c, opts)
	if err != nil {
		t.Fatalf("pipeline on %s: %v", projectDir, err)
	}
	return v
}

// guardAllFindings returns every finding in a verdict, in the order the verdict
// renders them, so a guard can iterate one list rather than three.
func guardAllFindings(v verdict.Verdict) []policy.Finding {
	out := make([]policy.Finding, 0, len(v.Blockers)+len(v.Conditions)+len(v.Notes))
	out = append(out, v.Blockers...)
	out = append(out, v.Conditions...)
	out = append(out, v.Notes...)
	return out
}

// guardWriteTree writes a map of slash-separated relative paths to contents
// under a fresh temporary directory and returns that directory.
//
// Parent directories are created. An empty value writes an empty file, which is
// how the "LICENSE exists but says nothing" case is expressed.
func guardWriteTree(t *testing.T, files map[string]string) string {
	t.Helper()
	root := t.TempDir()

	// Deterministic order, so that a failure caused by a partially written tree
	// is reported the same way every run.
	paths := make([]string, 0, len(files))
	for p := range files {
		paths = append(paths, p)
	}
	sort.Strings(paths)

	for _, rel := range paths {
		full := filepath.Join(root, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatalf("mkdir for %s: %v", rel, err)
		}
		if err := os.WriteFile(full, []byte(files[rel]), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	return root
}

// guardWriteCorpusTree writes a corpus source tree from a map of paths to
// contents and returns its root, so a guard can build a synthetic corpus that
// exercises a loader rule without touching the shipped one.
func guardWriteCorpusTree(t *testing.T, files map[string]string) string {
	t.Helper()
	return guardWriteTree(t, files)
}

// guardMCPServe drives the real MCP server in-process over buffers.
//
// # WHY THE SERVER AND NOT A CLIENT LIBRARY
//
// Because the guard is asserting a property of THIS server — that it refuses a
// path outside its declared root — and a client library would test the library.
// The server's contract is a byte stream in and a byte stream out, so the guard
// speaks that contract directly and needs no process, no port and no client.
//
// It returns the response lines verbatim, so a caller can assert on the raw
// protocol rather than on a decoded structure the test itself built.
//
// frames are written one per line, which is the transport's framing.
func guardMCPServe(t *testing.T, root, corpusDir string, frames []string) []string {
	t.Helper()

	srv, err := mcp.New(mcp.Options{
		Root:      root,
		CorpusDir: corpusDir,
		Today:     guardToday,
		Version:   "guard",
	})
	if err != nil {
		t.Fatalf("starting the MCP server over %s: %v", root, err)
	}

	in := strings.NewReader(strings.Join(frames, "\n") + "\n")
	var out strings.Builder

	// An error from Serve is a deliberate termination (E-MCP-001) or a
	// transport failure. Neither is fatal to the test: what the test asserts is
	// the responses that arrived before the stream ended, and a guard that
	// t.Fatal'd here could not check the refusal it just triggered.
	_ = srv.Serve(in, &out)

	var lines []string
	for _, line := range strings.Split(out.String(), "\n") {
		if strings.TrimSpace(line) != "" {
			lines = append(lines, line)
		}
	}
	return lines
}

// guardMCPFrame builds one tools/call frame with a JSON-encoded argument map.
//
// It marshals with encoding/json, which is what a real client does — the point
// of the guard is to send bytes a client would send, not bytes this codebase's
// own decoder would produce.
func guardMCPFrame(t *testing.T, id int, tool string, args map[string]any) string {
	t.Helper()
	msg := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  "tools/call",
		"params":  map[string]any{"name": tool, "arguments": args},
	}
	b, err := json.Marshal(msg)
	if err != nil {
		t.Fatalf("building an MCP frame: %v", err)
	}
	return string(b)
}
