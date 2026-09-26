// Tests for the process boundary: argument handling and corpus resolution.
//
// These two things live together because they are the two places where the CLI
// can be wrong in a way that no other package can catch. Everything below L5 is
// pure or root-scoped and is tested on its own terms; what is tested here is
// what the process does before any of that runs.
package cli

import (
	"flag"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestPermuteFlagsAllowsFlagsAfterThePath is the regression test for a real
// defect: `clearance check . --format json` used to fail with "check takes at
// most one path, got 3".
//
// Go's flag package stops parsing at the first token that does not begin with a
// hyphen, so everything after the path was treated as more paths. The error
// message described the symptom and pointed at nothing useful, which is the
// worst kind of failure: the user's command was correct and the tool blamed
// them for it.
func TestPermuteFlagsAllowsFlagsAfterThePath(t *testing.T) {
	newFS := func() (*flag.FlagSet, *string, *bool, *bool) {
		fs := flag.NewFlagSet("t", flag.ContinueOnError)
		format := fs.String("format", "human", "")
		verbose := fs.Bool("verbose", false, "")
		strict := fs.Bool("strict", false, "")
		return fs, format, verbose, strict
	}

	cases := []struct {
		name        string
		args        []string
		wantFormat  string
		wantVerbose bool
		wantStrict  bool
	}{
		{"flags before the path", []string{"--format", "json", "--verbose", "fixtures/x"}, "json", true, false},
		{"flags after the path", []string{"fixtures/x", "--format", "json", "--verbose"}, "json", true, false},
		{"flags on both sides", []string{"--verbose", "fixtures/x", "--format", "json"}, "json", true, false},
		{"bool flag adjacent to the path", []string{"--strict", "fixtures/x"}, "human", false, true},
		{"path between two bool flags", []string{"--verbose", "fixtures/x", "--strict"}, "human", true, true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			fs, format, verbose, strict := newFS()

			if err := fs.Parse(permuteFlags(fs, tc.args)); err != nil {
				t.Fatalf("Parse: %v", err)
			}
			if fs.NArg() != 1 || fs.Arg(0) != "fixtures/x" {
				t.Fatalf("positional args = %v, want exactly [fixtures/x]", fs.Args())
			}
			// Every flag is asserted in both directions. A permuter that set a
			// flag the user did not pass would be as wrong as one that dropped
			// a flag they did, and considerably harder to notice.
			if *format != tc.wantFormat {
				t.Errorf("--format = %q, want %q", *format, tc.wantFormat)
			}
			if *verbose != tc.wantVerbose {
				t.Errorf("--verbose = %v, want %v", *verbose, tc.wantVerbose)
			}
			if *strict != tc.wantStrict {
				t.Errorf("--strict = %v, want %v", *strict, tc.wantStrict)
			}
		})
	}
}

// TestPermuteFlagsDoesNotSwallowAPathAsAFlagValue guards the failure mode the
// permuter could itself introduce.
//
// `--format json` must keep its value attached, while a bare positional must
// not be consumed by a preceding BOOLEAN flag. Getting this wrong in the other
// direction would silently reinterpret a path as a flag value, which is worse
// than the bug being fixed: the scan would run against the wrong directory.
func TestPermuteFlagsDoesNotSwallowAPathAsAFlagValue(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	format := fs.String("format", "human", "")
	verbose := fs.Bool("verbose", false, "")

	// A boolean flag followed by the path: the path must stay positional.
	if err := fs.Parse(permuteFlags(fs, []string{"--verbose", "src/app"})); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if *format != "human" {
		t.Errorf("--format changed to %q; a boolean flag consumed the path", *format)
	}
	if fs.NArg() != 1 || fs.Arg(0) != "src/app" {
		t.Fatalf("positional args = %v, want [src/app]", fs.Args())
	}
	if !*verbose {
		t.Error("--verbose was not set")
	}
}

// TestPermuteFlagsRespectsDoubleDash documents the escape hatch. A path that
// genuinely begins with a hyphen is otherwise unreachable.
func TestPermuteFlagsRespectsDoubleDash(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	_ = fs.String("format", "human", "")

	if err := fs.Parse(permuteFlags(fs, []string{"--format", "json", "--", "-weird-name"})); err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if fs.NArg() != 1 || fs.Arg(0) != "-weird-name" {
		t.Fatalf("positional args = %v, want [-weird-name]", fs.Args())
	}
}

// TestPermuteFlagsLeavesUnknownFlagsForTheParser keeps the error message in one
// place. An unknown flag must reach fs.Parse so that it is reported once, in
// the flag package's wording, rather than being silently dropped here.
func TestPermuteFlagsLeavesUnknownFlagsForTheParser(t *testing.T) {
	fs := flag.NewFlagSet("t", flag.ContinueOnError)
	fs.SetOutput(new(strings.Builder)) // silence the flag package's own output
	_ = fs.String("format", "human", "")

	err := fs.Parse(permuteFlags(fs, []string{"--nonsense", "x"}))
	if err == nil {
		t.Fatal("an unknown flag was accepted")
	}
}

// TestCorpusIsNeverReadFromTheScannedTree is the guard for a supply-chain hole
// that existed in an earlier version of resolveCorpusDir.
//
// That version fell back to `<root>/corpus`, where root is the project under
// audit. The corpus is the only source of judgement in the system (ADR-003), so
// a project that shipped its own corpus could hand Clearance a permissive
// replacement and be told SHIP. The artefact being audited would have been
// choosing its own verdict — reachable by creating one directory, and it would
// have been invisible to every other test in the repository because the scanner
// and the policy engine would both have behaved perfectly.
//
// The test asserts the property directly rather than the behaviour: no
// candidate location may sit inside the scanned tree. It is written to fail if
// anyone reintroduces such a candidate, whatever the reason.
func TestCorpusIsNeverReadFromTheScannedTree(t *testing.T) {
	project := t.TempDir()
	if err := os.MkdirAll(filepath.Join(project, "corpus", "licences"), 0o755); err != nil {
		t.Fatal(err)
	}
	// The contents do not matter. What matters is that this directory is never
	// a candidate, so the file is deliberately left absent.

	// Point the one overridable location at a path that does not exist, so
	// every legitimate candidate misses. If a candidate inside the project
	// existed, it would be the only thing left to find — which is exactly the
	// condition under which the old code returned it.
	elsewhere := t.TempDir()
	t.Setenv("CLEARANCE_CORPUS", filepath.Join(elsewhere, "absent"))

	dir, tried := resolveCorpusDir("")

	if dir != "" {
		t.Fatalf("resolveCorpusDir returned %q; it must not resolve a corpus for a project "+
			"that ships one, because the project would then be choosing its own verdict", dir)
	}
	for _, candidate := range tried {
		if strings.Contains(candidate, project) {
			t.Fatalf("candidate %q is inside the project being scanned.\n"+
				"The corpus is the source of judgement; if the scanned tree can supply one, "+
				"a project can make Clearance report SHIP.", candidate)
		}
	}
}

// TestResolveCorpusDirPrefersTheExplicitFlag pins the precedence, because the
// order is the whole contract: an operator who passes --corpus must get that
// corpus or an error, never a silent substitution of something else.
func TestResolveCorpusDirPrefersTheExplicitFlag(t *testing.T) {
	explicit := t.TempDir()
	t.Setenv("CLEARANCE_CORPUS", t.TempDir()) // must lose to the flag

	dir, _ := resolveCorpusDir(explicit)
	if dir != explicit {
		t.Fatalf("resolveCorpusDir = %q, want the --corpus value %q", dir, explicit)
	}
}

// TestResolveCorpusDirReportsWhatItTried pins the failure-message contract.
//
// "Corpus not found" without saying where it looked is a bug report the user
// cannot act on, and the corpus path is the single most common reason a first
// run fails.
func TestResolveCorpusDirReportsWhatItTried(t *testing.T) {
	absent := filepath.Join(t.TempDir(), "definitely-absent")
	t.Setenv("CLEARANCE_CORPUS", absent)

	// Pinned so the candidate list is the same on every machine. The home
	// directory in particular is read from a different variable on each
	// platform, and a test that depends on the developer's real home would
	// pass for the wrong reason on one machine and fail on another.
	t.Setenv("HOME", t.TempDir())
	t.Setenv("USERPROFILE", t.TempDir())

	dir, tried := resolveCorpusDir("")
	if dir != "" {
		t.Skipf("a real corpus is installed at %q; this test needs a bare environment", dir)
	}
	if len(tried) == 0 {
		t.Fatal("resolveCorpusDir tried nothing and said so with an empty list")
	}
	joined := strings.Join(tried, "\n")
	for _, want := range []string{"$CLEARANCE_CORPUS", "next to the binary", "user home directory"} {
		if !strings.Contains(joined, want) {
			t.Errorf("the tried-list does not mention %q; it was:\n%s", want, joined)
		}
	}
}
