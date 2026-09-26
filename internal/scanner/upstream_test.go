package scanner

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// # WHY THIS FILE EXISTS
//
// shellCommands, makeCommands, workflowCommands and dockerfileCommands had no
// test of any kind before this one. The upstream-CLI family was covered only
// end-to-end, through fixtures written in Go — so the AST path was exercised
// and the four text paths were not, and the text paths are where the detector
// reads a language it has no parser for.
//
// They drifted in exactly the way an untested reader drifts. Run over this
// repository's own tree, the detector produced 84 notices, and every one of
// them named a third-party program that does not exist: `.PHONY:`,
// `GUARD_CORPUS`, `GO)`, `X`, `o`, `output-signature`, `build release
// vulncheck dogfood bench`, and the 22 `Test…` names in the guard lists.
// PLAN/02-SPECIFICATIONS/06-detection-spec-tos.md §3.2 says why that is not a
// cosmetic problem — "false positives are what kill a scanner's credibility".
//
// The tests below are the four grammar facts that were missing, one group each.
// Each one is written so that it fails against the old reader and passes
// against the new one; a test that passed before would not have caught this.

// ── helpers ──────────────────────────────────────────────────────────────────

// tokens renders the names a signal list claims, in order.
func tokens(sigs []upstreamSignal) []string {
	out := make([]string, 0, len(sigs))
	for _, s := range sigs {
		out = append(out, s.Token)
	}
	return out
}

// assertTokens pins the exact list, order included.
//
// Exact rather than "contains", because every bug this file guards against had
// the shape of *extra* tokens: the real command was always found, and the
// debris was found beside it. A contains-check passes on all of them.
func assertTokens(t *testing.T, what string, sigs []upstreamSignal, want ...string) {
	t.Helper()
	got := tokens(sigs)
	if len(got) != len(want) {
		t.Fatalf("%s named %d token(s) %v, want %d %v", what, len(got), got, len(want), want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("%s named %v, want %v", what, got, want)
		}
	}
}

// assertNoToken fails if any banned name appears, and reports the whole list so
// a reader can see what was produced instead.
func assertNoToken(t *testing.T, what string, sigs []upstreamSignal, banned ...string) {
	t.Helper()
	got := tokens(sigs)
	for _, b := range banned {
		for _, g := range got {
			if g == b {
				t.Errorf("%s named %q, which is not a program. It named %v.", what, b, got)
				return
			}
		}
	}
}

// ── the shell reader ─────────────────────────────────────────────────────────

func TestShellCommandsFindsTheFirstWordOfACommand(t *testing.T) {
	src := "ffmpeg -i in.mp4 out.mp4\n" +
		"npx yt-dlp https://example.test/clip\n"
	// The second is a package-runner invocation, so the tool is the word
	// after the runner and not the runner itself (§2.1).
	assertTokens(t, "shellCommands", shellCommands(src), "ffmpeg", "yt-dlp")

	// `go` is in the package-runner table and every `go <sub>` is this project
	// building its own code, so a `go build` line names nothing. Worth pinning
	// because it is the reason the Makefile reader finds no program in
	// Clearance's own recipes.
	assertTokens(t, "a go subcommand", shellCommands("go build -o out ./cmd/x\n"))
}

// TestShellCommandsJoinsAContinuedLine is grammar fact one.
//
// A `\` at end of line continues the command. Read line by line, every argument
// on the continuation is the first word of a line, and therefore a program.
func TestShellCommandsJoinsAContinuedLine(t *testing.T) {
	// The backslash here is a real one followed by a real newline.
	src := "ffmpeg -i in.mp4 \\\n" +
		"  -o out.mp4\n"
	assertTokens(t, "a continued ffmpeg", shellCommands(src), "ffmpeg")

	// The old reader split these into two commands and reported `-o` as a
	// program called `o`.
	assertNoToken(t, "a continued ffmpeg", shellCommands(src), "o", "-o", "\\")
}

// TestShellCommandsNamesNothingForAnExpansion is grammar fact three.
//
// §3.1: a command name that is not a literal cannot be determined, so the spawn
// is recorded and no name is claimed. `$(GO) test` used to name `GO)`.
func TestShellCommandsNamesNothingForAnExpansion(t *testing.T) {
	cases := []struct {
		name string
		src  string
	}{
		{"a variable as the command", "$(GO) test ./... -count=1\n"},
		{"a path built from variables", "./$(BINARY)$(EXE) check . --fail-on BLOCK\n"},
		{"a closing bracket left on the name", "$(date) +%s\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			assertTokens(t, tc.name, shellCommands(tc.src))
			assertNoToken(t, tc.name, shellCommands(tc.src),
				"GO)", "BINARY)", "EXE)", "./", "date)", "date")
		})
	}
}

// TestShellCommandsNamesTheProgramASubstitutionActuallySpawns pins the other
// side of the bracket rule, which is a limitation rather than a fix.
//
// `$(which ffmpeg)` spawns `which`; the substitution's *result* is a path, and
// the shell never runs it as a command word. So `which` is the honest answer,
// and `ffmpeg` is not claimed. The cost is a false negative for a tool reached
// only through a substitution — the `ffmpeg` here is invisible — and it is the
// safe direction: §3.1 says a name that is not a literal is not a name.
func TestShellCommandsNamesTheProgramASubstitutionActuallySpawns(t *testing.T) {
	assertTokens(t, "a substitution used as an argument",
		shellCommands("$(which ffmpeg) -i in.mp4 out.mp4\n"), "which")
}

// TestShellCommandsDropsAnAssignmentPrefix is grammar fact two.
//
// The `@`/`-`/`+` a Makefile puts in front of a recipe has to come off *before*
// the assignment test, or `@fail=0` reads as a program whose name contains an
// `=`.
func TestShellCommandsDropsAnAssignmentPrefix(t *testing.T) {
	// An environment prefix on a real command leaves the command behind.
	assertTokens(t, "an environment prefix",
		shellCommands("CGO_ENABLED=0 ffmpeg -i in.mp4\n"), "ffmpeg")

	// A silenced assignment leaves nothing behind.
	assertTokens(t, "a silenced assignment", shellCommands("@fail=0\n"))
	assertTokens(t, "an ignored-error assignment", shellCommands("-fail=0\n"))
}

func TestShellCommandsSkipsControlWords(t *testing.T) {
	assertTokens(t, "a control construct",
		shellCommands("if [ -f x ]; then echo hi; fi\n"))
	assertTokens(t, "a control word before a real command",
		shellCommands("echo hi && ffmpeg -i a b\n"), "echo", "ffmpeg")
}

// ── the Makefile reader ──────────────────────────────────────────────────────

// TestMakeCommandsReadsOnlyRecipeLines is grammar fact four, and it is the one
// that caused 74 of the 84 notices.
func TestMakeCommandsReadsOnlyRecipeLines(t *testing.T) {
	const src = `# A Makefile is not a shell script.
GO ?= go
GUARD_CORPUS := TestAlpha|TestBeta
.PHONY: build test
.DEFAULT_GOAL := build

build: ## Build it
	$(GO) build -trimpath -o out ./cmd/x
	goreleaser release --clean
`
	sigs := makeCommands(src)
	assertTokens(t, "the Makefile", sigs, "goreleaser")
	assertNoToken(t, "the Makefile", sigs,
		".PHONY:", ".DEFAULT_GOAL", "GUARD_CORPUS", "TestAlpha", "TestBeta",
		"GO", "build", "build:", "test", "GOFLAGS", "SHELL", "X", "\\")
}

// TestMakeCommandsKeepsTheLineTheReaderWouldFind pins the evidence line, which
// was absent entirely before: a Notice that says `Makefile` and nothing else
// does not tell anyone where to look.
func TestMakeCommandsKeepsTheLineTheReaderWouldFind(t *testing.T) {
	const src = "GO ?= go\n" + // 1
		"\n" + // 2
		"build:\n" + // 3
		"\tgoreleaser release --clean\n" // 4
	sigs := makeCommands(src)
	if len(sigs) != 1 {
		t.Fatalf("makeCommands named %v, want one token", tokens(sigs))
	}
	if sigs[0].Line != 4 {
		t.Errorf("the recipe is on line 4; the signal says line %d", sigs[0].Line)
	}
}

// TestMakeCommandsIgnoresAVariableAssignment covers the tab-indented form.
//
// The whole line has to be recognised as an assignment before anything splits
// it, because `|` is a shell separator and the value is not a command.
func TestMakeCommandsIgnoresAVariableAssignment(t *testing.T) {
	assertTokens(t, "a tab-indented assignment",
		makeCommands("\tGUARD_CORPUS := TestAlpha|TestBeta\n"))
}

// ── the CI workflow reader ───────────────────────────────────────────────────

func TestWorkflowCommandsReadsOnlyRunBlocks(t *testing.T) {
	const src = `name: release
jobs:
  build:
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
          persist-credentials: false
      - name: Sign
        run: cosign sign-blob --yes dist/checksums.txt
`
	sigs := workflowCommands(src)
	assertTokens(t, "the workflow", sigs, "cosign")
	assertNoToken(t, "the workflow", sigs,
		"uses", "actions/checkout@v4", "with", "fetch-depth", "persist-credentials")
}

// TestWorkflowCommandsJoinsAContinuedBlock is the release workflow's cosign
// step, which reported four programs that do not exist.
func TestWorkflowCommandsJoinsAContinuedBlock(t *testing.T) {
	const src = `jobs:
  release:
    steps:
      - name: Sign
        run: |
          cosign sign-blob --yes \
            --output-signature dist/checksums.txt.sig \
            dist/checksums.txt
`
	sigs := workflowCommands(src)
	assertTokens(t, "the signing step", sigs, "cosign")
	assertNoToken(t, "the signing step", sigs,
		"output-signature", "dist/checksums.txt", "dist/checksums.txt.sig", "--yes", "\\")
}

// TestWorkflowCommandsReadsASequenceItemStep covers the style GitHub's own
// documentation uses.
//
// `- run: …` is the same key as `run: …` one level in, and missing it made the
// reader blind to a whole file rather than wrong about one line — the direction
// that matters more, because nothing tells the user a file went unread.
func TestWorkflowCommandsReadsASequenceItemStep(t *testing.T) {
	const src = `jobs:
  build:
    steps:
      - uses: actions/checkout@v4
      - run: acme-render -i in.mp4 -o out.mp4
      - run: |
          acme-encode --in a.wav \
            --out b.mp3
`
	sigs := workflowCommands(src)
	assertTokens(t, "the workflow", sigs, "acme-render", "acme-encode")
	assertNoToken(t, "the workflow", sigs, "out.mp4", "b.mp3", "uses", "o")
}

// TestWorkflowInlineRunStepIsDetected is case A of the two ways the
// sequence-item rule can be wrong.
//
// `- run: ffmpeg …` is the plainest step there is — it is what GitHub's own
// examples show — and it must be read. It is pinned here so the structural rule
// below can never be satisfied by a reader that has stopped reading steps.
func TestWorkflowInlineRunStepIsDetected(t *testing.T) {
	const src = `jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - run: ffmpeg -i in.mp4 out.mp4
`
	assertTokens(t, "an inline run step", workflowCommands(src), "ffmpeg")
}

// TestWorkflowDefaultsRunMappingIsNotAStep is case B.
//
// A `defaults.run` is a *mapping* of settings, not a step: its keys are
// `working-directory` and `shell`, and no list marker introduces them. The
// reader used to treat every `run:` line as a step and hand the mapping's
// children to the shell reader, which read `working-directory:` as a program.
//
// # WHY THE RULE IS "IS THERE A LIST MARKER", NOT "IS THE KEY CALLED shell"
//
// The tempting fix is to skip the key names `working-directory` and `shell`.
// That breaks the day GitHub adds a third setting to defaults.run, and it is
// not what tells the two constructs apart anyway. What tells them apart is that
// a step is a list item and a defaults entry is not: a step's `run:` is
// introduced by the item's `-` marker — on the marker's own line, or indented
// under a `- name:` / `- uses:` item whose `-` sits shallower — and a
// `defaults.run` key has no list marker above it at all.
func TestWorkflowDefaultsRunMappingIsNotAStep(t *testing.T) {
	const src = `name: ci
on: [push]
defaults:
  run:
    working-directory: clearance
    shell: bash
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`
	sigs := workflowCommands(src)
	assertTokens(t, "a defaults.run mapping and no step", sigs)
	assertNoToken(t, "a defaults.run mapping", sigs,
		"working-directory", "working-directory:", "shell", "shell:")
}

// TestWorkflowDefaultsRunValueIsNeverRead pins the half that the trailing colon
// was hiding.
//
// `working-directory:` ends in a colon, and the shell reader refuses a token
// that ends in one, so the plain mapping above passed *by accident*: the
// mapping was still being read and only the shape of the key stopped it. Give
// the value a shell separator and the accident stops protecting it —
// `src|generated` splits on the shell's `|`, and `generated` is a name a
// program could have. The structural rule refuses the whole mapping before any
// of that can matter.
func TestWorkflowDefaultsRunValueIsNeverRead(t *testing.T) {
	const src = `defaults:
  run:
    working-directory: src|generated
jobs:
  build:
    steps:
      - run: acme-lint .
`
	assertTokens(t, "a defaults value containing a shell separator",
		workflowCommands(src), "acme-lint")
}

// TestWorkflowDefaultsAfterStepsIsNotAStep checks the other place a `defaults`
// block can appear: below the steps list, where the reader has already seen a
// list marker and has to notice the list has ended.
//
// `defaults:` is dedented to the level of `jobs:`, which closes the steps list;
// the `run:` under it then has no list marker above it any more and is not a
// step.
func TestWorkflowDefaultsAfterStepsIsNotAStep(t *testing.T) {
	const src = `jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - run: ffmpeg -i in.mp4 out.mp4
defaults:
  run:
    working-directory: clearance
`
	assertTokens(t, "steps then a workflow-level defaults",
		workflowCommands(src), "ffmpeg")
}

// TestWorkflowStepWithIndentedRunBlockStillWorks pins the list-item form that is
// not written on the marker line.
//
// `- name: …` opens the item, and `run: |` on the next line, indented under it,
// is the same step. The structural rule has to accept this as well as
// `- run: …`, or the fix for the false positive becomes a false negative.
func TestWorkflowStepWithIndentedRunBlockStillWorks(t *testing.T) {
	const src = `jobs:
  build:
    steps:
      - name: Render
        run: |
          acme-render --in a.mp4 \
            --out b.mp4
`
	assertTokens(t, "a run: block under a - name: item",
		workflowCommands(src), "acme-render")
}

// ── the Dockerfile reader ────────────────────────────────────────────────────

func TestDockerfileCommandsJoinsAContinuedRun(t *testing.T) {
	const src = `FROM ghcr.io/other/tool:1.2
RUN ffmpeg -i in.mp4 \
    -o out.mp4
`
	sigs := dockerfileCommands(src)
	assertTokens(t, "the Dockerfile", sigs, "ghcr.io/other/tool", "ffmpeg")
	assertNoToken(t, "the Dockerfile", sigs, "o", "-o", "\\", "tool")
}

// TestDockerfileCommandsKeepsTheRegistryInAnImageName pins the image identity.
//
// firstWord strips a leading path, which is right for a command — `/usr/bin/
// ffmpeg` is ffmpeg — and wrong for an image, where the path *is* the name.
// `FROM ghcr.io/other/tool` was reported as an image called `tool`: it would
// have matched a corpus entry named `tool` and missed the one keyed on
// `ghcr.io/other/tool`, and the tag and digest are already stripped separately.
func TestDockerfileCommandsKeepsTheRegistryInAnImageName(t *testing.T) {
	sigs := dockerfileCommands("FROM ghcr.io/other/tool@sha256:abc AS build\n")
	if len(sigs) != 1 {
		t.Fatalf("named %v, want one image", tokens(sigs))
	}
	if sigs[0].Token != "ghcr.io/other/tool" {
		t.Errorf("image = %q, want %q — the registry and namespace are the identity",
			sigs[0].Token, "ghcr.io/other/tool")
	}
	if sigs[0].Kind != signalImage {
		t.Errorf("kind = %q, want %q", sigs[0].Kind, signalImage)
	}
}

// ── the regression that started this ─────────────────────────────────────────

// TestOurOwnMakefileNamesNoThirdPartyProgram reads the real Makefile and
// asserts that the reader finds nothing it cannot account for.
//
// # WHY IT READS THE REAL FILE
//
// A synthetic Makefile proves the reader handles the shapes I thought of. This
// one proves it handles the file that actually broke — and the file is a moving
// target, so the test keeps working as the Makefile changes.
//
// The assertion is "every name it finds is in ubiquitousTools", not "it finds
// nothing". Both halves matter: the second would pass for the wrong reason if
// the tab rule were too strict and recipes stopped being read at all, so the
// non-vacuity check below requires that some commands were found. And if the
// Makefile ever invokes a genuinely third-party tool, this test fails — which
// is correct, because that would be a real dependency of this project, and the
// dogfooding doctrine in PLAN/08-BUSINESS/03-legal-posture.md §5 is that
// Clearance must pass its own check honestly.
func TestOurOwnMakefileNamesNoThirdPartyProgram(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "Makefile"))
	if err != nil {
		t.Fatalf("reading the Makefile: %v", err)
	}
	sigs := makeCommands(string(raw))
	if len(sigs) == 0 {
		t.Fatal("the Makefile yielded no commands at all. Recipes are not being " +
			"read, so this test would pass for the wrong reason.")
	}
	for _, s := range sigs {
		if !ubiquitousTools[strings.ToLower(s.Token)] {
			t.Errorf("Clearance's own Makefile is reported as invoking %q at line %d. "+
				"If that is a real third-party tool it belongs in the corpus; if it is "+
				"not, the Makefile reader is producing debris again. Full list: %v",
				s.Token, s.Line, tokens(sigs))
		}
	}
}
