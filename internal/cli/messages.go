package cli

import (
	"fmt"
	"io"
	"runtime"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// goVersion is the Go toolchain the binary was built with. It appears in
// `clearance version` because a bug report that names the toolchain is a bug
// report someone can reproduce, and because a stdlib security fix is the one
// dependency this project does have.
func goVersion() string { return runtime.Version() }

// Build information. These are the only variables in the program that are
// intended to be overwritten at link time:
//
//	go build -ldflags "-X github.com/clearance-dev/clearance/internal/cli.Version=1.0.0 \
//	                   -X github.com/clearance-dev/clearance/internal/cli.Commit=$(git rev-parse --short HEAD) \
//	                   -X github.com/clearance-dev/clearance/internal/cli.Provenance=release"
//
// The package path here must stay correct. It previously read internal/interface
// (the plan's name for this layer) while the Makefile and both release paths
// stamped `main.version` — so all three were silently stamping nothing, and
// every binary ever built reported 0.0.0-dev / unknown / local.
//
// They are recorded in the verdict's meta block, because a verdict a user
// cannot attribute to a build is a verdict they cannot report a bug against.
var (
	// Version is the tool version. "0.0.0-dev" is deliberately not a plausible
	// release number, so an unreleased binary is obvious in a report.
	Version = "0.0.0-dev"

	// Commit is the source revision, or "unknown" when built outside git.
	Commit = "unknown"

	// Provenance names how the binary was built (release, local, ci).
	Provenance = "local"
)

// VersionLine is the one-line identity used by `clearance version` and by the
// verdict's meta block.
func VersionLine() string {
	return fmt.Sprintf("clearance %s (build %s, %s)", Version, Commit, Provenance)
}

// usage is the top-level help text. It is deliberately written to be readable
// by someone who has never seen the tool: the first line says what it does, the
// second says what the exit codes mean, and only then does it list commands.
const usage = `clearance - licence, model-weights and platform-terms clearance

  Reads a project's declared dependencies, resolves each licence, and returns
  one of four verdicts with a citation on every finding. It never executes your
  code, never installs anything, and never sends your file list anywhere.

USAGE
  clearance <command> [flags]

COMMANDS
  check [path]        Scan a project and print a verdict. Default path: .
  doctor              What is installed, what is missing, and why. Start here.
  explain <code>      What an error code means, and what to do about it.
  corpus info         Show the loaded corpus version, contents and signature.
  corpus verify       Verify the corpus signature and print the result.
  mcp serve           Serve the engine to an agent over stdio (JSON-RPC / MCP).
  version             Tool version, build provenance and corpus version.
  help [command]      Usage.

EXIT CODES (frozen - a CI pipeline may depend on these forever)
  0   Verdict produced; no blocker
  1   DO NOT SHIP
  2   Configuration error
  3   Corpus error
  4   Internal error
  5   UNDETERMINED and --strict was passed

RUNNING check
  clearance check .
  clearance check . --format json --output verdict.json
  clearance check . --strict          # exit 5 instead of 0 on UNDETERMINED
  clearance check . --allow-medium-blockers

  Run 'clearance check --help' for the full flag list.

OPTIONAL AI EXPLANATION (off by default, and never part of the verdict)
  clearance check . --ai                      # explain findings with a model
  clearance check . --ai --ai-provider ollama # a local model, no key, no egress
  clearance check . --ai --ai-output ai.json  # also write the suggestion to a file

  You bring the key: set CLEARANCE_OPENAI_API_KEY (or the variable for your
  provider), pipe one in with --api-key-stdin, or put it in
  ~/.config/clearance/keys.yml at mode 0600. Run 'clearance explain --providers'
  for the twenty supported providers. The engine decides; the model explains.

WHAT IT DOES NOT DO
  It is not legal advice. It reports what the published licence text says, on
  the date the corpus recorded, and it flags the clauses it cannot resolve
  rather than guessing. Important decisions should be reviewed by a qualified
  professional.
`

// checkUsage is the `check` help text.
const checkUsage = `clearance check [path] - scan a project and print a verdict

FLAGS
  --config <path>             Intent file (default ./clearance.config.yml)
  --format <fmt>              human | json | md | sarif (default human)
                              md is the PR-comment form; sarif is for GitHub
                              code scanning.
  --offline                   Disable every network call (default true in this build)
  --strict                    Exit 5 on UNDETERMINED instead of 0
  --fail-on <sev>             BLOCK | CONDITION | NOTE (default BLOCK)
  --allow-medium-blockers     Promote MEDIUM findings to blocking
  --output <path>             Write to a file instead of stdout
  --sbom <fmt>                cyclonedx | spdx. Export an SBOM beside the
                              verdict. Needs --output to name a destination;
                              without it the file is named after the project.
  --policy <path>             Org policy file. It may raise a severity and may
                              never lower one; an exception must name one
                              dependency, an owner and an expiry, and it
                              demotes the finding to a NOTE rather than
                              removing it.
  --json-schema               Print the verdict JSON schema and exit
  --no-color                  Disable ANSI colour (auto-off when not a TTY)
  --quiet                     Suppress the NOTES section
  --verbose                   Show the predicate that fired for each finding
  --timeout <dur>             Scan timeout (default 60s)
  --corpus <path>             Corpus directory. Default: $CLEARANCE_CORPUS, then
                              <binary>/corpus, then <binary>/../corpus, then the
                              per-user data directory. It is never read from
                              inside the scanned project, because the corpus is
                              the source of judgement and the project must not
                              be able to supply its own verdict.
  --today <YYYY-MM-DD>        Override today's date. For reproducible runs.

AI (opt-in; the verdict is identical with it on or off)
  --ai                        Ask a model to explain the findings. The engine
                              has already decided; the model only explains, and
                              its output is a separate block, never the verdict.
  --no-ai                     Force AI off, even if the config enables it. It
                              always wins, because a repository you cloned must
                              not be able to spend your money.
  --ai-provider <id>          A provider id (see 'clearance explain --providers').
  --ai-model <name>           Override the provider's default model.
  --ai-jobs <list>            explain, remediate, triage (default: explain)
  --ai-output <path>          Write the suggestion to its own JSON file.
  --api-key-stdin             Read the key from stdin. This is the only way to
                              pass a key, because a key on a command line is a
                              key in the process table and in your shell history.

  A key comes from --api-key-stdin, then $CLEARANCE_<PROVIDER>_API_KEY, then
  ~/.config/clearance/keys.yml at mode 0600. --ai --offline is refused, never
  silently ignored.

NOT IMPLEMENTED IN THIS BUILD
  'clearance corpus update' is part of the frozen CLI contract and is not
  implemented here: it is the only command that needs the network, and this
  build is offline by default. It is refused rather than ignored, because
  silently accepting a subcommand and doing nothing is how a tool lies to a
  pipeline.

ENVIRONMENT
  CLEARANCE_CORPUS            Corpus path override
  CLEARANCE_OFFLINE           "1" = force offline
  NO_COLOR                    Standard; disables ANSI
  CLEARANCE_<PROVIDER>_API_KEY  The key for one AI provider (see doctor)
`

// doctorUsage is the `doctor` help text.
const doctorUsage = `clearance doctor - what is installed, what is missing, and why

It answers the only question a user has when nothing works: which of the five
things this program needs is absent? Each is named with its state, in the order
the pipeline uses them, so the first line that says something is wrong is the
thing to fix.

FLAGS
  --json     Emit the same facts as JSON, for a support script
  --keys     Print the provider table with key resolution, without a table header
             note. Key material is never printed, on any flag.

WHAT IT PRINTS
  binary    version, commit, build provenance, Go toolchain, platform, and
            whether this process can reach the network or an AI provider
  corpus    whether a corpus was found, its version, whether it is signed, and
            its contents
  config    whether an intent file loaded, from where, and the intent hash
  providers every supported AI provider, its kind, its default model, and
            whether a key resolves for it

It exits 0 whether or not something is missing: it is a report, not a gate.
`

// explainUsage is the `explain` help text.
const explainUsage = `clearance explain - look up an error code, or list what the binary knows

USAGE
  clearance explain E-CFG-001     One code: its class, exit code, message and
                                  recovery path.
  clearance explain --codes       Every code in the taxonomy.
  clearance explain --providers   Every supported AI provider.

FLAGS
  --json     Emit as JSON.

WHY IT EXISTS
  A user meets a code in a CI log at 2am. This is how they find out what it
  means without a browser, and it is generated from the same table the binary
  raises the code from, so it cannot describe a code the binary does not have.
`

// notImplemented reports a flag or subcommand that the frozen CLI contract
// names but this build does not implement.
//
// It returns exit 2, the configuration-error code, because the problem is the
// invocation rather than the tool's state.
//
// # WHAT IS LEFT, AND THE GAP THAT REMAINS
//
// One caller: `clearance corpus update`, the only command that needs the
// network and therefore the only one this offline-by-default build cannot
// provide. Everything else the contract names is implemented — `--sbom`,
// `--policy` and `--json-schema` were refused here until the phases that
// specify them landed, and refusing them was right at the time, because a
// pipeline that believed it had produced an SBOM is worse off than one that
// failed loudly.
//
// INV-5 still says every error carries a code from the taxonomy, and this one
// still does not. The taxonomy has no code for "a documented subcommand is
// unavailable in this build", because when it was written every subcommand was
// assumed to be implemented. The gap is narrower than it was — one caller
// instead of four — but it is not closed, and it is recorded rather than
// papered over by reusing E-CFG-011, whose meaning is "the org policy file
// is invalid" and which a user looking up this message would find unhelpful.
func notImplemented(stderr io.Writer, flag, detail string) int {
	fmt.Fprintf(stderr, "clearance: %s is not implemented in this build.\n", flag)
	fmt.Fprintf(stderr, "  %s\n", detail)
	fmt.Fprintf(stderr, "  this binary is %s\n", VersionLine())
	fmt.Fprintf(stderr, "  no scan was performed and no verdict was produced\n")
	return cerr.ExitConfig
}

// mcpUsage is the `clearance mcp` help text.
const mcpUsage = `clearance mcp - serve the engine to an agent

  Speaks the Model Context Protocol over stdio, so an agent that can run a
  process can ask Clearance for a verdict without a human in the loop.

  The server declares exactly one capability: fs.read, scoped to the root it was
  started in. It never writes, never executes and never makes an outbound call.

USAGE
  clearance mcp serve [flags]

SUBCOMMANDS
  serve               Read JSON-RPC on stdin, write responses on stdout.

TOOLS
  clearance_check          Scan a project and return a verdict.
  clearance_explain        Return the clause behind a citation id.
  clearance_corpus_info    Corpus version, signature status and counts.
  clearance_license_lookup One licence's obligations and traps, by SPDX id.

  Every tool is read-only and idempotent. Run 'clearance mcp serve --help' for
  the flags.
`

// mcpServeUsage is the `clearance mcp serve` help text.
const mcpServeUsage = `clearance mcp serve - the MCP server over stdio

USAGE
  clearance mcp serve [flags]

FLAGS
  --root <path>       The workspace root the fs.read capability is scoped to.
                      Default: the current directory. A tool call naming a path
                      outside it is refused with E-MCP-001 and ends the session.
  --corpus <path>     Corpus directory. Default: discovered the same way
                      'clearance check' discovers it.
  --today <date>      The date the staleness rule uses (YYYY-MM-DD).
                      Default: today. Injecting it is how a verdict from last
                      month is reproduced exactly.
  --quiet             Suppress the startup banner on stderr.

THE CAPABILITY BOUNDARY
  A request for a path outside --root is not a protocol error, it is an attempt
  to use the server as a confused deputy. The server answers with E-MCP-001 and
  stops rather than continuing to serve a client that has tried once.

  An unknown tool is answered with a JSON-RPC error and the server keeps
  running: an agent that guesses a name is an ordinary event in a long session.
`
