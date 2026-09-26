package cli

import (
	"fmt"
	"io"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/safefs"
)

// Main is the process entry point. It returns the exit code; the caller in
// cmd/clearance is three lines long because everything interesting happens
// here, where it can be tested.
//
// # WHY IT TAKES stdin
//
// `clearance mcp serve` reads a JSON-RPC stream from stdin, and a Main that
// opened os.Stdin itself would make the MCP path untestable from a buffer —
// which is the whole reason the stdout and stderr parameters exist. The reader
// is a parameter for the same reason they are, and the three together mean a
// test can drive any subcommand without a terminal.
//
// It never calls os.Exit, and it never panics out. A panic that escaped would
// print a Go stack trace to a user who is trying to find out whether they may
// legally ship their software, which is a bad way to be told that a licence
// tool has a bug. E-INT-002 exists for exactly this, and it is recovered here
// so that the exit code is still one of the five frozen values.
func Main(args []string, stdin io.Reader, stdout, stderr io.Writer) (code int) {
	defer func() {
		if r := recover(); r != nil {
			fmt.Fprintf(stderr, "clearance: %s — %s\n", cerr.EInt002, panicMessage(r))
			fmt.Fprintf(stderr, "  this is a bug, not a problem with your project\n")
			fmt.Fprintf(stderr, "  %s\n", VersionLine())
			code = cerr.ExitInternal
		}
	}()

	if len(args) == 0 {
		// No arguments at all is the one case where the usage text is the
		// *answer* rather than an error message, so it goes to stdout and the
		// exit code is 0. `clearance` typed by someone who does not know what
		// the tool does is not a failure.
		fmt.Fprint(stdout, usage)
		return cerr.ExitOK
	}

	switch args[0] {
	case "check":
		return runCheck(args[1:], stdout, stderr)
	case "version", "--version", "-v":
		return runVersion(stdout)
	case "corpus":
		return runCorpus(args[1:], stdout, stderr)
	case "doctor":
		return runDoctor(args[1:], stdout, stderr)
	case "explain":
		return runExplain(args[1:], stdout, stderr)
	case "mcp":
		return runMCP(args[1:], stdin, stdout, stderr)
	case "help", "--help", "-h":
		return runHelp(args[1:], stdout)
	}

	fmt.Fprintf(stderr, "clearance: unknown command %q\n\n", args[0])
	fmt.Fprint(stderr, usage)
	return cerr.ExitConfig
}

// panicMessage renders a recovered panic value. The taxonomy's E-INT-002
// template takes one argument — the component — so the panic value is passed
// through it rather than being concatenated, which keeps the message format
// owned by the taxonomy instead of by this function.
func panicMessage(r any) string {
	s := fmt.Sprintf("%v", r)
	// A panic value can contain a newline (a wrapped error, a formatted
	// message). Collapsing it keeps the output to one line per fact, which is
	// what makes the report greppable.
	s = strings.ReplaceAll(s, "\n", " ")
	if len(s) > 200 {
		s = s[:200] + "…"
	}
	return fmt.Sprintf("%s in the command layer", s)
}

// runVersion reports the tool, its build provenance, and what it knows about
// the corpus. It answers "which binary produced this verdict" and "can this
// binary reach the network", both of which a bug report needs.
func runVersion(stdout io.Writer) int {
	fmt.Fprintln(stdout, VersionLine())
	fmt.Fprintf(stdout, "go:       %s\n", goVersion())
	fmt.Fprintf(stdout, "network:  %s\n", networkState())

	// The candidate list is discarded here: both commands report the failure
	// through corpus.LoadInstalled's E-CORPUS-001, and `version` deliberately
	// treats a missing corpus as non-fatal (see below).
	//
	// LoadInstalled, not Load. A release installs a compiled signed bundle and
	// no YAML, so Load would fail here and `clearance version` would answer
	// "corpus: not loaded" on a machine where the corpus is present, valid and
	// signed — on exactly the machine where a user runs this command to find out
	// why nothing works. A diagnostic that is wrong in that direction is worse
	// than no diagnostic.
	dir, _ := resolveCorpusDir("")
	c, err := corpus.LoadInstalled(corpus.LoadOptions{Dir: dir, Today: ""})
	if err != nil {
		// Not fatal: `clearance version` must work on a machine where the
		// corpus is missing, because that is exactly the machine where a user
		// needs to ask why nothing works.
		fmt.Fprintf(stdout, "corpus:   not loaded (%s)\n", dir)
		fmt.Fprintf(stdout, "          %s\n", errorLine(err))
		return cerr.ExitOK
	}
	fmt.Fprintf(stdout, "corpus:   %s at %s\n", c.Version, dir)
	fmt.Fprintf(stdout, "          signed: %s\n", yesNo(c.Signed))
	s := c.Stats()
	fmt.Fprintf(stdout, "          %d licences, %d obligations, %d traps, %d citations\n",
		s.Licences, s.Obligations, s.Traps, s.Citations)
	return cerr.ExitOK
}

// runCorpus implements `corpus info` and `corpus verify`.
//
// `corpus update` is named in the frozen CLI contract and is deliberately
// absent: it is the one command that needs the network, and it lands with the
// signed-bundle fetcher rather than before it. It is refused explicitly.
func runCorpus(args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, "clearance: corpus needs a subcommand: info, verify\n")
		return cerr.ExitConfig
	}

	// The candidate list is discarded here: both commands report the failure
	// through corpus.Load's E-CORPUS-001, and `version` deliberately treats a
	// missing corpus as non-fatal (see below).
	dir, _ := resolveCorpusDir("")

	switch args[0] {
	case "info":
		// LoadInstalled, so `corpus info` reports the version of the bundle a
		// release actually installed, signature-verified, rather than the
		// `0.0.0-unsigned` of the YAML source tree beside it. Reporting the
		// version of a corpus that was not the one a verdict used is the same
		// class of defect as a stamp that names nothing.
		c, err := corpus.LoadInstalled(corpus.LoadOptions{Dir: dir, Today: ""})
		if err != nil {
			return fail(stderr, err)
		}
		fmt.Fprintf(stdout, "corpus:      %s\n", c.Version)
		fmt.Fprintf(stdout, "path:        %s\n", dir)
		fmt.Fprintf(stdout, "schema:      %d\n", c.SchemaVersion)
		fmt.Fprintf(stdout, "built:       %s\n", orNone(c.BuiltAt))
		fmt.Fprintf(stdout, "signed:      %s\n", yesNo(c.Signed))
		s := c.Stats()
		fmt.Fprintf(stdout, "licences:    %d\n", s.Licences)
		fmt.Fprintf(stdout, "obligations: %d\n", s.Obligations)
		fmt.Fprintf(stdout, "traps:       %d\n", s.Traps)
		fmt.Fprintf(stdout, "tos:         %d\n", s.ToS)
		fmt.Fprintf(stdout, "territories: %d\n", s.Territories)
		fmt.Fprintf(stdout, "citations:   %d\n", s.Citations)
		for _, n := range c.Notices {
			fmt.Fprintf(stdout, "notice:      %s %s\n", n.Code, n.Message)
		}
		return cerr.ExitOK

	case "verify":
		return runCorpusVerify(dir, stdout, stderr)

	case "update":
		return notImplemented(stderr, "corpus update",
			"Fetching a signed corpus bundle is the only network operation the tool has, and it lands with the signed-bundle fetcher rather than before it. Nothing was downloaded.")

	default:
		fmt.Fprintf(stderr, "clearance: unknown corpus subcommand %q\n", args[0])
		fmt.Fprint(stderr, "  expected: info, verify\n")
		return cerr.ExitConfig
	}
}

// runCorpusVerify performs the INV-9 check and reports the result.
//
// It is a separate command from `check` on purpose. `check` must work offline
// and must not depend on a key being present; `corpus verify` is the command a
// user runs when they want to know whether the data the verdict came from is
// the data that was published.
func runCorpusVerify(dir string, stdout, stderr io.Writer) int {
	pub, err := corpus.PublicKey()
	if err != nil {
		return fail(stderr, err)
	}
	// The read budget must admit the compiled bundle, which is the largest
	// file this command touches. safefs.Limits defaults MaxFileSize to 8 MiB,
	// which is right for a source file and wrong for a corpus bundle: a
	// bundle over the limit would be recorded but never parsed, and
	// `corpus verify` would then report a healthy corpus it had not actually
	// read. corpus.MaxCorpusBytes is the documented ceiling, so the budget is
	// that ceiling exactly — no larger, because a file bigger than the
	// documented maximum is a file worth refusing.
	root, err := safefs.New(dir, safefs.Limits{MaxFileSize: corpus.MaxCorpusBytes})
	if err != nil {
		return fail(stderr, err)
	}
	m, err := corpus.Verify(root, pub)
	if err != nil {
		return fail(stderr, err)
	}
	fmt.Fprintf(stdout, "corpus verify: OK\n")
	fmt.Fprintf(stdout, "  version:       %s\n", m.Version)
	fmt.Fprintf(stdout, "  schema:        %d\n", m.SchemaVersion)
	fmt.Fprintf(stdout, "  built_at:      %s\n", m.BuiltAt)
	fmt.Fprintf(stdout, "  signed_at:     %s\n", m.SignedAt)
	fmt.Fprintf(stdout, "  sha256:        %s\n", m.SHA256)
	fmt.Fprintf(stdout, "  entry_count:   %d\n", m.EntryCount)
	fmt.Fprintf(stdout, "  signature_alg: %s\n", m.SignatureAlg)
	return cerr.ExitOK
}

// runHelp prints usage. `help <command>` prints the command's own usage.
func runHelp(args []string, stdout io.Writer) int {
	if len(args) > 0 && args[0] == "check" {
		fmt.Fprint(stdout, checkUsage)
		return cerr.ExitOK
	}
	fmt.Fprint(stdout, usage)
	return cerr.ExitOK
}

// ─── small formatters ──────────────────────────────────────────────────────

func yesNo(b bool) string {
	if b {
		return "yes"
	}
	return "no"
}

func orNone(s string) string {
	if strings.TrimSpace(s) == "" {
		return "(not recorded)"
	}
	return s
}

// errorLine renders an error for a context that is not failing — `clearance
// version` on a machine with no corpus. It names the code when there is one,
// because a code is what the user will search for.
func errorLine(err error) string {
	if e, ok := cerr.As(err); ok {
		return string(e.Code()) + " " + e.Message()
	}
	return fmt.Sprintf("%v", err)
}

// networkState states plainly whether this binary can make an outbound call.
//
// It is printed by `clearance version` because the privacy claim in the README
// is a claim about the binary, and a user should be able to check it on their
// own machine without reading the source. In this build the answer is always
// "disabled" — see netclient.go for why that is structural rather than a
// setting.
func networkState() string {
	if NetworkEnabled() {
		return "enabled (corpus update only)"
	}
	return "disabled - no outbound calls are possible in this build"
}
