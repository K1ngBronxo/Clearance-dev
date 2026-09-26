package cli

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// newFlagSet builds a FlagSet with this program's conventions already applied:
// the flag package's own error output is discarded, and its usage is silenced,
// so that every message is rendered once in one format rather than twice in two.
//
// It exists because `doctor` and `explain` are the third and fourth commands to
// need exactly this, and three copies of four lines is how a convention drifts.
func newFlagSet(name string) *flag.FlagSet {
	fs := flag.NewFlagSet(name, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	fs.Usage = func() {}
	return fs
}

// parseFlags parses args and reports whether the caller should continue.
//
// The second result is false when the command is finished: either `-h` was
// passed (in which case the usage text has been printed and the exit code is 0),
// or the parse failed (in which case the error and the usage have been printed
// and the exit code is 2). Both are normal outcomes, which is why they are
// reported as a bool rather than as an error — an error would be caught by the
// linter's rule against untyped errors, and inventing a code for "the user asked
// for help" would put a non-failure in the taxonomy.
//
// permuteFlags is applied first, so that `clearance doctor --json` and
// `clearance explain E-CFG-001 --json` both work.
func parseFlags(fs *flag.FlagSet, args []string, stdout, stderr io.Writer, usageText string) (int, bool) {
	if err := fs.Parse(permuteFlags(fs, args)); err != nil {
		if errors.Is(err, flag.ErrHelp) {
			fmt.Fprint(stdout, usageText)
			return cerr.ExitOK, false
		}
		fmt.Fprintf(stderr, "clearance: %v\n\n", err)
		fmt.Fprint(stderr, usageText)
		return cerr.ExitConfig, false
	}
	return cerr.ExitOK, true
}

// writeJSON renders v as indented JSON, mapping a marshal failure to a code.
//
// A marshal failure over a struct of strings and ints is a bug rather than a
// condition, but INV-5 still applies: it has to be typed, and the caller has to
// be told which code to look up. The code is the caller's because the caller
// knows whether it was rendering a verdict, an SBOM or a doctor report.
func writeJSON(w, errw io.Writer, v any, code cerr.Code) int {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	// The verdict's own renderer makes this choice and this function matches it:
	// a citation URL containing `&` is written as `&`, not `\u0026`, because the
	// JSON is read by humans as often as by parsers.
	enc.SetEscapeHTML(false)
	if err := enc.Encode(v); err != nil {
		return fail(errw, cerr.Wrap(code, err))
	}
	return cerr.ExitOK
}
