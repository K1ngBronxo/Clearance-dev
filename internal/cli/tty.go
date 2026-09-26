package cli

import (
	"io"
	"os"
)

// colorEnabled decides whether ANSI colour may be emitted (R8).
//
// # WHY THIS IS IN L5 AND NOT IN internal/report
//
// It reads the environment and stats a file descriptor, which is I/O. The
// architecture confines I/O to L0, L1 and L5, and internal/report is L4: a
// pure function from a Verdict to bytes. The probe used to live in
// internal/report, which meant the renderer imported `os` — a purity breach
// that `internal/arch_test.go` now fails the build over.
//
// Keeping it here is also what makes the renderer testable: `report` takes a
// plain `Options{Color: bool}` and can be driven against a bytes.Buffer with
// no environment stubbing at all.
//
// Colour is off unless all three of these hold, and the order matters because
// each check is cheaper and more decisive than the next:
//
//  1. NO_COLOR is absent or empty. The convention (no-color.org) is that the
//     variable's *presence with a non-empty value* disables colour, whatever
//     the value says. Respecting this is not politeness — a user who has set
//     NO_COLOR has usually done so because their terminal mangles escapes.
//  2. TERM is not "dumb". A dumb terminal has no cursor control, so an escape
//     sequence is printed as literal garbage rather than interpreted.
//  3. The writer is a character device. A redirected file or a pipe is not,
//     and escape codes in a redirected log file are noise that breaks grep.
//
// The check is on the *writer*, not on os.Stdout, so that a caller rendering
// into a buffer for a test gets the honest answer rather than the answer for
// the process's real stdout.
func colorEnabled(w io.Writer) bool {
	if os.Getenv("NO_COLOR") != "" {
		return false
	}
	if os.Getenv("TERM") == "dumb" {
		return false
	}
	f, ok := w.(*os.File)
	if !ok {
		return false
	}
	st, err := f.Stat()
	if err != nil {
		return false
	}
	return st.Mode()&os.ModeCharDevice != 0
}
