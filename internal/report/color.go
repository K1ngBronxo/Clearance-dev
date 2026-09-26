package report

import "github.com/clearance-dev/clearance/internal/verdict"

// ANSI escapes. Kept as named constants rather than inline literals so that a
// reader can see every escape sequence this package can emit in one place —
// and so that a future reviewer can confirm there are only six.
const (
	ansiReset  = "\x1b[0m"
	ansiBold   = "\x1b[1m"
	ansiRed    = "\x1b[31m"
	ansiGreen  = "\x1b[32m"
	ansiYellow = "\x1b[33m"
	ansiCyan   = "\x1b[36m"
)

// ColorEnabled used to live here. It read NO_COLOR and TERM from the
// environment and stat'ed the writer to see whether it was a character device
// — which is I/O, and this package is L4. The architecture confines I/O to L0,
// L1 and L5, so the probe moved to internal/cli. `Options.Color` is the whole
// interface now, and this package imports no `os` at all.
//
// That is the point of the layering: the renderer takes a bool and produces
// bytes, so it can be tested against a buffer with no environment stubbing,
// and `internal/arch_test.go` can assert the purity mechanically.

// classColor maps a verdict to its colour (§1.1). There is no colour for an
// unrecognised class: an unknown class is a bug (E-INT-004) and colouring it
// would make it look like a designed outcome.
func classColor(c verdict.Class) string {
	switch c {
	case verdict.Ship:
		return ansiGreen
	case verdict.ShipConditional:
		return ansiYellow
	case verdict.DoNotShip:
		return ansiRed
	case verdict.Undetermined:
		return ansiCyan
	}
	return ""
}

// colourise applies the verdict's colour when colour is enabled and the class
// is known. Bold is included because the verdict is the one word on the screen
// the user is looking for.
func colourise(s string, c verdict.Class, opts Options) string {
	if !opts.Color {
		return s
	}
	col := classColor(c)
	if col == "" {
		return s
	}
	return ansiBold + col + s + ansiReset
}
