// Package interface is L5: the process boundary.
//
// It is the only package allowed to read the environment, read the clock, and
// touch the network. Everything below it is pure or root-scoped, which is what
// makes the decision engine testable without a filesystem and what makes INV-3
// ("the scanner never phones home") checkable by reading one file — see
// netclient.go.
//
// The rule for this package is that it may *supply* facts and may *present*
// facts, but it may never *decide* one. Concretely: this package is allowed to
// say "the config is at this path" and "today is the 23rd"; it is not allowed
// to say "that licence is fine". Every judgement lives in internal/policy.
package cli

import (
	"fmt"
	"io"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// fail renders a typed error and returns the exit code the taxonomy assigns it.
//
// The exit code is read from the error rather than chosen here, so that the
// frozen contract in ADR-008 has exactly one source of truth. A caller that
// invented an exit code at the call site could drift from the taxonomy, and the
// taxonomy is what CI pipelines are written against.
func fail(stderr io.Writer, err error) int {
	if err == nil {
		return cerr.ExitOK
	}

	e, ok := cerr.As(err)
	if !ok {
		// An untyped error escaped. That is itself a defect (INV-5: every error
		// is typed), so it is reported as internal rather than guessed at.
		fmt.Fprintf(stderr, "clearance: internal error: %v\n", err)
		fmt.Fprintf(stderr, "  this is a bug - every error should carry a code\n")
		return cerr.ExitInternal
	}

	fmt.Fprintf(stderr, "clearance: %s — %s\n", e.Code(), e.Message())
	for _, kv := range e.Detail() {
		fmt.Fprintf(stderr, "  %s: %s\n", kv.Key, kv.Value)
	}
	if r := e.Recovery(); r != "" {
		fmt.Fprintf(stderr, "  fix: %s\n", r)
	}
	return e.ExitCode()
}

// noticeText renders a warning that is not a taxonomy error. It exists for
// corpus load notices, which are already-coded strings rather than *cerr.Error
// values because the corpus package may not import the decision layer.
func noticeText(stderr io.Writer, code, message string) {
	if message == "" {
		return
	}
	if code == "" {
		fmt.Fprintf(stderr, "clearance: %s\n", message)
		return
	}
	fmt.Fprintf(stderr, "clearance: %s — %s\n", code, message)
}
