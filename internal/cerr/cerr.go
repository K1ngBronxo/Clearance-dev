package cerr

import (
	"errors"
	"fmt"
	"sort"
	"strings"
)

// Error is a typed, classified, actionable error.
//
// Every failure in Clearance is one of these (INV-5). There is deliberately no
// way to produce an untyped error in a product path: `errors.New` and
// `fmt.Errorf` without a code are banned in internal/ by the linter, because a
// message without a code is a message a stranger on a CI runner at 2am cannot
// look up.
type Error struct {
	code    Code
	class   Class
	exit    int
	message string
	detail  map[string]string
	cause   error
}

// New constructs a typed error. The args fill the `%s` placeholders in the
// code's message template; passing the wrong number is a programming error and
// panics immediately rather than emitting a message with `%!s(MISSING)` in it.
//
// A panic here is safe by construction: the interface layer recovers panics and
// reports them as E-INT-002 with exit 4, and TestEveryErrorCodeIsDocumented
// means an unknown code cannot survive a test run.
func New(c Code, args ...any) *Error {
	spec, ok := specsByCode[c]
	if !ok {
		panic(fmt.Sprintf("cerr: unknown error code %q (a code not in the taxonomy may not exist)", string(c)))
	}
	if want := spec.ArgCount(); want != len(args) {
		panic(fmt.Sprintf("cerr: %s takes %d message arguments, got %d", string(c), want, len(args)))
	}
	return &Error{
		code:    c,
		class:   spec.Class,
		exit:    spec.Exit,
		message: fmt.Sprintf(spec.Message, args...),
	}
}

// Newf is New with a single formatted detail string appended to the message.
// It exists for the rare case where a message needs a value the template does
// not have a placeholder for; prefer adding a placeholder to the taxonomy.
func Newf(c Code, args []any, format string, a ...any) *Error {
	e := New(c, args...)
	e.message = e.message + " " + fmt.Sprintf(format, a...)
	return e
}

// Error implements the error interface. The rendering is stable and is what a
// log line contains: `E-SCAN-004: Skipped symlink 'x' -> '/etc/passwd' ...`.
func (e *Error) Error() string {
	if e == nil {
		return "<nil>"
	}
	return string(e.code) + ": " + e.message
}

// Code returns the stable identifier.
func (e *Error) Code() Code { return e.code }

// Class returns FATAL / DEGRADE / WARN / INTERNAL.
func (e *Error) Class() Class { return e.class }

// ExitCode returns the process exit code if this error is terminal.
func (e *Error) ExitCode() int { return e.exit }

// Message returns the user-facing text, without the code prefix.
func (e *Error) Message() string { return e.message }

// Recovery returns the documented recovery path for this code.
func (e *Error) Recovery() string {
	if s, ok := specsByCode[e.code]; ok {
		return s.Recovery
	}
	return ""
}

// Detail returns the machine-readable detail payload, sorted by key so that
// rendering is deterministic (INV-6).
func (e *Error) Detail() []KV {
	if len(e.detail) == 0 {
		return nil
	}
	keys := make([]string, 0, len(e.detail))
	for k := range e.detail {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	out := make([]KV, 0, len(keys))
	for _, k := range keys {
		out = append(out, KV{Key: k, Value: e.detail[k]})
	}
	return out
}

// KV is one machine-readable detail pair.
type KV struct{ Key, Value string }

// Unwrap supports errors.Is / errors.As through the cause chain.
func (e *Error) Unwrap() error { return e.cause }

// WithCause attaches an underlying error (a filesystem error, a decoder error)
// without changing the code, class or exit code. The cause is for the log, not
// for the user.
func (e *Error) WithCause(err error) *Error {
	if err == nil {
		return e
	}
	c := *e
	c.cause = err
	return &c
}

// WithDetail attaches a machine-readable detail pair. Detail values must never
// contain user secrets: they are rendered into logs and into --format json.
func (e *Error) WithDetail(k, v string) *Error {
	c := *e
	c.detail = make(map[string]string, len(e.detail)+1)
	for kk, vv := range e.detail {
		c.detail[kk] = vv
	}
	c.detail[k] = v
	return &c
}

// Is makes errors.Is(err, cerr.New(cerr.ECfg001)) match by code, ignoring the
// message arguments. This is how callers branch on a failure without string
// comparison.
func (e *Error) Is(target error) bool {
	var t *Error
	if !errors.As(target, &t) {
		return false
	}
	return t.code == e.code
}

// As extracts a *Error from an error chain.
func As(err error) (*Error, bool) {
	var e *Error
	if errors.As(err, &e) {
		return e, true
	}
	return nil, false
}

// CodeOf returns the code of the first typed error in the chain, or "" if the
// error is not typed. An untyped error reaching here is a bug: the linter
// forbids producing one in internal/.
func CodeOf(err error) Code {
	if e, ok := As(err); ok {
		return e.code
	}
	return ""
}

// ClassOf returns the class of the first typed error in the chain, or
// ClassInternal for an untyped error (because an untyped error *is* a bug).
func ClassOf(err error) Class {
	if e, ok := As(err); ok {
		return e.class
	}
	return ClassInternal
}

// ExitCodeOf maps an error to a process exit code. An untyped error maps to
// ExitInternal, because a failure we cannot classify is by definition a bug in
// Clearance rather than a condition in the user's project.
func ExitCodeOf(err error) int {
	if err == nil {
		return ExitOK
	}
	if e, ok := As(err); ok {
		return e.exit
	}
	return ExitInternal
}

// IsFatal reports whether an error stops the run.
func IsFatal(err error) bool {
	if err == nil {
		return false
	}
	c := ClassOf(err)
	return c == ClassFatal || c == ClassInternal
}

// Wrap converts a plain error from the standard library into a typed one,
// keeping the original as the cause. This is the ONLY sanctioned way to
// introduce an error from outside this package, and it always names a code.
func Wrap(c Code, cause error, args ...any) *Error {
	return New(c, args...).WithCause(cause)
}

// Join formats several codes' messages into one line, for the cases where a
// validation pass finds more than one problem at once (a config with three
// missing fields should say all three, not one at a time).
func Join(errs []error) string {
	if len(errs) == 0 {
		return ""
	}
	parts := make([]string, 0, len(errs))
	for _, e := range errs {
		if e != nil {
			parts = append(parts, e.Error())
		}
	}
	return strings.Join(parts, "; ")
}

// ArgCount returns how many `%s` placeholders the message template has. It is
// computed rather than hand-maintained so it cannot drift from the text.
func (s Spec) ArgCount() int { return strings.Count(s.Message, "%s") }
