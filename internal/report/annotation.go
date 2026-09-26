package report

import (
	"fmt"
	"io"
	"strings"
)

// Annotation is out-of-band commentary printed beside a report.
//
// # WHY THIS TYPE EXISTS AND WHY IT IS NAMED FOR WHAT IT IS
//
// AI output may appear in the human terminal output, and only there, and only in
// a block that says plainly that it is not part of the verdict
// (PLAN/02-SPECIFICATIONS/10-ai-provider-spec.md §6.3).
//
// The renderer must not know that. `internal/report` is L4 and is a pure
// `Verdict → bytes` function; giving it a parameter of type `ai.Suggestion`
// would make the renderer depend on the AI layer, and the separation that keeps
// AI output out of `verdict.json` would then rest on care rather than on the
// type system.
//
// So the renderer is handed a heading and some lines, which is all it needs, and
// it cannot tell whether they came from a model, a plugin or a human. The
// heading is chosen by the caller; the one the AI layer uses is
// AnnotationAIHeading below, which says the thing that has to be said.
type Annotation struct {
	// Heading is the first line, printed verbatim. It must state the block's
	// status, not merely its topic: "AI explanation" describes the content, and
	// "AI EXPLANATION — not part of the verdict" describes its authority, which
	// is the fact a reader needs before they act on it.
	Heading string

	// Lines are the body. They are printed with a two-space indent.
	Lines []string
}

// AnnotationAIHeading is the heading the AI layer uses, and it is a constant
// here rather than a string literal in the CLI so that the wording has one home
// and a test can assert the block carries it.
const AnnotationAIHeading = "AI EXPLANATION — not part of the verdict"

// WriteAnnotation renders an annotation to w.
//
// It is deliberately not part of Write: a caller that wants the verdict alone —
// a CI log, a `--format json` consumer, a SARIF upload — must be able to get it,
// and a renderer that printed an annotation because one happened to be set would
// make the canonical output depend on an optional input.
//
// The block goes to whatever writer the caller passes, and the CLI passes
// stderr, so that `clearance check . > verdict.txt` produces a file that is
// still exactly the verdict.
func WriteAnnotation(w io.Writer, a Annotation, opts Options) error {
	if strings.TrimSpace(a.Heading) == "" || len(a.Lines) == 0 {
		return nil
	}

	head := a.Heading
	rule := strings.Repeat("─", displayWidth(head))
	if opts.Color {
		head = ansiBold + head + ansiReset
	}

	if _, err := fmt.Fprintf(w, "\n%s\n%s\n", head, rule); err != nil {
		return err
	}
	for _, line := range a.Lines {
		line = strings.TrimRight(line, " \t")
		if line == "" {
			if _, err := fmt.Fprintln(w); err != nil {
				return err
			}
			continue
		}
		if _, err := fmt.Fprintf(w, "  %s\n", line); err != nil {
			return err
		}
	}
	return nil
}

// displayWidth counts the runes of the first line of s, so the rule under a
// heading is the right length even when the heading is a multi-byte em dash.
func displayWidth(s string) int {
	if i := strings.IndexByte(s, '\n'); i >= 0 {
		s = s[:i]
	}
	// The heading may carry ANSI codes when colour is on; count only what a
	// reader sees. A crude strip is enough here because the only escape
	// sequences this package emits are its own two constants.
	if strings.Contains(s, "\x1b[") {
		var b strings.Builder
		inEscape := false
		for _, r := range s {
			switch {
			case r == '\x1b':
				inEscape = true
			case inEscape && r == 'm':
				inEscape = false
			case !inEscape:
				b.WriteRune(r)
			}
		}
		s = b.String()
	}
	return len([]rune(s))
}
