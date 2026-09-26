// Package report renders a Verdict. It is L4.
//
// The rule this package obeys absolutely: a renderer formats, it never decides.
// It may not import L1 (scanner, parsers) or L2 (corpus), because a renderer
// that can read the filesystem is a renderer that can produce a fact the
// verdict does not contain. Every fact printed below is read out of the
// verdict.Verdict it was handed, or out of the frozen error taxonomy.
//
// R6 in PLAN/02-SPECIFICATIONS/03-verdict-output-spec.md §6 says exactly this,
// and internal/arch_test.go enforces it at build time.
//
// ─── Where this file deviates from the spec's worked examples ───────────────
//
// The examples in §1.1–§1.4 of the output spec are internally inconsistent
// about column alignment. §1.2 states a rule — "[BLOCK] / [COND] / [NOTE] /
// [UNDETERMINED] are left-aligned in a fixed 14-column field" — but the example
// directly beneath it indents the dependency name to column 10, and the §1.4
// example indents to column 16. The detail lines are inconsistent too:
// `clause:` and `reason:` get two spaces of padding, `evidence:` gets one, and
// `confidence:` gets one after an eleven-character label.
//
// A golden-file contract cannot be satisfied against three mutually exclusive
// layouts, so this file implements the *stated rules* — 40-character separator,
// 14-column severity field, 30-character truncated name, mandatory clause /
// evidence / confidence lines — and makes the alignment self-consistent, which
// is what R7 ("column alignment is stable across runs") actually asks for. The
// detail-label field is 11 columns, chosen because `confidence:` is exactly 11
// characters wide, so the common case needs no padding at all.
//
// This deviation is recorded in LOGS.md. It is a spec defect, not a code
// defect, and the fix belongs in the spec.
package report

import (
	"io"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/cite"
	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// Layout constants. They are constants rather than options because R7 makes
// them part of the contract: a user's terminal is not a reason for the columns
// to move.
const (
	// SeparatorWidth is fixed at 40 regardless of content (§1.1).
	SeparatorWidth = 40

	// SeverityFieldWidth is the fixed field the [BLOCK]/[COND]/[NOTE]/
	// [UNDETERMINED] tag is left-aligned in (§1.2).
	SeverityFieldWidth = 14

	// NameFieldWidth is the column width a dependency name occupies before the
	// licence is printed. Names longer than this are truncated with a single
	// U+2026 HORIZONTAL ELLIPSIS (§1.2).
	NameFieldWidth = 30

	// severityGap separates the severity tag field from the dependency name.
	severityGap = 2

	// detailIndent is how far the per-finding detail lines are indented.
	//
	// It is DERIVED from SeverityFieldWidth rather than written as a literal.
	// An earlier version hardcoded 10, which put `clause:` and `reason:` four
	// columns to the left of the dependency name they belonged to — and since
	// R7 makes column alignment part of the contract, that was a contract
	// violation rather than a cosmetic one. Deriving it means the two cannot
	// drift apart again.
	detailIndent = SeverityFieldWidth + severityGap

	// detailLabelWidth is the width of the `clause:` / `reason:` / ... label
	// field, INCLUDING the gap before the value.
	//
	// 12, not 11. `confidence:` is exactly 11 characters, so a field of 11
	// left it with no separating space at all and the output read
	// `confidence:HIGH`. A label field must always be wider than its widest
	// label.
	detailLabelWidth = 12

	// quoteIndent is how far a quoted excerpt is indented beneath its
	// confidence line (§1.2, the MEDIUM/LOW case).
	quoteIndent = detailIndent + 4

	// headerLabelWidth is the width of the `SHIP:` / `BLOCKERS:` label field in
	// the header block, so all five values line up at column 13 (§1.1).
	headerLabelWidth = 13

	// DefaultWidth is the wrap width for prose fields when the caller does not
	// supply one.
	DefaultWidth = 100
)

// Disclaimer is the mandatory footer text (§1.3).
//
// R1 asserts this string is present in every human and Markdown output. It is
// not configurable, it is not suppressible by a flag, and it is not moved. A
// licence tool that can be made to stop saying it is not giving advice is a
// licence tool that is pretending to be a lawyer.
//
// The rule above it in §1.3 — a `---` separator — is deliberately NOT part of
// this constant. A separator is a layout decision and belongs to the renderer;
// baking it into the text would mean the Markdown `<sub>` variant, which has no
// separator, could not share the constant. The text is the disclaimer; the
// separator is how one renderer introduces it.
const Disclaimer = `This is an informational finding based on the licence text as published on the
date recorded. It is not legal advice. Ambiguous clauses are flagged as such.
Important decisions should be reviewed by a qualified professional.`

// DisclaimerSentence is the one sentence common to every disclaimer variant in
// the spec (the human block in §1.3 and the Markdown `<sub>` in §3 differ in
// wording). Tests assert on this, so that a future renderer cannot satisfy R1
// by printing a disclaimer that no longer says the thing that matters.
const DisclaimerSentence = "Important decisions should be reviewed by a qualified professional."

// Options controls rendering. Every field is a presentation choice; none of
// them can change what the verdict says.
type Options struct {
	// Color enables ANSI colour. It must be false when stdout is not a TTY or
	// NO_COLOR is set (R8). The caller decides — this package is L4 and does
	// not probe the environment; see internal/cli/tty.go.
	Color bool

	// Width is the prose wrap width. Zero means DefaultWidth.
	Width int

	// Strict reports that --strict was in effect, which changes only the
	// wording of the UNDETERMINED explanation, never the verdict.
	Strict bool

	// NoNotes suppresses the NOTE section. It is off by default, because a note
	// the user cannot see is a finding they were not told about.
	NoNotes bool

	// Verbose adds the fired predicate beneath each finding. A verdict a user
	// cannot interrogate is a verdict they will not trust, so this exists — but
	// it is opt-in because it makes the common case unreadable.
	Verbose bool
}

func (o Options) width() int {
	if o.Width <= 0 {
		return DefaultWidth
	}
	return o.Width
}

// WriteHuman renders the terminal form.
//
// A non-nil return means the *destination* failed, never the verdict: a
// renderer failure on well-formed input is a bug, not a user condition. The
// write error is propagated rather than swallowed because a truncated report
// piped into a file looks exactly like a clean bill of health.
func WriteHuman(w io.Writer, v verdict.Verdict, opts Options) error {
	b := &builder{w: w}

	writeHeader(b, v, opts)
	writeSummaryBlock(b, v)

	writeFindings(b, "BLOCKERS", policy.SeverityBlock, v.Blockers, opts)
	writeFindings(b, "CONDITIONS", policy.SeverityCondition, v.Conditions, opts)
	if !opts.NoNotes {
		writeFindings(b, "NOTES", policy.SeverityNote, v.Notes, opts)
	}
	writeUndetermined(b, v.Undetermined)

	b.blank()
	b.raw(strings.Repeat("-", SeparatorWidth))
	b.raw(Disclaimer)

	return b.err
}

// ─── header ────────────────────────────────────────────────────────────────

func writeHeader(b *builder, v verdict.Verdict, opts Options) {
	b.raw("CLEARANCE VERDICT — " + v.Project)
	b.raw(strings.Repeat("=", SeparatorWidth))
	b.kv("SHIP:", colourise(v.Verdict.Label(), v.Verdict, opts))
	b.kv("BLOCKERS:", itoa(len(v.Blockers)))
	b.kv("CONDITIONS:", itoa(len(v.Conditions)))
	b.kv("SCANNED:", scannedLine(v.Summary))

	// The corpus line is the trust anchor: a verdict computed against an
	// unsigned corpus is a verdict against a corpus anybody could have edited,
	// so the marker is loud rather than subtle.
	switch {
	case v.Meta.CorpusVersion == "":
		b.kv("CORPUS:", "not loaded")
	case v.Meta.CorpusSigned:
		b.kv("CORPUS:", v.Meta.CorpusVersion+" · signed ✓")
	default:
		b.kv("CORPUS:", v.Meta.CorpusVersion+" · UNSIGNED ✗")
	}
}

func writeSummaryBlock(b *builder, v verdict.Verdict) {
	// §1.4 asks for an explicit reason line when the verdict is UNDETERMINED,
	// because "UNDETERMINED" on its own does not tell the user what to do.
	if v.Verdict != verdict.Undetermined || len(v.Undetermined) == 0 {
		return
	}
	n := len(v.Undetermined)
	b.kv("REASON:", itoa(n)+" "+plural(n, "item", "items")+" could not be classified")
	if v.Meta.CorpusSigned {
		return
	}
	// An unsigned corpus is a plausible cause of an undetermined verdict, so it
	// is named as one rather than left for the user to work out.
	b.kv("NOTE:", "the corpus is unsigned, so its contents could not be trusted")
}

func scannedLine(s verdict.Summary) string {
	parts := []string{
		itoa(s.Dependencies) + " " + plural(s.Dependencies, "dependency", "dependencies"),
	}
	if s.WeightFiles > 0 {
		parts = append(parts, itoa(s.WeightFiles)+" "+plural(s.WeightFiles, "weight file", "weight files"))
	}
	if s.UpstreamCLIs > 0 {
		parts = append(parts, itoa(s.UpstreamCLIs)+" "+plural(s.UpstreamCLIs, "upstream CLI", "upstream CLIs"))
	}
	return strings.Join(parts, " · ")
}

// ─── findings ──────────────────────────────────────────────────────────────

// writeFindings renders one section. section is the severity the section is
// *for*, which is how writeFinding detects a finding that the confidence gate
// moved down: Fold places a finding by its effective severity, so a finding
// whose corpus severity outranks the section it is sitting in was gated.
func writeFindings(b *builder, heading string, section policy.Severity, fs []policy.Finding, opts Options) {
	if len(fs) == 0 {
		return
	}
	b.blank()
	b.raw(heading)
	for i := range fs {
		b.blank()
		writeFinding(b, fs[i], section, opts)
	}
}

func writeFinding(b *builder, f policy.Finding, section policy.Severity, opts Options) {
	tag := tagFor(f.Severity)
	if tag == "" {
		// A severity the taxonomy does not define. Printing it verbatim beats
		// guessing a tag; E-INT-004 documents the state.
		tag = "[?]"
	}

	// The head line is `[TAG]  name  LICENCE`, with every column padded so
	// that the eye can scan a long blocker list (§1.2, R7).
	//
	// The NAME is shown, not the raw dependency id. The id is
	// `npm:firecrawl@1.2.3`, which is precise but unreadable in a column, and
	// the version is already implied by the evidence line beneath.
	name := truncate(displayName(f.DependencyID), NameFieldWidth)
	head := pad(tag, SeverityFieldWidth) + strings.Repeat(" ", severityGap) +
		pad(name, NameFieldWidth)
	if f.Licence != "" {
		head += strings.Repeat(" ", severityGap) + f.Licence
	}
	b.raw(strings.TrimRight(head, " "))

	// clause: is mandatory (INV-1). An empty citation is the exact failure this
	// product exists to prevent, so it is printed as loudly as possible rather
	// than omitted.
	if f.Citation.Section == "" && f.Citation.URL == "" {
		b.detail("clause:", "MISSING — this is a bug (E-POLICY-002)")
	} else {
		if f.Citation.Section != "" {
			b.detail("clause:", f.Citation.Section)
		}
		if f.Citation.URL != "" {
			b.detail("source:", f.Citation.URL)
		}
	}

	if f.Title != "" {
		b.detail("finding:", f.Title)
	}
	if f.Reason != "" {
		b.detailWrapped("reason:", f.Reason, opts.width())
	}

	// Evidence is mandatory (§1.2). A finding that cannot say where it looked
	// is a finding the user cannot check.
	if len(f.Evidence) == 0 {
		b.detail("evidence:", "NONE RECORDED — this is a bug (INV-1)")
	} else {
		for i, ev := range f.Evidence {
			label := "evidence:"
			if i > 0 {
				label = ""
			}
			b.detail(label, evidenceLine(ev))
		}
	}

	if f.TrapID != "" {
		b.detail("trap:", f.TrapID)
	}

	// The confidence gate, made visible. Without this line a user seeing an
	// AGPL trap filed under NOTES would reasonably conclude the tool had
	// cleared it, when what actually happened is that the tool declined to
	// decide. That distinction is the whole product.
	if f.Severity.Weight() > section.Weight() {
		why := "confidence is LOW"
		if f.Confidence == policy.ConfidenceMedium {
			why = "confidence is MEDIUM"
		}
		b.detail("gate:", "severity "+string(f.Severity)+" → "+string(section)+" because "+why)
	}

	// confidence: is mandatory (INV-2).
	conf := string(f.Confidence)
	if conf == "" {
		conf = "MISSING — this is a bug (E-POLICY-007)"
	}
	if f.Confidence == policy.ConfidenceMedium || f.Confidence == policy.ConfidenceLow {
		b.detail("confidence:", conf+" — "+ambiguityNote(f.Confidence))
		// §1.2: the excerpt follows, indented, so the user can judge the
		// ambiguity for themselves instead of taking the label on trust.
		//
		// Whether it gets quotation marks depends on excerpt_kind, and that is
		// not a formatting preference. A quotation mark is a claim that the
		// words are the source's. The corpus was audited on 23 September 2026
		// and twelve of fourteen sampled excerpts turned out to be rewordings
		// that had been rendered in quotation marks since the first release —
		// a fabricated quotation, produced by the one tool whose entire claim
		// is that it quotes the exact clause. The marks are now printed only
		// for ExcerptVerbatim, which is a claim somebody actually checked.
		writeExcerpt(b, f.Citation, opts)
	} else {
		b.detail("confidence:", conf)
	}

	if f.UndeterminedField != "" {
		b.detail("needs:", "declare use."+f.UndeterminedField+" in the config to resolve this")
	}

	if f.Fix != nil && f.Fix.Suggestion != "" {
		fix := f.Fix.Suggestion
		if f.Fix.Alternative != "" {
			fix += " (alternative: " + f.Fix.Alternative + ")"
		}
		b.detailWrapped("fix:", fix, opts.width())
	}

	if opts.Verbose && f.Predicate != nil {
		b.detailWrapped("predicate:", f.Predicate.String(), opts.width())
	}
}

func ambiguityNote(c policy.Confidence) string {
	if c == policy.ConfidenceLow {
		return "the tool could not classify this confidently"
	}
	return "clause text is ambiguous"
}

func tagFor(s policy.Severity) string {
	switch s {
	case policy.SeverityBlock:
		return "[BLOCK]"
	case policy.SeverityCondition:
		return "[COND]"
	case policy.SeverityNote:
		return "[NOTE]"
	case policy.SeverityInfo:
		return "[INFO]"
	}
	return ""
}

// displayName resolves the name to show for a dependency.
//
// The id shapes are fixed by graph.PackageID and graph.LocalID:
//
//	npm:firecrawl@1.2.3      → firecrawl
//	pypi:torch               → torch
//	weights:models/model.bin → model.bin
//	vendored:node_modules/a  → a
//
// Deriving the name means the human renderer needs nothing but a Verdict, which
// is what makes it testable from a golden file with no graph in scope. The raw
// id is returned when nothing better can be derived: showing
// `npm:firecrawl@1.2.3` is merely ugly, while showing an empty column is a
// finding the user cannot identify.
func displayName(id string) string {
	rest := id
	if i := strings.IndexByte(rest, ':'); i >= 0 {
		rest = rest[i+1:]
	}
	// Strip a trailing @version — but only when the @ is not at position 0.
	// An npm scope is `@scope/name`, which carries no version, while
	// `@scope/name@1.0` does.
	if i := strings.LastIndexByte(rest, '@'); i > 0 {
		rest = rest[:i]
	}
	if rest == "" {
		return id
	}
	return rest
}

func evidenceLine(ev graph.Evidence) string {
	s := ev.Path
	if ev.LineStart > 0 {
		s += ":" + itoa(ev.LineStart)
		if ev.LineEnd > ev.LineStart {
			s += "-" + itoa(ev.LineEnd)
		}
	}
	if ev.Excerpt != "" {
		s += " — " + ev.Excerpt
	}
	return s
}

// ─── undetermined ──────────────────────────────────────────────────────────

func writeUndetermined(b *builder, us []graph.Undetermined) {
	if len(us) == 0 {
		return
	}
	b.blank()
	b.raw("UNDETERMINED")
	for i := range us {
		b.blank()
		u := us[i]
		// Same head layout as a finding: tag field, gap, name field, gap,
		// summary. `[UNDETERMINED]` is exactly SeverityFieldWidth characters,
		// so it fills the field completely and the separating gap has to come
		// from severityGap — without it the name ran straight into the
		// closing bracket and read `[UNDETERMINED]npm:leftpad@1.0.0`.
		head := pad("[UNDETERMINED]", SeverityFieldWidth) +
			strings.Repeat(" ", severityGap) +
			pad(truncate(displayName(u.ID), NameFieldWidth), NameFieldWidth) +
			strings.Repeat(" ", severityGap) + humaniseReason(u.Reason)
		b.raw(strings.TrimRight(head, " "))

		if u.ErrorCode != "" {
			b.detail("error:", u.ErrorCode+" — "+u.Detail)
		} else if u.Detail != "" {
			b.detail("reason:", u.Detail)
		}
		for i, ev := range u.Evidence {
			label := "evidence:"
			if i > 0 {
				label = ""
			}
			b.detail(label, evidenceLine(ev))
		}
		b.detail("action:", actionFor(u))
	}
}

// actionFor reads the recovery text from the frozen error taxonomy. It is the
// reason the taxonomy carries a Recovery string for every code: the tool can
// always tell the user what to do next, even when it cannot classify what it
// found. A tool that says "UNDETERMINED" and stops has moved the problem, not
// solved it.
func actionFor(u graph.Undetermined) string {
	const fallback = "supply the missing fact, or remove the file from the scan"
	if u.ErrorCode == "" {
		return fallback
	}
	spec, ok := cerr.Lookup(cerr.Code(u.ErrorCode))
	if !ok || spec.Recovery == "" {
		return fallback
	}
	return spec.Recovery
}

// humaniseReason turns the machine reason code into something a person reads.
// The machine code is preserved verbatim in the JSON; this is display only.
func humaniseReason(r string) string { return strings.ReplaceAll(r, "_", " ") }

// ─── builder ───────────────────────────────────────────────────────────────

// builder accumulates lines and remembers the first write error. Sticky errors
// matter: `clearance check . > report.txt` onto a full disk must fail, not
// silently produce a truncated file that reads like a clean bill of health.
type builder struct {
	w   io.Writer
	err error
}

func (b *builder) raw(s string) {
	if b.err != nil {
		return
	}
	if _, err := io.WriteString(b.w, s+"\n"); err != nil {
		b.err = err
	}
}

func (b *builder) blank() { b.raw("") }

// kv writes a header row at headerLabelWidth, so every value lines up.
func (b *builder) kv(label, value string) { b.raw(pad(label, headerLabelWidth) + value) }

// detail writes an indented label/value pair at detailLabelWidth.
func (b *builder) detail(label, value string) {
	if label == "" {
		b.raw(strings.Repeat(" ", detailIndent+detailLabelWidth) + value)
		return
	}
	b.raw(strings.Repeat(" ", detailIndent) + pad(label, detailLabelWidth) + value)
}

// detailWrapped writes a label followed by word-wrapped prose, with the
// continuation lines aligned under the first value column.
func (b *builder) detailWrapped(label, value string, width int) {
	avail := width - detailIndent - detailLabelWidth
	if avail < 20 {
		avail = 20
	}
	lines := wrap(value, avail)
	if len(lines) == 0 {
		b.detail(label, "")
		return
	}
	b.detail(label, lines[0])
	for _, ln := range lines[1:] {
		b.raw(strings.Repeat(" ", detailIndent+detailLabelWidth) + ln)
	}
}

// ─── text helpers ──────────────────────────────────────────────────────────

// pad right-pads s to width columns. Width is measured in runes, not bytes,
// because a dependency name is user data and may contain anything.
func pad(s string, width int) string {
	n := runeLen(s)
	if n >= width {
		return s
	}
	return s + strings.Repeat(" ", width-n)
}

// truncate shortens s to at most width runes, appending U+2026 when it had to.
// The ellipsis counts toward the width, so the result never exceeds it.
func truncate(s string, width int) string {
	r := []rune(s)
	if len(r) <= width {
		return s
	}
	if width <= 1 {
		return string(r[:width])
	}
	return string(r[:width-1]) + "…"
}

func runeLen(s string) int { return len([]rune(s)) }

// wrap breaks prose at word boundaries. It is deterministic — the same input
// always produces the same lines — because R7 applies to wrapped prose too.
//
// A word longer than the limit is emitted on its own line rather than broken:
// splitting a URL or a long identifier across lines makes it un-copyable, and
// a citation the user cannot copy is a citation they cannot check.
func wrap(s string, width int) []string {
	if width <= 0 {
		return []string{s}
	}
	words := strings.Fields(s)
	if len(words) == 0 {
		return nil
	}
	var out []string
	cur := words[0]
	for _, w := range words[1:] {
		if runeLen(cur)+1+runeLen(w) <= width {
			cur += " " + w
			continue
		}
		out = append(out, cur)
		cur = w
	}
	return append(out, cur)
}

// quote wraps an excerpt in typographic quotes, matching the Markdown form in
// §3. It distinguishes a quoted licence clause from the tool's own prose at a
// glance, which matters because the two must never be confused.
func quote(s string) string { return "“" + s + "”" }

// writeExcerpt prints a citation's excerpt beneath the confidence line.
//
// There are two forms because there are two different claims, and conflating
// them is the most damaging thing this renderer could do:
//
//	verbatim              → “the source's own words”
//	paraphrase/unverified → Clearance's reading: the same point, in our words
//
// A paraphrase is genuinely useful and is often clearer than the clause. What
// it is not is a quotation, and it may never be dressed as one.
func writeExcerpt(b *builder, c cite.Citation, opts Options) {
	if c.Excerpt == "" {
		return
	}
	indent := strings.Repeat(" ", quoteIndent)
	width := opts.width() - quoteIndent
	if width < 20 {
		width = 20
	}

	if c.ExcerptKind.IsVerbatim() {
		// One pair of quotation marks around the whole excerpt, not one pair
		// per wrapped line. A quote on every line reads as several separate
		// quotations, which is a different claim about the source.
		lines := wrap(c.Excerpt, width-2)
		for i, ln := range lines {
			switch {
			case len(lines) == 1:
				b.raw(indent + quote(ln))
			case i == 0:
				b.raw(indent + "“" + ln)
			case i == len(lines)-1:
				b.raw(indent + ln + "”")
			default:
				b.raw(indent + ln)
			}
		}
		return
	}

	// The label states the provenance of the words. `unverified` says so out
	// loud rather than borrowing `paraphrase`'s respectability, because "we
	// restated this" and "we do not know whether we restated this or copied
	// it" are different claims and only one of them is safe to imply.
	//
	// The label gets its own line rather than prefixing the text: the
	// unverified label is 55 characters, and hanging the paragraph off the end
	// of it pushed every continuation line halfway across the terminal.
	label := "Clearance's reading:"
	if c.ExcerptKind == cite.ExcerptUnverified {
		label = "Clearance's reading (not yet checked against the source):"
	}
	b.raw(indent + label)
	for _, ln := range wrap(c.Excerpt, width) {
		b.raw(indent + ln)
	}
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}

// itoa is a tiny integer formatter. The report package formats numbers in
// exactly one place, and pulling in strconv for it would make it the only
// reason this package imports anything beyond io and strings.
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}
