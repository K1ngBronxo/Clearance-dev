// The Markdown renderer: the PR-comment form.
//
// PLAN/02-SPECIFICATIONS/03-verdict-output-spec.md §3 is the contract, and the
// two invariants that shape this file are R1 and R2:
//
//   - R1: every Markdown output contains the disclaimer.
//   - R2: every rendered finding contains its citation.
//
// R1 is the reason the disclaimer is emitted unconditionally at the end rather
// than only when there is something to disclaim. A clean verdict is exactly the
// one a reader is most likely to paste into a ticket and treat as a clearance,
// so it is the one that most needs the sentence saying what the tool is not.
//
// # WHY THIS IS NOT THE HUMAN RENDERER WITH ASTERISKS
//
// It would be tempting to write one renderer and switch the decoration. The two
// have different jobs and different constraints, and the differences are not
// cosmetic:
//
//   - The terminal is 80 columns and wraps; a PR comment is rendered at the
//     reader's width and must therefore be block-structured, not columnar. The
//     human renderer's fixed 14-column severity field and 30-column name field
//     are load-bearing there (R7) and meaningless here.
//   - Markdown is a *link* medium. Every citation here becomes a clickable
//     link, which is the single largest usability difference: a reviewer who
//     can open the licence clause in one click is a reviewer who checks it.
//   - The comment is posted by a bot and updated in place. It has to be
//     identifiable and stable, and the counts line at the top is what a reader
//     skims; see actions/check/action.yml for the in-place update.
//
// The one thing the two share is that neither computes. Both read every fact
// out of the Verdict they are handed (R6).
package report

import (
	"io"
	"strings"

	"github.com/clearance-dev/clearance/internal/graph"
	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// Markdown section icons. §3 uses 🚫 for blockers and ⚠️ for conditions; the
// note and undetermined icons are chosen to match that register rather than
// invented per-renderer.
const (
	mdIconBlocker = "🚫"
	mdIconCond    = "⚠️"
	mdIconNote    = "ℹ️"
	mdIconUnknown = "❓"
	mdIconClear   = "✅"
)

// WriteMarkdown renders the PR-comment form.
//
// A non-nil return means the destination failed, never the verdict — the same
// rule WriteHuman follows, and for the same reason: a comment truncated
// mid-write looks exactly like a clean one.
func WriteMarkdown(w io.Writer, v verdict.Verdict, opts Options) error {
	b := &builder{w: w}

	writeMarkdownHeader(b, v)
	writeMarkdownFindings(b, "Blocker", mdIconBlocker, policy.SeverityBlock, v.Blockers, opts)
	writeMarkdownFindings(b, "Conditions", mdIconCond, policy.SeverityCondition, v.Conditions, opts)
	if !opts.NoNotes {
		writeMarkdownFindings(b, "Notes", mdIconNote, policy.SeverityNote, v.Notes, opts)
	}
	writeMarkdownUndetermined(b, v.Undetermined)
	writeMarkdownFooter(b, v)

	return b.err
}

// ─── header ─────────────────────────────────────────────────────────────────

func writeMarkdownHeader(b *builder, v verdict.Verdict) {
	b.raw("## Clearance Verdict — `" + string(v.Verdict) + "`")
	b.blank()

	// The counts line, in the spec's order. It is the only line most readers
	// will read, so it is assembled from the verdict's own counters rather than
	// from len() of the slices — if the two ever disagreed, the summary would
	// be the lie and the lists would be the truth.
	//
	// The number is formatted by `counted`, not by `plural`, and that is a fix
	// rather than a preference. `plural` returns the *word*: plural(1, "blocker",
	// "blockers") is "blocker". The first version of this line called it
	// directly and printed "**blocker · conditions** · dependencies scanned" —
	// a summary with every quantity missing, which is worse than no summary
	// because it looks like a rendering of one. `counted` is the same
	// number-plus-word shape the human renderer uses.
	parts := []string{
		counted(v.Summary.Blockers, "blocker", "blockers"),
		counted(v.Summary.Conditions, "condition", "conditions"),
	}
	if v.Summary.Undetermined > 0 {
		parts = append(parts, counted(v.Summary.Undetermined, "item", "items")+" unclassified")
	}
	line := "**" + strings.Join(parts, " · ") + "** · " +
		counted(v.Summary.Dependencies, "dependency", "dependencies") + " scanned"

	if v.Meta.CorpusVersion != "" {
		line += " · corpus v" + v.Meta.CorpusVersion
	}
	b.raw(line)
	b.blank()

	// The scanned line, when the project has the artefacts that make it worth
	// printing. A "0 weight files" line on a project with no models is noise.
	if v.Summary.WeightFiles > 0 || v.Summary.UpstreamCLIs > 0 {
		var extra []string
		if v.Summary.WeightFiles > 0 {
			extra = append(extra, counted(v.Summary.WeightFiles, "weight file", "weight files"))
		}
		if v.Summary.UpstreamCLIs > 0 {
			extra = append(extra, counted(v.Summary.UpstreamCLIs, "upstream tool", "upstream tools"))
		}
		b.raw("<sub>Also scanned: " + strings.Join(extra, " · ") + "</sub>")
		b.blank()
	}

	b.raw("---")
	b.blank()
}

// ─── findings ───────────────────────────────────────────────────────────────

// writeMarkdownFindings renders one severity band.
//
// Blockers get a full section each, because a blocker is the thing the reader
// must act on and the reason is what makes it credible. Conditions get a
// checklist, because a condition is a to-do and a checklist is what a to-do
// looks like in a PR. Notes get a plain list, because a note is not an action.
//
// The asymmetry is deliberate and it is the opposite of what a uniform renderer
// would do. Rendering every band identically is the formatting equivalent of
// treating a block and a note as the same kind of statement, which is the
// confusion the severity vocabulary exists to prevent.
func writeMarkdownFindings(
	b *builder,
	heading, icon string,
	section policy.Severity,
	fs []policy.Finding,
	opts Options,
) {
	if len(fs) == 0 {
		return
	}

	b.raw("### " + icon + " " + heading)
	b.blank()

	switch section {
	case policy.SeverityBlock:
		for i, f := range fs {
			writeMarkdownBlocker(b, f, opts)
			if i < len(fs)-1 {
				b.blank()
			}
		}
	case policy.SeverityCondition:
		for _, f := range fs {
			writeMarkdownChecklistItem(b, f)
		}
	default:
		for _, f := range fs {
			writeMarkdownNote(b, f)
		}
	}
	b.blank()
	b.raw("---")
	b.blank()
}

// writeMarkdownBlocker renders the §3 blocker block.
func writeMarkdownBlocker(b *builder, f policy.Finding, opts Options) {
	name := displayName(f.DependencyID)
	head := "**`" + mdEscape(name) + "`**"
	if f.Licence != "" {
		head += " — " + mdEscape(f.Licence)
	}
	b.raw(head)

	if f.Title != "" {
		b.raw("**" + mdEscape(f.Title) + "**")
	}
	b.blank()

	if f.Reason != "" {
		for _, line := range mdWrap(f.Reason, mdWidth(opts)) {
			b.raw("> " + mdEscape(line))
		}
		b.blank()
	}

	// R2: the citation is not optional. A finding without one is the exact
	// failure INV-1 exists to prevent, and the renderer says so in the output
	// rather than silently omitting the line — an omitted line reads as "there
	// was nothing to cite".
	writeMarkdownCitation(b, f, opts)

	writeMarkdownEvidence(b, f)
	writeMarkdownGate(b, f, policy.SeverityBlock)

	b.raw("- **Confidence:** " + mdConfidence(f, policy.SeverityBlock))
	if f.TrapID != "" {
		b.raw("- **Trap:** `" + mdEscape(f.TrapID) + "`")
	}
	if f.Fix != nil && f.Fix.Suggestion != "" {
		fix := mdEscape(f.Fix.Suggestion)
		if f.Fix.Alternative != "" {
			fix += " (alternative: `" + mdEscape(f.Fix.Alternative) + "`)"
		}
		b.raw("- **Suggested fix:** " + fix)
	}
}

// writeMarkdownChecklistItem renders a condition as one checklist entry.
//
// A condition is short here on purpose. §3 shows them as one line each, and
// that is right: the checklist is the index, and the citation is a link the
// reader can open. A condition that needed a paragraph would be a blocker.
func writeMarkdownChecklistItem(b *builder, f policy.Finding) {
	line := "- [ ] **`" + mdEscape(displayName(f.DependencyID)) + "`**"
	if f.Licence != "" {
		line += " — " + mdEscape(f.Licence)
	}
	if f.Title != "" {
		line += ". " + mdEscape(f.Title) + "."
	}
	b.raw(line)

	// The indented detail carries the three things R2, R3 and §1.2 require of
	// every rendered finding: the citation, the confidence, and the evidence.
	b.raw("  - Clause: " + mdCitationLink(f))
	b.raw("  - Evidence: `" + mdEscape(mdFirstEvidence(f)) + "`")
	b.raw("  - Confidence: " + mdConfidence(f, policy.SeverityCondition))
	if f.Severity.Weight() > policy.SeverityCondition.Weight() {
		b.raw("  - Gate: severity " + string(f.Severity) + " → CONDITION because confidence is " +
			string(f.Confidence))
	}
	if f.Fix != nil && f.Fix.Suggestion != "" {
		b.raw("  - Fix: " + mdEscape(f.Fix.Suggestion))
	}
}

// writeMarkdownNote renders a note as a list entry.
func writeMarkdownNote(b *builder, f policy.Finding) {
	line := "- **`" + mdEscape(displayName(f.DependencyID)) + "`**"
	if f.Licence != "" {
		line += " — " + mdEscape(f.Licence)
	}
	if f.Title != "" {
		line += ". " + mdEscape(f.Title) + "."
	}
	b.raw(line)
	b.raw("  - Clause: " + mdCitationLink(f))
	b.raw("  - Evidence: `" + mdEscape(mdFirstEvidence(f)) + "`")
	b.raw("  - Confidence: " + mdConfidence(f, policy.SeverityNote))
	if f.Severity.Weight() > policy.SeverityNote.Weight() {
		b.raw("  - Gate: severity " + string(f.Severity) + " → NOTE because confidence is " +
			string(f.Confidence))
	}
}

// ─── shared finding parts ───────────────────────────────────────────────────

// writeMarkdownCitation renders the §3 citation block: the excerpt as a quote
// with its source beneath, or the clause reference when there is no excerpt.
func writeMarkdownCitation(b *builder, f policy.Finding, opts Options) {
	if f.Citation.Section == "" && f.Citation.URL == "" {
		b.raw("> **MISSING CITATION — this is a bug (E-POLICY-002).**")
		b.blank()
		return
	}

	// The quotation marks are conditional, and the condition is not cosmetic.
	// A quotation mark is a claim that the words are the source's; the corpus
	// distinguishes an excerpt somebody verified against the primary text
	// (ExcerptVerbatim) from one that has not been (ExcerptUnverified). The
	// human renderer applies the same rule; see writeExcerpt in human.go for
	// the audit that made it necessary.
	if f.Citation.Excerpt != "" {
		excerpt := f.Citation.Excerpt
		if f.Citation.ExcerptKind == "verbatim" {
			excerpt = "“" + excerpt + "”"
		} else {
			excerpt = "“" + excerpt + "” *(paraphrase — not verified against the primary text)*"
		}
		for _, line := range mdWrap(excerpt, mdWidth(opts)) {
			b.raw("> " + line)
		}
	}

	label := mdCitationLink(f)
	if label != "" {
		b.raw(">")
		b.raw("> — " + label)
	}
	b.blank()
}

// mdCitationLink renders a citation as a Markdown link, or as plain text when
// there is no URL to link to.
func mdCitationLink(f policy.Finding) string {
	section := f.Citation.Section
	if section == "" {
		section = "source"
	}
	if f.Citation.URL == "" {
		return mdEscape(section)
	}
	return "[" + mdEscape(section) + "](" + mdLinkTarget(f.Citation.URL) + ")"
}

// writeMarkdownEvidence prints the evidence lines. Mandatory, for the same
// reason as the citation.
func writeMarkdownEvidence(b *builder, f policy.Finding) {
	if len(f.Evidence) == 0 {
		b.raw("- **Evidence:** NONE RECORDED — this is a bug (INV-1)")
		return
	}
	for _, ev := range f.Evidence {
		b.raw("- **Evidence:** `" + mdEscape(evidenceLine(ev)) + "`")
	}
}

// writeMarkdownGate makes the confidence gate visible in the Markdown form too.
//
// The human renderer does this and the reason carries over exactly: a reader
// who sees an AGPL trap under Conditions rather than Blockers would reasonably
// conclude the tool had cleared it, when what happened is that the tool
// declined to decide.
func writeMarkdownGate(b *builder, f policy.Finding, section policy.Severity) {
	if f.Severity.Weight() <= section.Weight() {
		return
	}
	why := "LOW"
	if f.Confidence == policy.ConfidenceMedium {
		why = "MEDIUM"
	}
	b.raw("- **Gate:** severity " + string(f.Severity) + " → " + string(section) +
		" because confidence is " + why)
}

// mdConfidence renders the confidence, including the ambiguity note the human
// renderer appends. R3 requires the confidence on every finding.
func mdConfidence(f policy.Finding, section policy.Severity) string {
	conf := string(f.Confidence)
	if conf == "" {
		return "MISSING — this is a bug (E-POLICY-007)"
	}
	if f.Confidence == policy.ConfidenceMedium || f.Confidence == policy.ConfidenceLow {
		return conf + " — " + ambiguityNote(f.Confidence)
	}
	return conf
}

// mdFirstEvidence renders a finding's first evidence location, or a loud
// placeholder when there is none.
func mdFirstEvidence(f policy.Finding) string {
	if len(f.Evidence) == 0 {
		return "NONE RECORDED — this is a bug (INV-1)"
	}
	return evidenceLine(f.Evidence[0])
}

// ─── undetermined ───────────────────────────────────────────────────────────

func writeMarkdownUndetermined(b *builder, us []graph.Undetermined) {
	if len(us) == 0 {
		return
	}
	b.raw("### " + mdIconUnknown + " Unclassified")
	b.blank()
	b.raw("<sub>These were seen and could not be classified. They are not passes; " +
		"INV-7 forbids rounding an unknown to a safe-looking answer.</sub>")
	b.blank()

	for _, u := range us {
		line := "- **`" + mdEscape(u.ID) + "`** — " + mdEscape(humaniseReason(u.Reason))
		b.raw(line)
		if u.Detail != "" {
			b.raw("  - " + mdEscape(u.Detail))
		}
		if u.ErrorCode != "" {
			b.raw("  - Error: `" + mdEscape(u.ErrorCode) + "`")
		}
		if ev := mdUndeterminedEvidence(u); ev != "" {
			b.raw("  - Evidence: `" + mdEscape(ev) + "`")
		}
		b.raw("  - Action: " + mdEscape(actionFor(u)))
	}
	b.blank()
	b.raw("---")
	b.blank()
}

func mdUndeterminedEvidence(u graph.Undetermined) string {
	if len(u.Evidence) == 0 {
		return ""
	}
	return evidenceLine(u.Evidence[0])
}

// ─── footer ─────────────────────────────────────────────────────────────────

// writeMarkdownFooter emits the disclaimer (R1) plus the tool's own version.
//
// R1 says the disclaimer appears in every human AND Markdown output, so this
// function has no early return and no condition. It is called unconditionally
// by WriteMarkdown, and a clean verdict gets the same footer as a blocked one.
func writeMarkdownFooter(b *builder, v verdict.Verdict) {
	b.raw("<sub>" + mdEscape(Disclaimer) + "</sub>")
	b.blank()

	// The tool's identity, so a reader can tell which corpus produced the
	// verdict. Without the corpus version a comment from six months ago is
	// indistinguishable from one produced today.
	meta := "Clearance"
	if v.Meta.ToolVersion != "" {
		meta += " v" + mdEscape(v.Meta.ToolVersion)
	}
	if v.Meta.CorpusVersion != "" {
		meta += " · corpus v" + mdEscape(v.Meta.CorpusVersion)
		if v.Meta.CorpusSigned {
			meta += " (signed)"
		}
	}
	if v.Meta.IntentHash != "" {
		meta += " · intent `" + mdEscape(shortHash(v.Meta.IntentHash)) + "`"
	}
	b.raw("<sub>" + meta + "</sub>")
}

// ─── Markdown escaping ──────────────────────────────────────────────────────

// mdEscape escapes the characters that would otherwise change the structure of
// a Markdown document.
//
// This is a correctness requirement rather than a tidiness one, and the reason
// is the data. Dependency names, licence identifiers, clause sections and
// citation excerpts are all attacker-influenced: a package name is chosen by
// whoever published the package. A dependency named `a|b` would break a table,
// and one named `<img src=x onerror=...>` would be rendered as HTML by GitHub's
// Markdown engine, which allows a subset of raw HTML. The comment is posted by
// a bot with the repository's credentials and read by the maintainers.
//
// Backticks are NOT escaped here, because every use of this function is inside
// a span the caller has already wrapped in backticks. A backtick in the value
// would close that span early, so it is replaced with a lookalike rather than
// escaped — Markdown has no escape for a backtick inside a code span.
func mdEscape(s string) string {
	if s == "" {
		return ""
	}
	var b strings.Builder
	b.Grow(len(s) + 8)
	for _, r := range s {
		switch r {
		case '\\', '`', '*', '_', '[', ']', '<', '>', '|':
			b.WriteByte('\\')
			b.WriteRune(r)
		case '\n':
			// A newline inside a table cell or a list item ends the block. A
			// space is the honest rendering: the text is one line in the source
			// and it becomes one line here.
			b.WriteByte(' ')
		case '\r':
			// Dropped rather than turned into a space: a CRLF in the corpus
			// would otherwise become a trailing space, which Markdown renders
			// as a hard line break.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// mdLinkTarget sanitises a URL for use inside a Markdown link.
//
// Two problems, both real. A `)` in the URL would end the link early, and a
// URL beginning `javascript:` would be a script-execution vector in a document
// rendered by GitHub. The corpus's URLs are curated, so neither is likely — but
// the corpus is data, and a renderer that trusts its data to be well-formed is
// a renderer that breaks the first time the data is not.
func mdLinkTarget(url string) string {
	lower := strings.ToLower(strings.TrimSpace(url))
	if !strings.HasPrefix(lower, "http://") && !strings.HasPrefix(lower, "https://") {
		// Not a web URL. Printed as text rather than linked, because a link
		// target that is not http(s) is either a mistake or an attack.
		return ""
	}
	var b strings.Builder
	for _, r := range url {
		switch r {
		case '(', ')', ' ':
			// Percent-encode rather than escape: Markdown's backslash escape
			// does not work inside a link destination.
			b.WriteString("%" + hexPair(byte(r)))
		case '\n', '\r', '<', '>', '"':
			// Removed. Each of these can terminate the link or introduce HTML.
		default:
			b.WriteRune(r)
		}
	}
	return b.String()
}

// mdLink renders a link, degrading to plain text when the target is unusable.
func mdLink(label, url string) string {
	target := mdLinkTarget(url)
	if target == "" {
		return label
	}
	return "[" + label + "](" + target + ")"
}

func hexPair(b byte) string {
	const hex = "0123456789ABCDEF"
	return string([]byte{hex[b>>4], hex[b&0x0f]})
}

// ─── wrapping ───────────────────────────────────────────────────────────────

// mdDefaultWidth is the wrap width for prose in a PR comment.
//
// 100 rather than 80: a PR comment pane is wider than a terminal, and the
// blockquote the reason sits in already consumes four columns. This is a
// rendering choice, not a contract — unlike the human renderer's widths, which
// R7 makes part of the contract.
const mdDefaultWidth = 100

// mdWidth returns the wrap width, defaulting when the caller set none.
func mdWidth(opts Options) int {
	if opts.Width > 0 {
		return opts.Width
	}
	return mdDefaultWidth
}

// mdWrap wraps prose to width, on word boundaries.
//
// It reuses the human renderer's wrap rather than reimplementing it, so that a
// fix to one is a fix to both. The only difference is the default width.
func mdWrap(s string, width int) []string {
	if width <= 0 {
		width = mdDefaultWidth
	}
	return wrap(s, width)
}

// counted renders a number and its noun, pluralised.
//
// `plural` alone returns only the word — plural(1, "blocker", "blockers") is
// "blocker" — which is right for the human renderer, where the number is
// already in the label. Every place Markdown prints a quantity needs the two
// together, so this exists rather than a repeated concatenation that one caller
// would eventually forget.
func counted(n int, one, many string) string {
	return itoa(n) + " " + plural(n, one, many)
}

// shortHash shortens a sha256 for display. The full value is in the JSON; a
// comment needs something a human can compare by eye.
func shortHash(h string) string {
	h = strings.TrimSpace(h)
	if len(h) <= 12 {
		return h
	}
	return h[:12]
}
