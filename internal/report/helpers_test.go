package report

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/policy"
	"github.com/clearance-dev/clearance/internal/verdict"
)

// ─── layout constants (R7) ──────────────────────────────────────────────────

// TestLayoutConstants pins the widths the output spec makes part of the
// contract. R7 says column alignment is stable across runs; a constant quietly
// changing is the way that breaks, and a golden only catches it for the
// fixtures whose content happens to be long enough to notice.
func TestLayoutConstants(t *testing.T) {
	if SeparatorWidth != 40 {
		t.Errorf("SeparatorWidth = %d, want 40", SeparatorWidth)
	}
	if SeverityFieldWidth != 14 {
		t.Errorf("SeverityFieldWidth = %d, want 14", SeverityFieldWidth)
	}
	if NameFieldWidth != 30 {
		t.Errorf("NameFieldWidth = %d, want 30", NameFieldWidth)
	}
	if detailIndent != SeverityFieldWidth+severityGap {
		t.Errorf("detailIndent = %d, want SeverityFieldWidth+severityGap = %d",
			detailIndent, SeverityFieldWidth+severityGap)
	}
	// A label field must be wider than its widest label, or `confidence:HIGH`
	// loses its separating space.
	if detailLabelWidth <= len("confidence:") {
		t.Errorf("detailLabelWidth = %d, must exceed len(%q) = %d",
			detailLabelWidth, "confidence:", len("confidence:"))
	}
	if DefaultWidth != 100 {
		t.Errorf("DefaultWidth = %d, want 100", DefaultWidth)
	}
	if !strings.Contains(Disclaimer, DisclaimerSentence) {
		t.Error("Disclaimer does not contain DisclaimerSentence; R1's load-bearing sentence is gone")
	}
}

// ─── colour rules (§1.1) ────────────────────────────────────────────────────

// TestClassColor pins the mapping, including that an unknown class has no
// colour: an unknown class is a bug (E-INT-004), and colouring it would make it
// look like a designed outcome.
func TestClassColor(t *testing.T) {
	cases := []struct {
		class verdict.Class
		want  string
	}{
		{verdict.Ship, ansiGreen},
		{verdict.ShipConditional, ansiYellow},
		{verdict.DoNotShip, ansiRed},
		{verdict.Undetermined, ansiCyan},
		{verdict.Class("BOGUS"), ""},
		{verdict.Class(""), ""},
	}
	for _, c := range cases {
		if got := classColor(c.class); got != c.want {
			t.Errorf("classColor(%q) = %q, want %q", c.class, got, c.want)
		}
	}
}

// TestColourise covers both sides of Options.Color, and the unknown-class case
// under colour-on.
func TestColourise(t *testing.T) {
	on := Options{Color: true}
	off := Options{Color: false}

	if got := colourise("SHIP", verdict.Ship, off); got != "SHIP" {
		t.Errorf("colour off: got %q, want the plain string", got)
	}
	if got := colourise("SHIP", verdict.Ship, on); got != ansiBold+ansiGreen+"SHIP"+ansiReset {
		t.Errorf("colour on: got %q", got)
	}
	// Unknown class: no colour even when colour is on.
	if got := colourise("BOGUS", verdict.Class("BOGUS"), on); got != "BOGUS" {
		t.Errorf("unknown class: got %q, want the plain string", got)
	}
}

// TestTagFor pins the four tags and the empty string for an unknown severity.
func TestTagFor(t *testing.T) {
	cases := map[policy.Severity]string{
		policy.SeverityBlock:     "[BLOCK]",
		policy.SeverityCondition: "[COND]",
		policy.SeverityNote:      "[NOTE]",
		policy.SeverityInfo:      "[INFO]",
		policy.Severity("BOGUS"): "",
	}
	for sev, want := range cases {
		if got := tagFor(sev); got != want {
			t.Errorf("tagFor(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestAmbiguityNote(t *testing.T) {
	if got := ambiguityNote(policy.ConfidenceLow); !strings.Contains(got, "could not classify") {
		t.Errorf("LOW note = %q", got)
	}
	if got := ambiguityNote(policy.ConfidenceMedium); !strings.Contains(got, "ambiguous") {
		t.Errorf("MEDIUM note = %q", got)
	}
}

// ─── text helpers ───────────────────────────────────────────────────────────

func TestDisplayName(t *testing.T) {
	cases := []struct{ in, want string }{
		{"npm:firecrawl@1.2.3", "firecrawl"},
		{"pypi:torch", "torch"},
		{"weights:models/model.bin", "models/model.bin"},
		{"vendored:node_modules/a", "node_modules/a"},
		{"@scope/name", "@scope/name"}, // no version, leading @ preserved
		{"npm:@scope/name@1.0", "@scope/name"},
		{"no-colon-here", "no-colon-here"},
		{"", ""},
		{"npm:", "npm:"}, // nothing after the colon: falls back to the raw id
	}
	for _, c := range cases {
		if got := displayName(c.in); got != c.want {
			t.Errorf("displayName(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestTruncate(t *testing.T) {
	// Short enough: unchanged.
	if got := truncate("short", 30); got != "short" {
		t.Errorf("truncate short = %q", got)
	}
	// Exactly the width: unchanged (no ellipsis).
	if got := truncate("abcdefghij", 10); got != "abcdefghij" {
		t.Errorf("truncate exact = %q", got)
	}
	// Too long: ellipsis, and the result is exactly width runes.
	got := truncate("abcdefghijklmnop", 10)
	if len([]rune(got)) != 10 {
		t.Errorf("truncate long: %q has %d runes, want 10", got, len([]rune(got)))
	}
	if !strings.HasSuffix(got, "…") {
		t.Errorf("truncate long: %q does not end with an ellipsis", got)
	}
	// Runes, not bytes: a multi-byte name must not be split mid-rune.
	got = truncate("日本語のパッケージ名です", 5)
	if len([]rune(got)) != 5 {
		t.Errorf("truncate runes: %q has %d runes, want 5", got, len([]rune(got)))
	}
	// width <= 1 is a plain slice, no ellipsis.
	if got := truncate("abc", 1); got != "a" {
		t.Errorf("truncate width 1 = %q, want a", got)
	}
}

func TestPad(t *testing.T) {
	if got := pad("ab", 5); got != "ab   " {
		t.Errorf("pad = %q", got)
	}
	if got := pad("abcdef", 3); got != "abcdef" {
		t.Errorf("pad over-width = %q, want unchanged", got)
	}
	if got := pad("日", 3); got != "日  " {
		t.Errorf("pad rune = %q", got)
	}
}

func TestWrap(t *testing.T) {
	// Deterministic word-boundary wrapping.
	got := wrap("one two three four", 7)
	want := []string{"one two", "three", "four"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wrap = %q, want %q", got, want)
	}
	// A word longer than the limit goes on its own line, unbroken.
	got = wrap("a verylongwordthatcannotbreak b", 5)
	want = []string{"a", "verylongwordthatcannotbreak", "b"}
	if !reflect.DeepEqual(got, want) {
		t.Errorf("wrap long word = %q, want %q", got, want)
	}
	// Empty input yields no lines.
	if got := wrap("   ", 10); got != nil {
		t.Errorf("wrap blank = %q, want nil", got)
	}
	// width <= 0 returns the input as a single line.
	if got := wrap("anything", 0); !reflect.DeepEqual(got, []string{"anything"}) {
		t.Errorf("wrap width 0 = %q", got)
	}
}

func TestMdEscape(t *testing.T) {
	cases := []struct{ in, want string }{
		{"a|b", `a\|b`},
		{"<img src=x>", `\<img src=x\>`},
		{"under_score", `under\_score`},
		{"star*", `star\*`},
		{"[link]", `\[link\]`},
		{"back`tick", "back\\`tick"},
		{"back\\slash", `back\\slash`},
		{"line\nbreak", "line break"},
		{"cr\rlf", "crlf"},
		{"", ""},
	}
	for _, c := range cases {
		if got := mdEscape(c.in); got != c.want {
			t.Errorf("mdEscape(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMdLinkTarget(t *testing.T) {
	cases := []struct{ in, want string }{
		{"https://example.com/a", "https://example.com/a"},
		{"HTTP://EXAMPLE.COM", "HTTP://EXAMPLE.COM"},
		{"javascript:alert(1)", ""},
		{"ftp://example.com", ""},
		{"not a url", ""},
		{"https://example.com/a(b)", "https://example.com/a%28b%29"},
		{"https://example.com/a b", "https://example.com/a%20b"},
		{"https://example.com/a<b>", "https://example.com/ab"},
	}
	for _, c := range cases {
		if got := mdLinkTarget(c.in); got != c.want {
			t.Errorf("mdLinkTarget(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestMdLink(t *testing.T) {
	if got := mdLink("label", "javascript:x"); got != "label" {
		t.Errorf("mdLink unsafe target = %q, want the bare label", got)
	}
	if got := mdLink("label", "https://e.com"); got != "[label](https://e.com)" {
		t.Errorf("mdLink = %q", got)
	}
}

func TestSarifURI(t *testing.T) {
	cases := []struct{ in, want string }{
		{"package.json", "package.json"},
		{`dir\file.txt`, "dir/file.txt"},
		{"./package.json", "package.json"},
		{"", ""},
		{"/abs/path", ""},
		{"../outside", ""},
		{"dir/../../outside", ""},
		{"dir/..", ""},
		{"file?query=1", ""},
		{"file#frag", ""},
	}
	for _, c := range cases {
		if got := sarifURI(c.in); got != c.want {
			t.Errorf("sarifURI(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestSarifLevelFor(t *testing.T) {
	cases := map[policy.Severity]string{
		policy.SeverityBlock:     "error",
		policy.SeverityCondition: "warning",
		policy.SeverityNote:      "note",
		policy.SeverityInfo:      "none",
	}
	for sev, want := range cases {
		if got := sarifLevelFor(sev); got != want {
			t.Errorf("sarifLevelFor(%q) = %q, want %q", sev, got, want)
		}
	}
}

func TestPurl(t *testing.T) {
	cases := []struct {
		ecosystem, name, version, want string
	}{
		{"npm", "@mendable/firecrawl-js", "1.2.3", "pkg:npm/@mendable/firecrawl-js@1.2.3"},
		{"pypi", "torch", "2.4.0", "pkg:pypi/torch@2.4.0"},
		{"go", "example.com/mod", "v1.0.0", "pkg:golang/example.com/mod@v1.0.0"},
		{"cargo", "serde", "1.0.0", "pkg:cargo/serde@1.0.0"},
		{"weights", "models/x.bin", "", ""},
		{"local", "thing", "1", ""},
		{"npm", "", "1.0.0", ""},
		{"npm", "a b", "", "pkg:npm/a%20b"},
	}
	for _, c := range cases {
		d := dep("id", "package", c.name, c.version, c.ecosystem, "", "", true, false)
		if got := purl(d); got != c.want {
			t.Errorf("purl(%s/%s@%s) = %q, want %q", c.ecosystem, c.name, c.version, got, c.want)
		}
	}
}

func TestDocumentUUID(t *testing.T) {
	a := documentUUID("seed")
	b := documentUUID("seed")
	c := documentUUID("other")
	if a != b {
		t.Errorf("documentUUID is not stable for the same seed: %q vs %q", a, b)
	}
	if a == c {
		t.Error("documentUUID is the same for different seeds")
	}
	if !isUUIDShaped(a) {
		t.Errorf("documentUUID(%q) = %q, not UUID-shaped", "seed", a)
	}
}

func TestShortHash(t *testing.T) {
	if got := shortHash("short"); got != "short" {
		t.Errorf("shortHash short = %q", got)
	}
	long := "9f2c1b7a4e8d0f3a5c6b1d2e3f4a5b6c"
	if got := shortHash(long); got != long[:12] {
		t.Errorf("shortHash long = %q, want %q", got, long[:12])
	}
}

func TestPluralAndCounted(t *testing.T) {
	if plural(1, "item", "items") != "item" {
		t.Error("plural(1) should be singular")
	}
	if plural(0, "item", "items") != "items" || plural(2, "item", "items") != "items" {
		t.Error("plural(0/2) should be plural")
	}
	if got := counted(1, "blocker", "blockers"); got != "1 blocker" {
		t.Errorf("counted = %q", got)
	}
	if got := counted(3, "blocker", "blockers"); got != "3 blockers" {
		t.Errorf("counted = %q", got)
	}
}

func TestHumaniseReason(t *testing.T) {
	if got := humaniseReason("licence_file_unreadable"); got != "licence file unreadable" {
		t.Errorf("humaniseReason = %q", got)
	}
}

// ─── renderer variants ──────────────────────────────────────────────────────

// TestHumanColourGolden pins the colour form of the human renderer. It is a
// separate golden because colour changes the header line, and the plain golden
// cannot show that.
func TestHumanColourGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHuman(&buf, fixtureBlocked(), Options{Color: true}); err != nil {
		t.Fatalf("WriteHuman: %v", err)
	}
	// The ANSI escape must actually be present, or the golden is pinning a
	// colour-off rendering under a colour-on name.
	if !bytes.Contains(buf.Bytes(), []byte(ansiRed)) {
		t.Error("colour-on rendering contains no red escape for DO NOT SHIP")
	}
	checkGolden(t, "blocked.human-color", buf.Bytes())
}

// TestHumanVerboseGolden pins the opt-in predicate line.
func TestHumanVerboseGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHuman(&buf, fixtureBlocked(), Options{Verbose: true}); err != nil {
		t.Fatalf("WriteHuman: %v", err)
	}
	if !bytes.Contains(buf.Bytes(), []byte("predicate:")) {
		t.Error("verbose rendering does not contain a predicate line")
	}
	checkGolden(t, "blocked.human-verbose", buf.Bytes())
}

// TestHumanNarrowWidthGolden pins that wrapping honours Options.Width, and that
// continuation lines stay aligned under the value column.
func TestHumanNarrowWidthGolden(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHuman(&buf, fixtureBlocked(), Options{Width: 60}); err != nil {
		t.Fatalf("WriteHuman: %v", err)
	}
	checkGolden(t, "blocked.human-narrow", buf.Bytes())
}

// TestHumanNoNotes pins that NoNotes suppresses the NOTES section and nothing
// else.
func TestHumanNoNotes(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteHuman(&buf, fixtureBlocked(), Options{NoNotes: true}); err != nil {
		t.Fatalf("WriteHuman: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "NOTES") {
		t.Error("NoNotes did not suppress the NOTES heading")
	}
	if !strings.Contains(out, "BLOCKERS") {
		t.Error("NoNotes suppressed more than the notes")
	}
	if !strings.Contains(out, DisclaimerSentence) {
		t.Error("NoNotes suppressed the disclaimer; R1 forbids that")
	}
}

// TestMarkdownNoNotes mirrors the human case for the PR-comment renderer.
func TestMarkdownNoNotes(t *testing.T) {
	var buf bytes.Buffer
	if err := WriteMarkdown(&buf, fixtureBlocked(), Options{NoNotes: true}); err != nil {
		t.Fatalf("WriteMarkdown: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "### ℹ️ Notes") {
		t.Error("NoNotes did not suppress the Markdown Notes section")
	}
	if !strings.Contains(out, DisclaimerSentence) {
		t.Error("NoNotes suppressed the disclaimer; R1 forbids that")
	}
}

// TestAnnotationGolden pins the annotation block, which is deliberately not
// part of Write: a caller that wants the verdict alone must be able to get it.
func TestAnnotationGolden(t *testing.T) {
	a := Annotation{
		Heading: AnnotationAIHeading,
		Lines: []string{
			"The AGPL clause applies because the service is network-exposed.",
			"",
			"Consider replacing the dependency.   ",
		},
	}
	var buf bytes.Buffer
	if err := WriteAnnotation(&buf, a, Options{}); err != nil {
		t.Fatalf("WriteAnnotation: %v", err)
	}
	checkGolden(t, "annotation", buf.Bytes())
}

// TestAnnotationColourGolden pins the coloured heading and its rule length.
func TestAnnotationColourGolden(t *testing.T) {
	a := Annotation{Heading: AnnotationAIHeading, Lines: []string{"one line"}}
	var buf bytes.Buffer
	if err := WriteAnnotation(&buf, a, Options{Color: true}); err != nil {
		t.Fatalf("WriteAnnotation: %v", err)
	}
	checkGolden(t, "annotation-color", buf.Bytes())
}

// TestAnnotationEmptyIsNoOutput pins that an empty annotation renders nothing:
// a heading with no body, or a body with no heading, is not an annotation.
func TestAnnotationEmptyIsNoOutput(t *testing.T) {
	cases := []Annotation{
		{},
		{Heading: "only a heading"},
		{Lines: []string{"only a body"}},
		{Heading: "   ", Lines: []string{"whitespace heading"}},
	}
	for i, a := range cases {
		var buf bytes.Buffer
		if err := WriteAnnotation(&buf, a, Options{}); err != nil {
			t.Fatalf("case %d: WriteAnnotation: %v", i, err)
		}
		if buf.Len() != 0 {
			t.Errorf("case %d: expected no output, got %q", i, buf.String())
		}
	}
}

// TestWriteAnnotationDoesNotTouchTheVerdict pins the separation the type exists
// for: the canonical verdict output must be identical whether or not an
// annotation was written, and to the same writer the annotation is not part of
// it.
func TestWriteAnnotationDoesNotTouchTheVerdict(t *testing.T) {
	v := fixtureBlocked()

	var verdictOut bytes.Buffer
	if err := WriteHuman(&verdictOut, v, Options{}); err != nil {
		t.Fatalf("WriteHuman: %v", err)
	}
	before := verdictOut.String()

	// Writing an annotation to a different writer must not change that.
	var annotationOut bytes.Buffer
	if err := WriteAnnotation(&annotationOut, Annotation{
		Heading: AnnotationAIHeading,
		Lines:   []string{"not part of the verdict"},
	}, Options{}); err != nil {
		t.Fatalf("WriteAnnotation: %v", err)
	}
	if strings.Contains(before, "not part of the verdict") {
		t.Error("the verdict output contains the annotation")
	}
}
