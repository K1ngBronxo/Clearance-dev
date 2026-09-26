package safeyaml

import (
	"strings"
	"testing"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// TestParseConfigShape exercises the exact shape of clearance.config.yml.
func TestParseConfigShape(t *testing.T) {
	src := `
schema_version: 1

project:
  name: my-saas
  description: A hosted document-analysis service.

use:
  commercial: true
  licence_model: closed-source
  modified: true
  network_exposed: true
  distributed: false
  saas: true

scale:
  mau: 5000
  employees: 2
  revenue_eur: 40000

territories:
  - EU
  - US
  - GB

policy:
  never_allow:
    - AGPL-3.0-only
    - AGPL-3.0-or-later
  block_on:
    - BLOCK
  allow_if:
    - licence: LGPL-3.0-only
      when:
        op: "=="
        field: use.modified
        value: false
  ignore:
    - path: "vendor/legacy-internal-only/**"
      reason: "internal tooling, never distributed"
`
	n, err := Parse([]byte(src), Limits{})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if v, _ := n.Get("schema_version"); v.Str() != "1" {
		t.Errorf("schema_version = %q, want 1", v.Str())
	}
	use, ok := n.Get("use")
	if !ok {
		t.Fatal("no use block")
	}
	if b, _ := mustGet(t, use, "commercial").Bool(); !b {
		t.Error("use.commercial should be true")
	}
	if b, _ := mustGet(t, use, "distributed").Bool(); b {
		t.Error("use.distributed should be false")
	}
	if s := mustGet(t, use, "licence_model").Str(); s != "closed-source" {
		t.Errorf("licence_model = %q", s)
	}

	scale := mustGet(t, n, "scale")
	if i, _ := mustGet(t, scale, "mau").Int(); i != 5000 {
		t.Errorf("scale.mau = %d, want 5000", i)
	}

	terr := mustGet(t, n, "territories")
	if got := terr.Strings(); len(got) != 3 || got[0] != "EU" || got[2] != "GB" {
		t.Errorf("territories = %v", got)
	}

	pol := mustGet(t, n, "policy")
	na := mustGet(t, pol, "never_allow")
	if got := na.Strings(); len(got) != 2 || got[0] != "AGPL-3.0-only" {
		t.Errorf("never_allow = %v", got)
	}

	ai := mustGet(t, pol, "allow_if")
	items := ai.List()
	if len(items) != 1 {
		t.Fatalf("allow_if has %d items, want 1", len(items))
	}
	if s := mustGet(t, items[0], "licence").Str(); s != "LGPL-3.0-only" {
		t.Errorf("allow_if[0].licence = %q", s)
	}
	when := mustGet(t, items[0], "when")
	if s := mustGet(t, when, "op").Str(); s != "==" {
		t.Errorf("when.op = %q, want ==", s)
	}
	// The value is the boolean false, not the string "false". This distinction
	// is load-bearing: a predicate comparing a bool field to the string "false"
	// would silently never match.
	if b, ok := mustGet(t, when, "value").Bool(); !ok || b {
		t.Errorf("when.value should be the boolean false")
	}

	ig := mustGet(t, pol, "ignore").List()
	if len(ig) != 1 {
		t.Fatalf("ignore has %d items", len(ig))
	}
	if s := mustGet(t, ig[0], "path").Str(); s != "vendor/legacy-internal-only/**" {
		t.Errorf("ignore[0].path = %q", s)
	}
}

// TestParseCorpusEntryShape exercises the exact shape of a corpus licence entry,
// including a folded block scalar for the message.
func TestParseCorpusEntryShape(t *testing.T) {
	src := `
id: licence.agpl-3.0-only
spdx_id: AGPL-3.0-only
name: GNU Affero General Public License v3.0 only
family: network-copyleft
osi_approved: true
fsf_libre: true
permissiveness: 1
obligations:
  - id: agpl-3.0.network-use
    kind: NETWORK_DISCLOSURE
    severity: BLOCK
    when:
      op: and
      l: { field: use.modified, op: "==", value: true }
      r: { field: use.network_exposed, op: "==", value: true }
    message: >
      AGPL-3.0 section 13 requires that a modified version exposed over a
      network must offer the Corresponding Source to every user interacting
      with it remotely.
    citation:
      url: https://www.gnu.org/licenses/agpl-3.0.txt
      section: "§13"
      excerpt: "your modified version must prominently offer all users interacting with it remotely"
    confidence: HIGH
    fix:
      action: replace
      suggestion: "swap to crawl4ai (Apache-2.0, same capability)"
      alternative: crawl4ai
      confidence: MEDIUM
traps: []
citation:
  url: https://www.gnu.org/licenses/agpl-3.0.txt
  section: "Preamble"
confidence: HIGH
last_verified: "2026-09-15"
`
	n, err := Parse([]byte(src), Limits{})
	if err != nil {
		t.Fatalf("parse failed: %v", err)
	}
	if s := mustGet(t, n, "spdx_id").Str(); s != "AGPL-3.0-only" {
		t.Errorf("spdx_id = %q", s)
	}
	if i, _ := mustGet(t, n, "permissiveness").Int(); i != 1 {
		t.Errorf("permissiveness = %d", i)
	}

	obs := mustGet(t, n, "obligations").List()
	if len(obs) != 1 {
		t.Fatalf("obligations = %d", len(obs))
	}
	ob := obs[0]
	if s := mustGet(t, ob, "kind").Str(); s != "NETWORK_DISCLOSURE" {
		t.Errorf("kind = %q", s)
	}
	msg := mustGet(t, ob, "message").Str()
	if !strings.Contains(msg, "section 13 requires") {
		t.Errorf("folded message lost content: %q", msg)
	}
	if !strings.Contains(msg, "Corresponding Source to every user") {
		t.Errorf("folded message did not join lines with a space: %q", msg)
	}
	if strings.Contains(strings.TrimRight(msg, "\n"), "\n") {
		t.Errorf("a folded scalar should have no interior newline here: %q", msg)
	}
	if !strings.HasSuffix(msg, "\n") {
		t.Errorf("clip chomping should keep one trailing newline: %q", msg)
	}

	// A flow mapping inside a block mapping.
	when := mustGet(t, ob, "when")
	if s := mustGet(t, when, "op").Str(); s != "and" {
		t.Errorf("when.op = %q", s)
	}
	l := mustGet(t, when, "l")
	if s := mustGet(t, l, "field").Str(); s != "use.modified" {
		t.Errorf("when.l.field = %q", s)
	}
	if b, ok := mustGet(t, l, "value").Bool(); !ok || !b {
		t.Error("when.l.value should be boolean true")
	}

	// An empty flow sequence.
	if got := mustGet(t, n, "traps").List(); len(got) != 0 {
		t.Errorf("traps should be empty, got %d", len(got))
	}

	// A quoted section keeps its § character and its quotes are removed. The
	// section under test is the *obligation's* citation, not the entry-level
	// one, because that is the citation a finding will carry.
	obCit := mustGet(t, ob, "citation")
	if s := mustGet(t, obCit, "section").Str(); s != "§13" {
		t.Errorf("obligation citation.section = %q", s)
	}
	if s := mustGet(t, obCit, "url").Str(); s != "https://www.gnu.org/licenses/agpl-3.0.txt" {
		t.Errorf("obligation citation.url = %q", s)
	}

	fix := mustGet(t, ob, "fix")
	if s := mustGet(t, fix, "alternative").Str(); s != "crawl4ai" {
		t.Errorf("fix.alternative = %q", s)
	}
}

// TestYAMLTagRCE is the INV-10 guard for tag-based deserialisation attacks.
// There is no tag syntax in this parser, so the payload must be refused.
func TestYAMLTagRCE(t *testing.T) {
	payloads := []string{
		"!!python/object/apply:os.system ['echo pwned']",
		"key: !!python/object:os.system {x: 1}",
		"key: !ruby/object:Gem::Installer {}",
		"key: !<tag:yaml.org,2002:python/name:os.system>",
	}
	for _, p := range payloads {
		_, err := Parse([]byte(p), Limits{})
		if err == nil {
			t.Fatalf("payload %q was accepted; it must be refused", p)
		}
		e, ok := cerr.As(err)
		if !ok {
			t.Fatalf("payload %q produced an untyped error %v", p, err)
		}
		if e.Code() != cerr.EParse009 {
			t.Errorf("payload %q produced %s, want %s", p, e.Code(), cerr.EParse009)
		}
	}
}

// TestBillionLaughs is the INV-10 guard for anchor/alias expansion bombs. This
// parser has no anchor syntax at all, so the bomb is refused rather than
// expanded — and refused fast, because nothing is ever expanded.
func TestBillionLaughs(t *testing.T) {
	bomb := `
a: &a ["x","x","x","x","x","x","x","x","x","x"]
b: &b [*a,*a,*a,*a,*a,*a,*a,*a,*a,*a]
c: &c [*b,*b,*b,*b,*b,*b,*b,*b,*b,*b]
d: [*c,*c,*c,*c,*c,*c,*c,*c,*c,*c]
`
	_, err := Parse([]byte(bomb), Limits{})
	if err == nil {
		t.Fatal("the alias bomb was accepted; it must be refused")
	}
	e, ok := cerr.As(err)
	if !ok {
		t.Fatalf("untyped error: %v", err)
	}
	if e.Code() != cerr.EParse008 {
		t.Errorf("got %s, want %s", e.Code(), cerr.EParse008)
	}
}

// TestDepthBomb is the INV-10 guard for deep nesting.
func TestDepthBomb(t *testing.T) {
	var b strings.Builder
	for i := 0; i < 200; i++ {
		b.WriteString(strings.Repeat("  ", i))
		b.WriteString("k:\n")
	}
	_, err := Parse([]byte(b.String()), Limits{MaxDepth: 16})
	if err == nil {
		t.Fatal("a 200-deep document was accepted with MaxDepth 16")
	}
	if e, ok := cerr.As(err); !ok || e.Code() != cerr.EParse006 {
		t.Errorf("got %v, want %s", err, cerr.EParse006)
	}
}

// TestJSONDepthBombGuard mirrors the YAML depth test for the JSON boundary.
func TestOversizeRefused(t *testing.T) {
	big := make([]byte, 2048)
	for i := range big {
		big[i] = 'a'
	}
	_, err := Parse(big, Limits{MaxBytes: 1024})
	if err == nil {
		t.Fatal("an oversized document was accepted")
	}
	if e, ok := cerr.As(err); !ok || e.Code() != cerr.EParse004 {
		t.Errorf("got %v, want %s", err, cerr.EParse004)
	}
}

func TestDuplicateKeyRefused(t *testing.T) {
	_, err := Parse([]byte("confidence: HIGH\nconfidence: LOW\n"), Limits{})
	if err == nil {
		t.Fatal("a duplicate key was accepted; last-wins is exactly the behaviour that hides a mistake")
	}
	if !strings.Contains(err.Error(), "duplicate") {
		t.Errorf("unhelpful message: %v", err)
	}
}

func TestTabIndentationRefused(t *testing.T) {
	_, err := Parse([]byte("a:\n\tb: 1\n"), Limits{})
	if err == nil {
		t.Fatal("tab indentation was accepted")
	}
}

func TestScalarTyping(t *testing.T) {
	cases := []struct {
		src   string
		check func(t *testing.T, n *Node)
	}{
		{"v: true\n", func(t *testing.T, n *Node) {
			if b, ok := mustGet(t, n, "v").Bool(); !ok || !b {
				t.Error("true should be a bool")
			}
		}},
		{"v: false\n", func(t *testing.T, n *Node) {
			if b, ok := mustGet(t, n, "v").Bool(); !ok || b {
				t.Error("false should be a bool")
			}
		}},
		{"v: 0\n", func(t *testing.T, n *Node) {
			if i, ok := mustGet(t, n, "v").Int(); !ok || i != 0 {
				t.Error("0 should be an int64")
			}
		}},
		{"v: 1.5\n", func(t *testing.T, n *Node) {
			if f, ok := mustGet(t, n, "v").Float(); !ok || f != 1.5 {
				t.Error("1.5 should be a float64")
			}
		}},
		{"v: null\n", func(t *testing.T, n *Node) {
			if !mustGet(t, n, "v").IsNull() {
				t.Error("null should be null")
			}
		}},
		{"v:\n", func(t *testing.T, n *Node) {
			if !mustGet(t, n, "v").IsNull() {
				t.Error("an empty value should be null")
			}
		}},
		{"v: 2026-09-15\n", func(t *testing.T, n *Node) {
			// A date is a string, not a number and not a time. Keeping it as
			// text is what lets the corpus compare dates itself.
			if s := mustGet(t, n, "v").Str(); s != "2026-09-15" {
				t.Errorf("date = %q", s)
			}
		}},
		{"v: \"1.0\"\n", func(t *testing.T, n *Node) {
			// A quoted number stays a string. A version must not be rounded.
			if _, ok := mustGet(t, n, "v").Int(); ok {
				t.Error("a quoted \"1.0\" must not decode as an integer")
			}
			if s := mustGet(t, n, "v").Str(); s != "1.0" {
				t.Errorf("quoted value = %q", s)
			}
		}},
		{"v: 1.10.0\n", func(t *testing.T, n *Node) {
			// Not a float: two dots. It must stay the string "1.10.0" and never
			// become 1.1.
			if s := mustGet(t, n, "v").Str(); s != "1.10.0" {
				t.Errorf("version = %q, want 1.10.0", s)
			}
		}},
		{"v: issue#12\n", func(t *testing.T, n *Node) {
			// A '#' not preceded by whitespace is content, not a comment.
			if s := mustGet(t, n, "v").Str(); s != "issue#12" {
				t.Errorf("value = %q", s)
			}
		}},
		{"v: a # comment\n", func(t *testing.T, n *Node) {
			if s := mustGet(t, n, "v").Str(); s != "a" {
				t.Errorf("value = %q, want a", s)
			}
		}},
		{"v: \"a # not a comment\"\n", func(t *testing.T, n *Node) {
			if s := mustGet(t, n, "v").Str(); s != "a # not a comment" {
				t.Errorf("value = %q", s)
			}
		}},
		{"v: https://example.com/x\n", func(t *testing.T, n *Node) {
			// A URL must not be mistaken for a key: value pair.
			if s := mustGet(t, n, "v").Str(); s != "https://example.com/x" {
				t.Errorf("value = %q", s)
			}
		}},
	}
	for _, c := range cases {
		n, err := Parse([]byte(c.src), Limits{})
		if err != nil {
			t.Errorf("%q: parse failed: %v", c.src, err)
			continue
		}
		c.check(t, n)
	}
}

func TestBlockScalars(t *testing.T) {
	lit := "v: |\n  line one\n  line two\n"
	n, err := Parse([]byte(lit), Limits{})
	if err != nil {
		t.Fatalf("literal: %v", err)
	}
	if s := mustGet(t, n, "v").Str(); s != "line one\nline two\n" {
		t.Errorf("literal = %q", s)
	}

	strip := "v: |-\n  line one\n  line two\n"
	n, err = Parse([]byte(strip), Limits{})
	if err != nil {
		t.Fatalf("strip: %v", err)
	}
	if s := mustGet(t, n, "v").Str(); s != "line one\nline two" {
		t.Errorf("strip = %q", s)
	}
}

func TestSequenceOfMappings(t *testing.T) {
	src := `
items:
  - id: one
    value: 1
  - id: two
    value: 2
`
	n, err := Parse([]byte(src), Limits{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	items := mustGet(t, n, "items").List()
	if len(items) != 2 {
		t.Fatalf("got %d items", len(items))
	}
	if s := mustGet(t, items[1], "id").Str(); s != "two" {
		t.Errorf("items[1].id = %q", s)
	}
	if i, _ := mustGet(t, items[1], "value").Int(); i != 2 {
		t.Errorf("items[1].value = %d", i)
	}
}

func TestNestedSequence(t *testing.T) {
	src := `
never_allow:
  - AGPL-3.0-only
  - AGPL-3.0-or-later
`
	n, err := Parse([]byte(src), Limits{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	got := mustGet(t, n, "never_allow").Strings()
	if len(got) != 2 || got[1] != "AGPL-3.0-or-later" {
		t.Errorf("got %v", got)
	}
}

func TestDecodeIntoStruct(t *testing.T) {
	type inner struct {
		Op    string `yaml:"op"`
		Field string `yaml:"field"`
		Value bool   `yaml:"value"`
	}
	type policy struct {
		NeverAllow []string `yaml:"never_allow"`
		When       inner    `yaml:"when"`
	}
	type doc struct {
		SchemaVersion int    `yaml:"schema_version"`
		Name          string `yaml:"name"`
		Policy        policy `yaml:"policy"`
	}

	src := `
schema_version: 1
name: test
policy:
  never_allow: [AGPL-3.0-only, SSPL-1.0]
  when:
    op: "=="
    field: use.modified
    value: true
`
	var d doc
	if err := Unmarshal([]byte(src), &d, Limits{}); err != nil {
		t.Fatalf("unmarshal: %v", err)
	}
	if d.SchemaVersion != 1 || d.Name != "test" {
		t.Errorf("scalars: %+v", d)
	}
	if len(d.Policy.NeverAllow) != 2 || d.Policy.NeverAllow[1] != "SSPL-1.0" {
		t.Errorf("never_allow: %v", d.Policy.NeverAllow)
	}
	if !d.Policy.When.Value || d.Policy.When.Field != "use.modified" {
		t.Errorf("when: %+v", d.Policy.When)
	}
}

func TestDecodeUnknownKeyRefused(t *testing.T) {
	type doc struct {
		Confidence string `yaml:"confidence"`
	}
	var d doc
	err := Unmarshal([]byte("confidencee: HIGH\n"), &d, Limits{})
	if err == nil {
		t.Fatal("a typo'd key was accepted; it would load with no confidence at all")
	}
	if !strings.Contains(err.Error(), "unknown key") {
		t.Errorf("message should name the problem: %v", err)
	}
}

func TestEmptyDocumentIsEmptyMapping(t *testing.T) {
	n, err := Parse([]byte("# just a comment\n"), Limits{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if n.Kind != MappingNode {
		t.Errorf("kind = %v", n.Kind)
	}
}

func TestCRLFHandled(t *testing.T) {
	n, err := Parse([]byte("a: 1\r\nb: 2\r\n"), Limits{})
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if i, _ := mustGet(t, n, "b").Int(); i != 2 {
		t.Errorf("CRLF handling broke: b = %d", i)
	}
}

func mustGet(t *testing.T, n *Node, key string) *Node {
	t.Helper()
	v, ok := n.Get(key)
	if !ok {
		t.Fatalf("missing key %q", key)
	}
	return v
}
