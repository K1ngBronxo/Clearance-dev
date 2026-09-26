// Package safeyaml is a strict, bounded YAML *subset* parser (control C2,
// INV-10).
//
// # WHY A SUBSET PARSER AND NOT A WRAPPER AROUND A YAML LIBRARY
//
// `safeyaml` was originally specified as a
// wrapper that "decodes with a strict decoder: no custom tags, alias limit,
// depth limit, duplicate-key rejection". A wrapper can only ever *mitigate* YAML
// deserialisation RCE, because the tag machinery still exists one layer down and
// the mitigation depends on getting every option right.
//
// This parser removes the machinery. There is no anchor syntax, no alias
// syntax, and no tag syntax in the grammar at all — so `!!python/object`,
// `&anchor` bombs and `*alias` expansions are not blocked, they are
// unrepresentable. The refusal is structural rather than configurational, which
// is the difference between a control and a hope.
//
// The cost is that the corpus and config files must stay inside a documented
// subset. That is a feature: the corpus is published as a public reference, and
// a reader can verify an entry by eye.
//
// SUPPORTED (and nothing else)
//
//	block mappings        key: value
//	block sequences       - item
//	nesting               by indentation, spaces only
//	scalars               plain, 'single', "double"
//	block scalars         > and | with - and + chomping
//	flow sequences        [a, b, c]
//	flow mappings         { key: value }
//	comments              # to end of line, when not inside a quoted scalar
//	types                 bool (true/false/yes/no/on/off), int, float, null, string
//
// REJECTED (with the code that documents it)
//
//	&anchor, *alias, <<merge   E-PARSE-008
//	!tag, !!tag                E-PARSE-009
//	nesting past MaxDepth      E-PARSE-006
//	file past MaxBytes         E-PARSE-004
//	tabs in indentation        SyntaxError (the caller maps it)
//	duplicate mapping keys     SyntaxError
//
// Anything else malformed is a SyntaxError, which the caller maps to the right
// code for its context (E-PARSE-003 for config, E-CORPUS-004 for a corpus entry).
package safeyaml

import (
	"fmt"
	"strconv"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// Limits bounds the parser. The zero value is replaced by DefaultLimits, so a
// caller that forgets cannot accidentally get an unbounded parse.
type Limits struct {
	MaxBytes int // default 256 KiB
	MaxDepth int // default 32
}

// DefaultLimits are the values from the plan's security architecture.
func DefaultLimits() Limits { return Limits{MaxBytes: 256 << 10, MaxDepth: 32} }

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxBytes <= 0 {
		l.MaxBytes = d.MaxBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	return l
}

// Kind is the node type.
type Kind int

const (
	ScalarNode Kind = iota
	MappingNode
	SequenceNode
)

// Node is one parsed value. Mappings keep their source order, because the plan
// requires deterministic iteration and because a mapping's order is meaningful
// to a human reading a corpus entry.
type Node struct {
	Kind Kind
	Line int // 1-based line in the source

	// Scalar
	Value any // string | bool | int64 | float64 | nil

	// Mapping (ordered)
	Keys   []string
	Values []*Node

	// Sequence
	Items []*Node
}

// SyntaxError is a malformed-document error that carries no code, because the
// right code depends on the context (a config file and a corpus entry are both
// YAML and both wrong, but they exit differently).
type SyntaxError struct {
	Line int
	Msg  string
}

func (e *SyntaxError) Error() string {
	if e.Line > 0 {
		return fmt.Sprintf("line %d: %s", e.Line, e.Msg)
	}
	return e.Msg
}

func syntaxf(line int, format string, a ...any) *SyntaxError {
	return &SyntaxError{Line: line, Msg: fmt.Sprintf(format, a...)}
}

// ── Node accessors ───────────────────────────────────────────────────────────

// Get returns the value for a mapping key. It is safe on a nil node and on a
// non-mapping node, both of which yield (nil, false).
func (n *Node) Get(key string) (*Node, bool) {
	if n == nil || n.Kind != MappingNode {
		return nil, false
	}
	for i, k := range n.Keys {
		if k == key {
			return n.Values[i], true
		}
	}
	return nil, false
}

// Has reports whether a mapping key is present.
func (n *Node) Has(key string) bool { _, ok := n.Get(key); return ok }

// Str returns a scalar as a string. A non-scalar yields "".
func (n *Node) Str() string {
	if n == nil || n.Kind != ScalarNode {
		return ""
	}
	switch v := n.Value.(type) {
	case string:
		return v
	case bool:
		return strconv.FormatBool(v)
	case int64:
		return strconv.FormatInt(v, 10)
	case float64:
		return strconv.FormatFloat(v, 'g', -1, 64)
	case nil:
		return ""
	}
	return ""
}

// Bool returns a scalar as a bool. The second result is false when the node is
// not a bool, so a caller can distinguish `false` from `absent` — a distinction
// this project depends on everywhere (an undeclared field is UNKNOWN, not
// false).
func (n *Node) Bool() (bool, bool) {
	if n == nil || n.Kind != ScalarNode {
		return false, false
	}
	b, ok := n.Value.(bool)
	return b, ok
}

// Int returns a scalar as an int64.
func (n *Node) Int() (int64, bool) {
	if n == nil || n.Kind != ScalarNode {
		return 0, false
	}
	switch v := n.Value.(type) {
	case int64:
		return v, true
	case float64:
		if v == float64(int64(v)) {
			return int64(v), true
		}
	}
	return 0, false
}

// Float returns a scalar as a float64.
func (n *Node) Float() (float64, bool) {
	if n == nil || n.Kind != ScalarNode {
		return 0, false
	}
	switch v := n.Value.(type) {
	case int64:
		return float64(v), true
	case float64:
		return v, true
	}
	return 0, false
}

// List returns a sequence's items, or nil for a non-sequence. A single scalar
// is NOT promoted to a one-element list: silently accepting both shapes is how
// a schema stops being a contract.
func (n *Node) List() []*Node {
	if n == nil || n.Kind != SequenceNode {
		return nil
	}
	return n.Items
}

// Strings returns a sequence of scalars as []string.
func (n *Node) Strings() []string {
	items := n.List()
	if items == nil {
		return nil
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, it.Str())
	}
	return out
}

// IsNull reports whether the node is an explicit null or an absent value.
func (n *Node) IsNull() bool {
	return n == nil || (n.Kind == ScalarNode && n.Value == nil)
}

// ── Parsing ──────────────────────────────────────────────────────────────────

// yline is one logical source line: its indentation, its content with comments
// stripped, and its original line number for error messages.
type yline struct {
	indent int
	text   string
	line   int
}

// Parse turns YAML bytes into a Node.
func Parse(data []byte, limits Limits) (*Node, error) {
	lim := limits.withDefaults()
	if len(data) > lim.MaxBytes {
		return nil, cerr.New(cerr.EParse004, "input", humanBytes(int64(len(data))), humanBytes(int64(lim.MaxBytes)))
	}

	lines, err := lex(data)
	if err != nil {
		return nil, err
	}
	if len(lines) == 0 {
		// An empty document is an empty mapping, not an error. A corpus entry
		// that is empty will fail its own schema validation with a better
		// message than "unexpected end of input".
		return &Node{Kind: MappingNode}, nil
	}

	p := &parser{lines: lines, maxDepth: lim.MaxDepth}
	n, next, err := p.parseNode(0, lines[0].indent, 0)
	if err != nil {
		return nil, err
	}
	if next < len(lines) {
		// Trailing content at a shallower indent than the document's first
		// line, or two documents in one file. Both are refused rather than
		// guessed at.
		return nil, syntaxf(lines[next].line, "unexpected content at indentation %d (expected the document to have ended)", lines[next].indent)
	}
	if n == nil {
		n = &Node{Kind: MappingNode}
	}
	return n, nil
}

// Unmarshal parses and decodes into a Go value. It is the function the plan
// names; see decode.go for the supported target shapes.
func Unmarshal(data []byte, v any, limits Limits) error {
	n, err := Parse(data, limits)
	if err != nil {
		return err
	}
	return Decode(n, v)
}

type parser struct {
	lines    []yline
	maxDepth int
	keys     int
}

// parseNode parses the block beginning at lines[i], which must be at exactly
// `indent`.
func (p *parser) parseNode(i, indent, depth int) (*Node, int, error) {
	if depth > p.maxDepth {
		return nil, i, cerr.New(cerr.EParse006, "input", strconv.Itoa(p.maxDepth))
	}
	if i >= len(p.lines) {
		return nil, i, nil
	}
	ln := p.lines[i]
	if ln.indent != indent {
		return nil, i, syntaxf(ln.line, "inconsistent indentation: expected %d spaces, found %d", indent, ln.indent)
	}

	switch {
	case isSequenceItem(ln.text):
		return p.parseSequence(i, indent, depth)
	case isKeyLine(ln.text):
		return p.parseMapping(i, indent, depth)
	default:
		// A bare scalar at block level. This happens for a single-scalar
		// document and for the virtual line synthesised from a `- value`
		// sequence item.
		return p.scalarNode(i, ln, depth)
	}
}

// parseMapping parses a block mapping whose keys all sit at `indent`.
func (p *parser) parseMapping(i, indent, depth int) (*Node, int, error) {
	node := &Node{Kind: MappingNode, Line: p.lines[i].line}
	seen := map[string]int{}

	for i < len(p.lines) {
		ln := p.lines[i]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			return nil, i, syntaxf(ln.line, "unexpected indentation: expected %d spaces, found %d", indent, ln.indent)
		}
		if isSequenceItem(ln.text) {
			break
		}
		if !isKeyLine(ln.text) {
			return nil, i, syntaxf(ln.line, "expected 'key: value', found %q", truncateForError(ln.text))
		}

		key, rest, err := splitKey(ln)
		if err != nil {
			return nil, i, err
		}
		if xErr := rejectExotic(ln.line, key, "key"); xErr != nil {
			return nil, i, xErr
		}
		if prev, dup := seen[key]; dup {
			// Duplicate keys are refused, not last-wins. A corpus entry that
			// declares `confidence` twice is a mistake someone must see.
			return nil, i, syntaxf(ln.line, "duplicate mapping key %q (first seen on line %d)", key, prev)
		}
		seen[key] = ln.line
		p.keys++

		i++
		child, next, err := p.valueAfterKey(i, ln, rest, indent, depth+1)
		if err != nil {
			return nil, i, err
		}
		i = next

		node.Keys = append(node.Keys, key)
		node.Values = append(node.Values, child)
	}
	return node, i, nil
}

// valueAfterKey resolves the value that follows `key:`, where `i` is the index
// of the line *after* the key line. The value is one of:
//
//	| / >          a block scalar
//	anything else  an inline scalar or flow collection
//	(empty)        a nested block at a deeper indent, or null
//
// It returns the index of the first line it did not consume, so the caller's
// cursor is always advanced by exactly what was read. An earlier draft returned
// 0 for the empty case, which reset the cursor and looped forever — the kind of
// bug that only shows up on the input shape nobody tested with.
func (p *parser) valueAfterKey(i int, ln yline, rest string, indent, depth int) (*Node, int, error) {
	rest = strings.TrimSpace(rest)

	// Block scalar.
	if isBlockScalarIndicator(rest) {
		return p.parseBlockScalar(i-1, rest, ln, indent)
	}

	// Inline value on the same line.
	if rest != "" {
		if err := rejectExotic(ln.line, rest, "value"); err != nil {
			return nil, i, err
		}
		n, err := parseInline(rest, ln.line)
		return n, i, err
	}

	// Empty. A more-indented next line is a nested block; anything else is an
	// explicit null.
	if i < len(p.lines) && p.lines[i].indent > indent {
		return p.parseNode(i, p.lines[i].indent, depth)
	}
	return &Node{Kind: ScalarNode, Value: nil, Line: ln.line}, i, nil
}

// parseBlockScalar reads a `|` or `>` scalar and its indented body. `i` is the
// index of the line carrying the indicator.
func (p *parser) parseBlockScalar(i int, indicator string, ln yline, indent int) (*Node, int, error) {
	literal := indicator[0] == '|'
	strip := strings.Contains(indicator, "-")
	keep := strings.Contains(indicator, "+")

	var body []yline
	// The body is every following line more indented than the key, plus blank
	// lines (which belong to the scalar and must not terminate it).
	for i+1 < len(p.lines) {
		nxt := p.lines[i+1]
		if strings.TrimSpace(nxt.text) == "" {
			body = append(body, nxt)
			i++
			continue
		}
		if nxt.indent <= indent {
			break
		}
		body = append(body, nxt)
		i++
	}

	// Strip the common indentation, computed from the first non-blank line.
	base := -1
	for _, b := range body {
		if strings.TrimSpace(b.text) != "" {
			base = b.indent
			break
		}
	}
	if base < 0 {
		base = indent + 2
	}

	parts := make([]string, 0, len(body))
	for _, b := range body {
		if strings.TrimSpace(b.text) == "" {
			parts = append(parts, "")
			continue
		}
		pad := b.indent - base
		if pad < 0 {
			pad = 0
		}
		parts = append(parts, strings.Repeat(" ", pad)+b.text)
	}

	var s string
	if literal {
		s = strings.Join(parts, "\n")
	} else {
		s = foldLines(parts)
	}

	switch {
	case strip:
		s = strings.TrimRight(s, "\n")
	case keep:
		s += "\n"
	default:
		s = strings.TrimRight(s, "\n") + "\n"
	}

	return &Node{Kind: ScalarNode, Value: s, Line: ln.line}, i + 1, nil
}

// foldLines implements `>` folding: a single line break between two non-blank
// lines becomes a space; a blank line becomes a newline.
func foldLines(parts []string) string {
	var b strings.Builder
	for i, part := range parts {
		if i == 0 {
			b.WriteString(part)
			continue
		}
		prevBlank := strings.TrimSpace(parts[i-1]) == ""
		curBlank := strings.TrimSpace(part) == ""
		switch {
		case prevBlank && curBlank:
			b.WriteString("\n")
		case prevBlank:
			b.WriteString(part)
		case curBlank:
			b.WriteString("\n")
		default:
			b.WriteString(" ")
			b.WriteString(part)
		}
	}
	return b.String()
}

// parseSequence parses a block sequence whose dashes all sit at `indent`.
func (p *parser) parseSequence(i, indent, depth int) (*Node, int, error) {
	node := &Node{Kind: SequenceNode, Line: p.lines[i].line}

	for i < len(p.lines) {
		ln := p.lines[i]
		if ln.indent < indent {
			break
		}
		if ln.indent > indent {
			return nil, i, syntaxf(ln.line, "unexpected indentation inside a sequence: expected %d spaces, found %d", indent, ln.indent)
		}
		if !isSequenceItem(ln.text) {
			break
		}

		// Where the item's own content begins. `-   key: v` is legal, so this
		// is a computed column rather than a constant 2.
		body := ln.text[1:]
		lead := len(body) - len(strings.TrimLeft(body, " "))
		itemIndent := ln.indent + 1 + lead
		itemText := strings.TrimLeft(body, " ")

		if itemText == "" {
			// A bare dash: the item is the following, more-indented block.
			i++
			if i < len(p.lines) && p.lines[i].indent > indent {
				child, next, err := p.parseNode(i, p.lines[i].indent, depth+1)
				if err != nil {
					return nil, i, err
				}
				node.Items = append(node.Items, child)
				i = next
				continue
			}
			node.Items = append(node.Items, &Node{Kind: ScalarNode, Value: nil, Line: ln.line})
			continue
		}

		if err := rejectExotic(ln.line, itemText, "value"); err != nil {
			return nil, i, err
		}

		if isBlockScalarIndicator(itemText) {
			child, next, err := p.parseBlockScalar(i, itemText, ln, ln.indent)
			if err != nil {
				return nil, i, err
			}
			node.Items = append(node.Items, child)
			i = next
			continue
		}

		// Rewrite this line as a normal line at the item's own indent, so that
		// an item which is a mapping (`- id: x` followed by more keys at the
		// same column) is parsed by exactly the same code as a top-level
		// mapping. One parser, one behaviour.
		p.lines[i] = yline{indent: itemIndent, text: itemText, line: ln.line}
		child, next, err := p.parseNode(i, itemIndent, depth+1)
		if err != nil {
			return nil, i, err
		}
		node.Items = append(node.Items, child)
		i = next
	}
	return node, i, nil
}

// scalarNode parses a virtual single-line scalar (a `- value` item). `i` is the
// index of that line; it returns the index after it.
func (p *parser) scalarNode(i int, ln yline, depth int) (*Node, int, error) {
	if err := rejectExotic(ln.line, ln.text, "value"); err != nil {
		return nil, i, err
	}
	n, err := parseInline(ln.text, ln.line)
	if err != nil {
		return nil, i, err
	}
	return n, i + 1, nil
}

// ── lexing ───────────────────────────────────────────────────────────────────

// lex turns raw bytes into logical lines, rejecting the constructs the subset
// does not have.
func lex(data []byte) ([]yline, error) {
	// A UTF-8 BOM is stripped rather than treated as content. A UTF-16 file is
	// refused explicitly, because its first bytes look like a NUL and the
	// resulting error would be baffling.
	text := string(data)
	text = strings.TrimPrefix(text, "\ufeff")
	if strings.HasPrefix(text, "\xff\xfe") || strings.HasPrefix(text, "\xfe\xff") {
		return nil, cerr.New(cerr.EParse010, "input", "utf-16")
	}

	raw := strings.Split(text, "\n")
	out := make([]yline, 0, len(raw))

	for idx, rl := range raw {
		lineNo := idx + 1
		rl = strings.TrimRight(rl, "\r")
		// Tabs are refused in indentation. YAML forbids them for a reason: a
		// tab is 1 to 8 columns depending on the reader, so "is this nested?"
		// becomes unanswerable.
		if t := strings.TrimLeft(rl, " "); strings.HasPrefix(t, "\t") {
			return nil, syntaxf(lineNo, "tab used for indentation; use spaces")
		}
		indent := len(rl) - len(strings.TrimLeft(rl, " "))
		content := rl[indent:]
		content = stripComment(content)
		content = strings.TrimRight(content, " \t")
		if content == "" {
			continue
		}
		out = append(out, yline{indent: indent, text: content, line: lineNo})
	}
	return out, nil
}

// stripComment removes a trailing `#` comment, respecting quoted scalars. A `#`
// inside quotes is content; a `#` at the start of a value is a comment; a `#`
// inside a word (`issue#12`) is content, because YAML requires whitespace before
// a comment.
func stripComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				if quote == '\'' && i+1 < len(s) && s[i+1] == '\'' {
					i++ // '' is an escaped single quote
					continue
				}
				if quote == '"' && i > 0 && s[i-1] == '\\' {
					continue
				}
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == '#':
			if i == 0 || s[i-1] == ' ' || s[i-1] == '\t' {
				return s[:i]
			}
		}
	}
	return s
}

// ── line classification ──────────────────────────────────────────────────────

func isSequenceItem(text string) bool {
	return text == "-" || strings.HasPrefix(text, "- ")
}

// isKeyLine reports whether a line is `key:` or `key: value`. The colon must be
// followed by a space or end the line, so that a URL value is not mistaken for
// a key.
func isKeyLine(text string) bool {
	if strings.HasPrefix(text, "{") || strings.HasPrefix(text, "[") {
		return false
	}
	_, _, ok := findKeyColon(text)
	return ok
}

func findKeyColon(text string) (int, string, bool) {
	var quote byte
	for i := 0; i < len(text); i++ {
		c := text[i]
		switch {
		case quote != 0:
			if c == quote {
				if quote == '\'' && i+1 < len(text) && text[i+1] == '\'' {
					i++
					continue
				}
				quote = 0
			}
		case c == '\'' || c == '"':
			quote = c
		case c == ':':
			if i+1 == len(text) {
				return i, text[:i], true
			}
			if text[i+1] == ' ' || text[i+1] == '\t' {
				return i, text[:i], true
			}
		}
	}
	return 0, "", false
}

func splitKey(ln yline) (string, string, error) {
	i, rawKey, ok := findKeyColon(ln.text)
	if !ok {
		return "", "", syntaxf(ln.line, "expected 'key: value', found %q", truncateForError(ln.text))
	}
	key := strings.TrimSpace(rawKey)
	if key == "" {
		return "", "", syntaxf(ln.line, "empty mapping key")
	}
	if (strings.HasPrefix(key, "\"") && strings.HasSuffix(key, "\"") && len(key) >= 2) ||
		(strings.HasPrefix(key, "'") && strings.HasSuffix(key, "'") && len(key) >= 2) {
		parsed, err := parseScalar(key, ln.line)
		if err != nil {
			return "", "", err
		}
		key = parsed.Str()
	}
	return key, ln.text[i+1:], nil
}

func isBlockScalarIndicator(s string) bool {
	if s == "" {
		return false
	}
	if s[0] != '|' && s[0] != '>' {
		return false
	}
	rest := s[1:]
	rest = strings.TrimRight(rest, " \t")
	for i := 0; i < len(rest); i++ {
		switch rest[i] {
		case '-', '+':
		case '0', '1', '2', '3', '4', '5', '6', '7', '8', '9':
			// Explicit indentation indicator. Accepted but ignored: the body
			// indentation is computed from the content, which is equivalent for
			// every file the corpus actually contains.
		default:
			return false
		}
	}
	return true
}

// rejectExotic refuses the three YAML features that make the language dangerous
// as a data format, naming the code that documents each refusal.
func rejectExotic(line int, s, where string) error {
	t := strings.TrimSpace(s)
	if t == "" {
		return nil
	}
	// A `<<` merge key is an alias mechanism wearing a hat.
	if strings.HasPrefix(t, "<<") {
		return cerr.New(cerr.EParse008, "input")
	}
	if t[0] == '&' || t[0] == '*' {
		return cerr.New(cerr.EParse008, "input")
	}
	if t[0] == '!' {
		tag := t
		if i := strings.IndexAny(tag, " \t"); i >= 0 {
			tag = tag[:i]
		}
		return cerr.New(cerr.EParse009, "input", tag)
	}
	// An anchor or alias may also appear after a flow delimiter or a comma,
	// e.g. `[&a x, *a]`. Refuse those too rather than half-supporting them.
	for i := 0; i < len(t); i++ {
		switch t[i] {
		case '&', '*':
			if i > 0 && (t[i-1] == '[' || t[i-1] == ',' || t[i-1] == '{' || t[i-1] == ' ') {
				return cerr.New(cerr.EParse008, "input")
			}
		}
	}
	_ = where
	return nil
}

func truncateForError(s string) string {
	const max = 60
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func humanBytes(n int64) string {
	const unit = 1024
	if n < unit {
		return strconv.FormatInt(n, 10) + " B"
	}
	units := []string{"KiB", "MiB", "GiB"}
	v := float64(n)
	for i, u := range units {
		v /= unit
		if v < unit || i == len(units)-1 {
			return strconv.FormatFloat(v, 'f', 1, 64) + " " + u
		}
	}
	return strconv.FormatInt(n, 10) + " B"
}
