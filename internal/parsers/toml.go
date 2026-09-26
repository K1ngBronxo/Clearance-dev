package parsers

import (
	"strconv"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// tomlDoc is a minimal TOML reader covering the subset that Cargo.lock,
// Cargo.toml, poetry.lock and pyproject.toml actually use:
//
//	[table]                 a table header
//	[[array.of.tables]]     an array-of-tables header
//	key = "string"          a basic string, with \escapes
//	key = 'literal'         a literal string, no escapes
//	key = 123 / 1.5         a number
//	key = true / false      a boolean
//	key = ["a", "b"]        an array of scalars, possibly multi-line
//	key = { k = "v" }       an inline table
//	# comment               to end of line
//	dotted.keys = "v"       a dotted key path
//
// # WHY A SUBSET AND NOT A TOML LIBRARY
//
// Same reason as safeyaml: this project has zero third-party dependencies, and
// the parsers read attacker-controlled files. A reader with no multi-line
// string, no date type and no exponent syntax has a correspondingly small
// attack surface. Anything outside the subset is refused with a clear error,
// never half-parsed — a lockfile that half-parses produces a dependency graph
// that is quietly wrong, which is worse than one that refuses.
type tomlDoc struct {
	// values is keyed by the fully-qualified dotted path.
	values map[string]any

	// lines records the source line of each value, so that a Declared built
	// from this document can carry a real line number as evidence rather than
	// a bare file path. Evidence with a location is a claim someone can check.
	lines map[string]int

	// tables preserves the order in which array-of-tables entries appeared,
	// because Cargo.lock's `[[package]]` order is the order we report.
	order []string
}

func newTomlDoc() *tomlDoc {
	return &tomlDoc{values: map[string]any{}, lines: map[string]int{}}
}

// parseTOML reads a document. It returns a SyntaxError-shaped error for
// anything outside the subset.
func parseTOML(data []byte, limit int) (*tomlDoc, error) {
	if len(data) > limit {
		return nil, cerr.New(cerr.EParse004, "input", itoa(int64(len(data))), itoa(int64(limit)))
	}
	text := strings.ReplaceAll(string(data), "\r\n", "\n")
	doc := newTomlDoc()

	// currentPrefix is the table header most recently seen, e.g. "package" or
	// "package.0".
	currentPrefix := ""
	// arrayCounts tracks how many entries each array-of-tables path has.
	arrayCounts := map[string]int{}

	lines := strings.Split(text, "\n")
	for idx := 0; idx < len(lines); idx++ {
		lineNo := idx + 1
		line := strings.TrimSpace(stripTomlComment(lines[idx]))
		if line == "" {
			continue
		}

		// ── table headers ───────────────────────────────────────────────────
		if strings.HasPrefix(line, "[[") {
			if !strings.HasSuffix(line, "]]") {
				return nil, tomlErr(lineNo, "unterminated array-of-tables header")
			}
			name := strings.TrimSpace(line[2 : len(line)-2])
			if name == "" {
				return nil, tomlErr(lineNo, "empty array-of-tables name")
			}
			n := arrayCounts[name]
			arrayCounts[name] = n + 1
			currentPrefix = name + "." + strconv.Itoa(n)
			doc.order = append(doc.order, currentPrefix)
			continue
		}
		if strings.HasPrefix(line, "[") {
			if !strings.HasSuffix(line, "]") {
				return nil, tomlErr(lineNo, "unterminated table header")
			}
			name := strings.TrimSpace(line[1 : len(line)-1])
			if name == "" {
				return nil, tomlErr(lineNo, "empty table name")
			}
			currentPrefix = name
			continue
		}

		// ── key = value ─────────────────────────────────────────────────────
		eq := indexOfTomlEquals(line)
		if eq < 0 {
			return nil, tomlErr(lineNo, "expected 'key = value', found "+truncate(line))
		}
		key := strings.TrimSpace(line[:eq])
		rawValue := strings.TrimSpace(line[eq+1:])
		if key == "" {
			return nil, tomlErr(lineNo, "empty key")
		}
		key = unquoteTomlKey(key)

		// A multi-line array: keep consuming until the brackets balance.
		if strings.HasPrefix(rawValue, "[") && !bracketsBalanced(rawValue) {
			for idx+1 < len(lines) {
				idx++
				rawValue += " " + strings.TrimSpace(stripTomlComment(lines[idx]))
				if bracketsBalanced(rawValue) {
					break
				}
			}
			if !bracketsBalanced(rawValue) {
				return nil, tomlErr(lineNo, "unterminated array")
			}
		}

		value, err := parseTomlValue(rawValue, lineNo)
		if err != nil {
			return nil, err
		}
		full := key
		if currentPrefix != "" {
			full = currentPrefix + "." + key
		}
		doc.values[full] = value
		doc.lines[full] = lineNo
	}
	return doc, nil
}

// Get returns a value by fully-qualified path.
func (d *tomlDoc) Get(path string) (any, bool) {
	v, ok := d.values[path]
	return v, ok
}

// String returns a string value, or "".
func (d *tomlDoc) String(path string) string {
	v, ok := d.values[path]
	if !ok {
		return ""
	}
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int64:
		return itoa(t)
	case float64:
		return trimFloat(t)
	}
	return ""
}

// Strings returns an array-of-strings value, or nil.
func (d *tomlDoc) Strings(path string) []string {
	v, ok := d.values[path]
	if !ok {
		return nil
	}
	arr, ok := v.([]any)
	if !ok {
		return nil
	}
	out := make([]string, 0, len(arr))
	for _, item := range arr {
		if s, ok := item.(string); ok {
			out = append(out, s)
		}
	}
	return out
}

// Has reports whether a path is present, as a value or as a table.
//
// A table header writes no entry of its own: the `[a.b]` branch in Parse sets
// currentPrefix and moves on, so only the leaf keys that follow it are stored
// (`a.b.c`), never `a.b`. A leaf-only lookup therefore answers false for a table
// that is plainly in the file, and `Has("tool.poetry.dependencies")` was false
// for every real pyproject.toml - which is the whole of the defect this guards
// against (internal/parsers/pypi.go:239).
//
// ponytail: a prefix match, not a recorded set of table headers. An empty table
// (`[a.b]` with no keys under it) still reads as absent, which is the wanted
// answer for a dependency table with nothing in it. Track the headers in Parse
// if some caller ever needs to tell "absent" from "empty".
func (d *tomlDoc) Has(path string) bool {
	if _, ok := d.values[path]; ok {
		return true
	}
	prefix := path + "."
	for k := range d.values {
		if strings.HasPrefix(k, prefix) {
			return true
		}
	}
	return false
}

// Line returns the source line a value was declared on, or 0 when unknown.
func (d *tomlDoc) Line(path string) int { return d.lines[path] }

// AllKeys returns every fully-qualified path in sorted order.
//
// Sorted, not map order: the dependency tables in a Cargo.toml are discovered
// by scanning keys, and iterating a Go map would make the resulting dependency
// list differ between runs. Determinism is INV-6, and it starts here.
func (d *tomlDoc) AllKeys() []string {
	out := make([]string, 0, len(d.values))
	for k := range d.values {
		out = append(out, k)
	}
	sortStrings(out)
	return out
}

// ArrayPrefixes returns the paths of every array-of-tables entry, in order.
func (d *tomlDoc) ArrayPrefixes() []string {
	out := make([]string, len(d.order))
	copy(out, d.order)
	return out
}

// KeysUnder returns the immediate child keys under a prefix, sorted, so that a
// caller iterating a table's members is deterministic.
func (d *tomlDoc) KeysUnder(prefix string) []string {
	var out []string
	seen := map[string]bool{}
	p := prefix + "."
	for k := range d.values {
		if !strings.HasPrefix(k, p) {
			continue
		}
		rest := strings.TrimPrefix(k, p)
		if i := strings.IndexByte(rest, '.'); i >= 0 {
			rest = rest[:i]
		}
		if rest == "" || seen[rest] {
			continue
		}
		seen[rest] = true
		out = append(out, rest)
	}
	sortStrings(out)
	return out
}

// ── lexing helpers ───────────────────────────────────────────────────────────

func stripTomlComment(s string) string {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote && (i == 0 || s[i-1] != '\\' || quote == '\'') {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '#':
			return s[:i]
		}
	}
	return s
}

// indexOfTomlEquals finds the `=` that separates a key from its value, skipping
// any `=` inside a quoted key.
func indexOfTomlEquals(s string) int {
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '=':
			return i
		}
	}
	return -1
}

func bracketsBalanced(s string) bool {
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			if c == quote && (i == 0 || s[i-1] != '\\' || quote == '\'') {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
		case c == '[':
			depth++
		case c == ']':
			depth--
		}
	}
	return depth == 0
}

func unquoteTomlKey(k string) string {
	k = strings.TrimSpace(k)
	if len(k) >= 2 {
		if (k[0] == '"' && k[len(k)-1] == '"') || (k[0] == '\'' && k[len(k)-1] == '\'') {
			return k[1 : len(k)-1]
		}
	}
	return k
}

func parseTomlValue(raw string, line int) (any, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return nil, tomlErr(line, "missing value")
	}

	switch {
	case raw[0] == '"':
		if len(raw) < 2 || raw[len(raw)-1] != '"' {
			return nil, tomlErr(line, "unterminated string")
		}
		return unescapeToml(raw[1 : len(raw)-1]), nil

	case raw[0] == '\'':
		if len(raw) < 2 || raw[len(raw)-1] != '\'' {
			return nil, tomlErr(line, "unterminated literal string")
		}
		return raw[1 : len(raw)-1], nil

	case raw[0] == '[':
		if !strings.HasSuffix(raw, "]") {
			return nil, tomlErr(line, "unterminated array")
		}
		inner := raw[1 : len(raw)-1]
		parts, err := splitTomlList(inner, line)
		if err != nil {
			return nil, err
		}
		out := make([]any, 0, len(parts))
		for _, p := range parts {
			if strings.TrimSpace(p) == "" {
				continue
			}
			v, err := parseTomlValue(p, line)
			if err != nil {
				return nil, err
			}
			out = append(out, v)
		}
		return out, nil

	case raw[0] == '{':
		// An inline table. Returned as a map; the callers in this package do
		// not need to read inside one, but refusing it outright would reject
		// valid Cargo manifests that use `dep = { version = "1", features = [] }`.
		if !strings.HasSuffix(raw, "}") {
			return nil, tomlErr(line, "unterminated inline table")
		}
		inner := raw[1 : len(raw)-1]
		m := map[string]any{}
		parts, err := splitTomlList(inner, line)
		if err != nil {
			return nil, err
		}
		for _, p := range parts {
			eq := indexOfTomlEquals(p)
			if eq < 0 {
				continue
			}
			k := unquoteTomlKey(strings.TrimSpace(p[:eq]))
			v, err := parseTomlValue(strings.TrimSpace(p[eq+1:]), line)
			if err != nil {
				return nil, err
			}
			m[k] = v
		}
		return m, nil

	case raw == "true":
		return true, nil
	case raw == "false":
		return false, nil
	}

	if n, err := strconv.ParseInt(strings.ReplaceAll(raw, "_", ""), 10, 64); err == nil {
		return n, nil
	}
	if f, err := strconv.ParseFloat(strings.ReplaceAll(raw, "_", ""), 64); err == nil {
		return f, nil
	}
	return nil, tomlErr(line, "unsupported value "+truncate(raw))
}

// splitTomlList splits a comma-separated list, respecting nested brackets and
// quotes, so that `["a,b", "c"]` is two items and not three.
func splitTomlList(s string, line int) ([]string, error) {
	var out []string
	var cur strings.Builder
	depth := 0
	var quote byte
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case quote != 0:
			cur.WriteByte(c)
			if c == quote && (i == 0 || s[i-1] != '\\' || quote == '\'') {
				quote = 0
			}
		case c == '"' || c == '\'':
			quote = c
			cur.WriteByte(c)
		case c == '[' || c == '{':
			depth++
			cur.WriteByte(c)
		case c == ']' || c == '}':
			depth--
			cur.WriteByte(c)
		case c == ',' && depth == 0:
			out = append(out, strings.TrimSpace(cur.String()))
			cur.Reset()
		default:
			cur.WriteByte(c)
		}
	}
	if quote != 0 {
		return nil, tomlErr(line, "unterminated string in a list")
	}
	if strings.TrimSpace(cur.String()) != "" {
		out = append(out, strings.TrimSpace(cur.String()))
	}
	return out, nil
}

func unescapeToml(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c != '\\' || i+1 >= len(s) {
			b.WriteByte(c)
			continue
		}
		i++
		switch s[i] {
		case 'n':
			b.WriteByte('\n')
		case 't':
			b.WriteByte('\t')
		case 'r':
			b.WriteByte('\r')
		case '"':
			b.WriteByte('"')
		case '\\':
			b.WriteByte('\\')
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

func tomlErr(line int, msg string) error {
	return &tomlError{Line: line, Msg: msg}
}

type tomlError struct {
	Line int
	Msg  string
}

func (e *tomlError) Error() string {
	return "line " + strconv.Itoa(e.Line) + ": " + e.Msg
}

func truncate(s string) string {
	const max = 40
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func sortStrings(s []string) {
	for i := 1; i < len(s); i++ {
		for j := i; j > 0 && s[j] < s[j-1]; j-- {
			s[j], s[j-1] = s[j-1], s[j]
		}
	}
}
