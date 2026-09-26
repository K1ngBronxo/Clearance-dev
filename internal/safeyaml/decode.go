package safeyaml

import (
	"fmt"
	"reflect"
	"strconv"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// Unmarshaler is implemented by a type that knows how to build itself from a
// parsed node. It exists for the one case reflection cannot serve: a value
// whose shape is not its Go struct's shape.
//
// The predicate type is that case. A predicate is written as
// `{ op: and, l: {...}, r: {...} }` where `op` means the boolean operator, and
// also as `{ field: x, op: "==", value: y }` where `op` means the comparison
// operator. One key, two meanings, decided by which other keys are present.
// Reflection cannot express that; a thirty-line method can.
type Unmarshaler interface {
	UnmarshalYAML(n *Node) error
}

var unmarshalerType = reflect.TypeOf((*Unmarshaler)(nil)).Elem()

// Any returns the node as plain Go values (string, bool, int64, float64, nil,
// []any, map[string]any). It is what an UnmarshalYAML implementation starts
// from.
func (n *Node) Any() any { return n.toAny() }

// Decode fills a Go value from a parsed Node.
//
// SUPPORTED TARGET SHAPES
//
//	*T                      pointer, allocated on demand; a null leaves it nil
//	struct                  fields matched by `yaml:"name"` tag, else lowercased
//	string, bool            scalars
//	int, int64, float64     scalars
//	[]T                     sequences
//	[]string                sequences of scalars
//	map[string]T            mappings
//	any                     the raw Go value (string|bool|int64|float64|nil,
//	                        []any, map[string]any)
//
// A field tagged `yaml:"-"` is skipped. An unknown key in the document is an
// error rather than a shrug: a corpus entry with a typo'd `confidencee` would
// otherwise silently load with no confidence, which is exactly the kind of
// silent degradation this product exists to refuse.
func Decode(n *Node, v any) error {
	rv := reflect.ValueOf(v)
	if rv.Kind() != reflect.Pointer || rv.IsNil() {
		return fmt.Errorf("safeyaml: Decode needs a non-nil pointer, got %T", v)
	}
	return decodeInto(n, rv.Elem(), "")
}

func decodeInto(n *Node, dst reflect.Value, path string) error {
	if !dst.CanSet() {
		return fmt.Errorf("safeyaml: cannot set %s", path)
	}

	// A null leaves a pointer nil and zeroes everything else. It is never a
	// silent default: the caller can tell the difference between "absent" and
	// "false" for a bool, because a bool field simply stays false and the
	// schema validation catches the absence where it matters.
	if n == nil || n.IsNull() {
		switch dst.Kind() {
		case reflect.Pointer, reflect.Interface, reflect.Slice, reflect.Map:
			dst.Set(reflect.Zero(dst.Type()))
		}
		return nil
	}

	// A custom decoder wins over reflection, for the shapes reflection cannot
	// express. Both the pointer and the addressable value are checked, so that
	// `When *expr.Expr` and `When expr.Expr` behave identically.
	if dst.Kind() == reflect.Pointer && dst.Type().Implements(unmarshalerType) {
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		return dst.Interface().(Unmarshaler).UnmarshalYAML(n)
	}
	if dst.CanAddr() && dst.Addr().Type().Implements(unmarshalerType) {
		return dst.Addr().Interface().(Unmarshaler).UnmarshalYAML(n)
	}

	switch dst.Kind() {
	case reflect.Pointer:
		if dst.IsNil() {
			dst.Set(reflect.New(dst.Type().Elem()))
		}
		return decodeInto(n, dst.Elem(), path)

	case reflect.Interface:
		if dst.NumMethod() != 0 {
			return fmt.Errorf("safeyaml: cannot decode into %s at %s", dst.Type(), path)
		}
		dst.Set(reflect.ValueOf(n.toAny()))
		return nil

	case reflect.Struct:
		return decodeStruct(n, dst, path)

	case reflect.Slice:
		if n.Kind != SequenceNode {
			return typeErr(n, path, "a sequence")
		}
		out := reflect.MakeSlice(dst.Type(), 0, len(n.Items))
		for i, item := range n.Items {
			el := reflect.New(dst.Type().Elem()).Elem()
			if err := decodeInto(item, el, fmt.Sprintf("%s[%d]", path, i)); err != nil {
				return err
			}
			out = reflect.Append(out, el)
		}
		dst.Set(out)
		return nil

	case reflect.Map:
		if dst.Type().Key().Kind() != reflect.String {
			return fmt.Errorf("safeyaml: only string-keyed maps are supported at %s", path)
		}
		if n.Kind != MappingNode {
			return typeErr(n, path, "a mapping")
		}
		out := reflect.MakeMapWithSize(dst.Type(), len(n.Keys))
		for i, k := range n.Keys {
			el := reflect.New(dst.Type().Elem()).Elem()
			if err := decodeInto(n.Values[i], el, path+"."+k); err != nil {
				return err
			}
			out.SetMapIndex(reflect.ValueOf(k), el)
		}
		dst.Set(out)
		return nil

	case reflect.String:
		if n.Kind != ScalarNode {
			return typeErr(n, path, "a scalar")
		}
		dst.SetString(n.Str())
		return nil

	case reflect.Bool:
		if n.Kind != ScalarNode {
			return typeErr(n, path, "a boolean")
		}
		b, ok := n.Bool()
		if !ok {
			return fmt.Errorf("safeyaml: %s: line %d: expected a boolean, found %q", path, n.Line, n.Str())
		}
		dst.SetBool(b)
		return nil

	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		if n.Kind != ScalarNode {
			return typeErr(n, path, "an integer")
		}
		i, ok := n.Int()
		if !ok {
			return fmt.Errorf("safeyaml: %s: line %d: expected an integer, found %q", path, n.Line, n.Str())
		}
		dst.SetInt(i)
		return nil

	case reflect.Float32, reflect.Float64:
		if n.Kind != ScalarNode {
			return typeErr(n, path, "a number")
		}
		f, ok := n.Float()
		if !ok {
			return fmt.Errorf("safeyaml: %s: line %d: expected a number, found %q", path, n.Line, n.Str())
		}
		dst.SetFloat(f)
		return nil
	}

	return fmt.Errorf("safeyaml: unsupported target %s at %s", dst.Type(), path)
}

func decodeStruct(n *Node, dst reflect.Value, path string) error {
	if n.Kind != MappingNode {
		return typeErr(n, path, "a mapping")
	}
	fields := structFields(dst.Type())

	for i, key := range n.Keys {
		f, ok := fields[key]
		if !ok {
			return fmt.Errorf("safeyaml: unknown key %q at line %d (in %s)", key, n.Values[i].Line, displayPath(path))
		}
		fv := dst.FieldByIndex(f.index)
		if !fv.CanSet() {
			continue // unexported
		}
		childPath := key
		if path != "" {
			childPath = path + "." + key
		}
		if err := decodeInto(n.Values[i], fv, childPath); err != nil {
			return err
		}
	}
	return nil
}

type fieldInfo struct {
	index []int
}

// structFields builds the key → field map for a struct type. It is computed per
// call rather than cached: corpus loading is not a hot path, and a cache is a
// place for a bug to hide between two runs.
func structFields(t reflect.Type) map[string]fieldInfo {
	out := make(map[string]fieldInfo, t.NumField())
	var walk func(t reflect.Type, prefix []int)
	walk = func(t reflect.Type, prefix []int) {
		for i := 0; i < t.NumField(); i++ {
			sf := t.Field(i)
			if sf.PkgPath != "" && !sf.Anonymous {
				continue // unexported
			}
			idx := append(append([]int{}, prefix...), i)
			// The tag lookup tries `yaml` first, then `json`. Corpus types
			// carry both, because the same struct is published as JSON in the
			// compiled bundle and authored as YAML in the source tree, and
			// keeping one set of tags means the two cannot drift apart.
			name := ""
			for _, key := range []string{"yaml", "json"} {
				tag := sf.Tag.Get(key)
				if tag == "" {
					continue
				}
				if tag == "-" {
					name = "-"
					break
				}
				name = strings.Split(tag, ",")[0]
				break
			}
			if name == "-" {
				continue
			}
			if sf.Anonymous && name == "" {
				// Embedded struct: promote its fields.
				ft := sf.Type
				if ft.Kind() == reflect.Pointer {
					ft = ft.Elem()
				}
				if ft.Kind() == reflect.Struct {
					walk(ft, idx)
					continue
				}
			}
			if name == "" {
				name = strings.ToLower(sf.Name)
			}
			if _, exists := out[name]; !exists {
				out[name] = fieldInfo{index: idx}
			}
		}
	}
	walk(t, nil)
	return out
}

// toAny converts a Node to plain Go values, for `any` targets.
func (n *Node) toAny() any {
	if n == nil {
		return nil
	}
	switch n.Kind {
	case ScalarNode:
		return n.Value
	case SequenceNode:
		out := make([]any, 0, len(n.Items))
		for _, it := range n.Items {
			out = append(out, it.toAny())
		}
		return out
	case MappingNode:
		out := make(map[string]any, len(n.Keys))
		for i, k := range n.Keys {
			out[k] = n.Values[i].toAny()
		}
		return out
	}
	return nil
}

func typeErr(n *Node, path, want string) error {
	return fmt.Errorf("safeyaml: %s: line %d: expected %s, found %s", displayPath(path), n.Line, want, kindName(n.Kind))
}

func kindName(k Kind) string {
	switch k {
	case ScalarNode:
		return "a scalar"
	case SequenceNode:
		return "a sequence"
	case MappingNode:
		return "a mapping"
	}
	return "nothing"
}

func displayPath(p string) string {
	if p == "" {
		return "the document root"
	}
	return p
}

// ── scalar parsing ───────────────────────────────────────────────────────────

// parseInline parses a value that appears on one line: a flow collection, or a
// scalar.
func parseInline(s string, line int) (*Node, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return &Node{Kind: ScalarNode, Value: nil, Line: line}, nil
	}
	if s[0] == '[' || s[0] == '{' {
		fp := &flowParser{s: s, line: line}
		n, err := fp.parse()
		if err != nil {
			return nil, err
		}
		fp.skipSpace()
		if fp.i != len(fp.s) {
			return nil, syntaxf(line, "unexpected trailing content after a flow collection: %q", truncateForError(fp.s[fp.i:]))
		}
		return n, nil
	}
	return parseScalar(s, line)
}

// parseScalar resolves a single scalar token to bool, int64, float64, nil or
// string.
func parseScalar(s string, line int) (*Node, error) {
	s = strings.TrimSpace(s)
	if s == "" {
		return &Node{Kind: ScalarNode, Value: nil, Line: line}, nil
	}

	if s[0] == '"' {
		v, err := unquoteDouble(s, line)
		if err != nil {
			return nil, err
		}
		return &Node{Kind: ScalarNode, Value: v, Line: line}, nil
	}
	if s[0] == '\'' {
		v, err := unquoteSingle(s, line)
		if err != nil {
			return nil, err
		}
		return &Node{Kind: ScalarNode, Value: v, Line: line}, nil
	}

	switch strings.ToLower(s) {
	case "null", "~":
		return &Node{Kind: ScalarNode, Value: nil, Line: line}, nil
	case "true", "yes", "on":
		return &Node{Kind: ScalarNode, Value: true, Line: line}, nil
	case "false", "no", "off":
		return &Node{Kind: ScalarNode, Value: false, Line: line}, nil
	}

	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return &Node{Kind: ScalarNode, Value: i, Line: line}, nil
	}
	if f, err := strconv.ParseFloat(s, 64); err == nil {
		// Only treat it as a float if it actually looks numeric: ParseFloat
		// accepts "Inf" and "NaN", which are almost certainly intended as
		// strings in a licence corpus.
		if looksNumeric(s) {
			return &Node{Kind: ScalarNode, Value: f, Line: line}, nil
		}
	}
	return &Node{Kind: ScalarNode, Value: s, Line: line}, nil
}

func looksNumeric(s string) bool {
	seenDigit := false
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9':
			seenDigit = true
		case c == '.' || c == '-' || c == '+' || c == 'e' || c == 'E':
		default:
			return false
		}
	}
	return seenDigit
}

func unquoteSingle(s string, line int) (string, error) {
	if len(s) < 2 || s[len(s)-1] != '\'' {
		return "", syntaxf(line, "unterminated single-quoted scalar")
	}
	inner := s[1 : len(s)-1]
	return strings.ReplaceAll(inner, "''", "'"), nil
}

func unquoteDouble(s string, line int) (string, error) {
	if len(s) < 2 || s[len(s)-1] != '"' {
		return "", syntaxf(line, "unterminated double-quoted scalar")
	}
	inner := s[1 : len(s)-1]
	var b strings.Builder
	for i := 0; i < len(inner); i++ {
		c := inner[i]
		if c != '\\' {
			b.WriteByte(c)
			continue
		}
		i++
		if i >= len(inner) {
			return "", syntaxf(line, "dangling escape at the end of a double-quoted scalar")
		}
		switch inner[i] {
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
		case '0':
			b.WriteByte(0)
		case 'u':
			if i+4 >= len(inner) {
				return "", syntaxf(line, "truncated \\u escape")
			}
			code, err := strconv.ParseUint(inner[i+1:i+5], 16, 32)
			if err != nil {
				return "", syntaxf(line, "invalid \\u escape %q", inner[i:i+5])
			}
			b.WriteRune(rune(code))
			i += 4
		default:
			return "", syntaxf(line, "unsupported escape \\%c", inner[i])
		}
	}
	return b.String(), nil
}

// ── flow collections ─────────────────────────────────────────────────────────

type flowParser struct {
	s    string
	i    int
	line int
}

func (f *flowParser) skipSpace() {
	for f.i < len(f.s) && (f.s[f.i] == ' ' || f.s[f.i] == '\t') {
		f.i++
	}
}

func (f *flowParser) parse() (*Node, error) {
	f.skipSpace()
	if f.i >= len(f.s) {
		return nil, syntaxf(f.line, "unexpected end of a flow collection")
	}
	switch f.s[f.i] {
	case '[':
		return f.parseSeq()
	case '{':
		return f.parseMap()
	}
	return nil, syntaxf(f.line, "expected '[' or '{'")
}

func (f *flowParser) parseSeq() (*Node, error) {
	node := &Node{Kind: SequenceNode, Line: f.line}
	f.i++ // consume '['
	for {
		f.skipSpace()
		if f.i >= len(f.s) {
			return nil, syntaxf(f.line, "unterminated flow sequence")
		}
		if f.s[f.i] == ']' {
			f.i++
			return node, nil
		}
		item, err := f.parseValue()
		if err != nil {
			return nil, err
		}
		node.Items = append(node.Items, item)
		f.skipSpace()
		if f.i < len(f.s) && f.s[f.i] == ',' {
			f.i++
			continue
		}
		if f.i < len(f.s) && f.s[f.i] == ']' {
			f.i++
			return node, nil
		}
		return nil, syntaxf(f.line, "expected ',' or ']' in a flow sequence")
	}
}

func (f *flowParser) parseMap() (*Node, error) {
	node := &Node{Kind: MappingNode, Line: f.line}
	f.i++ // consume '{'
	for {
		f.skipSpace()
		if f.i >= len(f.s) {
			return nil, syntaxf(f.line, "unterminated flow mapping")
		}
		if f.s[f.i] == '}' {
			f.i++
			return node, nil
		}
		key, err := f.readToken(':', true)
		if err != nil {
			return nil, err
		}
		f.skipSpace()
		if f.i >= len(f.s) || f.s[f.i] != ':' {
			return nil, syntaxf(f.line, "expected ':' in a flow mapping")
		}
		f.i++
		val, err := f.parseValue()
		if err != nil {
			return nil, err
		}
		node.Keys = append(node.Keys, key)
		node.Values = append(node.Values, val)

		f.skipSpace()
		if f.i < len(f.s) && f.s[f.i] == ',' {
			f.i++
			continue
		}
		if f.i < len(f.s) && f.s[f.i] == '}' {
			f.i++
			return node, nil
		}
		return nil, syntaxf(f.line, "expected ',' or '}' in a flow mapping")
	}
}

func (f *flowParser) parseValue() (*Node, error) {
	f.skipSpace()
	if f.i >= len(f.s) {
		return nil, syntaxf(f.line, "unexpected end of a flow collection")
	}
	if f.s[f.i] == '[' || f.s[f.i] == '{' {
		return f.parse()
	}
	if f.s[f.i] == '&' || f.s[f.i] == '*' {
		return nil, cerrNewAlias()
	}
	if f.s[f.i] == '!' {
		return nil, cerrNewTag(f.readTag())
	}
	tok, err := f.readToken(',', false)
	if err != nil {
		return nil, err
	}
	return parseScalar(tok, f.line)
}

// readToken reads up to a delimiter, respecting quotes.
func (f *flowParser) readToken(delim byte, key bool) (string, error) {
	var b strings.Builder
	var quote byte
	for f.i < len(f.s) {
		c := f.s[f.i]
		if quote != 0 {
			b.WriteByte(c)
			if c == quote {
				if quote == '\'' && f.i+1 < len(f.s) && f.s[f.i+1] == '\'' {
					f.i++
					b.WriteByte('\'')
				} else {
					quote = 0
				}
			} else if quote == '"' && c == '\\' && f.i+1 < len(f.s) {
				f.i++
				b.WriteByte(f.s[f.i])
			}
			f.i++
			continue
		}
		switch c {
		case '\'', '"':
			quote = c
			b.WriteByte(c)
			f.i++
		case delim, ',', ']', '}':
			return strings.TrimSpace(b.String()), nil
		default:
			b.WriteByte(c)
			f.i++
		}
	}
	if key {
		return "", syntaxf(f.line, "unterminated flow mapping key")
	}
	return strings.TrimSpace(b.String()), nil
}

func (f *flowParser) readTag() string {
	start := f.i
	for f.i < len(f.s) && f.s[f.i] != ' ' && f.s[f.i] != ',' && f.s[f.i] != ']' && f.s[f.i] != '}' {
		f.i++
	}
	return f.s[start:f.i]
}

// cerrNewAlias and cerrNewTag keep the flow parser's refusals identical to the
// block parser's. An anchor inside a flow collection must produce the same code
// as an anchor in a block scalar, or the taxonomy would have two answers for one
// problem.
func cerrNewAlias() error { return cerr.New(cerr.EParse008, "input") }

func cerrNewTag(tag string) error { return cerr.New(cerr.EParse009, "input", tag) }
