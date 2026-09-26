// Package safejson is a strict, bounded JSON decoder (control C2, INV-10).
//
// INV-10: "JSON has a max depth, max key count, and max size. A malicious
// manifest is a real attack surface."
//
// WHY NOT encoding/json
//
// encoding/json is not a security problem in the way a YAML library is, but it
// has two properties this product cannot live with:
//
//  1. No depth limit. A 10 KB file of `[[[[[…]]]]` will recurse until the
//     goroutine stack dies, which on a CI runner is a crash rather than a
//     finding. E-PARSE-006 exists for exactly this.
//  2. Silent coercion. Numbers become float64, so a version like
//     `1.10.0` that a manifest happened to encode unquoted becomes 1.1, and a
//     19-digit integer loses its last digits. A licence verdict built on a
//     rounded version is a verdict about a different package.
//
// So this package decodes JSON with a hand-written scanner that enforces both,
// and preserves integers as integers. It has no third-party dependency.
//
// `json.Unmarshal` and `json.NewDecoder` on project input are banned everywhere
// else in internal/ by the linter and by internal/arch_test.go.
package safejson

import (
	"strconv"
	"strings"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/clearance-dev/clearance/internal/cerr"
)

// Limits bounds the decoder. The zero value is replaced by DefaultLimits.
type Limits struct {
	MaxBytes int // default 8 MiB
	MaxDepth int // default 64
	MaxKeys  int // default 100_000, counted across the whole document
}

// DefaultLimits are the values from the plan's security architecture.
func DefaultLimits() Limits { return Limits{MaxBytes: 8 << 20, MaxDepth: 64, MaxKeys: 100_000} }

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxBytes <= 0 {
		l.MaxBytes = d.MaxBytes
	}
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxKeys <= 0 {
		l.MaxKeys = d.MaxKeys
	}
	return l
}

// Value is a decoded JSON value. One of:
//
//	nil      for null
//	bool
//	int64    for an integer literal that fits
//	float64  for a number with a fraction or an exponent
//	string
//	[]Value  for an array
//	Object   for an object
type Value any

// Object is a JSON object with its members in source order, so that iteration
// is deterministic (INV-6).
type Object struct {
	Keys   []string
	Values []Value
}

// Get returns a member value.
func (o Object) Get(key string) (Value, bool) {
	for i, k := range o.Keys {
		if k == key {
			return o.Values[i], true
		}
	}
	return nil, false
}

// Has reports whether a member is present.
func (o Object) Has(key string) bool { _, ok := o.Get(key); return ok }

// String returns a string member, or "".
func (o Object) String(key string) string {
	v, ok := o.Get(key)
	if !ok {
		return ""
	}
	s, _ := v.(string)
	return s
}

// Array returns an array member, or nil.
func (o Object) Array(key string) []Value {
	v, ok := o.Get(key)
	if !ok {
		return nil
	}
	a, _ := v.([]Value)
	return a
}

// Bool returns a bool member and whether it was present as a bool.
func (o Object) Bool(key string) (bool, bool) {
	v, ok := o.Get(key)
	if !ok {
		return false, false
	}
	b, ok := v.(bool)
	return b, ok
}

// Int returns an integer member. A number written as 1.0 is accepted, because a
// manifest that writes `"version": 1.0` means the integer 1.
func (o Object) Int(key string) (int64, bool) {
	v, ok := o.Get(key)
	if !ok {
		return 0, false
	}
	switch n := v.(type) {
	case int64:
		return n, true
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	}
	return 0, false
}

// Object returns an object member, or the zero Object.
func (o Object) Object(key string) Object {
	v, ok := o.Get(key)
	if !ok {
		return Object{}
	}
	ob, _ := v.(Object)
	return ob
}

// Decode parses a complete JSON document. Trailing non-whitespace content is an
// error: a manifest with two JSON documents concatenated is a corrupted file,
// not a document to guess at.
func Decode(data []byte, limits Limits) (Value, error) {
	lim := limits.withDefaults()
	if len(data) > lim.MaxBytes {
		return nil, cerr.New(cerr.EParse004, "input", humanBytes(int64(len(data))), humanBytes(int64(lim.MaxBytes)))
	}
	if !utf8.Valid(data) {
		return nil, cerr.New(cerr.EParse010, "input", "invalid utf-8")
	}
	d := &decoder{s: string(data), maxDepth: lim.MaxDepth, maxKeys: lim.MaxKeys}
	d.skipSpace()
	v, err := d.value(0)
	if err != nil {
		return nil, err
	}
	d.skipSpace()
	if d.i != len(d.s) {
		return nil, d.errf("unexpected trailing content")
	}
	return v, nil
}

// DecodeObject parses a document and requires it to be an object. It is the
// entry point for every manifest and lockfile.
func DecodeObject(data []byte, limits Limits) (Object, error) {
	v, err := Decode(data, limits)
	if err != nil {
		return Object{}, err
	}
	o, ok := v.(Object)
	if !ok {
		return Object{}, cerr.New(cerr.EParse002, "input", "the document is not a JSON object")
	}
	return o, nil
}

type decoder struct {
	s        string
	i        int
	maxDepth int
	keys     int
	maxKeys  int
}

// errf renders a SyntaxError-shaped message with the line and column, so that
// E-PARSE-002's message ("invalid JSON at line 42") is actually true.
func (d *decoder) errf(format string, a ...any) error {
	line := 1
	col := 1
	for j := 0; j < d.i && j < len(d.s); j++ {
		if d.s[j] == '\n' {
			line++
			col = 1
		} else {
			col++
		}
	}
	return &SyntaxError{Line: line, Col: col, Msg: sprintf(format, a...)}
}

// SyntaxError is a malformed-document error. The caller maps it to the right
// code for its context.
type SyntaxError struct {
	Line int
	Col  int
	Msg  string
}

func (e *SyntaxError) Error() string {
	return "line " + strconv.Itoa(e.Line) + ":" + strconv.Itoa(e.Col) + ": " + e.Msg
}

func (d *decoder) skipSpace() {
	for d.i < len(d.s) {
		switch d.s[d.i] {
		case ' ', '\t', '\n', '\r':
			d.i++
		default:
			return
		}
	}
}

func (d *decoder) value(depth int) (Value, error) {
	if depth > d.maxDepth {
		return nil, cerr.New(cerr.EParse006, "input", strconv.Itoa(d.maxDepth))
	}
	if d.i >= len(d.s) {
		return nil, d.errf("unexpected end of input")
	}
	switch c := d.s[d.i]; {
	case c == '{':
		return d.object(depth)
	case c == '[':
		return d.array(depth)
	case c == '"':
		return d.string()
	case c == 't':
		return d.literal("true", true)
	case c == 'f':
		return d.literal("false", false)
	case c == 'n':
		return d.literal("null", nil)
	case c == '-' || (c >= '0' && c <= '9'):
		return d.number()
	}
	return nil, d.errf("unexpected character %q", string(d.s[d.i]))
}

func (d *decoder) literal(word string, v Value) (Value, error) {
	if !strings.HasPrefix(d.s[d.i:], word) {
		return nil, d.errf("invalid literal, expected %q", word)
	}
	d.i += len(word)
	return v, nil
}

func (d *decoder) object(depth int) (Value, error) {
	obj := Object{}
	d.i++ // consume '{'
	d.skipSpace()
	if d.i < len(d.s) && d.s[d.i] == '}' {
		d.i++
		return obj, nil
	}
	for {
		d.skipSpace()
		if d.i >= len(d.s) || d.s[d.i] != '"' {
			return nil, d.errf("expected an object key")
		}
		key, err := d.string()
		if err != nil {
			return nil, err
		}
		d.keys++
		if d.keys > d.maxKeys {
			return nil, cerr.New(cerr.EParse006, "input", strconv.Itoa(d.maxDepth))
		}
		d.skipSpace()
		if d.i >= len(d.s) || d.s[d.i] != ':' {
			return nil, d.errf("expected ':' after an object key")
		}
		d.i++
		d.skipSpace()
		val, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		// A duplicate key is refused, not last-wins. A lockfile that names the
		// same package twice with different versions is a file a human must
		// look at, not a file to silently resolve.
		if obj.Has(key.(string)) {
			return nil, d.errf("duplicate object key %q", key.(string))
		}
		obj.Keys = append(obj.Keys, key.(string))
		obj.Values = append(obj.Values, val)
		d.skipSpace()
		if d.i >= len(d.s) {
			return nil, d.errf("unterminated object")
		}
		switch d.s[d.i] {
		case ',':
			d.i++
		case '}':
			d.i++
			return obj, nil
		default:
			return nil, d.errf("expected ',' or '}' in an object")
		}
	}
}

func (d *decoder) array(depth int) (Value, error) {
	arr := []Value{}
	d.i++ // consume '['
	d.skipSpace()
	if d.i < len(d.s) && d.s[d.i] == ']' {
		d.i++
		return arr, nil
	}
	for {
		d.skipSpace()
		v, err := d.value(depth + 1)
		if err != nil {
			return nil, err
		}
		arr = append(arr, v)
		d.skipSpace()
		if d.i >= len(d.s) {
			return nil, d.errf("unterminated array")
		}
		switch d.s[d.i] {
		case ',':
			d.i++
		case ']':
			d.i++
			return arr, nil
		default:
			return nil, d.errf("expected ',' or ']' in an array")
		}
	}
}

func (d *decoder) string() (Value, error) {
	d.i++ // consume the opening quote
	var b strings.Builder
	for d.i < len(d.s) {
		c := d.s[d.i]
		switch {
		case c == '"':
			d.i++
			return b.String(), nil
		case c == '\\':
			d.i++
			if d.i >= len(d.s) {
				return nil, d.errf("dangling escape")
			}
			switch d.s[d.i] {
			case '"':
				b.WriteByte('"')
			case '\\':
				b.WriteByte('\\')
			case '/':
				b.WriteByte('/')
			case 'b':
				b.WriteByte('\b')
			case 'f':
				b.WriteByte('\f')
			case 'n':
				b.WriteByte('\n')
			case 'r':
				b.WriteByte('\r')
			case 't':
				b.WriteByte('\t')
			case 'u':
				if d.i+4 >= len(d.s) {
					return nil, d.errf("truncated \\u escape")
				}
				code, err := strconv.ParseUint(d.s[d.i+1:d.i+5], 16, 32)
				if err != nil {
					return nil, d.errf("invalid \\u escape")
				}
				d.i += 4
				r := rune(code)
				// A surrogate pair is two escapes; join them so that an emoji
				// in a description does not become two replacement characters.
				if utf16.IsSurrogate(r) && d.i+6 < len(d.s) && d.s[d.i+1] == '\\' && d.s[d.i+2] == 'u' {
					if low, err := strconv.ParseUint(d.s[d.i+3:d.i+7], 16, 32); err == nil {
						if dec := utf16.DecodeRune(r, rune(low)); dec != utf8.RuneError {
							b.WriteRune(dec)
							d.i += 6
							d.i++
							continue
						}
					}
				}
				b.WriteRune(r)
			default:
				return nil, d.errf("unsupported escape \\%c", d.s[d.i])
			}
			d.i++
		case c < 0x20:
			return nil, d.errf("a raw control character in a string; escape it")
		default:
			b.WriteByte(c)
			d.i++
		}
	}
	return nil, d.errf("unterminated string")
}

func (d *decoder) number() (Value, error) {
	start := d.i
	if d.i < len(d.s) && d.s[d.i] == '-' {
		d.i++
	}
	isFloat := false
	for d.i < len(d.s) {
		c := d.s[d.i]
		switch {
		case c >= '0' && c <= '9':
			d.i++
		case c == '.' || c == 'e' || c == 'E' || c == '+' || c == '-':
			isFloat = true
			d.i++
		default:
			goto done
		}
	}
done:
	text := d.s[start:d.i]
	if text == "" || text == "-" {
		return nil, d.errf("invalid number")
	}
	if !isFloat {
		if n, err := strconv.ParseInt(text, 10, 64); err == nil {
			return n, nil
		}
		// An integer too large for int64. Keep it as a string rather than
		// rounding it: a version or a hash must not be silently changed.
		return text, nil
	}
	f, err := strconv.ParseFloat(text, 64)
	if err != nil {
		return nil, d.errf("invalid number %q", text)
	}
	return f, nil
}

// ── small helpers, to keep this package dependency-free of fmt for hot paths ──

func sprintf(format string, a ...any) string {
	if len(a) == 0 {
		return format
	}
	var b strings.Builder
	ai := 0
	for i := 0; i < len(format); i++ {
		if format[i] == '%' && i+1 < len(format) {
			i++
			if format[i] == '%' {
				b.WriteByte('%')
				continue
			}
			if ai < len(a) {
				b.WriteString(stringify(a[ai]))
				ai++
			}
			continue
		}
		b.WriteByte(format[i])
	}
	return b.String()
}

func stringify(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case rune:
		return string(t)
	case byte:
		return string(rune(t))
	case error:
		return t.Error()
	case bool:
		return strconv.FormatBool(t)
	}
	return ""
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
