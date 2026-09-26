package mcp

import (
	"strings"

	"github.com/clearance-dev/clearance/internal/safejson"
)

// toYAML renders a decoded JSON value as a YAML document.
//
// # WHY THIS EXISTS AT ALL
//
// Because `safejson.Object` cannot be handed to `encoding/json` — its Keys and
// Values slices are exported, so Marshal produces `{"Keys":[...]}` rather than
// the object — and because `safeyaml` cannot parse JSON either. Its parser is
// line-oriented and deliberately small: it looks for `key: value` on each line,
// so a one-line JSON document is a single unparseable line. The "JSON is a
// subset of YAML" truism is true of YAML 1.2 and false of this parser, which
// implements the subset the corpus needs rather than the whole specification.
//
// So the inline intent has to cross from one representation to the other
// somewhere, and this is that place. It emits the block style the parser reads
// natively.
//
// # WHY EVERY STRING IS QUOTED
//
// Because the alternative is a classifier that decides which strings are safe
// bare, and every YAML implementation has a different answer. `no` is a boolean
// in YAML 1.1 and a string in 1.2; `1.0` is a float; `null` is null; a leading
// `-` is a sequence marker; `a: b` is a mapping. A project name of "no" or a
// licence of "1.0" would silently become the wrong type, and the failure would
// surface as a type error three layers away from the client that sent it.
//
// Quoting everything removes the classifier. The cost is that a decode error
// prints `"commercial"` where it could have printed `commercial`, and that is a
// trade worth making in the direction of not guessing.
func toYAML(v safejson.Value) []byte {
	var b strings.Builder
	writeYAMLNode(&b, v, 0)
	return []byte(b.String())
}

// writeYAMLNode writes a whole node at the given indent. It is used for the
// document root and for the more-indented block under a bare dash.
func writeYAMLNode(b *strings.Builder, v safejson.Value, indent int) {
	switch t := v.(type) {
	case safejson.Object:
		if len(t.Keys) == 0 {
			b.WriteString(pad(indent) + "{}\n")
			return
		}
		writeYAMLMap(b, t, indent)
	case []safejson.Value:
		if len(t) == 0 {
			b.WriteString(pad(indent) + "[]\n")
			return
		}
		writeYAMLSeq(b, t, indent)
	default:
		b.WriteString(pad(indent) + yamlScalar(v) + "\n")
	}
}

// writeYAMLMap writes `key:` lines at the given indent.
func writeYAMLMap(b *strings.Builder, o safejson.Object, indent int) {
	for i, k := range o.Keys {
		var child safejson.Value
		if i < len(o.Values) {
			child = o.Values[i]
		}
		b.WriteString(pad(indent))
		b.WriteString(yamlKey(k))
		b.WriteString(":")
		writeYAMLValue(b, child, indent)
	}
}

// writeYAMLSeq writes `- ` items at the given indent.
//
// # WHY A SEQUENCE OF OBJECTS USES A BARE DASH
//
// Because `- licence: MIT` followed by `  when:` requires the parser to compute
// the item's own column from the dash's column plus the leading spaces, and
// getting that arithmetic wrong produces a document that parses into the wrong
// shape rather than one that fails. A bare `-` with the object indented under it
// is the form the parser's `itemText == ""` branch handles explicitly, and there
// is no column arithmetic to get wrong.
func writeYAMLSeq(b *strings.Builder, items []safejson.Value, indent int) {
	for _, item := range items {
		switch t := item.(type) {
		case safejson.Object:
			if len(t.Keys) == 0 {
				b.WriteString(pad(indent) + "- {}\n")
				continue
			}
			b.WriteString(pad(indent) + "-\n")
			writeYAMLMap(b, t, indent+2)
		case []safejson.Value:
			if len(t) == 0 {
				b.WriteString(pad(indent) + "- []\n")
				continue
			}
			b.WriteString(pad(indent) + "-\n")
			writeYAMLSeq(b, t, indent+2)
		default:
			b.WriteString(pad(indent) + "- " + yamlScalar(item) + "\n")
		}
	}
}

// writeYAMLValue writes the part of a line that follows `key:`.
//
// A scalar stays on the key's line; a collection moves to the next line at a
// deeper indent. That is the only distinction the line-oriented parser needs,
// and it is why this is a separate function from writeYAMLNode: the root has no
// key to follow.
func writeYAMLValue(b *strings.Builder, v safejson.Value, indent int) {
	switch t := v.(type) {
	case safejson.Object:
		if len(t.Keys) == 0 {
			b.WriteString(" {}\n")
			return
		}
		b.WriteString("\n")
		writeYAMLMap(b, t, indent+2)
	case []safejson.Value:
		if len(t) == 0 {
			b.WriteString(" []\n")
			return
		}
		b.WriteString("\n")
		writeYAMLSeq(b, t, indent+2)
	default:
		b.WriteString(" " + yamlScalar(v) + "\n")
	}
}

// yamlKey renders a mapping key.
//
// Keys are quoted by the same rule as values, for the same reason, and the
// parser handles a quoted key — splitKey runs parseScalar over one that begins
// and ends with a quote. Quoting is what stops a client-supplied key such as
// `a: b` from being read as a nested mapping.
func yamlKey(k string) string { return yamlQuote(k) }

// yamlScalar renders a scalar value.
func yamlScalar(v safejson.Value) string {
	switch t := v.(type) {
	case nil:
		return "null"
	case bool:
		if t {
			return "true"
		}
		return "false"
	case int64:
		return itoa64(t)
	case float64:
		return floatText(t)
	case string:
		return yamlQuote(t)
	default:
		// A shape safejson does not produce. Quoting its rendering is the safe
		// answer: it becomes a string rather than a syntax error, and the
		// decoder rejects it with a type error that names the field.
		return yamlQuote(sprintValue(v))
	}
}

// yamlQuote wraps a string in double quotes, escaping the two characters that
// matter inside them.
//
// Only `\` and `"` need escaping for the parser's unquoteDouble to invert this
// exactly. A newline inside a quoted scalar is left alone rather than escaped:
// the parser splits on lines first, so a value containing a newline cannot be
// represented in this subset at all, and emitting a literal newline inside
// quotes produces a document that fails to parse — which is the honest outcome
// for a value the format cannot carry.
func yamlQuote(s string) string {
	var b strings.Builder
	b.Grow(len(s) + 2)
	b.WriteByte('"')
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			b.WriteString(`\\`)
		case '"':
			b.WriteString(`\"`)
		default:
			b.WriteByte(s[i])
		}
	}
	b.WriteByte('"')
	return b.String()
}

// pad returns n spaces.
func pad(n int) string {
	if n <= 0 {
		return ""
	}
	return strings.Repeat(" ", n)
}

// itoa64 renders an int64 without strconv, for the same reason itoa exists.
func itoa64(n int64) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		if n == -9223372036854775808 {
			return "-9223372036854775808"
		}
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

// floatText renders a float the way the config spec writes one.
//
// Trailing zeros are trimmed so that `1.0` round-trips as `1` rather than as
// `1.000000`, and a whole number is rendered without a decimal point. The
// config has no float fields today — revenue is an integer number of euros —
// so this path exists for the predicate literals, which are the only place a
// client can send one.
func floatText(f float64) string {
	if f == float64(int64(f)) {
		return itoa64(int64(f))
	}
	neg := f < 0
	if neg {
		f = -f
	}
	whole := int64(f)
	frac := f - float64(whole)

	var digits []byte
	for i := 0; i < 12 && frac != 0; i++ {
		frac *= 10
		d := int(frac)
		if d < 0 || d > 9 {
			// Unreachable for a finite fraction in [0,1), which is the only
			// thing that gets here. Written out rather than assumed: the
			// number came from a parsed document, and the conversion below is
			// the one that would silently wrap if that ever stopped holding.
			break
		}
		digits = append(digits, byte('0'+d))
		frac -= float64(d)
	}
	// Trim trailing zeros; a fractional part of exactly zero was handled above.
	for len(digits) > 0 && digits[len(digits)-1] == '0' {
		digits = digits[:len(digits)-1]
	}
	if len(digits) == 0 {
		digits = []byte{'0'}
	}
	out := itoa64(whole) + "." + string(digits)
	if neg {
		return "-" + out
	}
	return out
}

// sprintValue renders an unexpected shape for quoting. It handles the two
// remaining Go types safejson can produce from a decode, and falls back to a
// marker rather than panicking.
func sprintValue(v any) string {
	switch v.(type) {
	case []any:
		return "[]"
	case map[string]any:
		return "{}"
	default:
		return ""
	}
}
