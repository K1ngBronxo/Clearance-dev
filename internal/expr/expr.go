// Package expr is the predicate language: a tiny, auditable, serialisable
// expression tree that decides whether an obligation applies.
//
// # WHY THIS PACKAGE EXISTS
//
// PLAN/01-ARCHITECTURE/03-data-model.md §9 places `Expr` in the policy package.
// But the corpus (L2) stores predicates and must validate them at build time
// (schema rules 4-6: every `when` references a known field, type-checks, and
// nests no deeper than 8), while the layer rule forbids L2 from importing L3.
// So the type lives here, at the same tier as `graph`: pure, dependency-free
// beyond `cerr`, and knowable by both.
//
// WHY THIS LANGUAGE AND NOT REGO, CEL, OR eval()
//
//	Rego / OPA   a heavy dependency and a second language to learn, to compare
//	             declared booleans.
//	CEL          better, but still a full expression language with function
//	             calls and a complexity budget of its own.
//	Lua/JS/eval  arbitrary code execution driven by corpus data. Categorically
//	             forbidden (control C7).
//	This tree    serialisable to JSON, printable to a human sentence, evaluable
//	             in one pass, and small enough that a reviewer can verify an
//	             entry's logic by eye.
//
// It is deliberately NOT Turing-complete. No loops, no function calls, no
// arithmetic beyond comparison. Every predicate terminates, and it terminates
// in time proportional to its size.
package expr

import (
	"sort"
	"strconv"
	"strings"

	"github.com/clearance-dev/clearance/internal/cerr"
	"github.com/clearance-dev/clearance/internal/safeyaml"
)

// MaxDepth is the documented nesting limit (corpus schema validation rule 6).
// A predicate deeper than this is a corpus bug, caught at build time.
const MaxDepth = 8

// Kind is the node type of a predicate.
type Kind string

const (
	KindAnd Kind = "and"
	KindOr  Kind = "or"
	KindNot Kind = "not"
	KindCmp Kind = "cmp"
	KindLit Kind = "lit"
)

// Op is a comparison operator.
type Op string

const (
	OpEQ       Op = "=="
	OpNE       Op = "!="
	OpGT       Op = ">"
	OpGTE      Op = ">="
	OpLT       Op = "<"
	OpLTE      Op = "<="
	OpIn       Op = "in"
	OpContains Op = "contains"
)

// Expr is a predicate node. Exactly one shape is populated, selected by Kind.
type Expr struct {
	Kind Kind `json:"op"`

	// And / Or
	L *Expr `json:"l,omitempty"`
	R *Expr `json:"r,omitempty"`

	// Not
	X *Expr `json:"x,omitempty"`

	// Cmp
	Field string `json:"field,omitempty"`
	Cmp   Op     `json:"cmp_op,omitempty"`
	Value any    `json:"value,omitempty"`

	// Lit
	Lit *bool `json:"lit,omitempty"`
}

// ── the field registry ───────────────────────────────────────────────────────

// FieldType is the declared type of an intent or dependency field.
type FieldType int

const (
	TypeBool FieldType = iota
	TypeInt
	TypeString
	TypeEnum
	TypeStringList
)

func (t FieldType) String() string {
	switch t {
	case TypeBool:
		return "bool"
	case TypeInt:
		return "int"
	case TypeString:
		return "string"
	case TypeEnum:
		return "enum"
	case TypeStringList:
		return "[]string"
	}
	return "unknown"
}

// Field is one addressable path in the predicate language.
type Field struct {
	Path   string
	Type   FieldType
	Source string // "intent" | "dependency" | "project"
	Note   string
}

// fields is the closed set of addressable paths, from
// PLAN/01-ARCHITECTURE/06-policy-engine.md §4.2.
//
// The set is closed on purpose: a predicate naming a field that does not exist
// is a corpus bug, and it fails the build rather than evaluating to false. A
// typo'd field that silently evaluates false is a trap that never fires, which
// is the most expensive kind of bug this product could ship.
//
// # WHY dep.licence.spdx AND dep.licence.resolved EXIST
//
// Because a family is a class, and several traps are about a licence.
//
// `trap.sspl.not-open-source`, `trap.elastic.licence-confusion` and
// `trap.busl.conversion` all carried `dep.licence.family == source-available`,
// which is the only predicate the vocabulary allowed. The consequence was that
// any one of the three would fire on the other two's licences: a dependency
// under SSPL-1.0 produced a finding citing Elastic's blog, and a dependency
// under the Elastic License produced a finding citing MongoDB's FAQ. A citation
// that points at the wrong licence is worse than no finding, because it is the
// part a reader is least able to check.
//
// The same shape appears elsewhere: `trap.lgpl.static-linking` keyed on
// `weak-copyleft`, which is LGPL-3.0-only *and* MPL-2.0, and MPL-2.0 has no
// relinking requirement at all. `trap.patent.retaliation` keyed on `permissive`,
// which is Apache-2.0 (which has the clause) and MIT (which does not).
//
// So the vocabulary gains a field for the licence itself. A trap that is about
// one licence now says so.
//
// `dep.licence.resolved` is the other half. `trap.licence.absent-all-rights-
// reserved` is about a dependency with *no* licence, and the vocabulary could
// not express that either — so it keyed on `family == custom`, which in this
// corpus is the Llama 3.1 Community License, a licence that grants commercial
// use. The trap would have fired its "all rights reserved" finding on a
// dependency that is nothing of the kind. `custom` means "bespoke", and
// "bespoke" is not "absent".
var fields = []Field{
	{"use.commercial", TypeBool, "intent", "are you charging or earning revenue?"},
	{"use.licence_model", TypeEnum, "intent", "closed-source | open-source | dual | internal-only"},
	{"use.modified", TypeBool, "intent", "do you modify vendored code?"},
	{"use.network_exposed", TypeBool, "intent", "do you expose it over a network?"},
	{"use.distributed", TypeBool, "intent", "do you ship binaries or source to third parties?"},
	{"use.saas", TypeBool, "intent", "is it offered as a service?"},
	{"scale.mau", TypeInt, "intent", "monthly active users"},
	{"scale.employees", TypeInt, "intent", "number of employees"},
	{"scale.revenue_eur", TypeInt, "intent", "annual revenue in euro"},
	{"territories", TypeStringList, "intent", "ISO-3166 alpha-2 codes or region groups"},
	{"project.name", TypeString, "intent", "the project name"},
	{"dep.kind", TypeEnum, "dependency", "package | vendored | weights | upstream_cli | asset"},
	{"dep.ecosystem", TypeString, "dependency", "npm | pypi | go | cargo | local | weights"},
	{"dep.licence.family", TypeEnum, "dependency", "permissive | weak-copyleft | strong-copyleft | network-copyleft | source-available | non-commercial | custom"},
	{"dep.licence.permissiveness", TypeInt, "dependency", "1..5, from the corpus"},
	{"dep.licence.spdx", TypeString, "dependency", "the resolved SPDX identifier, or empty when none was found"},
	{"dep.licence.resolved", TypeBool, "dependency", "did the scanner find a licence at all?"},
	{"dep.name", TypeString, "dependency", "the package or file name"},
	{"dep.version", TypeString, "dependency", "the resolved version, or empty"},
}

var fieldByPath = func() map[string]Field {
	m := make(map[string]Field, len(fields))
	for _, f := range fields {
		m[f.Path] = f
	}
	return m
}()

// Fields returns the registry in declaration order.
func Fields() []Field {
	out := make([]Field, len(fields))
	copy(out, fields)
	return out
}

// LookupField returns a field definition by path.
func LookupField(path string) (Field, bool) {
	f, ok := fieldByPath[path]
	return f, ok
}

// FieldPaths returns every addressable path, sorted. It is used by the
// corpus-build validator and by the `clearance explain` renderer.
func FieldPaths() []string {
	out := make([]string, 0, len(fields))
	for _, f := range fields {
		out = append(out, f.Path)
	}
	sort.Strings(out)
	return out
}

// ── construction ─────────────────────────────────────────────────────────────

// FromValue builds an Expr from a decoded YAML/JSON value: a map with an "op"
// key, as the corpus schema specifies.
//
// It is the only constructor. There is no way to build an Expr that has not
// passed through validation, which is what makes schema rules 4-6 structural
// rather than a check somebody remembers to call.
func FromValue(v any) (*Expr, error) {
	return fromValue(v, 0)
}

// UnmarshalYAML lets a corpus entry declare `when: *Expr` and have the decoder
// hand it a parsed node. A predicate has two meanings for one key (`op` is the
// boolean operator in `and`/`or`, and the comparison operator in a `field`
// node), which reflection cannot resolve; this method is where that ambiguity
// is settled, in one place, in ten lines.
func (e *Expr) UnmarshalYAML(n *safeyaml.Node) error {
	if n == nil || n.IsNull() {
		yes := true
		*e = Expr{Kind: KindLit, Lit: &yes}
		return nil
	}
	parsed, err := FromValue(n.Any())
	if err != nil {
		return err
	}
	*e = *parsed
	return nil
}

func fromValue(v any, depth int) (*Expr, error) {
	if depth > MaxDepth {
		return nil, cerr.New(cerr.EPolicy005)
	}
	switch t := v.(type) {
	case nil:
		// A missing predicate means "always". This is only reachable for a
		// hand-built Expr in a test; a corpus entry without a `when` fails
		// schema validation before it gets here.
		yes := true
		return &Expr{Kind: KindLit, Lit: &yes}, nil

	case bool:
		b := t
		return &Expr{Kind: KindLit, Lit: &b}, nil

	case map[string]any:
		return fromMap(t, depth)

	case map[any]any:
		// safeyaml decodes mappings as map[string]any, but a caller may hand us
		// a map[any]any from elsewhere. Convert rather than fail obscurely.
		m := make(map[string]any, len(t))
		for k, val := range t {
			ks, ok := k.(string)
			if !ok {
				return nil, cerr.New(cerr.EPolicy004, "op")
			}
			m[ks] = val
		}
		return fromMap(m, depth)

	case string:
		return nil, cerr.New(cerr.EPolicy004, "op")
	}
	return nil, cerr.New(cerr.EPolicy004, "op")
}

func fromMap(m map[string]any, depth int) (*Expr, error) {
	opRaw, ok := m["op"]
	if !ok {
		// A bare comparison without "op" is the shorthand
		// `{ field: x, op: "==", value: y }` — but that also has "op". So a map
		// with "field" but no "op" is ambiguous and refused.
		if _, hasField := m["field"]; hasField {
			return nil, cerr.New(cerr.EPolicy004, "op")
		}
		return nil, cerr.New(cerr.EPolicy004, "op")
	}
	opStr, ok := opRaw.(string)
	if !ok {
		return nil, cerr.New(cerr.EPolicy004, "op")
	}

	switch Kind(opStr) {
	case KindAnd, KindOr:
		l, err := fromValue(m["l"], depth+1)
		if err != nil {
			return nil, err
		}
		r, err := fromValue(m["r"], depth+1)
		if err != nil {
			return nil, err
		}
		return &Expr{Kind: Kind(opStr), L: l, R: r}, nil

	case KindNot:
		x, err := fromValue(m["x"], depth+1)
		if err != nil {
			return nil, err
		}
		return &Expr{Kind: KindNot, X: x}, nil

	case KindLit:
		b, isBool := m["value"].(bool)
		if !isBool {
			return nil, cerr.New(cerr.EPolicy004, "value")
		}
		return &Expr{Kind: KindLit, Lit: &b}, nil
	}

	// A comparison: `{ field: <path>, op: <cmpop>, value: <literal> }`.
	fieldRaw, hasField := m["field"]
	if !hasField {
		// `op` was not a boolean operator, so it must be a comparison operator,
		// which requires a field. Anything else is a corpus bug.
		return nil, cerr.New(cerr.EPolicy003, opStr)
	}
	field, ok := fieldRaw.(string)
	if !ok {
		return nil, cerr.New(cerr.EPolicy004, "field")
	}
	cmpOp := Op(opStr)
	if !validOp(cmpOp) {
		return nil, cerr.New(cerr.EPolicy004, string(cmpOp))
	}
	value, hasValue := m["value"]
	if !hasValue {
		return nil, cerr.New(cerr.EPolicy004, field)
	}
	e := &Expr{Kind: KindCmp, Field: field, Cmp: cmpOp, Value: value}
	if err := e.Validate(); err != nil {
		return nil, err
	}
	return e, nil
}

func validOp(op Op) bool {
	switch op {
	case OpEQ, OpNE, OpGT, OpGTE, OpLT, OpLTE, OpIn, OpContains:
		return true
	}
	return false
}

// ── validation ───────────────────────────────────────────────────────────────

// Validate enforces schema rules 4, 5 and 6: every field is known, every
// comparison type-checks against the field's declared type, and the tree nests
// no deeper than MaxDepth.
//
// It is called at corpus-build time. A failure here is a build failure, never a
// runtime condition.
func (e *Expr) Validate() error { return e.validate(0) }

func (e *Expr) validate(depth int) error {
	if e == nil {
		return nil
	}
	if depth > MaxDepth {
		return cerr.New(cerr.EPolicy005)
	}
	switch e.Kind {
	case KindAnd, KindOr:
		if e.L == nil || e.R == nil {
			return cerr.New(cerr.EPolicy004, string(e.Kind))
		}
		if err := e.L.validate(depth + 1); err != nil {
			return err
		}
		return e.R.validate(depth + 1)
	case KindNot:
		if e.X == nil {
			return cerr.New(cerr.EPolicy004, "not")
		}
		return e.X.validate(depth + 1)
	case KindLit:
		if e.Lit == nil {
			return cerr.New(cerr.EPolicy004, "lit")
		}
		return nil
	case KindCmp:
		f, ok := fieldByPath[e.Field]
		if !ok {
			return cerr.New(cerr.EPolicy003, e.Field)
		}
		if !validOp(e.Cmp) {
			return cerr.New(cerr.EPolicy004, string(e.Cmp))
		}
		return typeCheck(f, e.Cmp, e.Value)
	}
	return cerr.New(cerr.EPolicy004, string(e.Kind))
}

// typeCheck verifies that a comparison makes sense for its field's type. This
// is where a corpus entry comparing a bool field to the *string* "true" is
// caught, instead of silently never matching at runtime.
func typeCheck(f Field, op Op, value any) error {
	switch f.Type {
	case TypeBool:
		if _, ok := value.(bool); !ok {
			return cerr.New(cerr.EPolicy004, f.Path)
		}
		if op != OpEQ && op != OpNE {
			return cerr.New(cerr.EPolicy004, f.Path)
		}
		return nil

	case TypeInt:
		if _, ok := toInt(value); !ok {
			return cerr.New(cerr.EPolicy004, f.Path)
		}
		switch op {
		case OpEQ, OpNE, OpGT, OpGTE, OpLT, OpLTE:
			return nil
		}
		return cerr.New(cerr.EPolicy004, f.Path)

	case TypeString, TypeEnum:
		switch v := value.(type) {
		case string:
			if op == OpIn || op == OpContains {
				// `in` on a scalar string compares against a list on the other
				// side, which is not expressible here. Refuse rather than
				// half-implement.
				return cerr.New(cerr.EPolicy004, f.Path)
			}
			_ = v
			return nil
		case []any:
			if op != OpIn {
				return cerr.New(cerr.EPolicy004, f.Path)
			}
			for _, item := range v {
				if _, ok := item.(string); !ok {
					return cerr.New(cerr.EPolicy004, f.Path)
				}
			}
			return nil
		}
		return cerr.New(cerr.EPolicy004, f.Path)

	case TypeStringList:
		switch op {
		case OpContains:
			if _, ok := value.(string); !ok {
				return cerr.New(cerr.EPolicy004, f.Path)
			}
			return nil
		case OpIn:
			// `territories in [EU, US]` asks whether the declared set is a
			// subset. Expressed as a list literal, which is unambiguous.
			lst, ok := value.([]any)
			if !ok {
				return cerr.New(cerr.EPolicy004, f.Path)
			}
			for _, item := range lst {
				if _, ok := item.(string); !ok {
					return cerr.New(cerr.EPolicy004, f.Path)
				}
			}
			return nil
		case OpEQ, OpNE:
			if _, ok := value.(string); ok {
				return nil
			}
			return cerr.New(cerr.EPolicy004, f.Path)
		}
		return cerr.New(cerr.EPolicy004, f.Path)
	}
	return cerr.New(cerr.EPolicy004, f.Path)
}

func toInt(v any) (int64, bool) {
	switch n := v.(type) {
	case int:
		return int64(n), true
	case int64:
		return n, true
	case float64:
		if n == float64(int64(n)) {
			return int64(n), true
		}
	}
	return 0, false
}

// ── rendering ────────────────────────────────────────────────────────────────

// String renders the predicate as a human sentence. This is what
// `clearance explain` prints and what the finding's `predicate` field shows, so
// a user can see not just *that* an obligation applied but *why*.
func (e *Expr) String() string {
	if e == nil {
		return "always"
	}
	switch e.Kind {
	case KindAnd:
		return "(" + e.L.String() + ") AND (" + e.R.String() + ")"
	case KindOr:
		return "(" + e.L.String() + ") OR (" + e.R.String() + ")"
	case KindNot:
		return "NOT (" + e.X.String() + ")"
	case KindLit:
		if e.Lit == nil {
			return "always"
		}
		if *e.Lit {
			return "always"
		}
		return "never"
	case KindCmp:
		return e.Field + " " + string(e.Cmp) + " " + renderValue(e.Value)
	}
	return "?"
}

// Fields referenced by the predicate, in first-seen order. Used to tell the
// user exactly which undeclared fact would resolve an UNKNOWN.
func (e *Expr) Fields() []string {
	var out []string
	seen := map[string]bool{}
	var walk func(*Expr)
	walk = func(n *Expr) {
		if n == nil {
			return
		}
		switch n.Kind {
		case KindAnd, KindOr:
			walk(n.L)
			walk(n.R)
		case KindNot:
			walk(n.X)
		case KindCmp:
			if !seen[n.Field] {
				seen[n.Field] = true
				out = append(out, n.Field)
			}
		}
	}
	walk(e)
	return out
}

func renderValue(v any) string {
	switch t := v.(type) {
	case string:
		return strconv.Quote(t)
	case bool:
		return strconv.FormatBool(t)
	case int:
		return strconv.Itoa(t)
	case int64:
		return strconv.FormatInt(t, 10)
	case float64:
		return strconv.FormatFloat(t, 'g', -1, 64)
	case []any:
		parts := make([]string, 0, len(t))
		for _, item := range t {
			parts = append(parts, renderValue(item))
		}
		return "[" + strings.Join(parts, ", ") + "]"
	case nil:
		return "null"
	}
	return "?"
}
