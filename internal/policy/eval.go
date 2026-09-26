package policy

import (
	"strings"

	"github.com/clearance-dev/clearance/internal/config"
	"github.com/clearance-dev/clearance/internal/corpus"
	"github.com/clearance-dev/clearance/internal/expr"
	"github.com/clearance-dev/clearance/internal/graph"
)

// Tri is a three-valued truth: TRUE, FALSE or UNKNOWN.
//
// # WHY THREE VALUES AND NOT TWO
//
// The alternative is to coerce UNKNOWN to FALSE, which silently turns "we don't
// know" into "you're fine" — the single most dangerous behaviour this tool
// could have, and the behaviour every SCA tool exhibits. Kleene logic makes
// UNKNOWN propagate correctly: `UNKNOWN AND FALSE = FALSE` (a definite
// non-applicability wins, because the obligation genuinely does not apply), but
// `UNKNOWN AND TRUE = UNKNOWN` (an unset field leaves the obligation undecided,
// and undecided is what the user must be told).
type Tri int

const (
	TriFalse Tri = iota
	TriTrue
	TriUnknown
)

func (t Tri) String() string {
	switch t {
	case TriTrue:
		return "TRUE"
	case TriFalse:
		return "FALSE"
	}
	return "UNKNOWN"
}

// Result is an evaluation outcome plus the reason for an UNKNOWN.
type Result struct {
	Value Tri

	// UndeclaredField is the first field that was not declared and therefore
	// forced the result to UNKNOWN. It is how the tool tells the user exactly
	// which fact to supply (E-POLICY-009), rather than leaving them to guess.
	UndeclaredField string
}

func unknown(field string) Result { return Result{Value: TriUnknown, UndeclaredField: field} }

// Context is everything a predicate can address.
type Context struct {
	Intent *config.Intent
	Dep    *graph.Dependency
	Entry  *corpus.Entry
}

// Eval evaluates a predicate under Kleene three-valued logic.
//
// It is pure and total: every expression, including a malformed one, produces a
// Result. A malformed expression cannot reach here in production — the corpus
// build refuses it — so the default case is unreachable and returns UNKNOWN,
// which is the conservative direction if it ever is reached.
func Eval(e *expr.Expr, ctx *Context) Result {
	if e == nil {
		return Result{Value: TriTrue}
	}
	switch e.Kind {
	case expr.KindLit:
		if e.Lit == nil || *e.Lit {
			return Result{Value: TriTrue}
		}
		return Result{Value: TriFalse}

	case expr.KindAnd:
		l := Eval(e.L, ctx)
		if l.Value == TriFalse {
			// FALSE dominates AND, whatever the other side is. A definite
			// non-applicability is definite even next to an unknown.
			return Result{Value: TriFalse}
		}
		r := Eval(e.R, ctx)
		if r.Value == TriFalse {
			return Result{Value: TriFalse}
		}
		if l.Value == TriTrue && r.Value == TriTrue {
			return Result{Value: TriTrue}
		}
		return Result{Value: TriUnknown, UndeclaredField: firstNonEmpty(l.UndeclaredField, r.UndeclaredField)}

	case expr.KindOr:
		l := Eval(e.L, ctx)
		if l.Value == TriTrue {
			return Result{Value: TriTrue}
		}
		r := Eval(e.R, ctx)
		if r.Value == TriTrue {
			return Result{Value: TriTrue}
		}
		if l.Value == TriFalse && r.Value == TriFalse {
			return Result{Value: TriFalse}
		}
		return Result{Value: TriUnknown, UndeclaredField: firstNonEmpty(l.UndeclaredField, r.UndeclaredField)}

	case expr.KindNot:
		x := Eval(e.X, ctx)
		switch x.Value {
		case TriTrue:
			return Result{Value: TriFalse}
		case TriFalse:
			return Result{Value: TriTrue}
		}
		// NOT UNKNOWN = UNKNOWN.
		return x

	case expr.KindCmp:
		return evalCmp(e, ctx)
	}
	return Result{Value: TriUnknown}
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// evalCmp resolves one field and applies one operator.
func evalCmp(e *expr.Expr, ctx *Context) Result {
	v, declared, ok := resolveField(e.Field, ctx)
	if !ok {
		// The field exists in the registry but could not be resolved for this
		// dependency — a licence family with no corpus entry, for example.
		// That is UNKNOWN, never FALSE.
		return unknown(e.Field)
	}
	if !declared {
		// The user did not declare this fact. Absent is not zero: `mau` omitted
		// is UNKNOWN, `mau: 0` is a claim that you have no users.
		return unknown(e.Field)
	}

	switch e.Cmp {
	case expr.OpEQ:
		return boolResult(equals(v, e.Value))
	case expr.OpNE:
		return boolResult(!equals(v, e.Value))
	case expr.OpGT, expr.OpGTE, expr.OpLT, expr.OpLTE:
		a, aok := asInt(v)
		b, bok := asInt(e.Value)
		if !aok || !bok {
			return unknown(e.Field)
		}
		switch e.Cmp {
		case expr.OpGT:
			return boolResult(a > b)
		case expr.OpGTE:
			return boolResult(a >= b)
		case expr.OpLT:
			return boolResult(a < b)
		default:
			return boolResult(a <= b)
		}
	case expr.OpIn:
		return evalIn(v, e.Value)
	case expr.OpContains:
		return evalContains(v, e.Value)
	}
	return unknown(e.Field)
}

// evalIn implements `in`.
//
// SEMANTICS, DOCUMENTED BECAUSE `in` MEANS TWO DIFFERENT THINGS
//
//	scalar field in [a, b]      → the scalar equals one of the list members
//	list field   in [a, b]      → the declared set is a SUBSET of the literal
//	                              ("you operate only within this group")
//
// The second reading is the useful one for a territorial clause: "this gate
// applies only if you operate exclusively inside the EU/EEA" is a real clause
// shape, and expressing it as a subset keeps the predicate readable.
func evalIn(v any, literal any) Result {
	lst, ok := literal.([]any)
	if !ok {
		if ss, isStr := literal.([]string); isStr {
			lst = make([]any, 0, len(ss))
			for _, s := range ss {
				lst = append(lst, s)
			}
		} else {
			return unknown("")
		}
	}
	// Scalar field.
	if s, isStr := v.(string); isStr {
		for _, item := range lst {
			if itemStr, ok := item.(string); ok && itemStr == s {
				return Result{Value: TriTrue}
			}
		}
		return Result{Value: TriFalse}
	}
	// List field: subset.
	declared, isList := v.([]string)
	if !isList {
		return unknown("")
	}
	if len(declared) == 0 {
		return unknown("")
	}
	if containsFold(declared, "global") {
		// Declaring `global` means everywhere, so "operates only inside X" is
		// false for any specific X.
		return Result{Value: TriFalse}
	}
	allowed := map[string]bool{}
	for _, item := range lst {
		if itemStr, ok := item.(string); ok {
			allowed[strings.ToUpper(itemStr)] = true
		}
	}
	for _, d := range declared {
		if !allowed[strings.ToUpper(d)] {
			return Result{Value: TriFalse}
		}
	}
	return Result{Value: TriTrue}
}

// evalContains implements `contains`.
//
//	scalar string field contains "x"  → substring
//	list field contains "x"           → membership
//
// A declared `global` satisfies membership of any territory, because that is
// what declaring global means.
func evalContains(v any, literal any) Result {
	want, ok := literal.(string)
	if !ok {
		return unknown("")
	}
	switch t := v.(type) {
	case string:
		return boolResult(strings.Contains(t, want))
	case []string:
		if len(t) == 0 {
			return unknown("")
		}
		if containsFold(t, "global") {
			return Result{Value: TriTrue}
		}
		return boolResult(containsFold(t, want))
	}
	return unknown("")
}

// resolveField reads a dotted field path.
//
// The three results are deliberate and all three are used:
//
//	value, declared=true,  ok=true   a real value
//	value, declared=false, ok=true   a known field the user did not declare
//	value, _,              ok=false  a known field with no value in this context
//
// `ok=false` is not an error: `dep.licence.family` has no value for a
// dependency whose licence did not resolve, and that is exactly why INV-7
// exists.
func resolveField(path string, ctx *Context) (any, bool, bool) {
	switch path {
	// ── intent ──────────────────────────────────────────────────────────────
	case "use.commercial":
		return ctx.Intent.Use.Commercial, true, true
	case "use.licence_model":
		return string(ctx.Intent.Use.LicenceModel), true, true
	case "use.modified":
		return ctx.Intent.Use.Modified, true, true
	case "use.network_exposed":
		return ctx.Intent.Use.NetworkExposed, true, true
	case "use.distributed":
		return ctx.Intent.Use.Distributed, true, true
	case "use.saas":
		return ctx.Intent.Use.SaaS, true, true
	case "project.name":
		return ctx.Intent.Project.Name, ctx.Intent.IsDeclared("project.name"), true

	case "scale.mau":
		return ctx.Intent.Scale.MonthlyActiveUsers, ctx.Intent.IsDeclared("scale.mau"), true
	case "scale.employees":
		return ctx.Intent.Scale.Employees, ctx.Intent.IsDeclared("scale.employees"), true
	case "scale.revenue_eur":
		return ctx.Intent.Scale.RevenueEUR, ctx.Intent.IsDeclared("scale.revenue_eur"), true

	case "territories":
		return ctx.Intent.Territories, ctx.Intent.IsDeclared("territories"), true

	// ── dependency ──────────────────────────────────────────────────────────
	case "dep.kind":
		return string(ctx.Dep.Kind), true, true
	case "dep.ecosystem":
		return ctx.Dep.Ecosystem, true, true
	case "dep.name":
		return ctx.Dep.Name, true, true
	case "dep.version":
		return ctx.Dep.Version, ctx.Dep.Version != "", true
	case "dep.licence.family":
		if ctx.Entry == nil {
			return "", false, false
		}
		return ctx.Entry.Family, true, true
	case "dep.licence.permissiveness":
		if ctx.Entry == nil {
			return int64(0), false, false
		}
		return int64(ctx.Entry.Permissiveness), true, true

	case "dep.licence.spdx":
		// Deliberately always *declared*, including when it is empty.
		//
		// The "absent is not zero" rule (dep.version above) treats an empty
		// string as an undeclared fact and yields UNKNOWN. That rule is right
		// for a version, which a manifest either states or does not. It is wrong
		// here: an empty SPDX id is not a missing declaration, it is the scan's
		// definite answer that it found no licence — and that answer is the
		// whole subject of trap.licence.absent-all-rights-reserved. Under the
		// undeclared rule the one predicate that can express "there is no
		// licence" would evaluate to UNKNOWN and the trap could never fire.
		return ctx.Dep.Licence.SPDX, true, true

	case "dep.licence.resolved":
		// Mirrors the engine's own test exactly, so a trap and the
		// UNDETERMINED branch it is about cannot disagree about what "resolved"
		// means.
		return ctx.Dep.Licence.Resolved && ctx.Dep.Licence.SPDX != "", true, true
	}
	return nil, false, false
}

// ── comparison helpers ───────────────────────────────────────────────────────

func boolResult(b bool) Result {
	if b {
		return Result{Value: TriTrue}
	}
	return Result{Value: TriFalse}
}

func equals(a, b any) bool {
	// A bool field compared to a bool literal.
	if ab, ok := a.(bool); ok {
		if bb, ok := b.(bool); ok {
			return ab == bb
		}
		return false
	}
	// An int field compared to an int literal.
	if ai, ok := asInt(a); ok {
		if bi, ok := asInt(b); ok {
			return ai == bi
		}
		return false
	}
	// A string or enum field.
	if as, ok := a.(string); ok {
		bs, ok := b.(string)
		return ok && as == bs
	}
	// A list field compared to a scalar: exactly one member.
	if al, ok := a.([]string); ok {
		bs, ok := b.(string)
		if !ok {
			return false
		}
		return len(al) == 1 && strings.EqualFold(al[0], bs)
	}
	return false
}

func asInt(v any) (int64, bool) {
	switch t := v.(type) {
	case int:
		return int64(t), true
	case int64:
		return t, true
	case float64:
		if t == float64(int64(t)) {
			return int64(t), true
		}
	}
	return 0, false
}

func containsFold(list []string, want string) bool {
	for _, s := range list {
		if strings.EqualFold(s, want) {
			return true
		}
	}
	return false
}
